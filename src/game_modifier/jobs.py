"""Lightweight in-process background job manager (threading, no new deps).

Jobs are used for long-running read-only analysis (pointer_scan etc.).
Results are persisted to the session directory so work is never lost to
timeouts: a synchronous ``pointer_scan`` that exceeds its budget raises and
discards everything, while an async job keeps partial results on disk no
matter how it ends (done / failed / cancelled).

Contract between the manager and the submitted function::

    fn(progress_updater, cancel_checker) -> result

- ``progress_updater(phase: str, info: dict)`` - replace the job's progress
  snapshot (the manager merges ``{"phase": phase}`` with ``info``).
- ``cancel_checker() -> bool`` - cooperative cancellation; ``fn`` should poll
  it and return its partial result when it turns True.

On normal return the result is written to ``persist_path`` as JSON and the
job becomes ``done``; when cancellation was requested it becomes
``cancelled`` (partial results are persisted too); when ``fn`` raises the
job becomes ``failed`` with the error message. Worker threads are daemons,
so they never block process exit.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional


@dataclass
class Job:
    id: str
    kind: str
    session_id: str
    status: str = "pending"  # pending / running / done / failed / cancelled
    progress: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    error: Optional[str] = None
    results_file: Optional[str] = None
    # internal (not serialised by to_dict)
    cancel_requested: bool = False
    thread: Optional[threading.Thread] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        out = {
            "job_id": self.id,
            "kind": self.kind,
            "session_id": self.session_id,
            "status": self.status,
            "progress": dict(self.progress),
            "created_at": self.created_at,
            "finished_at": self.finished_at,
        }
        if self.error:
            out["error"] = self.error
        if self.results_file:
            out["results_file"] = self.results_file
        return out


class JobManager:
    """In-process job registry. Thread-safe (Lock), daemon worker threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}

    # ---------------------------------------------------------------- helpers
    def new_id(self) -> str:
        """Short unique job id (uuid4 hex prefix) for persist-path planning."""

        while True:
            candidate = uuid.uuid4().hex[:8]
            with self._lock:
                if candidate not in self._jobs:
                    return candidate

    # ----------------------------------------------------------------- submit
    def submit(
        self,
        kind: str,
        session_id: str,
        fn: Callable[[Callable[[str, dict], None], Callable[[], bool]], Any],
        *,
        persist_path: Path,
        job_id: Optional[str] = None,
    ) -> Job:
        """Register and start a job; returns immediately.

        ``fn(progress_updater, cancel_checker) -> result`` runs in a daemon
        thread; its return value is written to ``persist_path`` (JSON).
        ``job_id`` lets the caller pre-allocate the id used in the path.
        """

        job = Job(id=job_id or self.new_id(), kind=str(kind), session_id=str(session_id))
        with self._lock:
            self._jobs[job.id] = job
        thread = threading.Thread(
            target=self._run, args=(job, fn, Path(persist_path)),
            name=f"job-{job.id}", daemon=True,
        )
        job.thread = thread
        thread.start()
        return job

    def _run(self, job: Job, fn, persist_path: Path) -> None:
        with self._lock:
            job.status = "running"

        def progress_updater(phase: str, info: Optional[dict] = None) -> None:
            data: dict = {"phase": str(phase)}
            if isinstance(info, dict):
                data.update(info)
            with self._lock:
                job.progress = data

        def cancel_checker() -> bool:
            with self._lock:
                return job.cancel_requested

        try:
            result = fn(progress_updater, cancel_checker)
        except Exception as exc:
            with self._lock:
                job.status = "failed"
                job.error = f"{type(exc).__name__}: {exc}"
                job.finished_at = time.time()
            return

        # persist before the status flip so a done/cancelled job always has
        # its results on disk (work is never lost to a timeout).
        try:
            persist_path.parent.mkdir(parents=True, exist_ok=True)
            persist_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
            )
            with self._lock:
                job.results_file = str(persist_path)
        except Exception as exc:
            with self._lock:
                job.error = f"results not persisted: {type(exc).__name__}: {exc}"

        with self._lock:
            job.status = "cancelled" if job.cancel_requested else "done"
            job.finished_at = time.time()

    # ------------------------------------------------------------------ query
    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, session_id: Optional[str] = None) -> list[Job]:
        with self._lock:
            jobs = list(self._jobs.values())
        if session_id:
            jobs = [j for j in jobs if j.session_id == session_id]
        return sorted(jobs, key=lambda j: j.created_at)

    # ----------------------------------------------------------------- cancel
    def cancel(self, job_id: str) -> bool:
        """Set the cooperative cancellation flag. Returns False for unknown
        or already-finished jobs. ``fn`` observes the flag via its checker."""

        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status in ("done", "failed", "cancelled"):
                return False
            job.cancel_requested = True
            return True


#: Process-wide singleton used by the service layer.
JOBS = JobManager()

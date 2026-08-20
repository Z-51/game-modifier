"""Bridge to the ``il-tool`` subprocess (Unity Mono IL analysis / patching).

``il-tool`` (see ``iltool/``) reads exactly one JSON request line on stdin and
answers with exactly one JSON envelope line on stdout — the same ``ok``/
``error`` shape the rest of game-modifier uses. stderr is diagnostics only;
exit code 0 means the envelope is authoritative (even for ``ok:false``
business errors), non-zero means a transport-layer failure.

:func:`run_il_tool` mirrors the structured-failure mode of
``engines.unity.run_dumper_cli``: tool-level failures (timeout, non-zero exit,
unparseable envelope) come back as structured dicts instead of raw exceptions.
The only exception raised is :class:`IlToolMissingError` when no binary can be
located at all.

Binary location order (see :func:`locate_il_tool`):

1. packaged ``data/il-tool/il-tool.exe`` (built by ``iltool/build.ps1``)
2. config ``[tools] il_tool`` explicit path
3. toolchain registry probe (``PATH`` / ``[tools.search_dirs].extra``)
"""

from __future__ import annotations

import atexit
import json
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional


def packaged_il_tool_path() -> Optional[str]:
    """Path of the in-package ``il-tool.exe`` (None when not built/shipped).

    Kept as a function so tests can monkeypatch the packaged tier away.
    """

    candidate = Path(__file__).resolve().parents[1] / "data" / "il-tool" / "il-tool.exe"
    return str(candidate) if candidate.exists() else None


def locate_il_tool(config=None) -> Optional[str]:
    """Resolve the il-tool binary following the packaged > config > registry order."""

    packaged = packaged_il_tool_path()
    if packaged:
        return packaged

    if config is not None:
        override = config.tool_path("il_tool")
        if override and Path(override).exists():
            return override

    # registry probe (PATH + configured search dirs)
    from ..toolchain import registry as _registry

    spec = next((s for s in _registry._specs() if s.name == "il_tool"), None)
    if spec is not None:
        found = _registry.find_tool(spec, config)
        if found:
            return found
    return None


# --------------------------------------------------------------------------
# keep-alive worker (F4): one il-tool --serve process per binary, shared by
# every request of this host process. Requests are serialized on the wire;
# a crashed worker is transparently respawned and the request retried once;
# an idle worker is reaped after IDLE_TIMEOUT_S.
# --------------------------------------------------------------------------


class IlToolWorker:
    """One ``il-tool --serve`` process answering one request line at a time."""

    IDLE_TIMEOUT_S = 300.0
    _SWEEP_INTERVAL_S = 30.0

    def __init__(self, cmd: list[str]) -> None:
        self._cmd = list(cmd) + ["--serve"]
        self._proc: Optional[subprocess.Popen] = None
        self._lines: "queue.Queue[Optional[str]]" = queue.Queue()
        self._io_lock = threading.Lock()
        self._last_used = 0.0
        self._closed = False
        self._sweeper: Optional[threading.Thread] = None
        self.requests_served = 0  # observability for tests/diagnostics

    # ------------------------------------------------------------ lifecycle
    def _spawn(self) -> None:
        q: "queue.Queue[Optional[str]]" = queue.Queue()
        self._lines = q
        proc = subprocess.Popen(
            self._cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            errors="replace",
        )
        self._proc = proc
        threading.Thread(target=self._pump, args=(proc, q), daemon=True).start()
        self._last_used = time.monotonic()
        if self._sweeper is None:
            self._sweeper = threading.Thread(target=self._sweep, daemon=True)
            self._sweeper.start()

    def _pump(self, proc: subprocess.Popen, q: "queue.Queue") -> None:
        """Reader thread: child stdout lines -> queue; EOF -> None sentinel.

        The queue is passed explicitly: after a kill+respawn the old pump must
        NOT poison the new generation's queue with its trailing EOF sentinel.
        """

        try:
            for line in proc.stdout:
                q.put(line)
        except Exception:
            pass
        q.put(None)

    def _kill(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
        except Exception:
            pass
        try:
            proc.kill()
        except Exception:
            pass

    def close(self) -> None:
        self._closed = True
        self._kill()

    def _sweep(self) -> None:
        """Idle reaper: close the child after IDLE_TIMEOUT_S without traffic."""

        while not self._closed:
            time.sleep(self._SWEEP_INTERVAL_S)
            if self._closed:
                return
            if (self._proc is not None
                    and self._io_lock.acquire(blocking=False)):
                try:
                    if (self._proc is not None
                            and time.monotonic() - self._last_used > self.IDLE_TIMEOUT_S):
                        self._kill()
                finally:
                    self._io_lock.release()

    # -------------------------------------------------------------- request
    def request(self, request: dict, *, timeout: float = 120.0) -> dict:
        """Send one request, await one envelope; respawn+retry once on a crash.

        Returns the same envelope shape as :func:`run_il_tool` plus
        ``worker: True``. Transport failures carry ``transport`` =
        ``spawn_failed`` / ``broken_pipe`` / ``timeout``.
        """

        from ..errors import ErrorCode

        command = request.get("command", "")
        t0 = time.monotonic()

        def _fail(message: str, *, transport: str) -> dict:
            return {
                "ok": False,
                "command": command,
                "error": {"code": ErrorCode.TOOL_FAILED.value, "message": message},
                "elapsed": round(time.monotonic() - t0, 3),
                "worker": True,
                "transport": transport,
            }

        with self._io_lock:
            if self._closed:
                return _fail("il-tool worker is closed", transport="closed")
            payload = json.dumps({"v": 1, **request}, ensure_ascii=False)
            for attempt in (1, 2):
                try:
                    if self._proc is None or self._proc.poll() is not None:
                        self._kill()
                        self._spawn()
                    proc = self._proc
                    assert proc is not None and proc.stdin is not None
                    proc.stdin.write(payload + "\n")
                    proc.stdin.flush()
                except OSError as exc:
                    self._kill()
                    if attempt == 1:
                        continue  # one transparent respawn+retry
                    return _fail(f"il-tool worker spawn failed: {exc}",
                                 transport="spawn_failed")
                try:
                    reply = self._lines.get(timeout=timeout)
                except queue.Empty:
                    # never auto-retry a timeout - the request may be heavy
                    self._kill()
                    return _fail(
                        f"il-tool worker timed out after {timeout}s",
                        transport="timeout",
                    )
                if reply is None:  # EOF: child died mid-request
                    self._kill()
                    if attempt == 1:
                        continue
                    return _fail("il-tool worker exited (broken pipe)",
                                 transport="broken_pipe")
                self._last_used = time.monotonic()
                self.requests_served += 1
                try:
                    envelope = json.loads(reply.strip())
                    if not isinstance(envelope, dict):
                        raise ValueError("envelope is not a JSON object")
                except (ValueError, TypeError) as exc:
                    return _fail(f"il-tool worker produced an unparseable envelope: {exc}",
                                 transport="broken_pipe")
                res: dict[str, Any] = {
                    "ok": bool(envelope.get("ok")),
                    "command": envelope.get("command", command),
                    "returncode": 0,
                    "elapsed": round(time.monotonic() - t0, 3),
                    "worker": True,
                }
                if res["ok"]:
                    res["data"] = envelope.get("data", {})
                else:
                    err = envelope.get("error") or {}
                    res["error"] = err if isinstance(err, dict) else {
                        "code": ErrorCode.TOOL_FAILED.value, "message": str(err)}
                return res
            return _fail("il-tool worker failed", transport="broken_pipe")


_WORKERS: dict[tuple, IlToolWorker] = {}
_WORKERS_GUARD = threading.Lock()


def _shared_worker(cmd: list[str]) -> IlToolWorker:
    """One worker per il-tool binary, shared process-wide."""

    key = tuple(cmd)
    with _WORKERS_GUARD:
        worker = _WORKERS.get(key)
        if worker is None or worker._closed:
            worker = IlToolWorker(cmd)
            _WORKERS[key] = worker
        return worker


def _close_all_workers() -> None:
    with _WORKERS_GUARD:
        workers = list(_WORKERS.values())
        _WORKERS.clear()
    for w in workers:
        w.close()


atexit.register(_close_all_workers)


def run_il_tool(request: dict, *, timeout: float = 120.0, config=None,
                prefer_worker: bool = True) -> dict:
    """Invoke ``il-tool`` once with ``request`` and parse its envelope.

    Never raises for runtime failures (timeout / non-zero exit / bad JSON):
    the result carries ``ok=False`` plus a structured ``error`` so callers can
    branch on data. Only a missing binary raises
    :class:`~game_modifier.errors.IlToolMissingError` (``E_IL_TOOL_MISSING``).

    With ``prefer_worker=True`` (default) and a real ``.exe`` binary the call
    is served by the shared keep-alive worker (``--serve`` mode) instead of
    spawning a fresh process per request; ``.py`` stand-ins (tests) always
    take the single-shot path. A worker spawn failure falls back to the
    single-shot path so the richer error surface is preserved.

    Returns ``{"ok", "command", "data"|"error", "returncode", "elapsed", ...}``.
    """

    from ..errors import ErrorCode, IlToolMissingError

    t0 = time.monotonic()
    command = request.get("command", "")

    def _fail(message: str, *, code: str = ErrorCode.TOOL_FAILED.value, **extra) -> dict:
        res: dict[str, Any] = {
            "ok": False,
            "command": command,
            "error": {"code": code, "message": message},
            "elapsed": round(time.monotonic() - t0, 3),
        }
        res.update(extra)
        return res

    exe = locate_il_tool(config)
    if not exe:
        raise IlToolMissingError(
            "il-tool binary not found",
            details={"packaged": packaged_il_tool_path()},
        )

    cmd = [exe]
    # A .py stand-in (stub executable in tests / source-only deployments) runs
    # under the current interpreter, mirroring the .dll -> dotnet dispatch used
    # by unity.run_dumper_cli.
    if exe.lower().endswith(".py"):
        cmd = [sys.executable, exe]

    if prefer_worker and exe.lower().endswith(".exe"):
        res = _shared_worker(cmd).request(request, timeout=timeout)
        if res.get("transport") != "spawn_failed":
            return res
        # spawn failure: fall through to the single-shot path, whose error
        # surface (returncode / stderr tail / hints) is richer.

    payload = {"v": 1, **request}
    try:
        proc = subprocess.run(
            cmd,
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return _fail(
            f"il-tool timed out after {timeout}s",
            timeout=True,
            returncode=None,
            hint="Raise timeout or narrow the request (filter/max_types/max_results, or use 'out' spilling).",
        )
    except (FileNotFoundError, OSError) as exc:
        return _fail(
            f"could not execute il-tool: {exc}",
            returncode=None,
            il_tool_path=exe,
            hint="Verify the .NET 8 runtime is installed (framework-dependent build) or rebuild via iltool/build.ps1.",
        )

    stderr_tail = (proc.stderr or "")[-1500:]
    base = {
        "command": command,
        "returncode": proc.returncode,
        "elapsed": round(time.monotonic() - t0, 3),
        "stderr_tail": stderr_tail,
    }

    if proc.returncode != 0:
        # Transport-layer failure: the envelope contract is void.
        res = _fail(
            f"il-tool exited with code {proc.returncode} (transport failure, stdout not authoritative)",
            **base,
        )
        res["stdout_tail"] = (proc.stdout or "")[-1000:]
        return res

    try:
        envelope = json.loads((proc.stdout or "").strip())
        if not isinstance(envelope, dict):
            raise ValueError("envelope is not a JSON object")
    except (ValueError, TypeError) as exc:
        res = _fail(
            f"il-tool produced an unparseable envelope: {exc}",
            **base,
        )
        res["stdout_tail"] = (proc.stdout or "")[-1000:]
        return res

    ok = bool(envelope.get("ok"))
    res = dict(base)
    res["ok"] = ok
    res["command"] = envelope.get("command", command)
    if ok:
        res["data"] = envelope.get("data", {})
    else:
        # Business error envelope: pass the child's structured error through.
        err = envelope.get("error") or {}
        if not isinstance(err, dict):
            err = {"code": ErrorCode.TOOL_FAILED.value, "message": str(err)}
        res["error"] = err
    return res

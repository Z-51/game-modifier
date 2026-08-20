"""Background job framework + async pointer_scan tests.

Covers the JobManager lifecycle (done/progress/cancel/failure/list), the
async pointer_scan flow over FakeBackend, result persistence, the sync
pointer_scan regression check, and CLI/MCP wiring.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

from conftest import FakeBackend

from game_modifier import mcp_server
from game_modifier.cli import build_parser
from game_modifier.jobs import JobManager
from game_modifier.memory import process as procmod
from game_modifier.memory.base import MemoryRegion
from game_modifier.service import ModifierService

STATIC = 0x300000  # static storage holding a pointer into the heap
HEAP = 0x200000  # heap region holding a pointer to the target
TARGET = 0x400010  # the value address we want a chain to


def p64(v: int) -> bytes:
    return v.to_bytes(8, "little")


class ScanBackend(FakeBackend):
    """FakeBackend whose regions are readable/writable but not executable."""

    def regions(self):
        return [
            MemoryRegion(base=base, size=len(buf), readable=True, writable=True, executable=False, state=0x1000)
            for base, buf in self._regions.items()
        ]


def make_chain_backend() -> ScanBackend:
    """Build: STATIC+8 -> HEAP+0x30 (+8 offset), HEAP+0x30 -> TARGET."""

    static = bytearray(0x40)
    static[0x08:0x10] = p64(HEAP + 0x28)  # points at HEAP+0x30 minus 8
    heap = bytearray(0x100)
    heap[0x30:0x38] = p64(TARGET)
    return ScanBackend(regions={STATIC: static, HEAP: heap})


def join_within(job, seconds: float = 10.0) -> None:
    """Join a job's worker thread with a hard cap (never hang the suite)."""

    assert job.thread is not None
    job.thread.join(seconds)
    assert not job.thread.is_alive(), "job worker did not finish in time"


def wait_status(service, job_id: str, terminal=("done", "failed", "cancelled"), seconds: float = 10.0) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        st = service.job_status(job_id)
        if st["status"] in terminal:
            return st
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} never reached a terminal status")


# ---------------------------------------------------------------------------
# 1-5: JobManager lifecycle
# ---------------------------------------------------------------------------

def test_job_submit_done(tmp_path):
    mgr = JobManager()
    persist = tmp_path / "jobs" / "result.json"

    def fn(progress, cancel):
        return {"answer": 42}

    job = mgr.submit("demo", "sess-1", fn, persist_path=persist)
    join_within(job)
    assert job.status == "done"
    assert job.error is None
    assert job.results_file == str(persist)
    assert json.loads(persist.read_text(encoding="utf-8"))["answer"] == 42


def test_job_progress_updates(tmp_path):
    mgr = JobManager()
    started = threading.Event()

    def fn(progress, cancel):
        started.set()
        for i in range(3):
            progress("phase", {"step": i})
            time.sleep(0.01)
        return {"steps": 3}

    job = mgr.submit("demo", "sess-1", fn, persist_path=tmp_path / "r.json")
    assert started.wait(5.0)
    join_within(job)
    # final progress snapshot visible after completion
    assert job.progress["phase"] == "phase"
    assert job.progress["step"] == 2
    assert job.status == "done"


def test_job_cancel(tmp_path):
    mgr = JobManager()
    started = threading.Event()
    persist = tmp_path / "r.json"

    def fn(progress, cancel):
        started.set()
        n = 0
        while not cancel():
            n += 1
            progress("running", {"n": n})
            time.sleep(0.005)
        return {"partial": n}

    job = mgr.submit("demo", "sess-1", fn, persist_path=persist)
    assert started.wait(5.0)
    assert mgr.cancel(job.id) is True
    join_within(job)
    assert job.status == "cancelled"
    data = json.loads(persist.read_text(encoding="utf-8"))
    assert data["partial"] >= 1  # partial result persisted
    # cancelling again is a no-op
    assert mgr.cancel(job.id) is False


def test_job_failure(tmp_path):
    mgr = JobManager()

    def fn(progress, cancel):
        raise ValueError("boom")

    job = mgr.submit("demo", "sess-1", fn, persist_path=tmp_path / "r.json")
    join_within(job)
    assert job.status == "failed"
    assert "ValueError" in job.error and "boom" in job.error
    assert not (tmp_path / "r.json").exists()


def test_job_list_filter(tmp_path):
    mgr = JobManager()

    def fn(progress, cancel):
        return {}

    j1 = mgr.submit("demo", "sess-a", fn, persist_path=tmp_path / "a.json")
    j2 = mgr.submit("demo", "sess-b", fn, persist_path=tmp_path / "b.json")
    j3 = mgr.submit("demo", "sess-a", fn, persist_path=tmp_path / "c.json")
    for j in (j1, j2, j3):
        join_within(j)
    assert {j.id for j in mgr.list()} >= {j1.id, j2.id, j3.id}
    assert {j.id for j in mgr.list("sess-a")} == {j1.id, j3.id}
    assert {j.id for j in mgr.list("sess-b")} == {j2.id}
    assert mgr.list("no-such-session") == []


# ---------------------------------------------------------------------------
# 6-8: async pointer_scan through the service layer
# ---------------------------------------------------------------------------

@pytest.fixture
def scan_service(tmp_config, monkeypatch):
    backend = make_chain_backend()
    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: backend)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config)


def test_pointer_scan_async_flow(scan_service):
    sid = scan_service.attach(pid=4242)["session_id"]
    started = scan_service.pointer_scan_async(session_id=sid, address=hex(TARGET), max_depth=2, max_paths=100)
    job_id = started["job_id"]
    assert started["status"] in ("pending", "running")
    assert "job_status" in started["hint"]

    st = wait_status(scan_service, job_id)
    assert st["status"] == "done"
    assert st["paths_total"] >= 2
    assert any(p["base"] == hex(HEAP + 0x30) for p in st["paths_sample"])
    assert st["results_file"].endswith(f"{job_id}.json")

    # job_list finds it and filters by session
    listed = scan_service.job_list(session_id=sid)
    assert any(j["job_id"] == job_id and j["kind"] == "pointer_scan" for j in listed["jobs"])

    # discovered paths were persisted for pointer_rescan reuse
    assert scan_service.store.read_pointer_paths(sid)


def test_pointer_scan_sync_unchanged(scan_service):
    """Regression: the synchronous scan behaves exactly as before."""

    sid = scan_service.attach(pid=4242)["session_id"]
    res = scan_service.pointer_scan(session_id=sid, address=hex(TARGET), max_depth=2, max_paths=100)
    assert res["truncated"] is False
    assert "elapsed" in res and "confidence" in res and "reason" in res
    assert "cancelled" not in res
    by_base = {p["base"]: p for p in res["paths"]}
    assert by_base[hex(HEAP + 0x30)]["offsets"] == [0]
    assert by_base[hex(STATIC + 0x08)]["offsets"] == [8, 0]


def test_job_results_persist(scan_service, tmp_path):
    sid = scan_service.attach(pid=4242)["session_id"]
    started = scan_service.pointer_scan_async(session_id=sid, address=hex(TARGET), max_depth=1, max_paths=50)
    job_id = started["job_id"]
    st = wait_status(scan_service, job_id)

    results_file = scan_service.store.jobs_dir(sid) / f"{job_id}.json"
    assert results_file.exists()
    data = json.loads(results_file.read_text(encoding="utf-8"))
    assert data["truncated"] is False
    assert isinstance(data["paths"], list) and data["paths"]
    assert all({"base", "offsets", "depth"} <= set(p) for p in data["paths"])
    assert st["results_file"] == str(results_file)
    assert st["paths_total"] == len(data["paths"])

    # job_status via the persisted file alone (unknown to the registry path)
    from game_modifier.jobs import JOBS
    JOBS._jobs.pop(job_id, None)  # simulate a restarted server
    fallback = scan_service.job_status(job_id, session_id=sid)
    assert fallback["status"] == "done"
    assert fallback["paths_total"] == len(data["paths"])


# ---------------------------------------------------------------------------
# 9-10: CLI parsing + MCP registration
# ---------------------------------------------------------------------------

def test_cli_job_parsing():
    parser = build_parser()

    args = parser.parse_args(["pointer-scan", "--session", "s1", "--address", "0x400010", "--async", "--timeout", "120"])
    assert args.command == "pointer-scan"
    assert args.async_run is True
    assert args.timeout == 120.0

    args = parser.parse_args(["pointer-scan", "--session", "s1", "--address", "0x400010"])
    assert args.async_run is False

    args = parser.parse_args(["job", "status", "abc123", "--session", "s1"])
    assert args.command == "job" and args.job_action == "status"
    assert args.job_id == "abc123" and args.session == "s1"

    args = parser.parse_args(["job", "list", "--session", "s1"])
    assert args.job_action == "list" and args.session == "s1"

    args = parser.parse_args(["job", "cancel", "abc123"])
    assert args.job_action == "cancel" and args.job_id == "abc123"


@pytest.fixture
def mcp_config_path(tmp_path):
    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    return str(cfg)


def _tool_names(server) -> set[str]:
    tm = getattr(server, "_tool_manager", None)
    if tm is not None and hasattr(tm, "_tools"):
        return set(tm._tools.keys())
    import asyncio

    return {t.name for t in asyncio.run(server.list_tools())}


def test_mcp_job_tools_registered(mcp_config_path):
    default = _tool_names(mcp_server.build_server(mcp_config_path))
    readonly = _tool_names(mcp_server.build_server(mcp_config_path, profile="readonly"))

    # job_status / job_list are read-only -> present in both profiles
    assert {"job_status", "job_list", "pointer_scan"} <= default
    assert {"job_status", "job_list", "pointer_scan"} <= readonly
    # job_cancel has side effects -> writable profile only
    assert "job_cancel" in default
    assert "job_cancel" not in readonly

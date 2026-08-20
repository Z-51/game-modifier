"""F4: il-tool keep-alive worker (--serve mode) tests.

``IlToolWorker`` speaks the line protocol to one long-lived child; these tests
drive it with a Python stand-in (``--serve``-style loop script) plus a smoke
test against the real packaged binary when it is built (skipped otherwise).
"""

from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest

from game_modifier.engines import il_tool as iltool
from game_modifier.errors import ErrorCode


# A serve-mode stand-in: loops reading request lines until EOF.
SERVE_STUB = '''\
import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except Exception:
        sys.stdout.write(json.dumps({"ok": False, "command": "unknown",
            "error": {"code": "E_IL_BAD_REQUEST", "message": "bad json"}}) + "\\n")
        sys.stdout.flush()
        continue
    cmd = req.get("command", "")
    if cmd == "die":
        sys.exit(3)  # crash mid-stream: no answer line
    elif cmd == "sleep":
        import time as _t
        _t.sleep(30)
    echo = {"n": req.get("n")}
    sys.stdout.write(json.dumps({"ok": True, "command": cmd,
                                 "data": {"echo": echo, "pid_marker": True}}) + "\\n")
    sys.stdout.flush()
'''


@pytest.fixture
def serve_stub(tmp_path):
    p = tmp_path / "il-tool-serve-stub.py"
    p.write_text(SERVE_STUB, encoding="utf-8")
    return [sys.executable, str(p)]


def test_worker_serves_many_requests_one_process(serve_stub):
    worker = iltool.IlToolWorker(serve_stub)
    try:
        r1 = worker.request({"command": "analyze", "n": 1}, timeout=10)
        r2 = worker.request({"command": "dump", "n": 2}, timeout=10)
        r3 = worker.request({"command": "callers", "n": 3}, timeout=10)
        assert r1["ok"] and r1["data"]["echo"] == {"n": 1}
        assert r2["ok"] and r2["data"]["echo"] == {"n": 2}
        assert r3["ok"] and r3["data"]["echo"] == {"n": 3}
        assert r1["worker"] is True
        assert worker.requests_served == 3
        # still the same child process throughout
        assert worker._proc is not None and worker._proc.poll() is None
    finally:
        worker.close()
    assert worker._proc is None


def test_worker_business_error_passthrough(serve_stub):
    worker = iltool.IlToolWorker(serve_stub)
    try:
        res = worker.request({"command": "badjson-sim"}, timeout=10)
        assert res["ok"] is True  # stub answers ok for unknown commands
        res = worker.request({"command": "analyze"}, timeout=10)
        assert res["ok"] is True
    finally:
        worker.close()


def test_worker_crash_respawns_and_retries(serve_stub):
    worker = iltool.IlToolWorker(serve_stub)
    try:
        first = worker.request({"command": "analyze"}, timeout=10)
        assert first["ok"] is True
        crashed = worker.request({"command": "die"}, timeout=10)
        # the request itself cannot be answered (child died) - after one
        # transparent respawn+retry the "die" command kills it again, so the
        # final answer is a structured transport failure
        assert crashed["ok"] is False
        assert crashed["transport"] == "broken_pipe"
        # the NEXT request runs on a fresh child, transparently
        after = worker.request({"command": "analyze"}, timeout=10)
        assert after["ok"] is True
    finally:
        worker.close()


def test_worker_timeout_no_retry(serve_stub):
    worker = iltool.IlToolWorker(serve_stub)
    try:
        t0 = time.monotonic()
        res = worker.request({"command": "sleep"}, timeout=0.5)
        elapsed = time.monotonic() - t0
        assert res["ok"] is False
        assert res["transport"] == "timeout"
        assert elapsed < 10  # did NOT wait out the stub's 30s sleep
        # child was killed; next request respawns
        nxt = worker.request({"command": "analyze"}, timeout=10)
        assert nxt["ok"] is True
    finally:
        worker.close()


def test_worker_spawn_failure(tmp_path):
    worker = iltool.IlToolWorker([str(tmp_path / "no-such-exe.exe")])
    try:
        res = worker.request({"command": "analyze"}, timeout=5)
        assert res["ok"] is False
        assert res["transport"] == "spawn_failed"
        assert res["error"]["code"] == ErrorCode.TOOL_FAILED.value
    finally:
        worker.close()


def test_run_il_tool_routes_exe_to_worker(tmp_path, monkeypatch):
    """A real .exe path goes through the shared worker, not subprocess.run."""

    fake_exe = tmp_path / "il-tool.exe"
    fake_exe.write_bytes(b"MZ")  # existence is all locate checks
    monkeypatch.setattr(iltool, "packaged_il_tool_path", lambda: str(fake_exe))

    seen = {}

    class FakeWorker:
        def request(self, request, *, timeout=120.0):
            seen["request"] = request
            return {"ok": True, "command": request.get("command"),
                    "data": {"via": "worker"}, "returncode": 0,
                    "elapsed": 0.0, "worker": True}

    monkeypatch.setattr(iltool, "_shared_worker", lambda cmd: FakeWorker())
    res = iltool.run_il_tool({"command": "analyze", "args": {}}, timeout=5)
    assert res["ok"] is True
    assert res["data"]["via"] == "worker"
    assert seen["request"]["command"] == "analyze"


def test_run_il_tool_worker_spawn_failure_falls_back(tmp_path, monkeypatch):
    """spawn_failed from the worker falls back to the single-shot path, which
    produces the richer 'could not execute' failure for a bogus binary."""

    fake_exe = tmp_path / "il-tool.exe"
    fake_exe.write_bytes(b"MZ")
    monkeypatch.setattr(iltool, "packaged_il_tool_path", lambda: str(fake_exe))

    res = iltool.run_il_tool({"command": "analyze", "args": {}}, timeout=5)
    # the bogus MZ file cannot start under either path; the single-shot
    # fallback surfaces the OSError-derived failure with its hint
    assert res["ok"] is False
    assert "could not execute" in res["error"]["message"]


def test_py_standins_stay_single_shot(tmp_path, monkeypatch):
    """`.py` stubs must keep the legacy one-process-per-request behavior."""

    stub = tmp_path / "il-tool-stub.py"
    stub.write_text(
        'import json,sys\n'
        'req=json.loads(sys.stdin.readline())\n'
        'sys.stdout.write(json.dumps({"ok":True,"command":req.get("command"),"data":{"via":"single"}})+"\\n")\n',
        encoding="utf-8")
    monkeypatch.setattr(iltool, "packaged_il_tool_path", lambda: str(stub))

    def boom(cmd):
        raise AssertionError("worker must not be used for .py stand-ins")

    monkeypatch.setattr(iltool, "_shared_worker", boom)
    res = iltool.run_il_tool({"command": "analyze", "args": {}}, timeout=10)
    assert res["ok"] is True
    assert res["data"]["via"] == "single"
    assert "worker" not in res


def test_real_binary_serve_smoke(tmp_path):
    """End-to-end with the packaged il-tool.exe in --serve mode (skip when
    the binary was not built in this checkout)."""

    exe = iltool.packaged_il_tool_path()
    if not exe:
        pytest.skip("packaged il-tool.exe not built")
    proc = subprocess.Popen(
        [exe, "--serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        encoding="utf-8")
    try:
        assert proc.stdin is not None and proc.stdout is not None
        for req in ({"v": 1, "command": "analyze", "assembly": "missing.dll", "args": {}},
                    {"v": 1, "command": "unknown-cmd", "args": {}}):
            proc.stdin.write(json.dumps(req) + "\n")
            proc.stdin.flush()
            env = json.loads(proc.stdout.readline())
            assert env["ok"] is False
        proc.stdin.close()
        assert proc.wait(timeout=10) == 0  # clean EOF shutdown
    finally:
        if proc.poll() is None:
            proc.kill()

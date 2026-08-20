"""Regression tests for results_read (review P0-F1).

The MCP surface had no file-read tool: tools like il_dump/il_analyze/batch_run
spill full payloads under sessions/<id>/ and return only a summary, leaving
pure-MCP clients with no sanctioned read-back channel. results_read closes
that gap, restricted to the session's own directory (E_PATH_NOT_ALLOWED on
escape attempts).
"""

from __future__ import annotations

import json
import struct
import sys

import pytest

pytest.importorskip("mcp")

from game_modifier import mcp_server  # noqa: E402
from game_modifier import service as svc_mod  # noqa: E402
from game_modifier.errors import (  # noqa: E402
    ErrorCode,
    InvalidArgsError,
    PathNotAllowedError,
)
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory.base import ModuleInfo  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402


@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x1000)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={0x200000: region}, modules=[mod], name="fake.exe", pid=4242)
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


def _write_artifact(service: ModifierService, sid: str, rel: str, text: str):
    path = service.store.dir / sid / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ------------------------------------------------------------------ service


def test_results_read_absolute_path(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    payload = "\n".join(f"line-{i}" for i in range(10))
    f = _write_artifact(svc, sid, "il/dump-abc.json", payload)

    out = svc.results_read(sid, path=str(f))
    assert out["total_lines"] == 10
    assert out["returned_lines"] == 10  # default limit 400 covers everything
    assert "line-0" in out["content"] and "line-9" in out["content"]
    assert out["session_relative_path"].replace("\\", "/") == "il/dump-abc.json"


def test_results_read_relative_path_and_paging(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    payload = "\n".join(f"row{i}" for i in range(50))
    _write_artifact(svc, sid, "batch_results/r1.json", payload)

    page1 = svc.results_read(sid, path="batch_results/r1.json", offset=0, limit=20)
    assert page1["returned_lines"] == 20
    assert page1["has_more"] is True and page1["next_offset"] == 20
    page2 = svc.results_read(sid, path="batch_results/r1.json", offset=20, limit=0)
    assert page2["returned_lines"] == 30
    assert "has_more" not in page2


def test_results_read_escape_refused(service, tmp_path):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    outside = tmp_path / "secret.txt"
    outside.write_text("nope", encoding="utf-8")

    with pytest.raises(PathNotAllowedError) as ei:
        svc.results_read(sid, path=str(outside))
    assert ei.value.code == ErrorCode.PATH_NOT_ALLOWED

    with pytest.raises(PathNotAllowedError):
        svc.results_read(sid, path="../../secret.txt")

    with pytest.raises(PathNotAllowedError):
        svc.results_read(sid, path="../other-session/session.json")


def test_results_read_missing_lists_available(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    _write_artifact(svc, sid, "il/analyze-x.json", "{}")

    with pytest.raises(InvalidArgsError) as ei:
        svc.results_read(sid, path="il/nope.json")
    available = ei.value.details.get("available") or []
    assert any("analyze-x.json" in a for a in available)


def test_results_read_never_writes(service):
    """Read-only contract: no audit entries, no session.json rewrite."""

    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    f = _write_artifact(svc, sid, "jobs/j1.json", '{"status": "done"}')
    session_file = svc.store.dir / f"{sid}.json"
    before = session_file.stat().st_mtime_ns
    out = svc.results_read(sid, path=str(f))
    assert json.loads(out["content"])["status"] == "done"
    after = session_file.stat().st_mtime_ns
    assert after == before  # no save happened


# ---------------------------------------------------------------------- MCP


def _tool_names(server) -> set[str]:
    import asyncio

    async def _list():
        tools = await server.list_tools()
        return {t.name for t in tools}

    return asyncio.run(_list())


def test_results_read_registered_in_all_profiles(tmp_path, monkeypatch):
    import game_modifier.mcp_server as ms
    from game_modifier.config import load_config

    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    monkeypatch.setattr(ms, "load_config", lambda path=None: load_config(str(cfg)))
    for profile in ("default", "readonly", "dry-run", "symbols", "limited"):
        server = ms.build_server(str(cfg), profile=profile)
        assert "results_read" in _tool_names(server), f"missing in {profile}"


def test_results_read_mcp_call(service, tmp_path, monkeypatch):
    import game_modifier.mcp_server as ms

    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    _write_artifact(svc, sid, "il/dump-1.json", '{"instruction_count": 3}')

    monkeypatch.setattr(ms, "load_config", lambda path=None: svc.config)
    server = ms.build_server(str(tmp_path / "c.toml"), profile="readonly")

    import asyncio
    out = asyncio.run(server.call_tool("results_read", {"session": sid, "path": "il/dump-1.json"}))
    env = json.loads(out[0].text)
    assert env["ok"] is True
    assert env["data"]["total_lines"] == 1
    assert "instruction_count" in env["data"]["content"]

    # escape via MCP returns the structured error envelope
    out = asyncio.run(server.call_tool("results_read", {"session": sid, "path": "../../x"}))
    env = json.loads(out[0].text)
    assert env["ok"] is False
    assert env["error"]["code"] == "E_PATH_NOT_ALLOWED"

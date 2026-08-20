"""Polling watch tests (foreground loop, JSONL report, CLI + MCP wiring).

Uses the FakeBackend monkeypatch pattern from test_service.py. The watch is
polling-based: it records WHEN a value changes (old/new), not WHO wrote it.
"""

from __future__ import annotations

import json
import struct

import pytest

from conftest import FakeBackend

from game_modifier.memory import process as procmod
from game_modifier.memory.base import ModuleInfo
from game_modifier.service import ModifierService

BASE = 0x200000


@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x1000)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={BASE: region}, modules=[mod], name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    # keep the polling loop instant
    monkeypatch.setattr("game_modifier.service.time.sleep", lambda s: None)
    return ModifierService(tmp_config), fake


def _build(tmp_path, monkeypatch, fake):
    """Service wired to an arbitrary custom backend (same pattern as test_perf_freeze.py)."""

    from game_modifier.config import Config
    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    monkeypatch.setattr("game_modifier.service.time.sleep", lambda s: None)
    cfg = Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": True, "require_writable_region": True},
        "scan": {"max_results": 1000, "chunk_size": 4096, "alignment": 1, "max_region_bytes": 0},
        "output": {"format": "json"},
        "paths": {"home": str(tmp_path / ".game-modifier")},
        "tools": {"search_dirs": {"extra": []}},
    })
    return ModifierService(cfg)


class FlipBackend(FakeBackend):
    """The watched value flips to a new one after the Nth read() call."""

    def __init__(self, flip_after: int, new_value: int, **kwargs):
        super().__init__(**kwargs)
        self._reads = 0
        self._flip_after = flip_after
        self._new_value = new_value

    def read(self, address: int, size: int) -> bytes:
        self._reads += 1
        if self._reads > self._flip_after:
            self.write(address, struct.pack("<i", self._new_value))
        return super().read(address, size)


class StepBackend(FakeBackend):
    """Every read() bumps the value, so each poll observes a change."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._reads = 0

    def read(self, address: int, size: int) -> bytes:
        self._reads += 1
        self.write(address, struct.pack("<i", self._reads))
        return super().read(address, size)


# ----------------------------------------------------------------- watch_run
def test_watch_run_no_changes(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.watch_run(sid, address=hex(BASE), type="int32", interval=0.01, iterations=10)
    assert out["stable"] is True
    assert out["change_count"] == 0
    assert out["changes"] == []
    assert out["initial_value"] == 1000
    assert out["final_value"] == 1000
    assert out["iterations"] == 10


def test_watch_run_detects_change(tmp_path, monkeypatch):
    # initial read + 2 unchanged polls, then the value flips
    fake = FlipBackend(flip_after=3, new_value=777, regions={BASE: bytearray(struct.pack("<i", 100) + b"\x00" * 0x40)})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.watch_run(sid, address=hex(BASE), type="int32", interval=0.01, iterations=6)
    assert out["change_count"] == 1
    assert out["stable"] is False
    assert out["initial_value"] == 100
    assert out["final_value"] == 777
    assert len(out["changes"]) == 1
    ch = out["changes"][0]
    assert ch["old"] == 100 and ch["new"] == 777
    assert ch["iteration"] == 3
    assert isinstance(ch["ts"], float) and ch["ts"] > 0


def test_watch_run_changes_cap(tmp_path, monkeypatch):
    fake = StepBackend(regions={BASE: bytearray(struct.pack("<i", 0) + b"\x00" * 0x40)})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.watch_run(sid, address=hex(BASE), type="int32", interval=0.01, iterations=70)
    assert out["change_count"] == 70  # every poll changed the value
    assert len(out["changes"]) == svc.WATCH_MAX_CHANGES  # list is capped
    assert out["changes"][-1]["iteration"] == 70  # the newest entries survive
    assert out["changes"][0]["iteration"] == 70 - svc.WATCH_MAX_CHANGES + 1


def test_watch_run_read_failure(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.watch_run(sid, address="0x990000", type="int32", interval=0.01, iterations=5)
    assert out["ok"] is False
    assert out["error"]["code"] == "E_READ_FAILED"


# -------------------------------------------------------------- watch_report
def test_watch_report_empty(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.watch_report(sid)
    assert out["change_count"] == 0
    assert out["changes"] == []


def test_watch_report_reads_jsonl(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    path = svc.store.watch_jsonl_path(sid)
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [
        {"iteration": 1, "ts": 1.0, "old": 10, "new": 20},
        {"iteration": 2, "ts": 2.0, "old": 20, "new": 30},
        {"iteration": 3, "ts": 3.0, "old": 30, "new": 40},
    ]
    path.write_text("".join(json.dumps(r) + "\n" for r in records) + "{bad json\n", encoding="utf-8")

    out = svc.watch_report(sid, limit=2)
    assert out["change_count"] == 3  # corrupted line skipped
    assert out["returned"] == 2
    assert out["changes"] == records[-2:]  # most recent last


# ----------------------------------------------------------------------- CLI
def test_cli_watch_parsing():
    from game_modifier.cli import build_parser

    p = build_parser()

    args = p.parse_args(["watch", "run", "--session", "s1", "--address", "0x100",
                         "--type", "float32", "--interval", "0.2", "--iterations", "5"])
    assert args.command == "watch" and args.watch_action == "run"
    assert args.address == "0x100" and args.type == "float32"
    assert args.interval == pytest.approx(0.2) and args.iterations == 5
    assert args.log is None

    args = p.parse_args(["watch", "start", "--session", "s1", "--address", "0x100"])
    assert args.watch_action == "start" and args.interval == pytest.approx(0.1)

    args = p.parse_args(["watch", "stop", "--session", "s1"])
    assert args.watch_action == "stop"

    args = p.parse_args(["watch", "report", "--session", "s1", "--limit", "10"])
    assert args.watch_action == "report" and args.limit == 10


# ----------------------------------------------------------------------- MCP
def test_mcp_watch_registered(tmp_path):
    pytest.importorskip("mcp")
    from game_modifier import mcp_server
    from test_mcp_extended import _tool_names

    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    server = mcp_server.build_server(str(cfg))
    names = _tool_names(server)
    assert {"watch_run", "watch_start", "watch_stop", "watch_report"} <= names

    ro = mcp_server.build_server(str(cfg), profile="readonly")
    ro_names = _tool_names(ro)
    assert {"watch_run", "watch_report"} <= ro_names  # read-only tools stay available
    assert not ({"watch_start", "watch_stop"} & ro_names)  # worker control is gated

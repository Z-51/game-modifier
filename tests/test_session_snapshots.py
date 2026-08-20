"""Session state snapshots: save/list/restore with automatic pre-restore backup.

Covers SessionStore snapshot methods, ModifierService wrappers, the new
``session snapshot|snapshots|restore`` CLI subcommands and MCP registration.
"""

from __future__ import annotations

import struct

import pytest

from game_modifier.cli import _normalize_session_argv, build_parser
from game_modifier.errors import GameModifierError
from game_modifier.memory import process as procmod
from game_modifier.memory.base import ModuleInfo
from game_modifier.service import ModifierService


# ---------------------------------------------------------------------------
# fixtures (same fake-backend wiring as test_mcp_extended)
# ---------------------------------------------------------------------------

@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x1000)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={0x200000: region}, modules=[mod], name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


# ---------------------------------------------------------------------------
# store + service behaviour
# ---------------------------------------------------------------------------

def test_snapshot_save_list(service, tmp_config):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.gold", base_expr="0x200000", type="int32")

    res = svc.session_snapshot(sid, name="before_scan")
    assert res["name"] == "before_scan"
    assert res["path"].endswith("before_scan.json")
    assert (tmp_config.sessions_dir / sid / "snapshots" / "before_scan.json").exists()

    listing = svc.session_snapshots(sid)
    assert listing["session_id"] == sid
    entries = listing["snapshots"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["name"] == "before_scan"
    assert entry["size"] > 0 and entry["created_at"] > 0

    # the snapshot is a faithful copy of the session JSON state
    snap = svc.store.load_snapshot(sid, "before_scan")
    assert snap is not None and "player.gold" in snap["symbols"]


def test_snapshot_restore(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.gold", base_expr="0x200000", type="int32")
    svc.session_snapshot(sid, name="clean")

    # state drifts after the snapshot
    svc.name_set(session_id=sid, name="player.hp", base_expr="0x200004", type="int32")
    assert "player.hp" in svc.session_info(session_id=sid)["symbols"]

    res = svc.session_restore(sid, name="clean")
    assert res["restored"] is True
    assert "attach" in res["note"]  # warns that the process may have moved on

    # symbol table rolled back to the snapshot
    symbols = svc.session_info(session_id=sid)["symbols"]
    assert symbols == ["player.gold"]


def test_snapshot_restore_prebackup(service, tmp_config):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.gold", base_expr="0x200000", type="int32")
    svc.session_snapshot(sid, name="clean")
    svc.name_set(session_id=sid, name="player.hp", base_expr="0x200004", type="int32")

    res = svc.session_restore(sid, name="clean")
    pre = tmp_config.sessions_dir / sid / "snapshots" / "clean.pre-restore.json"
    assert pre.exists(), "the pre-restore backup must be written before overwriting"
    assert res["pre_restore_backup"] == str(pre)

    # the archived state still carries the post-snapshot symbol
    import json

    archived = json.loads(pre.read_text(encoding="utf-8"))
    assert "player.hp" in archived["symbols"]

    # pre-restore backups never show up in listings
    names = [e["name"] for e in svc.session_snapshots(sid)["snapshots"]]
    assert names == ["clean"]


def test_snapshot_missing(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    assert svc.session_snapshots(sid)["snapshots"] == []
    assert svc.store.load_snapshot(sid, "nope") is None

    with pytest.raises(GameModifierError) as ei:
        svc.session_restore(sid, name="nope")
    assert ei.value.code.value == "E_INVALID_ARGS"

    # invalid names are rejected too
    with pytest.raises(GameModifierError):
        svc.session_snapshot(sid, name="../evil")


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

def test_cli_snapshot_parsing():
    p = build_parser()

    a = p.parse_args(_normalize_session_argv(["session", "snapshot", "s1", "--session", "sid"]))
    assert (a.command, a.session_action, a.name, a.session) == ("session", "snapshot", "s1", "sid")

    b = p.parse_args(_normalize_session_argv(["session", "snapshots", "--session", "sid"]))
    assert (b.command, b.session_action, b.session) == ("session", "snapshots", "sid")

    c = p.parse_args(_normalize_session_argv(["session", "restore", "s1", "--session", "sid"]))
    assert (c.command, c.session_action, c.name, c.session) == ("session", "restore", "s1", "sid")

    # backward compat: bare `session <id>` still resolves to session info
    d = p.parse_args(_normalize_session_argv(["session", "abc123"]))
    assert d.session_action == "info" and d.session_id == "abc123"

    # global options before the command do not break normalization
    e = p.parse_args(_normalize_session_argv(["--json", "session", "abc"]))
    assert e.session_action == "info" and e.session_id == "abc"


# ---------------------------------------------------------------------------
# MCP registration
# ---------------------------------------------------------------------------

def test_mcp_snapshot_registered(tmp_path):
    pytest.importorskip("mcp")
    from game_modifier import mcp_server

    cfg = tmp_path / "cfg.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    def _names(server) -> set[str]:
        tm = getattr(server, "_tool_manager", None)
        if tm is not None and hasattr(tm, "_tools"):
            return set(tm._tools.keys())
        import asyncio

        return {t.name for t in asyncio.run(server.list_tools())}

    default = _names(mcp_server.build_server(str(cfg)))
    assert {"session_snapshot", "session_snapshots", "session_restore"} <= default

    ro = _names(mcp_server.build_server(str(cfg), profile="readonly"))
    assert "session_snapshots" in ro          # listing is read-only
    assert "session_snapshot" not in ro       # saving mutates session state
    assert "session_restore" not in ro        # restore overwrites the session JSON

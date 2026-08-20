"""Temp symbols and pointer-chain intermediate state retention (Task #47).

Covers: ``name set --temp``, ``name get`` temp visibility, ``name clear-temp``,
and ``name chain`` which walks a multi-level pointer chain and registers every
intermediate address as a ``<name>.stepN`` symbol (temp by default, persistable).

FakeBackend layout (multi-level chain)::

    Game.exe base = 0x140000000
    [0x140000010]  -> 0x500000          (base expr "Game.exe+0x10")
    [0x500020]     -> 0x600000          (offset[0] = 0x20)
    [0x600008]     -> 0x700000          (offset[1] = 0x8)
    final 0x700004 holds int32 12345    (offset[2] = 0x4)
"""

from __future__ import annotations

import json
import struct

import pytest

from game_modifier import mcp_server
from game_modifier.cli import build_parser
from game_modifier.errors import ErrorCode, GameModifierError
from game_modifier.memory import process as procmod
from game_modifier.memory.base import ModuleInfo
from game_modifier.memory import types as vt
from game_modifier.service import ModifierService
from game_modifier.session import Session, SessionStore
from test_mcp_extended import _tool_names

MOD_BASE = 0x140000000
STEP0 = MOD_BASE + 0x10   # resolved base of "Game.exe+0x10"
STEP1 = 0x500000 + 0x20   # after offset[0]
STEP2 = 0x600000 + 0x8    # after offset[1]
FINAL = 0x700000 + 0x4    # after offset[2]
OFFSETS = "0x20,0x8,0x4"


@pytest.fixture
def chain_service(tmp_config, fake_backend_factory, monkeypatch):
    """Service + fake backend wired with a 3-level pointer chain."""
    regions = {
        MOD_BASE: bytearray(0x1000),
        0x500000: bytearray(0x1000),
        0x600000: bytearray(0x1000),
        0x700000: bytearray(0x1000),
    }
    mod = ModuleInfo(name="Game.exe", base=MOD_BASE, size=0x1000, path="C:/games/Game.exe")
    fake = fake_backend_factory(regions=regions, modules=[mod], name="Game.exe", pid=4242)
    fake.write(STEP0, struct.pack("<Q", 0x500000))
    fake.write(STEP1, struct.pack("<Q", 0x600000))
    fake.write(STEP2, struct.pack("<Q", 0x700000))
    fake.write(FINAL, struct.pack("<i", 12345))

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]
    return service, fake, sid


# ------------------------------------------------------------------- temp flag
def test_name_set_temp_flag(chain_service):
    service, _, sid = chain_service
    out = service.name_set(session_id=sid, name="tmp.gold", base_expr="0x700004", temp=True)
    assert out["temp"] is True

    sym = service._load(sid).get_symbol("tmp.gold")
    assert sym is not None and sym.temp is True
    assert sym.to_dict()["temp"] is True

    # default stays persistent (no temp marker anywhere)
    out2 = service.name_set(session_id=sid, name="perm.gold", base_expr="0x700004")
    assert "temp" not in out2
    perm = service._load(sid).get_symbol("perm.gold")
    assert perm.temp is False
    assert "temp" not in perm.to_dict()


def test_name_get_shows_temp(chain_service):
    service, _, sid = chain_service
    service.name_set(session_id=sid, name="perm.a", base_expr="0x700004")
    service.name_set(session_id=sid, name="tmp.b", base_expr="0x700004", temp=True)

    listing = {s["name"]: s for s in service.name_get(session_id=sid)["symbols"]}
    assert listing["tmp.b"].get("temp") is True
    assert "temp" not in listing["perm.a"]

    # include_temp=False filters the transient ones out
    names = [s["name"] for s in service.name_get(session_id=sid, include_temp=False)["symbols"]]
    assert "perm.a" in names and "tmp.b" not in names

    # single-symbol lookup also carries the marker
    assert service.name_get(session_id=sid, name="tmp.b")["temp"] is True


def test_name_clear_temp(chain_service):
    service, _, sid = chain_service
    service.name_set(session_id=sid, name="perm.keep", base_expr="0x700004")
    service.name_set(session_id=sid, name="tmp.x", base_expr="0x700004", temp=True)
    service.name_set(session_id=sid, name="tmp.y", base_expr="0x700004", temp=True)

    out = service.name_clear_temp(session_id=sid)
    assert out["removed"] == ["tmp.x", "tmp.y"]
    assert out["count"] == 2

    session = service._load(sid)
    assert "perm.keep" in session.symbols
    assert "tmp.x" not in session.symbols and "tmp.y" not in session.symbols


# ------------------------------------------------------------------ name_chain
def test_name_chain_registers_steps(chain_service):
    service, _, sid = chain_service
    out = service.name_chain(sid, name="mgr", base="Game.exe+0x10", offsets=OFFSETS)

    assert out["depth"] == 3
    assert out["temp"] is True
    session = service._load(sid)
    for n in ("mgr.step0", "mgr.step1", "mgr.step2", "mgr"):
        assert n in session.symbols, f"missing {n}"
        assert session.symbols[n]["temp"] is True
    # no surplus step symbol beyond the penultimate level
    assert "mgr.step3" not in session.symbols


def test_name_chain_values_correct(chain_service):
    service, fake, sid = chain_service
    out = service.name_chain(sid, name="mgr", base="Game.exe+0x10", offsets=OFFSETS)

    assert out["final"] == hex(FINAL)
    assert out["final_address"] == FINAL
    by_name = {s["symbol"]: s["address_value"] for s in out["steps"]}
    assert by_name["mgr.step0"] == STEP0
    assert by_name["mgr.step1"] == STEP1
    assert by_name["mgr.step2"] == STEP2
    assert by_name["mgr"] == FINAL

    # the final symbol resolves back to the planted value via a plain read
    res = service.read(session_id=sid, symbol="mgr", type="int32")
    assert res["value"] == 12345
    # intermediates read back the next-hop pointer (uint64 by default)
    assert service.read(session_id=sid, symbol="mgr.step1")["value"] == 0x600000


def test_name_chain_partial_failure(chain_service):
    service, fake, sid = chain_service
    # break the chain: the third hop points into unmapped memory
    fake.write(STEP1, struct.pack("<Q", 0xDEAD0000))

    with pytest.raises(GameModifierError) as ei:
        service.name_chain(sid, name="brk", base="Game.exe+0x10", offsets=OFFSETS)
    exc = ei.value
    assert exc.code == ErrorCode.INVALID_POINTER
    assert exc.details["failed_step"] == 2
    assert exc.details["read_at"] == hex(0xDEAD0000 + 0x8)
    assert exc.details["registered"] == ["brk.step0", "brk.step1", "brk.step2"]

    # already-registered intermediates survive (session persisted) for resume
    session = service._load(sid)
    assert session.get_symbol("brk.step1").base_expr == hex(STEP1)
    assert session.get_symbol("brk.step2").base_expr == hex(0xDEAD0000 + 0x8)
    assert "brk" not in session.symbols  # final never registered


def test_name_chain_persist_option(chain_service):
    service, _, sid = chain_service
    out = service.name_chain(sid, name="root", base="Game.exe+0x10", offsets=OFFSETS, temp=False)
    assert out["temp"] is False

    session = service._load(sid)
    for n in ("root.step0", "root.step1", "root.step2", "root"):
        assert session.symbols[n]["temp"] is False

    # clear-temp must not touch persisted chain symbols
    cleared = service.name_clear_temp(session_id=sid)
    assert cleared["count"] == 0
    assert "root" in service._load(sid).symbols


# -------------------------------------------------------------------- compat
def test_symbol_old_json_compat(tmp_path):
    old = {
        "id": "legacy-sym", "pid": 1, "process_name": "game.exe",
        "exe_path": "", "arch": "x64", "platform": "windows",
        "engine": {}, "anti_cheat": {}, "modules": {},
        "symbols": {
            "player.gold": {
                "name": "player.gold", "base_expr": "0x700004",
                "offsets": [], "type": "int32", "description": "", "mode": "",
            }
        },
        "freezes": [], "scan": {}, "save_edit_info": {},
    }
    session = Session.from_dict(old)
    sym = session.get_symbol("player.gold")
    assert sym is not None and sym.temp is False
    # round-trip does not invent a temp field for persistent symbols
    assert "temp" not in sym.to_dict()

    store = SessionStore(tmp_path)
    store.dir.mkdir(parents=True, exist_ok=True)
    (store.dir / "legacy-sym.json").write_text(json.dumps(old), encoding="utf-8")
    assert store.load("legacy-sym").get_symbol("player.gold").temp is False


# ------------------------------------------------------------------- CLI/MCP
def test_cli_name_chain_parsing():
    p = build_parser()

    a = p.parse_args(["name", "chain", "mgr", "--session", "s1",
                      "--base", "Game.exe+0x10", "--offsets", OFFSETS,
                      "--type", "uint64", "--persist"])
    assert a.command == "name" and a.name_action == "chain"
    assert a.name == "mgr" and a.session == "s1"
    assert a.base == "Game.exe+0x10" and a.offsets == OFFSETS
    assert a.type == "uint64" and a.persist is True

    # defaults: uint64, transient
    a = p.parse_args(["name", "chain", "mgr", "--session", "s1", "--base", "0x100"])
    assert a.type == "uint64" and a.persist is False and a.offsets is None

    a = p.parse_args(["name", "set", "player.gold", "--session", "s1",
                      "--base", "0x700004", "--temp"])
    assert a.name_action == "set" and a.temp is True

    a = p.parse_args(["name", "clear-temp", "--session", "s1"])
    assert a.name_action == "clear-temp" and a.session == "s1"

    a = p.parse_args(["name", "get", "--session", "s1", "--no-include-temp"])
    assert a.name_action == "get" and a.include_temp is False
    a = p.parse_args(["name", "get", "--session", "s1"])
    assert a.include_temp is True  # default lists everything


def test_mcp_name_chain_registered(tmp_path):
    cfg = tmp_path / "cfg.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    server = mcp_server.build_server(str(cfg))
    names = _tool_names(server)
    assert {"name_set", "name_chain", "name_clear_temp"} <= names

    # both mutate session state -> excluded from the readonly profile
    ro = mcp_server.build_server(str(cfg), profile="readonly")
    ro_names = _tool_names(ro)
    assert "name_chain" not in ro_names
    assert "name_clear_temp" not in ro_names
    assert "name_get" in ro_names

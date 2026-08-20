"""field_chain pointer mode: offset+deref struct-field chains (Task #56).

``field_chain`` walks nested struct fields (``addr = read(addr + offset)``),
the semantics of ``gem.__data.MainPowerData.mPowerType``-style access, as
opposed to ``pointer_chain`` (Cheat Engine deref+offset) and ``relative``
(plain addition).

FakeBackend layout (nested struct ``gem.__data.MainPowerData.mPowerType``)::

    gem  = 0x200000        [gem+0x10]  -> data = 0x300000   (__data pointer)
    data = 0x300000        [data+0x20] -> mpd  = 0x400000   (MainPowerData ptr)
    mpd  = 0x400000        [mpd+0x08]  -> tgt  = 0x500000   (mPowerType slot)
    tgt  = 0x500000        [tgt]       = int32 42

    [gem] = gem            (self-pointer so pointer_chain walks on the same
                            layout and yields a *different* final address)
"""

from __future__ import annotations

import struct

import pytest

from game_modifier import mcp_server
from game_modifier.cli import build_parser
from game_modifier.errors import ErrorCode, GameModifierError, InvalidArgsError
from game_modifier.memory import pointers
from game_modifier.memory import process as procmod
from game_modifier.memory import types as vt
from game_modifier.memory.base import ModuleInfo
from game_modifier.service import ModifierService

GEM = 0x200000
DATA = 0x300000
MPD = 0x400000
TGT = 0x500000
FIELD_SLOT = MPD + 0x08       # [mpd+0x08] = mPowerType slot
OFFSETS = "0x10,0x20,0x08"


def _plant(fake, value_at_tgt=42):
    fake.write(GEM, struct.pack("<Q", GEM))          # pointer_chain anchor
    fake.write(GEM + 0x10, struct.pack("<Q", DATA))  # gem.__data
    fake.write(DATA + 0x20, struct.pack("<Q", MPD))  # __data.MainPowerData
    fake.write(FIELD_SLOT, struct.pack("<Q", TGT))   # MainPowerData.mPowerType
    fake.write(TGT, struct.pack("<i", value_at_tgt))


@pytest.fixture
def field_backend(fake_backend_factory):
    regions = {GEM: bytearray(0x1000), DATA: bytearray(0x1000),
               MPD: bytearray(0x1000), TGT: bytearray(0x1000)}
    fake = fake_backend_factory(regions=regions, name="Game.exe")
    _plant(fake)
    return fake


@pytest.fixture
def field_service(tmp_config, fake_backend_factory, monkeypatch):
    """Service + fake backend wired with the nested struct layout."""
    regions = {GEM: bytearray(0x1000), DATA: bytearray(0x1000),
               MPD: bytearray(0x1000), TGT: bytearray(0x1000)}
    fake = fake_backend_factory(regions=regions, name="Game.exe", pid=4242)
    _plant(fake)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]
    return service, fake, sid


# ------------------------------------------------------------ resolve_pointer
def test_field_chain_deref(field_backend):
    # gem -> __data -> MainPowerData -> mPowerType (deref'd by default)
    info = pointers.resolve_pointer(field_backend, hex(GEM), OFFSETS, mode="field_chain")
    assert info["mode"] == "field_chain"
    assert info["final_address"] == TGT
    assert vt.decode_value("int32", field_backend.read(TGT, 4)) == 42


def test_field_chain_deref_last_false(field_backend):
    # value-typed field: stop after the final offset, no dereference
    field_backend.write(FIELD_SLOT, struct.pack("<i", 7))
    info = pointers.resolve_pointer(field_backend, hex(GEM), OFFSETS,
                                    mode="field_chain", deref_last=False)
    assert info["final_address"] == FIELD_SLOT
    assert vt.decode_value("int32", field_backend.read(info["final_address"], 4)) == 7


def test_field_chain_vs_pointer_chain(field_backend):
    # identical base + offsets, the two semantics MUST diverge:
    # pointer_chain: read[GEM]+0x10, read[GEM+0x10]+0x20, read[DATA+0x20]+0x08
    pc = pointers.resolve_pointer(field_backend, hex(GEM), OFFSETS, mode="pointer_chain")
    assert pc["final_address"] == FIELD_SLOT      # ends at the slot address
    # field_chain: read[GEM+0x10], read[DATA+0x20], read[MPD+0x08]
    fc = pointers.resolve_pointer(field_backend, hex(GEM), OFFSETS, mode="field_chain")
    assert fc["final_address"] == TGT             # ends at the dereferenced target
    assert pc["final_address"] != fc["final_address"]


def test_field_chain_trace(field_backend):
    info = pointers.resolve_pointer(field_backend, hex(GEM), OFFSETS, mode="field_chain")
    trace = info["trace"]
    assert trace[0]["stage"] == "base" and trace[0]["address_hex"] == hex(GEM)
    steps = trace[1:]
    assert len(steps) == 3
    for i, entry in enumerate(steps):
        assert entry["stage"] == f"offset[{i}]"
        assert entry["step"] == i
        assert entry["op"] == "offset+deref"      # default derefs every step
        for key in ("offset_hex", "addr_before_hex", "addr_after_hex",
                    "read_at_hex", "deref_hex", "address_hex"):
            assert key in entry
    # walk values recorded correctly
    assert steps[0]["addr_before_hex"] == hex(GEM)
    assert steps[0]["read_at_hex"] == hex(GEM + 0x10)
    assert steps[0]["deref_hex"] == hex(DATA)
    assert steps[1]["read_at_hex"] == hex(DATA + 0x20)
    assert steps[1]["deref_hex"] == hex(MPD)
    assert steps[2]["read_at_hex"] == hex(FIELD_SLOT)
    assert steps[2]["deref_hex"] == hex(TGT)

    # deref_last=False: the final step is tagged plain "offset" (no deref)
    info2 = pointers.resolve_pointer(field_backend, hex(GEM), OFFSETS,
                                     mode="field_chain", deref_last=False)
    last = info2["trace"][-1]
    assert last["op"] == "offset"
    assert "read_at_hex" not in last and "deref_hex" not in last
    assert last["address_hex"] == hex(FIELD_SLOT)


def test_field_chain_mid_failure(field_backend):
    # break the chain: __data.MainPowerData points into unmapped memory
    field_backend.write(DATA + 0x20, struct.pack("<Q", 0xDEAD0000))

    with pytest.raises(GameModifierError) as ei:
        pointers.resolve_pointer(field_backend, hex(GEM), OFFSETS, mode="field_chain")
    exc = ei.value
    assert exc.code == ErrorCode.INVALID_POINTER
    assert exc.details["failed_step"] == 2
    assert exc.details["read_at"] == hex(0xDEAD0000 + 0x08)
    # the successfully walked steps survive in the trace
    trace = exc.details["trace"]
    good = [e for e in trace if e.get("op") == "offset+deref" and "error" not in e]
    assert len(good) == 2
    assert good[0]["deref_hex"] == hex(DATA)
    assert good[1]["deref_hex"] == hex(0xDEAD0000)


# ---------------------------------------------------------------- service API
def test_field_chain_via_resolve_service(field_service):
    service, _, sid = field_service
    out = service.resolve(session_id=sid, base_expr=hex(GEM), offsets=OFFSETS,
                          mode="field_chain")
    assert out["final_address"] == TGT

    out2 = service.resolve(session_id=sid, base_expr=hex(GEM), offsets=OFFSETS,
                           mode="field_chain", deref_last=False)
    assert out2["final_address"] == FIELD_SLOT


def test_field_chain_name_chain(field_service):
    service, _, sid = field_service
    out = service.name_chain(sid, name="gem", base=hex(GEM), offsets=OFFSETS,
                             mode="field_chain")
    assert out["depth"] == 3
    # final offset step is not dereferenced -> the symbol addresses the slot
    assert out["final"] == hex(FIELD_SLOT)
    by_name = {s["symbol"]: s["address_value"] for s in out["steps"]}
    assert by_name["gem.step0"] == GEM
    assert by_name["gem.step1"] == DATA      # deref of [gem+0x10]
    assert by_name["gem.step2"] == MPD       # deref of [data+0x20]
    assert by_name["gem"] == FIELD_SLOT      # slot itself, no final deref

    session = service._load(sid)
    for n in ("gem.step0", "gem.step1", "gem.step2", "gem"):
        assert n in session.symbols
    # the slot symbol reads back the planted pointer (uint64 by default)
    assert service.read(session_id=sid, symbol="gem")["value"] == TGT


def test_name_set_field_chain_mode(field_service):
    service, _, sid = field_service
    out = service.name_set(session_id=sid, name="gem.power", base_expr=hex(GEM),
                           offsets=OFFSETS, type="int32", mode="field_chain")
    assert out["mode"] == "field_chain"

    # the stored mode is honored on later reads: final = deref'd target
    res = service.read(session_id=sid, symbol="gem.power")
    assert res["address_hex"] == hex(TGT)
    assert res["value"] == 42
    assert res["mode"] == "field_chain"


def test_invalid_mode(field_service):
    service, fake, sid = field_service
    with pytest.raises(InvalidArgsError) as ei:
        pointers.resolve_pointer(fake, hex(GEM), OFFSETS, mode="bogus")
    assert ei.value.details["supported"] == ["pointer_chain", "relative", "field_chain"]

    with pytest.raises(GameModifierError) as ei2:
        service.name_set(session_id=sid, name="x.y", base_expr=hex(GEM), mode="bogus")
    assert ei2.value.code == ErrorCode.INVALID_ARGS
    assert ei2.value.details["supported"] == ["pointer_chain", "relative", "field_chain"]

    # relative is not meaningful for a multi-level chain walk
    with pytest.raises(GameModifierError) as ei3:
        service.name_chain(sid, name="z", base=hex(GEM), offsets=OFFSETS, mode="relative")
    assert ei3.value.code == ErrorCode.INVALID_ARGS


# ------------------------------------------------------------------- regress
def test_existing_modes_unchanged(fake_backend_factory):
    """relative / pointer_chain behavior + trace shape must not change."""
    mod = ModuleInfo(name="Game.exe", base=0x140000000, size=0x10000, path="Game.exe")
    regions = {0x140000000: bytearray(0x1000), 0x500000: bytearray(0x1000)}
    be = fake_backend_factory(regions=regions, modules=[mod])
    be.write(0x140000000 + 0x10, struct.pack("<Q", 0x500000))
    be.write(0x500000 + 0x20, struct.pack("<i", 777))

    # pointer_chain (CE semantics): deref then add offset
    pc = pointers.resolve_pointer(be, "Game.exe+0x10", [0x20])
    assert pc["mode"] == "pointer_chain"
    assert pc["final_address"] == 0x500000 + 0x20
    step = pc["trace"][1]
    assert step == {"stage": "offset[0]", "read_at_hex": hex(0x140000000 + 0x10),
                    "deref_hex": hex(0x500000), "offset_hex": hex(0x20),
                    "address_hex": hex(0x500000 + 0x20)}
    assert vt.decode_value("int32", be.read(pc["final_address"], 4)) == 777

    # relative: plain addition, no dereference
    rel = pointers.resolve_pointer(be, "0x140000010", [0x10], mode="relative")
    assert rel["mode"] == "relative"
    assert rel["final_address"] == 0x140000000 + 0x20
    assert rel["trace"][1] == {"stage": "relative", "offset_hex": hex(0x10),
                               "address_hex": hex(0x140000000 + 0x20)}


# ------------------------------------------------------------------ CLI / MCP
def test_cli_field_chain_parsing():
    p = build_parser()

    a = p.parse_args(["resolve", "--session", "s1", "--base", "0x200000",
                      "--offsets", OFFSETS, "--mode", "field_chain", "--no-deref-last"])
    assert a.command == "resolve"
    assert a.mode == "field_chain" and a.deref_last is False

    # default: deref_last stays true; mode default unchanged (pointer_chain)
    a = p.parse_args(["resolve", "--session", "s1", "--base", "0x200000"])
    assert a.mode == "pointer_chain" and a.deref_last is True

    a = p.parse_args(["name", "chain", "gem", "--session", "s1",
                      "--base", "0x200000", "--offsets", OFFSETS,
                      "--mode", "field_chain"])
    assert a.name_action == "chain" and a.mode == "field_chain"

    a = p.parse_args(["name", "chain", "gem", "--session", "s1", "--base", "0x200000"])
    assert a.mode is None  # unset -> historical pointer_chain behavior

    # read / modify / name set accept the new choice too
    a = p.parse_args(["read", "--session", "s1", "--address", "0x200000",
                      "--mode", "field_chain"])
    assert a.mode == "field_chain"
    a = p.parse_args(["name", "set", "gem.power", "--session", "s1",
                      "--base", "0x200000", "--mode", "field_chain"])
    assert a.mode == "field_chain"

    with pytest.raises(SystemExit):
        p.parse_args(["resolve", "--session", "s1", "--base", "0x1", "--mode", "bogus"])


def test_mcp_resolve_deref_last(tmp_path):
    pytest.importorskip("mcp")
    cfg = tmp_path / "cfg.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    server = mcp_server.build_server(str(cfg))

    tm = server._tool_manager
    tool = tm._tools["resolve"]
    schema = None
    for attr in ("parameters", "input_schema", "inputSchema"):
        val = getattr(tool, attr, None)
        if callable(val):
            try:
                val = val()
            except Exception:
                val = None
        if isinstance(val, dict):
            schema = val
            break
    assert schema is not None, "resolve tool schema not found"
    props = schema["properties"]
    assert "deref_last" in props and props["deref_last"].get("default") is True
    assert "mode" in props
    assert "deref_last" not in schema.get("required", [])  # optional, backward compatible

    # name_chain gained the mode selector
    nc = tm._tools["name_chain"]
    nc_schema = None
    for attr in ("parameters", "input_schema", "inputSchema"):
        val = getattr(nc, attr, None)
        if callable(val):
            try:
                val = val()
            except Exception:
                val = None
        if isinstance(val, dict):
            nc_schema = val
            break
    assert nc_schema is not None and "mode" in nc_schema["properties"]

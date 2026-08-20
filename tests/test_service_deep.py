"""Deep service-level tests: freeze, symbols, dry-run, scans, guards."""

from __future__ import annotations

import struct

import pytest

from game_modifier.errors import ErrorCode, GameModifierError, SymbolNotFoundError
from game_modifier.memory import process as procmod
from game_modifier.memory.base import ModuleInfo
from game_modifier.service import ModifierService

BASE = 0x200000


def _build_service(tmp_config, monkeypatch, fake):
    import game_modifier.service as svc_module

    monkeypatch.setattr(svc_module, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config)


@pytest.fixture
def deep_service(tmp_config, fake_backend_factory, monkeypatch):
    # region layout: three int32 = 77 at +0/+4/+8, one int32 = 1000 at +12, then zeros
    region = bytearray(struct.pack("<iiii", 77, 77, 77, 1000) + b"\x00" * 0x100)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={BASE: region}, modules=[mod], name="fake.exe", pid=4242)
    svc = _build_service(tmp_config, monkeypatch, fake)
    return svc, fake


# ----------------------------------------------------------------- freeze
def test_freeze_register_and_run(deep_service):
    svc, fake = deep_service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.hp", base_expr=hex(BASE), type="int32")

    res = svc.modify(session_id=sid, symbol="player.hp", value=42, confirm=True, freeze=True)
    assert res["applied"] is True and res["freeze"] is True, "confirmed freeze-modify must apply"
    assert svc.freeze_list(session_id=sid)["count"] == 1, "freeze must be registered"

    # simulate the game overwriting the value, then run the freeze loop
    fake.write(BASE, struct.pack("<i", 1))
    out = svc.freeze_run(session_id=sid, interval=0.0, iterations=2)
    assert out["loops"] == 2, f"loop must run exactly 2 iterations, got {out['loops']}"
    assert out["writes"] == 2, f"one freeze x 2 loops = 2 writes, got {out['writes']}"
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 42, "freeze loop must restore the frozen value"


def test_freeze_clear(deep_service):
    svc, _ = deep_service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.hp", base_expr=hex(BASE), type="int32")
    svc.modify(session_id=sid, symbol="player.hp", value=42, confirm=True, freeze=True)
    assert svc.freeze_list(session_id=sid)["count"] == 1

    out = svc.freeze_clear(session_id=sid)
    assert out["cleared"] == 1, f"one freeze should have been cleared, got {out['cleared']}"
    assert svc.freeze_list(session_id=sid)["count"] == 0, "no freezes must remain after clear"
    # running with no freezes is a no-op
    assert svc.freeze_run(session_id=sid, iterations=1)["frozen"] == 0, "empty freeze list must short-circuit"


# ---------------------------------------------------------------- symbols
def test_symbol_set_get(deep_service):
    svc, _ = deep_service
    sid = svc.attach(pid=4242)["session_id"]
    out = svc.name_set(session_id=sid, name="player.gold", base_expr="fake.exe+0x10",
                       offsets="0x20,0x8", type="int32", description="gold")
    assert out["offsets"] == ["0x20", "0x8"], f"offsets must be parsed and echoed, got {out['offsets']}"

    sym = svc.name_get(session_id=sid, name="player.gold")
    assert sym["base_expr"] == "fake.exe+0x10", "stored base expression must round-trip"
    assert sym["type"] == "int32" and sym["description"] == "gold", "type/description must persist"

    all_syms = svc.name_get(session_id=sid)
    assert [s["name"] for s in all_syms["symbols"]] == ["player.gold"], "listing must contain the symbol"


def test_symbol_invalid_raises(deep_service):
    svc, _ = deep_service
    sid = svc.attach(pid=4242)["session_id"]
    with pytest.raises(SymbolNotFoundError) as exc:
        svc.name_get(session_id=sid, name="no.such.symbol")
    assert exc.value.code == ErrorCode.SYMBOL_NOT_FOUND, f"wrong error code: {exc.value.code}"


# ----------------------------------------------------------------- modify
def test_modify_dry_run_default(deep_service):
    svc, fake = deep_service
    sid = svc.attach(pid=4242)["session_id"]
    res = svc.modify(session_id=sid, address=hex(BASE), type="int32", value=555)
    assert res["applied"] is False and res["dry_run"] is True, "modify without confirm must stay dry-run"
    assert "hint" in res, "dry-run response must tell the caller how to apply"
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 77, "memory must be untouched on dry-run"


def test_modify_confirm_writes(deep_service):
    svc, fake = deep_service
    sid = svc.attach(pid=4242)["session_id"]
    res = svc.modify(session_id=sid, address=hex(BASE), type="int32", value=555, confirm=True)
    assert res["applied"] is True and res["dry_run"] is False, "confirmed modify must apply"
    assert res["old_value"] == 77 and res["verified_value"] == 555, "old/verified values must be reported"
    assert res["backup_id"], "auto_backup must create a backup for a confirmed write"
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 555, "memory must hold the new value"


# ------------------------------------------------------------------- scan
def test_scan_next_incremental(deep_service):
    svc, fake = deep_service
    sid = svc.attach(pid=4242)["session_id"]

    first = svc.scan(session_id=sid, type="int32", value=77)
    assert first["count"] == 3, f"initial scan should find the three 77s, got {first['count']}"

    # game "increases" only the first candidate; narrow with increased
    fake.write(BASE, struct.pack("<i", 78))
    nxt = svc.scan_next(session_id=sid, comparator="increased")
    assert nxt["count"] == 1, f"increased filter should keep one candidate, got {nxt['count']}"
    assert nxt["addresses_hex"] == [hex(BASE)], "surviving candidate must be the mutated address"

    # a second refinement uses the updated candidate set from the session
    nxt2 = svc.scan_next(session_id=sid, comparator="exact", value=78)
    assert nxt2["count"] == 1, "exact refinement must confirm the single survivor"


# ------------------------------------------------------------------ guard
def test_anti_cheat_blocks_attach(tmp_config, fake_backend_factory, monkeypatch):
    eac = ModuleInfo(name="EasyAntiCheat_x64.dll", base=0x7FF000000000, size=0x1000, path="eac.dll")
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={BASE: bytearray(16)}, modules=[mod, eac], name="fake.exe", pid=4242)
    svc = _build_service(tmp_config, monkeypatch, fake)

    with pytest.raises(GameModifierError) as exc:
        svc.attach(pid=4242)
    assert exc.value.code == ErrorCode.ANTI_CHEAT, f"wrong error code: {exc.value.code}"
    assert "EasyAntiCheat" in exc.value.details.get("systems", []), "detection details must name the system"

    # explicit override still allows attaching (user accepts the risk)
    info = svc.attach(pid=4242, allow_anti_cheat=True)
    assert info["anti_cheat"]["detected"] is True, "override must keep the detection report"


# ---------------------------------------------------------------- max/min
def test_max_min_type_inference(deep_service):
    svc, fake = deep_service
    sid = svc.attach(pid=4242)["session_id"]

    res = svc.modify(session_id=sid, address=hex(BASE), type="int32", value="max", confirm=True)
    assert res["new_value"] == 2**31 - 1, f"int32 MAX must be 2147483647, got {res['new_value']}"
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 2**31 - 1, "memory must hold int32 max"

    res = svc.modify(session_id=sid, address=hex(BASE + 0x20), type="uint8", value="max", confirm=True)
    assert res["new_value"] == 255, f"uint8 MAX must be 255, got {res['new_value']}"

    res = svc.modify(session_id=sid, address=hex(BASE), type="int32", value="min", confirm=True)
    assert res["new_value"] == 0, "MIN for signed types is clamped to 0 (no negative stats)"


# ------------------------------------------------------------------- read
def test_read_unresolved_symbol(deep_service):
    svc, _ = deep_service
    sid = svc.attach(pid=4242)["session_id"]
    with pytest.raises(SymbolNotFoundError) as exc:
        svc.read(session_id=sid, symbol="player.ghost")
    assert exc.value.code == ErrorCode.SYMBOL_NOT_FOUND, f"wrong error code: {exc.value.code}"
    assert exc.value.details.get("known") == [], "error details must list known symbols (none yet)"

"""Deep tests for the safety subsystem: guard, backup, validation."""

from __future__ import annotations

import json

import pytest

from game_modifier import safety
from game_modifier.errors import (
    ErrorCode,
    GameModifierError,
    InvalidAddressError,
    InvalidTypeError,
    ValueOutOfRangeError,
)
from game_modifier.memory import types as vt
from game_modifier.safety.backup import BackupManager
from game_modifier.safety.guard import ANTI_CHEAT_SIGNATURES


# ------------------------------------------------------------------ guard
def test_detect_all_11_anti_cheat():
    # 11 original systems + 5 added in phase 1 (TenSafe/ACE, NEACProtect,
    # HackShield, Anti-Cheat Expert, VAC).
    assert len(ANTI_CHEAT_SIGNATURES) == 16, f"expected 16 known systems, got {len(ANTI_CHEAT_SIGNATURES)}"
    for system, fragments in ANTI_CHEAT_SIGNATURES.items():
        module = f"{fragments[0]}_x64.dll"
        res = safety.detect_anti_cheat([module], [])
        assert res["detected"] is True, f"{system} not detected via module {module!r}"
        assert system in res["systems"], f"{system} missing from systems list: {res['systems']}"
        assert any(h["where"] == "module" for h in res["hits"]), f"{system} hit must be tagged 'module'"


def test_detect_multiple_simultaneously():
    res = safety.detect_anti_cheat(
        ["EasyAntiCheat_x64.dll", "game.dll"],
        ["BEService.exe", "vgc.exe"],
    )
    assert res["detected"] is True, "at least one system present, must detect"
    assert set(res["systems"]) >= {"EasyAntiCheat", "BattlEye", "Riot Vanguard"}, (
        f"all three systems must be reported, got {res['systems']}"
    )
    assert len(res["hits"]) >= 3, f"one hit per matching name expected, got {res['hits']}"


def test_detect_case_insensitive():
    for name in ("EASYANTICHEAT.DLL", "EasyAntiCheat.dll", "easyanticheat.dll"):
        res = safety.detect_anti_cheat([name], [])
        assert res["detected"] is True, f"case variant {name!r} must be detected"
        assert "EasyAntiCheat" in res["systems"], f"{name!r} must map to EasyAntiCheat"


def test_detect_empty_inputs():
    res = safety.detect_anti_cheat([], [])
    assert res["detected"] is False, "empty inputs must report a clean result"
    assert res["systems"] == [] and res["hits"] == [], "no systems or hits expected"
    # empty / None-ish entries are ignored rather than crashing
    res2 = safety.detect_anti_cheat(["", None], ["", None])
    assert res2["detected"] is False, "blank names must be skipped safely"


# ----------------------------------------------------------------- backup
def test_backup_corrupted_json(tmp_path, fake_backend_factory):
    mgr = BackupManager(tmp_path / "backups")
    mgr.dir.mkdir(parents=True, exist_ok=True)
    (mgr.dir / "bak-corrupt.json").write_text("{not valid json", encoding="utf-8")

    # get() on the corrupted record surfaces the parse error
    with pytest.raises(json.JSONDecodeError):
        mgr.get("bak-corrupt")
    # list_backups() must skip the corrupted record instead of crashing
    assert all(b["id"] != "bak-corrupt" for b in mgr.list_backups()), "corrupted backup must be skipped"

    # a valid backup next to the corrupted one is still listed
    be = fake_backend_factory(regions={0x10000: bytearray(8)})
    rec = mgr.create(be, [{"address": 0x10000, "size": 4}])
    ids = [b["id"] for b in mgr.list_backups()]
    assert rec["id"] in ids, f"valid backup must survive a corrupted sibling, got {ids}"


def test_backup_nonexistent_raises(tmp_path):
    mgr = BackupManager(tmp_path / "backups")
    with pytest.raises(GameModifierError) as exc:
        mgr.get("bak-doesnotexist")
    assert exc.value.code == ErrorCode.BACKUP_NOT_FOUND, f"wrong error code: {exc.value.code}"
    assert exc.value.details.get("known") == [], "empty dir must report no known backups"


def test_backup_empty_targets(tmp_path, fake_backend_factory):
    be = fake_backend_factory(regions={0x10000: bytearray(8)})
    mgr = BackupManager(tmp_path / "backups")
    rec = mgr.create(be, [], label="empty")
    assert rec["entries"] == [], "no targets means no entries"
    # restoring an empty backup is a no-op, not an error
    out = mgr.restore(be, rec["id"])
    assert out["restored_count"] == 0 and out["failed_count"] == 0, "empty restore must be a clean no-op"


# -------------------------------------------------------------- validation
def test_validation_address_boundaries(fake_backend_factory):
    be = fake_backend_factory(regions={0x10000: bytearray(0x10)})

    with pytest.raises(InvalidAddressError):
        safety.validate_address(be, 0, 4)  # zero address
    with pytest.raises(InvalidAddressError):
        safety.validate_address(be, -8, 4)  # negative address
    with pytest.raises(InvalidAddressError):
        safety.validate_address(be, 0x50000, 4)  # unmapped address

    # last valid 4-byte slot ends exactly at the region end
    region = safety.validate_address(be, 0x1000C, 4)
    assert region is not None and region.contains(0x1000C, 4), "range ending at region end must pass"
    # one byte further spans outside the committed region
    with pytest.raises(InvalidAddressError):
        safety.validate_address(be, 0x1000D, 4)


def test_validation_all_types():
    samples = {
        "int8": -1, "uint8": 1, "int16": -2, "uint16": 2,
        "int32": -3, "uint32": 3, "int64": -4, "uint64": 4,
        "float": 1.25, "double": 2.5, "bool": True,
        "string": "ok", "string_utf16": "ok", "bytes": "90 90",
    }
    for name in vt.supported_types():
        dt = safety.validate_type(name)
        assert dt.name == name, f"validate_type must return the canonical type for {name}"
        canonical = safety.validate_value(name, samples[name])
        assert canonical is not None, f"validate_value must return a canonical value for {name}"
    with pytest.raises(InvalidTypeError):
        safety.validate_type("no_such_type")


def test_validation_value_overflow():
    overflows = [
        ("int8", 128), ("int8", -129),
        ("uint8", 256), ("uint8", -1),
        ("int16", 32768), ("uint16", 65536),
        ("int32", 2**31), ("uint32", 2**32),
        ("int64", 2**63), ("uint64", -1),
    ]
    for name, value in overflows:
        with pytest.raises(ValueOutOfRangeError):
            safety.validate_value(name, value)
    # boundary values themselves are accepted
    assert safety.validate_value("int8", 127) == 127, "int8 max must validate"
    assert safety.validate_value("uint8", 255) == 255, "uint8 max must validate"


def test_encoded_size_and_write_mode():
    assert safety.encoded_size("int32", 0) == 4, "fixed types report their struct size"
    assert safety.encoded_size("string", "abcd") == 4, "variable types report the encoded length"
    assert safety.resolve_write_mode(True, False) == "dry_run", "unconfirmed write stays dry-run"
    assert safety.resolve_write_mode(False, False) == "dry_run", "even with dry_run off, confirmation is required"
    assert safety.resolve_write_mode(True, True) == "apply", "confirmation applies the write"

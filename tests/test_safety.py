"""Safety: anti-cheat guard, validation, backup/restore."""

from __future__ import annotations

import struct

import pytest

from game_modifier import safety
from game_modifier.errors import InvalidAddressError, ValueOutOfRangeError
from game_modifier.safety.backup import BackupManager


def test_detect_anti_cheat_hit():
    res = safety.detect_anti_cheat(["EasyAntiCheat.dll", "game.exe"], [])
    assert res["detected"] is True
    assert "EasyAntiCheat" in res["systems"]


def test_detect_anti_cheat_from_process_list():
    res = safety.detect_anti_cheat(["game.dll"], ["BEService.exe"])
    assert res["detected"] is True
    assert "BattlEye" in res["systems"]


def test_detect_anti_cheat_clean():
    res = safety.detect_anti_cheat(["game.dll", "d3d11.dll"], ["explorer.exe"])
    assert res["detected"] is False


def test_validate_value_range():
    with pytest.raises(ValueOutOfRangeError):
        safety.validate_value("uint8", 999)
    assert safety.validate_value("int32", 100) == 100


def test_validate_address_ok(fake_backend_factory):
    be = fake_backend_factory(regions={0x10000: bytearray(0x100)})
    region = safety.validate_address(be, 0x10000, 4)
    assert region.writable


def test_validate_address_out_of_region(fake_backend_factory):
    be = fake_backend_factory(regions={0x10000: bytearray(0x10)})
    with pytest.raises(InvalidAddressError):
        safety.validate_address(be, 0x99999, 4)


def test_backup_and_restore_roundtrip(tmp_path, fake_backend_factory):
    be = fake_backend_factory(regions={0x10000: bytearray(struct.pack("<i", 1000) + b"\x00" * 12)})
    mgr = BackupManager(tmp_path / "backups")
    rec = mgr.create(be, [{"address": 0x10000, "size": 4}], label="test")
    # change memory
    be.write(0x10000, struct.pack("<i", 9999))
    assert struct.unpack("<i", be.read(0x10000, 4))[0] == 9999
    # restore
    out = mgr.restore(be, rec["id"])
    assert out["restored_count"] == 1
    assert struct.unpack("<i", be.read(0x10000, 4))[0] == 1000

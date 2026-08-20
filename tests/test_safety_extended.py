"""Phase-1 extensions: new error codes, guard signatures, write-span and
writability validation, dry-run impact reporting and batched reads."""

from __future__ import annotations

import struct

import pytest

from game_modifier.errors import (
    ErrorCode,
    GameModifierError,
    InvalidArgsError,
    LayoutUnsupportedError,
    PatternNotFoundError,
    ScanCacheStaleError,
    ScanTimeoutError,
)
from game_modifier.memory import process as procmod
from game_modifier.memory.base import MemoryRegion
from game_modifier.safety import detect_anti_cheat
from game_modifier.safety.guard import ANTI_CHEAT_SIGNATURES
from game_modifier.safety.validation import validate_write_span
from game_modifier.service import ModifierService

from conftest import FakeBackend


# ------------------------------------------------------------------ error codes
def test_new_error_codes_exist():
    expected = {
        "PATTERN_NOT_FOUND": "E_PATTERN_NOT_FOUND",
        "LAYOUT_UNSUPPORTED": "E_LAYOUT_UNSUPPORTED",
        "SCAN_TIMEOUT": "E_SCAN_TIMEOUT",
        "SCAN_CACHE_STALE": "E_SCAN_CACHE_STALE",
    }
    for name, value in expected.items():
        assert ErrorCode[name].value == value

    # subclasses default to their stable code
    for cls, code in [
        (PatternNotFoundError, ErrorCode.PATTERN_NOT_FOUND),
        (LayoutUnsupportedError, ErrorCode.LAYOUT_UNSUPPORTED),
        (ScanTimeoutError, ErrorCode.SCAN_TIMEOUT),
        (ScanCacheStaleError, ErrorCode.SCAN_CACHE_STALE),
    ]:
        exc = cls("boom")
        assert exc.code is code
        assert isinstance(exc, GameModifierError)


# ------------------------------------------------------------------ guard sigs
EXISTING_SIGNATURES = {
    "EasyAntiCheat": ["easyanticheat", "eac_launcher", "easyanticheat_eos"],
    "BattlEye": ["beservice", "beclient", "bedaisy", "battleye"],
    "Riot Vanguard": ["vgc", "vgk", "vanguard"],
    "nProtect GameGuard": ["gameguard", "gamemon", "npggnt", "npgg"],
    "XIGNCODE3": ["xigncode", "x3.xem", "xhunter"],
    "Denuvo Anti-Cheat": ["denuvoanti", "denuvo-anti"],
    "PunkBuster": ["pnkbstr", "punkbuster"],
    "mhyprot (miHoYo)": ["mhyprot"],
    "FACEIT": ["faceit"],
    "FairFight": ["fairfight"],
    "Ricochet (COD)": ["ricochet"],
}


def test_existing_signatures_unchanged():
    # the original 11 systems keep their exact signature lists (regression)
    for system, frags in EXISTING_SIGNATURES.items():
        assert ANTI_CHEAT_SIGNATURES[system] == frags
        # and they still trigger detection
        report = detect_anti_cheat([frags[0] + ".dll"])
        assert report["detected"] is True
        assert system in report["systems"]


def test_new_anti_cheat_signatures():
    cases = {
        "TenSafe/ACE (Tencent)": "TenSafe.dll",
        "NEACProtect (NetEase)": "NEACProtect.sys",
        "HackShield": "HackShield.bin",
        "Anti-Cheat Expert": "Anti-Cheat-Expert.dll",
        "VAC": "VACModule.dll",
    }
    for system, module in cases.items():
        assert system in ANTI_CHEAT_SIGNATURES
        report = detect_anti_cheat([module])
        assert report["detected"] is True
        assert system in report["systems"]

    # narrow VAC signature must not false-positive on plain Steam clients
    report = detect_anti_cheat(["steamclient64.dll", "valve_ags.dll"])
    assert "VAC" not in report["systems"]


# ------------------------------------------------------------------ write span
def test_validate_write_span_over_limit():
    with pytest.raises(InvalidArgsError) as ei:
        validate_write_span(8192, 4096)
    assert ei.value.code is ErrorCode.INVALID_ARGS
    assert ei.value.details["size"] == 8192


def test_validate_write_span_within_limit():
    validate_write_span(4, 4096)
    validate_write_span(4096, 4096)  # exactly at the limit passes


# ------------------------------------------------------------------ service-level
class ReadOnlyFakeBackend(FakeBackend):
    """FakeBackend whose queried regions report writable=False."""

    def query(self, address: int):
        base, buf = self._find(address)
        if buf is None:
            return None
        return MemoryRegion(base=base, size=len(buf), readable=True, writable=False, executable=False, state=0x1000)


@pytest.fixture
def service(tmp_config, monkeypatch):
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x100)
    fake = FakeBackend(regions={0x200000: region}, name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


def test_require_writable_rejects_readonly(tmp_config, monkeypatch):
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x100)
    fake = ReadOnlyFakeBackend(regions={0x200000: region}, name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]

    with pytest.raises(GameModifierError) as ei:
        service.modify(session_id=sid, address="0x200000", type="int32", value="9999", confirm=False)
    assert ei.value.code is ErrorCode.ADDRESS_NOT_WRITABLE


def test_dry_run_impact_field(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]

    dry = svc.modify(session_id=sid, address="0x200000", type="int32", value="9999", confirm=False)
    assert dry["dry_run"] is True and dry["applied"] is False
    impact = dry["impact"]
    assert impact["address_hex"] == "0x200000"
    assert impact["size"] == 4
    assert impact["old_value"] == 1000
    assert impact["new_value"] == 9999
    assert impact["region"]["writable"] is True
    assert impact["backup_would_create"] is True
    # nothing was actually written
    assert struct.unpack("<i", fake.read(0x200000, 4))[0] == 1000


# ------------------------------------------------------------------ read_many
def test_read_many_default(fake_backend_factory):
    data = struct.pack("<iii", 11, 22, 33) + b"\x00" * 0x10
    fake = fake_backend_factory(regions={0x1000: bytearray(data)})

    out = fake.read_many([0x1000, 0x1004, 0x1008], 4)
    assert out == {
        0x1000: struct.pack("<i", 11),
        0x1004: struct.pack("<i", 22),
        0x1008: struct.pack("<i", 33),
    }


def test_read_many_skip_failed(fake_backend_factory):
    data = struct.pack("<ii", 5, 6)
    fake = fake_backend_factory(regions={0x1000: bytearray(data)})

    # 0x9999 is unmapped -> skipped, not raised
    out = fake.read_many([0x1000, 0x9999, 0x1004], 4)
    assert set(out) == {0x1000, 0x1004}
    assert out[0x1000] == struct.pack("<i", 5)
    assert out[0x1004] == struct.pack("<i", 6)

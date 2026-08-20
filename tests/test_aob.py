"""Tests for AOB pattern scanning and variable-length next_scan comparators."""

from __future__ import annotations

import pytest

from game_modifier.errors import InvalidArgsError, PatternNotFoundError
from game_modifier.memory import aob, scanner
from game_modifier.memory import process as procmod
from game_modifier.service import ModifierService


# ---------------------------------------------------------------- parse_pattern
def test_parse_pattern_basic():
    values, mask = aob.parse_pattern("48 8B 05")
    assert values == b"\x48\x8b\x05"
    assert mask == b"\x01\x01\x01"


def test_parse_pattern_wildcards():
    values, mask = aob.parse_pattern("48 ?? 05")
    assert values[0] == 0x48 and values[2] == 0x05
    assert mask == b"\x01\x00\x01"
    # single '?' also works, comma separators accepted
    _, mask2 = aob.parse_pattern("48, ?, 05")
    assert mask2 == b"\x01\x00\x01"


def test_parse_pattern_invalid():
    for bad in ("", "   ", "zz 12", "48 g 05", "4", "123"):
        with pytest.raises(InvalidArgsError):
            aob.parse_pattern(bad)


def test_parse_pattern_all_wildcards():
    with pytest.raises(InvalidArgsError):
        aob.parse_pattern("?? ?? ?")


# -------------------------------------------------------------------- aob_scan
def test_aob_scan_single_hit(fake_backend_factory):
    region = bytearray(b"\x00" * 8 + b"\x48\x8b\x05\x12\x34" + b"\x00" * 8)
    be = fake_backend_factory(regions={0x10000: region})
    res = aob.aob_scan(be, "48 8B 05 12 34")
    assert res["count"] == 1
    assert res["truncated"] is False
    assert res["addresses_hex"] == [hex(0x10008)]
    assert res["scanned_regions"] == 1
    assert res["scanned_bytes"] == len(region)


def test_aob_scan_multiple_hits(fake_backend_factory):
    needle = b"\xde\xad\xbe\xef"
    region = bytearray()
    expected = []
    for i in range(5):
        expected.append(0x20000 + len(region) + 2)
        region += b"\x00\x00" + needle
    be = fake_backend_factory(regions={0x20000: region})

    full = aob.aob_scan(be, "DE AD BE EF")
    assert full["count"] == 5
    assert full["addresses"] == expected

    cut = aob.aob_scan(be, "DE AD BE EF", max_results=2)
    assert cut["count"] == 2
    assert cut["truncated"] is True
    assert cut["addresses"] == expected[:2]


def test_aob_scan_cross_chunk_boundary(fake_backend_factory):
    region = bytearray(64)
    region[14:18] = b"\xde\xad\xbe\xef"  # straddles the 16-byte chunk edge
    be = fake_backend_factory(regions={0x1000: region})
    res = aob.aob_scan(be, "DE AD BE EF", chunk_size=16)
    assert res["count"] == 1, "match straddling a chunk boundary must be found exactly once"
    assert res["addresses_hex"] == [hex(0x1000 + 14)]


def test_aob_scan_wildcard_match(fake_backend_factory):
    region = bytearray(b"\x11" + b"\xaa\x7f\xcc" + b"\x22" + b"\xaa\x00\xcc")
    be = fake_backend_factory(regions={0x30000: region})
    res = aob.aob_scan(be, "AA ?? CC")
    assert res["count"] == 2, "wildcard position must match any byte"
    assert res["addresses"] == [0x30001, 0x30005]


def test_aob_scan_no_hit(fake_backend_factory):
    be = fake_backend_factory(regions={0x10000: bytearray(b"\x00" * 64)})
    with pytest.raises(PatternNotFoundError):
        aob.aob_scan(be, "FF EE DD")


# ------------------------------------------------- varlen next_scan comparators
def test_varlen_next_scan_changed(fake_backend_factory):
    buf = bytearray(b"\x00\x00" + b"gold\x00" + b"\x00" * 96)
    be = fake_backend_factory(regions={0x40000: buf})

    first = scanner.first_scan(be, "string", "gold")
    assert first.count == 1
    addr = first.addresses[0]
    assert addr == 0x40002
    assert first.values[addr] == "gold"

    # unchanged while memory still holds the old value
    res = scanner.next_scan(be, "string", first.addresses, comparator="unchanged", previous=first.values)
    assert res.count == 1
    res = scanner.next_scan(be, "string", first.addresses, comparator="changed", previous=first.values)
    assert res.count == 0

    # mutate in place (FakeBackend copies the buffer, so write through it)
    be.write(addr, b"silv")
    res = scanner.next_scan(be, "string", first.addresses, comparator="changed", previous=first.values)
    assert res.count == 1 and res.addresses == [addr]
    assert res.values[addr] == "silv"
    res = scanner.next_scan(be, "string", first.addresses, comparator="unchanged", previous=first.values)
    assert res.count == 0

    # numeric comparators remain unsupported for variable-length types
    with pytest.raises(InvalidArgsError):
        scanner.next_scan(be, "string", first.addresses, comparator="increased", previous=first.values)


# ------------------------------------------------------------- service layer
@pytest.fixture
def aob_service(tmp_config, fake_backend_factory, monkeypatch):
    region = bytearray(b"\x00" * 0x10 + b"\x48\x8b\xc3\x90" + b"\x00" * 0x10)
    fake = fake_backend_factory(regions={0x200000: region}, name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


def test_service_scan_aob(aob_service):
    service, _ = aob_service
    sid = service.attach(pid=4242)["session_id"]

    out = service.scan_aob(sid, pattern="48 8B ?? 90", max_results=10)
    assert out["count"] == 1
    assert out["addresses_hex"] == [hex(0x200010)]
    assert out["truncated"] is False

    # the candidate set is persisted in the session ScanState for reuse
    session = service.store.load(sid)
    assert session.scan.type == "bytes"
    assert session.scan.addresses == [0x200010]
    assert session.scan.count == 1

    # a missing signature raises PatternNotFoundError (structured E_PATTERN_NOT_FOUND)
    with pytest.raises(PatternNotFoundError):
        service.scan_aob(sid, pattern="FF FF FF FF 42")

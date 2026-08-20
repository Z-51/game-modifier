"""Deep tests for the value scanner (first_scan / next_scan edge cases)."""

from __future__ import annotations

import struct
import warnings

from game_modifier.memory import scanner
from game_modifier.memory import types as vt


def _region_with_values(base, values, type_name="int32"):
    buf = bytearray()
    for v in values:
        buf += vt.encode_value(type_name, v)
    return {base: buf}


# ------------------------------------------------------------- comparators
def test_first_scan_gt(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x10000, [10, 20, 30]))
    res = scanner.first_scan(be, "int32", 15, comparator="gt", alignment=4)
    assert res.count == 2, f"expected 2 values > 15, got {res.count}"
    assert set(res.values.values()) == {20, 30}, "gt should keep only 20 and 30"


def test_first_scan_lt(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x10000, [10, 20, 30]))
    res = scanner.first_scan(be, "int32", 25, comparator="lt", alignment=4)
    assert res.count == 2, f"expected 2 values < 25, got {res.count}"
    assert set(res.values.values()) == {10, 20}, "lt should keep only 10 and 20"


def test_first_scan_gte(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x10000, [10, 20, 30]))
    res = scanner.first_scan(be, "int32", 20, comparator="gte", alignment=4)
    assert res.count == 2, f"expected 2 values >= 20, got {res.count}"
    assert set(res.values.values()) == {20, 30}, "gte must include the boundary value 20"


def test_first_scan_lte(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x10000, [10, 20, 30]))
    res = scanner.first_scan(be, "int32", 20, comparator="lte", alignment=4)
    assert res.count == 2, f"expected 2 values <= 20, got {res.count}"
    assert set(res.values.values()) == {10, 20}, "lte must include the boundary value 20"


def test_first_scan_not_equal(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x10000, [5, 5, 7]))
    res = scanner.first_scan(be, "int32", 5, comparator="not_equal", alignment=4)
    assert res.count == 1, f"expected 1 value != 5, got {res.count}"
    assert list(res.values.values()) == [7], "only the 7 should survive not_equal 5"


def test_first_scan_unknown(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x10000, [1, 2, 3]))
    res = scanner.first_scan(be, "int32", None, comparator="unknown", alignment=4)
    assert res.count == 3, f"unknown comparator must match every aligned slot, got {res.count}"
    assert res.values[0x10000] == 1 and res.values[0x10008] == 3, "unknown scan must record current values"


# --------------------------------------------------------------- next scan
def test_next_scan_unchanged(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x20000, [7, 7, 7]))
    first = scanner.first_scan(be, "int32", 7, alignment=4)
    assert first.count == 3
    be.write(0x20000, struct.pack("<i", 99))  # mutate the first candidate
    nxt = scanner.next_scan(be, "int32", first.addresses, comparator="unchanged", previous=first.values)
    assert nxt.count == 2, f"expected 2 unchanged candidates, got {nxt.count}"
    assert 0x20000 not in nxt.addresses, "mutated address must be filtered out by 'unchanged'"


def test_next_scan_increased(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x20000, [10, 10, 10]))
    first = scanner.first_scan(be, "int32", 10, alignment=4)
    be.write(0x20004, struct.pack("<i", 50))   # increased
    be.write(0x20008, struct.pack("<i", 1))    # decreased
    nxt = scanner.next_scan(be, "int32", first.addresses, comparator="increased", previous=first.values)
    assert nxt.addresses == [0x20004], f"only the increased slot should survive, got {nxt.addresses}"
    assert nxt.values[0x20004] == 50, "new value must be re-read from memory"


def test_next_scan_decreased(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x20000, [10, 10, 10]))
    first = scanner.first_scan(be, "int32", 10, alignment=4)
    be.write(0x20004, struct.pack("<i", 50))   # increased
    be.write(0x20008, struct.pack("<i", 1))    # decreased
    nxt = scanner.next_scan(be, "int32", first.addresses, comparator="decreased", previous=first.values)
    assert nxt.addresses == [0x20008], f"only the decreased slot should survive, got {nxt.addresses}"
    assert nxt.values[0x20008] == 1, "new value must be re-read from memory"


# ----------------------------------------------------------- chunk/alignment
def test_first_scan_alignment_boundary(fake_backend_factory):
    # value straddles the chunk boundary (chunk_size=8, value at offset 6)
    buf = bytearray(16)
    buf[6:10] = struct.pack("<i", 0x11223344)
    be = fake_backend_factory(regions={0x30000: buf})
    res = scanner.first_scan(be, "int32", 0x11223344, alignment=1, chunk_size=8)
    assert 0x30006 in res.addresses, (
        f"value straddling the chunk boundary must still be found, got {list(map(hex, res.addresses))}"
    )
    assert res.count == 1, f"expected exactly one hit, got {res.count}"


def test_first_scan_read_fails_graceful(fake_backend_factory, monkeypatch):
    be = fake_backend_factory(regions={0x40000: bytearray(16)})

    def _boom(address, size):
        raise RuntimeError("simulated read failure")

    monkeypatch.setattr(be, "read", _boom)
    res = scanner.first_scan(be, "int32", 0, alignment=4)
    assert res.count == 0, "a failing read must not produce candidates"
    assert res.scanned_regions == 1, "the region should still be counted as visited"
    assert res.scanned_bytes == 0, "no bytes were actually read"


def test_first_scan_truncate_at_max(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x50000, [9] * 10))
    res = scanner.first_scan(be, "int32", 9, alignment=4, max_results=3)
    assert res.truncated is True, "hitting max_results must set truncated"
    assert res.count == 3, f"result must be capped at max_results=3, got {res.count}"
    assert len(res.addresses) == 3, "address list must also be capped"


def test_first_scan_empty_regions(fake_backend_factory):
    be = fake_backend_factory(regions={})
    res = scanner.first_scan(be, "int32", 42, alignment=4)
    assert res.count == 0, "no regions means no results"
    assert res.scanned_regions == 0, "no regions should have been scanned"
    assert res.addresses == [], "address list must be empty"


def test_next_scan_empty_addresses(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x60000, [1, 2, 3]))
    res = scanner.next_scan(be, "int32", [], comparator="exact", value=1)
    assert res.count == 0, "empty candidate set must yield an empty result"
    assert res.addresses == [] and res.values == {}, "no addresses or values expected"


# --------------------------------------------------------- performance paths
def test_next_scan_batch_read_equivalence(fake_backend_factory):
    """Grouped span reads must produce the exact same result as per-address reads."""

    regions = {
        0x10000: bytearray(struct.pack("<iii", 1, 2, 3)),
        0x11000: bytearray(struct.pack("<ii", 2, 9)),
        0x12000: bytearray(struct.pack("<i", 7)),
    }
    candidates = [0x10000, 0x10004, 0x10008, 0x11000, 0x11004, 0x12000, 0xDEAD0000]

    for comparator, kwargs in (
        ("exact", {"value": 2}),
        ("gt", {"value": 2}),
        ("changed", {"previous": {a: 2 for a in candidates if a != 0xDEAD0000}}),
    ):
        be = fake_backend_factory(regions=regions)
        a = scanner.next_scan(be, "int32", list(candidates), comparator=comparator, use_batch_read=True, **kwargs)
        be2 = fake_backend_factory(regions=regions)
        b = scanner.next_scan(be2, "int32", list(candidates), comparator=comparator, use_batch_read=False, **kwargs)
        assert a.to_dict() == b.to_dict(), f"batch and sequential next_scan diverge for {comparator}"

    # the unmapped candidate is skipped either way
    be = fake_backend_factory(regions=regions)
    res = scanner.next_scan(be, "int32", list(candidates), comparator="exact", value=2)
    assert 0xDEAD0000 not in res.addresses, "unreadable candidates must be skipped"
    assert res.addresses == [0x10004, 0x11000], f"unexpected survivors: {list(map(hex, res.addresses))}"


def test_next_scan_batch_read_fewer_calls(fake_backend_factory):
    """Contiguous candidates collapse into one span read per region."""

    be = fake_backend_factory(regions={0x10000: bytearray(struct.pack("<iiii", 1, 2, 3, 4))})
    calls = {"read": 0}
    orig_read = be.read

    def counting(address, size):
        calls["read"] += 1
        return orig_read(address, size)

    be.read = counting
    scanner.next_scan(be, "int32", [0x10000, 0x10004, 0x10008, 0x1000C], comparator="exact", value=2, use_batch_read=True)
    assert calls["read"] == 1, f"one contiguous span must need a single read, got {calls['read']}"


def _worker_regions():
    return {
        0x10000: bytearray(struct.pack("<ii", 5, 9)),
        0x10800: bytearray(struct.pack("<ii", 5, 5)),
        0x11000: bytearray(struct.pack("<ii", 9, 5)),
        0x11800: bytearray(struct.pack("<ii", 5, 1)),
    }


def test_workers_consistency(fake_backend_factory):
    """workers>1 with a backend factory yields the identical candidate set."""

    regions = _worker_regions()
    assert scanner.first_scan(fake_backend_factory(regions=regions), "int32", 5, alignment=4).count == 5, \
        "sanity: five slots across the four regions hold the value 5"

    for comparator_args in ({"value": 5}, {"comparator": "unknown", "value": None}):
        comparator = comparator_args.get("comparator", "exact")
        value = comparator_args.get("value")
        ref = scanner.first_scan(fake_backend_factory(regions=regions), "int32", value,
                                 comparator=comparator, alignment=4)
        factory = lambda: fake_backend_factory(regions=regions)  # noqa: E731 - fresh backend per worker
        par = scanner.first_scan(factory(), "int32", value,
                                 comparator=comparator,
                                 alignment=4, workers=3, backend_factory=factory)
        assert par.addresses == ref.addresses, f"parallel scan must keep region-ordered results ({comparator})"
        assert par.values == ref.values
        assert par.count == ref.count and par.scanned_regions == ref.scanned_regions


def test_workers_without_factory_falls_back(fake_backend_factory):
    regions = _worker_regions()
    be = fake_backend_factory(regions=regions)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        res = scanner.first_scan(be, "int32", 5, alignment=4, workers=4)
    assert res.count == 5, "fallback must still produce the full result"
    assert any("single-threaded" in str(w.message) for w in caught), "missing factory must warn about the fallback"


def test_vector_scalar_equivalence(fake_backend_factory, monkeypatch):
    """The numpy path must match the pure-Python slot loop byte-for-byte.

    Covers alignment == size and alignment < size (multi-offset views) across
    every first-scan comparator; the scalar result is produced by hiding numpy
    from the scanner module.
    """

    if scanner._np is None:
        import pytest

        pytest.skip("numpy not installed; the vector path is inactive")

    buf = bytearray()
    for i in range(64):
        buf += struct.pack("<i", i % 7)
    regions = {0x400040: buf}  # unaligned base exercises the lead correction

    cases = [
        ("exact", 3, None, 4),
        ("exact", 3, None, 2),   # alignment < size -> multi-offset views
        ("exact", 3, None, 1),
        ("gt", 4, None, 2),
        ("between", 2, 4, 2),
        ("not_equal", 0, None, 4),
    ]
    for comparator, value, value2, alignment in cases:
        vec = scanner.first_scan(
            fake_backend_factory(regions=regions), "int32", value,
            comparator=comparator, value2=value2, alignment=alignment, chunk_size=60,
        )
        monkeypatch.setattr(scanner, "_np", None)
        try:
            ref = scanner.first_scan(
                fake_backend_factory(regions=regions), "int32", value,
                comparator=comparator, value2=value2, alignment=alignment, chunk_size=60,
            )
        finally:
            monkeypatch.undo()
        assert vec.addresses == ref.addresses, f"address lists diverge ({comparator}, alignment={alignment})"
        assert vec.values == ref.values, f"values diverge ({comparator}, alignment={alignment})"
        assert vec.count == ref.count and vec.scanned_bytes == ref.scanned_bytes

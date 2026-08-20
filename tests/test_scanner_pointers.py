"""Scanner (first/next) and pointer resolution against the fake backend."""

from __future__ import annotations

import struct

from game_modifier.memory import scanner, pointers
from game_modifier.memory import types as vt
from game_modifier.memory.base import ModuleInfo


def _region_with_values(base, values, type_name="int32"):
    buf = bytearray()
    for v in values:
        buf += vt.encode_value(type_name, v)
    return {base: buf}


def test_first_scan_exact(fake_backend_factory):
    # three int32s: 100, 9999, 100
    be = fake_backend_factory(regions=_region_with_values(0x10000, [100, 9999, 100]))
    res = scanner.first_scan(be, "int32", 100, alignment=4)
    assert res.count == 2
    assert 0x10000 in res.addresses
    assert 0x10000 + 8 in res.addresses


def test_first_scan_between(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x20000, [10, 50, 90, 130], "int32"))
    res = scanner.first_scan(be, "int32", 40, comparator="between", value2=100, alignment=4)
    # 50 and 90 fall in [40,100]
    assert res.count == 2


def test_next_scan_narrows(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x30000, [7, 7, 8], "int32"))
    first = scanner.first_scan(be, "int32", 7, alignment=4)
    assert first.count == 2
    # change one of them to 8 in memory, then next-scan for changed
    be.write(0x30000, struct.pack("<i", 8))
    nxt = scanner.next_scan(be, "int32", first.addresses, comparator="changed", previous=first.values)
    assert nxt.count == 1
    assert nxt.addresses == [0x30000]


def test_next_scan_exact(fake_backend_factory):
    be = fake_backend_factory(regions=_region_with_values(0x40000, [5, 5, 5], "int32"))
    first = scanner.first_scan(be, "int32", 5, alignment=4)
    be.write(0x40000 + 4, struct.pack("<i", 42))
    nxt = scanner.next_scan(be, "int32", first.addresses, comparator="exact", value=5)
    assert nxt.count == 2


def test_pointer_chain(fake_backend_factory):
    # module base 0x140000000; at base+0x10 store a pointer to 0x500000; value at 0x500000+0x20
    mod = ModuleInfo(name="Game.exe", base=0x140000000, size=0x10000, path="Game.exe")
    regions = {
        0x140000000: bytearray(0x1000),
        0x500000: bytearray(0x1000),
    }
    be = fake_backend_factory(regions=regions, modules=[mod])
    # write pointer 0x500000 at module+0x10
    be.write(0x140000000 + 0x10, struct.pack("<Q", 0x500000))
    be.write(0x500000 + 0x20, struct.pack("<i", 777))

    info = pointers.resolve_pointer(be, "Game.exe+0x10", [0x20])
    assert info["final_address"] == 0x500000 + 0x20
    assert vt.decode_value("int32", be.read(info["final_address"], 4)) == 777


def test_parse_offsets_variants():
    assert pointers.parse_offsets("0x10,0x20") == [0x10, 0x20]
    assert pointers.parse_offsets(["0x8", "16"]) == [0x8, 16]
    assert pointers.parse_offsets(None) == []

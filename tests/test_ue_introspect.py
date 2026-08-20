"""UE structure introspection tests on a synthetic FakeBackend memory image.

Builds a fake TUObjectArray (2 chunks, 0x18 item stride, increasing
SerialNumbers), a fake FNamePool (Ansi entries) and an "Object" -> "Actor" ->
"MyActor" UClass chain, mirroring the fixture style of test_layout.py.
"""

from __future__ import annotations

import time

import pytest

from conftest import FakeBackend

from game_modifier.engines import ue_introspect
from game_modifier.engines.ue_introspect import (
    compare_fname,
    decode_fname,
    enumerate_actors,
    introspect,
    read_fname,
)
from game_modifier.errors import ScanTimeoutError

# ------------------------------------------------------------------ addresses
BASE = 0x400000
GOBJECTS = BASE + 0x10000
CHUNK_TABLE = BASE + 0x20000
CHUNK0 = BASE + 0x30000
CHUNK1 = BASE + 0x40000
GNAMES = BASE + 0x50000
BLOCKS_TABLE = BASE + 0x51000
BLOCK0 = BASE + 0x52000
C_OBJECT = BASE + 0x60000
C_ACTOR = BASE + 0x60100
C_MYACTOR = BASE + 0x60200
OBJ_BASE = BASE + 0x70000
FNAME_HANDLE = BASE + 0x80000

ITEM_STRIDE = 0x18
OBJECTS_PER_CHUNK = 25
N_OBJECTS = 50
OBJ_SPACING = 0x100
FNAME_STRIDE = 0xC
FNAME_NAMES = ["Object", "Actor", "MyActor", "Instance"]


def p64(v: int) -> bytes:
    return v.to_bytes(8, "little")


def p32(v: int) -> bytes:
    return v.to_bytes(4, "little")


def p16(v: int) -> bytes:
    return v.to_bytes(2, "little")


class CountingBackend(FakeBackend):
    """FakeBackend counting read() calls (for the O(chunks+groups) assertion)."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.read_calls = 0

    def read(self, address: int, size: int) -> bytes:
        self.read_calls += 1
        return super().read(address, size)


def _fname_entry(text: str) -> bytes:
    raw = text.encode("ascii")
    # uint16 header: length << 1 | wide-bit(0); string starts at +2
    return p16(len(raw) << 1) + raw + b"\x00"


def make_ue_backend(corrupt_items: bool = False) -> CountingBackend:
    buf = bytearray(0x100000)

    def put(addr: int, data: bytes) -> None:
        off = addr - BASE
        buf[off : off + len(data)] = data

    # TUObjectArray header: Objects* at +0x10, NumElements (i32) at +0x18
    put(GOBJECTS + 0x10, p64(CHUNK_TABLE))
    put(GOBJECTS + 0x18, p32(N_OBJECTS))
    # chunk pointer table (2 chunks)
    put(CHUNK_TABLE, p64(CHUNK0) + p64(CHUNK1))

    # FUObjectItem arrays: UObject* at +0, SerialNumber (i32) at +0x10
    for i in range(N_OBJECTS):
        chunk = CHUNK0 if i < OBJECTS_PER_CHUNK else CHUNK1
        local = i % OBJECTS_PER_CHUNK
        item = chunk + local * ITEM_STRIDE
        if corrupt_items:
            put(item, p64(0))           # not pointer-shaped
            put(item + 0x10, p32((1000 - i) & 0xFFFFFFFF))  # decreasing
        else:
            put(item, p64(OBJ_BASE + i * OBJ_SPACING))
            put(item + 0x10, p32(i + 1))  # strictly increasing

    # heap objects: ClassPrivate at +0x10, FName (index/number) at +0x18
    for i in range(N_OBJECTS):
        obj = OBJ_BASE + i * OBJ_SPACING
        put(obj + 0x10, p64(C_MYACTOR))
        put(obj + 0x18, p32(3))  # "Instance"
        put(obj + 0x1C, p32(i))

    # UClass chain: Object <- Actor <- MyActor (NamePrivate +0x18, Super +0x40)
    put(C_OBJECT + 0x18, p32(0))
    put(C_OBJECT + 0x40, p64(0))
    put(C_ACTOR + 0x18, p32(1))
    put(C_ACTOR + 0x40, p64(C_OBJECT))
    put(C_MYACTOR + 0x18, p32(2))
    put(C_MYACTOR + 0x40, p64(C_ACTOR))

    # FNamePool: header -> block table -> block0 with Ansi entries
    put(GNAMES, p64(BLOCKS_TABLE))
    put(BLOCKS_TABLE, p64(BLOCK0))
    for idx, text in enumerate(FNAME_NAMES):
        put(BLOCK0 + idx * FNAME_STRIDE, _fname_entry(text))

    # a raw FName handle for read_fname
    put(FNAME_HANDLE, p32(2) + p32(7))

    return CountingBackend(regions={BASE: buf})


def _introspected(backend=None) -> tuple:
    backend = backend or make_ue_backend()
    layout = introspect(backend, gobjects=GOBJECTS, gnames=GNAMES,
                        objects_per_chunk=OBJECTS_PER_CHUNK)
    return backend, layout


FLAT_FNAME_LAYOUT = {
    "blocks_address": BLOCKS_TABLE,
    "per_chunk": 16384,
    "entry_stride": FNAME_STRIDE,
    "string_offset": 2,
    "wide": False,
}


# ---------------------------------------------------------------- introspect
def test_introspect_stride_detection():
    backend, res = _introspected()
    assert res["verdict"] == "confirmed"
    assert 0.8 < res["confidence"] <= 0.95
    hyp = res["hypotheses"]["item_stride"]
    assert hyp["chosen"] == 0x18
    assert hyp["confidence"] >= 0.8
    assert any("条目具指针形状" in e for e in hyp["evidence"])
    assert any(c["stride"] == 0x18 for c in hyp["candidates"])
    # chunk table verification
    assert res["hypotheses"]["chunks"]["confidence"] >= 0.8
    # resolved addresses
    resolved = res["resolved"]
    assert resolved["gobjects_array"] == hex(GOBJECTS)
    assert resolved["chunk_ptrs"] == hex(CHUNK_TABLE)
    assert resolved["num_elements"] == N_OBJECTS
    assert resolved["gnames_blocks"] == hex(BLOCKS_TABLE)
    assert resolved["item_stride"] == 0x18
    # fname dialect chosen
    chosen = res["hypotheses"]["fname_pool"]["chosen"]
    assert chosen["entry_stride"] == FNAME_STRIDE
    assert chosen["string_offset"] == 2
    assert chosen["wide"] is False


def test_introspect_wrong_stride_low_confidence():
    """Corrupted item arrays degrade the verdict instead of raising."""
    backend, res = _introspected(make_ue_backend(corrupt_items=True))
    assert res["verdict"] in ("partial", "failed")
    assert res["hypotheses"]["item_stride"]["confidence"] < 0.5


def test_introspect_unmapped_graceful():
    backend = make_ue_backend()
    res = introspect(backend, gobjects=0x99990000)  # not mapped anywhere
    assert res["verdict"] == "failed"
    assert res["hypotheses"]["item_stride"]["evidence"]
    assert res["confidence"] <= 0.1


def test_introspect_pattern_candidates_only():
    backend = make_ue_backend()
    backend._regions[BASE][0x90000 : 0x90004] = bytes.fromhex("deadbeef")
    res = introspect(backend, gobjects=None, gobjects_pattern="DE AD BE EF")
    assert res["candidates"]["gobjects"] == [hex(BASE + 0x90000)]
    # candidates are never auto-adopted: no probing happened
    assert res["verdict"] == "failed"
    assert "resolved" in res and res["resolved"] == {}


# --------------------------------------------------------- enumerate: basic
def test_enumerate_actors_basic():
    backend, layout = _introspected()
    res = enumerate_actors(backend, layout, list_results=True)
    assert res["by_class"]["MyActor"] == N_OBJECTS
    assert res["truncated"] is False
    assert res["skipped"] == 0
    assert len(res["actors"]) == N_OBJECTS
    first = res["actors"][0]
    assert first["address"] == hex(OBJ_BASE)
    assert first["class_name"] == "MyActor"
    assert first["name"] == "Instance"


def test_enumerate_actors_filter_limit():
    backend, layout = _introspected()
    # limit converges the stream
    res = enumerate_actors(backend, layout, limit=10, list_results=True)
    assert res["totals"]["actors"] == 10
    assert res["truncated"] is True
    assert len(res["actors"]) == 10
    # class filter (case-insensitive substring)
    assert enumerate_actors(backend, layout, class_filter="myact")["totals"]["actors"] == N_OBJECTS
    assert enumerate_actors(backend, layout, class_filter="Pawn")["totals"]["actors"] == 0
    # name filter
    assert enumerate_actors(backend, layout, name_filter="instance")["totals"]["actors"] == N_OBJECTS
    assert enumerate_actors(backend, layout, name_filter="zzz")["totals"]["actors"] == 0
    # max_objects caps how many GObjects entries are examined
    res = enumerate_actors(backend, layout, max_objects=10)
    assert res["totals"]["objects_examined"] <= 10
    assert res["totals"]["actors"] <= 10


def test_enumerate_actors_aggregate_view():
    backend, layout = _introspected()
    res = enumerate_actors(backend, layout)  # list_results=False
    assert res["by_class"] == {"MyActor": N_OBJECTS}
    assert res["totals"] == {"objects_examined": N_OBJECTS, "actors": N_OBJECTS, "unique_classes": 1}
    assert "actors" not in res  # aggregate view only
    assert res["elapsed"] >= 0


def test_enumerate_actors_empty_layout():
    backend = make_ue_backend()
    res = enumerate_actors(backend, {"resolved": {}})
    assert res["totals"]["actors"] == 0
    assert res["by_class"] == {}


# ---------------------------------------------------------------------- fname
def test_fname_decode_ansi():
    backend = make_ue_backend()
    assert decode_fname(backend, FLAT_FNAME_LAYOUT, 0) == "Object"
    assert decode_fname(backend, FLAT_FNAME_LAYOUT, 1) == "Actor"
    assert decode_fname(backend, FLAT_FNAME_LAYOUT, 2) == "MyActor"
    # cache deduplicates: no extra reads on a hit
    cache: dict = {}
    assert decode_fname(backend, FLAT_FNAME_LAYOUT, 3, cache=cache) == "Instance"
    before = backend.read_calls
    assert decode_fname(backend, FLAT_FNAME_LAYOUT, 3, cache=cache) == "Instance"
    assert backend.read_calls == before
    # decode also accepts the full introspect result as the layout
    _, layout = _introspected()
    assert decode_fname(backend, layout, 2) == "MyActor"


def test_fname_compare_index():
    backend = make_ue_backend()
    a = read_fname(backend, FNAME_HANDLE)
    assert a == {"comparison_index": 2, "number": 7}
    same = {"comparison_index": 2, "number": 99}
    diff = {"comparison_index": 3, "number": 7}
    res = compare_fname(a, same)
    assert res == {"equal": True, "basis": "index"}
    assert compare_fname(a, diff)["equal"] is False


# ----------------------------------------------------------------- efficiency
def test_read_counter_efficiency():
    """Enumeration reads scale with chunks+groups+caches, not O(N) objects."""
    backend, layout = _introspected()
    backend.read_calls = 0
    res = enumerate_actors(backend, layout)
    assert res["by_class"] == {"MyActor": N_OBJECTS}
    # 1 table read + 2 chunk reads + 2 span groups + 3 class reads
    # + 4 unique fname indices * 2 reads = 16 << N_OBJECTS
    assert backend.read_calls < N_OBJECTS
    assert backend.read_calls <= 20


# -------------------------------------------------------------------- timeout
def test_timeout_partial(monkeypatch):
    class _Clock:
        def __init__(self, step=8.0):
            self.t = 1000.0
            self.step = step

        def __call__(self):
            v = self.t
            self.t += self.step
            return v

    backend, layout = _introspected()
    monkeypatch.setattr(time, "monotonic", _Clock())
    with pytest.raises(ScanTimeoutError) as excinfo:
        enumerate_actors(backend, layout, timeout=30.0)
    details = excinfo.value.details
    # partial progress is carried on the exception
    assert details["objects_examined"] > 0
    assert details["actors_found"] > 0
    assert "by_class" in details


# --------------------------------------------------------------- package API
def test_engines_package_exports():
    from game_modifier import engines

    assert engines.ue_introspect is ue_introspect
    assert set(ue_introspect.__all__) == {
        "introspect", "enumerate_actors", "read_fname", "decode_fname", "compare_fname",
    }

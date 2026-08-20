"""Layout analysis tests (vtables / RTTI / class layout / heap) on FakeBackend."""

from __future__ import annotations

import pytest

from conftest import FakeBackend

from game_modifier.analysis import (
    find_rtti_classes,
    find_vtables,
    infer_alignment,
    infer_class_layout,
    looks_like_pointer,
    scan_heap_objects,
    to_text,
)
from game_modifier.cli import build_parser
from game_modifier.memory import process as procmod
from game_modifier.memory.base import MemoryRegion, ModuleInfo
from game_modifier.service import ModifierService

CODE = 0x100000
VTABLE = 0x200010


def p64(v: int) -> bytes:
    return v.to_bytes(8, "little")


def p32(v: int) -> bytes:
    return v.to_bytes(4, "little")


class LayoutBackend(FakeBackend):
    """FakeBackend with per-region executable/writable flags."""

    def __init__(self, flags=None, **kwargs):
        super().__init__(**kwargs)
        self._flags = flags or {}

    def regions(self):
        out = []
        for base, buf in self._regions.items():
            f = self._flags.get(base, {})
            out.append(
                MemoryRegion(
                    base=base,
                    size=len(buf),
                    readable=f.get("readable", True),
                    writable=f.get("writable", True),
                    executable=f.get("executable", False),
                    state=0x1000,
                )
            )
        return out


def make_vtable_backend(ptr_size: int = 8, slots: int = 5) -> LayoutBackend:
    """Data region holding one run of ``slots`` pointers into executable code."""

    pack = p64 if ptr_size == 8 else p32
    data = bytearray(0x100)
    for i in range(slots):
        target = CODE + 0x20 + i * 0x10
        off = 0x10 + i * ptr_size
        data[off : off + ptr_size] = pack(target)
    return LayoutBackend(
        regions={CODE: bytearray(0x1000), 0x200000: data},
        flags={CODE: {"executable": True, "writable": False}},
        arch="x64" if ptr_size == 8 else "x86",
    )


# ------------------------------------------------------------------ alignment
def test_infer_alignment():
    assert infer_alignment([0x1000, 0x1008, 0x1010]) == 8
    assert infer_alignment([0x1004, 0x100C]) == 4
    assert infer_alignment([0x1002, 0x1006]) == 2
    assert infer_alignment([0x1001, 0x1003]) == 1
    assert infer_alignment([]) == 1


def test_looks_like_pointer():
    region = MemoryRegion(base=0x10000, size=0x1000, readable=True, writable=True)
    assert looks_like_pointer(0x10080, [region], [], 8) is True
    assert looks_like_pointer(0x10083, [region], [], 8) is False  # misaligned
    assert looks_like_pointer(0x99999, [region], [], 8) is False  # outside
    assert looks_like_pointer(0, [region], [], 8) is False
    # module spans also count as targets
    module = ModuleInfo(name="game.exe", base=0x400000, size=0x1000)
    assert looks_like_pointer(0x400040, [], [module], 8) is True
    # x86: 4-byte alignment
    assert looks_like_pointer(0x10004, [region], [], 4) is True
    assert looks_like_pointer(0x10002, [region], [], 4) is False


# -------------------------------------------------------------------- vtables
def test_find_vtables():
    backend = make_vtable_backend()
    res = find_vtables(backend)
    assert res["truncated"] is False
    cand = [c for c in res["candidates"] if c["address"] == hex(VTABLE)]
    assert len(cand) == 1
    assert cand[0]["slots"] == 5
    assert 0.0 < cand[0]["confidence"] <= 0.95
    assert cand[0]["reason"]


def test_find_vtables_confidence():
    pack = p64
    data = bytearray(0x400)
    # cluster A: 3 slots at 0x200010
    for i in range(3):
        off = 0x10 + i * 8
        data[off : off + 8] = pack(CODE + 0x20 + i * 0x10)
    # cluster B: 8 slots at 0x200100
    for i in range(8):
        off = 0x100 + i * 8
        data[off : off + 8] = pack(CODE + 0x40 + i * 0x10)
    backend = LayoutBackend(
        regions={CODE: bytearray(0x1000), 0x200000: data},
        modules=[ModuleInfo(name="game.exe", base=CODE, size=0x1000)],
        flags={CODE: {"executable": True, "writable": False}},
    )
    res = find_vtables(backend)
    by_addr = {c["address"]: c for c in res["candidates"]}
    small, big = by_addr[hex(0x200010)], by_addr[hex(0x200100)]
    assert small["slots"] == 3 and big["slots"] == 8
    assert big["confidence"] > small["confidence"]
    assert big["confidence"] <= 0.95
    # module filter keeps candidates inside the module range
    filtered = find_vtables(backend, module_name="game.exe")
    assert any(c["address"] == hex(0x200010) for c in filtered["candidates"])


# ----------------------------------------------------------------------- rtti
def test_find_rtti_classes():
    blob = bytearray(0x100)
    blob[0x20 : 0x20 + 14] = b".?AVMyClass@@\x00"
    blob[0x60 : 0x60 + 11] = b".?AUGadget\x00"
    backend = LayoutBackend(regions={0x300000: blob})
    res = find_rtti_classes(backend)
    names = {c["name"]: c for c in res["classes"]}
    assert "MyClass" in names and "Gadget" in names
    assert names["MyClass"]["address"] == hex(0x300020)
    assert 0.0 < names["MyClass"]["confidence"] <= 0.95
    assert names["MyClass"]["reason"]
    # truncation cap
    res2 = find_rtti_classes(backend, max_results=1)
    assert res2["truncated"] is True and len(res2["classes"]) == 1


# ---------------------------------------------------------------- class layout
def make_instance_backend() -> LayoutBackend:
    heap = bytearray(0x400)
    for inst in (0x000, 0x040, 0x080):
        heap[inst : inst + 8] = p64(VTABLE)  # first word = vtable
        heap[inst + 8 : inst + 16] = (100).to_bytes(8, "little")  # stable int field
        heap[inst + 16 : inst + 24] = p64(CODE + 0x20)  # stable pointer field
    return LayoutBackend(
        regions={CODE: bytearray(0x1000), VTABLE - 0x10: bytearray(0x40), 0x200000: heap},
        flags={CODE: {"executable": True, "writable": False}},
    )


def test_infer_class_layout():
    backend = make_instance_backend()
    res = infer_class_layout(backend, VTABLE)
    assert res["instances_found"] == 3
    by_off = {f["offset"]: f for f in res["fields"]}
    assert by_off[8]["guessed_type"] == "uint64"
    assert by_off[8]["stability"] == 1.0
    assert by_off[16]["guessed_type"] == "ptr"
    assert 0.0 < res["confidence"] <= 0.95
    assert res["reason"]
    # unknown vtable -> nothing
    empty = infer_class_layout(backend, 0xDEAD0000)
    assert empty["instances_found"] == 0 and empty["fields"] == []


# ----------------------------------------------------------------------- heap
def test_scan_heap_objects():
    backend = make_instance_backend()
    # filtered by vtable: exactly the three instances
    res = scan_heap_objects(backend, vtable_addr=VTABLE)
    addrs = [o["address"] for o in res["objects"]]
    assert addrs == [hex(0x200000), hex(0x200040), hex(0x200080)]
    assert all(o["vtable"] == hex(VTABLE) for o in res["objects"])
    assert res["truncated"] is False
    # unfiltered: superset, vtable field is None
    res2 = scan_heap_objects(backend)
    addrs2 = {o["address"] for o in res2["objects"]}
    assert set(addrs).issubset(addrs2)
    assert all(o["vtable"] is None for o in res2["objects"])
    # max_results truncation
    res3 = scan_heap_objects(backend, vtable_addr=VTABLE, max_results=2)
    assert res3["truncated"] is True and len(res3["objects"]) == 2


# ----------------------------------------------------------------- x86 / x64
def test_layout_x86_x64():
    for arch, ptr_size in (("x64", 8), ("x86", 4)):
        backend = make_vtable_backend(ptr_size=ptr_size)
        assert backend.pointer_size == ptr_size
        res = find_vtables(backend)
        assert res["candidates"], f"no vtable found on {arch}"
        assert res["candidates"][0]["address"] == hex(VTABLE)
        assert res["candidates"][0]["slots"] == 5


# --------------------------------------------------------------------- report
def test_report_to_text():
    res = find_vtables(make_vtable_backend())
    text = to_text(res)
    assert "candidates" in text and hex(VTABLE) in text


# ------------------------------------------------------------- service wiring
@pytest.fixture
def layout_service(tmp_config, monkeypatch):
    backend = make_vtable_backend()
    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: backend)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), backend


def test_service_layout_and_heap(layout_service):
    service, _ = layout_service
    sid = service.attach(pid=4242)["session_id"]
    res = service.layout_analyze(sid, what="vtables")
    assert res["what"] == "vtables"
    assert any(c["address"] == hex(VTABLE) for c in res["candidates"])
    heap = service.heap_scan(sid)
    assert isinstance(heap["objects"], list)


# --------------------------------------------------------------- CLI parsing
def test_cli_layout_and_pointer_scan_parsers():
    parser = build_parser()
    args = parser.parse_args(["layout", "--session", "s1", "--what", "rtti"])
    assert args.command == "layout" and args.what == "rtti"
    args = parser.parse_args(["layout", "--session", "s1", "--what", "class", "--address", "0x1000"])
    assert args.address == "0x1000"
    args = parser.parse_args(["pointer-scan", "--session", "s1", "--address", "0x2000", "--max-depth", "3", "--max-paths", "10"])
    assert args.command == "pointer-scan" and args.max_depth == 3 and args.max_paths == 10

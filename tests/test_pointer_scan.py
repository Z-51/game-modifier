"""Reverse pointer-scan tests (BFS, depth limit, timeout) on FakeBackend."""

from __future__ import annotations

import pytest

from conftest import FakeBackend

import game_modifier.analysis.pointerscan as psmod
from game_modifier.analysis import find_pointer_paths
from game_modifier.errors import ErrorCode, ScanTimeoutError
from game_modifier.memory import process as procmod
from game_modifier.memory.base import MemoryRegion
from game_modifier.service import ModifierService

STATIC = 0x300000  # static storage holding a pointer into the heap
HEAP = 0x200000  # heap region holding a pointer to the target
TARGET = 0x400010  # the value address we want a chain to


def p64(v: int) -> bytes:
    return v.to_bytes(8, "little")


class ScanBackend(FakeBackend):
    """FakeBackend whose regions are readable/writable but not executable."""

    def regions(self):
        return [
            MemoryRegion(base=base, size=len(buf), readable=True, writable=True, executable=False, state=0x1000)
            for base, buf in self._regions.items()
        ]


def make_chain_backend() -> ScanBackend:
    """Build: STATIC+8 -> HEAP+0x30 (+8 offset), HEAP+0x30 -> TARGET."""

    static = bytearray(0x40)
    static[0x08:0x10] = p64(HEAP + 0x28)  # points at HEAP+0x30 minus 8
    heap = bytearray(0x100)
    heap[0x30:0x38] = p64(TARGET)
    return ScanBackend(regions={STATIC: static, HEAP: heap})


def test_pointer_scan_basic():
    backend = make_chain_backend()
    res = find_pointer_paths(backend, TARGET, max_depth=2, max_paths=500, timeout=30.0)
    assert res["truncated"] is False
    assert res["elapsed"] >= 0
    assert 0.0 < res["confidence"] <= 0.95
    by_base = {p["base"]: p for p in res["paths"]}
    # depth-1: the heap slot points straight at the target
    assert by_base[hex(HEAP + 0x30)]["offsets"] == [0]
    assert by_base[hex(HEAP + 0x30)]["depth"] == 1
    # depth-2: static -> heap(+8) -> target
    deep = by_base[hex(STATIC + 0x08)]
    assert deep["offsets"] == [8, 0]
    assert deep["depth"] == 2


def test_pointer_scan_depth_limit():
    backend = make_chain_backend()
    res = find_pointer_paths(backend, TARGET, max_depth=1)
    bases = {p["base"] for p in res["paths"]}
    assert hex(HEAP + 0x30) in bases
    assert hex(STATIC + 0x08) not in bases  # beyond the depth budget
    assert all(p["depth"] == 1 for p in res["paths"])


def test_pointer_scan_max_paths_truncates():
    backend = make_chain_backend()
    res = find_pointer_paths(backend, TARGET, max_depth=2, max_paths=1)
    assert res["truncated"] is True
    assert len(res["paths"]) == 1


def test_pointer_scan_timeout(monkeypatch):
    backend = make_chain_backend()
    clock = [0.0]

    def fake_monotonic():
        value = clock[0]
        clock[0] += 1.0  # each call advances a full second -> instant expiry
        return value

    monkeypatch.setattr(psmod.time, "monotonic", fake_monotonic)
    with pytest.raises(ScanTimeoutError) as excinfo:
        find_pointer_paths(backend, TARGET, max_depth=2, timeout=0.5)
    assert excinfo.value.code == ErrorCode.SCAN_TIMEOUT
    details = excinfo.value.details
    assert details["timeout"] == 0.5
    assert "paths_found" in details and "depth_reached" in details


def test_pointer_scan_x86():
    static = bytearray(0x20)
    heap = bytearray(0x40)
    heap[0x10:0x14] = p32(0x400010)
    static[0x04:0x08] = p32(0x200010 - 4)  # points at HEAP+0x10 minus 4
    backend = ScanBackend(regions={0x300000: static, 0x200000: heap}, arch="x86")
    assert backend.pointer_size == 4
    res = find_pointer_paths(backend, 0x400010, max_depth=2)
    by_base = {p["base"]: p for p in res["paths"]}
    assert by_base[hex(0x200010)]["offsets"] == [0]
    assert by_base[hex(0x300004)]["offsets"] == [4, 0]


def p32(v: int) -> bytes:
    return v.to_bytes(4, "little")


# ------------------------------------------------------------- service wiring
@pytest.fixture
def scan_service(tmp_config, monkeypatch):
    backend = make_chain_backend()
    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: backend)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config)


def test_service_pointer_scan(scan_service):
    sid = scan_service.attach(pid=4242)["session_id"]
    res = scan_service.pointer_scan(session_id=sid, address=hex(TARGET), max_depth=2, max_paths=100)
    assert any(p["base"] == hex(HEAP + 0x30) for p in res["paths"])
    assert "elapsed" in res

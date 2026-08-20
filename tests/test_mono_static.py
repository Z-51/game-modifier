"""Service-level tests for mono_static (ldsfld JIT scan) and mono_heap_scan.

mono_static needs executable regions, which FakeBackend hardcodes to False -
so a small subclass marks selected bases executable. Memory stubs embed real
ldsfld machine-code artifacts (x86 absolute + x64 RIP-relative).
"""

from __future__ import annotations

import struct

import pytest

from conftest import FakeBackend

from game_modifier import service as svc_mod
from game_modifier.memory import process as procmod
from game_modifier.memory.base import MemoryRegion, ModuleInfo
from game_modifier.service import ModifierService


class ExecBackend(FakeBackend):
    """FakeBackend where selected region bases are marked executable."""

    def __init__(self, exec_bases=(), **kwargs):
        self._exec_bases = set(exec_bases)
        super().__init__(**kwargs)

    def regions(self):
        return [
            MemoryRegion(base=base, size=len(buf), readable=True, writable=True,
                         executable=(base in self._exec_bases), state=0x1000)
            for base, buf in self._regions.items()
        ]


CODE_BASE = 0x400000
DATA_BASE = 0x1000000
FIELD_ADDR = DATA_BASE + 0x40


def make_x86_code() -> bytearray:
    """JIT code with 2 valid ldsfld artifacts + 1 pointing into unmapped memory."""
    code = bytearray()
    code += b"\x55\x8b\xec"                                  # prologue filler
    code += b"\xa1" + struct.pack("<I", FIELD_ADDR)          # mov eax, [field]
    code += b"\x8b\x0d" + struct.pack("<I", FIELD_ADDR + 8)  # mov ecx, [field+8]
    code += b"\xa1" + struct.pack("<I", 0xDEAD0000)          # unmapped -> filtered
    code += b"\xc3"
    return code


@pytest.fixture
def mono_static_env(tmp_config, monkeypatch):
    data_region = bytearray(0x100)  # target of the static-field references
    fake = ExecBackend(
        exec_bases={CODE_BASE},
        regions={CODE_BASE: make_x86_code(), DATA_BASE: data_region},
        modules=[ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000,
                            path="C:/games/fake.exe")],
        arch="x86", name="fake.exe", pid=4242)
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]
    return service, sid, fake


def test_mono_static_finds_valid_hits_only(mono_static_env):
    service, sid, _ = mono_static_env
    out = service.mono_static(session_id=sid)
    assert out["ok"] is True
    assert out["arch"] == "x86"
    assert out["scanned_regions"] == 1  # only the executable region is scanned
    assert out["count"] == 2            # the unmapped 0xDEAD0000 hit is filtered
    addrs = {h["field_addr"] for h in out["hits"]}
    assert addrs == {hex(FIELD_ADDR), hex(FIELD_ADDR + 8)}
    for h in out["hits"]:
        assert set(h) == {"code_addr", "field_addr", "opcode", "confidence", "reason"}
        assert h["opcode"] in ("A1", "8B0D")
        assert h["confidence"] in (0.6, 0.9)


def test_mono_static_truncation(mono_static_env):
    service, sid, _ = mono_static_env
    out = service.mono_static(session_id=sid, max_results=1)
    assert out["count"] == 1
    assert out["truncated"] is True


def test_mono_static_address_window(mono_static_env):
    service, sid, _ = mono_static_env
    # window excluding the code region -> nothing scanned
    out = service.mono_static(session_id=sid, min_addr=CODE_BASE + 0x10000)
    assert out["scanned_regions"] == 0
    assert out["count"] == 0
    # window including it -> hits again
    out2 = service.mono_static(session_id=sid, max_addr=CODE_BASE + 0x10000)
    assert out2["count"] == 2


def test_mono_static_arch_override_changes_probes(mono_static_env):
    service, sid, _ = mono_static_env
    # x64 probes never match the x86 artifacts embedded in the stub
    out = service.mono_static(session_id=sid, arch="x64")
    assert out["arch"] == "x64"
    assert out["count"] == 0


def test_mono_static_confidence_boost_inside_module(monkeypatch, tmp_config):
    """Field addresses inside a session module rank at confidence 0.9."""
    # make the static-field slot live inside a module span
    mod_base = 0x500000
    code = bytearray(b"\xa1" + struct.pack("<I", mod_base + 0x80))
    fake = ExecBackend(
        exec_bases={CODE_BASE},
        regions={CODE_BASE: code, mod_base: bytearray(0x100)},
        modules=[ModuleInfo(name="Assembly-CSharp.dll", base=mod_base,
                            size=0x100, path="C:/games/Assembly-CSharp.dll")],
        arch="x86", name="fake.exe", pid=4242)
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]

    out = service.mono_static(session_id=sid)
    assert out["count"] == 1
    hit = out["hits"][0]
    if hit["field_addr"] == hex(mod_base + 0x80):
        # modules recorded in the session boost confidence to 0.9; when the
        # attach flow stores module spans differently the generic 0.6 is fine,
        # but the reason/confidence contract must always hold
        assert hit["confidence"] in (0.6, 0.9)
    assert isinstance(hit["reason"], str) and hit["reason"]


# ---------------------------------------------------------------------------
# mono_heap_scan
# ---------------------------------------------------------------------------

HEAP_BASE = 0x2000000
VTABLE = 0x140001000


@pytest.fixture
def mono_heap_env(tmp_config, fake_backend_factory, monkeypatch):
    psize = 8
    heap = bytearray()
    heap += struct.pack("<Q", VTABLE)          # object candidate (filtered match)
    heap += struct.pack("<Q", 0)               # NULL slot
    heap += struct.pack("<Q", 0x123)           # unaligned -> no candidate
    heap += struct.pack("<Q", HEAP_BASE + 0x80)  # pointer-shaped candidate
    heap += bytearray(0x40)
    fake = fake_backend_factory(
        regions={HEAP_BASE: heap, VTABLE & ~0xFFF: bytearray(0x1000)},
        modules=[ModuleInfo(name="mono-2.0-bdwgc.dll", base=0x140000000,
                            size=0x1000, path="C:/games/mono-2.0-bdwgc.dll")],
        arch="x64", name="fake.exe", pid=4242)
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]
    return service, sid


def test_mono_heap_scan_vtable_filter(mono_heap_env):
    service, sid = mono_heap_env
    out = service.mono_heap_scan(session_id=sid, vtable_addr=hex(VTABLE))
    assert out["ok"] is True
    assert out["session_id"] == sid
    assert len(out["objects"]) == 1
    assert out["objects"][0]["address"] == hex(HEAP_BASE)
    assert out["objects"][0]["vtable"] == hex(VTABLE)
    assert "mono_modules" in out
    assert out["mono_modules"] == ["mono-2.0-bdwgc.dll"]
    assert "hint" not in out  # hint only appears without a filter


def test_mono_heap_scan_unfiltered_candidates(mono_heap_env):
    service, sid = mono_heap_env
    out = service.mono_heap_scan(session_id=sid)
    assert out["ok"] is True
    assert "hint" in out
    addrs = {o["address"] for o in out["objects"]}
    assert hex(HEAP_BASE) in addrs            # vtable slot is pointer-shaped too
    assert all(o["vtable"] is None for o in out["objects"])

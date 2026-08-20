"""Tests for engines.mono_layout + the mono_string/mono_list/mono_dict service tools.

Covers the per-arch Mono System.String layout table, the ldsfld JIT artifact
byte scanner (pure pattern matching, x86 absolute + x64 RIP-relative) and the
service-layer decoders which reuse the parameterised il2cpp decoders with the
Mono layout override (zero duplicated decode code).
"""

from __future__ import annotations

import struct

import pytest

from game_modifier.engines import mono_layout as ml
from game_modifier.engines import unity_introspect


# ---------------------------------------------------------------------------
# layout tables
# ---------------------------------------------------------------------------

class TestMonoLayoutTables:
    def test_per_arch_string_offsets(self):
        assert ml.MONO_LAYOUTS["x86"] == {"string_length_off": 0x8, "string_chars_off": 0xC}
        assert ml.MONO_LAYOUTS["x64"] == {"string_length_off": 0x10, "string_chars_off": 0x14}

    def test_mono_layout_lookup_and_fallback(self):
        assert ml.mono_layout("x86") == ml.MONO_LAYOUTS["x86"]
        assert ml.mono_layout("x64") == ml.MONO_LAYOUTS["x64"]
        # unknown / missing arch falls back to x64
        assert ml.mono_layout("arm64") == ml.MONO_LAYOUTS["x64"]
        assert ml.mono_layout(None) == ml.MONO_LAYOUTS["x64"]
        # returned tables are copies (callers may not mutate the registry)
        t = ml.mono_layout("x86")
        t["string_length_off"] = 0
        assert ml.MONO_LAYOUTS["x86"]["string_length_off"] == 0x8

    def test_normalize_arch(self):
        for a in ("x86", "i386", "i686", "win32", "32", "32-bit", "X86"):
            assert ml.normalize_arch(a) == "x86"
        for a in ("x64", "amd64", "x86_64", None, "", "weird"):
            assert ml.normalize_arch(a) == "x64"


# ---------------------------------------------------------------------------
# ldsfld artifact byte scanning
# ---------------------------------------------------------------------------

class TestFindLdsfldHits:
    def test_x86_a1_absolute_address(self):
        data = b"\xa1" + struct.pack("<I", 0x10002000)
        hits = ml.find_ldsfld_hits(data, 0x400000, "x86")
        assert hits == [{"code_addr": 0x400000, "field_addr": 0x10002000, "opcode": "A1"}]

    def test_x86_8b0d_absolute_address(self):
        data = b"\x90" + b"\x8b\x0d" + struct.pack("<I", 0x10003000) + b"\xc3"
        hits = ml.find_ldsfld_hits(data, 0x400000, "x86")
        assert any(h["opcode"] == "8B0D" and h["field_addr"] == 0x10003000
                   and h["code_addr"] == 0x400001 for h in hits)

    def test_x86_multiple_hits_ordered(self):
        data = (b"\xa1" + struct.pack("<I", 0x10002000)
                + b"\x8b\x0d" + struct.pack("<I", 0x10003000))
        hits = ml.find_ldsfld_hits(data, 0x400000, "x86")
        assert [h["code_addr"] for h in hits] == sorted(h["code_addr"] for h in hits)
        assert len(hits) == 2

    def test_x64_rip_relative_positive_disp(self):
        base = 0x140000000
        disp = 0x1000 - 6  # target = base + instruction_end(6) + disp
        data = b"\x8b\x05" + struct.pack("<i", disp)
        hits = ml.find_ldsfld_hits(data, base, "x64")
        assert hits[0]["field_addr"] == base + 0x1000
        assert hits[0]["opcode"] == "8B05"

    def test_x64_rex_w_negative_disp(self):
        base = 0x140000000
        disp = -10  # target = base + 7 + (-10)
        data = b"\x48\x8b\x05" + struct.pack("<i", disp)
        hits = [h for h in ml.find_ldsfld_hits(data, base, "x64") if h["opcode"] == "488B05"]
        assert hits and hits[0]["field_addr"] == base - 3

    def test_arch_isolation(self):
        # an x86 absolute pattern must not surface under x64 probes and vice versa
        data = b"\xa1" + struct.pack("<I", 0x10002000)
        assert ml.find_ldsfld_hits(data, 0x400000, "x64") == []

    def test_truncated_tail_ignored(self):
        # signature present but the 4-byte immediate runs past the buffer
        data = b"\xa1" + b"\x12\x34"
        assert ml.find_ldsfld_hits(data, 0x400000, "x86") == []


class TestScanRegionLdsfld:
    def test_invalid_pointers_filtered_out(self):
        data = b"\xa1" + struct.pack("<I", 0xDEAD0000)
        out = ml.scan_region_ldsfld(data, 0x400000, "x86", is_valid=lambda p: False)
        assert out == []

    def test_confidence_and_reason(self):
        field = 0x10002000
        data = b"\xa1" + struct.pack("<I", field)
        in_mod = ml.scan_region_ldsfld(data, 0x400000, "x86", is_valid=lambda p: True,
                                       module_spans=[(field, field + 0x1000)])
        assert in_mod[0]["confidence"] == 0.9
        assert "module" in in_mod[0]["reason"]

        generic = ml.scan_region_ldsfld(data, 0x400000, "x86", is_valid=lambda p: True)
        assert generic[0]["confidence"] == 0.6

    def test_hex_output_and_max_results(self):
        field = 0x10002000
        data = (b"\xa1" + struct.pack("<I", field)) * 4
        out = ml.scan_region_ldsfld(data, 0x400000, "x86", is_valid=lambda p: True,
                                    max_results=3)
        assert len(out) == 3
        assert out[0]["code_addr"] == hex(0x400000)
        assert out[0]["field_addr"] == hex(field)
        assert out[0]["opcode"] == "A1"


# ---------------------------------------------------------------------------
# decoder reuse: layout override on the shared il2cpp string decoder
# ---------------------------------------------------------------------------

class _MiniBackend:
    """Minimal read-only backend over one bytearray (string decoder contract)."""

    def __init__(self, buf: bytearray, base: int = 0x10000000):
        self._buf = buf
        self._base = base

    def read(self, address: int, size: int) -> bytes:
        off = address - self._base
        if off < 0 or off >= len(self._buf):
            raise RuntimeError(f"unmapped read at {hex(address)}")
        return bytes(self._buf[off:off + size])


def _mono_x86_string(text: str) -> bytearray:
    """Mono x86 System.String: 8-byte header, length@0x8, UTF-16 chars@0xC."""
    buf = bytearray(0x40)
    data = text.encode("utf-16-le")
    struct.pack_into("<i", buf, 0x8, len(text))
    buf[0xC:0xC + len(data)] = data
    return buf


def test_shared_decoder_with_mono_x86_layout():
    be = _MiniBackend(_mono_x86_string("Hola"))
    out = unity_introspect.read_string(be, 0x10000000, layout=ml.MONO_LAYOUTS["x86"])
    assert out["ok"] is True
    assert out["value"] == "Hola"
    assert out["length"] == 4


def test_shared_decoder_default_layout_is_il2cpp_not_mono():
    # the same bytes must NOT decode to the same value under the default
    # (IL2CPP) layout, proving the override is what makes Mono x86 strings
    # readable (default layout reads length@0x10 = 0 -> empty string)
    be = _MiniBackend(_mono_x86_string("Hola"))
    out = unity_introspect.read_string(be, 0x10000000)
    assert out.get("value") != "Hola"


# ---------------------------------------------------------------------------
# service layer: mono_string / mono_list / mono_dict
# ---------------------------------------------------------------------------

from game_modifier import service as svc_mod  # noqa: E402
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory.base import ModuleInfo  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402

BASE = 0x10000000


def p64(v):
    return struct.pack("<Q", v)


def p32(v):
    return struct.pack("<i", v)


def make_mono_image() -> bytearray:
    """x64 image: Mono x64 string (== IL2CPP offsets) + List<int> + Dictionary."""
    img = bytearray(0x2000)
    # string "Gold" at +0x100 with x64 layout (length@0x10, chars@0x14)
    hdr = bytearray(0x20)
    hdr[0:16] = p64(0xDEAD0001) + p64(0)
    struct.pack_into("<i", hdr, 0x10, 4)
    img[0x100:0x120] = hdr
    img[0x114:0x114 + 8] = "Gold".encode("utf-16-le")
    # List<int> at +0x600 -> items array +0x700, size 3
    img[0x600:0x610] = p64(0xDEAD0002) + p64(0)
    img[0x610:0x618] = p64(BASE + 0x700)   # _items
    img[0x618:0x61C] = p32(3)              # _size
    img[0x700:0x710] = p64(0xDEAD0003) + p64(0)
    img[0x710:0x718] = p64(0)              # bounds
    img[0x718:0x720] = p64(3)              # max_length
    img[0x720:0x72C] = p32(11) + p32(22) + p32(33)
    # Dictionary at +0x900: 1 live entry in a 2-slot table
    img[0x900:0x910] = p64(0xDEAD0004) + p64(0)
    img[0x910:0x918] = p64(BASE + 0x940)          # buckets
    img[0x918:0x920] = p64(BASE + 0x960)          # entries
    img[0x920:0x924] = p32(1)                     # count
    img[0x960:0x970] = p64(0xDEAD0005) + p64(0)
    img[0x970:0x978] = p64(0)
    img[0x978:0x980] = p64(2)
    entry_live = p32(7) + p32(-1) + p64(0x2000) + p64(0x2100)
    entry_free = p32(0) + p32(-1) + p64(0) + p64(0)
    img[0x980:0x980 + 24] = entry_live
    img[0x980 + 24:0x980 + 48] = entry_free
    return img


@pytest.fixture
def mono_env(tmp_config, fake_backend_factory, monkeypatch):
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={BASE: bytearray(make_mono_image())},
                                modules=[mod], arch="x64", name="fake.exe", pid=4242)
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]
    return service, sid, fake


def test_service_mono_string_x64(mono_env):
    service, sid, _ = mono_env
    out = service.mono_string(session_id=sid, address=hex(BASE + 0x100))
    assert out["ok"] is True
    assert out["value"] == "Gold"
    assert out["arch"] == "x64"
    assert out["session_id"] == sid


def test_service_mono_string_x86_layout(mono_env):
    """arch='x86' override applies the x86 offset table (length@0x8/chars@0xC)."""
    service, sid, fake = mono_env
    # plant an x86-layout string: 8-byte header, length@0x8, chars@0xC
    img = fake._regions[BASE]
    off = 0x300
    struct.pack_into("<i", img, off + 0x8, 2)
    img[off + 0xC:off + 0xC + 4] = "OK".encode("utf-16-le")
    out = service.mono_string(session_id=sid, address=hex(BASE + off), arch="x86")
    assert out["ok"] is True
    assert out["value"] == "OK"
    assert out["arch"] == "x86"


def test_service_mono_list_reuses_il2cpp_decoder(mono_env):
    service, sid, _ = mono_env
    out = service.mono_list(session_id=sid, address=hex(BASE + 0x600), elem_type="int32")
    assert out["ok"] is True
    assert out["elements"] == [11, 22, 33]
    assert out["session_id"] == sid
    assert out["arch"] == "x64"


def test_service_mono_dict_reuses_il2cpp_decoder(mono_env):
    service, sid, _ = mono_env
    out = service.mono_dict(session_id=sid, address=hex(BASE + 0x900))
    assert out["ok"] is True
    assert out["count"] == 1
    assert out["entries"][0]["key_ptr"] == hex(0x2000)
    assert out["entries"][0]["value_ptr"] == hex(0x2100)
    assert out["session_id"] == sid

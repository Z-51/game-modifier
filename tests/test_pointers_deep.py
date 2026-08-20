"""Deep tests for pointer parsing and multi-level resolution."""

from __future__ import annotations

import struct

import pytest

from game_modifier.errors import InvalidAddressError, InvalidArgsError
from game_modifier.memory import pointers
from game_modifier.memory import types as vt
from game_modifier.memory.base import ModuleInfo


# --------------------------------------------------------------- parse_int
def test_parse_int_negative_hex():
    assert pointers.parse_int("-0x10") == -16, "negative 0x-prefixed hex must parse"
    assert pointers.parse_int("-1f") == -31, "negative bare hex must parse"
    assert pointers.parse_int("+0x20") == 32, "explicit plus sign must parse"


def test_parse_int_leading_zeros():
    assert pointers.parse_int("0010") == 10, "digit-only token with leading zeros is decimal"
    assert pointers.parse_int("0x0010") == 16, "0x-prefixed token with leading zeros is hex"
    assert pointers.parse_int("000ff") == 255, "bare hex with leading zeros must parse as hex"


def test_parse_int_invalid_raises():
    with pytest.raises(InvalidArgsError):
        pointers.parse_int("zzz")
    with pytest.raises(InvalidArgsError):
        pointers.parse_int("")
    with pytest.raises(InvalidArgsError):
        pointers.parse_int("12g4")


# ------------------------------------------------------------ resolve_base
def test_resolve_base_module_not_found(fake_backend_factory):
    mod = ModuleInfo(name="Game.exe", base=0x140000000, size=0x1000, path="Game.exe")
    be = fake_backend_factory(regions={0x140000000: bytearray(0x100)}, modules=[mod])
    with pytest.raises(InvalidAddressError) as exc:
        pointers.resolve_base(be, "Missing.dll+0x10")
    assert "Missing.dll" in str(exc.value), "error must name the missing module"


def test_resolve_base_empty_expression(fake_backend_factory):
    be = fake_backend_factory(regions={})
    with pytest.raises(InvalidArgsError):
        pointers.resolve_base(be, "")
    with pytest.raises(InvalidArgsError):
        pointers.resolve_base(be, "   ")


# ------------------------------------------------------------ read_pointer
def test_read_pointer_insufficient_data(fake_backend_factory):
    # region only 4 bytes long, but x64 pointer needs 8
    be = fake_backend_factory(regions={0x1000: bytearray(4)}, arch="x64")
    assert be.pointer_size == 8, "x64 backend must use 8-byte pointers"
    with pytest.raises(InvalidAddressError):
        pointers.read_pointer(be, 0x1000)


# --------------------------------------------------------- resolve_pointer
def test_resolve_pointer_multistep_chain(fake_backend_factory):
    # module+0x10 -> 0x500000; [0x500000]+0x20 -> 0x600000; final = 0x600000+0x8
    mod = ModuleInfo(name="Game.exe", base=0x140000000, size=0x10000, path="Game.exe")
    regions = {
        0x140000000: bytearray(0x1000),
        0x500000: bytearray(0x1000),
        0x600000: bytearray(0x1000),
    }
    be = fake_backend_factory(regions=regions, modules=[mod])
    be.write(0x140000000 + 0x10, struct.pack("<Q", 0x500000))
    be.write(0x500000 + 0x20, struct.pack("<Q", 0x600000))
    be.write(0x600000 + 0x8, struct.pack("<i", 4321))

    info = pointers.resolve_pointer(be, "Game.exe+0x10", [0x20, 0x8])
    assert info["final_address"] == 0x600008, f"3-step chain resolved to {info['final_address_hex']}"
    assert vt.decode_value("int32", be.read(info["final_address"], 4)) == 4321, "value at final address must match"
    assert len(info["trace"]) == 3, "trace must record base + one entry per offset"


def test_resolve_pointer_negative_offsets(fake_backend_factory):
    regions = {
        0x1000: bytearray(0x100),
        0x2000: bytearray(0x100),
        0x3000: bytearray(0x100),
    }
    be = fake_backend_factory(regions=regions)
    be.write(0x1000, struct.pack("<Q", 0x2010))   # deref -> 0x2010, -0x10 -> 0x2000
    be.write(0x2000, struct.pack("<Q", 0x3020))   # deref -> 0x3020, -0x20 -> 0x3000
    be.write(0x3000, struct.pack("<i", 999))

    # pointer_chain is now explicit: a bare absolute address defaults to
    # "relative" (plain addition), so the chain must opt in.
    info = pointers.resolve_pointer(be, "0x1000", [-0x10, -0x20], mode="pointer_chain")
    assert info["final_address"] == 0x3000, f"negative offsets must subtract, got {info['final_address_hex']}"
    assert vt.decode_value("int32", be.read(0x3000, 4)) == 999, "value at final address must match"
    assert info["offsets"] == ["-0x10", "-0x20"], "negative offsets must survive hex formatting"


def test_resolve_pointer_absolute_relative_default(fake_backend_factory):
    """Bare absolute address + offsets must default to 'relative' (no deref)."""
    regions = {0x1000: bytearray(0x100)}
    be = fake_backend_factory(regions=regions)
    be.write(0x1000, struct.pack("<Q", 0xDEADBEEF))  # garbage that a deref would misread
    be.write(0x1010, struct.pack("<i", 1234))

    info = pointers.resolve_pointer(be, "0x1000", [0x10])
    assert info["mode"] == "relative", "bare absolute address must default to relative"
    assert info["final_address"] == 0x1010, "relative mode must add the offset without dereferencing"
    assert vt.decode_value("int32", be.read(0x1010, 4)) == 1234


# ------------------------------------------------------------ parse_offsets
def test_parse_offsets_whitespace_mixed():
    out = pointers.parse_offsets("0x10, 0x20\t0x30\n0x40")
    assert out == [0x10, 0x20, 0x30, 0x40], f"mixed comma/tab/newline separators must parse, got {out}"


def test_parse_offsets_empty():
    assert pointers.parse_offsets(None) == [], "None must yield an empty list"
    assert pointers.parse_offsets("") == [], "empty string must yield an empty list"
    assert pointers.parse_offsets("   ") == [], "whitespace-only string must yield an empty list"
    assert pointers.parse_offsets([]) == [], "empty list must stay empty"

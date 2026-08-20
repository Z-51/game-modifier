"""Type system: encode/decode/range/aliases."""

from __future__ import annotations

import struct

import pytest

from game_modifier.errors import InvalidTypeError, ValueOutOfRangeError
from game_modifier.memory import types as vt


def test_int32_roundtrip_little_endian():
    assert vt.encode_value("int32", 9999) == struct.pack("<i", 9999)
    assert vt.decode_value("int32", vt.encode_value("int32", 9999)) == 9999


def test_aliases_resolve():
    assert vt.resolve_type("dword").name == "uint32"
    assert vt.resolve_type("byte").name == "uint8"
    assert vt.resolve_type("float32").name == "float"
    assert vt.resolve_type("qword").name == "uint64"


def test_value_range_bounds():
    assert vt.value_range("uint8") == (0, 255)
    assert vt.value_range("int8") == (-128, 127)
    assert vt.value_range("float") is None


def test_range_enforced():
    with pytest.raises(ValueOutOfRangeError):
        vt.encode_value("uint8", 256)
    with pytest.raises(ValueOutOfRangeError):
        vt.encode_value("int8", -200)


def test_float_encoding():
    assert vt.decode_value("float", vt.encode_value("float", "5")) == 5.0
    val = vt.decode_value("float", vt.encode_value("float", 1234.5))
    assert abs(val - 1234.5) < 1e-6


def test_string_and_bytes():
    assert vt.encode_value("string", "hi") == b"hi"
    assert vt.encode_value("string_utf16", "hi") == "hi".encode("utf-16-le")
    assert vt.encode_value("aob", "DE AD BE EF").hex() == "deadbeef"
    assert vt.encode_value("aob", "deadbeef").hex() == "deadbeef"


def test_hex_string_value_for_int():
    assert vt.decode_value("uint32", vt.encode_value("uint32", "0x10")) == 16


def test_unknown_type_raises():
    with pytest.raises(InvalidTypeError):
        vt.resolve_type("wat")


def test_is_integer_numeric():
    assert vt.is_integer("int32")
    assert not vt.is_integer("float")
    assert vt.is_numeric("double")
    assert not vt.is_numeric("string")

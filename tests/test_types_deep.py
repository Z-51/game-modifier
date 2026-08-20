"""Deep tests for the value type system (encode/decode/aliases/ranges)."""

from __future__ import annotations

import math

import pytest

from game_modifier.errors import InvalidTypeError, ValueOutOfRangeError
from game_modifier.memory import types as vt
from game_modifier.memory.types import _ALIASES  # noqa: PLC2701 - white-box alias check


# one representative value per canonical type
_ROUNDTRIP_SAMPLES = {
    "int8": -5,
    "uint8": 200,
    "int16": -1234,
    "uint16": 60000,
    "int32": -123456,
    "uint32": 4000000000,
    "int64": -(2**40),
    "uint64": 2**63,
    "float": 1.5,               # exactly representable in binary32
    "double": math.pi,
    "bool": True,
    "string": "hello",
    "string_utf16": "gold",
    "bytes": b"\x01\x02\x03",
}


def test_all_13_types_roundtrip():
    supported = vt.supported_types()
    assert len(supported) >= 13, f"registry unexpectedly small: {supported}"
    assert set(_ROUNDTRIP_SAMPLES) == set(supported), "sample table must cover every registered type"
    for name, value in _ROUNDTRIP_SAMPLES.items():
        encoded = vt.encode_value(name, value)
        decoded = vt.decode_value(name, encoded)
        assert decoded == value, f"roundtrip failed for {name}: {value!r} -> {decoded!r}"


def test_uint32_uint64_encoding():
    assert vt.encode_value("uint32", 0xFFFFFFFF) == b"\xff" * 4, "uint32 max must encode as 4x 0xFF"
    assert vt.encode_value("uint64", 0xFFFFFFFFFFFFFFFF) == b"\xff" * 8, "uint64 max must encode as 8x 0xFF"
    # values above the signed range must still be accepted for unsigned types
    assert vt.decode_value("uint32", vt.encode_value("uint32", 2**31)) == 2**31, "uint32 must hold 2^31"
    assert vt.decode_value("uint64", vt.encode_value("uint64", 2**63)) == 2**63, "uint64 must hold 2^63"


def test_int64_negative_bounds():
    lo, hi = vt.value_range("int64")
    assert (lo, hi) == (-(2**63), 2**63 - 1), f"unexpected int64 range: {(lo, hi)}"
    assert vt.decode_value("int64", vt.encode_value("int64", lo)) == lo, "int64 min must roundtrip"
    assert vt.decode_value("int64", vt.encode_value("int64", hi)) == hi, "int64 max must roundtrip"
    with pytest.raises(ValueOutOfRangeError):
        vt.encode_value("int64", lo - 1)
    with pytest.raises(ValueOutOfRangeError):
        vt.encode_value("int64", hi + 1)


def test_double_precision():
    value = 0.1 + 0.2  # 0.30000000000000004 - only representable at 64-bit precision
    assert vt.decode_value("double", vt.encode_value("double", value)) == value, "double must keep full precision"
    # float (binary32) must lose precision for the same value
    assert vt.decode_value("float", vt.encode_value("float", value)) != value, "float32 should not keep 64-bit precision"


def test_bool_encode_decode():
    for truthy in (True, 1, "1", "true", "True", "yes"):
        assert vt.encode_value("bool", truthy) == b"\x01", f"{truthy!r} must encode as truthy"
    for falsy in (False, 0, "0", "false", "no"):
        assert vt.encode_value("bool", falsy) == b"\x00", f"{falsy!r} must encode as falsy"
    assert vt.decode_value("bool", b"\x01") is True, "0x01 must decode to True"
    assert vt.decode_value("bool", b"\x00") is False, "0x00 must decode to False"


def test_string_utf16_roundtrip():
    text = "gold=9999"
    encoded = vt.encode_value("string_utf16", text)
    assert encoded == text.encode("utf-16-le"), "string_utf16 must encode as UTF-16-LE"
    assert vt.decode_value("string_utf16", encoded) == text, "UTF-16 roundtrip must be lossless"
    # decoding stops at the first NUL terminator
    assert vt.decode_value("string_utf16", encoded + b"\x00\x00X\x00") == text, "decode must stop at NUL"


def test_parse_bytes_mixed_formats():
    expected = b"\xde\xad\xbe\xef"
    assert vt.parse_bytes("DEADBEEF") == expected, "plain hex string must parse"
    assert vt.parse_bytes("DE AD BE EF") == expected, "space-separated hex must parse"
    assert vt.parse_bytes("de,ad,be,ef") == expected, "comma-separated hex must parse"
    assert vt.parse_bytes("0xDE 0xAD 0xBE 0xEF") == expected, "0x-prefixed hex must parse"
    assert vt.parse_bytes(r"\xde\xad\xbe\xef") == expected, "\\x-escaped hex must parse"
    assert vt.parse_bytes([0xDE, 0xAD, 0xBE, 0x1EF]) == b"\xde\xad\xbe\xef", "list ints must be masked to a byte"
    assert vt.parse_bytes(bytearray(expected)) == expected, "bytearray passes through"
    with pytest.raises(InvalidTypeError):
        vt.parse_bytes("abc")  # odd-length hex without separators


def test_decode_insufficient_data():
    for name in ("int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "float", "double", "bool"):
        size = vt.type_size(name)
        with pytest.raises(InvalidTypeError):
            vt.decode_value(name, b"\x00" * (size - 1))
        with pytest.raises(InvalidTypeError):
            vt.decode_value(name, b"")


def test_all_aliases_resolve():
    assert _ALIASES, "alias table must not be empty"
    for alias, canonical in _ALIASES.items():
        resolved = vt.resolve_type(alias)
        assert resolved.name == canonical, f"alias {alias!r} resolved to {resolved.name!r}, expected {canonical!r}"


def test_value_range_all_integer_types():
    expected = {
        "int8": (-128, 127),
        "uint8": (0, 255),
        "int16": (-32768, 32767),
        "uint16": (0, 65535),
        "int32": (-(2**31), 2**31 - 1),
        "uint32": (0, 2**32 - 1),
        "int64": (-(2**63), 2**63 - 1),
        "uint64": (0, 2**64 - 1),
    }
    for name, rng in expected.items():
        assert vt.value_range(name) == rng, f"wrong range for {name}: {vt.value_range(name)}"
    # non-integer types have no integer range
    for name in ("float", "double", "bool", "string", "string_utf16", "bytes"):
        assert vt.value_range(name) is None, f"{name} must not report an integer range"

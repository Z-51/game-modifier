"""Value type system: encode/decode/size/range for memory operations.

A small, explicit registry maps friendly type names (including common aliases
like ``dword``, ``float``, ``byte``) to their binary representation. All
multi-byte values are little-endian, matching x86/x64 game processes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Union

from ..errors import InvalidTypeError, ValueOutOfRangeError

Number = Union[int, float]


@dataclass(frozen=True)
class DataType:
    name: str
    kind: str  # "int" | "uint" | "float" | "bool" | "string" | "bytes"
    fmt: Optional[str]  # struct format (little-endian) or None for variable
    size: Optional[int]  # fixed size in bytes, or None for variable
    signed: bool = False
    bits: int = 0


# Canonical types --------------------------------------------------------------
_TYPES: dict[str, DataType] = {
    "int8": DataType("int8", "int", "<b", 1, signed=True, bits=8),
    "uint8": DataType("uint8", "uint", "<B", 1, bits=8),
    "int16": DataType("int16", "int", "<h", 2, signed=True, bits=16),
    "uint16": DataType("uint16", "uint", "<H", 2, bits=16),
    "int32": DataType("int32", "int", "<i", 4, signed=True, bits=32),
    "uint32": DataType("uint32", "uint", "<I", 4, bits=32),
    "int64": DataType("int64", "int", "<q", 8, signed=True, bits=64),
    "uint64": DataType("uint64", "uint", "<Q", 8, bits=64),
    "float": DataType("float", "float", "<f", 4, signed=True, bits=32),
    "double": DataType("double", "float", "<d", 8, signed=True, bits=64),
    "bool": DataType("bool", "bool", "<?", 1),
    "string": DataType("string", "string", None, None),
    "string_utf16": DataType("string_utf16", "string", None, None),
    "bytes": DataType("bytes", "bytes", None, None),
}

# Friendly aliases -------------------------------------------------------------
_ALIASES: dict[str, str] = {
    "i8": "int8", "sbyte": "int8",
    "u8": "uint8", "byte": "uint8", "ubyte": "uint8",
    "i16": "int16", "short": "int16",
    "u16": "uint16", "word": "uint16", "ushort": "uint16",
    "i32": "int32", "int": "int32", "integer": "int32", "long32": "int32",
    "u32": "uint32", "uint": "uint32", "dword": "uint32",
    "i64": "int64", "long": "int64", "longlong": "int64",
    "u64": "uint64", "qword": "uint64", "ulong": "uint64",
    "f32": "float", "single": "float", "float32": "float",
    "f64": "double", "float64": "double",
    "boolean": "bool",
    "str": "string", "utf8": "string",
    "wstring": "string_utf16", "str16": "string_utf16",
    "utf16": "string_utf16", "unicode": "string_utf16",
    "aob": "bytes", "arrayofbytes": "bytes", "hex": "bytes", "buffer": "bytes",
}


def resolve_type(name: str) -> DataType:
    """Return the canonical :class:`DataType` for a friendly name."""

    if not name:
        raise InvalidTypeError("type name is empty")
    key = name.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
    # Preserve underscores only for the two string variants handled above.
    key_us = name.strip().lower().replace(" ", "").replace("-", "_")
    if key_us in _TYPES:
        return _TYPES[key_us]
    if key in _TYPES:
        return _TYPES[key]
    if key in _ALIASES:
        return _TYPES[_ALIASES[key]]
    if key_us in _ALIASES:
        return _TYPES[_ALIASES[key_us]]
    raise InvalidTypeError(
        f"unknown value type: {name!r}",
        details={"supported": supported_types()},
    )


def supported_types() -> list[str]:
    return sorted(_TYPES.keys())


def type_size(name: str) -> Optional[int]:
    """Fixed size in bytes, or ``None`` for variable-length types."""

    return resolve_type(name).size


def is_numeric(name: str) -> bool:
    return resolve_type(name).kind in ("int", "uint", "float")


def is_integer(name: str) -> bool:
    return resolve_type(name).kind in ("int", "uint")


def value_range(name: str) -> Optional[tuple[int, int]]:
    """Inclusive (min, max) for integer types, else ``None``."""

    dt = resolve_type(name)
    if dt.kind == "uint":
        return (0, (1 << dt.bits) - 1)
    if dt.kind == "int":
        half = 1 << (dt.bits - 1)
        return (-half, half - 1)
    return None


def parse_bytes(value: Union[str, bytes, bytearray, list]) -> bytes:
    """Parse an AOB from hex string / bytes / list of ints."""

    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, list):
        return bytes(int(b) & 0xFF for b in value)
    if isinstance(value, str):
        cleaned = value.replace("0x", "").replace(",", " ").replace("-", " ")
        cleaned = cleaned.replace("\\x", " ").strip()
        if " " in cleaned:
            parts = [p for p in cleaned.split() if p]
            return bytes(int(p, 16) for p in parts)
        if len(cleaned) % 2 != 0:
            raise InvalidTypeError(f"odd-length hex byte string: {value!r}")
        return bytes.fromhex(cleaned)
    raise InvalidTypeError(f"cannot interpret {value!r} as bytes")


def _coerce_number(dt: DataType, value: Union[Number, str]) -> Number:
    if isinstance(value, str):
        text = value.strip()
        try:
            if dt.kind == "float":
                return float(text)
            # allow hex/underscore integer literals
            return int(text, 0) if text.lower().startswith(("0x", "0b", "0o")) else int(text)
        except ValueError as exc:
            raise InvalidTypeError(f"cannot parse {value!r} as {dt.name}") from exc
    if dt.kind == "float":
        return float(value)
    if isinstance(value, float) and not value.is_integer():
        raise InvalidTypeError(f"value {value!r} is not an integer for type {dt.name}")
    return int(value)


def encode_value(name: str, value) -> bytes:
    """Encode ``value`` to little-endian bytes for ``name``."""

    dt = resolve_type(name)
    if dt.kind == "bytes":
        return parse_bytes(value)
    if dt.kind == "string":
        text = value if isinstance(value, str) else str(value)
        return text.encode("utf-16-le") if name.lower() in ("string_utf16", "wstring", "str16") or dt.name == "string_utf16" else text.encode("utf-8")
    if dt.kind == "bool":
        truthy = value in (True, 1, "1", "true", "True", "yes")
        return struct.pack(dt.fmt, bool(truthy))  # type: ignore[arg-type]

    num = _coerce_number(dt, value)
    if dt.kind in ("int", "uint"):
        lo, hi = value_range(dt.name)  # type: ignore[misc]
        if not (lo <= num <= hi):
            raise ValueOutOfRangeError(
                f"value {num} out of range for {dt.name} [{lo}, {hi}]",
                details={"type": dt.name, "min": lo, "max": hi, "value": num},
            )
    try:
        return struct.pack(dt.fmt, num)  # type: ignore[arg-type]
    except struct.error as exc:  # pragma: no cover - guarded by range check
        raise ValueOutOfRangeError(f"cannot pack {value!r} as {dt.name}: {exc}") from exc


def decode_value(name: str, data: bytes):
    """Decode ``data`` into a Python value for ``name``."""

    dt = resolve_type(name)
    if dt.kind == "bytes":
        return bytes(data)
    if dt.kind == "string":
        if dt.name == "string_utf16":
            return data.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        return data.decode("utf-8", errors="replace").split("\x00", 1)[0]
    if dt.size is None or len(data) < dt.size:
        raise InvalidTypeError(f"not enough bytes to decode {dt.name}: need {dt.size}, got {len(data)}")
    return struct.unpack(dt.fmt, data[: dt.size])[0]  # type: ignore[arg-type]

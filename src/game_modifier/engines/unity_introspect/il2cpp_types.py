"""Il2Cpp runtime type decoders. Read-only.

Decodes the managed runtime types agents hit constantly in Unity il2cpp
games - ``Il2CppString``, ``List<T>`` and ``Dictionary<K,V>`` - so one call
replaces the 3~5 manual reads (length -> chars, items pointer -> size ->
step) each of them otherwise costs.

Il2Cpp standard layout (x64). Every offset lives in :data:`DEFAULT_LAYOUT`
and can be overridden per call (``layout=``) to cope with patched/modified
runtimes:

* ``Il2CppObject``: klass@0x0, monitor@0x8 (16-byte object header).
* ``Il2CppString``: object header + length@0x10 (int32) + chars@0x14
  (UTF-16LE, ``length`` code units).
* ``Il2CppArray``: object header + bounds@0x10 (ptr) + max_length@0x18
  (uint64) + items@0x20 (element data starts here).
* ``List<T>``: object header + _items@0x10 (Il2CppArray*) + _size@0x18
  (int32) + _version@0x1C.
* ``Dictionary<K,V>``: object header + buckets@0x10 + entries@0x18
  (Il2CppArray*) + count@0x20; each entry is 24 bytes: hashCode@0 (int32) +
  next@4 (int32) + key@8 (ptr) + value@16 (ptr).

All functions follow the "degrade, never crash" contract: read failures and
implausible headers come back as ``{"ok": False, "reason": ...}`` instead of
raising, so a wrong address costs one cheap call rather than a retry loop.
"""

from __future__ import annotations

import struct

from ...memory import types as vt

DEFAULT_LAYOUT = {
    "string_length_off": 0x10, "string_chars_off": 0x14,
    "array_bounds_off": 0x10, "array_maxlen_off": 0x18, "array_items_off": 0x20,
    "list_items_off": 0x10, "list_size_off": 0x18,
    "dict_entries_off": 0x18, "dict_count_off": 0x20,
    "entry_size": 24, "entry_key_off": 8, "entry_value_off": 16,
    "entry_next_off": 4,
}

# Declared lengths/slot counts above this are effectively certain evidence of
# a misread layout (or that the address is not the expected runtime type).
_LENGTH_CAP = 16_000_000
# Dictionary entry tables are read in one shot; cap the slot window.
_MAX_DICT_SLOTS = 65536


def _merge_layout(layout: dict = None) -> dict:
    merged = dict(DEFAULT_LAYOUT)
    if layout:
        merged.update({k: int(v) for k, v in layout.items()})
    return merged


def _u64(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off : off + 8], "little")


def _i32(buf: bytes, off: int = 0) -> int:
    return struct.unpack_from("<i", buf, off)[0]


def _elem_spec(elem_type: str, elem_size: int):
    """Resolve ``(byte_size, decoder)`` for one list element type.

    ``ptr`` decodes to a hex address string; any fixed-size canonical type
    (int32/float/...) decodes to a number. Variable-length types fall back to
    raw hex bytes of ``elem_size``.
    """

    name = str(elem_type or "ptr").strip().lower()
    if name in ("ptr", "pointer"):
        return 8, lambda b: "0x%x" % int.from_bytes(b[:8], "little")
    try:
        size = vt.type_size(name)
    except Exception as exc:
        raise ValueError(f"unsupported elem_type: {elem_type!r}") from exc
    if size:
        return size, (lambda b, _n=name: vt.decode_value(_n, b))
    if elem_size and int(elem_size) > 0:
        size = int(elem_size)
        return size, lambda b: b.hex()
    raise ValueError(
        f"elem_type {elem_type!r} has no fixed size; pass an explicit elem_size"
    )


def read_string(backend, addr: int, *, layout: dict = None, max_chars: int = 4096) -> dict:
    """Decode an ``Il2CppString`` at ``addr``.

    Returns ``{"ok": True, "address": hex, "length": int, "value": str,
    "truncated": bool}``; the value is capped at ``max_chars`` code units
    (``truncated`` flags the cut). Implausible lengths (negative or above an
    absolute cap) and read failures return ``{"ok": False, "reason": ...}``
    instead of raising.
    """

    L = _merge_layout(layout)
    addr = int(addr)
    max_chars = max(1, int(max_chars))

    try:
        head = backend.read(addr + L["string_length_off"], 4)
    except Exception as exc:
        return {"ok": False, "address": hex(addr), "reason": f"length read failed: {exc}"}
    if len(head) < 4:
        return {"ok": False, "address": hex(addr), "reason": "short string length read"}
    length = _i32(head, 0)
    if length < 0 or length > _LENGTH_CAP:
        return {
            "ok": False, "address": hex(addr), "length": length,
            "reason": (
                f"suspicious Il2CppString length {length}; the address is likely "
                "not a string or the runtime layout is modified (pass a layout override)"
            ),
        }

    truncated = length > max_chars
    n_chars = min(length, max_chars)
    try:
        raw = backend.read(addr + L["string_chars_off"], n_chars * 2)
    except Exception as exc:
        return {"ok": False, "address": hex(addr), "reason": f"chars read failed: {exc}"}
    # drop a dangling odd byte before UTF-16LE decoding
    raw = raw[: len(raw) - (len(raw) & 1)]
    return {
        "ok": True,
        "address": hex(addr),
        "length": length,
        "value": raw.decode("utf-16-le", errors="replace"),
        "truncated": truncated,
    }


def _array_data(backend, arr_addr: int, L: dict):
    """Return ``(element_data_addr, max_length)`` for an ``Il2CppArray``.

    Element data is inline - it starts at ``arr_addr + array_items_off``
    (0x20); there is no items pointer field. Raises ``ValueError`` with a
    human-readable reason on short/failed reads.
    """

    need = max(
        L["array_bounds_off"] + 8,
        L["array_maxlen_off"] + 8,
    )
    buf = backend.read(arr_addr, need)
    if len(buf) < need:
        raise ValueError(f"short Il2CppArray header read at {hex(arr_addr)}")
    max_length = _u64(buf, L["array_maxlen_off"])
    if max_length > _LENGTH_CAP:
        raise ValueError(
            f"suspicious Il2CppArray max_length {max_length} at {hex(arr_addr)}"
        )
    return arr_addr + L["array_items_off"], max_length


def read_array_header(backend, arr_addr: int, *, layout: dict = None) -> dict:
    """Read an ``Il2CppArray`` header: bounds / max_length / items data address."""

    L = _merge_layout(layout)
    arr_addr = int(arr_addr)
    try:
        data_ptr, max_length = _array_data(backend, arr_addr, L)
        bounds = _u64(backend.read(arr_addr + L["array_bounds_off"], 8), 0)
    except Exception as exc:
        return {"ok": False, "address": hex(arr_addr), "reason": str(exc)}
    return {
        "ok": True,
        "address": hex(arr_addr),
        "bounds": hex(bounds) if bounds else None,
        "max_length": max_length,
        "items": hex(data_ptr),
    }


def read_list(backend, list_addr: int, *, elem_size: int = 8, elem_type: str = "ptr",
              limit: int = 100, layout: dict = None) -> dict:
    """Read a ``List<T>``: ``_items`` backing array + ``_size`` -> elements.

    ``elem_type`` selects the per-element decoder (``ptr`` yields hex address
    strings; ``int32``/``int64``/``float``/... yield numbers). At most
    ``limit`` elements are returned; ``truncated`` flags a cut.
    """

    L = _merge_layout(layout)
    list_addr = int(list_addr)
    limit = max(1, int(limit))
    try:
        esize, decode_elem = _elem_spec(elem_type, elem_size)
    except ValueError as exc:
        return {"ok": False, "address": hex(list_addr), "reason": str(exc)}

    need = max(L["list_items_off"] + 8, L["list_size_off"] + 4)
    try:
        buf = backend.read(list_addr, need)
    except Exception as exc:
        return {"ok": False, "address": hex(list_addr), "reason": f"List header read failed: {exc}"}
    if len(buf) < need:
        return {"ok": False, "address": hex(list_addr), "reason": "short List header read"}
    items_ptr = _u64(buf, L["list_items_off"])
    size = _i32(buf, L["list_size_off"])
    if not items_ptr:
        return {"ok": False, "address": hex(list_addr), "reason": "List._items is NULL"}
    if size < 0 or size > _LENGTH_CAP:
        return {
            "ok": False, "address": hex(list_addr), "size": size,
            "reason": f"suspicious List._size {size}; wrong address or modified layout",
        }

    try:
        data_ptr, max_length = _array_data(backend, items_ptr, L)
    except Exception as exc:
        return {"ok": False, "address": hex(list_addr), "reason": f"List._items array read failed: {exc}"}

    truncated = size > limit
    n = min(size, limit)
    elements: list = []
    if n:
        try:
            data = backend.read(data_ptr, n * esize)
        except Exception as exc:
            return {"ok": False, "address": hex(list_addr), "reason": f"element read failed: {exc}"}
        for i in range(len(data) // esize):
            elements.append(decode_elem(data[i * esize : (i + 1) * esize]))
    return {
        "ok": True,
        "address": hex(list_addr),
        "size": size,
        "max_length": max_length,
        "elements": elements,
        "truncated": truncated,
    }


def read_dict(backend, dict_addr: int, *, limit: int = 100, layout: dict = None) -> dict:
    """Read a ``Dictionary<K,V>`` entry table.

    Walks the ``entries`` backing array in ``entry_size`` (24-byte) steps and
    skips free slots (``hashCode == 0``, i.e. the ``next == -1`` empty slots
    left by inserts/removals). Each reported entry carries ``key_ptr`` /
    ``value_ptr`` hex pointers - decode them with :func:`read_string` when
    they point at ``Il2CppString`` objects. ``truncated`` flags a ``limit``
    cut relative to ``count``.
    """

    L = _merge_layout(layout)
    dict_addr = int(dict_addr)
    limit = max(1, int(limit))

    need = max(L["dict_entries_off"] + 8, L["dict_count_off"] + 4)
    try:
        buf = backend.read(dict_addr, need)
    except Exception as exc:
        return {"ok": False, "address": hex(dict_addr), "reason": f"Dictionary header read failed: {exc}"}
    if len(buf) < need:
        return {"ok": False, "address": hex(dict_addr), "reason": "short Dictionary header read"}
    entries_ptr = _u64(buf, L["dict_entries_off"])
    count = _i32(buf, L["dict_count_off"])
    if not entries_ptr:
        return {"ok": False, "address": hex(dict_addr), "reason": "Dictionary.entries is NULL"}
    if count < 0 or count > _LENGTH_CAP:
        return {
            "ok": False, "address": hex(dict_addr), "count": count,
            "reason": f"suspicious Dictionary.count {count}; wrong address or modified layout",
        }

    try:
        data_ptr, max_length = _array_data(backend, entries_ptr, L)
    except Exception as exc:
        return {"ok": False, "address": hex(dict_addr), "reason": f"Dictionary.entries array read failed: {exc}"}

    stride = max(1, L["entry_size"])
    n_slots = min(int(max_length), _MAX_DICT_SLOTS)
    try:
        table = backend.read(data_ptr, n_slots * stride)
    except Exception as exc:
        return {"ok": False, "address": hex(dict_addr), "reason": f"entry table read failed: {exc}"}

    entries: list[dict] = []
    slots_read = len(table) // stride
    for i in range(slots_read):
        if len(entries) >= limit:
            break
        off = i * stride
        if off + stride > len(table):
            break
        hash_code = _i32(table, off)
        key = _u64(table, off + L["entry_key_off"])
        value = _u64(table, off + L["entry_value_off"])
        # free slot: Dictionary clears hashCode on removal; a terminal empty
        # slot also carries next == -1 (a live end-of-chain entry keeps its
        # non-zero hashCode and is reported normally)
        if hash_code == 0:
            continue
        entries.append({"key_ptr": hex(key), "value_ptr": hex(value), "hash_code": hash_code})

    return {
        "ok": True,
        "address": hex(dict_addr),
        "count": count,
        "entries": entries,
        "truncated": count > len(entries),
    }

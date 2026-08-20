"""FName reading / decoding / comparison (read-only).

An ``FName`` is an 8-byte handle: a 32-bit ``comparison_index`` into the
global name pool plus a 32-bit ``number`` (instance suffix counter). Equality
is decided by the index alone (:func:`compare_fname`) which keeps comparisons
as pure integer operations - no string decoding needed in hot loops.

Decoding resolves the index against the FNamePool block table:
``entry = Blocks[index / per_chunk] + (index % per_chunk) * entry_stride``.
Two entry dialects are supported:

* ``string_offset == 2``: a ``uint16`` header carries the length (``len =
  header >> 1``) and the wide flag (low bit); the string starts at +2.
* ``string_offset == 8`` (UE5-style): the string starts at +8 and is
  null-terminated within the read window.

A fixed 64-byte window is read first; only when the declared length (or the
missing null terminator) exceeds it is a single supplementary read issued, so
each unique index costs at most two reads when a cache is passed.
"""

from __future__ import annotations

from typing import Optional

_WINDOW = 64


def read_fname(backend, addr: int) -> dict:
    """Read a raw FName handle at ``addr`` (8 bytes).

    Returns ``{"comparison_index": int, "number": int}``.
    """

    data = backend.read(int(addr), 8)
    if len(data) < 8:
        raise ValueError(f"short FName read at {hex(int(addr))}")
    return {
        "comparison_index": int.from_bytes(data[0:4], "little"),
        "number": int.from_bytes(data[4:8], "little"),
    }


def compare_fname(a: dict, b: dict) -> dict:
    """Pure integer FName comparison: equality is decided by the index only.

    The ``number`` suffix (e.g. ``MyActor_0`` vs ``MyActor_1``) does not
    affect name-table identity, so it is intentionally ignored.
    """

    return {
        "equal": int(a["comparison_index"]) == int(b["comparison_index"]),
        "basis": "index",
    }


def _fname_layout(layout: dict) -> dict:
    """Normalise ``layout`` into a flat fname-pool descriptor.

    Accepts either a flat dict (``blocks_address`` / ``entry_stride`` / ...)
    or a full :func:`introspect` result (nested ``hypotheses``/``resolved``).
    """

    if isinstance(layout.get("blocks_address"), int) and "entry_stride" in layout:
        return {
            "blocks_address": layout["blocks_address"],
            "per_chunk": int(layout.get("per_chunk", 16384)),
            "entry_stride": int(layout["entry_stride"]),
            "string_offset": int(layout.get("string_offset", 2)),
            "wide": bool(layout.get("wide", False)),
        }

    hyp = (layout.get("hypotheses") or {}).get("fname_pool") or {}
    chosen = hyp.get("chosen") or {}
    resolved = layout.get("resolved") or {}
    blocks = chosen.get("blocks_address", resolved.get("gnames_blocks"))
    if isinstance(blocks, str):
        blocks = int(blocks, 16)
    return {
        "blocks_address": blocks,
        "per_chunk": int(hyp.get("per_chunk", 16384)),
        "entry_stride": int(chosen.get("entry_stride", 0xC)),
        "string_offset": int(chosen.get("string_offset", 2)),
        "wide": bool(chosen.get("wide", False)),
    }


def _decode_raw(raw: bytes, wide: bool) -> str:
    if wide:
        # trim a dangling odd byte, then UTF-16LE
        raw = raw[: len(raw) - (len(raw) & 1)]
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("latin-1", errors="replace")


def _null_terminator(buf: bytes, wide: bool) -> Optional[int]:
    """Byte-length of the string in ``buf`` (up to the terminator), or None."""

    if wide:
        for i in range(0, len(buf) - 1, 2):
            if buf[i] == 0 and buf[i + 1] == 0:
                return i
        return None
    pos = buf.find(b"\x00")
    return None if pos == -1 else pos


def decode_fname(backend, layout: dict, index: int, *, cache: Optional[dict] = None) -> str:
    """Decode a name-pool ``index`` into its string.

    ``cache`` (a plain dict shared across calls) deduplicates indices; each
    unique index performs at most two reads (block pointer lookups are folded
    into the same budget).
    """

    L = _fname_layout(layout)
    blocks_address = L["blocks_address"]
    if not blocks_address:
        raise ValueError("layout has no fname pool blocks address")
    index = int(index)
    if cache is not None and index in cache:
        return cache[index]

    per_chunk = max(1, L["per_chunk"])
    stride = max(1, L["entry_stride"])
    soff = L["string_offset"]

    block_ptr_addr = blocks_address + (index // per_chunk) * 8
    block_data = backend.read(block_ptr_addr, 8)
    if len(block_data) < 8:
        raise ValueError(f"short block-pointer read at {hex(block_ptr_addr)}")
    block_ptr = int.from_bytes(block_data[:8], "little")
    entry = block_ptr + (index % per_chunk) * stride

    window = backend.read(entry, _WINDOW)  # read #1
    wide = L["wide"]
    if soff == 2 and len(window) >= 2:
        header = int.from_bytes(window[0:2], "little")
        wide = bool(header & 1) or wide
        length = header >> 1
        csize = 2 if wide else 1
        need = soff + length * csize
        buf = window
        if need > len(buf):
            # supplementary read #2, issued only when the declared length
            # exceeds the fixed window
            buf = buf + backend.read(entry + len(buf), need - len(buf))
        raw = buf[soff : soff + length * csize]
        text = _decode_raw(raw, wide)
    else:
        buf = window[soff:] if soff < len(window) else b""
        term = _null_terminator(buf, wide)
        if term is None:
            buf = buf + backend.read(entry + _WINDOW, _WINDOW)  # read #2
            term = _null_terminator(buf, wide)
            if term is None:
                term = len(buf)
        text = _decode_raw(buf[:term], wide)

    if cache is not None:
        cache[index] = text
    return text

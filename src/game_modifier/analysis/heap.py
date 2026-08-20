"""Heap object enumeration.

Walks writable, non-executable regions (the private heaps in practice) and
enumerates pointer-aligned object candidates. Optionally filters to objects
whose first word equals a given vtable address. Read-only throughout.
"""

from __future__ import annotations

from typing import Optional

from ..memory.base import MemoryBackend
from .alignment import build_intervals, in_intervals

_CHUNK = 1024 * 1024


def scan_heap_objects(backend: MemoryBackend, *, vtable_addr: Optional[int] = None, max_results: int = 500) -> dict:
    """Enumerate object candidates on heap-like regions.

    With ``vtable_addr`` only objects whose first pointer equals it are kept
    (``vtable`` echoes the filter); without it, every aligned slot whose value
    has pointer shape is a candidate (``vtable`` is ``None``).
    Returns ``{"objects": [{"address"(hex), "vtable"(hex|None)}],
    "truncated": bool, "confidence", "reason"}``.
    """

    psize = backend.pointer_size
    regions = list(backend.regions())
    starts, ends = build_intervals((r.base, r.end) for r in regions)
    filter_value = int(vtable_addr) if vtable_addr is not None else None

    objects: list[dict] = []
    truncated = False
    scanned = 0

    for region in regions:
        if not (region.readable and region.writable) or region.executable:
            continue
        offset = 0
        while offset < region.size:
            to_read = min(_CHUNK, region.size - offset)
            try:
                data = backend.read(region.base + offset, to_read)
            except Exception:
                break
            if len(data) < psize:
                break
            scanned += len(data)
            chunk_base = region.base + offset
            first_aligned = (-chunk_base) % psize
            limit = len(data) - psize
            i = first_aligned
            while i <= limit:
                value = int.from_bytes(data[i : i + psize], "little")
                if filter_value is not None:
                    is_obj = value == filter_value
                    vt = filter_value if is_obj else None
                else:
                    is_obj = value != 0 and (value & (psize - 1)) == 0 and in_intervals(starts, ends, value)
                    vt = None
                if is_obj:
                    objects.append({"address": hex(chunk_base + i), "vtable": hex(vt) if vt else None})
                    if len(objects) >= max_results:
                        truncated = True
                        return _finish(objects, truncated, filter_value, scanned)
                i += psize
            if to_read < _CHUNK:
                break
            offset += to_read - (psize - 1)

    return _finish(objects, truncated, filter_value, scanned)


def _finish(objects: list[dict], truncated: bool, filter_value: Optional[int], scanned: int) -> dict:
    if filter_value is not None:
        confidence = 0.9 if objects else 0.1
        reason = f"{len(objects)} object(s) matched vtable {hex(filter_value)}"
    else:
        confidence = 0.4 if objects else 0.1
        reason = f"{len(objects)} pointer-shaped candidate(s) across {scanned} bytes of heap memory"
    return {
        "objects": objects,
        "truncated": truncated,
        "confidence": confidence,
        "reason": reason,
    }

"""UE Actor enumeration over GObjects (read-only, batch-read optimised).

Three-level batch read pipeline:

* L0: one read of the TUObjectArray chunk pointer table;
* L1: one ``read`` per chunk (segmented below 1 MB) decoding the whole
  ``FUObjectItem`` array via ``struct.unpack_from``;
* L2: :func:`_read_span_groups` - sorted nearby addresses are merged into one
  bare ``read(start, span)`` per group (falling back to per-address reads when
  a group span fails). ``read_many`` is deliberately not used. One 0x20-byte
  span covers both ``ClassPrivate`` (+0x10) and the object FName (+0x18).

Three caches keep reads at O(chunks + groups), not O(objects):

* ``class_cache``: one 0x48-byte read per unique UClass (NamePrivate +0x18,
  SuperStruct +0x40);
* ``actor_verdict_cache``: per class pointer, whether the Super chain reaches
  ``"Actor"``;
* ``fname_cache``: decoded name strings per unique name index.

Per-item read failures count into ``skipped`` and never abort the walk; the
wall-clock budget raises :class:`ScanTimeoutError` with partial progress.
"""

from __future__ import annotations

import struct
import time

from ...errors import ScanTimeoutError
from .fname import _fname_layout, decode_fname

# UObject field offsets (x64)
_CLASS_OFFSET = 0x10      # UClass* ClassPrivate
_NAME_OFFSET = 0x18       # FName NamePrivate
_SUPER_OFFSET = 0x40      # UClass* SuperStruct (in UClass)
_OBJ_SPAN = 0x20          # covers ClassPrivate + NamePrivate
_CLASS_SPAN = 0x48        # covers NamePrivate + SuperStruct

_MAX_SUPER_DEPTH = 32
_DEFAULT_MAX_OBJECTS = 100_000
_SEGMENT_BYTES = 1024 * 1024  # L1 chunk reads above this are segmented
_TIMEOUT_CHECK_EVERY = 128


def _u64(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off : off + 8], "little")


def _u32(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off : off + 4], "little")


def _read_span_groups(backend, addrs: list[int], size: int, gap: int) -> dict:
    """Read ``size`` bytes at each address, merging nearby addresses.

    Sorted addresses whose distance from the previous span end is ``<= gap``
    are grouped into a single ``read(start, span)``; a failed group read
    degrades to per-address reads inside the group. Returns
    ``{address: bytes}`` for every successfully read address.
    """

    out: dict[int, bytes] = {}
    if not addrs:
        return out
    groups: list[list] = []  # [start, end, [addrs]]
    for a in sorted(set(int(x) for x in addrs)):
        if groups and a <= groups[-1][1] + gap:
            groups[-1][1] = max(groups[-1][1], a + size)
            groups[-1][2].append(a)
        else:
            groups.append([a, a + size, [a]])
    for start, end, gaddrs in groups:
        try:
            buf = backend.read(start, end - start)
            for a in gaddrs:
                off = a - start
                if off + size <= len(buf):
                    out[a] = buf[off : off + size]
        except Exception:
            # span read failed: degrade to per-address reads
            for a in gaddrs:
                try:
                    out[a] = backend.read(a, size)
                except Exception:
                    continue
    return out


def _as_int(value) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        return int(value, 16)
    return int(value)


def _actor_layout(layout: dict) -> dict:
    """Extract GObjects walk parameters from a flat dict or introspect result."""

    resolved = layout.get("resolved") or {}
    hyp = layout.get("hypotheses") or {}
    stride_hyp = hyp.get("item_stride") or {}
    chunk_table = _as_int(resolved.get("chunk_ptrs") or resolved.get("gobjects_array"))
    return {
        "chunk_table": chunk_table,
        "num_elements": int(resolved.get("num_elements") or 0),
        "item_stride": int(resolved.get("item_stride") or stride_hyp.get("chosen") or 0x18),
        "objects_per_chunk": int(resolved.get("objects_per_chunk") or 65536),
        "max_chunks": int(resolved.get("max_chunks") or 512),
        "max_objects_cfg": int(resolved.get("max_objects") or 0),
    }


def enumerate_actors(backend, layout: dict, *, limit: int = 100,
                     name_filter=None, class_filter=None,
                     timeout: float = 30.0, max_objects=None,
                     batch_gap: int = 256, list_results: bool = False) -> dict:
    """Enumerate Actor instances via the GObjects chunked array.

    Default output aggregates ``by_class`` counts; ``list_results=True`` adds
    per-actor detail (``address`` / ``class_name`` / ``name``). ``limit`` and
    the filters converge the stream before reporting; ``max_objects`` caps how
    many GObjects entries are examined overall. Read failures on single items
    are counted in ``skipped`` and never abort the walk. Raises
    :class:`ScanTimeoutError` (with partial progress) past ``timeout``.
    """

    started = time.monotonic()
    deadline = started + float(timeout)
    info = _actor_layout(layout)
    chunk_table = info["chunk_table"]
    num = info["num_elements"]
    stride = max(8, info["item_stride"])
    per_chunk = max(1, info["objects_per_chunk"])
    if max_objects is None:
        max_objects = info["max_objects_cfg"] or _DEFAULT_MAX_OBJECTS
    max_objects = max(1, int(max_objects))

    try:
        fname_layout = _fname_layout(layout)
        have_fname = bool(fname_layout.get("blocks_address"))
    except Exception:
        have_fname = False

    by_class: dict[str, int] = {}
    details: list[dict] = []
    examined = 0
    skipped = 0
    actors_found = 0
    truncated = False

    def _check(stage: str) -> None:
        if time.monotonic() >= deadline:
            raise ScanTimeoutError(
                f"actor enumeration exceeded {timeout}s at {stage}",
                details={
                    "timeout": timeout,
                    "stage": stage,
                    "objects_examined": examined,
                    "actors_found": actors_found,
                    "skipped": skipped,
                    "by_class": dict(by_class),
                },
                hint="Lower limit/max_objects or raise the timeout.",
            )

    if not chunk_table or num <= 0:
        return {
            "by_class": {}, "totals": {"objects_examined": 0, "actors": 0, "unique_classes": 0},
            "truncated": False, "skipped": 0,
            "elapsed": round(time.monotonic() - started, 3),
            "note": "layout lacks a usable GObjects chunk table",
        }

    # ------------------------------------------------------------- L0: table
    _check("L0")
    chunk_count = min(info["max_chunks"], (num + per_chunk - 1) // per_chunk)
    table = backend.read(chunk_table, chunk_count * 8)
    chunk_ptrs = [_u64(table, i * 8) for i in range(min(chunk_count, len(table) // 8))]

    # ------------------------------------------------------------ three caches
    class_cache: dict[int, object] = {}     # class_ptr -> (name_index, super_ptr) | None
    verdict_cache: dict[int, bool] = {}     # class_ptr -> is Actor subclass
    fname_cache: dict[int, str] = {}        # name index -> decoded string

    def _class_info(class_ptr: int):
        if class_ptr in class_cache:
            return class_cache[class_ptr]
        entry = None
        try:
            data = backend.read(class_ptr, _CLASS_SPAN)
            if len(data) >= _CLASS_SPAN:
                entry = (_u32(data, _NAME_OFFSET), _u64(data, _SUPER_OFFSET))
        except Exception:
            entry = None
        class_cache[class_ptr] = entry
        return entry

    def _class_name(class_ptr: int):
        ci = _class_info(class_ptr)
        if ci is None:
            return None
        if not have_fname:
            return f"0x{class_ptr:x}"
        try:
            return decode_fname(backend, layout, ci[0], cache=fname_cache)
        except Exception:
            return None

    def _is_actor(class_ptr: int) -> bool:
        if class_ptr in verdict_cache:
            return verdict_cache[class_ptr]
        verdict = False
        cur = class_ptr
        seen: set[int] = set()
        for _ in range(_MAX_SUPER_DEPTH):
            if not cur or cur in seen:
                break
            seen.add(cur)
            if _class_name(cur) == "Actor":
                verdict = True
                break
            ci = _class_info(cur)
            if ci is None:
                break
            cur = ci[1]
        verdict_cache[class_ptr] = verdict
        return verdict

    # ------------------------------------------------- L1/L2: chunk pipeline
    remaining = max_objects
    for ci, chunk_ptr in enumerate(chunk_ptrs):
        _check("L1")
        if remaining <= 0:
            truncated = True
            break
        if not chunk_ptr:
            continue
        items = min(per_chunk, num - ci * per_chunk, remaining)
        remaining -= items
        examined += items

        # L1: whole-chunk FUObjectItem array, one read per <=1MB segment
        obj_ptrs: list[int] = []
        items_per_seg = max(1, _SEGMENT_BYTES // stride)
        pos = 0
        while pos < items:
            n = min(items_per_seg, items - pos)
            try:
                data = backend.read(chunk_ptr + pos * stride, n * stride)
            except Exception:
                skipped += n
                pos += n
                continue
            limit_i = min(n, len(data) // stride)
            for j in range(limit_i):
                # <Q = UObject* at +0, <i = SerialNumber at +0x10 (decoded to
                # validate the item layout; only the pointer feeds L2)
                if j * stride + 0x14 > len(data):
                    skipped += 1
                    continue
                (obj_ptr,) = struct.unpack_from("<Q", data, j * stride)
                (_serial,) = struct.unpack_from("<i", data, j * stride + 0x10)
                if obj_ptr:
                    obj_ptrs.append(obj_ptr)
            if limit_i < n:
                skipped += n - limit_i
            pos += n
        if not obj_ptrs:
            continue

        # L2: grouped span reads (one 0x20 window covers class + FName)
        _check("L2")
        spans = _read_span_groups(backend, obj_ptrs, _OBJ_SPAN, batch_gap)
        loop_i = 0
        for addr in obj_ptrs:
            loop_i += 1
            if loop_i % _TIMEOUT_CHECK_EVERY == 0:
                _check("L2-items")
            if truncated:
                break
            obj = spans.get(addr)
            if obj is None or len(obj) < _OBJ_SPAN:
                skipped += 1
                continue
            class_ptr = _u64(obj, _CLASS_OFFSET)
            if not class_ptr:
                skipped += 1
                continue
            if not _is_actor(class_ptr):
                continue
            cname = _class_name(class_ptr) or f"0x{class_ptr:x}"
            if class_filter and class_filter.lower() not in cname.lower():
                continue
            oname = ""
            if have_fname:
                try:
                    oname = decode_fname(backend, layout, _u32(obj, _NAME_OFFSET), cache=fname_cache)
                except Exception:
                    oname = ""
            if name_filter and name_filter.lower() not in oname.lower():
                continue
            actors_found += 1
            by_class[cname] = by_class.get(cname, 0) + 1
            if list_results:
                details.append({"address": hex(addr), "class_name": cname, "name": oname})
            if actors_found >= limit:
                truncated = True
                break

    out = {
        "by_class": by_class,
        "totals": {
            "objects_examined": examined,
            "actors": actors_found,
            "unique_classes": len(by_class),
        },
        "truncated": truncated,
        "skipped": skipped,
        "elapsed": round(time.monotonic() - started, 3),
    }
    if list_results:
        out["actors"] = details
    return out

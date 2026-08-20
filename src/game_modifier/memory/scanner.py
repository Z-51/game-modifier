"""Value scanner: first scan + iterative refinement (next scan).

Works against any :class:`MemoryBackend`, so tests can drive it with a fake
process. The first scan walks committed, readable regions; subsequent scans
re-read only the surviving candidate addresses, which is both fast and how a
Cheat-Engine-style narrowing workflow keeps agent token usage tiny (the agent
just passes the new observed value).
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..errors import InvalidArgsError
from . import types as vt
from .base import MemoryBackend

try:
    import numpy as _np
except Exception:  # pragma: no cover - numpy is optional
    _np = None

FIRST_SCAN_COMPARATORS = {"exact", "not_equal", "gt", "gte", "lt", "lte", "between", "unknown"}
NEXT_SCAN_COMPARATORS = FIRST_SCAN_COMPARATORS | {
    "changed",
    "unchanged",
    "increased",
    "decreased",
}
# Variable-length types (string/bytes) can only be re-compared against the
# value recorded by the previous scan; numeric predicates make no sense there.
VARLEN_NEXT_SCAN_COMPARATORS = {"exact", "changed", "unchanged"}


@dataclass
class ScanResult:
    type: str
    comparator: str
    count: int
    truncated: bool
    addresses: list[int] = field(default_factory=list)
    values: dict[int, object] = field(default_factory=dict)
    scanned_regions: int = 0
    scanned_bytes: int = 0

    def to_dict(self, *, sample: int = 20, offset: int = 0, limit: Optional[int] = None) -> dict:
        """Serialise the result. ``offset``/``limit`` page the address window:
        with ``limit=None`` the historical behaviour is kept (first ``sample``
        addresses); with an explicit ``limit`` the window is
        ``addresses[offset:offset+limit]``."""

        offset = max(0, offset)
        if limit is None:
            addrs = self.addresses[offset:offset + sample]
        else:
            addrs = self.addresses[offset:offset + max(0, limit)]
        return {
            "type": self.type,
            "comparator": self.comparator,
            "count": self.count,
            "truncated": self.truncated,
            "addresses_hex": [hex(a) for a in addrs],
            "sample_values": {hex(a): self.values.get(a) for a in addrs if a in self.values},
            "scanned_regions": self.scanned_regions,
            "scanned_bytes": self.scanned_bytes,
            "page": {"offset": offset, "limit": limit},
        }


def _canon(type_name: str, value) -> object:
    """Canonical Python value as it would be stored (encode then decode)."""

    return vt.decode_value(type_name, vt.encode_value(type_name, value))


def filter_regions(regions, *, min_addr: Optional[int] = None, max_addr: Optional[int] = None,
                   region_types: Optional[list[int]] = None) -> list:
    """Pre-filter a region list before scanning.

    ``min_addr``/``max_addr`` keep regions overlapping ``[min_addr, max_addr]``;
    ``region_types`` keeps regions whose ``MemoryRegion.type`` is in the set
    (Windows MEM_* constants, e.g. 0x1000000 MEM_IMAGE, 0x20000 MEM_PRIVATE,
    0x40000 MEM_MAPPED). All filters default to None = no filtering, i.e. the
    historical behaviour.
    """

    types = set(int(t) for t in region_types) if region_types else None
    out = []
    for r in regions:
        if min_addr is not None and r.end <= min_addr:
            continue
        if max_addr is not None and r.base > max_addr:
            continue
        if types is not None and r.type not in types:
            continue
        out.append(r)
    return out


def _emit_progress(cb: Optional[Callable[[dict], None]], result: "ScanResult", done: int, total: int) -> None:
    """Best-effort progress callback; callback errors never break the scan."""

    if cb is None:
        return
    try:
        cb({
            "regions_done": done,
            "regions_total": total,
            "bytes_scanned": result.scanned_bytes,
            "hits": len(result.addresses),
        })
    except Exception:
        pass


def _compare(comparator: str, cur, value, value2, prev) -> bool:
    if comparator == "exact":
        return cur == value
    if comparator == "not_equal":
        return cur != value
    if comparator == "gt":
        return cur > value
    if comparator == "gte":
        return cur >= value
    if comparator == "lt":
        return cur < value
    if comparator == "lte":
        return cur <= value
    if comparator == "between":
        lo, hi = (value, value2) if value <= value2 else (value2, value)
        return lo <= cur <= hi
    if comparator == "changed":
        return prev is not None and cur != prev
    if comparator == "unchanged":
        return prev is not None and cur == prev
    if comparator == "increased":
        return prev is not None and cur > prev
    if comparator == "decreased":
        return prev is not None and cur < prev
    if comparator == "unknown":
        return True
    raise InvalidArgsError(f"unknown comparator: {comparator!r}", details={"supported": sorted(NEXT_SCAN_COMPARATORS)})


def first_scan(
    backend: MemoryBackend,
    type_name: str,
    value=None,
    *,
    comparator: str = "exact",
    value2=None,
    max_results: int = 20000,
    chunk_size: int = 4 * 1024 * 1024,
    alignment: int = 4,
    max_region_bytes: int = 0,
    workers: int = 1,
    backend_factory: Optional[Callable[[], MemoryBackend]] = None,
    progress_cb: Optional[Callable[[dict], None]] = None,
    min_addr: Optional[int] = None,
    max_addr: Optional[int] = None,
    region_types: Optional[list[int]] = None,
) -> ScanResult:
    """Search all readable regions for values matching the predicate.

    Numeric fixed-size types take a numpy vectorised path when numpy is
    available (including ``alignment < size`` via multiple aligned offset
    views); every other combination falls back to the pure-Python slot loop.
    Both paths produce byte-for-byte identical candidate sets.

    ``workers`` > 1 scans readable regions in parallel with a thread pool.
    Each worker opens its own backend via ``backend_factory`` (a zero-arg
    callable). Without a factory the scan degrades to single-threaded with a
    warning; without numpy ``workers`` > 1 also degrades to single-threaded
    (the pure-Python slot loop gains nothing from threading under the GIL).
    The main thread aggregates partial results in region order, so the
    candidate list is deterministic and identical to the ``workers=1`` run.

    ``progress_cb`` (optional) is invoked after each region completes with
    ``{"regions_done", "regions_total", "bytes_scanned", "hits"}``; callback
    exceptions are swallowed. On truncation the scan stops early, so
    ``regions_done`` may end below ``regions_total``.
    """

    if comparator not in FIRST_SCAN_COMPARATORS:
        raise InvalidArgsError(
            f"comparator {comparator!r} needs a previous scan",
            details={"first_scan_supports": sorted(FIRST_SCAN_COMPARATORS)},
        )
    dt = vt.resolve_type(type_name)
    size = dt.size

    result = ScanResult(type=dt.name, comparator=comparator, count=0, truncated=False)

    # variable-length (string / bytes): exact byte-substring search only
    if size is None:
        if comparator != "exact":
            raise InvalidArgsError(f"type {dt.name} supports only 'exact' scans")
        needle = vt.encode_value(type_name, value)
        return _scan_bytes(backend, dt.name, needle, result, max_results, chunk_size, max_region_bytes, progress_cb,
                           min_addr=min_addr, max_addr=max_addr, region_types=region_types)

    target = _canon(type_name, value) if value is not None and comparator != "unknown" else None
    target2 = _canon(type_name, value2) if value2 is not None else None
    alignment = max(1, alignment)

    plan = _vector_plan(dt, comparator, target, target2)
    # The vector path reproduces the scalar slot walk exactly when the slot
    # grid maps onto flat array views: alignment == size (one view) or a
    # sub-size alignment that divides the type size (multiple offset views).
    vec_ok = alignment == size or (alignment < size and size % alignment == 0)
    use_vector = _np is not None and plan is not None and _np_dtype(dt) is not None and vec_ok

    regions = [
        r for r in backend.readable_regions()
        if not (max_region_bytes and r.size > max_region_bytes)
    ]
    # optional region pre-filter (address range / MemoryRegion.type); all
    # filters default to None which keeps the historical region set
    regions = filter_regions(regions, min_addr=min_addr, max_addr=max_addr, region_types=region_types)

    if workers > 1 and _np is None:
        # threading the scalar loop only adds overhead under the GIL
        workers = 1
    if workers > 1 and backend_factory is None:
        import warnings

        warnings.warn(
            "first_scan: workers>1 requires backend_factory for per-thread backends; "
            "falling back to single-threaded scan",
            stacklevel=2,
        )
        workers = 1
    if workers > 1:
        return _first_scan_parallel(
            regions, backend_factory, result, type_name, comparator, target, target2,
            plan, use_vector, max_results, chunk_size, alignment, size, dt, workers,
            progress_cb,
        )

    if progress_cb is None:
        if use_vector:
            _scan_regions_vector(regions, result, type_name, plan, max_results, chunk_size, alignment, size, dt, backend=backend)
        else:
            _scan_regions_scalar(backend, regions, result, type_name, comparator, target, target2, max_results, chunk_size, alignment, size)
        return result

    # progress reporting: scan one region at a time so the callback can fire
    # after each completes (same aggregation order, identical candidate set)
    total = len(regions)
    for i, region in enumerate(regions, 1):
        if use_vector:
            _scan_regions_vector([region], result, type_name, plan, max_results, chunk_size, alignment, size, dt, backend=backend)
        else:
            _scan_regions_scalar(backend, [region], result, type_name, comparator, target, target2, max_results, chunk_size, alignment, size)
        _emit_progress(progress_cb, result, i, total)
        if result.truncated:
            break
    return result


# --------------------------------------------------------- serial region loops
def _scan_regions_scalar(backend, regions, result, type_name, comparator, target, target2, max_results, chunk_size, alignment, size) -> None:
    """Pure-Python aligned-slot scan over ``regions`` (mutates ``result``)."""

    for region in regions:
        result.scanned_regions += 1
        offset = 0
        while offset < region.size:
            to_read = min(chunk_size, region.size - offset)
            try:
                data = backend.read(region.base + offset, to_read)
            except Exception:
                break
            if not data:
                break
            result.scanned_bytes += len(data)
            # iterate aligned slots that fully fit within the chunk
            region_addr = region.base + offset
            first_aligned = (-region_addr) % alignment
            i = first_aligned
            limit = len(data) - size
            while i <= limit:
                try:
                    cur = vt.decode_value(type_name, data[i : i + size])
                except Exception:
                    i += alignment
                    continue
                if _compare(comparator, cur, target, target2, None):
                    addr = region_addr + i
                    result.addresses.append(addr)
                    result.values[addr] = cur
                    if len(result.addresses) >= max_results:
                        result.truncated = True
                        result.count = len(result.addresses)
                        return
                i += alignment
            # advance, keeping (size-1) overlap so a value straddling the chunk
            # boundary is not missed
            if to_read < chunk_size:
                break
            offset += to_read - (size - 1)
    result.count = len(result.addresses)


def _vector_plan(dt, comparator: str, target, target2) -> Optional[dict]:
    """Build a numpy comparison plan for a numeric fixed-size type, or None.

    Only simple scalar comparators map cleanly onto vector operations; the
    ``unknown`` comparator matches every slot so it has no dedicated plan (the
    caller still benefits from the aligned-slot loop below).
    """

    if _np is None or dt.kind not in ("int", "uint", "float") or dt.fmt is None:
        return None
    if comparator == "exact" and target is not None:
        return {"kind": "exact", "value": target}
    if comparator == "not_equal" and target is not None:
        return {"kind": "neq", "value": target}
    if comparator in ("gt", "gte", "lt", "lte") and target is not None:
        return {"kind": comparator, "value": target}
    if comparator == "between" and target is not None and target2 is not None:
        return {"kind": "between", "lo": min(target, target2), "hi": max(target, target2)}
    return None


def _scan_regions_vector(regions, result, type_name, plan, max_results, chunk_size, alignment, size, dt, *, backend=None, stop_flag=None) -> None:
    """numpy-accelerated scan over ``regions`` (mutates ``result``).

    ``alignment == size`` scans each chunk as a single flat array;
    ``alignment < size`` scans multiple offset views (one per residue class of
    the alignment) so the candidate set matches the pure-Python slot loop
    byte-for-byte.
    """

    np = _np
    dtype = _np_dtype(dt)
    if dtype is None:
        return

    for region in regions:
        result.scanned_regions += 1
        offset = 0
        while offset < region.size:
            if stop_flag is not None and stop_flag.is_set():
                break
            to_read = min(chunk_size, region.size - offset)
            try:
                data = backend.read(region.base + offset, to_read)
            except Exception:
                break
            if not data:
                break
            result.scanned_bytes += len(data)
            chunk_base = region.base + offset
            # One flat view per slot residue class: a single view when
            # alignment >= size, otherwise one view per alignment-sized offset
            # (each re-aligned to an absolute alignment boundary). Hits are
            # merged in ascending address order so the candidate list matches
            # the scalar slot walk byte-for-byte.
            view_offsets = (0,) if alignment >= size else tuple(range(0, size, alignment))
            chunk_hits: list = []
            for view_start in view_offsets:
                view_addr = chunk_base + view_start
                lead = (-view_addr) % alignment if alignment < size else (-view_addr) % size
                if view_start + lead >= len(data):
                    continue
                view = data[view_start + lead:]
                # slots must fit wholly inside the chunk - identical to the
                # scalar loop's ``i <= len(data) - size`` condition; the
                # (size-1) chunk overlap takes care of straddling values
                n = len(view) // size
                if n <= 0:
                    continue
                try:
                    arr = np.frombuffer(view[: n * size], dtype=dtype)
                except Exception:  # pragma: no cover - defensive
                    continue
                mask = _apply_plan(arr, plan)
                if mask is None:
                    continue
                idxs = np.nonzero(mask)[0]
                if idxs.size == 0:
                    continue
                # batched hit materialisation: vector address arithmetic + a
                # single tolist() instead of per-element Python extraction
                addrs = (view_addr + lead + idxs * size).tolist()
                chunk_hits.extend(zip(addrs, arr[idxs].tolist()))
            if chunk_hits:
                if len(view_offsets) > 1:
                    chunk_hits.sort(key=lambda hv: hv[0])
                if len(result.addresses) + len(chunk_hits) > max_results:
                    chunk_hits = chunk_hits[: max_results - len(result.addresses)]
                for addr, cur in chunk_hits:
                    result.addresses.append(addr)
                    result.values[addr] = cur
                if len(result.addresses) >= max_results:
                    result.truncated = True
                    result.count = len(result.addresses)
                    return
            if to_read < chunk_size:
                break
            offset += to_read - (size - 1)
    result.count = len(result.addresses)


def _np_dtype(dt):
    """Map a numeric DataType to a numpy dtype (little-endian)."""

    if _np is None or dt.kind not in ("int", "uint", "float"):
        return None
    if dt.name == "int8":
        return _np.int8
    if dt.name == "uint8":
        return _np.uint8
    if dt.name == "int16":
        return _np.int16
    if dt.name == "uint16":
        return _np.uint16
    if dt.name == "int32":
        return _np.int32
    if dt.name == "uint32":
        return _np.uint32
    if dt.name == "int64":
        return _np.int64
    if dt.name == "uint64":
        return _np.uint64
    if dt.name == "float":
        return _np.float32
    if dt.name == "double":
        return _np.float64
    return None


def _apply_plan(arr, plan: dict):
    if _np is None:
        return None
    kind = plan["kind"]
    if kind == "exact":
        return arr == plan["value"]
    if kind == "neq":
        return arr != plan["value"]
    if kind == "gt":
        return arr > plan["value"]
    if kind == "gte":
        return arr >= plan["value"]
    if kind == "lt":
        return arr < plan["value"]
    if kind == "lte":
        return arr <= plan["value"]
    if kind == "between":
        return (arr >= plan["lo"]) & (arr <= plan["hi"])
    return None


# ------------------------------------------------------------- parallel scan
def _first_scan_parallel(
    regions, backend_factory, result, type_name, comparator, target, target2,
    plan, use_vector, max_results, chunk_size, alignment, size, dt, workers,
    progress_cb=None,
) -> ScanResult:
    """Thread-pool first scan; aggregates per-region partials in region order.

    Deterministic: partial results are merged in the original region order and
    trimmed to ``max_results`` afterwards, which matches the serial walk.
    """

    stop_flag = threading.Event()
    parts: list[Optional[ScanResult]] = [None] * len(regions)

    def _worker(idx: int, region) -> tuple:
        b = backend_factory()
        part = ScanResult(type=result.type, comparator=result.comparator, count=0, truncated=False)
        try:
            if use_vector:
                _scan_regions_vector([region], part, type_name, plan, max_results, chunk_size, alignment, size, dt, backend=b, stop_flag=stop_flag)
            else:
                _scan_regions_scalar(b, [region], part, type_name, comparator, target, target2, max_results, chunk_size, alignment, size)
        finally:
            try:
                b.close()
            except Exception:
                pass
        return idx, part

    total = len(regions)
    done = 0
    bytes_acc = 0
    hits_acc = 0
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_worker, i, regions[i]) for i in range(len(regions))]
            for fut in futures:
                idx, part = fut.result()
                parts[idx] = part
                # progress reflects completed regions (completion order, best-effort)
                done += 1
                bytes_acc += part.scanned_bytes
                hits_acc += len(part.addresses)
                if progress_cb is not None:
                    try:
                        progress_cb({
                            "regions_done": done,
                            "regions_total": total,
                            "bytes_scanned": bytes_acc,
                            "hits": hits_acc,
                        })
                    except Exception:
                        pass
                if part.truncated:
                    stop_flag.set()
    except Exception:
        stop_flag.set()
        raise

    # aggregate in region order for deterministic output
    for part in parts:
        if part is None:
            continue
        result.scanned_regions += part.scanned_regions
        result.scanned_bytes += part.scanned_bytes
        for addr in part.addresses:
            result.addresses.append(addr)
            result.values[addr] = part.values[addr]
    if len(result.addresses) > max_results:
        trimmed = result.addresses[:max_results]
        result.values = {a: result.values[a] for a in trimmed}
        result.addresses = trimmed
        result.truncated = True
    result.count = len(result.addresses)
    return result


def _scan_bytes(backend, type_name, needle, result, max_results, chunk_size, max_region_bytes, progress_cb=None,
                *, min_addr: Optional[int] = None, max_addr: Optional[int] = None,
                region_types: Optional[list[int]] = None) -> ScanResult:
    nlen = len(needle)
    if nlen == 0:
        return result
    # record the matched value per address so a later next_scan can run
    # changed/unchanged comparisons against it (JSON-safe representation)
    dt = vt.resolve_type(type_name)
    match_value = vt.decode_value(type_name, needle) if dt.kind == "string" else needle.hex()
    regions = [
        r for r in backend.readable_regions()
        if not (max_region_bytes and r.size > max_region_bytes)
    ]
    regions = filter_regions(regions, min_addr=min_addr, max_addr=max_addr, region_types=region_types)
    total = len(regions)
    for ri, region in enumerate(regions, 1):
        result.scanned_regions += 1
        offset = 0
        while offset < region.size:
            to_read = min(chunk_size, region.size - offset)
            try:
                data = backend.read(region.base + offset, to_read)
            except Exception:
                break
            if not data:
                break
            result.scanned_bytes += len(data)
            pos = data.find(needle)
            while pos != -1:
                addr = region.base + offset + pos
                result.addresses.append(addr)
                result.values[addr] = match_value
                if len(result.addresses) >= max_results:
                    result.truncated = True
                    result.count = len(result.addresses)
                    return result
                pos = data.find(needle, pos + 1)
            if to_read < chunk_size:
                break
            offset += to_read - (nlen - 1)
        _emit_progress(progress_cb, result, ri, total)
    result.count = len(result.addresses)
    return result


def next_scan(
    backend: MemoryBackend,
    type_name: str,
    addresses: list[int],
    *,
    comparator: str = "exact",
    value=None,
    value2=None,
    previous: Optional[dict[int, object]] = None,
    use_batch_read: bool = True,
    batch_gap: int = 64,
) -> ScanResult:
    """Refine an existing candidate set by re-reading each address.

    ``use_batch_read`` groups sorted candidates by memory region and reads each
    contiguous span with a single ``backend.read`` (falling back to
    ``read_many``-style individual reads on failure); unreadable addresses are
    skipped exactly like the sequential path. The result is identical to
    ``use_batch_read=False``.
    """

    if comparator not in NEXT_SCAN_COMPARATORS:
        raise InvalidArgsError(f"unknown comparator: {comparator!r}")
    dt = vt.resolve_type(type_name)
    size = dt.size
    if size is None:
        return _next_scan_varlen(backend, dt, addresses, comparator=comparator, value=value, previous=previous)

    target = _canon(type_name, value) if value is not None else None
    target2 = _canon(type_name, value2) if value2 is not None else None

    result = ScanResult(type=dt.name, comparator=comparator, count=0, truncated=False)
    if use_batch_read:
        reads = _next_scan_batch_reads(backend, addresses, size, batch_gap)
    else:
        reads = {}
        for addr in addresses:
            try:
                reads[addr] = backend.read(addr, size)
            except Exception:
                continue
    for addr in sorted(reads):
        data = reads[addr]
        if len(data) < size:
            continue
        try:
            cur = vt.decode_value(type_name, data)
        except Exception:
            continue
        prev = previous.get(addr) if previous else None
        if _compare(comparator, cur, target, target2, prev):
            result.addresses.append(addr)
            result.values[addr] = cur
    result.count = len(result.addresses)
    return result


def _next_scan_batch_reads(backend: MemoryBackend, addresses: list[int], size: int, batch_gap: int) -> dict[int, bytes]:
    """Read candidate addresses grouped into contiguous per-region spans.

    Addresses outside any known region are skipped (they would fail a plain
    read too); a span read failure falls back to per-address reads so partial
    successes are preserved.
    """

    if not addresses:
        return {}
    ordered = sorted(set(addresses))
    groups: list[tuple[int, int, list[int]]] = []
    for addr in ordered:
        try:
            region = backend.query(addr)
        except Exception:
            region = None
        if region is None:
            continue
        if groups:
            gkey, gend, gaddrs = groups[-1]
            if gkey == (region.base, region.end) and addr <= gend + batch_gap:
                gaddrs.append(addr)
                groups[-1] = (gkey, max(gend, addr + size), gaddrs)
                continue
        groups.append(((region.base, region.end), addr + size, [addr]))

    reads: dict[int, bytes] = {}
    for (_rbase, rend), gend, gaddrs in groups:
        start = gaddrs[0]
        span = min(gend, rend) - start
        try:
            buf = backend.read(start, span)
            for addr in gaddrs:
                off = addr - start
                if off + size <= len(buf):
                    reads[addr] = buf[off : off + size]
        except Exception:
            # span read failed: degrade to per-address reads (read_many
            # semantics - failures are skipped silently)
            for addr in gaddrs:
                try:
                    data = backend.read(addr, size)
                except Exception:
                    continue
                reads[addr] = data
    return reads


def _next_scan_varlen(backend, dt, addresses, *, comparator, value, previous) -> ScanResult:
    """Refine candidates for variable-length types (string / bytes).

    ``exact`` compares against a freshly encoded needle; ``changed`` /
    ``unchanged`` re-read each candidate and compare against the value recorded
    by the previous scan. A fixed-size window (old length + slack) is read so
    values that grew still fit; strings are compared null-terminated, raw bytes
    are compared over the previous value's length.
    """

    if comparator not in VARLEN_NEXT_SCAN_COMPARATORS:
        raise InvalidArgsError(
            f"variable-length type {dt.name} supports only {sorted(VARLEN_NEXT_SCAN_COMPARATORS)} in next_scan",
            details={"supported": sorted(VARLEN_NEXT_SCAN_COMPARATORS)},
        )

    result = ScanResult(type=dt.name, comparator=comparator, count=0, truncated=False)

    if comparator == "exact":
        if value is None:
            raise InvalidArgsError(f"next_scan exact on {dt.name} requires a value")
        needle = vt.encode_value(dt.name, value)
        match_value = vt.decode_value(dt.name, needle) if dt.kind == "string" else needle.hex()
        for addr in addresses:
            try:
                data = backend.read(addr, len(needle))
            except Exception:
                continue
            if data == needle:
                result.addresses.append(addr)
                result.values[addr] = match_value
        result.count = len(result.addresses)
        return result

    for addr in addresses:
        prev = previous.get(addr) if previous else None
        if prev is None:
            continue
        prev_bytes = vt.encode_value(dt.name, prev)
        window = max(len(prev_bytes) + 16, 64)
        try:
            data = backend.read(addr, window)
        except Exception:
            continue
        if dt.kind == "string":
            cur = vt.decode_value(dt.name, data)  # null-terminated decode
            if not _compare(comparator, cur, None, None, prev):
                continue
        else:
            if len(data) < len(prev_bytes):
                continue
            cur_bytes = bytes(data[: len(prev_bytes)])
            changed = cur_bytes != prev_bytes
            if comparator == "changed" and not changed:
                continue
            if comparator == "unchanged" and changed:
                continue
            cur = cur_bytes.hex()
        result.addresses.append(addr)
        result.values[addr] = cur
    result.count = len(result.addresses)
    return result

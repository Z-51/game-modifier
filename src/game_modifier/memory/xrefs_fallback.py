"""Pure-Python cross-reference fallback (no radare2 required).

The primary ``xrefs`` path analyzes the on-disk binary via radare2; when that
toolchain is missing (or fails) this module answers "who holds a pointer to
this address" by scanning every readable region for 4/8-byte slots whose value
equals the target address. Read-only: it never writes process memory.

Design mirrors :mod:`game_modifier.memory.scanner`:

- chunked region walks with a ``(size - 1)`` overlap so a slot straddling a
  chunk boundary is never missed;
- a numpy vectorised path (``arr == target``) when numpy is available,
  identical in spirit to the exact-scan branch; a ``bytes.find`` anchor +
  alignment filter otherwise;
- an optional thread pool (``workers`` > 1 + ``backend_factory``) that opens
  an independent backend handle per worker thread and aggregates partial
  results in region order, so the output is deterministic and identical to a
  single-threaded run;
- a 4/8-byte alignment filter by default (slots must sit at an address
  divisible by their width) to suppress false positives; ``aligned=False``
  disables it.

Every hit carries a ``region`` label derived from ``MemoryRegion.type``
(Windows MEM_* constants) so image sections (code/data tables) can be told
apart from heap-like private allocations.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from .base import MemoryBackend

try:
    import numpy as _np
except Exception:  # pragma: no cover - numpy is optional
    _np = None

# Windows MEM_* region type constants (semantic annotation for hits)
_MEM_IMAGE = 0x1000000
_MEM_PRIVATE = 0x20000
_MEM_MAPPED = 0x40000


def region_kind(region_type: int) -> str:
    """Semantic bucket for a ``MemoryRegion.type`` (Windows MEM_* value)."""

    if region_type == _MEM_IMAGE:
        return "image"
    if region_type == _MEM_PRIVATE:
        return "heap"
    if region_type == _MEM_MAPPED:
        return "mapped"
    return "other"


def slot_sizes(arch: str) -> list[int]:
    """Slot widths searched for the process architecture.

    x64 processes may carry both 8-byte pointers and 4-byte (RVA / 32-bit)
    references; x86 processes only 4-byte slots.
    """

    return [8, 4] if str(arch or "x64").lower() != "x86" else [4]


def _scan_region(backend: MemoryBackend, region, target: int, size: int, *,
                 aligned: bool, max_results: int, chunk_size: int,
                 hits: list[dict], stop_flag: Optional[threading.Event] = None) -> tuple[int, bool]:
    """Scan one region for ``size``-byte slots equal to ``target``.

    Returns ``(scanned_bytes, truncated)``. Appends hit dicts to ``hits``.
    """

    needle = target.to_bytes(size, "little") if target < (1 << (8 * size)) else None
    kind = region_kind(getattr(region, "type", 0) or 0)
    truncated = False
    scanned = 0
    offset = 0
    if needle is None:
        # the target cannot fit in a slot of this width: nothing to find
        return scanned, truncated
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
        scanned += len(data)
        chunk_addr = region.base + offset
        if _np is not None and aligned and target < (1 << (8 * size)):
            # vectorised path: one aligned flat view, arr == target
            lead = (-chunk_addr) % size
            if lead < len(data):
                view = data[lead:]
                n = len(view) // size
                if n > 0:
                    try:
                        dtype = _np.uint64 if size == 8 else _np.uint32
                        arr = _np.frombuffer(bytes(view[: n * size]), dtype=dtype)
                        idxs = _np.nonzero(arr == target)[0]
                        for i in idxs.tolist():
                            hits.append({
                                "address": hex(chunk_addr + lead + i * size),
                                "size": size,
                                "region": kind,
                            })
                            if len(hits) >= max_results:
                                return scanned, True
                    except Exception:  # pragma: no cover - defensive
                        pass
        else:
            # bytes.find anchor path (always used without numpy; also for the
            # unaligned variant where every byte offset is a candidate)
            pos = data.find(needle)
            while pos != -1:
                addr = chunk_addr + pos
                if not aligned or addr % size == 0:
                    hits.append({"address": hex(addr), "size": size, "region": kind})
                    if len(hits) >= max_results:
                        return scanned, True
                pos = data.find(needle, pos + 1)
        if to_read < chunk_size:
            break
        offset += to_read - (size - 1)
    return scanned, truncated


def find_xrefs(
    backend: MemoryBackend,
    target: int,
    *,
    arch: str = "x64",
    aligned: bool = True,
    max_results: int = 1000,
    chunk_size: int = 4 * 1024 * 1024,
    workers: int = 1,
    backend_factory: Optional[Callable[[], MemoryBackend]] = None,
    min_addr: Optional[int] = None,
    max_addr: Optional[int] = None,
) -> dict:
    """Find slots holding ``target`` across all readable regions (read-only).

    Returns ``{"xrefs": [{address, size, region}], "count", "truncated",
    "scanned_regions", "scanned_bytes", "slot_sizes", "aligned"}``.

    ``workers`` > 1 splits regions across a thread pool (each worker opens its
    own backend via ``backend_factory``); partial results are aggregated in
    region order, so the candidate list is deterministic and identical to the
    ``workers=1`` run. Without a factory the scan degrades to single-threaded.
    """

    target = int(target)
    if target < 0:
        raise ValueError(f"target address must be non-negative, got {target}")
    max_results = max(1, int(max_results))
    sizes = slot_sizes(arch)
    regions = [r for r in backend.readable_regions()]
    if min_addr is not None:
        regions = [r for r in regions if r.end > min_addr]
    if max_addr is not None:
        regions = [r for r in regions if r.base <= max_addr]

    use_pool = workers > 1 and backend_factory is not None
    stop_flag = threading.Event()

    def _walk(backend_: MemoryBackend, region) -> tuple[list[dict], int]:
        part: list[dict] = []
        scanned = 0
        for size in sizes:
            nb, trunc = _scan_region(backend_, region, target, size,
                                     aligned=aligned, max_results=max_results,
                                     chunk_size=chunk_size, hits=part,
                                     stop_flag=stop_flag)
            scanned += nb
            if trunc or stop_flag.is_set():
                break
        return part, scanned

    hits: list[dict] = []
    scanned_regions = 0
    scanned_bytes = 0

    if use_pool:
        # mirror _first_scan_parallel: independent handle per worker thread,
        # aggregate per-region partials in region order (deterministic output)
        parts: list[Optional[list[dict]]] = [None] * len(regions)

        def _worker(idx: int, region):
            b = backend_factory()
            try:
                part, scanned = _walk(b, region)
                return idx, part, scanned
            finally:
                try:
                    b.close()
                except Exception:
                    pass

        try:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(_worker, i, regions[i]) for i in range(len(regions))]
                for fut in futures:
                    idx, part, scanned = fut.result()
                    parts[idx] = part
                    scanned_regions += 1
                    scanned_bytes += scanned
                    if len(part) + len(hits) >= max_results:
                        stop_flag.set()
        except Exception:
            stop_flag.set()
            raise
        for part in parts:
            if not part:
                continue
            hits.extend(part)
            if len(hits) >= max_results:
                break
    else:
        for region in regions:
            scanned_regions += 1
            part, scanned = _walk(backend, region)
            scanned_bytes += scanned
            hits.extend(part)
            if len(hits) >= max_results:
                stop_flag.set()
                break

    truncated = len(hits) > max_results
    if truncated:
        hits = hits[:max_results]
    return {
        "xrefs": hits,
        "count": len(hits),
        "truncated": truncated,
        "scanned_regions": scanned_regions,
        "scanned_bytes": scanned_bytes,
        "slot_sizes": sizes,
        "aligned": bool(aligned),
    }

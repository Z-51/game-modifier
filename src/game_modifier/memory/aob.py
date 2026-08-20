"""AOB (Array of Bytes) pattern scanning with ?? wildcards.

Locates code/data signatures (e.g. ``48 8B ?? ?? 05``) across all readable
regions. The chunking keeps the same invariant as :mod:`scanner`: every read
overlaps the previous one by ``pattern_len - 1`` bytes, so a match straddling a
chunk boundary is never missed and never reported twice.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterator, Optional

from ..errors import InvalidArgsError, PatternNotFoundError
from .base import MemoryBackend
from .scanner import filter_regions

_WILDCARD_TOKENS = {"?", "??", "xx", "**"}
_HEX_DIGITS = set("0123456789abcdef")
_ADDRESS_SAMPLE = 20


def parse_pattern(text: str) -> tuple[bytes, bytes]:
    """Parse a ``'48 8B ?? ?? 05'`` style pattern.

    Returns ``(values, mask)`` where ``mask`` contains 1 for concrete bytes
    and 0 for wildcards. Space/comma separators are supported, wildcards are
    ``?`` / ``??`` (also ``xx`` / ``**``). An empty or all-wildcard pattern is
    rejected with :class:`InvalidArgsError`.
    """

    if not isinstance(text, str):
        raise InvalidArgsError(
            f"pattern must be a string, got {type(text).__name__}",
            details={"pattern": repr(text)},
        )
    tokens = text.replace(",", " ").split()
    if not tokens:
        raise InvalidArgsError(
            "empty AOB pattern",
            hint="Provide hex bytes separated by spaces, e.g. '48 8B ?? ?? 05'.",
        )

    values = bytearray()
    mask = bytearray()
    for tok in tokens:
        t = tok.strip().lower()
        if t in _WILDCARD_TOKENS:
            values.append(0)
            mask.append(0)
            continue
        if t.startswith("0x"):
            t = t[2:]
        if not t or len(t) % 2 != 0 or any(c not in _HEX_DIGITS for c in t):
            raise InvalidArgsError(
                f"invalid pattern token: {tok!r}",
                details={"pattern": text},
                hint="Use two-digit hex bytes separated by spaces/commas; '??' for wildcards.",
            )
        for i in range(0, len(t), 2):
            values.append(int(t[i : i + 2], 16))
            mask.append(1)

    if not any(mask):
        raise InvalidArgsError(
            "pattern is all wildcards; nothing to anchor the search",
            details={"pattern": text},
        )
    return bytes(values), bytes(mask)


def _match_at(data: bytes, start: int, values: bytes, solid_idx: list[int]) -> bool:
    for i in solid_idx:
        if data[start + i] != values[i]:
            return False
    return True


def _find_matches(data: bytes, values: bytes, mask: bytes) -> Iterator[int]:
    """Yield every offset in ``data`` where the masked pattern matches."""

    plen = len(values)
    if len(data) < plen:
        return
    solid_idx = [i for i, m in enumerate(mask) if m]
    if len(solid_idx) == plen:
        # fast path: no wildcards -> plain substring search
        pos = data.find(values)
        while pos != -1:
            yield pos
            pos = data.find(values, pos + 1)
        return

    # wildcard path: anchor on the first concrete byte, then mask-verify
    anchor = solid_idx[0]
    anchor_byte = bytes([values[anchor]])
    pos = data.find(anchor_byte, anchor)  # start at `anchor` so start >= 0
    while pos != -1:
        start = pos - anchor
        if start + plen <= len(data) and _match_at(data, start, values, solid_idx):
            yield start
        pos = data.find(anchor_byte, pos + 1)


def _aob_scan_serial(backend, regions, values: bytes, mask: bytes, overlap: int,
                     chunk_size: int, max_results: int, stop_on_limit: bool,
                     stop_flag: Optional[threading.Event] = None) -> dict:
    """Chunked AOB scan over ``regions`` (single thread).

    ``stop_on_limit=False`` (frozen default): collection stops the moment
    ``max_results`` is reached. ``stop_on_limit=True`` keeps scanning every
    region but only counts matches beyond the cap.
    """

    addresses: list[int] = []
    total_matches = 0
    scanned_regions = 0
    scanned_bytes = 0
    regions_completed = 0
    stopped_early = False

    for region in regions:
        scanned_regions += 1
        completed = True
        offset = 0
        while offset < region.size:
            if stop_flag is not None and stop_flag.is_set():
                completed = False
                break
            to_read = min(chunk_size, region.size - offset)
            try:
                data = backend.read(region.base + offset, to_read)
            except Exception:
                completed = False
                break
            if not data:
                completed = False
                break
            scanned_bytes += len(data)
            hit_cap = False
            for pos in _find_matches(data, values, mask):
                total_matches += 1
                if len(addresses) < max_results:
                    addresses.append(region.base + offset + pos)
                    if len(addresses) >= max_results and not stop_on_limit:
                        hit_cap = True
                        break
            if hit_cap:
                stopped_early = True
                return {
                    "addresses": addresses, "total_matches": total_matches,
                    "scanned_regions": scanned_regions, "scanned_bytes": scanned_bytes,
                    "regions_completed": regions_completed, "stopped_early": stopped_early,
                }
            if to_read < chunk_size:
                break
            # keep (plen-1) overlap so a match straddling the chunk boundary
            # is not missed
            offset += to_read - overlap
        if completed:
            regions_completed += 1

    return {
        "addresses": addresses, "total_matches": total_matches,
        "scanned_regions": scanned_regions, "scanned_bytes": scanned_bytes,
        "regions_completed": regions_completed, "stopped_early": stopped_early,
    }


def _aob_scan_parallel(regions, backend_factory, values: bytes, mask: bytes, overlap: int,
                       chunk_size: int, max_results: int, stop_on_limit: bool, workers: int) -> dict:
    """Thread-pool AOB scan; aggregates per-region partials in region order.

    Mirrors ``scanner._first_scan_parallel``: each worker opens its own
    backend, partial results are merged in the original region order, so the
    collected address list is deterministic and identical to a serial run.
    """

    stop_flag = threading.Event()
    parts: list[Optional[dict]] = [None] * len(regions)

    def _worker(idx: int, region) -> tuple:
        b = backend_factory()
        try:
            part = _aob_scan_serial(b, [region], values, mask, overlap, chunk_size,
                                    max_results, stop_on_limit, stop_flag)
        finally:
            try:
                b.close()
            except Exception:
                pass
        return idx, part

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_worker, i, regions[i]) for i in range(len(regions))]
            for fut in futures:
                idx, part = fut.result()
                parts[idx] = part
                if part["stopped_early"] and not stop_on_limit:
                    stop_flag.set()
    except Exception:
        stop_flag.set()
        raise

    addresses: list[int] = []
    total_matches = 0
    scanned_regions = 0
    scanned_bytes = 0
    regions_completed = 0
    stopped_early = False
    for part in parts:
        if part is None:
            continue
        addresses.extend(part["addresses"])
        total_matches += part["total_matches"]
        scanned_regions += part["scanned_regions"]
        scanned_bytes += part["scanned_bytes"]
        regions_completed += part["regions_completed"]
        stopped_early = stopped_early or part["stopped_early"]
    if len(addresses) > max_results:
        addresses = addresses[:max_results]
    return {
        "addresses": addresses, "total_matches": total_matches,
        "scanned_regions": scanned_regions, "scanned_bytes": scanned_bytes,
        "regions_completed": regions_completed, "stopped_early": stopped_early,
    }


def aob_scan(
    backend: MemoryBackend,
    pattern: str,
    *,
    max_results: int = 1000,
    chunk_size: int = 4_194_304,
    min_addr: Optional[int] = None,
    max_addr: Optional[int] = None,
    region_types: Optional[list[int]] = None,
    stop_on_limit: bool = False,
    workers: int = 1,
    backend_factory: Optional[Callable[[], MemoryBackend]] = None,
) -> dict:
    """Scan all readable regions for matches of ``pattern``.

    Reuses the scanner's chunked-read invariant: each chunk overlaps the
    previous one by ``len(pattern) - 1`` bytes so boundary-straddling matches
    are found exactly once. Matching uses ``bytes.find`` on the fully concrete
    fast path, and a first-solid-byte anchor + mask verification for patterns
    containing wildcards.

    ``min_addr`` / ``max_addr`` / ``region_types`` pre-filter the region list
    (defaults ``None`` = historical behaviour). ``stop_on_limit=False``
    (default, frozen behaviour) stops scanning as soon as ``max_results``
    matches are collected; ``stop_on_limit=True`` keeps scanning and only
    counts further matches. ``workers`` > 1 scans regions in parallel via
    ``backend_factory`` (region-order aggregation keeps results deterministic
    and identical to the serial run); without a factory it degrades to
    single-threaded. Truncated results carry a ``coverage`` block.

    Raises :class:`PatternNotFoundError` when nothing matches.
    """

    values, mask = parse_pattern(pattern)
    plen = len(values)
    overlap = plen - 1

    regions = filter_regions(
        list(backend.readable_regions()),
        min_addr=min_addr, max_addr=max_addr, region_types=region_types,
    )
    regions_total = len(regions)

    use_parallel = workers > 1
    if use_parallel and backend_factory is None:
        import warnings

        warnings.warn(
            "aob_scan: workers>1 requires backend_factory for per-thread backends; "
            "falling back to single-threaded scan",
            stacklevel=2,
        )
        use_parallel = False

    if use_parallel:
        scan = _aob_scan_parallel(regions, backend_factory, values, mask, overlap,
                                  chunk_size, max_results, stop_on_limit, workers)
    else:
        scan = _aob_scan_serial(backend, regions, values, mask, overlap,
                                chunk_size, max_results, stop_on_limit)

    addresses = scan["addresses"]
    scanned_regions = scan["scanned_regions"]
    scanned_bytes = scan["scanned_bytes"]

    if not addresses:
        raise PatternNotFoundError(
            f"no match for pattern {pattern!r}",
            details={"pattern": pattern, "scanned_regions": scanned_regions, "scanned_bytes": scanned_bytes},
            hint="Check the signature against the target module's bytes; wildcards '??' match any byte.",
        )

    truncated = scan["stopped_early"] or scan["total_matches"] > len(addresses)
    summary = {
        "pattern": pattern,
        "count": len(addresses),
        "addresses_hex": [hex(a) for a in addresses[:_ADDRESS_SAMPLE]],
        "addresses": addresses,
        "truncated": truncated,
        "scanned_regions": scanned_regions,
        "scanned_bytes": scanned_bytes,
    }
    if truncated:
        pct = round(100.0 * scan["regions_completed"] / regions_total, 1) if regions_total else 100.0
        summary["coverage"] = {
            "regions_scanned": scan["regions_completed"],
            "regions_total": regions_total,
            "pct": pct,
        }
    return summary

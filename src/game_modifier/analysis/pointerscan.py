"""Reverse pointer-path discovery (Cheat Engine style pointer scan).

Starting from a target address, readable memory is scanned level by level for
slots whose value points at the current frontier (within ``OFFSET_WINDOW``);
each such slot extends the paths one hop backwards. The search is bounded by
``max_depth``, ``max_paths`` and a wall-clock ``timeout`` (a
:class:`ScanTimeoutError` carrying the progress so far is raised on expiry).
Read-only throughout.
"""

from __future__ import annotations

import time

from ..errors import ScanTimeoutError
from ..memory.base import MemoryBackend
from .alignment import nearest_interval

# grouped span reads for batch path validation (same helper the UE actor
# walk uses); falls back to per-address reads when unavailable.
try:
    from ..engines.ue_introspect.actors import _read_span_groups
except Exception:  # pragma: no cover - defensive import guard
    _read_span_groups = None

_CHUNK = 1024 * 1024
# A pointer whose value lands this many bytes *before* a frontier address is
# treated as pointing at an object that contains the frontier address at a
# non-negative field offset (Cheat Engine pointer-scan semantics).
OFFSET_WINDOW = 0x2000


def find_pointer_paths(
    backend: MemoryBackend,
    target_addr: int,
    *,
    max_depth: int = 2,
    max_paths: int = 500,
    timeout: float = 30.0,
    progress_cb=None,
    cancel_cb=None,
) -> dict:
    """Reverse-BFS from ``target_addr`` up to ``max_depth`` hops.

    Returns ``{"paths": [{"base"(hex), "offsets": [int], "depth"}],
    "truncated": bool, "elapsed": float, "confidence", "reason"}``.
    Raises :class:`ScanTimeoutError` (with partial progress in ``details``)
    when the time budget is exceeded.

    Optional callbacks for background-job integration (no effect when
    omitted, so synchronous behavior is unchanged):

    - ``progress_cb(phase: str, info: dict)`` - called once per BFS depth
      level (plus a ``starting`` event) with the current path/frontier
      counts; exceptions inside the callback are swallowed.
    - ``cancel_cb() -> bool`` - polled between levels and chunks; when it
      returns True the search stops early and returns the partial result
      with ``cancelled=True`` instead of raising.
    """

    psize = backend.pointer_size
    target_addr = int(target_addr)
    max_depth = max(1, int(max_depth))
    deadline = time.monotonic() + float(timeout)
    started = time.monotonic()

    paths: list[dict] = []
    seen_paths: set[tuple] = set()
    truncated = False
    cancelled = False

    def _is_cancelled() -> bool:
        if cancel_cb is None:
            return False
        try:
            return bool(cancel_cb())
        except Exception:
            return False

    def _report(phase: str, info: dict) -> None:
        if progress_cb is None:
            return
        try:
            progress_cb(phase, dict(info))
        except Exception:
            pass

    _report("starting", {"target": hex(target_addr), "max_depth": max_depth, "max_paths": max_paths})

    # frontier: sorted (address) list; suffix_by_addr maps a frontier address
    # to every recorded offset-suffix reaching the original target from it.
    frontier = [target_addr]
    suffix_by_addr: dict[int, list[list[int]]] = {target_addr: [[]]}

    def _check_time(level: int) -> None:
        if time.monotonic() >= deadline:
            raise ScanTimeoutError(
                f"pointer scan exceeded {timeout}s at depth level {level}",
                details={
                    "timeout": timeout,
                    "depth_reached": level,
                    "paths_found": len(paths),
                    "truncated": truncated or len(paths) >= max_paths,
                },
                hint=(
                    "缩小扫描范围后重试: 降低 max_depth/max_paths 或调大 [analysis] scan_timeout；"
                    "或改用 pointer-scan --async 后台执行（无30s硬超时）并用 job status 轮询。"
                ),
            )

    for level in range(1, max_depth + 1):
        _check_time(level)
        if _is_cancelled():
            cancelled = True
            break
        _report(f"depth:{level}", {
            "level": level,
            "depth_reached": level,
            "paths_found": len(paths),
            "frontier_size": len(frontier),
        })
        # windowed intervals: a pointer value v counts as "points at frontier
        # address f" when f - OFFSET_WINDOW <= v <= f (the object base may sit
        # a few field-widths before the target field).
        win_starts = [s - OFFSET_WINDOW for s in frontier]
        win_ends = [s + 1 for s in frontier]
        matches: list[tuple[int, int, int]] = []  # (slot_addr, value, frontier_base)
        for region in backend.readable_regions():
            offset = 0
            while offset < region.size:
                to_read = min(_CHUNK, region.size - offset)
                try:
                    data = backend.read(region.base + offset, to_read)
                except Exception:
                    break
                if len(data) < psize:
                    break
                chunk_base = region.base + offset
                first_aligned = (-chunk_base) % psize
                limit = len(data) - psize
                i = first_aligned
                while i <= limit:
                    value = int.from_bytes(data[i : i + psize], "little")
                    if value:
                        base, _ = nearest_interval(win_starts, win_ends, value)
                        if base is not None:
                            frontier_addr = base + OFFSET_WINDOW
                            if 0 <= frontier_addr - value <= OFFSET_WINDOW:
                                matches.append((chunk_base + i, value, frontier_addr))
                    i += psize
                if len(matches) >= max_paths * 8:  # bound memory per level
                    break
                if to_read < _CHUNK:
                    break
                offset += to_read - (psize - 1)
                if _is_cancelled():
                    break
            if cancelled or _is_cancelled():
                cancelled = True
                break
            if len(matches) >= max_paths * 8:
                break
            _check_time(level)

        if cancelled:
            break

        next_suffixes: dict[int, list[list[int]]] = {}
        for slot_addr, value, base in matches:
            off = base - value
            for suffix in suffix_by_addr.get(base, [[]]):
                new_suffix = [off] + suffix
                key = (slot_addr, tuple(new_suffix))
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                paths.append({"base": slot_addr, "offsets": list(new_suffix), "depth": level})
                if len(paths) >= max_paths:
                    truncated = True
                    break
                next_suffixes.setdefault(slot_addr, []).append(list(new_suffix))
            if truncated:
                break
        if truncated:
            break

        next_frontier = sorted(next_suffixes)
        if not next_frontier or level == max_depth:
            break
        frontier = next_frontier
        suffix_by_addr = next_suffixes

    elapsed = round(time.monotonic() - started, 3)
    for p in paths:
        p["base"] = hex(p["base"])
    confidence = min(0.95, round(0.4 + 0.1 * min(len(paths), 5), 3)) if paths else 0.1
    reason = f"{len(paths)} pointer path(s) to {hex(target_addr)} within depth {max_depth}"
    if cancelled:
        reason = f"cancelled: {len(paths)} partial pointer path(s) to {hex(target_addr)} (depth reached {max(0, level - 1) if level else 0})"
        _report("cancelled", {"paths_found": len(paths)})
    else:
        _report("finished", {"paths_found": len(paths), "truncated": truncated})
    result = {
        "paths": paths,
        "truncated": truncated,
        "elapsed": elapsed,
        "confidence": confidence,
        "reason": reason,
    }
    if cancelled:
        result["cancelled"] = True
    return result


def rescan_paths(
    backend: MemoryBackend,
    paths: list[dict],
    target_addr: int,
    *,
    timeout: float = 30.0,
    window: int = OFFSET_WINDOW,
) -> dict:
    """Re-validate previously discovered pointer paths against ``target_addr``.

    Each path (``{"base"(hex/int), "offsets": [int], "depth"}``) is walked
    from its base: at every offset the current address is dereferenced and the
    offset added (pointer-chain semantics, matching :func:`find_pointer_paths`).
    A path survives when its final address lands within ``±window`` of
    ``target_addr``; stale paths are dropped.

    Returns ``{"paths": [...], "valid_count": int, "invalid_count": int,
    "truncated": bool, "elapsed": float}``. Survivors are sorted by
    (depth ascending, stability descending) and carry a ``"stability"``
    score. On timeout a *partial* result is returned with ``truncated=True``
    (rescan never raises :class:`ScanTimeoutError` - partial progress is the
    useful answer). Read-only throughout.
    """

    psize = backend.pointer_size
    target = int(target_addr)
    window = max(0, int(window))
    deadline = time.monotonic() + float(timeout)
    started = time.monotonic()

    # normalise input (base may arrive as hex string or int)
    pending: list[list] = []  # [original_path, base_int, offsets, step]
    for p in paths or []:
        base = p.get("base")
        try:
            base = int(str(base), 16) if isinstance(base, str) else int(base)
        except (TypeError, ValueError):
            continue
        offs = []
        try:
            offs = [int(o) for o in (p.get("offsets") or [])]
        except (TypeError, ValueError):
            continue
        pending.append([p, base, offs, 0])

    valid: list[dict] = []
    invalid_count = 0
    truncated = False

    def _read_ptrs(addrs: list[int]) -> dict:
        if _read_span_groups is not None:
            return _read_span_groups(backend, addrs, psize, gap=0x1000)
        out: dict[int, bytes] = {}
        for a in addrs:
            try:
                out[a] = backend.read(a, psize)
            except Exception:
                continue
        return out

    while pending:
        if time.monotonic() >= deadline:
            truncated = True
            break
        # paths that consumed all their offsets are finished: validate final addr
        still: list[list] = []
        for item in pending:
            path, addr, offs, step = item
            if step >= len(offs):
                if target - window <= addr <= target + window:
                    kept = dict(path)
                    kept["stability"] = round(float(kept.get("stability", 1.0)), 3)
                    valid.append(kept)
                else:
                    invalid_count += 1
            else:
                still.append(item)
        pending = still
        if not pending or time.monotonic() >= deadline:
            if pending:
                truncated = True
            break
        # batch-dereference every live path's current address in one pass
        reads = _read_ptrs(sorted({addr for _, addr, _, _ in pending}))
        nxt: list[list] = []
        for item in pending:
            path, addr, offs, step = item
            buf = reads.get(addr)
            if buf is None or len(buf) < psize:
                invalid_count += 1  # unreadable slot -> path is stale
                continue
            value = int.from_bytes(buf[:psize], "little")
            nxt.append([path, value + offs[step], offs, step + 1])
        pending = nxt

    valid.sort(key=lambda p: (int(p.get("depth", len(p.get("offsets") or []))), -float(p.get("stability", 1.0)), str(p.get("base"))))
    return {
        "paths": valid,
        "valid_count": len(valid),
        "invalid_count": invalid_count,
        "truncated": truncated,
        "elapsed": round(time.monotonic() - started, 3),
    }

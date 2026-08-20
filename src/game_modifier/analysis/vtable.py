"""vtable candidate discovery.

A vtable is laid out as a run of consecutive pointer-sized slots that all
point into executable code. This module walks writable regions looking for
such clusters and scores them; it never writes memory.
"""

from __future__ import annotations

from typing import Optional

from ..memory.base import MemoryBackend
from .alignment import build_intervals, in_intervals

_CHUNK = 1024 * 1024  # bytes read per region chunk


def find_vtables(
    backend: MemoryBackend,
    *,
    module_name: Optional[str] = None,
    max_candidates: int = 100,
    min_slots: int = 3,
) -> dict:
    """Scan writable regions for clusters of pointers into executable code.

    ``module_name`` restricts slot *targets* to that module's range (useful
    when hunting the vtables of one specific module).
    Returns ``{"candidates": [...], "truncated": bool}`` where each candidate
    carries ``address`` (hex), ``slots``, ``confidence`` (0.0-0.95) and a
    ``reason`` string.
    """

    psize = backend.pointer_size
    modules = backend.modules()
    regions = list(backend.regions())

    exec_ranges = [(r.base, r.end) for r in regions if r.executable]
    if module_name:
        module = backend.find_module(module_name)
        if module:
            exec_ranges = [
                (max(base, module.base), min(end, module.end))
                for base, end in exec_ranges
                if max(base, module.base) < min(end, module.end)
            ]
    exec_starts, exec_ends = build_intervals(exec_ranges)

    candidates: list[dict] = []
    truncated = False

    for region in regions:
        if not (region.readable and region.writable):
            continue
        if region.executable:
            continue  # code is scanned as a *target*, not a host

        offset = 0
        run_start = -1
        run_slots = 0
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
                slot_addr = chunk_base + i
                hit = value != 0 and in_intervals(exec_starts, exec_ends, value)
                if hit:
                    if run_slots == 0:
                        run_start = slot_addr
                    run_slots += 1
                else:
                    if run_slots >= min_slots:
                        candidates.append(_candidate(backend, run_start, run_slots, psize, exec_starts, exec_ends))
                        if len(candidates) >= max_candidates:
                            truncated = True
                            return {"candidates": candidates, "truncated": True}
                    run_slots = 0
                i += psize
            # keep (psize-1) overlap so a slot straddling the chunk boundary is
            # not missed; the alignment recompute above prevents double counts
            if to_read < _CHUNK:
                break
            offset += to_read - (psize - 1)
        # flush a run that reaches the region end
        if run_slots >= min_slots and run_start >= 0:
            candidates.append(_candidate(backend, run_start, run_slots, psize, exec_starts, exec_ends))
            if len(candidates) >= max_candidates:
                truncated = True
                break

    candidates.sort(key=lambda c: c["confidence"], reverse=True)
    return {"candidates": candidates, "truncated": truncated}


def _candidate(backend: MemoryBackend, address: int, slots: int, psize: int, exec_starts, exec_ends) -> dict:
    """Score one run: more slots and denser same-module targets raise confidence."""

    values = []
    try:
        data = backend.read(address, slots * psize)
        for i in range(slots):
            if (i + 1) * psize <= len(data):
                values.append(int.from_bytes(data[i * psize : (i + 1) * psize], "little"))
    except Exception:
        pass

    module_hits: dict[str, int] = {}
    for v in values:
        for mod in backend.modules():
            if mod.base <= v < mod.end:
                module_hits[mod.name] = module_hits.get(mod.name, 0) + 1
                break

    confidence = min(0.95, 0.30 + 0.05 * min(slots, 10))
    reason = f"{slots} consecutive pointer slots target executable memory"
    if module_hits:
        best_name, best_n = max(module_hits.items(), key=lambda kv: kv[1])
        density = best_n / max(1, len(values))
        confidence = min(0.95, confidence + 0.25 * density)
        reason += f"; {best_n}/{len(values)} slots point into {best_name}"
    return {
        "address": hex(address),
        "slots": slots,
        "confidence": round(confidence, 3),
        "reason": reason,
    }

"""Class layout inference from a known vtable address.

Given a vtable address, instances are located by scanning writable memory for
slots whose first pointer-sized word equals the vtable address. Field offsets
are then inferred from co-occurrence across instances: offsets whose values
are consistent (stable) across instances are reported with a guessed type.
Read-only throughout.
"""

from __future__ import annotations

import math
import struct
from collections import Counter

from ..engines.ue_introspect.actors import _read_span_groups
from ..memory.base import MemoryBackend
from .alignment import build_intervals, in_intervals

_CHUNK = 1024 * 1024
_INSPECT_BYTES = 256  # bytes read per instance for field inference
_MAX_FIELDS = 24


def infer_class_layout(backend: MemoryBackend, vtable_addr: int, *, max_instances: int = 50) -> dict:
    """Reverse-locate instances of ``vtable_addr`` and profile field offsets.

    Returns ``{"instances_found", "fields": [{"offset", "guessed_type",
    "stability"}], "confidence", "reason"}``.
    """

    psize = backend.pointer_size
    vtable_addr = int(vtable_addr)
    instances = _find_instances(backend, vtable_addr, psize, max_instances)

    bodies = backend.read_many(instances, _INSPECT_BYTES)

    regions = list(backend.regions())
    starts, ends = build_intervals((r.base, r.end) for r in regions)

    # collect per-offset value histograms across instances
    values_at: dict[int, Counter] = {}
    usable = 0
    for addr in instances:
        data = bodies.get(addr)
        if not data or len(data) < psize * 2:
            continue
        usable += 1
        limit = min(len(data) - psize, _INSPECT_BYTES - psize)
        for off in range(psize, limit + 1, psize):
            value = int.from_bytes(data[off : off + psize], "little")
            values_at.setdefault(off, Counter())[value] += 1

    fields: list[dict] = []
    stability_sum = 0.0
    for off in sorted(values_at):
        counter = values_at[off]
        mode_value, mode_count = counter.most_common(1)[0]
        stability = mode_count / max(1, usable)
        guessed = _guess_type(mode_value, psize, starts, ends)
        # skip slots that are zero everywhere (no layout signal)
        if mode_value == 0 and stability >= 1.0:
            continue
        fields.append({"offset": off, "guessed_type": guessed, "stability": round(stability, 3)})
        stability_sum += stability
        if len(fields) >= _MAX_FIELDS:
            break

    if usable > 0 and fields:
        confidence = min(0.95, round(0.3 + 0.05 * usable + 0.3 * (stability_sum / len(fields)), 3))
    elif usable > 0:
        confidence = 0.3
    else:
        confidence = 0.0
    return {
        "instances_found": len(instances),
        "fields": fields,
        "confidence": confidence,
        "reason": f"{len(instances)} instance(s) share vtable {hex(vtable_addr)}; "
        f"{len(fields)} stable field offset(s) profiled",
    }


def _find_instances(backend: MemoryBackend, vtable_addr: int, psize: int, max_instances: int) -> list[int]:
    instances: list[int] = []
    needle = vtable_addr.to_bytes(psize, "little")
    for region in backend.regions():
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
            chunk_base = region.base + offset
            pos = data.find(needle)
            while pos != -1:
                addr = chunk_base + pos
                if (addr % psize) == 0:
                    instances.append(addr)
                    if len(instances) >= max_instances:
                        return instances
                pos = data.find(needle, pos + psize)
            if to_read < _CHUNK:
                break
            offset += to_read - (psize - 1)
    return instances


def _guess_type(value: int, psize: int, starts, ends) -> str:
    if value != 0 and (value & (psize - 1)) == 0 and in_intervals(starts, ends, value):
        return "ptr"
    if psize == 8:
        return "int64" if (1 << 62) <= value < (1 << 63) else "uint64"
    return "int32" if (1 << 30) <= value < (1 << 31) else "uint32"


# ------------------------------------------------------------------ dissect
# Cheat Engine-style structure dissection: given one or more instances of the
# same class, read each instance's leading bytes and classify every
# pointer-aligned slot (vtable / ptr / int / float / bool / unknown). The
# cross-instance agreement drives the per-field confidence: a single instance
# can never exceed _SINGLE_CAP, multiple instances up to _MULTI_CAP.

_DISSECT_MAX_BYTES = 4096   # hard cap on bytes analyzed per instance
_SINGLE_CAP = 0.6           # confidence ceiling with one instance
_MULTI_CAP = 0.9            # confidence ceiling with multiple instances
_MAJORITY = 0.5             # agreement fraction needed to claim a type
_FLOAT_LO = 1e-6            # plausible float32 magnitude window
_FLOAT_HI = 1e6
_MAX_SAMPLES = 8            # sample values kept per field


def dissect_structure(backend: MemoryBackend, instance_addrs, *,
                      size: int = 256, pointer_size: int = None,
                      max_instances: int = 20) -> dict:
    """Dissect the field layout of one or more same-class object instances.

    Reads ``size`` bytes at every address in ``instance_addrs`` (nearby
    addresses are merged into grouped span reads), splits each body into
    pointer-aligned slots and classifies every slot across instances:

    * ``vtable``: first slot, value points into an executable region;
    * ``ptr``: value falls inside a known region (aligned, non-zero);
    * ``int``: values stay within a plausible integer range;
    * ``float``: low 32 bits decode to a finite float32 in 1e-6..1e6;
    * ``bool``: every value is 0 or 1 (at least one 1);
    * ``unknown``: no consistent signal (all-zero slots included).

    Returns ``{"fields": [{"offset", "guessed_type", "confidence",
    "sample_values", "reason"}], "instances_used", "instances_skipped",
    "size_analyzed", "reason"}``. Unreadable instances are skipped, never
    fatal. Read-only throughout.
    """

    psize = int(pointer_size or backend.pointer_size)
    size = max(psize * 2, min(int(size), _DISSECT_MAX_BYTES))
    addrs = [int(a) for a in instance_addrs][: max(1, int(max_instances))]

    bodies = _read_span_groups(backend, addrs, size, gap=size)
    usable = [a for a in addrs if len(bodies.get(a) or b"") >= psize]
    skipped = len(addrs) - len(usable)

    regions = list(backend.regions())
    all_starts, all_ends = build_intervals((r.base, r.end) for r in regions)
    exec_starts, exec_ends = build_intervals(
        (r.base, r.end) for r in regions if getattr(r, "executable", False))

    fields: list[dict] = []
    if usable:
        cap = _SINGLE_CAP if len(usable) == 1 else _MULTI_CAP
        for off in range(0, size - psize + 1, psize):
            values = []
            for a in usable:
                data = bodies[a]
                if off + psize <= len(data):
                    values.append(int.from_bytes(data[off : off + psize], "little"))
            if not values:
                continue
            guessed, agreement, reason, samples = _classify_slot(
                off, values, psize, (all_starts, all_ends), (exec_starts, exec_ends))
            confidence = 0.1 if guessed == "unknown" else round(min(cap, agreement * cap + 0.05), 3)
            fields.append({
                "offset": off,
                "guessed_type": guessed,
                "confidence": confidence,
                "sample_values": samples,
                "reason": reason,
            })

    return {
        "fields": fields,
        "instances_used": len(usable),
        "instances_skipped": skipped,
        "size_analyzed": size,
        "reason": f"{len(usable)} instance(s) dissected over {size} bytes"
        + (f"; {skipped} unreadable instance(s) skipped" if skipped else ""),
    }


def _classify_slot(off: int, values: list[int], psize: int,
                   all_iv, exec_iv) -> tuple:
    """Classify one slot's cross-instance values; returns (type, agreement, reason, samples)."""

    n = len(values)
    all_starts, all_ends = all_iv
    exec_starts, exec_ends = exec_iv

    def _is_ptr(v: int, starts, ends) -> bool:
        return v != 0 and (psize <= 1 or (v & (psize - 1)) == 0) and in_intervals(starts, ends, v)

    # bool: strictly 0/1 (all-zero reads as padding, not a field)
    if all(v in (0, 1) for v in values):
        if any(values):
            ones = sum(values)
            return "bool", 1.0, f"{ones}/{n} instance(s) hold 1, rest 0", list(values[:_MAX_SAMPLES])
        return "unknown", 0.0, "all-zero across instances (padding?)", [0]

    # vtable: first slot pointing into executable memory
    if off == 0:
        hits = sum(1 for v in values if _is_ptr(v, exec_starts, exec_ends))
        if hits / n >= _MAJORITY:
            return ("vtable", hits / n, f"{hits}/{n} value(s) point into executable regions",
                    [hex(v) for v in values[:_MAX_SAMPLES]])

    # ptr: value inside any known region
    hits = sum(1 for v in values if _is_ptr(v, all_starts, all_ends))
    if hits / n >= _MAJORITY:
        return ("ptr", hits / n, f"{hits}/{n} value(s) fall inside readable regions",
                [hex(v) for v in values[:_MAX_SAMPLES]])

    # float: low 32 bits decode to a finite float32 of plausible magnitude
    decoded = [struct.unpack("<f", (v & 0xFFFFFFFF).to_bytes(4, "little"))[0] for v in values]
    fhits = sum(1 for f in decoded if math.isfinite(f) and _FLOAT_LO <= abs(f) <= _FLOAT_HI)
    if fhits / n >= _MAJORITY:
        return ("float", fhits / n, f"{fhits}/{n} value(s) decode to plausible float32 (1e-6..1e6)",
                [round(f, 6) for f in decoded[:_MAX_SAMPLES]])

    # int: values stay within a plausible integer range
    int_hi = 1 << 32 if psize >= 8 else 1 << 31
    ihits = sum(1 for v in values if v < int_hi)
    if ihits / n >= _MAJORITY:
        distinct = len(set(values))
        reason = f"{ihits}/{n} value(s) within plausible integer range"
        if distinct > 1:
            reason += f"; {distinct} distinct value(s) vary across instances"
        return "int", ihits / n, reason, list(values[:_MAX_SAMPLES])

    return ("unknown", 0.0, "no consistent ptr/int/float/bool signal",
            [hex(v) for v in values[:_MAX_SAMPLES]])

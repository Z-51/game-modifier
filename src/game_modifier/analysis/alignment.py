"""Alignment inference and pointer-shape heuristics (pure functions).

Everything here is read-only and backend-agnostic: the callers pass in
region/module snapshots so the functions stay trivially testable.
"""

from __future__ import annotations

import bisect
from typing import Iterable, Sequence

# Largest alignment we ever claim (x86/x64 pointer slots are at most 8-byte
# aligned in practice; larger powers of two carry no extra signal).
MAX_ALIGNMENT = 8


def infer_alignment(addresses: list[int]) -> int:
    """Return the largest power-of-two alignment shared by ``addresses``.

    The greatest common divisor of the address set is computed, then reduced
    to its largest power-of-two divisor (capped at :data:`MAX_ALIGNMENT`).
    An empty or all-zero set yields ``1`` (no signal).
    """

    g = 0
    for a in addresses:
        a = int(a)
        if a == 0:
            continue
        g = _gcd(g, a) if g else a
    if g <= 0:
        return 1
    alignment = 1
    while alignment * 2 <= g and alignment * 2 <= MAX_ALIGNMENT:
        alignment *= 2
    return alignment


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def looks_like_pointer(value: int, regions, modules, pointer_size: int) -> bool:
    """Heuristic: does ``value`` plausibly hold a pointer?

    A value qualifies when it is non-zero, aligned to ``pointer_size`` (the
    natural slot alignment on x86/x64), and falls inside at least one known
    region. ``modules`` is accepted as extra evidence but regions alone are
    sufficient; both are sequences of objects with ``base`` and ``end`` (or
    ``size``).
    """

    value = int(value)
    if value == 0:
        return False
    if pointer_size > 1 and (value & (pointer_size - 1)) != 0:
        return False
    for span in _spans(regions):
        if span[0] <= value < span[1]:
            return True
    for span in _spans(modules):
        if span[0] <= value < span[1]:
            return True
    return False


def _spans(items) -> Iterable[tuple[int, int]]:
    for item in items or ():
        base = getattr(item, "base", None)
        if base is None:
            continue
        end = getattr(item, "end", None)
        if end is None:
            end = base + int(getattr(item, "size", 0))
        yield (int(base), int(end))


# ---------------------------------------------------------------- intervals
def build_intervals(ranges) -> tuple[list[int], list[int]]:
    """Build sorted start/end lists for membership queries (via bisect)."""

    starts: list[int] = []
    ends: list[int] = []
    for base, end in sorted((int(b), int(e)) for b, e in ranges if e > b):
        if starts and base <= ends[-1]:
            ends[-1] = max(ends[-1], end)  # merge overlap
        else:
            starts.append(base)
            ends.append(end)
    return starts, ends


def in_intervals(starts: Sequence[int], ends: Sequence[int], value: int) -> bool:
    i = bisect.bisect_right(starts, value) - 1
    return i >= 0 and value < ends[i]


def nearest_interval(starts: Sequence[int], ends: Sequence[int], value: int):
    """Return (interval_start, delta) for the interval containing ``value``."""

    i = bisect.bisect_right(starts, value) - 1
    if i >= 0 and value < ends[i]:
        return starts[i], value - starts[i]
    return None, 0

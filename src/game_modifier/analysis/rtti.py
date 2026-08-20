"""MSVC RTTI TypeDescriptor discovery.

MSVC stores the decorated class name inside the RTTI TypeDescriptor as an
ASCII string starting with ``. ? A V`` (class) or ``. ? A U`` (struct). This
module scans readable regions for those signatures and returns the raw names;
no full CompleteObjectLocator / class-hierarchy parsing is attempted.
Read-only throughout.
"""

from __future__ import annotations

from ..memory.base import MemoryBackend

_CHUNK = 1024 * 1024
_MAX_NAME = 256
_SIGNATURES = (b".?AV", b".?AU")

_IDENT_CHARS = set(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:@$<>?"
)


def find_rtti_classes(backend: MemoryBackend, *, max_results: int = 200) -> dict:
    """Scan readable regions for ``.?AV`` / ``.?AU`` RTTI name signatures.

    Returns ``{"classes": [{"name", "address"(hex), "confidence", "reason"}],
    "truncated": bool}``.
    """

    classes: list[dict] = []
    truncated = False
    seen: set[str] = set()
    overlap = _MAX_NAME + 4  # keep names straddling chunk boundaries

    for region in backend.readable_regions():
        offset = 0
        while offset < region.size:
            to_read = min(_CHUNK, region.size - offset)
            try:
                data = backend.read(region.base + offset, to_read)
            except Exception:
                break
            if len(data) < 4:
                break
            pos = _find_any(data, 0)
            while pos != -1:
                end = data.find(b"\x00", pos + 4, pos + 4 + _MAX_NAME)
                if end == -1:
                    end = min(pos + 4 + _MAX_NAME, len(data))
                raw = data[pos + 4 : end]
                name = _clean_name(raw)
                if name:
                    kind = "class" if data[pos + 3 : pos + 4] == b"V" else "struct"
                    if name not in seen:
                        seen.add(name)
                        classes.append(
                            {
                                "name": name,
                                "address": hex(region.base + offset + pos),
                                "confidence": _confidence(name),
                                "reason": f"RTTI TypeDescriptor signature .?A{kind[0]}{name!r}",
                            }
                        )
                        if len(classes) >= max_results:
                            return {"classes": classes, "truncated": True}
                pos = _find_any(data, pos + 1)
            if to_read < _CHUNK:
                break
            offset += to_read - overlap
    return {"classes": classes, "truncated": truncated}


def _find_any(data: bytes, start: int) -> int:
    best = -1
    for sig in _SIGNATURES:
        pos = data.find(sig, start)
        if pos != -1 and (best == -1 or pos < best):
            best = pos
    return best


def _clean_name(raw: bytes) -> str:
    """Strip the MSVC decoration (@@...) and validate identifier chars."""

    if not raw:
        return ""
    cut = raw.find(b"@@")
    if cut != -1:
        raw = raw[:cut]
    if not raw or any(b not in _IDENT_CHARS for b in raw):
        return ""
    return raw.decode("ascii", errors="replace")


def _confidence(name: str) -> float:
    """Longer plausible identifiers are more likely genuine class names."""

    if len(name) >= 12:
        return 0.9
    if len(name) >= 6:
        return 0.8
    return 0.7

"""Binary Ninja adapter (headless, optional).

Only usable when a licensed Binary Ninja with the ``binaryninja`` Python API is
installed. Provides a minimal static overview; absence is reported cleanly.
"""

from __future__ import annotations

from pathlib import Path

from ..errors import ToolNotFoundError, GameModifierError, ErrorCode


def available() -> bool:
    import importlib.util

    return importlib.util.find_spec("binaryninja") is not None


def analyze(path: str) -> dict:
    if not available():
        raise ToolNotFoundError(
            "Binary Ninja headless API not available",
            hint="Install Binary Ninja and its 'binaryninja' Python module (requires a commercial/headless license).",
        )
    if not Path(path).exists():
        raise GameModifierError(f"binary not found: {path}", code=ErrorCode.INVALID_ARGS)

    import binaryninja  # type: ignore

    bv = binaryninja.load(path)  # type: ignore[attr-defined]
    try:
        functions = list(bv.functions)
        sections = list(getattr(bv, "sections", {}).keys())
        return {
            "backend": "binaryninja",
            "arch": str(bv.arch) if bv.arch else None,
            "platform": str(bv.platform) if bv.platform else None,
            "entry_point": hex(bv.entry_point),
            "function_count": len(functions),
            "sections": sections[:60],
        }
    finally:
        try:
            bv.file.close()
        except Exception:
            pass

"""Reverse-engineering toolchain: detection registry and per-tool adapters."""

from __future__ import annotations

from .registry import (
    detect_all,
    detect_tool,
    find_tool,
    metadata_version,
    recommended_unity_dumper,
)
from . import radare2
from . import x64dbg
from . import windbg
from . import binaryninja

__all__ = [
    "detect_all",
    "detect_tool",
    "find_tool",
    "metadata_version",
    "recommended_unity_dumper",
    "radare2",
    "x64dbg",
    "windbg",
    "binaryninja",
]

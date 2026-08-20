"""Engine detection and per-engine reverse-engineering adapters."""

from __future__ import annotations

from .detect import (
    UNITY_IL2CPP,
    UNITY_MONO,
    UNREAL,
    UNKNOWN,
    NWJS,
    RPG_MAKER,
    RENPY,
    WEBVIEW,
    detect,
    detect_from_modules,
)
from . import nwjs
from . import unity
from . import unreal
from . import ue_introspect
from . import unity_introspect
from . import mono_layout

__all__ = [
    "detect",
    "detect_from_modules",
    "UNITY_IL2CPP",
    "UNITY_MONO",
    "UNREAL",
    "UNKNOWN",
    "NWJS",
    "RPG_MAKER",
    "RENPY",
    "WEBVIEW",
    "nwjs",
    "unity",
    "unreal",
    "ue_introspect",
    "unity_introspect",
]

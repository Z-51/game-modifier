"""Memory layout analysis subsystem (phase 3).

Read-only heuristics that turn raw process memory into structure: vtable
candidates, MSVC RTTI class names, per-class field layouts, heap object
enumeration and reverse pointer-path discovery. Every result carries a
``confidence`` (0.0-0.95) plus a ``reason`` so agents can branch without
parsing prose.
"""

from __future__ import annotations

from .alignment import (
    build_intervals,
    in_intervals,
    infer_alignment,
    looks_like_pointer,
    nearest_interval,
)
from .classlayout import dissect_structure, infer_class_layout
from .disasm import basic_blocks, disassemble
from .heap import scan_heap_objects
from .pointerscan import OFFSET_WINDOW, find_pointer_paths, rescan_paths
from .report import to_text
from .rtti import find_rtti_classes
from .vtable import find_vtables

__all__ = [
    "infer_alignment",
    "looks_like_pointer",
    "build_intervals",
    "in_intervals",
    "nearest_interval",
    "find_vtables",
    "find_rtti_classes",
    "infer_class_layout",
    "dissect_structure",
    "scan_heap_objects",
    "find_pointer_paths",
    "rescan_paths",
    "OFFSET_WINDOW",
    "disassemble",
    "basic_blocks",
    "to_text",
]

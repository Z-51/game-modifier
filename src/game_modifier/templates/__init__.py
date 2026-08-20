"""Template subsystem: load/validate/expand genre modification templates."""

from __future__ import annotations

from .loader import (
    expand_option,
    get_option,
    list_templates,
    load_template,
    validate_template,
)

__all__ = [
    "list_templates",
    "load_template",
    "validate_template",
    "get_option",
    "expand_option",
]

"""Human-readable rendering of layout-analysis results.

``to_text`` turns any result dict (vtables / RTTI / class layout / heap /
pointer scan) into an indented text tree for ``--format human``.
"""

from __future__ import annotations

from typing import Any

_INDENT = "  "


def to_text(result: dict) -> str:
    """Render ``result`` as an indented text tree."""

    lines: list[str] = []
    _render(result, lines, depth=0)
    return "\n".join(lines)


def _render(node: Any, lines: list[str], depth: int) -> None:
    pad = _INDENT * depth
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (dict, list)) and value:
                lines.append(f"{pad}{key}:")
                _render(value, lines, depth + 1)
            else:
                lines.append(f"{pad}{key}: {_scalar(value)}")
    elif isinstance(node, list):
        for index, item in enumerate(node):
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}-")
                _render(item, lines, depth + 1)
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    else:
        lines.append(f"{pad}{_scalar(node)}")


def _scalar(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)

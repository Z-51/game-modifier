"""Ren'Py save file handler (detection only for now).

Ren'Py saves are zip archives containing pickled Python objects; editing them
safely requires a pickle-aware rewriter, so this handler reports the files as
not editable yet instead of risking corruption.
"""

from __future__ import annotations

from pathlib import Path

_NOT_EDITABLE_REASON = "Ren'Py pickle format not yet supported"


class RenPyHandler:
    """Detect Ren'Py save files; loading/editing is not supported yet."""

    def detect(self, game_dir: str) -> list[dict]:
        root = Path(game_dir)
        if root.is_file():
            root = root.parent
        if not root.is_dir():
            return []
        found: list[dict] = []
        seen: set[str] = set()
        hits = sorted(root.glob("game/saves/*.save")) + sorted(root.glob("saves/*.save"))
        for hit in hits:
            key = str(hit.resolve())
            if key in seen or not hit.is_file():
                continue
            seen.add(key)
            found.append({
                "path": str(hit),
                "format": "renpy-save",
                "size": hit.stat().st_size,
                "editable": False,
                "reason": _NOT_EDITABLE_REASON,
            })
        return found

    def load(self, path: str) -> dict:
        return {"path": str(path), "editable": False, "reason": _NOT_EDITABLE_REASON}

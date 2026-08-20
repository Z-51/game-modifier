"""RPG Maker MV/MZ save file handler.

RPG Maker MZ writes ``*.rmmzsave`` next to the executable (or under ``save/``)
and MV keeps ``www/save/file*.json``. The payload is JSON, sometimes wrapped in
base64. Newer pako-deflated saves are detected but reported as unsupported so
the agent gets a clear error instead of garbage.
"""

from __future__ import annotations

import base64
import binascii
import json
import shutil
from pathlib import Path
from typing import Any, Optional

from ..errors import SaveFormatUnsupportedError

_NOT_FOUND = object()


def _find_and_set(node: Any, field: str, value: Any):
    """Depth-first search for the first dict key == field; set it, return old value."""

    if isinstance(node, dict):
        if field in node:
            old = node[field]
            node[field] = value
            return old
        for child in node.values():
            old = _find_and_set(child, field, value)
            if old is not _NOT_FOUND:
                return old
    elif isinstance(node, list):
        for child in node:
            old = _find_and_set(child, field, value)
            if old is not _NOT_FOUND:
                return old
    return _NOT_FOUND


class RMMZHandler:
    """Detect / load / modify RPG Maker MV/MZ JSON-based save files."""

    # ------------------------------------------------------------- detect
    def detect(self, game_dir: str) -> list[dict]:
        root = Path(game_dir)
        if root.is_file():
            root = root.parent
        if not root.is_dir():
            return []
        found: list[dict] = []
        seen: set[str] = set()
        hits = sorted(root.rglob("*.rmmzsave")) + sorted(root.glob("www/save/*.json"))
        for hit in hits:
            key = str(hit.resolve())
            if key in seen or not hit.is_file():
                continue
            seen.add(key)
            found.append({
                "path": str(hit),
                "format": "rmmzsave" if hit.suffix == ".rmmzsave" else "json",
                "size": hit.stat().st_size,
                "editable": True,
            })
        return found

    # --------------------------------------------------------------- load
    def load(self, path: str) -> dict:
        p = Path(path)
        raw = p.read_text(encoding="utf-8", errors="replace").strip()
        data, encoding = self._parse(raw)
        if data is None:
            raise SaveFormatUnsupportedError(
                f"cannot parse save file as JSON or base64 JSON: {p.name}",
                details={"path": str(p)},
                hint="Compressed (pako/zlib) RPG Maker saves are not supported yet.",
            )
        return {"path": str(p), "data": data, "encoding": encoding, "editable": True}

    @staticmethod
    def _parse(raw: str) -> tuple[Optional[Any], str]:
        try:
            return json.loads(raw), "plain"
        except ValueError:
            pass
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8")
            return json.loads(decoded), "base64"
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None, ""

    # ------------------------------------------------------------- modify
    def modify(self, data: Any, field: str, value: Any) -> dict:
        old: Any = _NOT_FOUND
        if "." in field:
            # dotted path, e.g. "party._gold"
            node = data
            parts = field.split(".")
            for part in parts[:-1]:
                node = node.get(part) if isinstance(node, dict) else None
                if node is None:
                    break
            if isinstance(node, dict) and parts[-1] in node:
                old = node[parts[-1]]
                node[parts[-1]] = value
        else:
            old = _find_and_set(data, field, value)
        found = old is not _NOT_FOUND
        return {
            "found": found,
            "field": field,
            "old_value": old if found else None,
            "new_value": value,
        }

    # --------------------------------------------------------------- save
    def save(self, path: str, data: Any, *, backup: bool = True, encoding: str = "plain") -> dict:
        p = Path(path)
        backup_path: Optional[Path] = None
        if backup and p.exists():
            backup_path = p.with_suffix(p.suffix + ".bak")
            shutil.copy2(p, backup_path)
        text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        if encoding == "base64":
            text = base64.b64encode(text.encode("utf-8")).decode("ascii")
        p.write_text(text, encoding="utf-8")
        return {"path": str(p), "backup": str(backup_path) if backup_path else None}

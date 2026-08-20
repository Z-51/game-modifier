"""Save file editing for archive-based games (RPG Maker, Ren'Py, etc.).

Some engines (RPG Maker MV/MZ, Ren'Py) keep player state in save files rather
than stable memory locations, so ``attach`` flags them with ``save_edit`` and
the agent is routed here. All modifications are dry-run by default and the
original file is backed up (``.bak``) before any write.
"""

from __future__ import annotations

from pathlib import Path

from ..errors import InvalidArgsError, SaveFormatUnsupportedError
from .renpy import RenPyHandler
from .rmmz import RMMZHandler
from .unity import UnityHandler

_HANDLERS = {"rpg-maker": RMMZHandler, "renpy": RenPyHandler, "unity-encrypted": UnityHandler}

# extension -> handler class (for path-based dispatch in load/modify)
_EXT_HANDLERS = {
    ".rmmzsave": RMMZHandler,
    ".rpgsave": RMMZHandler,
    ".json": RMMZHandler,
    ".save": RenPyHandler,
    ".sav": UnityHandler,
    ".dat": UnityHandler,
}


def detect_saves(game_dir: str, engine: str) -> list[dict]:
    """Find editable save files in the game directory.

    Unity custom-encrypted candidates (``*.sav`` / ``*.dat`` carrying pure
    base64 payloads) are surfaced for every engine in addition to the
    engine-specific handler's own results.
    """

    handler_cls = _HANDLERS.get(engine)
    results: list[dict] = list(handler_cls().detect(game_dir)) if handler_cls else []
    if engine != "unity-encrypted":
        seen = {entry["path"] for entry in results}
        for entry in UnityHandler().detect(game_dir):
            if entry["path"] not in seen:
                results.append(entry)
    return results


def _handler_for(path: str):
    suffix = Path(path).suffix.lower()
    handler_cls = _EXT_HANDLERS.get(suffix)
    if not handler_cls:
        raise SaveFormatUnsupportedError(
            f"unsupported save format: {suffix or path!r}",
            details={"path": str(path), "known": sorted(_EXT_HANDLERS)},
        )
    return handler_cls()


def load_save(path: str, *, key=None, iv=None) -> dict:
    """Load and deserialize a save file.

    ``key``/``iv`` are only consumed by the Unity encrypted handler
    (Base64(DES-CBC(JSON))); all other handlers ignore them.
    """

    handler = _handler_for(path)
    if getattr(handler, "requires_key", False):
        return handler.load(path, key=key, iv=iv)
    return handler.load(path)


def _coerce(value):
    """CLI values arrive as strings; map them to int/float/bool when possible."""

    if not isinstance(value, str):
        return value
    low = value.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def modify_save(path: str, field: str, value, *, confirm: bool = False,
                key=None, iv=None) -> dict:
    """Modify a field in a save file. Dry-run by default.

    ``key``/``iv`` are required for Unity encrypted saves (``*.sav`` / ``*.dat``
    with a base64 payload) and are passed through in memory only - they are
    never persisted.
    """

    handler = _handler_for(path)
    load_kwargs: dict = {}
    if getattr(handler, "requires_key", False):
        if key is None:
            raise InvalidArgsError(
                "该存档为 Unity 加密格式，需提供 --key",
                details={"path": str(path)},
                hint="密钥来自游戏代码逆向；CLI: --key <密钥> [--iv <IV>]，MCP: key/iv 参数。",
            )
        load_kwargs = {"key": key, "iv": iv}
    loaded = handler.load(path, **load_kwargs)
    if not loaded.get("editable", False):
        raise SaveFormatUnsupportedError(
            loaded.get("reason") or "save file is not editable",
            details={"path": str(path)},
        )

    new_value = _coerce(value)
    res = handler.modify(loaded["data"], field, new_value)
    out = {
        "path": str(path),
        "field": field,
        "found": res["found"],
        "old_value": res["old_value"],
        "new_value": new_value,
    }

    if not res["found"]:
        out.update({"applied": False, "dry_run": not confirm})
        out["hint"] = f"field {field!r} not found in the save data; check the key name (dotted paths supported)."
        return {"ok": False, **out}

    if not confirm:
        out.update({"applied": False, "dry_run": True})
        out["hint"] = "Re-run with confirm=true (CLI: --confirm) to apply."
        return {"ok": True, **out}

    if getattr(handler, "requires_key", False):
        written = handler.save(path, loaded["data"], backup=True, key=key, iv=iv)
    else:
        written = handler.save(path, loaded["data"], backup=True, encoding=loaded.get("encoding", "plain"))
    out.update({"applied": True, "dry_run": False, "backup": written.get("backup")})
    return {"ok": True, **out}

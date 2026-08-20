"""Batch file loading and execution.

A batch file (YAML) lists operations to run in one shot - each a small mapping
selecting exactly one action (``nl`` / ``modify`` / ``template`` / ``scan`` /
``read`` / ``resolve`` / ``name``). Running many edits from a single invocation
is a key token-saving path: one tool call performs many modifications.

The runner is execution-agnostic: the service supplies an ``execute`` callback
that knows how to perform each step against the attached process.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import yaml

from ..errors import BatchError, GameModifierError

STEP_KEYS = {"nl", "modify", "template", "scan", "scan_next", "read", "resolve", "name", "backup"}

# A batch document is a small YAML file; anything beyond this is a mistake
# (or an attack), never a real batch.
_MAX_BATCH_BYTES = 1024 * 1024


def load_batch(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise BatchError(f"batch file not found: {path}", details={"path": path})
    if not p.is_file():
        raise BatchError(
            f"batch path is not a file: {path}",
            details={"path": path},
            hint="file= 需要指向一个 YAML 文件（不是目录）。",
        )
    size = p.stat().st_size
    if size > _MAX_BATCH_BYTES:
        raise BatchError(
            f"batch file too large: {size} bytes (limit {_MAX_BATCH_BYTES})",
            details={"path": path, "size": size, "limit": _MAX_BATCH_BYTES},
            hint="拆成多个批处理文件，或用 yaml= 内联小型操作集。",
        )
    try:
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise BatchError(
            f"batch file is not valid YAML: {exc}",
            details={"path": path},
        )
    except OSError as exc:
        raise BatchError(
            f"batch file unreadable: {exc}",
            details={"path": path},
        )
    return validate_batch(data)


def load_batch_text(text: str) -> dict:
    """Parse an inline YAML batch document (the ``batch_run(yaml=...)`` path).

    Shares the exact same validation rules as :func:`load_batch`; a YAML
    syntax error surfaces as a structured :class:`BatchError`.
    """

    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise BatchError(
            f"inline batch YAML is not valid: {exc}",
            details={"yaml_chars": len(str(text or ""))},
        )
    return validate_batch(data)


def validate_batch(data: dict) -> dict:
    if not isinstance(data, dict):
        raise BatchError("batch file must be a mapping with an 'operations' list")
    ops = data.get("operations")
    if not isinstance(ops, list) or not ops:
        raise BatchError("batch file must contain a non-empty 'operations' list")
    for i, step in enumerate(ops):
        if not isinstance(step, dict):
            raise BatchError(f"operation #{i} is not a mapping", details={"index": i})
        keys = STEP_KEYS & set(step.keys())
        if len(keys) != 1:
            raise BatchError(
                f"operation #{i} must select exactly one action of {sorted(STEP_KEYS)}",
                details={"index": i, "found_keys": sorted(step.keys())},
            )
    return data


def step_action(step: dict) -> str:
    return next(iter(STEP_KEYS & set(step.keys())))


def run(
    operations: list[dict],
    execute: Callable[[int, dict], dict],
    *,
    stop_on_error: bool = True,
) -> dict:
    """Execute each step via ``execute(index, step) -> result dict``.

    ``result`` should contain at least ``{"ok": bool}``. Aggregates a summary.
    """

    results: list[dict] = []
    ok_count = 0
    error_count = 0
    for i, step in enumerate(operations):
        action = step_action(step)
        try:
            res = execute(i, step)
        except GameModifierError as exc:
            res = {"ok": False, "action": action, "error": exc.to_dict()}
        except Exception as exc:  # pragma: no cover - defensive
            res = {"ok": False, "action": action, "error": {"code": "E_INTERNAL", "message": str(exc)}}
        res.setdefault("index", i)
        res.setdefault("action", action)
        results.append(res)
        if res.get("ok"):
            ok_count += 1
        else:
            error_count += 1
            if stop_on_error:
                break
    return {
        "total": len(operations),
        "executed": len(results),
        "ok_count": ok_count,
        "error_count": error_count,
        "stopped_early": stop_on_error and error_count > 0 and len(results) < len(operations),
        "results": results,
    }

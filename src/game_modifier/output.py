"""Structured output envelopes.

Every command returns a single JSON object with a stable shape so agents can
branch on fields instead of parsing prose:

    {
      "ok": true,
      "command": "modify",
      "data": { ... },              # present when ok
      "warnings": ["..."],          # optional
      "error": {"code": "E_...", "message": "...", "details": {...}}  # when !ok
    }

A compact human renderer is provided for interactive terminal use, but JSON is
the default because it is the token-efficient contract for agents.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

from .errors import ErrorCode, GameModifierError


@dataclass
class Result:
    """Container for a command result."""

    command: str
    ok: bool = True
    data: Any = None
    warnings: list[str] = field(default_factory=list)
    error: Optional[dict[str, Any]] = None

    # ------------------------------------------------------------------ build
    @classmethod
    def success(cls, command: str, data: Any = None, warnings: Optional[list[str]] = None) -> "Result":
        return cls(command=command, ok=True, data=data, warnings=warnings or [])

    @classmethod
    def failure(
        cls,
        command: str,
        code: ErrorCode | str,
        message: str,
        *,
        details: Optional[dict[str, Any]] = None,
        hint: Optional[str] = None,
        warnings: Optional[list[str]] = None,
    ) -> "Result":
        err: dict[str, Any] = {
            "code": code.value if isinstance(code, ErrorCode) else str(code),
            "message": message,
        }
        if hint:
            err["hint"] = hint
        if details:
            err["details"] = details
        return cls(command=command, ok=False, error=err, warnings=warnings or [])

    @classmethod
    def from_exception(cls, command: str, exc: GameModifierError) -> "Result":
        return cls(command=command, ok=False, error=exc.to_dict())

    # ------------------------------------------------------------------ warn
    def warn(self, message: str) -> "Result":
        self.warnings.append(message)
        return self

    # ------------------------------------------------------------------ dump
    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"ok": self.ok, "command": self.command}
        if self.ok:
            payload["data"] = self.data if self.data is not None else {}
        else:
            payload["error"] = self.error or {"code": ErrorCode.INTERNAL.value, "message": "unknown"}
        if self.warnings:
            payload["warnings"] = self.warnings
        return payload

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1


def _default(obj: Any) -> Any:
    # Best-effort JSON serialization for uncommon types.
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (set, tuple)):
        return list(obj)
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


def emit(result: Result, *, fmt: str = "json", stream=None) -> int:
    """Print ``result`` in the requested format and return the exit code."""

    stream = stream or sys.stdout
    if fmt == "json":
        stream.write(json.dumps(result.to_dict(), ensure_ascii=False, default=_default))
        stream.write("\n")
    elif fmt == "json-pretty":
        stream.write(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, default=_default))
        stream.write("\n")
    else:  # human
        _render_human(result, stream)
    stream.flush()
    return result.exit_code


def _render_human(result: Result, stream) -> None:
    status = "OK" if result.ok else "ERROR"
    stream.write(f"[{status}] {result.command}\n")
    if result.ok:
        if result.data is not None:
            stream.write(json.dumps(result.data, ensure_ascii=False, indent=2, default=_default))
            stream.write("\n")
    else:
        err = result.error or {}
        stream.write(f"  code: {err.get('code')}\n")
        stream.write(f"  message: {err.get('message')}\n")
        if err.get("hint"):
            stream.write(f"  hint: {err['hint']}\n")
        if err.get("details"):
            stream.write("  details: ")
            stream.write(json.dumps(err["details"], ensure_ascii=False, default=_default))
            stream.write("\n")
    for w in result.warnings:
        stream.write(f"  warning: {w}\n")

"""Intent data model produced by the NLP processor."""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Any, Optional

# Sentinels for symbolic values.
MAX = "__MAX__"
MIN = "__MIN__"

ACTIONS = {"set", "add", "sub", "freeze", "get", "unlock", "max", "min"}


@dataclass
class Intent:
    action: str  # one of ACTIONS
    field: Optional[str] = None  # semantic field, e.g. "gold", "health"
    value: Any = None  # number, MAX/MIN sentinel, or None
    value_type: Optional[str] = None  # inferred data type hint, e.g. "int32"
    raw: str = ""
    confidence: float = 0.0
    matched: dict = dc_field(default_factory=dict)  # debug: which keywords matched

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "field": self.field,
            "value": self.value,
            "value_type": self.value_type,
            "confidence": round(self.confidence, 3),
            "raw": self.raw,
            "matched": self.matched,
        }

    @property
    def is_write(self) -> bool:
        return self.action in {"set", "add", "sub", "freeze", "max", "min", "unlock"}

    @property
    def needs_value(self) -> bool:
        return self.action in {"set", "add", "sub"}

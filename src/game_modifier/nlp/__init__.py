"""Natural-language subsystem (deterministic Chinese/English intent parsing)."""

from __future__ import annotations

from .intents import MAX, MIN, ACTIONS, Intent
from .processor import parse
from . import lexicon

__all__ = ["Intent", "parse", "lexicon", "MAX", "MIN", "ACTIONS"]

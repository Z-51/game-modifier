"""Deterministic natural-language processor (Chinese + English).

Turns a short phrase into a structured :class:`Intent`. No LLM is involved:
matching is dictionary + regex, so results are reproducible and instant. The
service layer maps ``Intent.field`` onto the session symbol table to find the
concrete address; when it cannot, it returns a structured ``E_NEEDS_SCAN`` so
the agent knows exactly what to scan next.
"""

from __future__ import annotations

from typing import Optional

from ..errors import NlpUnresolvedError
from . import lexicon as lex
from .intents import MAX, MIN, Intent


def _find_terms(text_norm: str, text_lower: str, terms: list[str]) -> Optional[str]:
    """Return the longest matching term (most specific), or None."""

    best: Optional[str] = None
    for term in terms:
        hay = text_lower if term.isascii() else text_norm
        needle = term.lower() if term.isascii() else term
        if needle in hay:
            if best is None or len(term) > len(best):
                best = term
    return best


def detect_field(text_norm: str, text_lower: str):
    best_field = None
    best_type = None
    best_term = ""
    for field, (dtype, terms) in lex.FIELDS.items():
        term = _find_terms(text_norm, text_lower, terms)
        if term and len(term) > len(best_term):
            best_field, best_type, best_term = field, dtype, term
    return best_field, best_type, best_term


def detect_unlock_target(text_norm: str, text_lower: str) -> Optional[str]:
    for target, terms in lex.UNLOCK_TARGET_TERMS.items():
        if _find_terms(text_norm, text_lower, terms):
            return target
    return None


def parse(text: str) -> Intent:
    raw = text or ""
    norm = lex.normalize(raw)
    lower = norm.lower()
    matched: dict = {}

    field, field_type, field_term = detect_field(norm, lower)
    if field:
        matched["field_term"] = field_term

    num, kind = lex.extract_number(norm)
    if num is not None:
        matched["number"] = num

    # detect action cues
    set_t = _find_terms(norm, lower, lex.SET_TERMS)
    add_t = _find_terms(norm, lower, lex.ADD_TERMS)
    sub_t = _find_terms(norm, lower, lex.SUB_TERMS)
    freeze_t = _find_terms(norm, lower, lex.FREEZE_TERMS)
    get_t = _find_terms(norm, lower, lex.GET_TERMS)
    unlock_t = _find_terms(norm, lower, lex.UNLOCK_TERMS)
    max_t = _find_terms(norm, lower, lex.MAX_TERMS)
    min_t = _find_terms(norm, lower, lex.MIN_TERMS)

    unlock_target = detect_unlock_target(norm, lower)

    action = None
    value = num
    confidence = 0.0

    # unlock has priority when an unlock target is named
    if unlock_target and (unlock_t or get_t or "所有" in norm or "全部" in norm or "全" in norm):
        action = "unlock"
        value = unlock_target
        field = field or f"unlock_{unlock_target}"
        matched["unlock_target"] = unlock_target
        matched["action_term"] = unlock_t or "unlock"
        confidence = 0.8
    elif freeze_t:
        action = "freeze"
        matched["action_term"] = freeze_t
        if num is not None:
            value = num
        elif max_t or freeze_t in ("无限", "无敌", "unlimited", "infinite", "god mode", "godmode"):
            value = MAX
        else:
            value = None  # freeze current value
        confidence = 0.75 if field else 0.4
    elif add_t and num is not None:
        action, value, confidence = "add", num, 0.85
        matched["action_term"] = add_t
    elif sub_t and num is not None:
        action, value, confidence = "sub", num, 0.85
        matched["action_term"] = sub_t
    elif set_t and num is not None:
        action, value, confidence = "set", num, 0.9
        matched["action_term"] = set_t
    elif max_t:
        action, value, confidence = "set", MAX, 0.7
        matched["action_term"] = max_t
    elif min_t:
        action, value, confidence = "set", MIN, 0.7
        matched["action_term"] = min_t
    elif num is not None and field:
        # "金币9999" - implicit set
        action, value, confidence = "set", num, 0.6
    elif get_t and field:
        action, value, confidence = "get", None, 0.7
        matched["action_term"] = get_t
    elif field:
        action, value, confidence = "get", None, 0.4

    if action is None:
        raise NlpUnresolvedError(
            f"could not derive an action from: {raw!r}",
            details={
                "raw": raw,
                "detected_field": field,
                "detected_number": num,
                "hint_supported_fields": sorted(lex.FIELDS.keys()),
            },
            hint="Try phrasing like '将金币设为9999' / 'set health to 100' / '无限弹药'.",
        )

    # value type inference
    if kind == "float":
        value_type = "float"
    else:
        value_type = field_type or "int32"

    return Intent(
        action=action,
        field=field,
        value=value,
        value_type=value_type,
        raw=raw,
        confidence=confidence,
        matched=matched,
    )

"""Template loading, validation and expansion.

Templates standardize *what* to change for a genre (RPG/action/strategy) - for
example "infinite health = freeze player.health at max". The concrete address
is game-specific and comes from the session symbol table (populated by scanning
or an engine dump). So a template references symbolic names; the service
resolves them and reports any that are not yet mapped.

Built-in templates ship inside the package; user templates live in
``<home>/templates`` (configurable). Both are YAML.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from ..errors import TemplateNotFoundError, GameModifierError, ErrorCode

_BUILTIN_DIR = Path(__file__).with_name("builtin")
_PARAM_RE = re.compile(r"^\$\{(\w+)\}$")

VALID_STRATEGIES = {"set", "freeze"}


@dataclass
class TemplateOption:
    key: str
    label: str
    description: str
    params: list[str]
    targets: list[dict]


def _template_dirs(user_dir: Optional[Path]) -> list[Path]:
    dirs = [_BUILTIN_DIR]
    if user_dir:
        dirs.append(Path(user_dir))
    return dirs


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise GameModifierError(f"template {path.name} is not a mapping", code=ErrorCode.TEMPLATE_INVALID)
    return data


def list_templates(user_dir: Optional[Path] = None) -> list[dict]:
    seen: dict[str, dict] = {}
    for d in _template_dirs(user_dir):
        if not d or not d.exists():
            continue
        for path in sorted(d.glob("*.yaml")):
            try:
                data = _load_yaml(path)
            except Exception:
                continue
            name = data.get("name", path.stem)
            seen[name] = {
                "name": name,
                "description": data.get("description", ""),
                "game_types": data.get("game_types", []),
                "options": sorted((data.get("options") or {}).keys()),
                "source": "builtin" if d == _BUILTIN_DIR else "user",
                "path": str(path),
            }
    return list(seen.values())


def load_template(name: str, user_dir: Optional[Path] = None) -> dict:
    for d in _template_dirs(user_dir):
        if not d or not d.exists():
            continue
        # match by file stem or by internal name
        for path in d.glob("*.yaml"):
            if path.stem == name:
                return validate_template(_load_yaml(path), name)
        for path in d.glob("*.yaml"):
            data = _load_yaml(path)
            if data.get("name") == name:
                return validate_template(data, name)
    raise TemplateNotFoundError(
        f"template not found: {name!r}",
        details={"known": [t["name"] for t in list_templates(user_dir)]},
    )


def validate_template(data: dict, name: str) -> dict:
    options = data.get("options")
    if not isinstance(options, dict) or not options:
        raise GameModifierError(
            f"template {name!r} has no options", code=ErrorCode.TEMPLATE_INVALID
        )
    for opt_key, opt in options.items():
        if not isinstance(opt, dict):
            raise GameModifierError(f"option {opt_key!r} is not a mapping", code=ErrorCode.TEMPLATE_INVALID)
        targets = opt.get("targets")
        if not isinstance(targets, list) or not targets:
            raise GameModifierError(
                f"option {opt_key!r} has no targets", code=ErrorCode.TEMPLATE_INVALID
            )
        for t in targets:
            if "symbol" not in t and "address" not in t:
                raise GameModifierError(
                    f"target in {opt_key!r} needs 'symbol' or 'address'",
                    code=ErrorCode.TEMPLATE_INVALID,
                )
            strat = t.get("strategy", "set")
            if strat not in VALID_STRATEGIES:
                raise GameModifierError(
                    f"invalid strategy {strat!r} in {opt_key!r}",
                    code=ErrorCode.TEMPLATE_INVALID,
                    details={"valid": sorted(VALID_STRATEGIES)},
                )
    return data


def get_option(template: dict, option_key: str) -> TemplateOption:
    options = template.get("options", {})
    opt = options.get(option_key)
    if opt is None:
        raise TemplateNotFoundError(
            f"option not found: {option_key!r}",
            details={"template": template.get("name"), "options": sorted(options.keys())},
        )
    return TemplateOption(
        key=option_key,
        label=opt.get("label", option_key),
        description=opt.get("description", ""),
        params=list(opt.get("params", [])),
        targets=list(opt.get("targets", [])),
    )


def _sub_value(value, params: dict):
    if isinstance(value, str):
        m = _PARAM_RE.match(value.strip())
        if m:
            key = m.group(1)
            if key not in params:
                raise GameModifierError(
                    f"missing template parameter: {key!r}",
                    code=ErrorCode.INVALID_ARGS,
                    details={"required_param": key},
                )
            return params[key]
    return value


def expand_option(template: dict, option_key: str, params: Optional[dict] = None) -> list[dict]:
    """Return concrete targets with parameters substituted.

    Each target: ``{symbol|address, type, value, strategy}`` where ``value`` is a
    number or the tokens ``"max"``/``"min"`` (the service maps those to the
    type's range).
    """

    params = params or {}
    option = get_option(template, option_key)
    out: list[dict] = []
    for t in option.targets:
        target = {
            "type": t.get("type", "int32"),
            "strategy": t.get("strategy", "set"),
            "value": _sub_value(t.get("value", "max"), params),
        }
        if "symbol" in t:
            target["symbol"] = t["symbol"]
        if "address" in t:
            target["address"] = t["address"]
        if t.get("offsets"):
            target["offsets"] = t["offsets"]
        target["note"] = f"{template.get('name')}::{option_key} -> {t.get('symbol', t.get('address'))}"
        out.append(target)
    return out

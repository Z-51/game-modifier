"""NW.js / RPG Maker / Ren'Py engine detection.

These web-runtime style engines are easy to confuse with Unreal because they
also ship ``*.pak`` files (Chromium resource packs).  This module runs a
multi-feature weighted scan so that the presence of e.g. ``nw.dll`` or
``rmmz_core.js`` overrides the weak "found some .pak" Unreal signal.
RPG Maker and Ren'Py results additionally flag ``save_edit`` because their
save files are plain JSON/pickle and can be edited without memory access.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .detect import NWJS, RENPY, RPG_MAKER

# module names that identify a live NW.js process
_NWJS_MODULES = {"nw.dll", "nw_elf.dll", "nw.exe"}


def detect_from_modules(modules) -> Optional[dict]:
    """Return an NW.js result when the loaded module list contains nw.dll etc."""

    for m in modules or []:
        if hasattr(m, "name"):
            name = str(m.name).lower()
        elif isinstance(m, dict):
            name = str(m.get("name", "")).lower()
        elif isinstance(m, str):
            name = m.lower()
        else:
            continue
        if name in _NWJS_MODULES:
            return {"engine": NWJS, "confidence": 0.9, "evidence": [f"module:{name}"]}
    return None


def _first_existing(game_dir: Path, *relpaths: str) -> Optional[Path]:
    for rel in relpaths:
        p = game_dir / rel
        if p.exists():
            return p
    return None


def _first_glob(game_dir: Path, pattern: str) -> Optional[Path]:
    for hit in game_dir.rglob(pattern):
        return hit
    return None


def _confidence_from(score: int) -> float:
    if score >= 70:
        return 0.95
    if score >= 50:
        return 0.88
    return 0.7


def scan_filesystem(game_dir: Path) -> Optional[dict]:
    """Weighted multi-feature scan for NW.js / RPG Maker / Ren'Py layouts."""

    # candidate -> (score, evidence, artifacts)
    candidates: dict[str, tuple[int, list[str], dict[str, str]]] = {}

    # ------------------------------------------------------------- NW.js
    score = 0
    evidence: list[str] = []
    artifacts: dict[str, str] = {}
    for rel, weight in (("nw.dll", 40), ("index.html", 30), ("package.json", 20), ("resources.pak", 10)):
        p = game_dir / rel
        if p.exists():
            score += weight
            evidence.append(f"file:{rel}")
            artifacts[rel.replace(".", "_")] = str(p)
    if score:
        candidates[NWJS] = (score, evidence, artifacts)

    # --------------------------------------------------------- RPG Maker
    score = 0
    evidence = []
    artifacts = {}
    core = _first_existing(
        game_dir,
        "rmmz_core.js", "rmmv_core.js",
        "js/rmmz_core.js", "js/rmmv_core.js",
        "www/js/rmmz_core.js", "www/js/rmmv_core.js",
    )
    if core:
        score += 50
        evidence.append(f"file:{core.name}")
        artifacts["core_js"] = str(core)
    plugins = _first_existing(game_dir, "js/plugins.js", "www/js/plugins.js")
    if plugins:
        score += 20
        evidence.append("file:plugins.js")
        artifacts["plugins_js"] = str(plugins)
    save = _first_glob(game_dir, "*.rmmzsave")
    if save:
        # a .rmmzsave file is uniquely RPG Maker MZ, so it qualifies on its own
        score += 40
        evidence.append("file:*.rmmzsave")
        artifacts["save_file"] = str(save)
    if score:
        candidates[RPG_MAKER] = (score, evidence, artifacts)

    # ------------------------------------------------------------ Ren'Py
    score = 0
    evidence = []
    artifacts = {}
    if (game_dir / "renpy").is_dir():
        score += 50
        evidence.append("dir:renpy")
        artifacts["renpy_dir"] = str(game_dir / "renpy")
    if (game_dir / "game").is_dir():
        score += 30
        evidence.append("dir:game")
        artifacts["game_dir"] = str(game_dir / "game")
    rpy = _first_glob(game_dir, "*.rpy")
    if rpy:
        score += 20
        evidence.append("file:*.rpy")
        artifacts["rpy_file"] = str(rpy)
    if score:
        candidates[RENPY] = (score, evidence, artifacts)

    if not candidates:
        return None

    engine, (best_score, evidence, artifacts) = max(candidates.items(), key=lambda kv: kv[1][0])
    if best_score < 40:
        return None

    return {
        "engine": engine,
        "confidence": _confidence_from(best_score),
        "evidence": evidence,
        "artifacts": artifacts,
        "save_edit": engine in (RPG_MAKER, RENPY),
    }

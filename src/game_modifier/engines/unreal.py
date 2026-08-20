"""Unreal Engine adapter.

Handles UE4/UE5 titles: locate artifacts (shipping exe, .pak, UE4SS), guess the
engine version, and parse the offset tables that UE dumpers (UE4 Dumper,
Dumper-7, UE4SS) emit for ``GObjects`` / ``GNames`` / ``GWorld`` and friends.

Parsing is pure and unit-tested; running a dumper or UE4SS requires the
external tool.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Optional

from ..errors import ToolNotFoundError, GameModifierError, ErrorCode
# import the submodule members directly: the package rebinds the name ``detect``
# to the function, so ``from . import detect`` would not yield this module.
from .detect import UNREAL, _scan_unreal

# "GObjects = 0x1234" / "GObjects: 0x1234" / "constexpr auto GObjects = 0x1234;"
_KV_RE = re.compile(
    r"(?P<name>GObjects|GNames|GWorld|GEngine|ProcessEvent|GUObjectArray|AppendString|FNameToString|GMalloc)"
    r"\s*[:=]\s*(?P<val>0x[0-9A-Fa-f]+|\d+)",
    re.IGNORECASE,
)

_VERSION_RE = re.compile(r"(?:UE|UnrealEngine|EngineVersion)[ _-]?(?P<ver>[45]\.\d+(?:\.\d+)?)", re.IGNORECASE)


def locate_artifacts(game_dir: str) -> dict:
    result = _scan_unreal(Path(game_dir))
    return (result or {}).get("artifacts", {})


def parse_offsets(text: str) -> dict:
    """Parse a dumper offsets file into ``{name: address}`` (ints)."""

    offsets: dict[str, int] = {}
    for m in _KV_RE.finditer(text):
        name = m.group("name")
        val = m.group("val")
        try:
            offsets[name] = int(val, 16) if val.lower().startswith("0x") else int(val)
        except ValueError:
            continue
    return {
        "count": len(offsets),
        "offsets": offsets,
        "offsets_hex": {k: hex(v) for k, v in offsets.items()},
    }


def guess_version(*, exe_name: str = "", text: str = "") -> Optional[str]:
    for source in (exe_name, text):
        if not source:
            continue
        m = _VERSION_RE.search(source)
        if m:
            return m.group("ver")
    return None


def project_name_from_shipping(exe_path: str) -> Optional[str]:
    """``MyGame-Win64-Shipping.exe`` -> ``MyGame``."""

    name = Path(exe_path).name
    low = name.lower()
    marker = "-win64-shipping.exe"
    if low.endswith(marker):
        return name[: -len(marker)]
    return None


def analyze(game_dir: str, *, modules=None) -> dict:
    """High-level convenience: artifacts + version guess + project name."""

    artifacts = locate_artifacts(game_dir)
    shipping = artifacts.get("shipping_exe", "")
    project = project_name_from_shipping(shipping) if shipping else None
    version = guess_version(exe_name=Path(shipping).name if shipping else "")
    return {
        "engine": UNREAL,
        "artifacts": artifacts,
        "project": project,
        "version_guess": version,
        "notes": [
            "Use a UE dumper (UE4 Dumper / Dumper-7) to obtain GObjects/GNames offsets,",
            "then resolve object addresses via GameName.exe + offset with `resolve`.",
        ],
    }


def run_dumper(dumper_path: str, target: str, out_dir: str, *, args=None, timeout: int = 600) -> dict:
    """Invocation scaffold for a UE dumper (UE4 Dumper / Dumper-7 / UE4SS).

    Runs the configured dumper against ``target`` (a pid, exe, or game dir),
    then parses any offsets file it produced in ``out_dir``. Best-effort: the
    exact CLI differs per dumper, so extra ``args`` can be supplied.
    """

    if not dumper_path or not Path(dumper_path).exists():
        raise ToolNotFoundError(
            "UE dumper not found",
            details={"dumper_path": dumper_path},
            hint="Install a UE dumper (UE4 Dumper / Dumper-7) and set tools.ue4dumper, or pass --tool-path.",
        )
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cmd = [dumper_path, str(target), *(args or []), str(out)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"could not execute UE dumper: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise GameModifierError(f"UE dumper timed out after {timeout}s", code=ErrorCode.TOOL_FAILED) from exc

    # try to locate and parse a produced offsets file
    offsets: dict = {"count": 0, "offsets": {}, "offsets_hex": {}}
    for name in ("Offsets.hpp", "offsets.txt", "OFFSETS.txt", "SDK.hpp"):
        candidate = out / name
        if candidate.exists():
            offsets = parse_offsets(candidate.read_text(encoding="utf-8", errors="replace"))
            offsets["source"] = str(candidate)
            break
    else:
        # also parse stdout in case the dumper prints offsets directly
        parsed = parse_offsets(proc.stdout or "")
        if parsed["count"]:
            offsets = parsed
            offsets["source"] = "stdout"

    return {
        "returncode": proc.returncode,
        "out_dir": str(out),
        "stdout_tail": (proc.stdout or "")[-1000:],
        "offsets": offsets,
    }

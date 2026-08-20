"""Reverse-engineering toolchain detection.

Auto-detects installed tools (radare2/rizin, x64dbg, WinDbg/cdb, Binary Ninja,
Il2CppDumper/Inspector, UE dumpers, UE4SS) via, in order:

  1. an explicit path in config ``[tools]``
  2. ``PATH`` (shutil.which over candidate executable names)
  3. common install directories (+ ``[tools.search_dirs].extra``)

Everything degrades gracefully: a missing tool is reported as ``found: false``
with an install hint rather than raising, so unrelated commands keep working.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _env_dirs() -> dict[str, str]:
    return {
        "pf": os.environ.get("ProgramFiles", r"C:\Program Files"),
        "pf86": os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        "pfw": os.environ.get("ProgramW6432", r"C:\Program Files"),
        "local": os.environ.get("LOCALAPPDATA", ""),
        "user": os.environ.get("USERPROFILE", ""),
    }


@dataclass
class ToolSpec:
    name: str
    config_key: str
    executables: list[str]
    default_dirs: list[str] = field(default_factory=list)
    version_args: Optional[list[str]] = None
    kind: str = "cli"  # cli | gui | dumper | debugger
    install_hint: str = ""


def _specs() -> list[ToolSpec]:
    e = _env_dirs()
    return [
        ToolSpec("radare2", "radare2", ["radare2", "r2"], [rf"{e['pf']}\radare2\bin"], ["-v"], "cli",
                 "Install radare2 (https://github.com/radareorg/radare2) and add it to PATH."),
        ToolSpec("rizin", "rizin", ["rizin", "rz"], [rf"{e['pf']}\rizin\bin"], ["-v"], "cli",
                 "Install rizin (https://rizin.re)."),
        ToolSpec("x64dbg", "x64dbg", ["x64dbg", "x96dbg"],
                 [rf"{e['pf']}\x64dbg\release\x64", r"C:\x64dbg\release\x64", rf"{e['local']}\x64dbg"], None, "gui",
                 "Install x64dbg (https://x64dbg.com) and set tools.x64dbg."),
        ToolSpec("x32dbg", "x32dbg", ["x32dbg"],
                 [rf"{e['pf']}\x64dbg\release\x32", r"C:\x64dbg\release\x32"], None, "gui",
                 "Install x64dbg (32-bit build) and set tools.x32dbg."),
        ToolSpec("cdb", "cdb", ["cdb"],
                 [rf"{e['pf86']}\Windows Kits\10\Debuggers\x64",
                  rf"{e['pf']}\Windows Kits\10\Debuggers\x64",
                  rf"{e['pf86']}\Windows Kits\10\Debuggers\x86"], None, "debugger",
                 "Install the Windows SDK 'Debugging Tools for Windows' (provides cdb.exe)."),
        ToolSpec("windbg", "windbg", ["windbg", "WinDbgX"],
                 [rf"{e['pf86']}\Windows Kits\10\Debuggers\x64"], None, "debugger",
                 "Install WinDbg / WinDbg Preview."),
        ToolSpec("binaryninja", "binaryninja", ["binaryninja", "binaryninja.exe"],
                 [rf"{e['pf']}\Vector35\BinaryNinja", rf"{e['local']}\Programs\Vector35\BinaryNinja"], None, "gui",
                 "Install Binary Ninja; the headless API also needs the 'binaryninja' Python module."),
        ToolSpec("il2cppdumper", "il2cppdumper", ["Il2CppDumper", "Il2CppDumper.exe"], [], None, "dumper",
                 "Download Il2CppDumper (https://github.com/Perfare/Il2CppDumper) and set tools.il2cppdumper. "
                 "Only supports metadata <= 31 (Unity < 2022.2); use il2cppdumper_rs for newer titles."),
        ToolSpec("il2cppdumper_rs", "il2cppdumper_rs", ["il2cpp_dumper", "il2cpp_dumper.exe"], [], None, "dumper",
                 "Install il2cpp-dumper-rs (https://github.com/rodroidmods/il2cpp-dumper-rs) via "
                 "'cargo install il2cpp_dumper', or download a release from the repo, and set tools.il2cppdumper_rs. "
                 "Supports metadata v16-v39 (Unity 5.3 - Unity 6)."),
        ToolSpec("il2cppinspector", "il2cppinspector", ["Il2CppInspector", "Il2CppInspector-cli", "Il2CppInspector.exe"], [], None, "dumper",
                 "Download Il2CppInspector and set tools.il2cppinspector."),
        ToolSpec("ue4dumper", "ue4dumper", ["UE4Dumper", "Dumper-7", "UnrealDumper"], [], None, "dumper",
                 "Download a UE dumper (UE4 Dumper / Dumper-7) and set tools.ue4dumper."),
        ToolSpec("ue4ss", "ue4ss", ["UE4SS"], [], None, "dumper",
                 "Install UE4SS (https://github.com/UE4SS-RE/RE-UEPseudo) into the game and set tools.ue4ss."),
        ToolSpec("dotnet", "dotnet", ["dotnet"], [], ["--version"], "cli",
                 "Install the .NET 8 SDK or runtime (https://dotnet.microsoft.com/download/dotnet/8.0); "
                 "'dotnet --version' must succeed. Required to build/run il-tool."),
        ToolSpec("il_tool", "il_tool", ["il-tool", "il-tool.exe"], [], ["--version"], "cli",
                 "Build il-tool via 'iltool/build.ps1' (.NET 8 SDK required; publishes framework-dependent "
                 "win-x64 into src/game_modifier/data/il-tool/), or set tools.il_tool to an existing il-tool.exe."),
    ]


def _query_version(path: str, args: Optional[list[str]]) -> Optional[str]:
    if not args:
        return None
    try:
        proc = subprocess.run([path, *args], capture_output=True, text=True, timeout=8)
        out = (proc.stdout or proc.stderr or "").strip().splitlines()
        return out[0].strip() if out else None
    except Exception:
        return None


def find_tool(spec: ToolSpec, config=None) -> Optional[str]:
    # 1. explicit config path
    if config is not None:
        override = config.tool_path(spec.config_key)
        if override and Path(override).exists():
            return override
    # 2. PATH
    for exe in spec.executables:
        found = shutil.which(exe)
        if found:
            return found
    # 3. default + extra dirs
    search_dirs = list(spec.default_dirs)
    if config is not None:
        search_dirs.extend(config.tool_search_dirs())
    for d in search_dirs:
        if not d:
            continue
        base = Path(d)
        for exe in spec.executables:
            for candidate in (base / exe, base / f"{exe}.exe"):
                if candidate.exists():
                    return str(candidate)
    return None


def detect_tool(name: str, config=None) -> dict:
    spec = next((s for s in _specs() if s.name == name), None)
    if spec is None:
        return {"name": name, "found": False, "error": "unknown tool"}
    path = find_tool(spec, config)
    result = {
        "name": spec.name,
        "kind": spec.kind,
        "found": bool(path),
        "path": path,
    }
    if path:
        version = _query_version(path, spec.version_args)
        if version:
            result["version"] = version
    else:
        result["hint"] = spec.install_hint
    return result


def detect_all(config=None) -> dict:
    tools = {s.name: detect_tool(s.name, config) for s in _specs()}
    available = sorted(n for n, t in tools.items() if t.get("found"))
    return {
        "available": available,
        "available_count": len(available),
        "tools": tools,
    }


# --- Unity IL2CPP metadata version routing ----------------------------------
# The official Il2CppDumper stopped at metadata v31 (Unity ~2022.1). Unity 6
# titles ship metadata up to v39 (variable-width indices); only the Rust
# rewrite (il2cpp-dumper-rs) handles those. Route by the version read from
# the global-metadata.dat header.

def metadata_version(metadata_path) -> Optional[int]:
    """Read the IL2CPP metadata version from a ``global-metadata.dat`` header.

    Layout (all little-endian): 4-byte magic ``0xFAB11BAF``, then the version
    as a plain int. Returns ``None`` for unreadable / non-IL2CPP files.
    """

    try:
        with open(metadata_path, "rb") as fh:
            head = fh.read(8)
        if len(head) < 8:
            return None
        magic, version = struct.unpack_from("<II", head, 0)
        if magic != 0xFAB11BAF:
            return None
        return version
    except Exception:  # noqa: BLE001 - file may be locked/absent
        return None


def recommended_unity_dumper(metadata_path=None, config=None) -> dict:
    """Pick the dumper that can handle the title's metadata version.

    Routing (by ``global-metadata.dat`` version header):

    * version unknown / unreadable -> ``il2cppdumper_rs`` (superset v16-v39);
    * version <= 31 (Unity < 2022.2) -> official ``il2cppdumper``;
    * version  > 31 (Unity 2022.2+, incl. Unity 6) -> ``il2cppdumper_rs``.

    Returns ``{"dumper": "il2cppdumper_rs"|"il2cppdumper", "metadata_version":
    int|None, "found": bool, "path": str|None, "hint": str}``. With no
    metadata path, returns the default (Rust dumper, which covers the full
    v16-v39 range).

    Note: when the recommended family is not installed, callers (see
    ``service.il2cpp_dump``) fall back to the other family before raising
    ``ToolNotFoundError`` with install hints for *both* dumpers - so a title
    that is only ever dumped once with whatever is available still works.
    """

    version = metadata_version(metadata_path) if metadata_path else None
    if version is None:
        # Unknown version: prefer the Rust dumper (superset coverage).
        spec_name = "il2cppdumper_rs"
    elif version <= 31:
        spec_name = "il2cppdumper"
    else:
        spec_name = "il2cppdumper_rs"
    spec = next((s for s in _specs() if s.name == spec_name), None)
    path = find_tool(spec, config) if spec else None
    return {
        "dumper": spec_name,
        "metadata_version": version,
        "found": bool(path),
        "path": path,
        "hint": spec.install_hint if spec else "",
    }

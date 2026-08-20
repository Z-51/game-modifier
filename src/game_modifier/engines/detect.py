"""Game engine detection.

Identifies the engine behind a target (Unity Il2Cpp, Unity Mono, Unreal
Engine, or unknown) from the loaded module list and/or an on-disk game folder.
The detection result tells the higher layers which reverse-engineering adapter
to use and where the key artifacts live (global-metadata.dat, GameAssembly.dll,
*.pak, ...), so an agent does not have to rediscover the layout each time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

# engine identifiers
UNITY_IL2CPP = "unity-il2cpp"
UNITY_MONO = "unity-mono"
UNREAL = "unreal"
UNKNOWN = "unknown"
NWJS = "nwjs"
RPG_MAKER = "rpg-maker"
RENPY = "renpy"
WEBVIEW = "webview"


def _norm_modules(modules) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in modules or []:
        if hasattr(m, "name"):
            out.append((str(m.name).lower(), str(getattr(m, "path", "") or "")))
        elif isinstance(m, dict):
            out.append((str(m.get("name", "")).lower(), str(m.get("path", "") or "")))
        elif isinstance(m, str):
            out.append((m.lower(), ""))
    return out


def _game_dir_from(target: Optional[str]) -> Optional[Path]:
    if not target:
        return None
    p = Path(target)
    if p.is_file():
        return p.parent
    if p.is_dir():
        return p
    return None


def detect_from_modules(modules) -> dict:
    mods = _norm_modules(modules)
    names = {n for n, _ in mods}
    evidence: list[str] = []

    if "gameassembly.dll" in names:
        evidence.append("module:GameAssembly.dll")
        return {"engine": UNITY_IL2CPP, "confidence": 0.9, "evidence": evidence}
    # mono-2.0* is a *generic* runtime (Godot, .NET apps, Mono embedding);
    # it only identifies a Unity Mono game when UnityPlayer.dll is also loaded.
    has_mono = any(n.startswith("mono-2.0") or n.startswith("monobleedingedge") for n in names)
    has_unity_player = "unityplayer.dll" in names
    if has_mono:
        evidence.append("module:mono runtime")
        if has_unity_player:
            evidence.append("module:UnityPlayer.dll")
            return {"engine": UNITY_MONO, "confidence": 0.85, "evidence": evidence}
        # runtime present but no Unity marker -> record the evidence, do NOT
        # claim Unity; fall through to the unknown result below.
    for n, _ in mods:
        if n.endswith("-win64-shipping.exe") or n.startswith("ue4ss") or n in ("ue4ss.dll",):
            evidence.append(f"module:{n}")
            return {"engine": UNREAL, "confidence": 0.85, "evidence": evidence}
    if has_unity_player:
        evidence.append("module:UnityPlayer.dll")
        return {"engine": UNITY_MONO, "confidence": 0.6, "evidence": evidence}
    return {"engine": UNKNOWN, "confidence": 0.0, "evidence": evidence}


def _scan_unity(game_dir: Path) -> Optional[dict]:
    evidence: list[str] = []
    artifacts: dict[str, str] = {}

    ga = game_dir / "GameAssembly.dll"
    if ga.exists():
        artifacts["game_assembly"] = str(ga)
        evidence.append("file:GameAssembly.dll")

    # locate *_Data directory
    data_dir: Optional[Path] = None
    for child in game_dir.glob("*_Data"):
        if child.is_dir():
            data_dir = child
            break
    if data_dir:
        artifacts["data_dir"] = str(data_dir)
        meta = data_dir / "il2cpp_data" / "Metadata" / "global-metadata.dat"
        if meta.exists():
            artifacts["global_metadata"] = str(meta)
            evidence.append("file:global-metadata.dat")
        managed = data_dir / "Managed" / "Assembly-CSharp.dll"
        if managed.exists():
            artifacts["assembly_csharp"] = str(managed)
            evidence.append("file:Assembly-CSharp.dll")

    if (game_dir / "UnityPlayer.dll").exists():
        evidence.append("file:UnityPlayer.dll")

    if "global_metadata" in artifacts or "game_assembly" in artifacts:
        return {"engine": UNITY_IL2CPP, "confidence": 0.95, "evidence": evidence, "artifacts": artifacts}
    if "assembly_csharp" in artifacts:
        return {"engine": UNITY_MONO, "confidence": 0.9, "evidence": evidence, "artifacts": artifacts}
    if evidence:
        return {"engine": UNITY_MONO, "confidence": 0.5, "evidence": evidence, "artifacts": artifacts}
    return None


def _scan_unreal(game_dir: Path) -> Optional[dict]:
    # 排除NW.js/RPG Maker特征——这些引擎也使用.pak文件
    exclusion_markers = ["nw.dll", "index.html", "rmmz_core.js", "rmmv_core.js", "package.json"]
    if any((game_dir / m).exists() for m in exclusion_markers):
        return None
    if (game_dir / "renpy").is_dir():
        return None

    evidence: list[str] = []
    artifacts: dict[str, str] = {}

    shipping = list(game_dir.rglob("*-Win64-Shipping.exe"))
    if shipping:
        artifacts["shipping_exe"] = str(shipping[0])
        evidence.append("file:*-Win64-Shipping.exe")

    paks = list(game_dir.rglob("*.pak"))
    if paks:
        artifacts["pak_dir"] = str(paks[0].parent)
        evidence.append(f"file:{len(paks)} .pak")

    for loader in ("UE4SS.dll", "dwmapi.dll", "xinput1_3.dll"):
        hit = list(game_dir.rglob(loader))
        if any("ue4ss" in str(h).lower() or loader == "UE4SS.dll" for h in hit):
            artifacts["ue4ss"] = str(hit[0])
            evidence.append("file:UE4SS")
            break

    if (game_dir / "Engine").is_dir():
        evidence.append("dir:Engine")

    if artifacts or "dir:Engine" in evidence:
        conf = 0.9 if "shipping_exe" in artifacts else 0.35
        return {"engine": UNREAL, "confidence": conf, "evidence": evidence, "artifacts": artifacts}
    return None


def detect(target: Optional[str] = None, modules: Optional[Iterable] = None) -> dict:
    """Detect the engine from a live module list and/or on-disk folder."""

    from . import nwjs as _nwjs_mod

    # 模块级检测：优先NW.js，否则走原有逻辑
    nwjs_module_result = _nwjs_mod.detect_from_modules(modules) if modules else None
    module_result = nwjs_module_result or (detect_from_modules(modules) if modules else {"engine": UNKNOWN, "confidence": 0.0, "evidence": []})

    game_dir = _game_dir_from(target)
    fs_result: Optional[dict] = None
    if game_dir:
        # 优先检测NW.js/RPG Maker/Ren'Py（否定优先级最高）
        nwjs_result = _nwjs_mod.scan_filesystem(game_dir)
        if nwjs_result and nwjs_result["confidence"] >= 0.7:
            fs_result = nwjs_result
        else:
            fs_result = _scan_unity(game_dir) or _scan_unreal(game_dir)

    # merge: prefer the higher-confidence, richer result but keep artifacts
    best = module_result
    if fs_result and fs_result.get("confidence", 0) >= module_result.get("confidence", 0):
        best = fs_result
    elif fs_result:
        # module result wins but attach filesystem artifacts
        best = dict(module_result)
        best["evidence"] = module_result.get("evidence", []) + fs_result.get("evidence", [])
        if fs_result.get("artifacts"):
            best["artifacts"] = fs_result["artifacts"]

    best.setdefault("artifacts", {})
    if game_dir:
        best["game_dir"] = str(game_dir)
    return best

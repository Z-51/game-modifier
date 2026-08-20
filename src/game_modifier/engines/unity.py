"""Unity Il2Cpp / Mono adapter.

Two responsibilities:

* Drive Il2CppDumper (when installed) to turn ``GameAssembly.dll`` +
  ``global-metadata.dat`` into ``dump.cs`` / ``script.json``.
* Parse those artifacts into structured field offsets and method RVAs so the
  higher layers can build ``GameAssembly.dll+RVA`` addresses or field-offset
  pointer chains without the agent reading the (huge) dump by hand.

The parsers are pure functions and unit-tested against sample text; running the
dumper requires the external tool and the actual game files.
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Optional

from ..errors import ToolNotFoundError, GameModifierError, ErrorCode
# import the submodule members directly: the package rebinds the name ``detect``
# to the function, so ``from . import detect`` would not yield this module.
from .detect import _scan_unity

_NS_RE = re.compile(r"^//\s*Namespace:\s*(?P<ns>.*?)\s*$")
_CLASS_RE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*(?:public|private|internal|protected|sealed|abstract|static|partial|\s)*"
    r"\s*(?:class|struct|enum|interface)\s+(?P<name>[\w`<>]+)"
)
_FIELD_RE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*"
    r"(?P<mods>(?:public|private|protected|internal|static|readonly|const|volatile|extern|unsafe|\s)*)"
    r"\s*(?P<type>[\w\.\<\>\[\]\,\?:]+)\s+(?P<name>\w+)\s*;\s*//\s*(?P<off>0x[0-9A-Fa-f]+)\s*$"
)


def locate_artifacts(game_dir: str) -> dict:
    result = _scan_unity(Path(game_dir))
    return (result or {}).get("artifacts", {})


def parse_dump_cs(text: str, *, max_fields: int = 0) -> list[dict]:
    """Extract field offsets from an Il2CppDumper ``dump.cs``.

    Returns a list of ``{namespace, class, field, type, offset, static}``.
    """

    fields: list[dict] = []
    namespace = ""
    current_class = ""
    for line in text.splitlines():
        ns_m = _NS_RE.match(line)
        if ns_m:
            namespace = ns_m.group("ns")
            continue
        cls_m = _CLASS_RE.match(line)
        if cls_m:
            current_class = cls_m.group("name").split("`")[0]
            continue
        f_m = _FIELD_RE.match(line)
        if f_m and current_class:
            mods = f_m.group("mods") or ""
            fields.append(
                {
                    "namespace": namespace,
                    "class": current_class,
                    "field": f_m.group("name"),
                    "type": f_m.group("type"),
                    "offset": int(f_m.group("off"), 16),
                    "offset_hex": f_m.group("off"),
                    "static": "static" in mods,
                }
            )
            if max_fields and len(fields) >= max_fields:
                break
    return fields


def find_field(fields: list[dict], class_name: str, field_name: str) -> Optional[dict]:
    cls = class_name.lower()
    fld = field_name.lower()
    for f in fields:
        if f["class"].lower() == cls and f["field"].lower() == fld:
            return f
    return None


def parse_script_json(data) -> dict:
    """Parse an Il2CppDumper ``script.json`` into method-name -> RVA map."""

    import json

    if isinstance(data, (str, Path)) and Path(str(data)).exists():
        data = json.loads(Path(str(data)).read_text(encoding="utf-8"))
    elif isinstance(data, str):
        data = json.loads(data)

    methods = {}
    for m in data.get("ScriptMethod", []) or []:
        name = m.get("Name")
        addr = m.get("Address")
        if name is not None and addr is not None:
            methods[name] = int(addr)
    strings = {}
    for s in data.get("ScriptString", []) or []:
        if "Address" in s and "Value" in s:
            strings[int(s["Address"])] = s["Value"]
    return {
        "method_count": len(methods),
        "methods": methods,
        "string_count": len(strings),
    }


def run_dumper(
    dumper_path: str,
    game_assembly: str,
    metadata: str,
    out_dir: str,
    *,
    timeout: int = 600,
) -> dict:
    """Invoke Il2CppDumper and return the produced artifact paths."""

    if not dumper_path or not Path(dumper_path).exists():
        raise ToolNotFoundError(
            "Il2CppDumper not found",
            details={"dumper_path": dumper_path},
            hint="Install Il2CppDumper and set tools.il2cppdumper in config, or pass --tool-path.",
        )
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cmd = [dumper_path, game_assembly, metadata, str(out)]
    if dumper_path.lower().endswith(".dll"):
        cmd = ["dotnet", *cmd]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"could not execute Il2CppDumper: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise GameModifierError(
            f"Il2CppDumper timed out after {timeout}s",
            code=ErrorCode.TOOL_FAILED,
        ) from exc

    dump_cs = out / "dump.cs"
    script_json = out / "script.json"
    artifacts = {name: str(out / name) for name in ("dump.cs", "script.json", "il2cpp.h", "stringliteral.json") if (out / name).exists()}
    if proc.returncode != 0 and not dump_cs.exists():
        raise GameModifierError(
            "Il2CppDumper failed",
            code=ErrorCode.TOOL_FAILED,
            details={"returncode": proc.returncode, "stderr": (proc.stderr or "")[-1500:]},
        )
    return {
        "returncode": proc.returncode,
        "artifacts": artifacts,
        "dump_cs": str(dump_cs) if dump_cs.exists() else None,
        "script_json": str(script_json) if script_json.exists() else None,
    }


# --- session-integrated dumper invocation (il2cpp dump) --------------------
# Unlike :func:`run_dumper` above (which raises on failure and needs explicit
# GameAssembly.dll + global-metadata.dat paths), this variant mirrors the
# ``unreal.run_dumper`` pattern: it takes a single target, runs the tool with
# ``out_dir`` as the working directory (so dumpers that write to CWD land in
# the managed output dir), and reports failures as structured data instead of
# raising, so the service layer can branch on ``ok``.

_DUMPER_OUTPUT_NAMES = ("script.json", "dump.cs", "il2cpp.h", "stringliteral.json")


def run_dumper_cli(dumper_path: str, target: str, out_dir: str, *, timeout: float = 120.0) -> dict:
    """Run an external Il2CppDumper against ``target`` and harvest its outputs.

    Never raises for tool-level failures (missing binary, non-zero exit,
    timeout): the result carries ``ok=False`` plus ``error``/``returncode``/
    ``stderr_tail`` so callers branch on structured data.

    Returns ``{"ok", "outputs", "returncode", "elapsed", ...}`` where
    ``outputs`` maps artifact names (script.json / dump.cs / ...) to paths.
    """

    t0 = time.monotonic()

    def _fail(reason: str, **extra) -> dict:
        res = {"ok": False, "error": reason, "outputs": {},
               "elapsed": round(time.monotonic() - t0, 3)}
        res.update(extra)
        return res

    if not dumper_path or not Path(dumper_path).exists():
        return _fail("dumper not found", dumper_path=dumper_path,
                     hint="Install Il2CppDumper / il2cpp-dumper-rs and set tools.il2cppdumper.")

    out = Path(out_dir)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return _fail(f"cannot create output dir: {exc}", out_dir=str(out_dir))

    cmd = [dumper_path, str(target)]
    if dumper_path.lower().endswith(".dll"):
        cmd = ["dotnet", *cmd]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, cwd=str(out))
    except FileNotFoundError as exc:
        return _fail(f"could not execute dumper: {exc}", dumper_path=dumper_path)
    except subprocess.TimeoutExpired:
        return _fail(f"dumper timed out after {timeout}s", timeout=True,
                     returncode=None, hint="Raise --timeout or narrow the target.")

    outputs = {name: str(out / name) for name in _DUMPER_OUTPUT_NAMES if (out / name).exists()}
    ok = proc.returncode == 0 and bool(outputs)
    res = {
        "ok": ok,
        "outputs": outputs,
        "returncode": proc.returncode,
        "out_dir": str(out),
        "elapsed": round(time.monotonic() - t0, 3),
        "stdout_tail": (proc.stdout or "")[-1000:],
        "stderr_tail": (proc.stderr or "")[-1500:],
    }
    if not ok:
        res["error"] = (
            f"dumper exited with code {proc.returncode}"
            if proc.returncode != 0 else "dumper produced no script.json/dump.cs outputs"
        )
    return res

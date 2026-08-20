"""radare2 / rizin adapter.

Prefers the ``r2pipe`` Python binding when installed (rich, structured JSON);
otherwise shells out to the ``radare2`` executable for a minimal static
overview. Used by ``analyze`` to seed scanning with sections, symbols, imports
and strings.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

from ..errors import ToolNotFoundError, GameModifierError, ErrorCode, InvalidArgsError


def have_r2pipe() -> bool:
    import importlib.util

    return importlib.util.find_spec("r2pipe") is not None


def _analyze_r2pipe(path: str, deep: bool) -> dict:
    import r2pipe

    r2 = r2pipe.open(path, flags=["-2"])
    try:
        r2.cmd("aa" if deep else "aab")
        info = r2.cmdj("ij") or {}
        sections = r2.cmdj("iSj") or []
        symbols = r2.cmdj("isj") or []
        imports = r2.cmdj("iij") or []
        strings = r2.cmdj("izj") or []
        functions = r2.cmdj("aflj") or []
    finally:
        r2.quit()

    bin_info = info.get("bin", {}) if isinstance(info, dict) else {}
    return {
        "backend": "r2pipe",
        "arch": bin_info.get("arch"),
        "bits": bin_info.get("bits"),
        "bintype": bin_info.get("bintype"),
        "sections": [{"name": s.get("name"), "vaddr": s.get("vaddr"), "size": s.get("size")} for s in sections[:60]],
        "section_count": len(sections),
        "symbol_count": len(symbols),
        "import_count": len(imports),
        "string_count": len(strings),
        "function_count": len(functions),
    }


def _analyze_subprocess(path: str, r2_path: str) -> dict:
    try:
        proc = subprocess.run([r2_path, "-q", "-c", "ij", path], capture_output=True, text=True, timeout=120)
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"could not execute radare2: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise GameModifierError("radare2 timed out", code=ErrorCode.TOOL_FAILED) from exc

    info = {}
    try:
        info = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        pass
    bin_info = info.get("bin", {}) if isinstance(info, dict) else {}
    return {
        "backend": "subprocess",
        "arch": bin_info.get("arch"),
        "bits": bin_info.get("bits"),
        "bintype": bin_info.get("bintype"),
        "note": "Install the r2pipe Python package for full static analysis (sections/symbols/strings).",
    }


def analyze(path: str, *, r2_path: Optional[str] = None, deep: bool = False) -> dict:
    if not Path(path).exists():
        raise GameModifierError(f"binary not found: {path}", code=ErrorCode.INVALID_ARGS)
    if have_r2pipe():
        return _analyze_r2pipe(path, deep)
    if r2_path:
        return _analyze_subprocess(path, r2_path)
    raise ToolNotFoundError(
        "radare2 not available",
        hint="Install radare2 and/or `pip install r2pipe`.",
    )


# --- cross-reference queries -------------------------------------------------


def _fmt_addr(address) -> str:
    return hex(int(address)) if not str(address).lower().startswith("0x") else str(address)


def _normalize_xrefs(rows) -> list[dict]:
    out: list[dict] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        src = row.get("from", row.get("ref"))
        dst = row.get("to")
        out.append(
            {
                "from": hex(int(src)) if isinstance(src, int) else src,
                "to": hex(int(dst)) if isinstance(dst, int) else dst,
                "type": str(row.get("type") or ""),
                "fcn": row.get("fcn") or row.get("function") or None,
            }
        )
    return out


def _xrefs_r2pipe(path: str, addr_hex: str, direction: str) -> dict:
    import r2pipe

    r2 = r2pipe.open(path, flags=["-2"])
    try:
        # local analysis of the function containing the address keeps big
        # binaries fast; fall back to the query itself if it fails
        r2.cmd(f"af @ {addr_hex}")
        cmd = "axt" if direction == "to" else "axf"  # cmdj appends 'j'
        rows = r2.cmdj(f"{cmd} {addr_hex}") or []
    finally:
        r2.quit()
    return _normalize_xrefs(rows)


def _xrefs_subprocess(path: str, r2_path: str, addr_hex: str, direction: str,
                      timeout: float) -> dict:
    cmd = "axtj" if direction == "to" else "axfj"
    script = f"af @ {addr_hex};{cmd} {addr_hex}"
    try:
        proc = subprocess.run([r2_path, "-q", "-c", script, path],
                              capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"could not execute radare2: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise GameModifierError("radare2 timed out", code=ErrorCode.TOOL_FAILED) from exc
    rows: list = []
    try:
        parsed = json.loads(proc.stdout or "[]")
        if isinstance(parsed, list):
            rows = parsed
    except json.JSONDecodeError:
        pass
    return _normalize_xrefs(rows)


def xrefs_at(binary_path: str, address, *, direction: str = "to",
             timeout: float = 60.0, r2_path: Optional[str] = None) -> dict:
    """Query cross-references for ``address`` inside an on-disk binary.

    ``direction='to'`` lists who references the address (``axt``),
    ``direction='from'`` lists what the address references (``axf``). The
    address should be an RVA / file virtual address: r2 analyzes the binary
    on disk, not live process memory. Uses ``r2pipe`` when installed,
    otherwise shells out to the radare2 executable. Note: r2pipe has no
    native timeout - very large binaries may take a while to analyze.
    """

    if direction not in ("to", "from"):
        raise InvalidArgsError(
            f"unknown xref direction: {direction!r}",
            details={"supported": ["to", "from"]},
        )
    if not Path(binary_path).exists():
        raise GameModifierError(f"binary not found: {binary_path}", code=ErrorCode.INVALID_ARGS)
    addr_hex = _fmt_addr(address)

    if have_r2pipe():
        xrefs = _xrefs_r2pipe(binary_path, addr_hex, direction)
        backend = "r2pipe"
    elif r2_path:
        xrefs = _xrefs_subprocess(binary_path, r2_path, addr_hex, direction, timeout)
        backend = "subprocess"
    else:
        raise ToolNotFoundError(
            "radare2 not available for xref analysis",
            hint="Install radare2 (https://github.com/radareorg/radare2) and/or `pip install r2pipe`.",
        )
    return {
        "backend": backend,
        "address": addr_hex,
        "direction": direction,
        "xrefs": xrefs,
        "count": len(xrefs),
    }

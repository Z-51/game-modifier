"""x64dbg adapter.

x64dbg is a GUI debugger, so the practical integration is: generate an x64dbg
script that performs the requested memory writes, and optionally launch x64dbg
on the target. The generated script is deterministic and easy for a user to
review before running (Plugins > Script > Load).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from ..errors import ToolNotFoundError
from ..memory import types as vt


def _fmt_value(type_name: str, value) -> str:
    dt = vt.resolve_type(type_name)
    if dt.kind in ("int", "uint", "bool"):
        canon = vt.decode_value(type_name, vt.encode_value(type_name, value))
        return hex(int(canon))
    # floats / strings are written as raw bytes below instead
    return str(value)


def generate_script(operations: list[dict], *, header: str = "") -> str:
    """Build an x64dbg script from ``[{address, type, value, note}]`` operations.

    Integer writes use ``mov [addr], value``. Non-integer values are written as
    a byte sequence via repeated single-byte ``mov`` so any type is supported.
    """

    lines: list[str] = [
        "// ---- game-modifier generated x64dbg script ----",
        "// Review before running. Load via: Plugins > Script > Load, then Run.",
    ]
    if header:
        lines.append(f"// {header}")
    lines.append("")

    for op in operations:
        addr = op["address"]
        addr_s = addr if isinstance(addr, str) else hex(int(addr))
        type_name = op.get("type", "int32")
        value = op.get("value")
        note = op.get("note", "")
        dt = vt.resolve_type(type_name)
        if note:
            lines.append(f"// {note}")
        if dt.kind in ("int", "uint", "bool"):
            lines.append(f"mov [{addr_s}], {_fmt_value(type_name, value)}")
        else:
            raw = vt.encode_value(type_name, value)
            for i, byte in enumerate(raw):
                lines.append(f"mov byte:[{addr_s}+{i}], {hex(byte)}")
        lines.append("")
    lines.append("msg \"game-modifier: writes applied\"")
    return "\n".join(lines)


def write_script(path: str, operations: list[dict], *, header: str = "") -> str:
    text = generate_script(operations, header=header)
    Path(path).write_text(text, encoding="utf-8")
    return path


def launch(x64dbg_path: Optional[str], *, exe: Optional[str] = None, pid: Optional[int] = None) -> dict:
    """Best-effort launch of x64dbg on a target (fire and forget)."""

    if not x64dbg_path or not Path(x64dbg_path).exists():
        raise ToolNotFoundError("x64dbg not found", hint="Set tools.x64dbg in config or pass --tool-path.")
    cmd = [x64dbg_path]
    if pid is not None:
        cmd += ["-p", str(pid)]
    elif exe:
        cmd += [exe]
    proc = subprocess.Popen(cmd)  # noqa: S603 - user-configured debugger
    return {"launched": True, "debugger_pid": proc.pid, "cmd": cmd}

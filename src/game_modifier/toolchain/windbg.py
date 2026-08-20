"""WinDbg (cdb) adapter.

Uses the console debugger ``cdb`` to read/inspect a running process. Attaching a
debugger suspends the target; the adapter always detaches with ``qd`` (quit and
detach) so the game keeps running. Best-effort output parsing is provided for
``db`` (byte dump).

Note: attaching a debugger is intrusive and slower than the native memory
backend - prefer ``read``/``scan`` for routine work; cdb is for deeper
inspection or when a symbol server is needed.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Optional

from ..errors import ToolNotFoundError, GameModifierError, ErrorCode

_BYTE = re.compile(r"\b[0-9A-Fa-f]{2}\b")


def run_cdb(
    cdb_path: str,
    commands: list[str],
    *,
    pid: Optional[int] = None,
    exe: Optional[str] = None,
    process_name: Optional[str] = None,
    timeout: int = 60,
) -> dict:
    """Attach cdb, run ``commands``, always detach with ``qd``.

    Attach by pid (``-p``), by process name (``-pn``), or launch an exe.
    """

    if not cdb_path or not Path(cdb_path).exists():
        raise ToolNotFoundError("cdb not found", hint="Install 'Debugging Tools for Windows' and set tools.cdb.")
    script = ";".join([*commands, "qd"])
    cmd = [cdb_path]
    if pid is not None:
        cmd += ["-p", str(pid)]
    elif process_name:
        cmd += ["-pn", process_name]
    elif exe:
        cmd += [exe]
    else:
        raise GameModifierError("cdb needs a pid, process_name or exe", code=ErrorCode.INVALID_ARGS)
    cmd += ["-c", script]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"could not execute cdb: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise GameModifierError("cdb timed out", code=ErrorCode.TOOL_FAILED) from exc
    return {"returncode": proc.returncode, "stdout": proc.stdout or "", "stderr": proc.stderr or ""}


def parse_db(output: str) -> bytes:
    """Parse the bytes out of a cdb ``db`` dump."""

    data = bytearray()
    for line in output.splitlines():
        # a db line looks like: 00000140`00000000  0f 27 00 00-... ".'.."
        if "`" not in line and not re.match(r"^\s*[0-9A-Fa-f]{8}", line):
            continue
        body = line.replace("-", " ")
        # drop the leading address token
        parts = body.split(None, 1)
        if len(parts) < 2:
            continue
        rest = parts[1]
        # stop at the ASCII column (two+ spaces) if present
        ascii_split = re.split(r"\s{2,}", rest, maxsplit=1)
        hexpart = ascii_split[0]
        for tok in _BYTE.findall(hexpart):
            data.append(int(tok, 16))
    return bytes(data)


def read_bytes(cdb_path: str, pid: int, address: int, size: int, *, timeout: int = 60) -> bytes:
    result = run_cdb(cdb_path, [f"db {hex(address)} L{size:#x}"], pid=pid, timeout=timeout)
    return parse_db(result["stdout"])[:size]


def write_bytes(cdb_path: str, pid: int, address: int, data: bytes, *, timeout: int = 60) -> dict:
    """Write raw bytes via cdb ``eb`` (edit bytes)."""

    byte_str = " ".join(f"{b:02x}" for b in data)
    result = run_cdb(cdb_path, [f"eb {hex(address)} {byte_str}"], pid=pid, timeout=timeout)
    return {"returncode": result["returncode"], "wrote": len(data), "address_hex": hex(address)}


def write_dword(cdb_path: str, pid: int, address: int, value: int, *, timeout: int = 60) -> dict:
    """Write a 32-bit value via cdb ``ed`` (edit dword)."""

    result = run_cdb(cdb_path, [f"ed {hex(address)} {value:#x}"], pid=pid, timeout=timeout)
    return {"returncode": result["returncode"], "address_hex": hex(address), "value": value}

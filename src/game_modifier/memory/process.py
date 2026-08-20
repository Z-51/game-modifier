"""Process discovery.

Uses ``psutil`` when available (richer, cross-platform); otherwise falls back
to a pure-ctypes Toolhelp snapshot on Windows so the tool works with zero
optional dependencies. Only enumeration lives here - attaching and
reading/writing memory is the backend's job.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Optional

try:  # optional convenience dependency
    import psutil  # type: ignore

    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover - psutil absent
    psutil = None  # type: ignore
    _HAVE_PSUTIL = False


@dataclass
class ProcInfo:
    pid: int
    name: str
    exe: str = ""

    def to_dict(self) -> dict:
        return {"pid": self.pid, "name": self.name, "exe": self.exe}


def _list_psutil() -> list[ProcInfo]:
    out: list[ProcInfo] = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):  # type: ignore[union-attr]
        try:
            info = proc.info
            out.append(ProcInfo(pid=info["pid"], name=info.get("name") or "", exe=info.get("exe") or ""))
        except Exception:
            continue
    return out


def list_processes() -> list[ProcInfo]:
    """Return all visible processes."""

    if _HAVE_PSUTIL:
        return _list_psutil()
    if sys.platform.startswith("win"):
        from .windows import enum_processes_win

        return enum_processes_win()
    raise RuntimeError("process enumeration requires psutil on this platform")


def find_by_name(name: str) -> list[ProcInfo]:
    """Case-insensitive match on the executable's base name (``.exe`` optional)."""

    needle = name.lower()
    if needle.endswith(".exe"):
        needle = needle[:-4]
    matches: list[ProcInfo] = []
    for proc in list_processes():
        base = proc.name.lower()
        if base.endswith(".exe"):
            base = base[:-4]
        if base == needle:
            matches.append(proc)
    return matches


def find_by_exe(path: str) -> list[ProcInfo]:
    target = os.path.normcase(os.path.abspath(path))
    matches: list[ProcInfo] = []
    for proc in list_processes():
        if proc.exe and os.path.normcase(os.path.abspath(proc.exe)) == target:
            matches.append(proc)
    return matches


def find_by_window_title(title_pattern: str) -> list[ProcInfo]:
    """Find processes owning a visible window whose title matches ``title_pattern``.

    The pattern is a case-insensitive regex (falling back to a substring match
    when it is not valid regex). Several windows may belong to one process, so
    results are de-duplicated by pid. Windows only.
    """

    finder = globals().get("find_windows_by_title")
    if finder is None:
        if not sys.platform.startswith("win"):
            raise RuntimeError("window title matching requires Windows")
        from .windows import find_windows_by_title as finder

    seen_pids: set[int] = set()
    matches: list[ProcInfo] = []
    for window in finder(title_pattern):
        pid = window["pid"]
        if pid in seen_pids:
            continue
        proc = get_process(pid)
        if proc:
            matches.append(proc)
            seen_pids.add(pid)
    return matches


def process_exists(pid: int) -> bool:
    if _HAVE_PSUTIL:
        return psutil.pid_exists(pid)  # type: ignore[union-attr]
    for proc in list_processes():
        if proc.pid == pid:
            return True
    return False


def get_process(pid: int) -> Optional[ProcInfo]:
    for proc in list_processes():
        if proc.pid == pid:
            return proc
    return None


def is_admin() -> bool:
    """Cross-platform elevation check (Administrator on Windows, root elsewhere)."""

    if sys.platform.startswith("win"):
        from .windows import is_admin as _win_is_admin

        return _win_is_admin()
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover - platform without geteuid
        return False

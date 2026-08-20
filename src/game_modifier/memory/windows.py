"""Windows memory backend built directly on kernel32 via ctypes.

No third-party dependency is required. Implements attach, region enumeration,
module enumeration (Toolhelp), typed reads/writes with an automatic
``VirtualProtectEx`` fallback for read-only pages, and architecture detection.

This module is import-safe on non-Windows platforms (ctypes bindings are built
lazily inside functions), so the rest of the package still imports for tests.
"""

from __future__ import annotations

import ctypes
import re
from ctypes import wintypes
from typing import Optional

from ..errors import (
    AccessDeniedError,
    ProcessNotFoundError,
    ReadFailedError,
    UnsupportedOSError,
    WriteFailedError,
)
from .base import MemoryBackend, MemoryRegion, ModuleInfo, ProcessInfo
from .process import ProcInfo

# --- constants ---------------------------------------------------------------
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
_DESIRED_ACCESS = (
    PROCESS_QUERY_INFORMATION
    | PROCESS_QUERY_LIMITED_INFORMATION
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE
)

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

_READABLE = {
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
}
_WRITABLE = {PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}
_EXECUTABLE = {PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}

STILL_ACTIVE = 259
_MAX_USER_ADDR_X64 = 0x00007FFFFFFF0000
_MAX_USER_ADDR_X86 = 0x00000000FFFF0000


def _is_windows() -> bool:
    return hasattr(ctypes, "windll")


def _require_windows():
    if not _is_windows():
        raise UnsupportedOSError("Windows memory backend used on a non-Windows platform")
    return ctypes.windll.kernel32


def is_admin() -> bool:
    """Return True if the current process has administrator privileges."""

    if not _is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover - defensive
        return False


# --- ctypes structures -------------------------------------------------------
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


_prototyped = False


def _setup_prototypes(k32) -> None:
    global _prototyped
    if _prototyped:
        return
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    ]
    k32.ReadProcessMemory.restype = wintypes.BOOL
    k32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    ]
    k32.WriteProcessMemory.restype = wintypes.BOOL
    k32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
    ]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.VirtualProtectEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]
    k32.VirtualProtectEx.restype = wintypes.BOOL
    k32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    k32.IsWow64Process.restype = wintypes.BOOL
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.GetExitCodeProcess.restype = wintypes.BOOL
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for fn in ("Process32FirstW", "Process32NextW"):
        getattr(k32, fn).argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        getattr(k32, fn).restype = wintypes.BOOL
    for fn in ("Module32FirstW", "Module32NextW"):
        getattr(k32, fn).argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
        getattr(k32, fn).restype = wintypes.BOOL
    _prototyped = True


# --- enumeration helpers -----------------------------------------------------
def enum_processes_win() -> list[ProcInfo]:
    k32 = _require_windows()
    _setup_prototypes(k32)
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (0, None) or snap == wintypes.HANDLE(-1).value:
        return []
    out: list[ProcInfo] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            out.append(ProcInfo(pid=int(entry.th32ProcessID), name=entry.szExeFile))
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return out


def _enum_modules_win(pid: int) -> list[ModuleInfo]:
    k32 = _require_windows()
    _setup_prototypes(k32)
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap in (0, None) or snap == wintypes.HANDLE(-1).value:
        return []
    mods: list[ModuleInfo] = []
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        ok = k32.Module32FirstW(snap, ctypes.byref(entry))
        while ok:
            mods.append(
                ModuleInfo(
                    name=entry.szModule,
                    base=int(entry.modBaseAddr or 0),
                    size=int(entry.modBaseSize),
                    path=entry.szExePath,
                )
            )
            ok = k32.Module32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return mods


def find_windows_by_title(title_pattern: str) -> list[dict]:
    """Enumerate visible top-level windows whose title matches ``title_pattern``.

    The pattern is a case-insensitive regex; an invalid regex degrades to a
    plain (escaped) substring match. Returns a list of
    ``{"hwnd": int, "pid": int, "title": str}`` in enumeration order.
    """

    if not _is_windows():
        raise UnsupportedOSError("window enumeration used on a non-Windows platform")
    user32 = ctypes.windll.user32
    try:
        pattern = re.compile(title_pattern, re.IGNORECASE)
    except re.error:
        pattern = re.compile(re.escape(title_pattern), re.IGNORECASE)

    results: list[dict] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def _enum_callback(hwnd, _lparam):
        if user32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, buf, 512)
            title = buf.value
            if title and pattern.search(title):
                pid = wintypes.DWORD(0)
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                results.append({"hwnd": int(hwnd), "pid": int(pid.value), "title": title})
        return True

    user32.EnumWindows(_enum_callback, 0)
    return results


class WindowsMemoryBackend(MemoryBackend):
    def __init__(self) -> None:
        super().__init__()
        self._handle: Optional[int] = None
        self._k32 = None
        # Reusable read buffer: avoids a fresh ctypes allocation per read.
        self._rbuf = bytearray(64 * 1024)
        self._rview = memoryview(self._rbuf)

    # ------------------------------------------------------------- lifecycle
    def open(self, pid: int) -> ProcessInfo:
        self._k32 = _require_windows()
        _setup_prototypes(self._k32)
        handle = self._k32.OpenProcess(_DESIRED_ACCESS, False, pid)
        if not handle:
            err = ctypes.get_last_error()
            if err == 5:  # ERROR_ACCESS_DENIED
                admin = is_admin()
                raise AccessDeniedError(
                    f"access denied opening pid {pid}",
                    hint=(
                        "Run the terminal/agent as Administrator to attach to this process."
                        if not admin
                        else "Already elevated; the process may be protected (anti-cheat/DRM) or a system process."
                    ),
                    details={"pid": pid, "win_error": err, "is_admin": admin},
                )
            raise ProcessNotFoundError(
                f"could not open pid {pid} (win error {err})",
                details={"pid": pid, "win_error": err},
            )
        self._handle = handle
        modules = _enum_modules_win(pid)
        arch = self._detect_arch()
        name = modules[0].name if modules else str(pid)
        exe = modules[0].path if modules else ""
        self.info = ProcessInfo(pid=pid, name=name, exe_path=exe, arch=arch, modules=modules)
        return self.info

    def _detect_arch(self) -> str:
        is_wow64 = wintypes.BOOL(False)
        try:
            if self._k32.IsWow64Process(self._handle, ctypes.byref(is_wow64)):
                # On a 64-bit OS, a WOW64 process is 32-bit.
                return "x86" if is_wow64.value else "x64"
        except Exception:  # pragma: no cover
            pass
        return "x64"

    def close(self) -> None:
        if self._handle and self._k32:
            self._k32.CloseHandle(self._handle)
        self._handle = None

    def is_alive(self) -> bool:
        if not self._handle or not self._k32:
            return False
        code = wintypes.DWORD(0)
        if self._k32.GetExitCodeProcess(self._handle, ctypes.byref(code)):
            return code.value == STILL_ACTIVE
        return False

    # -------------------------------------------------------------- read/write
    def read(self, address: int, size: int) -> bytes:
        if not self._handle:
            raise ReadFailedError("backend not attached")
        if len(self._rbuf) < size:
            self._rbuf = bytearray(size)
            self._rview = memoryview(self._rbuf)
        read = ctypes.c_size_t(0)
        ok = self._k32.ReadProcessMemory(
            self._handle, ctypes.c_void_p(address), (ctypes.c_char * size).from_buffer(self._rbuf),
            size, ctypes.byref(read),
        )
        if not ok or read.value != size:
            # A partial read (0 < read < size) is a failure, not a truncated
            # success: returning short data would silently decode corrupt
            # values downstream. Treat it exactly like a failed read.
            err = ctypes.get_last_error()
            raise ReadFailedError(
                f"failed to read {size} bytes at {hex(address)} (got {read.value}, win error {err})",
                details={
                    "address": address,
                    "address_hex": hex(address),
                    "size": size,
                    "bytes_read": read.value,
                    "partial": read.value > 0,
                    "win_error": err,
                },
            )
        return bytes(self._rview[:size])

    def read_many(self, addresses: list[int], size: int) -> dict[int, bytes]:
        """Batched read: merge contiguous addresses per VirtualQueryEx region.

        A merged span never crosses a region boundary; each run is satisfied by
        a single ``ReadProcessMemory`` call whose result is sliced per address.
        Addresses that cannot be read are omitted from the result.
        """

        if not addresses:
            return {}
        out: dict[int, bytes] = {}
        for run_start, run_len, addrs in self._plan_read_runs(sorted(set(addresses)), size):
            try:
                data = self.read(run_start, run_len)
            except Exception:
                continue
            for addr in addrs:
                out[addr] = data[addr - run_start: addr - run_start + size]
        return out

    def _plan_read_runs(self, sorted_addrs: list[int], size: int) -> list[tuple[int, int, list[int]]]:
        """Group sorted addresses into contiguous runs inside one region each."""

        runs: list[tuple[int, int, list[int]]] = []
        cur_start = cur_len = 0
        cur_addrs: list[int] = []
        region: Optional[MemoryRegion] = None
        for addr in sorted_addrs:
            r = self.query(addr)
            if r is None or not r.contains(addr, size):
                continue
            if cur_addrs and addr == cur_start + cur_len and region is not None and r.contains(cur_start, cur_len + size):
                cur_len += size
                cur_addrs.append(addr)
                continue
            if cur_addrs:
                runs.append((cur_start, cur_len, cur_addrs))
            cur_start, cur_len, cur_addrs, region = addr, size, [addr], r
        if cur_addrs:
            runs.append((cur_start, cur_len, cur_addrs))
        return runs

    def write(self, address: int, data: bytes) -> int:
        if not self._handle:
            raise WriteFailedError("backend not attached")
        size = len(data)
        buf = (ctypes.c_char * size).from_buffer_copy(data)
        written = ctypes.c_size_t(0)
        ok = self._k32.WriteProcessMemory(
            self._handle, ctypes.c_void_p(address), ctypes.byref(buf), size, ctypes.byref(written)
        )
        if not ok:
            # Retry once with a temporary RW protection for read-only pages.
            if self._write_with_protect(address, buf, size, written):
                return written.value
            err = ctypes.get_last_error()
            raise WriteFailedError(
                f"failed to write {size} bytes at {hex(address)} (win error {err})",
                details={"address": address, "address_hex": hex(address), "size": size, "win_error": err},
            )
        return written.value

    def _write_with_protect(self, address, buf, size, written) -> bool:
        old = wintypes.DWORD(0)
        if not self._k32.VirtualProtectEx(
            self._handle, ctypes.c_void_p(address), size, PAGE_EXECUTE_READWRITE, ctypes.byref(old)
        ):
            return False
        try:
            ok = self._k32.WriteProcessMemory(
                self._handle, ctypes.c_void_p(address), ctypes.byref(buf), size, ctypes.byref(written)
            )
        finally:
            restore = wintypes.DWORD(0)
            self._k32.VirtualProtectEx(self._handle, ctypes.c_void_p(address), size, old.value, ctypes.byref(restore))
        return bool(ok)

    # ----------------------------------------------------------------- layout
    def query(self, address: int) -> Optional[MemoryRegion]:
        if not self._handle:
            return None
        mbi = MEMORY_BASIC_INFORMATION()
        got = self._k32.VirtualQueryEx(
            self._handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if got == 0:
            return None
        return self._region_from_mbi(mbi)

    @staticmethod
    def _region_from_mbi(mbi: MEMORY_BASIC_INFORMATION) -> MemoryRegion:
        protect = int(mbi.Protect)
        guarded = bool(protect & PAGE_GUARD)
        base_protect = protect & ~PAGE_GUARD & ~0x200  # strip GUARD / NOCACHE
        committed = int(mbi.State) == MEM_COMMIT
        readable = committed and (base_protect in _READABLE) and not guarded
        writable = committed and (base_protect in _WRITABLE) and not guarded
        executable = committed and (base_protect in _EXECUTABLE)
        return MemoryRegion(
            base=int(mbi.BaseAddress or 0),
            size=int(mbi.RegionSize),
            protect=protect,
            state=int(mbi.State),
            type=int(mbi.Type),
            readable=readable,
            writable=writable,
            executable=executable,
        )

    def regions(self) -> list[MemoryRegion]:
        if not self._handle:
            return []
        out: list[MemoryRegion] = []
        addr = 0
        max_addr = _MAX_USER_ADDR_X86 if (self.info and self.info.arch == "x86") else _MAX_USER_ADDR_X64
        mbi = MEMORY_BASIC_INFORMATION()
        while addr < max_addr:
            got = self._k32.VirtualQueryEx(
                self._handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if got == 0:
                break
            region = self._region_from_mbi(mbi)
            if region.size == 0:
                break
            if region.state == MEM_COMMIT:
                out.append(region)
            addr = region.base + region.size
        return out

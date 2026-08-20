"""Hardware write watchpoints via x86 debug registers (DR0-DR3). Windows only.

Technique: attach a temporary debugger (``DebugActiveProcess``), enumerate the
target process threads, ``SuspendThread`` + ``GetThreadContext`` on each, set
``DR0=target address`` / ``DR7=write-enable`` for that slot, resume, then pump
``WaitForDebugEvent`` capturing ``EXCEPTION_SINGLE_STEP`` (hardware breakpoint)
events, recording the faulting RIP and thread id. Original DR values are
restored and the debugger detaches on every exit path (try/finally).

This is the precise upgrade of the polling ``watch`` command: instead of
observing *that* a value changed, it identifies *which instruction* wrote it
(Cheat Engine's "Find what writes to this address").

Safety: sampling suspends target threads briefly; ``duration`` is hard-capped.
Only usable on anti-cheat-free sessions (enforced by the service layer).
"""

from __future__ import annotations

import ctypes
import time
from ctypes import wintypes
from typing import Optional

from ..errors import AccessDeniedError, InvalidArgsError, ProcessNotFoundError, UnsupportedOSError

# --- constants ---------------------------------------------------------------
TH32CS_SNAPTHREAD = 0x00000004
THREAD_SUSPEND_RESUME = 0x0002
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_QUERY_INFORMATION = 0x0040
PROCESS_SUSPEND_RESUME = 0x0800

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

INFINITE = 0xFFFFFFFF
WAIT_TIMEOUT = 0x102
WAIT_OBJECT_0 = 0x0

DBG_CONTINUE = 0x00010002

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
EXIT_PROCESS_DEBUG_EVENT = 5
EXCEPTION_SINGLE_STEP = 0x80000004

CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = 0x00000001
CONTEXT_INTEGER = 0x00000002
CONTEXT_SEGMENTS = 0x00000004
CONTEXT_FLOATING_POINT = 0x00000008
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010  # 0x100010
WOW64_CONTEXT_i386 = 0x00010000
WOW64_CONTEXT_DEBUG_REGISTERS = WOW64_CONTEXT_i386 | 0x00000010  # 0x10010

DR_SLOT = 0  # simplified implementation: fixed DR0 slot
_LEN_CODE = {1: 0, 2: 1, 4: 3, 8: 2}  # size -> LEN field (8 encoded as 2)
MAX_DURATION = 30.0  # hard cap: target threads are suspended while sampling
_SUSPEND_FAILED = (-1, 0xFFFFFFFF)  # signed and unsigned views of the failure code


def _is_windows() -> bool:
    return hasattr(ctypes, "windll")


# --- pure DR7 math (unit-testable) -------------------------------------------
def dr7_enable_write_slot(old_dr7: int, slot: int = DR_SLOT, size: int = 4) -> int:
    """Return DR7 with a write breakpoint armed on ``slot``.

    Sets L+G enable for the slot (RW=01: writes only) and programs the LEN
    field for ``size`` bytes (1/2/4/8). All unrelated bits are preserved.
    """

    if size not in _LEN_CODE:
        raise InvalidArgsError(f"unsupported watchpoint size: {size}", details={"supported": [1, 2, 4, 8]})
    if not 0 <= slot <= 3:
        raise InvalidArgsError(f"invalid DR slot: {slot}", details={"supported": [0, 1, 2, 3]})
    dr7 = old_dr7 & ~(0xF << (16 + 4 * slot))  # clear RW + LEN for the slot
    dr7 |= (0x1 << (16 + 4 * slot))  # RW = 01 (write)
    dr7 |= (_LEN_CODE[size] << (18 + 4 * slot))  # LEN
    dr7 |= (1 << (2 * slot)) | (1 << (2 * slot + 1))  # local + global enable
    return dr7


def dr7_disable_slot(old_dr7: int, slot: int = DR_SLOT) -> int:
    """Return DR7 with the enable bits for ``slot`` cleared (RW/LEN preserved)."""

    return old_dr7 & ~(0x3 << (2 * slot))


# --- ctypes structures -------------------------------------------------------
class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
    ]


class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]


class XSAVE_FORMAT64(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.WORD),
        ("StatusWord", wintypes.WORD),
        ("TagWord", ctypes.c_byte),
        ("Reserved1", ctypes.c_byte),
        ("ErrorOpcode", wintypes.WORD),
        ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.WORD),
        ("Reserved2", wintypes.WORD),
        ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.WORD),
        ("Reserved3", wintypes.WORD),
        ("MxCsr", wintypes.DWORD),
        ("MxCsr_Mask", wintypes.DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", ctypes.c_byte * 96),
    ]


class CONTEXT64(ctypes.Structure):
    """amd64 CONTEXT (sizeof == 1232). Layout must be exact: the kernel
    validates the structure and reads/writes DRs at fixed offsets."""

    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("FltSave", XSAVE_FORMAT64),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", wintypes.DWORD),
        ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD),
        ("FloatSave", ctypes.c_byte * 112),
        ("SegGs", wintypes.DWORD),
        ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD),
        ("Edi", wintypes.DWORD),
        ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD),
        ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD),
        ("Ebp", wintypes.DWORD),
        ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD),
        ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD),
        ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", wintypes.DWORD),
        ("ExceptionFlags", wintypes.DWORD),
        ("ExceptionRecord", ctypes.c_void_p),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", wintypes.DWORD),
        ("ExceptionInformation", ctypes.c_ulonglong * 15),
    ]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", wintypes.DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wintypes.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]


class _DEBUG_EVENT_U(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("_pad", ctypes.c_byte * 160),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", _DEBUG_EVENT_U),
    ]


_prototyped = set()


def _setup_prototypes(k32) -> None:
    """Set argtypes/restypes so large DWORDs (e.g. EXCEPTION_SINGLE_STEP =
    0x80000004) survive the default signed-int result conversion.

    Silently skipped for non-ctypes stand-ins (test fakes)."""

    if id(k32) in _prototyped:
        return
    try:
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenThread.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
        k32.IsWow64Process.restype = wintypes.BOOL
        k32.DebugActiveProcess.argtypes = [wintypes.DWORD]
        k32.DebugActiveProcess.restype = wintypes.BOOL
        k32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
        k32.DebugActiveProcessStop.restype = wintypes.BOOL
        k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
        k32.Thread32First.restype = wintypes.BOOL
        k32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
        k32.Thread32Next.restype = wintypes.BOOL
        k32.SuspendThread.argtypes = [wintypes.HANDLE]
        k32.SuspendThread.restype = wintypes.DWORD
        k32.ResumeThread.argtypes = [wintypes.HANDLE]
        k32.ResumeThread.restype = wintypes.DWORD
        k32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD]
        k32.WaitForDebugEvent.restype = wintypes.BOOL
        k32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
        k32.ContinueDebugEvent.restype = wintypes.BOOL
        k32.GetLastError.restype = wintypes.DWORD
    except (AttributeError, TypeError):
        pass  # fake / non-ctypes kernel32 stand-in
    _prototyped.add(id(k32))


# --- thread helpers -----------------------------------------------------------
def _enum_thread_ids(k32, pid: int) -> list[int]:
    """Thread ids belonging to ``pid`` via CreateToolhelp32Snapshot(THREAD)."""

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap in (0, None) or snap == wintypes.HANDLE(-1).value:
        return []
    tids: list[int] = []
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        if k32.Thread32First(snap, entry):
            while True:
                if int(entry.th32OwnerProcessID) == pid:
                    tids.append(int(entry.th32ThreadID))
                if not k32.Thread32Next(snap, entry):
                    break
    finally:
        k32.CloseHandle(snap)
    return tids


def _context_cls(is_wow64: bool):
    if is_wow64:
        return WOW64_CONTEXT, WOW64_CONTEXT_DEBUG_REGISTERS, lambda ctx: int(ctx.Eip)
    return CONTEXT64, CONTEXT_DEBUG_REGISTERS, lambda ctx: int(ctx.Rip)


def _get_context(k32, h_thread, ctx):
    """``ctx`` is a ctypes structure; byref is applied at the real call site."""

    if isinstance(ctx, ctypes.Structure):
        return bool(k32.GetThreadContext(h_thread, ctypes.byref(ctx)))
    return bool(k32.GetThreadContext(h_thread, ctx))


def _set_context(k32, h_thread, ctx) -> bool:
    if isinstance(ctx, ctypes.Structure):
        return bool(k32.SetThreadContext(h_thread, ctypes.byref(ctx)))
    return bool(k32.SetThreadContext(h_thread, ctx))


def _snapshot_thread_drs(k32, tid: int, ctx_cls, ctx_flags,
                         originals: dict[int, tuple[int, int]], warnings: list[str]) -> None:
    """Record the current DR0/DR7 of one thread so cleanup can restore them."""

    h = k32.OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, False, tid)
    if not h:
        return
    try:
        if int(k32.SuspendThread(h)) in _SUSPEND_FAILED:
            return
        try:
            ctx = ctx_cls()
            ctx.ContextFlags = ctx_flags
            if _get_context(k32, h, ctx):
                originals[tid] = (int(ctx.Dr0), int(ctx.Dr7))
        finally:
            k32.ResumeThread(h)
    finally:
        k32.CloseHandle(h)


def _arm_thread(k32, tid: int, address: int, size: int, ctx_cls, ctx_flags,
                originals: dict[int, tuple[int, int]], warnings: list[str]) -> None:
    """Suspend one thread, record original DR0/DR7, arm the write breakpoint."""

    h = k32.OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, False, tid)
    if not h:
        warnings.append(f"OpenThread failed for tid {tid}")
        return
    try:
        susp = int(k32.SuspendThread(h))
        if susp in _SUSPEND_FAILED:  # 0xFFFFFFFF: thread terminated / inaccessible
            return
        try:
            ctx = ctx_cls()
            ctx.ContextFlags = ctx_flags
            if not _get_context(k32, h, ctx):
                warnings.append(f"GetThreadContext failed for tid {tid}")
                return
            if tid not in originals:
                originals[tid] = (int(ctx.Dr0), int(ctx.Dr7))
            ctx.Dr0 = address
            ctx.Dr7 = dr7_enable_write_slot(int(ctx.Dr7), DR_SLOT, size)
            ctx.ContextFlags = ctx_flags
            if not _set_context(k32, h, ctx):
                warnings.append(f"SetThreadContext failed for tid {tid}")
        finally:
            k32.ResumeThread(h)
    finally:
        k32.CloseHandle(h)


def _restore_thread(k32, tid: int, orig: tuple[int, int], ctx_cls, ctx_flags,
                    warnings: list[str]) -> Optional[bool]:
    """Restore the original DR0/DR7 of one thread.

    Returns True on success, False when the thread exists but the restore
    failed, and None when the thread is gone (nothing left to restore).
    """

    h = k32.OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, False, tid)
    if not h:
        return None
    try:
        if int(k32.SuspendThread(h)) in _SUSPEND_FAILED:
            return None  # thread gone; nothing left to restore
        try:
            ctx = ctx_cls()
            ctx.ContextFlags = ctx_flags
            if not _get_context(k32, h, ctx):
                warnings.append(f"restore GetThreadContext failed for tid {tid}")
                return False
            ctx.Dr0 = orig[0]
            ctx.Dr7 = orig[1]
            ctx.ContextFlags = ctx_flags
            if not _set_context(k32, h, ctx):
                warnings.append(f"restore SetThreadContext failed for tid {tid}")
                return False
            return True
        finally:
            k32.ResumeThread(h)
    finally:
        k32.CloseHandle(h)


def _disable_hit(k32, tid: int, ctx_cls, ctx_flags) -> None:
    """After a hit, clear the slot enable bits so the thread doesn't re-trigger."""

    h = k32.OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, False, tid)
    if not h:
        return
    try:
        ctx = ctx_cls()
        ctx.ContextFlags = ctx_flags
        if _get_context(k32, h, ctx):
            ctx.Dr7 = dr7_disable_slot(int(ctx.Dr7), DR_SLOT)
            ctx.ContextFlags = ctx_flags
            _set_context(k32, h, ctx)
    finally:
        k32.CloseHandle(h)


def _detect_wow64(k32, h_process) -> bool:
    is_wow = wintypes.BOOL(False)
    try:
        if k32.IsWow64Process(h_process, ctypes.byref(is_wow)):
            return bool(is_wow.value)
    except Exception:  # pragma: no cover - defensive
        pass
    return False


# --- public API ---------------------------------------------------------------
def find_writers(pid: int, address: int, *, size: int = 4, duration: float = 5.0,
                 max_hits: int = 20, kernel32=None) -> dict:
    """Set a hardware write breakpoint and sample the writers of ``address``.

    Returns ``{"address", "hits": [{"rip", "thread_id", "ts"}], "hit_count",
    "duration_sampled", "restored", "warning"}``. All debug-register state is
    restored and the debugger detached on every exit path.
    """

    if not _is_windows():
        raise UnsupportedOSError("hardware watchpoints are Windows-only")
    if size not in _LEN_CODE:
        raise InvalidArgsError(f"unsupported watchpoint size: {size}", details={"supported": [1, 2, 4, 8]})
    k32 = kernel32 or ctypes.windll.kernel32
    _setup_prototypes(k32)

    duration = min(max(float(duration), 0.25), MAX_DURATION)
    max_hits = max(1, int(max_hits))

    h_process = k32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME, False, pid
    )
    if not h_process:
        err = ctypes.get_last_error()
        raise ProcessNotFoundError(
            f"could not open pid {pid} (win error {err})",
            details={"pid": pid, "win_error": err},
        )
    try:
        is_wow64 = _detect_wow64(k32, h_process)
    finally:
        k32.CloseHandle(h_process)

    ctx_cls, ctx_flags, rip_of = _context_cls(is_wow64)

    if not k32.DebugActiveProcess(pid):
        err = ctypes.get_last_error()
        if err in (5, 1):  # ERROR_ACCESS_DENIED / ERROR_INVALID_FUNCTION
            raise AccessDeniedError(
                f"DebugActiveProcess failed for pid {pid} (win error {err})",
                hint="Run the terminal/agent as Administrator to debug this process.",
                details={"pid": pid, "win_error": err},
            )
        raise ProcessNotFoundError(
            f"DebugActiveProcess failed for pid {pid} (win error {err}; process may already be debugged)",
            details={"pid": pid, "win_error": err},
        )

    originals: dict[int, tuple[int, int]] = {}  # tid -> (orig_dr0, orig_dr7)
    armed: set[int] = set()
    pending: set[int] = set()
    hits: list[dict] = []
    warnings: list[str] = []
    start = time.time()
    try:
        # IMPORTANT: threads are debug-stopped until the initial events are
        # continued, so we must NOT SuspendThread them right after attach
        # (Suspend/ResumeThread on debug-stopped threads can deadlock the
        # target). Arming is deferred to the event loop: threads observed via
        # the snapshot are armed on the first idle timeout (by then the
        # initial breakpoint has been continued and they are running), and
        # newly created threads are armed on the next idle timeout as well.
        pending.update(_enum_thread_ids(k32, pid))

        deadline = start + duration
        ev = DEBUG_EVENT()
        while time.time() < deadline and len(hits) < max_hits:
            if not k32.WaitForDebugEvent(ev, 100):
                if int(k32.GetLastError()) == 121:  # ERROR_SEM_TIMEOUT: benign
                    if pending:  # idle: all events continued, threads running
                        for tid in sorted(pending):
                            _snapshot_thread_drs(k32, tid, ctx_cls, ctx_flags, originals, warnings)
                            _arm_thread(k32, tid, address, size, ctx_cls, ctx_flags, originals, warnings)
                            armed.add(tid)
                        pending.clear()
                    continue
                break
            code = int(ev.dwDebugEventCode)
            tid = int(ev.dwThreadId)
            try:
                if code == EXIT_PROCESS_DEBUG_EVENT:
                    break
                if code == CREATE_THREAD_DEBUG_EVENT:
                    # race handling: remember brand-new threads (they inherit
                    # DRs from the creator) and arm them on the next idle
                    # timeout -- never SuspendThread while an event is pending
                    pending.add(tid)
                    continue
                if code == EXCEPTION_DEBUG_EVENT:
                    rec = ev.u.Exception.ExceptionRecord
                    if int(rec.ExceptionCode) == EXCEPTION_SINGLE_STEP:
                        rip = 0
                        h_t = k32.OpenThread(THREAD_GET_CONTEXT, False, tid)
                        if h_t:
                            try:
                                ctx = ctx_cls()
                                ctx.ContextFlags = ctx_flags
                                if _get_context(k32, h_t, ctx):
                                    rip = rip_of(ctx)
                                    # confirm our slot fired (DR6 bit0 == DR0) when readable
                            finally:
                                k32.CloseHandle(h_t)
                        hits.append({"rip": hex(rip), "rip_addr": rip, "thread_id": tid, "ts": time.time()})
                        _disable_hit(k32, tid, ctx_cls, ctx_flags)
                    # swallow all other exceptions (DBG_CONTINUE)
            finally:
                k32.ContinueDebugEvent(int(ev.dwProcessId), tid, DBG_CONTINUE)
    finally:
        # Cleanup is mandatory on every exit path: restore DRs, then detach.
        # Re-enumerate so late-created threads (which inherited armed DRs
        # from their parent) are also cleaned; vanished threads are benign.
        restored = True
        seen: set[int] = set()
        for tid in _enum_thread_ids(k32, pid):
            seen.add(tid)
            orig = originals.get(tid, (0, 0))
            if _restore_thread(k32, tid, orig, ctx_cls, ctx_flags, warnings) is False:
                restored = False
        for tid in armed - seen:
            orig = originals.get(tid, (0, 0))
            if _restore_thread(k32, tid, orig, ctx_cls, ctx_flags, warnings) is False:
                restored = False
        if not k32.DebugActiveProcessStop(pid):
            restored = False
            warnings.append(f"DebugActiveProcessStop failed for pid {pid}")

    out = {
        "address": hex(address),
        "size": size,
        "hits": hits,
        "hit_count": len(hits),
        "duration_sampled": round(time.time() - start, 3),
        "restored": restored,
        "warning": "; ".join(warnings) if warnings else None,
    }
    return out

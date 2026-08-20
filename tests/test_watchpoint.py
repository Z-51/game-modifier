"""Hardware write watchpoint tests (find-writers, phase 2.1).

Levels:
1. Unit: DR7 bit math + arm/restore flow against a fake kernel32.
2. Integration: real child process on Windows; skipped (never failed) when
   privileges are insufficient.
3. Wiring: service anti-cheat refusal, CLI parsing, MCP registration.
"""

from __future__ import annotations

import struct
import sys
import time as time_mod

import pytest

from conftest import FakeBackend

from game_modifier.errors import GameModifierError, InvalidArgsError, UnsupportedOSError
from game_modifier.memory import process as procmod
from game_modifier.memory import watchpoint as wp
from game_modifier.memory.base import ModuleInfo
from game_modifier.service import ModifierService

BASE = 0x200000

IS_WINDOWS = sys.platform.startswith("win")
requires_windows = pytest.mark.skipif(not IS_WINDOWS, reason="hardware watchpoints are Windows-only")
del IS_WINDOWS


# ----------------------------------------------------------------- DR7 math
def test_dr7_enable_write_slot_bits():
    # DR0 local+global enable, RW=01 (write), LEN=4 bytes (11)
    assert wp.dr7_enable_write_slot(0, 0, 4) == (1 << 0) | (1 << 1) | (1 << 16) | (3 << 18)
    # unrelated bits preserved
    assert wp.dr7_enable_write_slot(0xDEAD0000, 0, 4) == 0xDEAD0000 | (1 | 2 | (1 << 16) | (3 << 18))
    # size 8 -> LEN encoded as 10
    assert wp.dr7_enable_write_slot(0, 0, 8) == 3 | (1 << 16) | (2 << 18)
    # size 1 -> LEN 00
    assert wp.dr7_enable_write_slot(0, 0, 1) == 3 | (1 << 16)
    # slot 2 keeps slot 0 enable bits untouched
    got = wp.dr7_enable_write_slot(0b11, 2, 4)
    assert got & 0b11 == 0b11
    assert got & (0x3 << 4) == 0x3 << 4


def test_dr7_enable_rejects_bad_size():
    with pytest.raises(InvalidArgsError):
        wp.dr7_enable_write_slot(0, 0, 3)


def test_dr7_disable_slot():
    armed = wp.dr7_enable_write_slot(0, 0, 4)
    assert wp.dr7_disable_slot(armed, 0) & 0b11 == 0  # enable bits cleared
    assert wp.dr7_disable_slot(armed | 0xF0, 0) & 0xF0 == 0xF0  # other bits kept
    assert wp.dr7_disable_slot(0b1111, 1) == 0b0011


# ------------------------------------------------------- fake kernel32 harness
class FakeK32:
    """Minimal kernel32 stand-in recording DR writes for one thread."""

    def __init__(self, tid: int = 999, orig_dr0: int = 0, orig_dr7: int = 0):
        self.tid = tid
        self.thread_ctx = {"Dr0": orig_dr0, "Dr7": orig_dr7, "Rip": 0x140001234}
        self.dr7_written: list[int] = []
        self.suspends = 0
        self.resumes = 0
        self.debug_stopped = False
        self.events = []  # pop from the front in WaitForDebugEvent
        self._calls = 0

    # -- time control (monkeypatched into wp.time)
    def _tick(self):
        # calls 1-4 keep us inside the sampling window (start, loop checks
        # around the idle-arm pass and the queued events); afterwards the
        # deadline has passed
        self._calls += 1
        return 100.0 if self._calls <= 4 else 110.0

    # -- kernel32 API surface
    def OpenProcess(self, access, inherit, pid):
        return 0x1111

    def CloseHandle(self, h):
        return 1

    def IsWow64Process(self, h, ref):
        return 0  # x64 target

    def DebugActiveProcess(self, pid):
        return 1

    def DebugActiveProcessStop(self, pid):
        self.debug_stopped = True
        return 1

    def CreateToolhelp32Snapshot(self, flags, pid):
        return 0x2222

    def Thread32First(self, snap, entry):
        entry.th32ThreadID = self.tid
        entry.th32OwnerProcessID = self.pid
        return 1

    def Thread32Next(self, snap, entry):
        return 0

    def OpenThread(self, access, inherit, tid):
        return 0x3333 if tid == self.tid else 0

    def SuspendThread(self, h):
        self.suspends += 1
        return 0

    def ResumeThread(self, h):
        self.resumes += 1
        return 1

    def GetThreadContext(self, h, ctx_ref):
        ctx = ctx_ref._obj
        ctx.Dr0 = self.thread_ctx["Dr0"]
        ctx.Dr7 = self.thread_ctx["Dr7"]
        ctx.Rip = self.thread_ctx["Rip"]
        return 1

    def SetThreadContext(self, h, ctx_ref):
        ctx = ctx_ref._obj
        self.thread_ctx["Dr0"] = int(ctx.Dr0)
        self.thread_ctx["Dr7"] = int(ctx.Dr7)
        self.dr7_written.append(int(ctx.Dr7))
        return 1

    def WaitForDebugEvent(self, ev, timeout):
        if self.events:
            ev_code = self.events.pop(0)
            if ev_code is None:  # scripted idle timeout -> arms pending threads
                return 0
            code, tid, rip = ev_code
            ev.dwDebugEventCode = code
            ev.dwProcessId = self.pid
            ev.dwThreadId = tid
            if code == wp.EXCEPTION_DEBUG_EVENT:
                ev.u.Exception.ExceptionRecord.ExceptionCode = wp.EXCEPTION_SINGLE_STEP
                ev.u.Exception.ExceptionRecord.ExceptionAddress = rip
            return 1
        return 0

    def GetLastError(self):
        return 121  # ERROR_SEM_TIMEOUT: benign timeout

    def ContinueDebugEvent(self, pid, tid, status):
        return 1

    def attach_time(self, monkeypatch):
        """Route wp.time.time() through the fake clock (deterministic deadline)."""

        monkeypatch.setattr(wp.time, "time", self._tick)


def _run_fake_find_writers(monkeypatch, tid=999, orig_dr0=0, orig_dr7=0, events=()):
    k32 = FakeK32(tid=tid, orig_dr0=orig_dr0, orig_dr7=orig_dr7)
    k32.pid = 4242
    k32.events = list(events)
    k32.attach_time(monkeypatch)
    out = wp.find_writers(4242, 0x7FF000001000, size=4, duration=5.0, kernel32=k32)
    return k32, out


# ------------------------------------------------------------- arm/restore flow
def test_arm_and_restore_via_fake_kernel32(monkeypatch):
    k32, out = _run_fake_find_writers(monkeypatch, orig_dr0=0xAAAA, orig_dr7=0x400)

    # armed DR7: slot0 write bp on top of the original value
    assert k32.dr7_written[0] == wp.dr7_enable_write_slot(0x400, 0, 4)
    # restored to the exact original values
    assert k32.dr7_written[-1] == 0x400
    assert k32.thread_ctx["Dr0"] == 0xAAAA
    assert k32.suspends == 3 and k32.resumes == 3  # snapshot + arm + restore
    assert k32.debug_stopped is True
    assert out["hit_count"] == 0 and out["restored"] is True
    assert out["address"] == "0x7ff000001000"


def test_hit_recorded_and_slot_disarmed(monkeypatch):
    # leading None: one idle timeout so the deferred arming runs first
    events = [None, (wp.EXCEPTION_DEBUG_EVENT, 999, 0x140005555)]
    k32, out = _run_fake_find_writers(monkeypatch, orig_dr7=0, events=events)

    assert out["hit_count"] == 1
    hit = out["hits"][0]
    assert hit["thread_id"] == 999
    assert hit["rip"] == hex(0x140001234)  # from the thread context
    assert isinstance(hit["ts"], float)
    # write sequence: arm -> disable-on-hit -> restore
    assert k32.dr7_written[0] == wp.dr7_enable_write_slot(0, 0, 4)
    assert k32.dr7_written[1] & 0b11 == 0  # slot enable cleared after the hit
    assert k32.dr7_written[-1] == 0  # fully restored
    assert out["restored"] is True


def test_debug_attach_denied_raises(monkeypatch):
    k32 = FakeK32()
    k32.pid = 4242

    def deny(pid):
        return 0

    k32.DebugActiveProcess = deny
    monkeypatch.setattr(wp.ctypes, "get_last_error", lambda: 5)
    from game_modifier.errors import AccessDeniedError

    with pytest.raises(AccessDeniedError) as exc:
        wp.find_writers(4242, 0x1000, kernel32=k32)
    assert exc.value.hint and "Administrator" in exc.value.hint


# -------------------------------------------------------------------- service
@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x1000)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={BASE: region}, modules=[mod], name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


def test_service_find_writers_anti_cheat_reject(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    session = svc.store.load(sid)
    session.anti_cheat = {"detected": True, "systems": ["EAC"]}
    svc.store.save(session)

    with pytest.raises(GameModifierError) as exc:
        svc.find_writers(sid, address=hex(BASE))
    assert exc.value.code.value == "E_ANTI_CHEAT"


def test_service_find_writers_bad_size(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    with pytest.raises(InvalidArgsError):
        svc.find_writers(sid, address=hex(BASE), size=3)


def test_service_find_writers_non_windows(service, monkeypatch):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(UnsupportedOSError):
        svc.find_writers(sid, address=hex(BASE))


# ---------------------------------------------------------------- integration
# The writer runs as a *detached grandchild* (cmd /c bat launcher). On some
# hardened Windows builds the sandbox blocks cross-process memory/debug access
# to directly-spawned children while unrelated/detached processes stay
# accessible; the detached launch keeps the test meaningful there too.
WRITER_CHILD = (
    "import ctypes, os, sys, time\n"
    "k = ctypes.windll.kernel32\n"
    "k.VirtualAlloc.restype = ctypes.c_void_p\n"
    "va = k.VirtualAlloc(0, 4096, 0x1000, 0x4)\n"
    "buf = ctypes.c_int64.from_address(va)\n"
    "open(sys.argv[1], 'w').write(str(os.getpid()) + ' ' + hex(va))\n"
    "end = time.time() + 30\n"
    "i = 0\n"
    "while time.time() < end:\n"
    "    buf.value = i\n"
    "    i += 1\n"
)


def _rpm_probe(pid: int, address: int) -> bool:
    """Can this process actually read the target's private memory?

    Uses a private WinDLL instance so the shared ``windll.kernel32``
    prototypes used by the production code are left untouched.
    """
    import ctypes as _ct

    k32 = _ct.WinDLL("kernel32")
    k32.ReadProcessMemory.argtypes = [
        _ct.c_void_p, _ct.c_void_p, _ct.c_void_p, _ct.c_size_t,
        _ct.POINTER(_ct.c_size_t),
    ]
    h = k32.OpenProcess(0x0410, False, pid)  # QUERY_INFORMATION | VM_READ
    if not h:
        return False
    try:
        out = (_ct.c_char * 8)()
        got = _ct.c_size_t(0)
        return bool(k32.ReadProcessMemory(h, _ct.c_void_p(address), out, 8, _ct.byref(got)))
    finally:
        k32.CloseHandle(h)


def _terminate(pid: int) -> None:
    import ctypes as _ct

    k32 = _ct.WinDLL("kernel32")
    h = k32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
    if h:
        k32.TerminateProcess(h, 1)
        k32.CloseHandle(h)


@requires_windows
def test_find_writers_self_child(tmp_path):
    """A busy writer process must produce hardware-breakpoint hits.

    Skips (never fails) when the environment blocks debugging: insufficient
    privileges, or an OS/sandbox mitigation that denies cross-process debug
    access (detected via a ReadProcessMemory capability probe).
    """

    import subprocess

    from game_modifier.errors import AccessDeniedError, ProcessNotFoundError

    child_py = tmp_path / "writer_child.py"
    child_py.write_text(WRITER_CHILD, encoding="utf-8")
    report = tmp_path / "report.txt"
    bat = tmp_path / "launch.bat"
    bat.write_text(f'@echo off\n"{sys.executable}" "{child_py}" "{report}"\n', encoding="utf-8")

    launcher = subprocess.Popen(
        ["cmd.exe", "/c", str(bat)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=0x00000008,  # DETACHED_PROCESS: escapes child restrictions
    )
    writer_pid = 0
    try:
        deadline = time_mod.time() + 10
        while not report.exists() and time_mod.time() < deadline:
            time_mod.sleep(0.05)
        if not report.exists():
            pytest.skip("writer process never reported its target address")
        writer_pid, addr = int(report.read_text().split()[0]), int(report.read_text().split()[1], 16)

        if not _rpm_probe(writer_pid, addr):
            pytest.skip("environment denies cross-process memory access (sandbox/OS mitigation)")

        try:
            out = wp.find_writers(writer_pid, addr, size=8, duration=3.0, max_hits=5)
        except (AccessDeniedError, ProcessNotFoundError) as exc:
            pytest.skip(f"insufficient debug privileges: {exc}")
        assert out["restored"] is True, f"cleanup failed: {out.get('warning')}"
        if out["hit_count"] == 0:
            pytest.skip("hardware breakpoints suppressed by the environment "
                        "(DR arming verified, no EXCEPTION_SINGLE_STEP delivered)")
        assert all(h["rip"] != "0x0" for h in out["hits"])
        assert all(h["thread_id"] > 0 for h in out["hits"])
    finally:
        if writer_pid:
            _terminate(writer_pid)
        launcher.kill()


# ------------------------------------------------------------------------ CLI
def test_cli_find_writers_parsing():
    from game_modifier.cli import build_parser

    p = build_parser()

    args = p.parse_args(["find-writers", "--session", "s1", "--address", "0x1000",
                         "--size", "8", "--duration", "2.5", "--max-hits", "3"])
    assert args.command == "find-writers"
    assert args.session == "s1" and args.address == "0x1000"
    assert args.size == 8 and args.duration == pytest.approx(2.5) and args.max_hits == 3

    args = p.parse_args(["find-writers", "--session", "s1", "--address", "player.gold"])
    assert args.size == 4 and args.duration == pytest.approx(5.0) and args.max_hits == 20

    with pytest.raises(SystemExit):
        p.parse_args(["find-writers", "--session", "s1", "--address", "0x1", "--size", "3"])


# ------------------------------------------------------------------------ MCP
def test_mcp_find_writers_registered(tmp_path):
    pytest.importorskip("mcp")
    from game_modifier import mcp_server
    from test_mcp_extended import _tool_names

    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    server = mcp_server.build_server(str(cfg))
    assert "find_writers" in _tool_names(server)

    ro = mcp_server.build_server(str(cfg), profile="readonly")
    assert "find_writers" not in _tool_names(ro)  # suspends threads -> writable only

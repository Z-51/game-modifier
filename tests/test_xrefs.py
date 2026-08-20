"""Tests for cross-reference queries (toolchain.radare2.xrefs_at / service.xrefs).

radare2 / r2pipe are optional dependencies and typically absent in CI, so all
backend interactions are mocked - no real binaries are analyzed.
"""

from __future__ import annotations

import json
import types

import pytest

from conftest import FakeBackend  # noqa: E402

from game_modifier import mcp_server  # noqa: E402
from game_modifier.cli import build_parser  # noqa: E402
from game_modifier.config import Config  # noqa: E402
from game_modifier.errors import InvalidArgsError, ToolNotFoundError  # noqa: E402
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory.base import ModuleInfo  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402
from game_modifier.toolchain import radare2 as r2mod  # noqa: E402
import game_modifier.toolchain as toolchain_pkg  # noqa: E402
from test_mcp_extended import _tool_names  # noqa: E402

MODULE_BASE = 0x140000000
MODULE_SIZE = 0x1000000


# ---------------------------------------------------------------- adapters
class FakeR2:
    """Stand-in for an r2pipe session object."""

    def __init__(self, xrefs_by_cmd: dict[str, list]):
        self.cmds: list[str] = []
        self.cmdj_calls: list[str] = []
        self._xrefs = xrefs_by_cmd
        self.quit_called = False

    def cmd(self, c: str):
        self.cmds.append(c)
        return ""

    def cmdj(self, c: str):
        self.cmdj_calls.append(c)
        # r2pipe.cmdj appends 'j' to the command, mirroring real behavior
        return self._xrefs.get(c)

    def quit(self):
        self.quit_called = True


def _install_fake_r2pipe(monkeypatch, fake: FakeR2):
    fake_mod = types.ModuleType("r2pipe")
    fake_mod.open = lambda path, flags=None: fake
    monkeypatch.setitem(__import__("sys").modules, "r2pipe", fake_mod)
    monkeypatch.setattr(r2mod, "have_r2pipe", lambda: True)


# ------------------------------------------------------------- 1. r2pipe path
def test_xrefs_r2pipe_mock(tmp_path, monkeypatch):
    binary = tmp_path / "game.exe"
    binary.write_bytes(b"MZ\x00\x00")
    fake = FakeR2({"axt 0x1000": [{"from": 0x1234, "to": 0x1000, "type": "CALL", "fcn": "main"}]})
    _install_fake_r2pipe(monkeypatch, fake)

    res = r2mod.xrefs_at(str(binary), 0x1000)
    assert res["backend"] == "r2pipe"
    assert res["address"] == "0x1000"
    assert res["direction"] == "to"
    assert res["count"] == 1
    assert res["xrefs"] == [{"from": "0x1234", "to": "0x1000", "type": "CALL", "fcn": "main"}]
    assert fake.quit_called
    assert any(c.startswith("af @ 0x1000") for c in fake.cmds)  # local analysis first


# ------------------------------------------------------- 2. subprocess fallback
def test_xrefs_subprocess_fallback_mock(tmp_path, monkeypatch):
    binary = tmp_path / "game.exe"
    binary.write_bytes(b"MZ\x00\x00")
    monkeypatch.setattr(r2mod, "have_r2pipe", lambda: False)

    captured: dict = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return types.SimpleNamespace(stdout=json.dumps(
            [{"from": 0x2000, "to": 0x1000, "type": "DATA", "fcn": None}]))

    monkeypatch.setattr(r2mod.subprocess, "run", fake_run)

    res = r2mod.xrefs_at(str(binary), 0x1000, direction="to", r2_path="/usr/bin/r2")
    assert res["backend"] == "subprocess"
    assert res["count"] == 1
    assert res["xrefs"][0]["from"] == "0x2000"
    assert res["xrefs"][0]["fcn"] is None
    assert captured["cmd"][0] == "/usr/bin/r2"
    assert "axtj 0x1000" in captured["cmd"][3]  # -c script uses the json form


# ------------------------------------------------------------ 3. no tool error
def test_xrefs_no_tool_raises(tmp_path, monkeypatch):
    binary = tmp_path / "game.exe"
    binary.write_bytes(b"MZ\x00\x00")
    monkeypatch.setattr(r2mod, "have_r2pipe", lambda: False)

    with pytest.raises(ToolNotFoundError) as ei:
        r2mod.xrefs_at(str(binary), 0x1000)
    assert ei.value.hint  # install hint present
    assert "radare2" in ei.value.hint


def test_xrefs_bad_direction(tmp_path, monkeypatch):
    binary = tmp_path / "game.exe"
    binary.write_bytes(b"MZ\x00\x00")
    monkeypatch.setattr(r2mod, "have_r2pipe", lambda: False)
    with pytest.raises(InvalidArgsError):
        r2mod.xrefs_at(str(binary), 0x1000, direction="sideways", r2_path="/usr/bin/r2")


# ------------------------------------------------------------ service fixture
@pytest.fixture
def xrefs_service(tmp_path, monkeypatch):
    cfg = Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": True,
                   "require_writable_region": True},
        "scan": {"max_results": 1000, "chunk_size": 4096, "alignment": 1, "max_region_bytes": 0},
        "output": {"format": "json"},
        "paths": {"home": str(tmp_path / ".game-modifier")},
        "tools": {"search_dirs": {"extra": []}},
    })
    fake = FakeBackend(
        regions={0x200000: b"\x90" * 16},
        modules=[ModuleInfo(name="GameAssembly.dll", base=MODULE_BASE,
                            size=MODULE_SIZE, path="C:/games/GameAssembly.dll")],
        arch="x64",
    )

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(cfg), fake


def _capture_xrefs(monkeypatch, svc):
    """Stub xrefs_at + toolchain detection; return the captured call kwargs."""
    calls: list[dict] = []

    def fake_xrefs_at(binary_path, address, *, direction="to", timeout=60.0, r2_path=None):
        calls.append({"binary": binary_path, "address": address,
                      "direction": direction, "r2_path": r2_path})
        return {"backend": "fake", "address": hex(address), "direction": direction,
                "xrefs": [], "count": 0}

    monkeypatch.setattr(r2mod, "xrefs_at", fake_xrefs_at)
    monkeypatch.setattr(toolchain_pkg, "detect_all", lambda cfg=None: {
        "available": ["radare2"],
        "tools": {"radare2": {"found": True, "path": "C:/r2/radare2.exe"}},
    })
    return calls


# --------------------------------------------------------- 4. RVA conversion
def test_xrefs_rva_conversion(xrefs_service, monkeypatch):
    svc, _ = xrefs_service
    calls = _capture_xrefs(monkeypatch, svc)
    sid = svc.attach(pid=4242)["session_id"]

    # absolute runtime address inside the module -> RVA
    res = svc.xrefs(session_id=sid, address=hex(MODULE_BASE + 0x1234))
    assert res["module"] == "GameAssembly.dll"
    assert res["rva"] == "0x1234"
    assert calls[-1]["address"] == 0x1234
    assert calls[-1]["binary"] == "C:/games/fake.exe"  # session exe default

    # module+0x.. expression -> direct RVA
    res = svc.xrefs(session_id=sid, address="GameAssembly.dll+0x2000")
    assert res["rva"] == "0x2000"
    assert calls[-1]["address"] == 0x2000

    # binary override is forwarded
    svc.xrefs(session_id=sid, address=hex(MODULE_BASE), binary="C:/custom/game.dll")
    assert calls[-1]["binary"] == "C:/custom/game.dll"
    assert calls[-1]["address"] == 0x0

    # unknown module name is rejected with a helpful error
    with pytest.raises(InvalidArgsError):
        svc.xrefs(session_id=sid, address="missing.dll+0x10")


# ----------------------------------------------------------- 5. direction param
def test_xrefs_direction_param(xrefs_service, monkeypatch):
    svc, _ = xrefs_service
    calls = _capture_xrefs(monkeypatch, svc)
    sid = svc.attach(pid=4242)["session_id"]

    res_to = svc.xrefs(session_id=sid, address=hex(MODULE_BASE + 0x10), direction="to")
    assert res_to["direction"] == "to"
    assert calls[-1]["direction"] == "to"

    res_from = svc.xrefs(session_id=sid, address=hex(MODULE_BASE + 0x10), direction="from")
    assert res_from["direction"] == "from"
    assert calls[-1]["direction"] == "from"

    # r2 executable path discovered by the toolchain is forwarded
    assert calls[-1]["r2_path"] == "C:/r2/radare2.exe"

    with pytest.raises(InvalidArgsError):
        svc.xrefs(session_id=sid, address=hex(MODULE_BASE + 0x10), direction="both")


def test_xrefs_service_falls_back_to_python_when_radare2_missing(xrefs_service, monkeypatch):
    """phase 3.4: radare2 unavailable -> automatic pure-Python memory fallback.

    The historical ToolNotFoundError propagation is preserved behind the
    ``fallback=False`` opt-out (see the next test); the default now answers
    with a live-memory pointer-slot scan instead of failing.
    """
    svc, _ = xrefs_service
    monkeypatch.setattr(toolchain_pkg, "detect_all", lambda cfg=None: {
        "available": [], "tools": {"radare2": {"found": False, "path": None}}})

    def raise_missing(*a, **kw):
        raise ToolNotFoundError("radare2 not available for xref analysis",
                                hint="Install radare2 and/or `pip install r2pipe`.")

    monkeypatch.setattr(r2mod, "xrefs_at", raise_missing)
    sid = svc.attach(pid=4242)["session_id"]
    res = svc.xrefs(session_id=sid, address=hex(MODULE_BASE + 0x10))
    assert res["backend"] == "python"
    assert res["backend_kind"] == "python"
    assert res["count"] == 0  # the 16-byte \x90 stub region holds no pointer slots
    assert res["xrefs"] == []
    assert res["aligned"] is True
    assert res["slot_sizes"] == [8, 4]
    assert "ToolNotFoundError" in res["fallback_reason"]
    assert res["module"] == "GameAssembly.dll"
    assert res["rva"] == "0x10"


def test_xrefs_service_fallback_opt_out_propagates_tool_not_found(xrefs_service, monkeypatch):
    """fallback=False restores the frozen pre-phase-3 propagation behavior."""
    svc, _ = xrefs_service
    monkeypatch.setattr(toolchain_pkg, "detect_all", lambda cfg=None: {
        "available": [], "tools": {"radare2": {"found": False, "path": None}}})

    def raise_missing(*a, **kw):
        raise ToolNotFoundError("radare2 not available for xref analysis",
                                hint="Install radare2 and/or `pip install r2pipe`.")

    monkeypatch.setattr(r2mod, "xrefs_at", raise_missing)
    sid = svc.attach(pid=4242)["session_id"]
    with pytest.raises(ToolNotFoundError):
        svc.xrefs(session_id=sid, address=hex(MODULE_BASE + 0x10), fallback=False)


# ------------------------------------------------------------------ 6. cli
def test_cli_xrefs_parsing():
    p = build_parser()
    args = p.parse_args(["xrefs", "--session", "s1", "--address", "0x1000",
                         "--direction", "from", "--binary", "c:/game.exe"])
    assert args.command == "xrefs"
    assert args.session == "s1"
    assert args.address == "0x1000"
    assert args.direction == "from"
    assert args.binary == "c:/game.exe"

    defaults = p.parse_args(["xrefs", "--session", "s1", "--address", "0x1000"])
    assert defaults.direction == "to"
    assert defaults.binary is None


# ------------------------------------------------------------------ 7. mcp
def test_mcp_xrefs_registered(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    server = mcp_server.build_server(str(cfg))
    names = _tool_names(server)
    assert "xrefs" in names

    ro = mcp_server.build_server(str(cfg), profile="readonly")
    ro_names = _tool_names(ro)
    assert "xrefs" in ro_names  # read-only tool -> included in readonly profile

"""il-tool subprocess bridge: protocol, failure modes, binary location, registry.

Tests use a Python-script stand-in for il-tool (``run_il_tool`` dispatches
``.py`` paths under the current interpreter, mirroring the ``.dll -> dotnet``
dispatch in ``engines.unity.run_dumper_cli``), so they never depend on the
real .NET binary. A final smoke test exercises the packaged real binary when
present (skipped otherwise).
"""

from __future__ import annotations

import pytest

from game_modifier import errors as err
from game_modifier.config import Config
from game_modifier.engines import il_tool as iltool
from game_modifier.errors import ErrorCode
from game_modifier.toolchain import registry


# ----------------------------------------------------------------- stub exe

STUB_SOURCE = '''\
import json
import sys
import time

line = sys.stdin.readline()
req = json.loads(line)
cmd = req.get("command", "")

def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\\n")
    sys.stdout.flush()

if cmd == "analyze":
    emit({"ok": True, "command": "analyze",
          "data": {"type_count": 2, "method_count": 5,
                   "echo_v": req.get("v"), "echo_assembly": req.get("assembly")}})
elif cmd == "failbiz":
    sys.stderr.write("il-tool: E_IL_METHOD_NOT_FOUND: nope\\n")
    emit({"ok": False, "command": "failbiz",
          "error": {"code": "E_IL_METHOD_NOT_FOUND", "message": "nope",
                    "details": {"method": "Ghost"}}})
elif cmd == "crash":
    sys.stderr.write("il-tool: fatal diagnostic text\\n")
    sys.exit(3)
elif cmd == "sleep":
    time.sleep(30)
    emit({"ok": True, "command": "sleep", "data": {}})
elif cmd == "badjson":
    sys.stdout.write("this is not json\\n")
    sys.stdout.flush()
else:
    emit({"ok": False, "command": cmd,
          "error": {"code": "E_IL_BAD_REQUEST", "message": "unknown"}})
sys.exit(0)
'''


@pytest.fixture
def stub_exe(tmp_path):
    """A Python script disguised as il-tool (speaks the real protocol)."""

    p = tmp_path / "il-tool-stub.py"
    p.write_text(STUB_SOURCE, encoding="utf-8")
    return p


@pytest.fixture
def stub_config(stub_exe, monkeypatch):
    """Resolution forced onto the stub: packaged tier patched away."""

    monkeypatch.setattr(iltool, "packaged_il_tool_path", lambda: None)
    return Config({"tools": {"il_tool": str(stub_exe), "search_dirs": {"extra": []}}})


# ------------------------------------------------------------------ protocol

def test_protocol_envelope(stub_config):
    res = iltool.run_il_tool(
        {"command": "analyze", "assembly": "C:/g/Assembly-CSharp.dll", "args": {}},
        config=stub_config,
    )

    assert res["ok"] is True
    assert res["command"] == "analyze"
    assert res["returncode"] == 0
    assert res["data"]["type_count"] == 2
    assert res["data"]["method_count"] == 5
    # protocol version v:1 is injected by the bridge and reached the child
    assert res["data"]["echo_v"] == 1
    assert res["data"]["echo_assembly"] == "C:/g/Assembly-CSharp.dll"
    assert "elapsed" in res


def test_protocol_business_error(stub_config):
    # ok:false envelopes are transport-successful (exit 0) and pass through
    res = iltool.run_il_tool({"command": "failbiz", "args": {}}, config=stub_config)

    assert res["ok"] is False
    assert res["returncode"] == 0  # envelope authoritative
    assert res["error"]["code"] == "E_IL_METHOD_NOT_FOUND"
    assert res["error"]["message"] == "nope"
    assert res["error"]["details"] == {"method": "Ghost"}
    assert "il-tool" in res["stderr_tail"]  # diagnostics captured, not parsed


def test_protocol_transport_failure(stub_config):
    # non-zero exit: envelope contract void -> synthetic transport error
    res = iltool.run_il_tool({"command": "crash", "args": {}}, config=stub_config)

    assert res["ok"] is False
    assert res["error"]["code"] == ErrorCode.TOOL_FAILED.value
    assert res["returncode"] == 3
    assert "fatal diagnostic text" in res["stderr_tail"]


def test_protocol_unparseable_envelope(stub_config):
    res = iltool.run_il_tool({"command": "badjson", "args": {}}, config=stub_config)

    assert res["ok"] is False
    assert res["error"]["code"] == ErrorCode.TOOL_FAILED.value
    assert "unparseable" in res["error"]["message"]
    assert "this is not json" in res["stdout_tail"]


def test_protocol_timeout(stub_config):
    res = iltool.run_il_tool({"command": "sleep", "args": {}}, config=stub_config, timeout=0.5)

    assert res["ok"] is False
    assert res["timeout"] is True
    assert res["returncode"] is None
    assert res["error"]["code"] == ErrorCode.TOOL_FAILED.value
    assert "timed out" in res["error"]["message"]
    assert res["hint"]


# -------------------------------------------------------------- binary lookup

def test_binary_missing(monkeypatch):
    monkeypatch.setattr(iltool, "packaged_il_tool_path", lambda: None)
    monkeypatch.setattr(registry, "find_tool", lambda spec, config=None: None)

    with pytest.raises(err.IlToolMissingError) as excinfo:
        iltool.run_il_tool({"command": "analyze", "args": {}}, config=None)

    exc = excinfo.value
    assert exc.code is ErrorCode.IL_TOOL_MISSING
    assert exc.hint and "build.ps1" in exc.hint
    assert exc.to_dict()["code"] == "E_IL_TOOL_MISSING"


def test_binary_location_order(tmp_path, monkeypatch):
    pkg_exe = tmp_path / "pkg" / "il-tool.exe"
    cfg_exe = tmp_path / "cfg" / "il-tool.exe"
    reg_exe = tmp_path / "reg" / "il-tool.exe"
    for p in (pkg_exe, cfg_exe, reg_exe):
        p.parent.mkdir(parents=True)
        p.write_text("x")

    monkeypatch.setattr(iltool, "packaged_il_tool_path", lambda: str(pkg_exe))
    monkeypatch.setattr(registry, "find_tool", lambda spec, config=None: str(reg_exe))
    cfg = Config({"tools": {"il_tool": str(cfg_exe), "search_dirs": {"extra": []}}})

    # tier 1: packaged wins over config and registry
    assert iltool.locate_il_tool(cfg) == str(pkg_exe)

    # tier 2: config override wins over registry
    monkeypatch.setattr(iltool, "packaged_il_tool_path", lambda: None)
    assert iltool.locate_il_tool(cfg) == str(cfg_exe)

    # tier 3: registry probe
    cfg_empty = Config({"tools": {"search_dirs": {"extra": []}}})
    assert iltool.locate_il_tool(cfg_empty) == str(reg_exe)

    # nothing anywhere -> None (run_il_tool turns this into E_IL_TOOL_MISSING)
    monkeypatch.setattr(registry, "find_tool", lambda spec, config=None: None)
    assert iltool.locate_il_tool(cfg_empty) is None


def test_registry_il_tool_dotnet(tmp_path, monkeypatch):
    names = {s.name for s in registry._specs()}
    assert "dotnet" in names
    assert "il_tool" in names

    # install hints registered for both specs
    for name in ("dotnet", "il_tool"):
        spec = next(s for s in registry._specs() if s.name == name)
        assert spec.install_hint

    # not-found path: hint surfaced, found=False (block PATH lookups)
    monkeypatch.setattr(registry.shutil, "which", lambda exe: None)
    cfg_empty = Config({"tools": {"search_dirs": {"extra": []}}})
    for name in ("dotnet", "il_tool"):
        res = registry.detect_tool(name, cfg_empty)
        assert res["found"] is False
        assert res["hint"]

    # explicit config override is detected
    fake = tmp_path / "il-tool.exe"
    fake.write_text("x")
    cfg = Config({"tools": {"il_tool": str(fake), "search_dirs": {"extra": []}}})
    res = registry.detect_tool("il_tool", cfg)
    assert res["found"] is True and res["path"] == str(fake)

    # live dotnet probe is environment-dependent; only assert the structure
    live = registry.detect_tool("dotnet")
    assert live["name"] == "dotnet"
    assert isinstance(live["found"], bool)


def test_error_codes_exist():
    assert ErrorCode.IL_TOOL_MISSING == "E_IL_TOOL_MISSING"
    assert ErrorCode.IL_PATCH_FAILED == "E_IL_PATCH_FAILED"
    assert ErrorCode.IL_VERIFY_FAILED == "E_IL_VERIFY_FAILED"

    # subclasses default to their codes and ship actionable hints
    for cls, code in [
        (err.IlToolMissingError, ErrorCode.IL_TOOL_MISSING),
        (err.IlPatchFailedError, ErrorCode.IL_PATCH_FAILED),
        (err.IlVerifyFailedError, ErrorCode.IL_VERIFY_FAILED),
    ]:
        exc = cls("boom")
        assert exc.code is code
        assert exc.hint and exc.hint.strip()

    # IlToolMissingError stays catchable as the generic tool-not-found family
    assert issubclass(err.IlToolMissingError, err.ToolNotFoundError)


# ------------------------------------------- real binary smoke (when present)

@pytest.mark.skipif(
    iltool.packaged_il_tool_path() is None,
    reason="packaged il-tool.exe not built (run iltool/build.ps1)",
)
def test_real_binary_protocol_smoke(tmp_path):
    """End-to-end against the compiled il-tool: business error envelope."""

    monkey_cfg = Config({"tools": {"search_dirs": {"extra": []}}})
    res = iltool.run_il_tool(
        {"command": "analyze", "assembly": str(tmp_path / "missing.dll"), "args": {}},
        config=monkey_cfg,
    )

    assert res["returncode"] == 0  # envelope authoritative
    assert res["ok"] is False
    assert res["error"]["code"] == "E_IL_ASSEMBLY_NOT_FOUND"
    assert res["error"]["details"]["assembly"].endswith("missing.dll")

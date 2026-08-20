"""Multi-level safety profiles + runtime safety level (Task #51).

Covers: readonly regression, dry-run/symbols/limited profile tool sets and
guard behavior, invalid profiles, the runtime safety level front gates on
modify/nl/batch_run, CLI parsing and MCP safety tool registration.
"""

from __future__ import annotations

import struct

import pytest

from game_modifier import cli as climod
from game_modifier.errors import ErrorCode, GameModifierError, InvalidArgsError
from game_modifier.service import ModifierService

# the mcp package is optional; skip this whole module when absent
pytest.importorskip("mcp")

from game_modifier import mcp_server  # noqa: E402
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory.base import ModuleInfo  # noqa: E402


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x1000)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={0x200000: region}, modules=[mod], name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


@pytest.fixture
def mcp_config_path(tmp_path):
    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    return str(cfg)


def _tool_names(server) -> set[str]:
    tm = getattr(server, "_tool_manager", None)
    if tm is not None and hasattr(tm, "_tools"):
        return set(tm._tools.keys())
    import asyncio

    return {t.name for t in asyncio.run(server.list_tools())}


# historical readonly gating anchors (must keep working unchanged)
WRITE_TOOLS = {"modify", "nl", "name_set", "template_apply", "batch_run", "freeze_start",
               "freeze_stop", "watch_start", "watch_stop", "backup_create", "backup_restore",
               "save_edit_modify", "detach"}

READONLY_EXPECTED = {"attach", "analyze", "scan", "scan_next", "scan_aob", "read", "resolve",
                     "name_get", "session_info", "sessions", "session_survey", "value_convert",
                     "toolchain_detect", "layout_analyze", "heap_scan", "pointer_scan",
                     "backup_list", "freeze_list", "audit_tail", "template_list",
                     "template_show", "save_edit_detect",
                     "watch_run", "watch_report",
                     "ue_introspect", "ue_actors", "ue_fname", "disasm", "xrefs"}


# ---------------------------------------------------------------------------
# 1. profiles: tool registration
# ---------------------------------------------------------------------------

def test_profile_readonly_unchanged(mcp_config_path):
    """readonly keeps its historical behavior (regression anchor)."""
    server = mcp_server.build_server(mcp_config_path, profile="readonly")
    names = _tool_names(server)
    assert not (names & WRITE_TOOLS)
    assert READONLY_EXPECTED <= names
    # the new read-only safety inspector is available; the switch itself is not
    assert "safety_get_level" in names
    assert "safety_set_level" not in names


def test_profile_symbols_tools(mcp_config_path):
    server = mcp_server.build_server(mcp_config_path, profile="symbols")
    names = _tool_names(server)
    assert READONLY_EXPECTED <= names
    assert {"name_set", "name_chain", "name_clear_temp",
            "session_snapshot", "session_restore",
            "macro_define", "macro_delete"} <= names
    # memory/bulk write tools stay excluded
    assert "modify" not in names
    assert "nl" not in names
    assert "batch_run" not in names
    assert "macro_run" not in names
    assert "template_apply" not in names
    assert "freeze_start" not in names
    assert "save_edit_modify" not in names


def test_profile_limited_tools(mcp_config_path):
    server = mcp_server.build_server(mcp_config_path, profile="limited")
    names = _tool_names(server)
    assert READONLY_EXPECTED <= names
    assert {"modify", "nl", "name_set", "name_chain", "name_clear_temp"} <= names
    # bulk/batch write tools stay excluded
    assert "batch_run" not in names
    assert "template_apply" not in names
    assert "freeze_start" not in names
    assert "save_edit_modify" not in names
    assert "macro_run" not in names


def test_profile_dryrun_registers_write_tools(mcp_config_path):
    server = mcp_server.build_server(mcp_config_path, profile="dry-run")
    names = _tool_names(server)
    assert READONLY_EXPECTED <= names
    # write tools stay registered (they are guarded at call time instead)
    assert {"modify", "nl", "template_apply", "batch_run",
            "save_edit_modify", "macro_run"} <= names


def test_profile_invalid(mcp_config_path):
    with pytest.raises(ValueError):
        mcp_server.build_server(mcp_config_path, profile="dangerous")


def test_profile_invalid_argparse():
    with pytest.raises(SystemExit):
        mcp_server.main(["--profile", "dangerous"])


# ---------------------------------------------------------------------------
# 2. profiles: dry-run guard behavior
# ---------------------------------------------------------------------------

def _service_fn(server, tool_name):
    """Return a callable yielding the tool's JSON envelope.

    FastMCP wraps registered functions (the raw result becomes a TextContent
    payload), so non-dict returns are unpacked from the content list.
    """

    import json as _json

    tool = server._tool_manager._tools[tool_name]
    raw = getattr(tool, "fn", None) or getattr(tool, "func")

    def call(**kwargs):
        out = raw(**kwargs)
        if isinstance(out, dict):
            return out
        item = out[0]
        text = getattr(item, "text", item if isinstance(item, str) else None)
        return _json.loads(text)

    return call


def test_profile_dryrun_blocks_confirm(mcp_config_path):
    server = mcp_server.build_server(mcp_config_path, profile="dry-run")
    modify = _service_fn(server, "modify")
    env = modify(session="s1", value="1", address="0x200000", confirm=True)
    assert env["ok"] is False
    assert env["error"]["code"] == "E_PROFILE_RESTRICTED"
    assert "dry-run" in env["error"]["message"]
    assert env["error"].get("hint")


def test_profile_dryrun_allows_preview(service, mcp_config_path, monkeypatch):
    """confirm=False previews run normally through the guard."""
    svc, _fake = service
    sid = svc.attach(pid=4242)["session_id"]

    # point the server's service at the same session store (same config home)
    import game_modifier.mcp_server as ms

    monkeypatch.setattr(ms, "load_config", lambda path=None: svc.config)
    server = mcp_server.build_server(mcp_config_path, profile="dry-run")
    modify = _service_fn(server, "modify")
    env = modify(session=sid, value="111", address="0x200000", type="int32", confirm=False)
    assert env["ok"] is True
    # dry-run preview: nothing applied
    assert env["data"].get("applied") is False
    # the fake memory is untouched
    assert _fake.read(0x200000, 4) == struct.pack("<i", 1000)

    # and a confirm=True call is still refused on the same server
    env2 = modify(session=sid, value="222", address="0x200000", type="int32", confirm=True)
    assert env2["ok"] is False
    assert env2["error"]["code"] == "E_PROFILE_RESTRICTED"


# ---------------------------------------------------------------------------
# 3. runtime safety level (service front gates)
# ---------------------------------------------------------------------------

def test_runtime_level_get_default(service):
    svc, _ = service
    out = svc.safety_get_level()
    assert out == {"level": "normal", "source": "default"}


def test_runtime_level_dry_run_only(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.safety_set_level(level="dry_run_only")
    assert out["level"] == "dry_run_only"
    assert svc.safety_get_level() == {"level": "dry_run_only", "source": "runtime"}

    with pytest.raises(GameModifierError) as ei:
        svc.modify(session_id=sid, address="0x200000", type="int32", value="111", confirm=True)
    assert ei.value.code == ErrorCode.PROFILE_RESTRICTED
    assert ei.value.hint  # actionable hint present
    # nothing was written
    assert fake.read(0x200000, 4) == struct.pack("<i", 1000)

    # nl entry point carries the same gate
    with pytest.raises(GameModifierError) as ei2:
        svc.nl(session_id=sid, text="将金币设为9999", confirm=True)
    assert ei2.value.code == ErrorCode.PROFILE_RESTRICTED


def test_runtime_level_allows_preview(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.safety_set_level(level="dry_run_only")

    res = svc.modify(session_id=sid, address="0x200000", type="int32", value="111", confirm=False)
    assert res.get("applied") is False
    assert fake.read(0x200000, 4) == struct.pack("<i", 1000)


def test_runtime_level_restore_normal(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.safety_set_level(level="dry_run_only")
    out = svc.safety_set_level(level="normal")
    assert out["level"] == "normal" and out["previous"] == "dry_run_only"
    assert svc.safety_get_level() == {"level": "normal", "source": "default"}

    # confirmed writes work again
    svc.modify(session_id=sid, address="0x200000", type="int32", value="111", confirm=True)
    assert fake.read(0x200000, 4) == struct.pack("<i", 111)


def test_runtime_level_invalid(service):
    svc, _ = service
    with pytest.raises(InvalidArgsError):
        svc.safety_set_level(level="yolo")
    # state unchanged
    assert svc.safety_get_level()["level"] == "normal"


def test_runtime_level_batch_gate(service, tmp_path):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    batch = tmp_path / "ops.yaml"
    batch.write_text(
        "operations:\n"
        '  - modify: {address: "0x200000", type: int32, value: 111}\n',
        encoding="utf-8")

    svc.safety_set_level(level="dry_run_only")
    with pytest.raises(GameModifierError) as ei:
        svc.batch_run(session_id=sid, path=str(batch), confirm=True)
    assert ei.value.code == ErrorCode.PROFILE_RESTRICTED
    assert fake.read(0x200000, 4) == struct.pack("<i", 1000)

    # preview batch (confirm=False) is not gated
    summary = svc.batch_run(session_id=sid, path=str(batch), confirm=False)
    assert summary["error_count"] == 0
    assert fake.read(0x200000, 4) == struct.pack("<i", 1000)

    # back to normal the same batch applies
    svc.safety_set_level(level="normal")
    summary = svc.batch_run(session_id=sid, path=str(batch), confirm=True)
    assert summary["ok_count"] == 1
    assert fake.read(0x200000, 4) == struct.pack("<i", 111)


# ---------------------------------------------------------------------------
# 4. CLI
# ---------------------------------------------------------------------------

def test_cli_safety_parsing():
    p = climod.build_parser()

    args = p.parse_args(["safety", "level"])
    assert args.command == "safety" and args.safety_action == "level"
    assert args.set_level is None

    args = p.parse_args(["safety", "level", "--set", "dry_run_only"])
    assert args.set_level == "dry_run_only"

    args = p.parse_args(["safety", "level", "--set", "normal"])
    assert args.set_level == "normal"

    with pytest.raises(SystemExit):
        p.parse_args(["safety", "level", "--set", "chaos"])


def test_cli_safety_dispatch(service):
    svc, _ = service
    res = climod.dispatch(svc, climod.build_parser().parse_args(["safety", "level"]))
    assert res.ok and res.data == {"level": "normal", "source": "default"}

    res = climod.dispatch(svc, climod.build_parser().parse_args(["safety", "level", "--set", "dry_run_only"]))
    assert res.ok and res.data["level"] == "dry_run_only"
    assert svc.safety_get_level()["level"] == "dry_run_only"


# ---------------------------------------------------------------------------
# 5. MCP safety tools registration
# ---------------------------------------------------------------------------

def test_mcp_safety_tools_registered(mcp_config_path):
    default = _tool_names(mcp_server.build_server(mcp_config_path))
    assert {"safety_get_level", "safety_set_level"} <= default

    for prof in ("dry-run", "symbols", "limited"):
        names = _tool_names(mcp_server.build_server(mcp_config_path, profile=prof))
        assert "safety_get_level" in names      # read-only inspector everywhere
        assert "safety_set_level" not in names  # switching is writable-only


def test_mcp_safety_tools_group_catalog():
    assert "safety" in mcp_server.TOOL_GROUPS
    assert set(mcp_server.TOOL_GROUPS["safety"]) == {
        "safety_get_level", "safety_set_level",
        # phase 2 registration: file-level snapshot/restore live in the
        # safety group (both are write tools, see WRITE_TOOLS)
        "file_snapshot", "file_restore",
    }

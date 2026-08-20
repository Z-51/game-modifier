"""Phase-5 MCP integration upgrades (ida-pro-mcp patterns).

Covers: value_convert, output throttling, session_survey, audit log/tail,
readonly profile tool gating and batch per-item error normalisation.
"""

from __future__ import annotations

import json
import struct

import pytest

# the mcp package is optional; skip this whole module when absent
pytest.importorskip("mcp")

from game_modifier import mcp_server  # noqa: E402
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory.base import ModuleInfo  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402


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


# ---------------------------------------------------------------------------
# 5.2 value_convert
# ---------------------------------------------------------------------------

def test_value_convert_int():
    out = mcp_server.convert_value("42")
    assert out["as_type"] == "int32"
    assert out["decimal"] == 42
    assert out["hex"] == "0x2a"
    assert out["bytes_le"] == "2a000000"
    assert out["bytes_be"] == "0000002a"


def test_value_convert_hex():
    out = mcp_server.convert_value("0x2A")
    assert out["decimal"] == 42
    assert out["bytes_le"] == "2a000000"


def test_value_convert_float():
    out = mcp_server.convert_value("1.0", as_type="float32")
    assert out["bytes_le"] == "0000803f"
    assert out["float_bits"] == "0x3f800000"
    assert struct.unpack("<f", bytes.fromhex(out["bytes_le"]))[0] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# 5.1 output throttling
# ---------------------------------------------------------------------------

def test_truncate_output():
    huge = {"ok": True, "command": "scan", "data": {"addresses_hex": [hex(0x400000 + i) for i in range(200000)]}}
    assert len(json.dumps(huge)) > mcp_server.MAX_OUTPUT_CHARS

    out = mcp_server._truncate_output(huge)
    data = out["data"]
    assert len(json.dumps(out)) <= mcp_server.MAX_OUTPUT_CHARS
    assert data["totals"]["addresses_hex"] == 200000  # original total preserved
    assert len(data["addresses_hex"]) < 200000
    assert "preview_note" in data


def test_truncate_output_small_passthrough():
    small = {"ok": True, "command": "scan", "data": {"addresses_hex": ["0x1", "0x2"]}}
    assert mcp_server._truncate_output(small) == small


# ---------------------------------------------------------------------------
# 5.3 session_survey
# ---------------------------------------------------------------------------

def test_session_survey(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.gold", base_expr="0x200000", type="int32")

    survey = svc.session_survey(session_id=sid)
    for key in ("session_id", "summary", "engine", "anti_cheat", "alive", "module_count",
                "modules_top", "symbols", "freezes", "backups", "scan", "save_edit",
                "toolchain_available"):
        assert key in survey
    assert survey["session_id"] == sid
    assert survey["alive"] is True
    assert survey["symbols"] == ["player.gold"]
    assert survey["modules_top"] and survey["modules_top"][0]["name"] == "fake.exe"
    assert survey["backups"] == []


# ---------------------------------------------------------------------------
# 5.4 audit log
# ---------------------------------------------------------------------------

def test_audit_log_written(service, tmp_config):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    res = svc.modify(session_id=sid, address="0x200000", type="int32", value="9999", confirm=True)
    assert res["applied"] is True

    path = tmp_config.sessions_dir / sid / "audit.jsonl"
    assert path.exists()
    lines = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    entry = lines[0]
    assert entry["op"] == "modify"
    assert entry["ok"] is True
    assert entry["backup_id"] == res["backup_id"]
    assert "ts" in entry and "args" in entry


def test_audit_log_not_written_on_dry_run(service, tmp_config):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.modify(session_id=sid, address="0x200000", type="int32", value="9999", confirm=False)
    assert not (tmp_config.sessions_dir / sid / "audit.jsonl").exists()


def test_audit_tail(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.modify(session_id=sid, address="0x200000", type="int32", value="111", confirm=True)
    svc.modify(session_id=sid, address="0x200000", type="int32", value="222", confirm=True)

    tail = svc.audit_tail(session_id=sid, limit=50)
    assert tail["count"] == 2
    assert [e["args"]["value"] for e in tail["entries"]] == ["111", "222"]

    limited = svc.audit_tail(session_id=sid, limit=1)
    assert limited["count"] == 2
    assert len(limited["entries"]) == 1
    assert limited["entries"][0]["args"]["value"] == "222"  # newest last


# ---------------------------------------------------------------------------
# 5.5 profiles
# ---------------------------------------------------------------------------

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


def test_readonly_profile_excludes_write_tools(mcp_config_path):
    server = mcp_server.build_server(mcp_config_path, profile="readonly")
    names = _tool_names(server)
    assert not (names & WRITE_TOOLS)
    assert READONLY_EXPECTED <= names


def test_default_profile_includes_all(mcp_config_path):
    server = mcp_server.build_server(mcp_config_path)  # default profile
    names = _tool_names(server)
    assert WRITE_TOOLS <= names
    assert READONLY_EXPECTED <= names


def test_unknown_profile_rejected(mcp_config_path):
    with pytest.raises(ValueError):
        mcp_server.build_server(mcp_config_path, profile="dangerous")


# ---------------------------------------------------------------------------
# 5.6 batch per-item errors
# ---------------------------------------------------------------------------

def test_batch_run_item_errors(service, tmp_path):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    batch = tmp_path / "ops.yaml"
    batch.write_text(
        "operations:\n"
        '  - modify: {address: "0x200000", type: int32, value: 111}\n'
        "  - modify: {value: 2}\n"  # no symbol/address -> E_INVALID_ARGS
        , encoding="utf-8")

    summary = svc.batch_run(session_id=sid, path=str(batch), confirm=True, stop_on_error=False)
    assert summary["ok_count"] == 1
    assert summary["error_count"] == 1
    assert summary["stopped_early"] is False

    first, second = summary["results"]
    for item in (first, second):
        assert item["op"] == "modify"
        assert "ok" in item and "error_code" in item
    assert first["ok"] is True and first["error_code"] is None
    assert second["ok"] is False and second["error_code"] == "E_INVALID_ARGS"
    assert struct.unpack("<i", fake.read(0x200000, 4))[0] == 111

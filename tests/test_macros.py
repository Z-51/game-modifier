"""Task #48 - reusable macro system (parameterized operation sequences).

Covers: SessionStore macro persistence, service macro_define/list/show/run/
delete, ${param} substitution semantics, confirm gating, results persistence,
CLI parser wiring and MCP tool registration (readonly vs writable profiles).
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
import yaml

from game_modifier import cli as climod
from game_modifier.errors import ErrorCode, GameModifierError
from game_modifier.memory import process as procmod
from game_modifier.memory.base import ModuleInfo
from game_modifier.service import ModifierService

BASE = 0x200000


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    # three int32 values: 111 @ BASE, 222 @ BASE+4, 333 @ BASE+8
    region = bytearray(struct.pack("<iii", 111, 222, 333) + b"\x00" * 0x100)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={BASE: region}, modules=[mod], name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


@pytest.fixture
def sid(service):
    svc, _ = service
    return svc.attach(pid=4242)["session_id"]


READ_MACRO = {
    "description": "read two neighbouring values",
    "params": {
        "addr": {"description": "base address", "required": True},
        "off": {"description": "second offset", "default": "0x4"},
    },
    "operations": [
        {"read": {"address": "${addr}", "type": "int32"}},
        {"read": {"address": "${addr}+${off}", "type": "int32"}},
    ],
}


def _define_read_macro(svc, sid, name="read_vals"):
    return svc.macro_define(session_id=sid, name=name, definition=READ_MACRO)


# ---------------------------------------------------------------------------
# store + define
# ---------------------------------------------------------------------------

def test_macro_define_store(service, sid, tmp_config):
    svc, _ = service
    res = _define_read_macro(svc, sid)

    path = tmp_config.sessions_dir / sid / "macros" / "read_vals.yaml"
    assert res["path"] == str(path)
    assert path.exists()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["name"] == "read_vals"
    assert data["params"]["addr"]["required"] is True
    assert data["params"]["off"]["default"] == "0x4"
    assert len(data["operations"]) == 2
    assert res["params"] == ["addr", "off"]
    assert res["operations"] == 2


def test_macro_define_accepts_yaml_string(service, sid):
    svc, _ = service
    inline = (
        "params:\n"
        "  addr: {required: true}\n"
        "operations:\n"
        '  - read: {address: "${addr}", type: int32}\n'
    )
    res = svc.macro_define(session_id=sid, name="inline_macro", definition=inline,
                           description="from a string")
    assert res["name"] == "inline_macro"
    assert res["description"] == "from a string"


def test_macro_define_invalid_ops(service, sid):
    svc, _ = service
    bad = {"operations": [{"frobnicate": {"address": "0x200000"}}]}
    with pytest.raises(GameModifierError) as ei:
        svc.macro_define(session_id=sid, name="bad", definition=bad)
    assert ei.value.code == ErrorCode.INVALID_ARGS

    with pytest.raises(GameModifierError) as ei2:
        svc.macro_define(session_id=sid, name="empty", definition={"operations": []})
    assert ei2.value.code == ErrorCode.INVALID_ARGS


# ---------------------------------------------------------------------------
# list / show
# ---------------------------------------------------------------------------

def test_macro_list_show(service, sid):
    svc, _ = service
    assert svc.macro_list(session_id=sid) == {"session_id": sid, "count": 0, "macros": []}

    _define_read_macro(svc, sid)
    listing = svc.macro_list(session_id=sid)
    assert listing["count"] == 1
    entry = listing["macros"][0]
    assert entry["name"] == "read_vals"
    assert entry["params"] == ["addr", "off"]
    assert entry["operations"] == 2
    assert entry["description"] == "read two neighbouring values"

    shown = svc.macro_show(session_id=sid, name="read_vals")
    assert shown["definition"]["operations"] == READ_MACRO["operations"]

    with pytest.raises(GameModifierError) as ei:
        svc.macro_show(session_id=sid, name="nope")
    assert ei.value.code == ErrorCode.INVALID_ARGS
    assert ei.value.details["known"] == ["read_vals"]


# ---------------------------------------------------------------------------
# run: substitution / defaults / missing params / confirm / persistence
# ---------------------------------------------------------------------------

def test_macro_run_param_substitution(service, sid):
    svc, fake = service
    _define_read_macro(svc, sid)

    summary = svc.macro_run(session_id=sid, name="read_vals",
                            params={"addr": "0x200000", "off": "0x8"})
    assert summary["ok_count"] == 2
    assert summary["error_count"] == 0
    assert summary["macro"] == "read_vals"
    assert summary["macro_params"] == {"addr": "0x200000", "off": "0x8"}

    first, second = summary["results"]
    assert first["ok"] is True and first["value"] == 111
    assert first["address_hex"] == "0x200000"
    assert second["ok"] is True and second["value"] == 333
    assert second["address_hex"] == "0x200008"


def test_macro_run_missing_param(service, sid):
    svc, _ = service
    _define_read_macro(svc, sid)

    with pytest.raises(GameModifierError) as ei:
        svc.macro_run(session_id=sid, name="read_vals")
    exc = ei.value
    assert exc.code == ErrorCode.INVALID_ARGS
    assert exc.details["missing"] == ["addr"]
    assert "addr" in str(exc)


def test_macro_run_default_param(service, sid):
    svc, _ = service
    _define_read_macro(svc, sid)

    # 'off' falls back to its declared default ("0x4")
    summary = svc.macro_run(session_id=sid, name="read_vals", params={"addr": "0x200000"})
    assert summary["ok_count"] == 2
    assert summary["results"][1]["value"] == 222
    assert summary["results"][1]["address_hex"] == "0x200004"


def test_macro_run_unknown_placeholder(service, sid):
    svc, _ = service
    svc.macro_define(session_id=sid, name="loose", definition={
        "operations": [{"read": {"address": "${never_declared}", "type": "int32"}}],
    })
    with pytest.raises(GameModifierError) as ei:
        svc.macro_run(session_id=sid, name="loose")
    assert ei.value.code == ErrorCode.INVALID_ARGS
    assert ei.value.details["missing"] == ["never_declared"]


def test_macro_run_confirm_gate(service, sid):
    svc, fake = service
    svc.macro_define(session_id=sid, name="set_val", definition={
        "params": {"val": {"required": True}},
        "operations": [
            {"modify": {"address": "0x200000", "type": "int32", "value": "${val}"}},
        ],
    })

    # no confirm -> dry-run, memory untouched
    dry = svc.macro_run(session_id=sid, name="set_val", params={"val": 777}, confirm=False)
    assert dry["ok_count"] == 1
    assert dry["confirm"] is False
    assert dry["results"][0]["applied"] is False
    assert dry["results"][0]["dry_run"] is True
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 111

    # confirm -> real write
    wet = svc.macro_run(session_id=sid, name="set_val", params={"val": 777}, confirm=True)
    assert wet["confirm"] is True
    assert wet["results"][0]["applied"] is True
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 777


def test_macro_run_results_file(service, sid, tmp_config):
    svc, _ = service
    _define_read_macro(svc, sid)

    summary = svc.macro_run(session_id=sid, name="read_vals", params={"addr": "0x200000"})
    results_file = summary["results_file"]
    assert results_file
    assert Path(results_file).exists()
    full = json.loads(Path(results_file).read_text(encoding="utf-8"))
    assert full["results_total"] == 2
    assert full["macro"] == "read_vals"
    # persistence lives under the session's batch_results dir (shared with batch_run)
    assert str(tmp_config.sessions_dir / sid / "batch_results") in results_file


def test_macro_delete(service, sid):
    svc, _ = service
    _define_read_macro(svc, sid)

    res = svc.macro_delete(session_id=sid, name="read_vals")
    assert res["deleted"] is True
    assert res["known"] == []
    assert svc.macro_list(session_id=sid)["count"] == 0

    again = svc.macro_delete(session_id=sid, name="read_vals")
    assert again["deleted"] is False


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

def test_cli_macro_parsing(tmp_path):
    parser = climod.build_parser()

    mfile = tmp_path / "m.yaml"
    mfile.write_text("operations:\n  - read: {address: '0x1'}\n", encoding="utf-8")

    a = parser.parse_args(["macro", "define", "read_vals", "--session", "s1", "--file", str(mfile)])
    assert (a.command, a.macro_action, a.name, a.session, a.file) == ("macro", "define", "read_vals", "s1", str(mfile))

    b = parser.parse_args(["macro", "define", "m2", "--session", "s1", "--inline", "operations: []",
                           "--description", "desc"])
    assert b.inline == "operations: []" and b.description == "desc"

    c = parser.parse_args(["macro", "list", "--session", "s1"])
    assert (c.command, c.macro_action) == ("macro", "list")

    d = parser.parse_args(["macro", "show", "read_vals", "--session", "s1"])
    assert (d.macro_action, d.name) == ("show", "read_vals")

    e = parser.parse_args(["macro", "run", "read_vals", "--session", "s1",
                           "--params", "base=0x100,count=5", "--confirm", "--no-stop-on-error"])
    assert e.params == "base=0x100,count=5"
    assert e.confirm is True and e.stop_on_error is False

    f = parser.parse_args(["macro", "run", "read_vals", "--session", "s1"])
    assert f.stop_on_error is True and f.confirm is False

    g = parser.parse_args(["macro", "delete", "read_vals", "--session", "s1"])
    assert (g.macro_action, g.name) == ("delete", "read_vals")

    # --params parsing: YAML scalars typed, strings preserved
    parsed = climod._parse_macro_params("count=5,base=0x200000,label=abc,flag=true")
    assert parsed["count"] == 5
    assert parsed["label"] == "abc"
    assert parsed["flag"] is True
    assert parsed["base"] in ("0x200000", 0x200000)  # YAML may type hex as int


# ---------------------------------------------------------------------------
# MCP registration
# ---------------------------------------------------------------------------

def test_mcp_macro_registered(tmp_path):
    pytest.importorskip("mcp")
    from game_modifier import mcp_server

    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    def _names(server) -> set[str]:
        tm = getattr(server, "_tool_manager", None)
        if tm is not None and hasattr(tm, "_tools"):
            return set(tm._tools.keys())
        import asyncio
        return {t.name for t in asyncio.run(server.list_tools())}

    readonly = _names(mcp_server.build_server(str(cfg), profile="readonly"))
    assert {"macro_list", "macro_show"} <= readonly                      # read-only tools present
    assert not ({"macro_define", "macro_run", "macro_delete"} & readonly)  # write tools gated

    default = _names(mcp_server.build_server(str(cfg)))
    assert {"macro_list", "macro_show", "macro_define", "macro_run", "macro_delete"} <= default

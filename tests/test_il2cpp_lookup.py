"""Tests for Task #41: script.json RVA reverse-lookup + il2cppdumper session integration.

Covers the unity_lookup index (build/cache/invalidation/lookup), the
unity.run_dumper_cli subprocess wrapper, the service layer (il2cpp_lookup /
il2cpp_dump artifact association), CLI parsing and MCP tool registration.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from types import SimpleNamespace

import pytest

from game_modifier import mcp_server
from game_modifier.cli import build_parser
from game_modifier.config import Config
from game_modifier.engines import unity as unity_mod
from game_modifier.engines import unity_lookup
from game_modifier.errors import InvalidArgsError, ToolNotFoundError
from game_modifier.service import ModifierService
from game_modifier.session import Session
from test_mcp_extended import _tool_names


# ----------------------------------------------------------------- fixtures
SAMPLE_METHODS = [
    {"Address": 0x1000, "Name": "Player.Update", "Signature": "void Player.Update(Player* this)"},
    {"Address": 0x4E85670, "Name": "Dictionary.TryAdd", "Signature": "bool Dictionary.TryAdd(dict* this, k, v)"},
    {"Address": 0x4E85800, "Name": "Dictionary.Remove", "Signature": "bool Dictionary.Remove(dict* this, k)"},
]


@pytest.fixture
def script_json(tmp_path):
    """Small pseudo script.json plus a cleared module memo (test isolation)."""

    path = tmp_path / "script.json"
    path.write_text(json.dumps({"ScriptMethod": SAMPLE_METHODS,
                                "ScriptString": []}), encoding="utf-8")
    unity_lookup._MEMO.clear()
    yield path
    unity_lookup._MEMO.clear()


@pytest.fixture
def svc(tmp_path):
    cfg = Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": True,
                   "require_writable_region": True},
        "scan": {"max_results": 1000, "chunk_size": 4096, "alignment": 1, "max_region_bytes": 0},
        "output": {"format": "json"},
        "paths": {"home": str(tmp_path / ".game-modifier")},
        "tools": {"search_dirs": {"extra": []}},
    })
    return ModifierService(cfg)


def _make_session(svc, sid="s-il2cpp", engine=None):
    session = Session(id=sid, pid=4242, process_name="Game.exe",
                      exe_path="C:/games/Game.exe", engine=engine or {})
    svc.store.save(session)
    return session


# --------------------------------------------------------- unity_lookup core
def test_build_index_small(script_json):
    info = unity_lookup.build_index(str(script_json))
    assert info["methods"] == len(SAMPLE_METHODS)
    assert info["cached"] is False
    assert info["elapsed"] >= 0
    idx = script_json.with_name("script.json.idx")
    assert info["index_path"] == str(idx)
    assert idx.exists() and idx.stat().st_size > 0


def test_lookup_exact(script_json):
    res = unity_lookup.lookup_rva(str(script_json), 0x4E85670)
    assert res["matched"] == "exact"
    assert res["name"] == "Dictionary.TryAdd"
    assert res["rva"] == hex(0x4E85670)
    assert "Dictionary.TryAdd" in res["signature"]


def test_lookup_nearest(script_json):
    # 0x10 bytes inside Player.Update body -> nearest function start
    res = unity_lookup.lookup_rva(str(script_json), 0x1010, tolerance=0x100)
    assert res["matched"] == "nearest"
    assert res["name"] == "Player.Update"
    assert res["method_rva"] == hex(0x1000)
    assert res["offset"] == hex(0x10)
    # same RVA without tolerance -> no match
    res2 = unity_lookup.lookup_rva(str(script_json), 0x1010, tolerance=0)
    assert res2["matched"] == "none" and res2["name"] is None
    # beyond the tolerance window -> no match either
    res3 = unity_lookup.lookup_rva(str(script_json), 0x1000 + 0x400, tolerance=0x100)
    assert res3["matched"] == "none"


def test_lookup_miss(script_json):
    res = unity_lookup.lookup_rva(str(script_json), 0x10, tolerance=0x100)
    assert res["matched"] == "none"
    assert res["name"] is None and res["signature"] is None


def test_index_cache_hit(script_json):
    first = unity_lookup.build_index(str(script_json))
    assert first["cached"] is False
    second = unity_lookup.build_index(str(script_json))
    assert second["cached"] is True
    assert second["methods"] == first["methods"]

    # also via a fresh memo (sidecar fingerprint path)
    unity_lookup._MEMO.clear()
    third = unity_lookup.build_index(str(script_json))
    assert third["cached"] is True
    assert third["methods"] == first["methods"]


def test_index_cache_invalidate(script_json):
    unity_lookup.build_index(str(script_json))

    # rewrite the source with different content (size + mtime change)
    time.sleep(0.01)
    extra = SAMPLE_METHODS + [{"Address": 0x9000, "Name": "Extra.Method", "Signature": ""}]
    script_json.write_text(json.dumps({"ScriptMethod": extra}), encoding="utf-8")
    os.utime(script_json, (time.time() + 5, time.time() + 5))

    rebuilt = unity_lookup.build_index(str(script_json))
    assert rebuilt["cached"] is False
    assert rebuilt["methods"] == len(extra)
    res = unity_lookup.lookup_rva(str(script_json), 0x9000)
    assert res["matched"] == "exact" and res["name"] == "Extra.Method"


# ---------------------------------------------------------- run_dumper_cli
def _fake_dumper(tmp_path):
    exe = tmp_path / "Il2CppDumper.exe"
    exe.write_bytes(b"MZ-fake")
    return str(exe)


def test_run_dumper_mock_success(tmp_path):
    exe = _fake_dumper(tmp_path)

    def fake_run(cmd, **kw):
        assert cmd[0] == exe
        import pathlib
        pathlib.Path(kw["cwd"], "script.json").write_text("{}", encoding="utf-8")
        pathlib.Path(kw["cwd"], "dump.cs").write_text("// dump", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="Generated", stderr="")

    orig = unity_mod.subprocess.run
    unity_mod.subprocess.run = fake_run
    try:
        res = unity_mod.run_dumper_cli(exe, "C:/games/GameAssembly.dll", str(tmp_path / "out"))
    finally:
        unity_mod.subprocess.run = orig
    assert res["ok"] is True
    assert res["returncode"] == 0
    assert "script.json" in res["outputs"] and "dump.cs" in res["outputs"]
    assert res["elapsed"] >= 0


def test_run_dumper_mock_failure_and_timeout(tmp_path, monkeypatch):
    exe = _fake_dumper(tmp_path)

    monkeypatch.setattr(unity_mod.subprocess, "run",
                        lambda cmd, **kw: SimpleNamespace(returncode=1, stdout="", stderr="boom"))
    res = unity_mod.run_dumper_cli(exe, "target.dll", str(tmp_path / "out"))
    assert res["ok"] is False
    assert "code 1" in res["error"]
    assert res["stderr_tail"] == "boom"

    def timeout_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=5)

    monkeypatch.setattr(unity_mod.subprocess, "run", timeout_run)
    res = unity_mod.run_dumper_cli(exe, "target.dll", str(tmp_path / "out"), timeout=5.0)
    assert res["ok"] is False
    assert res.get("timeout") is True
    assert "timed out" in res["error"]

    # missing dumper binary is reported, not raised
    res = unity_mod.run_dumper_cli(str(tmp_path / "nope.exe"), "t.dll", str(tmp_path / "out"))
    assert res["ok"] is False and "not found" in res["error"]


# ------------------------------------------------------------- service layer
def test_service_il2cpp_lookup(svc, script_json):
    _make_session(svc)  # no artifacts associated

    with pytest.raises(InvalidArgsError) as exc:
        svc.il2cpp_lookup("s-il2cpp", rva="0x4E85670")
    assert exc.value.hint and "il2cpp dump" in exc.value.hint

    # explicit --script-json works without association
    res = svc.il2cpp_lookup("s-il2cpp", rva="0x4E85670", script_json=str(script_json))
    assert res["matched"] == "exact"
    assert res["name"] == "Dictionary.TryAdd"
    assert res["session_id"] == "s-il2cpp"

    # address-expression rva + tolerance through the service layer
    # 0x4E85680+0x10 = 0x4E85690 -> 0x20 bytes inside Dictionary.TryAdd
    res = svc.il2cpp_lookup("s-il2cpp", rva="0x4E85680+0x10",
                            script_json=str(script_json), tolerance="0x40")
    assert res["matched"] == "nearest" and res["name"] == "Dictionary.TryAdd"
    assert res["offset"] == hex(0x20)

    # associated via session engine artifacts
    session = svc.store.load("s-il2cpp")
    session.engine = {"artifacts": {"script_json": str(script_json)}}
    svc.store.save(session)
    res = svc.il2cpp_lookup("s-il2cpp", rva="0x1000")
    assert res["matched"] == "exact" and res["name"] == "Player.Update"


def test_service_il2cpp_dump_associate(svc, tmp_path, monkeypatch):
    import game_modifier.service as svc_mod

    session = _make_session(svc, engine={"artifacts": {"game_assembly": "C:/games/GameAssembly.dll"}})
    sid = session.id
    out_dir = tmp_path / "dump_out"
    outputs = {"script.json": str(out_dir / "script.json"),
               "dump.cs": str(out_dir / "dump.cs")}

    monkeypatch.setattr(svc_mod.toolchain, "recommended_unity_dumper",
                        lambda meta, cfg: {"dumper": "il2cppdumper", "metadata_version": 29,
                                           "found": True, "path": "C:/tools/Il2CppDumper.exe",
                                           "hint": ""})

    calls = {}

    def fake_run_cli(dumper_path, target, out, *, timeout=120.0):
        calls.update(dumper_path=dumper_path, target=target, out=out, timeout=timeout)
        return {"ok": True, "outputs": outputs, "returncode": 0,
                "out_dir": str(out), "elapsed": 0.42}

    monkeypatch.setattr(svc_mod.engines.unity, "run_dumper_cli", fake_run_cli)

    res = svc.il2cpp_dump(sid, out_dir=str(out_dir), timeout=33.0)
    assert res["ok"] is True and res["associated"] is True
    assert res["outputs"] == outputs
    assert res["dumper"] == "il2cppdumper"
    assert calls["target"] == "C:/games/GameAssembly.dll"
    assert calls["timeout"] == 33.0

    # artifacts persisted into the session file
    reloaded = svc.store.load(sid)
    assert reloaded.engine["artifacts"]["script_json"] == outputs["script.json"]
    assert reloaded.engine["artifacts"]["dump_cs"] == outputs["dump.cs"]
    assert reloaded.engine["il2cpp_dump"]["dumper"] == "il2cppdumper"

    # lookup now resolves without an explicit path
    sj = tmp_path / "dump_out" / "script.json"
    sj.parent.mkdir(parents=True, exist_ok=True)
    sj.write_text(json.dumps({"ScriptMethod": SAMPLE_METHODS}), encoding="utf-8")
    unity_lookup._MEMO.clear()
    res = svc.il2cpp_lookup(sid, rva="0x4E85670")
    assert res["matched"] == "exact" and res["name"] == "Dictionary.TryAdd"


def test_service_il2cpp_dump_no_tool(svc, monkeypatch):
    import game_modifier.service as svc_mod

    _make_session(svc, sid="s-notool", engine={"artifacts": {"game_assembly": "C:/g/GA.dll"}})
    monkeypatch.setattr(svc_mod.toolchain, "recommended_unity_dumper",
                        lambda meta, cfg: {"dumper": "il2cppdumper_rs", "metadata_version": None,
                                           "found": False, "path": None, "hint": "install rs dumper"})
    monkeypatch.setattr(svc_mod.toolchain, "detect_tool",
                        lambda name, cfg=None: {"name": name, "found": False})
    with pytest.raises(ToolNotFoundError):
        svc.il2cpp_dump("s-notool")


# ------------------------------------------------------------------ CLI/MCP
def test_cli_il2cpp_lookup_dump_parsing():
    p = build_parser()

    a = p.parse_args(["il2cpp", "lookup", "--session", "s1", "--rva", "0x4E85670",
                      "--script-json", "C:/dump/script.json", "--tolerance", "0x100",
                      "--force-index"])
    assert a.command == "il2cpp" and a.il2cpp_action == "lookup"
    assert a.session == "s1" and a.rva == "0x4E85670"
    assert a.script_json == "C:/dump/script.json"
    assert a.tolerance == "0x100" and a.force_index is True

    a = p.parse_args(["il2cpp", "lookup", "--session", "s1", "--rva", "0x10"])
    assert a.script_json is None and a.tolerance == "0" and a.force_index is False

    a = p.parse_args(["il2cpp", "dump", "--session", "s1", "--out-dir", "C:/dumps", "--timeout", "60"])
    assert a.il2cpp_action == "dump"
    assert a.out_dir == "C:/dumps" and a.timeout == 60.0

    a = p.parse_args(["il2cpp", "dump", "--session", "s1"])
    assert a.out_dir is None and a.timeout == 120.0


def test_mcp_il2cpp_lookup_dump_registered(tmp_path):
    cfg = tmp_path / "cfg.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    names = _tool_names(mcp_server.build_server(str(cfg)))
    assert {"il2cpp_lookup", "il2cpp_dump"} <= names

    ro_names = _tool_names(mcp_server.build_server(str(cfg), profile="readonly"))
    assert "il2cpp_lookup" in ro_names       # read-only profile keeps the lookup
    assert "il2cpp_dump" not in ro_names     # dumper invocation is a side effect

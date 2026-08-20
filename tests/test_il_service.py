"""Service-layer tests for the il_* seven tools + mono_dump/mono_symbol (Task #65).

The il-tool bridge is monkeypatched with an in-process fake (records every
request, answers with protocol-shaped envelopes) so CI never depends on the
real .NET binary. Session/audit/artifact behavior runs against FakeBackend.
"""

from __future__ import annotations

import json
import struct

import pytest

pytest.importorskip("mcp")

from game_modifier import service as svc_mod  # noqa: E402
from game_modifier.errors import ErrorCode, GameModifierError, InvalidArgsError  # noqa: E402
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory.base import ModuleInfo  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402


# ------------------------------------------------------------------- fixtures

INDEX_PAYLOAD = {
    "assembly": "Assembly-CSharp, Version=0.0.0.0",
    "type_count": 1,
    "method_count": 1,
    "field_count": 0,
    "namespaces": {
        "Game": [
            {
                "full_name": "Game.Player",
                "methods": [
                    {"name": "AddGold", "full_name": "System.Void Game.Player::AddGold(System.Int32)",
                     "rva_hex": "0x5A1234", "static": False},
                ],
                "fields": [],
            }
        ]
    },
}


class FakeIlTool:
    """In-process stand-in for ``il_tool_bridge.run_il_tool``."""

    def __init__(self):
        self.requests: list[dict] = []
        self.fail: dict | None = None
        # dump size knob: <= service._IL_DUMP_INLINE_MAX stays inline
        self.dump_instructions = 12

    def __call__(self, request, *, timeout=120.0, config=None):
        self.requests.append(request)
        cmd = request.get("command")
        if self.fail is not None:
            return {"ok": False, "command": cmd, "error": dict(self.fail),
                    "returncode": 0, "elapsed": 0.0, "stderr_tail": ""}
        if cmd == "analyze":
            data = {"assembly": "Assembly-CSharp, Version=0.0.0.0",
                    "type_count": 1, "method_count": 1, "field_count": 0, "truncated": False,
                    "types": [{"name": "Player", "full_name": "Game.Player", "namespace": "Game",
                               "methods": [{"name": "AddGold", "full_name": "System.Void Game.Player::AddGold(System.Int32)"}],
                               "fields": [{"name": "gold", "field_type": "System.Int32"}]}]}
        elif cmd == "dump":
            rows = [{"offset": f"0x{i * 2:04X}", "opcode": "nop", "operand": ""}
                    for i in range(self.dump_instructions)]
            data = {"method": "Game.Player::AddGold", "instruction_count": len(rows),
                    "instructions": rows}
        elif cmd == "callers":
            data = {"target": request["args"]["target"], "scanned_methods": 50, "caller_count": 2}
        elif cmd == "patch":
            data = {"op": request["patch"]["op"], "method": "Game.Player::AddGold",
                    "out_assembly": request["assembly"], "instruction_count": 13}
        elif cmd == "verify":
            data = {"method": "Game.Player::AddGold", "matched": True,
                    "exact": bool(request["args"].get("exact", False)),
                    "expected": request["args"]["expected"],
                    "instruction_count": 12, "sequence": ["ldarg.0", "mul", "ret"]}
        elif cmd == "index":
            # the real tool writes the big payload to `out` and keeps the
            # *_count summary inline - mirror that contract exactly
            out = request["out"]
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(INDEX_PAYLOAD, fh, ensure_ascii=False)
            data = {"out_file": out, "type_count": 1, "method_count": 1, "field_count": 0}
        else:  # pragma: no cover - defensive
            return {"ok": False, "command": cmd,
                    "error": {"code": "E_IL_BAD_REQUEST", "message": "unknown"},
                    "returncode": 0, "elapsed": 0.0, "stderr_tail": ""}
        # out-spilling protocol: stdout keeps out_file + *_count only
        out = request.get("out")
        if out and cmd in ("analyze", "dump", "callers"):
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
            data = {"out_file": out,
                    **{k: v for k, v in data.items() if k.endswith("_count")}}
        return {"ok": True, "command": cmd, "data": data,
                "returncode": 0, "elapsed": 0.01, "stderr_tail": ""}


@pytest.fixture
def fake_il_tool(monkeypatch):
    fake = FakeIlTool()
    monkeypatch.setattr(svc_mod.il_tool_bridge, "run_il_tool", fake)
    return fake


@pytest.fixture
def il_env(tmp_path, tmp_config, fake_backend_factory, monkeypatch, fake_il_tool):
    """Service + an attached session whose exe dir holds Assembly-CSharp.dll."""

    region = bytearray(struct.pack("<i", 1) + b"\x00" * 0x100)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x100, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={0x200000: region}, modules=[mod],
                                name="fake.exe", pid=4242)
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])

    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]

    game_dir = tmp_path / "game"
    game_dir.mkdir()
    asm = game_dir / "Assembly-CSharp.dll"
    asm.write_bytes(b"MZ" + b"\x00" * 1022)
    exe = game_dir / "fake.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 100)

    session = service.store.load(sid)
    session.exe_path = str(exe)
    service.store.save(session)
    return service, sid, asm


# ---------------------------------------------------------------- il_* tools

def test_il_analyze(il_env, fake_il_tool):
    service, sid, asm = il_env
    out = service.il_analyze(sid, type_filter="Player")

    assert out["ok"] is True
    assert out["assembly"] == str(asm)  # default resolution via <exe>_Data-less exe dir
    req = fake_il_tool.requests[0]
    assert req["command"] == "analyze"
    assert req["assembly"] == str(asm)
    assert req["args"] == {"filter": "Player"}
    assert out["type_count"] == 1  # data passed through


def test_il_dump_small_inline(il_env, fake_il_tool):
    """Small dumps (<= _IL_DUMP_INLINE_MAX) come back inline, no spill file."""

    service, sid, asm = il_env
    fake_il_tool.dump_instructions = 12
    out = service.il_dump(sid, method="AddGold", type="Game.Player")

    assert out["ok"] is True
    req = fake_il_tool.requests[0]
    assert req["command"] == "dump"
    assert req["args"] == {"method": "AddGold", "type": "Game.Player"}
    # small dumps are NOT spilled: no out param in the request, no out_file
    assert "out" not in req
    assert "out_file" not in out
    assert out["instruction_count"] == 12
    assert len(out["instructions"]) == 12
    assert out["instructions"][0]["opcode"] == "nop"


def test_il_dump_large_spills(il_env, fake_il_tool):
    """Large dumps still spill under sessions/<id>/il/ (read back via results_read)."""

    service, sid, asm = il_env
    fake_il_tool.dump_instructions = service._IL_DUMP_INLINE_MAX + 1
    out = service.il_dump(sid, method="AddGold", type="Game.Player")

    assert out["ok"] is True
    req = fake_il_tool.requests[0]
    assert "out" not in req  # the service spills itself, post-hoc
    assert out["instruction_count"] == service._IL_DUMP_INLINE_MAX + 1
    assert "instructions" not in out  # big payload stayed out of the reply
    out_file = out["out_file"]
    assert out_file.startswith(str(service.store.dir / sid / "il"))
    # the spilled file holds the FULL payload and is readable via results_read
    page = service.results_read(sid, path=out_file)
    assert page["total_lines"] >= 1
    full = json.loads(page["content"])
    assert len(full["instructions"]) == service._IL_DUMP_INLINE_MAX + 1


def test_il_analyze_fingerprint_cache(il_env, fake_il_tool):
    """F4: a repeated full analyze on an unchanged assembly is served from the
    fingerprint cache; touching the file (game update) re-runs the tool."""

    service, sid, asm = il_env
    first = service.il_analyze(sid)
    assert first["ok"] is True
    assert "cached" not in first
    runs = len(fake_il_tool.requests)

    second = service.il_analyze(sid)
    assert second["ok"] is True
    assert second["cached"] is True
    assert second["out_file"] == first["out_file"]
    assert len(fake_il_tool.requests) == runs  # no second tool invocation

    # different filter -> different cache key -> re-runs
    third = service.il_analyze(sid, type_filter="Player")
    assert "cached" not in third
    assert len(fake_il_tool.requests) == runs + 1

    # same filter again -> cached
    fourth = service.il_analyze(sid, type_filter="Player")
    assert fourth["cached"] is True
    assert len(fake_il_tool.requests) == runs + 1

    # game update: file content+mtime change -> fingerprint shifts -> re-run
    asm.write_bytes(b"MZ" + b"\x01" * 1022)
    import os as _os
    st = asm.stat()
    _os.utime(asm, (st.st_atime, st.st_mtime + 5))
    fifth = service.il_analyze(sid)
    assert "cached" not in fifth
    assert len(fake_il_tool.requests) == runs + 2


def test_il_callers(il_env, fake_il_tool):
    service, sid, asm = il_env
    out = service.il_callers(sid, method="AddGold", max_results=50)

    assert out["ok"] is True
    req = fake_il_tool.requests[0]
    assert req["command"] == "callers"
    assert req["args"] == {"target": "AddGold", "max_results": 50}
    assert out["caller_count"] == 2


def test_il_patch_confirm_gate(il_env, fake_il_tool):
    service, sid, asm = il_env
    out = service.il_patch(sid, op="mul_before_ret", method="AddGold", value=2.0)

    # refused as a write: dry-run preview only, il-tool never invoked
    assert out["applied"] is False
    assert out["dry_run"] is True
    assert out["status"] == "dry_run_preview"
    assert out["planned"]["op"] == "mul_before_ret"
    assert out["planned"]["value"] == 2.0
    assert fake_il_tool.requests == []


def test_il_patch_auto_backup(il_env, fake_il_tool):
    service, sid, asm = il_env
    out = service.il_patch(sid, op="mul_before_ret", method="AddGold", value=4.0, confirm=True)

    assert out["applied"] is True
    assert out["ok"] is True
    # automatic file-level backup before the patch
    backup_id = out["backup_id"]
    assert backup_id and backup_id.startswith("ilbk-")
    bdir = service.store.dir / sid / "file_backups"
    assert (bdir / f"{backup_id}.dll").exists()
    manifest = json.loads((bdir / f"{backup_id}.json").read_text(encoding="utf-8"))
    assert manifest["source"] == str(asm)
    assert manifest["sha256"]
    # patch request carried the op + parameter
    req = fake_il_tool.requests[-1]
    assert req["command"] == "patch"
    assert req["patch"] == {"op": "mul_before_ret", "value": 4.0}
    # audit trail records both operations
    entries = service.audit_tail(session_id=sid)["entries"]
    ops = [e["op"] for e in entries]
    assert "il_backup" in ops and "il_patch" in ops
    patch_entry = next(e for e in entries if e["op"] == "il_patch")
    assert patch_entry["backup_id"] == backup_id


def test_il_patch_parameterized(il_env, fake_il_tool):
    service, sid, asm = il_env
    # re-running with a different multiplier is the tuning loop
    for factor in (2.0, 8.0):
        out = service.il_patch(sid, op="mul_before_ret", method="AddGold",
                               value=factor, confirm=True)
        assert out["applied"] is True
        req = fake_il_tool.requests[-1]
        assert req["patch"]["value"] == factor

    # insert_after_call carries its target through
    out = service.il_patch(sid, op="insert_after_call", method="Update",
                           target="CheckSave", confirm=True)
    assert out["applied"] is True
    req = fake_il_tool.requests[-1]
    assert req["patch"] == {"op": "insert_after_call", "target": "CheckSave"}


def test_il_verify(il_env, fake_il_tool):
    service, sid, asm = il_env
    out = service.il_verify(sid, method="AddGold", expect={"expected": ["mul", "ret"]})

    assert out["ok"] is True
    assert out["matched"] is True
    req = fake_il_tool.requests[0]
    assert req["command"] == "verify"
    assert req["args"]["expected"] == ["mul", "ret"]
    assert req["args"]["method"] == "AddGold"

    # a bare opcode list is normalized to {"expected": [...]}
    service.il_verify(sid, method="AddGold", expect=["mul"])
    assert fake_il_tool.requests[-1]["args"]["expected"] == ["mul"]


def test_il_verify_failure_maps_to_typed_error(il_env, fake_il_tool):
    service, sid, asm = il_env
    fake_il_tool.fail = {"code": "E_IL_VERIFY_FAILED",
                         "message": "expected opcode pattern not found",
                         "details": {"expected": ["mul"], "actual": ["ret"]}}
    with pytest.raises(GameModifierError) as excinfo:
        service.il_verify(sid, method="AddGold", expect=["mul"])
    assert excinfo.value.code is ErrorCode.IL_VERIFY_FAILED
    assert excinfo.value.details["expected"] == ["mul"]


def test_il_backup_restore(il_env):
    service, sid, asm = il_env
    original = asm.read_bytes()

    backup = service.il_backup(sid, label="manual")
    backup_id = backup["backup_id"]
    assert backup["ok"] is True and backup["sha256"]
    assert backup["label"] == "manual"

    # preview without confirm: nothing written back
    preview = service.il_restore(sid, backup_id=backup_id)
    assert preview["applied"] is False and preview["dry_run"] is True
    assert preview["process_alive"] is True
    assert asm.read_bytes() == original

    # mutate the assembly, then restore with confirm
    asm.write_bytes(b"MZ" + b"\xff" * 1022)
    out = service.il_restore(sid, backup_id=backup_id, confirm=True)
    assert out["applied"] is True
    assert out["warning"]  # process alive -> restart hint
    assert asm.read_bytes() == original

    entries = service.audit_tail(session_id=sid)["entries"]
    assert {e["op"] for e in entries} == {"il_backup", "il_restore"}

    # unknown backup id -> E_BACKUP_NOT_FOUND with the known list
    with pytest.raises(GameModifierError) as excinfo:
        service.il_restore(sid, backup_id="ilbk-deadbeef-000000", confirm=True)
    assert excinfo.value.code is ErrorCode.BACKUP_NOT_FOUND
    assert backup_id in excinfo.value.details["known"]


# ------------------------------------------------------------- mono index flow

def test_mono_dump_index_cache(il_env, fake_il_tool):
    service, sid, asm = il_env
    out = service.mono_dump(sid)

    assert out["ok"] is True
    assert out["type_count"] == 1
    index_path = service.store.dir / sid / "mono_dump" / "Assembly-CSharp.index.json"
    assert out["index"] == str(index_path)
    assert index_path.exists()
    meta_path = index_path.with_name("Assembly-CSharp.index.meta.json")
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["fingerprint"]["head_hash"]
    # index associated with the session artifacts
    session = service.store.load(sid)
    assert session.engine["artifacts"]["mono_index"]["index"] == str(index_path)
    assert len(fake_il_tool.requests) == 1

    # fingerprint still fresh -> reuse short-circuit (no new il-tool call)
    out2 = service.mono_dump(sid)
    assert out2["reused"] is True and out2["fresh"] is True
    assert len(fake_il_tool.requests) == 1

    # force rebuilds regardless
    out3 = service.mono_dump(sid, force=True)
    assert "reused" not in out3
    assert len(fake_il_tool.requests) == 2


def test_mono_symbol_lookup(il_env):
    service, sid, asm = il_env
    service.mono_dump(sid)

    by_name = service.mono_symbol(sid, query="addgold")
    assert by_name["count"] == 1
    m = by_name["matches"][0]
    assert m["kind"] == "method" and m["name"] == "AddGold"
    assert m["type"] == "Game.Player"

    type_hit = service.mono_symbol(sid, query="Player")
    kinds = {x["kind"] for x in type_hit["matches"]}
    assert "type" in kinds and "method" in kinds

    by_rva = service.mono_symbol(sid, query="0x5a1234")
    assert by_rva["count"] == 1
    assert by_rva["matches"][0]["full_name"].endswith("AddGold(System.Int32)")


def test_mono_symbol_no_index(il_env):
    service, sid, asm = il_env
    with pytest.raises(InvalidArgsError) as excinfo:
        service.mono_symbol(sid, query="Player")
    assert "mono dump" in (excinfo.value.hint or "")


# --------------------------------------------------------------- MCP surface

def _tool_names(server) -> set:
    tm = getattr(server, "_tool_manager", None)
    if tm is not None and hasattr(tm, "_tools"):
        return set(tm._tools.keys())
    import asyncio
    return {t.name for t in asyncio.run(server.list_tools())}


def test_mcp_il_tools_registered(tmp_path):
    import asyncio

    from game_modifier import mcp_server as mcp

    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    il_tools = {"il_analyze", "il_dump", "il_callers", "il_patch",
                "il_verify", "il_backup", "il_restore"}
    mono_tools = {"mono_dump", "mono_symbol",
                  "mono_string", "mono_list", "mono_dict",
                  "mono_static", "mono_heap_scan"}

    # group constants
    assert set(mcp.TOOL_GROUPS["il"]) == il_tools
    assert set(mcp.TOOL_GROUPS["mono"]) == mono_tools

    # default profile registers everything
    names = _tool_names(mcp.build_server(str(cfg)))
    assert il_tools | mono_tools <= names

    # readonly profile: read tools in, write tools out
    ro = _tool_names(mcp.build_server(str(cfg), profile="readonly"))
    assert {"il_analyze", "il_dump", "il_callers", "il_verify", "mono_symbol",
            "mono_string", "mono_list", "mono_dict",
            "mono_static", "mono_heap_scan"} <= ro
    assert not ({"il_patch", "il_backup", "il_restore", "mono_dump"} & ro)

    # dry-run profile: il_patch stays registered behind the confirm guard
    dr_server = mcp.build_server(str(cfg), profile="dry-run")
    dr = _tool_names(dr_server)
    assert "il_patch" in dr and "il_restore" in dr
    refused = asyncio.run(dr_server.call_tool(
        "il_patch", {"session": "s", "op": "mul_before_ret", "method": "M", "confirm": True}))
    payload = json.loads(refused[0].text)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "E_PROFILE_RESTRICTED"

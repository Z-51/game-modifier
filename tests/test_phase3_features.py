"""Phase 3 (P2) feature tests: inline batch YAML + batch_preview, scan result
persistence (results_file), session_notes (notes.jsonl) and the pure-Python
xrefs fallback.

These complement the frozen surface: every new tool/field registered here is
also locked in test_surface_lock.py.
"""

from __future__ import annotations

import asyncio
import json
import struct

import pytest

pytest.importorskip("mcp")

from conftest import FakeBackend  # noqa: E402

from game_modifier import mcp_server  # noqa: E402
from game_modifier.config import Config  # noqa: E402
from game_modifier.errors import BatchError, InvalidArgsError, ToolNotFoundError  # noqa: E402
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory import xrefs_fallback  # noqa: E402
from game_modifier.memory.base import MemoryRegion, ModuleInfo  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402
from game_modifier.session import SessionStore  # noqa: E402
from game_modifier.toolchain import radare2 as r2mod  # noqa: E402
import game_modifier.toolchain as toolchain_pkg  # noqa: E402
from test_mcp_extended import _tool_names  # noqa: E402


def _patch_backend(monkeypatch, fake):
    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])


@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x1000)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={0x200000: region}, modules=[mod],
                               name="fake.exe", pid=4242)
    _patch_backend(monkeypatch, fake)
    return ModifierService(tmp_config), fake


# ===========================================================================
# 3.1 batch_run inline yaml + batch_preview
# ===========================================================================

BATCH_YAML = (
    "operations:\n"
    '  - modify: {address: "0x200000", type: int32, value: 111}\n'
    '  - read: {address: "0x200000"}\n'
)


def test_batch_run_inline_yaml_and_file_mutually_exclusive(service, tmp_path):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    f = tmp_path / "ops.yaml"
    f.write_text(BATCH_YAML, encoding="utf-8")

    # both sources -> structured E_INVALID_ARGS
    with pytest.raises(InvalidArgsError) as ei:
        svc.batch_run(session_id=sid, path=str(f), yaml_text=BATCH_YAML)
    assert "not both" in str(ei.value)

    # neither source -> structured E_INVALID_ARGS
    with pytest.raises(InvalidArgsError) as ei:
        svc.batch_run(session_id=sid)
    assert ei.value.details is not None


def test_batch_run_inline_yaml_executes(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    res = svc.batch_run(session_id=sid, yaml_text=BATCH_YAML, confirm=True)
    assert res["ok_count"] == 2 and res["error_count"] == 0
    assert res["results_file"]  # batch persistence untouched
    # the write really happened (inline path shares the file pipeline)
    val = svc.read(session_id=sid, address="0x200000", type="int32")
    assert val["value"] == 111


def test_batch_run_malformed_inline_yaml(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    with pytest.raises(BatchError):
        svc.batch_run(session_id=sid, yaml_text="operations: [ - modify: {address: ")


def test_batch_preview_preflight_without_execution(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    res = svc.batch_preview(session_id=sid, yaml_text=BATCH_YAML)

    assert res["source"] == "yaml"
    assert res["total"] == 2
    assert res["risk_breakdown"] == {"high": 0, "normal": 1, "none": 1}
    assert res["estimated_write_bytes"] == 4  # one int32 write

    modify_op = res["ops"][0]
    assert modify_op["action"] == "modify"
    assert modify_op["risk"] == "normal"      # writable private region
    assert modify_op["write_bytes"] == 4
    assert modify_op["target"] == "0x200000"
    read_op = res["ops"][1]
    assert read_op["action"] == "read" and read_op["risk"] == "none"

    # pre-flight must not execute anything: memory still holds 1000
    assert struct.unpack_from("<i", fake._regions[0x200000], 0)[0] == 1000


def test_batch_preview_file_source_and_mutual_exclusion(service, tmp_path):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    f = tmp_path / "ops.yaml"
    f.write_text(BATCH_YAML, encoding="utf-8")

    res = svc.batch_preview(session_id=sid, path=str(f))
    assert res["source"] == "file" and res["total"] == 2

    with pytest.raises(InvalidArgsError):
        svc.batch_preview(session_id=sid, path=str(f), yaml_text=BATCH_YAML)
    with pytest.raises(InvalidArgsError):
        svc.batch_preview(session_id=sid)


def test_mcp_batch_preview_visible_in_every_profile(tmp_path):
    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    for profile in ("default", "readonly", "dry-run", "symbols", "limited"):
        names = _tool_names(mcp_server.build_server(str(cfg), profile=profile))
        assert "batch_preview" in names, f"batch_preview missing from {profile}"
    assert "batch_preview" in mcp_server.READONLY_TOOLS
    assert "batch_preview" in mcp_server.TOOL_GROUPS["modify"]


# ===========================================================================
# 3.2 scan result persistence + results_file
# ===========================================================================

def test_save_scan_result_atomic_roundtrip(tmp_path):
    from pathlib import Path

    store = SessionStore(tmp_path / "home")
    payload = {"session_id": "s1", "count": 2, "addresses_hex": ["0x1000", "0x2000"]}
    path = store.save_scan_result("s1", payload)
    assert path.startswith(str(store.scan_results_dir("s1")))
    assert path.endswith(".json")
    assert not Path(path).with_suffix(".json.tmp").exists()  # atomic temp+rename left no litter
    assert store.read_scan_result(path) == payload
    # consecutive saves never collide
    path2 = store.save_scan_result("s1", payload)
    assert path2 != path


def test_scan_returns_results_file_with_full_candidate_set(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    out = svc.scan(session_id=sid, type="int32", value="1000")
    rf = out["results_file"]
    assert rf and json.loads(open(rf, encoding="utf-8").read())["count"] == out["count"]
    # pagination metadata coexists untouched
    assert out["candidates_total"] == out["count"]
    assert out["page"] == {"offset": 0, "limit": None}
    assert "region_summary" in out


def test_scan_aob_returns_results_file(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    out = svc.scan_aob(session_id=sid, pattern="E8 03")
    rf = out["results_file"]
    assert rf
    saved = json.loads(open(rf, encoding="utf-8").read())
    assert saved["comparator"] == "aob"
    assert saved["addresses_hex"] == out["addresses_hex"]
    assert out["candidates_total"] == out["count"]  # paging meta intact


# ===========================================================================
# 3.3 session_notes (append-only notes.jsonl)
# ===========================================================================

def test_session_notes_set_get_delete_not_found(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    # empty store
    res = svc.session_notes(session_id=sid, action="get")
    assert res["notes"] == {} and res["count"] == 0

    # set + single-key get + overwrite semantics
    svc.session_notes(session_id=sid, action="set", key="gold", value="100")
    svc.session_notes(session_id=sid, action="set", key="strategy", value="rush B")
    res = svc.session_notes(session_id=sid, action="set", key="gold", value="999")
    assert res["count"] == 2
    res = svc.session_notes(session_id=sid, action="get", key="gold")
    assert res["found"] is True and res["value"] == "999"
    res = svc.session_notes(session_id=sid, action="get")
    assert res["notes"] == {"gold": "999", "strategy": "rush B"}

    # append-only JSONL on disk (3 set records, NOT a rewritten session JSON)
    lines = [json.loads(l) for l in
             svc.store.notes_path(sid).read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 3 and all("ts" in e and "key" in e for e in lines)

    # delete existing -> deleted=True; delete missing -> structured not_found
    res = svc.session_notes(session_id=sid, action="delete", key="strategy")
    assert res["deleted"] is True and res["not_found"] is False and res["count"] == 1
    res = svc.session_notes(session_id=sid, action="delete", key="ghost")
    assert res["deleted"] is False and res["not_found"] is True

    # invalid action / missing key are structured errors
    with pytest.raises(InvalidArgsError):
        svc.session_notes(session_id=sid, action="purge")
    with pytest.raises(InvalidArgsError):
        svc.session_notes(session_id=sid, action="set", value="x")


def test_mcp_session_notes_profile_gating(tmp_path, tmp_config, fake_backend_factory, monkeypatch):
    # a real session in the same home both servers will use
    fake = fake_backend_factory(regions={0x200000: bytearray(b"\x00" * 16)},
                                name="fake.exe", pid=4242)
    _patch_backend(monkeypatch, fake)
    svc = ModifierService(tmp_config)
    sid = svc.attach(pid=4242)["session_id"]

    # point the MCP servers at the SAME home as tmp_config so the session resolves
    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / ".game-modifier").as_posix()}"\n',
                   encoding="utf-8")

    for profile in ("default", "readonly", "dry-run", "symbols", "limited"):
        assert "session_notes" in _tool_names(mcp_server.build_server(str(cfg), profile=profile))
    assert "session_notes" in mcp_server.READONLY_TOOLS
    assert "session_notes" in mcp_server.TOOL_GROUPS["core"]

    # default profile: set works end to end
    server = mcp_server.build_server(str(cfg))
    reply = asyncio.run(server.call_tool("session_notes", {
        "session": sid, "action": "set", "key": "hp", "value": "42"}))
    payload = json.loads(reply[0].text)
    assert payload["ok"] is True and payload["data"]["count"] == 1

    # readonly profile: get allowed, set refused server-side
    ro = mcp_server.build_server(str(cfg), profile="readonly")
    got = json.loads(asyncio.run(ro.call_tool(
        "session_notes", {"session": sid, "action": "get"}))[0].text)
    assert got["ok"] is True and got["data"]["notes"] == {"hp": "42"}
    refused = json.loads(asyncio.run(ro.call_tool(
        "session_notes", {"session": sid, "action": "set", "key": "hp", "value": "1"}))[0].text)
    assert refused["ok"] is False
    assert refused["error"]["code"] == "E_PROFILE_RESTRICTED"


# ===========================================================================
# 3.4 xrefs pure-Python fallback
# ===========================================================================

TARGET = 0x7FF012345678
NEEDLE = TARGET.to_bytes(8, "little")


class TypedFakeBackend(FakeBackend):
    """FakeBackend whose regions carry real MEM_* types (region-kind labels)."""

    def __init__(self, region_types=None, **kwargs):
        super().__init__(**kwargs)
        self._region_types = region_types or {}

    def regions(self):
        return [MemoryRegion(base=base, size=len(buf), readable=True, writable=True,
                             state=0x1000, type=self._region_types.get(base, 0))
                for base, buf in self._regions.items()]


def _xrefs_stub_region() -> bytearray:
    region = bytearray(b"\xCC" * 64)
    struct.pack_into("<Q", region, 16, TARGET)  # aligned 8-byte slot (0x300010)
    struct.pack_into("<Q", region, 35, TARGET)  # unaligned occurrence (0x300023)
    return region


def _disable_radare2(monkeypatch):
    monkeypatch.setattr(toolchain_pkg, "detect_all", lambda cfg=None: {
        "available": [], "tools": {"radare2": {"found": False, "path": None}}})

    def raise_missing(*a, **kw):
        raise ToolNotFoundError("radare2 not available", hint="install radare2")

    monkeypatch.setattr(r2mod, "xrefs_at", raise_missing)


@pytest.fixture
def fallback_service(tmp_path, monkeypatch):
    cfg = Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": True,
                   "require_writable_region": True},
        "scan": {"max_results": 1000, "chunk_size": 4096, "alignment": 1,
                 "max_region_bytes": 0, "workers": 1},
        "output": {"format": "json"},
        "paths": {"home": str(tmp_path / ".game-modifier")},
        "tools": {"search_dirs": {"extra": []}},
    })
    fake = TypedFakeBackend(
        region_types={0x300000: 0x20000},  # MEM_PRIVATE -> heap
        regions={0x300000: _xrefs_stub_region()},
        modules=[ModuleInfo(name="GameAssembly.dll", base=0x140000000,
                            size=0x1000000, path="C:/games/GameAssembly.dll")],
        arch="x64",
    )
    _patch_backend(monkeypatch, fake)
    return ModifierService(cfg), fake


def test_xrefs_fallback_hits_aligned_vs_unaligned(fallback_service, monkeypatch):
    svc, _ = fallback_service
    _disable_radare2(monkeypatch)
    sid = svc.attach(pid=4242)["session_id"]

    # aligned filter (default): only the 8-byte-aligned slot survives
    res = svc.xrefs(session_id=sid, address=hex(TARGET))
    assert res["backend"] == "python"
    assert res["backend_kind"] == "python"
    assert res["aligned"] is True
    assert res["count"] == 1
    hit = res["xrefs"][0]
    assert hit["address"] == hex(0x300000 + 16)
    assert hit["size"] == 8
    assert hit["region"] == "heap"  # MEM_PRIVATE region label

    # filter off: the unaligned occurrence is reported too
    res2 = svc.xrefs(session_id=sid, address=hex(TARGET), aligned=False)
    assert res2["aligned"] is False
    addrs = {h["address"] for h in res2["xrefs"]}
    assert hex(0x300000 + 16) in addrs
    assert hex(0x300000 + 35) in addrs
    assert res2["count"] >= 2


def test_xrefs_fallback_parallel_matches_serial(tmp_path, monkeypatch):
    fake = TypedFakeBackend(
        region_types={0x300000: 0x20000, 0x400000: 0x1000000},
        regions={0x300000: _xrefs_stub_region(),
                 0x400000: _xrefs_stub_region()},
        arch="x64",
    )
    serial = xrefs_fallback.find_xrefs(fake, TARGET, aligned=True, workers=1)
    parallel = xrefs_fallback.find_xrefs(
        fake, TARGET, aligned=True, workers=2, backend_factory=lambda: fake)
    assert parallel["xrefs"] == serial["xrefs"]
    assert parallel["count"] == serial["count"] == 2  # one aligned slot per region
    kinds = {h["region"] for h in serial["xrefs"]}
    assert kinds == {"heap", "image"}  # MEM_PRIVATE vs MEM_IMAGE labels


def test_xrefs_fallback_region_kind_mapping():
    assert xrefs_fallback.region_kind(0x1000000) == "image"
    assert xrefs_fallback.region_kind(0x20000) == "heap"
    assert xrefs_fallback.region_kind(0x40000) == "mapped"
    assert xrefs_fallback.region_kind(0) == "other"
    assert xrefs_fallback.slot_sizes("x64") == [8, 4]
    assert xrefs_fallback.slot_sizes("x86") == [4]


def test_xrefs_fallback_target_too_wide_for_4byte_slots():
    # a 48-bit target can never sit in a 4-byte slot: no OverflowError, still found at width 8
    fake = TypedFakeBackend(regions={0x300000: _xrefs_stub_region()}, arch="x64")
    res = xrefs_fallback.find_xrefs(fake, TARGET, aligned=True, workers=1)
    assert res["count"] == 1 and res["xrefs"][0]["size"] == 8


def test_xrefs_radare2_path_still_preferred(fallback_service, monkeypatch):
    """radare2 available -> original path wins, fallback never runs."""
    svc, _ = fallback_service
    calls = []

    def fake_xrefs_at(binary_path, address, *, direction="to", timeout=60.0, r2_path=None):
        calls.append(address)
        return {"backend": "r2pipe", "address": hex(address), "direction": direction,
                "xrefs": [{"from": "0x1", "to": hex(address), "type": "DATA", "fcn": None}],
                "count": 1}

    monkeypatch.setattr(r2mod, "xrefs_at", fake_xrefs_at)
    monkeypatch.setattr(toolchain_pkg, "detect_all", lambda cfg=None: {
        "available": ["radare2"],
        "tools": {"radare2": {"found": True, "path": "C:/r2/radare2.exe"}}})
    sid = svc.attach(pid=4242)["session_id"]

    res = svc.xrefs(session_id=sid, address="GameAssembly.dll+0x10")
    assert res["backend"] == "r2pipe"           # frozen field untouched
    assert res["backend_kind"] == "radare2"     # additive classification
    assert res["count"] == 1 and calls == [0x10]
    assert "fallback_reason" not in res

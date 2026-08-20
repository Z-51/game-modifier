"""Regression tests for the review-fix round (Task #70).

Covers: dry-run profile batch document self-elevation (#1), FileBackupManager
manifest/payload name collision (#2), sidecar values-segment paging cache (#3),
scan/batch result retention pruning (#5), corrupt GMSC2 sidecar detection (#6),
xrefs fallback scanned_bytes (#7) and il_patch failure audit (#8).
"""

from __future__ import annotations

import json
import struct
import sys

import pytest

pytest.importorskip("mcp")

from game_modifier import mcp_server  # noqa: E402
from game_modifier import service as svc_mod  # noqa: E402
from game_modifier.config import Config  # noqa: E402
from game_modifier.errors import ErrorCode, GameModifierError  # noqa: E402
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory import xrefs_fallback  # noqa: E402
from game_modifier.memory.base import ModuleInfo  # noqa: E402
from game_modifier.safety import FileBackupManager  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402
from game_modifier.session import ScanState, SessionStore  # noqa: E402

from conftest import FakeBackend  # noqa: E402


# ---------------------------------------------------------------------------
# shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x1000)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={0x200000: region}, modules=[mod], name="fake.exe", pid=4242)
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


@pytest.fixture
def mcp_config_path(tmp_path):
    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    return str(cfg)


def _call(server, tool_name):
    def call(**kwargs):
        import asyncio
        out = asyncio.run(server.call_tool(tool_name, kwargs))
        return json.loads(out[0].text)
    return call


# ---------------------------------------------------------------------------
# #1 dry-run profile: batch document must not self-elevate via confirm
# ---------------------------------------------------------------------------

def test_dryrun_batch_doc_confirm_rejected(service, mcp_config_path, monkeypatch):
    """confirm=false call + a document carrying confirm:true stays refused."""
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]

    import game_modifier.mcp_server as ms

    monkeypatch.setattr(ms, "load_config", lambda path=None: svc.config)
    server = mcp_server.build_server(mcp_config_path, profile="dry-run")
    batch_run = _call(server, "batch_run")

    yaml_text = ("confirm: true\n"
                 "operations:\n"
                 "  - modify: {address: '0x200000', value: '6666', type: int32}\n")
    env = batch_run(session=sid, yaml=yaml_text, confirm=False)
    assert env["ok"] is False
    assert env["error"]["code"] == "E_PROFILE_RESTRICTED"
    assert env["error"].get("hint")
    # no write happened
    assert fake.read(0x200000, 4) == struct.pack("<i", 1000)


def test_dryrun_batch_file_confirm_code_rejected(service, mcp_config_path, monkeypatch, tmp_path):
    """The file= source path refuses a document-level confirm_code too."""
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]

    import game_modifier.mcp_server as ms

    monkeypatch.setattr(ms, "load_config", lambda path=None: svc.config)
    server = mcp_server.build_server(mcp_config_path, profile="dry-run")
    batch_run = _call(server, "batch_run")

    bfile = tmp_path / "evil.yaml"
    bfile.write_text("confirm_code: true\noperations:\n"
                     "  - modify: {address: '0x200000', value: '6666', type: int32}\n",
                     encoding="utf-8")
    env = batch_run(session=sid, file=str(bfile), confirm=False)
    assert env["ok"] is False
    assert env["error"]["code"] == "E_PROFILE_RESTRICTED"
    assert fake.read(0x200000, 4) == struct.pack("<i", 1000)


def test_dryrun_batch_plain_preview_still_runs(service, mcp_config_path, monkeypatch):
    """A document without confirm still previews normally (behavior frozen)."""
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]

    import game_modifier.mcp_server as ms

    monkeypatch.setattr(ms, "load_config", lambda path=None: svc.config)
    server = mcp_server.build_server(mcp_config_path, profile="dry-run")
    batch_run = _call(server, "batch_run")

    yaml_text = ("operations:\n"
                 "  - modify: {address: '0x200000', value: '6666', type: int32}\n")
    env = batch_run(session=sid, yaml=yaml_text, confirm=False)
    assert env["ok"] is True
    assert fake.read(0x200000, 4) == struct.pack("<i", 1000), "preview must not write"


# ---------------------------------------------------------------------------
# #2 FileBackupManager: payload must never collide with the manifest path
# ---------------------------------------------------------------------------

def test_backup_dir_layout_manifest_name_collision(tmp_path):
    src = tmp_path / "manifest.json"
    src.write_bytes(b'{"payload": true}')
    mgr = FileBackupManager(tmp_path / "file_backups")

    m = mgr.create(src, layout="dir", id_prefix="fbk")
    assert m["file"] == "manifest.json.payload", "payload renamed off the manifest slot"
    bdir = mgr.dir / m["backup_id"]
    assert (bdir / "manifest.json.payload").read_bytes() == b'{"payload": true}'
    manifest_on_disk = json.loads((bdir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest_on_disk == m, "manifest stays a real manifest"

    # round-trip through lookup + integrity check
    mf, bf = mgr.load_manifest(m["backup_id"])
    assert bf.name == "manifest.json.payload"
    assert bf.read_bytes() == b'{"payload": true}'
    assert FileBackupManager.verify(mf, bf) is True


def test_backup_flat_layout_json_source_collision(tmp_path):
    src = tmp_path / "save.json"
    src.write_bytes(b'{"gold": 1}')
    mgr = FileBackupManager(tmp_path / "file_backups")

    m = mgr.create(src, layout="flat", id_prefix="ilbk")
    assert m["file"].endswith(".json.payload")
    manifest_path = mgr.dir / f"{m['backup_id']}.json"
    manifest_on_disk = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest_on_disk == m
    assert (mgr.dir / f"{m['backup_id']}.json.payload").read_bytes() == b'{"gold": 1}'

    mf, bf = mgr.load_manifest(m["backup_id"])
    assert bf.read_bytes() == b'{"gold": 1}'
    assert FileBackupManager.verify(mf, bf) is True


# ---------------------------------------------------------------------------
# #3 sidecar values segment: paged reads hit the process-local cache
# ---------------------------------------------------------------------------

def _sidecar_scan(tmp_path, monkeypatch, fake_backend_factory):
    import game_modifier.session as sess_mod

    base = 0x200000
    buf = bytearray()
    for _ in range(30):
        buf += struct.pack("<i", 5)
    fake = fake_backend_factory(regions={base: buf})
    config = Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": False,
                   "require_writable_region": True},
        "scan": {"max_results": 20000, "chunk_size": 4096, "alignment": 1,
                 "candidates_sidecar_threshold": 10},
        "paths": {"home": str(tmp_path / ".game-modifier")},
    })
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    svc = ModifierService(config)
    sid = svc.attach(pid=4242)["session_id"]
    svc.scan(session_id=sid, type="int32", value=5)
    return svc, sid, base


def test_scan_candidates_values_parsed_once(tmp_path, monkeypatch, fake_backend_factory):
    """Paging must not re-parse the full values blob on every window read."""
    svc, sid, base = _sidecar_scan(tmp_path, monkeypatch, fake_backend_factory)

    import game_modifier.session as sess_mod

    sess_mod._VALUES_CACHE.clear()
    counter = {"n": 0}
    orig_loads = json.loads

    def counting_loads(s, *a, **kw):
        # count only the values-blob parse (the one inside _cached_values),
        # not session/header JSON loads
        if sys._getframe(1).f_code.co_name == "_cached_values":
            counter["n"] += 1
        return orig_loads(s, *a, **kw)

    monkeypatch.setattr(json, "loads", counting_loads)

    p1 = svc.scan_candidates(sid, offset=0, limit=5)
    assert counter["n"] == 1, "first window parses the values segment once"
    p2 = svc.scan_candidates(sid, offset=5, limit=5)
    p3 = svc.scan_candidates(sid, offset=10, limit=5)
    assert counter["n"] == 1, "subsequent pages are served from the cache"
    assert p1["values"] == {hex(base + 4 * i): 5 for i in range(0, 5)}
    assert p2["values"] == {hex(base + 4 * i): 5 for i in range(5, 10)}
    assert p3["values"] == {hex(base + 4 * i): 5 for i in range(10, 15)}


# ---------------------------------------------------------------------------
# #5 scan/batch result retention: newest 10 kept, oldest pruned
# ---------------------------------------------------------------------------

def test_batch_and_scan_results_pruned_to_ten(tmp_path):
    store = SessionStore(tmp_path / "sessions")
    bdir = store.batch_results_dir("s1")
    sdir = store.scan_results_dir("s1")

    batch_paths = [store.save_batch_result("s1", {"i": i}) for i in range(12)]
    scan_paths = [store.save_scan_result("s1", {"i": i}) for i in range(12)]

    remaining_b = sorted(p.name for p in bdir.glob("*.json"))
    remaining_s = sorted(p.name for p in sdir.glob("*.json"))
    assert len(remaining_b) == 10
    assert len(remaining_s) == 10
    # the newest files (including the one just written) survive
    for p in batch_paths[-10:]:
        assert (bdir / p).exists()
    for p in scan_paths[-10:]:
        assert (sdir / p).exists()
    # the oldest two were pruned
    assert not (bdir / batch_paths[0]).exists()
    assert not (sdir / scan_paths[0]).exists()


# ---------------------------------------------------------------------------
# #6 corrupt GMSC2 sidecar: never silently misread as a legacy v1 array
# ---------------------------------------------------------------------------

def test_corrupt_gmsc2_sidecar_structured_error(tmp_path):
    path = tmp_path / "scan_candidates.bin"
    path.write_bytes(b"GMSC2" + b"\x00" * 32)
    state = ScanState()

    with pytest.raises(GameModifierError) as ei:
        state.load_candidates_file(path)
    assert ei.value.code == ErrorCode.SCAN_CACHE_STALE

    with pytest.raises(GameModifierError) as ei2:
        state.read_candidates_window(path, offset=0, limit=5)
    assert ei2.value.code == ErrorCode.SCAN_CACHE_STALE

    assert state.sidecar_count(path) == -1


# ---------------------------------------------------------------------------
# #7 xrefs fallback reports scanned_bytes
# ---------------------------------------------------------------------------

def test_xrefs_fallback_scanned_bytes():
    target = 0x11223344
    region = bytearray(struct.pack("<I", target) + b"\x00" * 60)
    backend = FakeBackend(regions={0x10000: region})

    out = xrefs_fallback.find_xrefs(backend, target, aligned=True)
    # x64 probes 4- and 8-byte slots; the zero tail makes the 8-byte slot
    # at offset 0 match too, so expect one hit per slot size
    assert out["count"] == 2
    assert {x["size"] for x in out["xrefs"]} == {4, 8}
    # bytes are counted per slot-size pass: 64-byte region x 2 sizes
    assert out["scanned_bytes"] == 128, "serial path accumulates scanned bytes"

    out2 = xrefs_fallback.find_xrefs(
        backend, target, aligned=True, workers=2,
        backend_factory=lambda: FakeBackend(regions={0x10000: bytes(region)}))
    assert out2["count"] == 2
    assert out2["scanned_bytes"] == 128, "parallel path sums per-chunk bytes"


# ---------------------------------------------------------------------------
# #8 il_patch: a failed confirmed patch still leaves an audit trail
# ---------------------------------------------------------------------------

@pytest.fixture
def il_env(tmp_path, tmp_config, fake_backend_factory, monkeypatch):
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
    return service, sid


def test_il_patch_failure_records_audit(il_env):
    service, sid = il_env

    def boom(request, *, timeout=120.0):
        raise GameModifierError("il-tool exploded", code=ErrorCode.IL_PATCH_FAILED)

    monkeypatch_local = pytest.MonkeyPatch()
    monkeypatch_local.setattr(service, "_il_run", boom)
    try:
        with pytest.raises(GameModifierError) as ei:
            service.il_patch(sid, op="mul_before_ret", method="AddGold", value=2.0, confirm=True)
        assert ei.value.code == ErrorCode.IL_PATCH_FAILED
    finally:
        monkeypatch_local.undo()

    entries = service.audit_tail(session_id=sid)["entries"]
    patch_entries = [e for e in entries if e["op"] == "il_patch"]
    assert patch_entries, "the failed confirmed patch must be audited"
    fail_entry = patch_entries[-1]
    assert fail_entry["ok"] is False
    assert fail_entry["backup_id"], "backup_id lets the operator roll back"
    assert fail_entry["args"]["error_code"] == ErrorCode.IL_PATCH_FAILED.value

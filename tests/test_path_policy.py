"""Regression tests for the F2 path policy + staged confirm_code (review P0-F2).

Covers:
- validate_file_path: smart-default allow roots (game dir / sessions dir /
  save locations / config extras), hard deny of the OS system directory,
  ``..``/symlink normalization
- file_snapshot / file_restore / save_edit_modify / batch file= enforcement
- BackupManager backup_id traversal guard
- load_batch directory/oversize/invalid-YAML hardening
- modify high-risk staged confirmation (confirm + confirm_code) incl. nl and
  template_apply per-target skip semantics
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

import yaml  # noqa: E402

from game_modifier import service as svc_mod  # noqa: E402
from game_modifier.batch import runner as batch_runner  # noqa: E402
from game_modifier.config import Config  # noqa: E402
from game_modifier.errors import (  # noqa: E402
    BatchError,
    ErrorCode,
    GameModifierError,
    InvalidArgsError,
    PathNotAllowedError,
)
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory.base import MemoryRegion, ModuleInfo  # noqa: E402
from game_modifier.safety import BackupManager  # noqa: E402
from game_modifier.safety.validation import default_save_roots, validate_file_path  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402

from conftest import FakeBackend  # noqa: E402


DATA = 0x200000  # writable data region
CODE = 0x400000  # executable region (high-risk write)


class RiskBackend(FakeBackend):
    """FakeBackend with per-region executable flags (code region = high risk)."""

    def __init__(self, flags=None, **kwargs):
        super().__init__(**kwargs)
        self._flags = flags or {}

    def _region_for(self, address: int):
        base, buf = self._find(address)
        if buf is None:
            return None
        f = self._flags.get(base, {})
        return MemoryRegion(base=base, size=len(buf),
                            readable=f.get("readable", True),
                            writable=f.get("writable", True),
                            executable=f.get("executable", False), state=0x1000)

    def query(self, address: int):
        return self._region_for(address)

    def regions(self):
        return [self._region_for(base) for base in self._regions]


@pytest.fixture
def service(tmp_config, monkeypatch):
    data = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x100)
    code = bytearray(struct.pack("<i", 0x0A0B0C0D) + b"\x00" * 0x100)
    fake = RiskBackend(
        regions={DATA: data, CODE: code},
        flags={DATA: {"writable": True, "executable": False},
               CODE: {"writable": True, "executable": True}},
        modules=[ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000,
                            path="C:/games/fake.exe")],
        name="fake.exe", pid=4242,
    )
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


# ------------------------------------------------------------- pure policy


def test_validate_file_path_allows_and_denies(tmp_path):
    allowed = [tmp_path]
    ok = validate_file_path(str(tmp_path / "a" / "b.txt"), allowed_roots=allowed)
    assert ok.is_absolute()

    with pytest.raises(PathNotAllowedError):
        validate_file_path(str(tmp_path / ".." / "escape.txt"), allowed_roots=[tmp_path / "sub"])


def test_validate_file_path_hard_denies_system_dir(tmp_path):
    windir = os.environ.get("SystemRoot") or r"C:\Windows"
    target = str(Path(windir) / "system32" / "drivers" / "etc" / "hosts")
    # even with an allow root that would otherwise cover it
    with pytest.raises(PathNotAllowedError):
        validate_file_path(target, allowed_roots=[tmp_path])
    # an allow root of the drive root still cannot release the system dir
    drive = Path(windir).anchor
    with pytest.raises(PathNotAllowedError):
        validate_file_path(target, allowed_roots=[drive])


def test_validate_file_path_empty(tmp_path):
    with pytest.raises(InvalidArgsError):
        validate_file_path("", allowed_roots=[tmp_path])


def test_default_save_roots_exist():
    roots = default_save_roots()
    assert any("Documents" in str(r) for r in roots)
    assert any("LocalLow" in str(r) for r in roots)  # Unity saves


# ----------------------------------------------------- service enforcement


def test_file_snapshot_whitelist(service, tmp_path):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    allowed_file = tmp_path / "save.dat"
    allowed_file.write_bytes(b"data")
    out = svc.file_snapshot(sid, path=str(allowed_file))  # tmp_config allows tmp_path
    assert out["ok"] is True

    denied = Path(os.environ.get("SystemDrive", "C:")) / "evil-not-in-roots.txt"
    with pytest.raises(PathNotAllowedError) as ei:
        svc.file_snapshot(sid, path=str(denied))
    assert ei.value.code == ErrorCode.PATH_NOT_ALLOWED


def test_file_restore_validates_manifest_source(service, tmp_path):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    good = tmp_path / "orig.dat"
    good.write_bytes(b"v1")
    bid = svc.file_snapshot(sid, path=str(good))["backup_id"]

    # tamper the manifest: point source at an out-of-policy location
    mgr = svc._file_backup_manager(sid)
    manifest, _ = mgr.load_manifest(bid)
    manifest["source"] = str(Path(os.environ.get("SystemDrive", "C:")) / "tampered-target.dat")
    mpath = mgr.dir / bid / "manifest.json"
    import json as _json
    mpath.write_text(_json.dumps(manifest), encoding="utf-8")

    monkeypatch_target = pytest.MonkeyPatch()
    monkeypatch_target.setattr(procmod, "process_exists", lambda pid: False)
    try:
        with pytest.raises(PathNotAllowedError):
            svc.file_restore(sid, backup_id=bid, confirm=True)
    finally:
        monkeypatch_target.undo()


def test_batch_file_whitelist(service, tmp_path):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    ok_file = tmp_path / "ops.yaml"
    ok_file.write_text('operations:\n  - read: {address: "0x200000", type: int32}\n',
                       encoding="utf-8")
    out = svc.batch_run(session_id=sid, path=str(ok_file), confirm=False)
    assert out["results"][0]["ok"] is True

    denied_dir = Path(os.environ.get("SystemDrive", "C:")) / "not-allowed"
    denied_dir.mkdir(exist_ok=True)
    denied = denied_dir / "ops.yaml"
    denied.write_text('operations:\n  - read: {address: "0x200000"}\n', encoding="utf-8")
    with pytest.raises(PathNotAllowedError):
        svc.batch_run(session_id=sid, path=str(denied), confirm=False)
    with pytest.raises(PathNotAllowedError):
        svc.batch_preview(session_id=sid, path=str(denied))


def test_save_edit_modify_whitelist(service, tmp_path):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    denied = Path(os.environ.get("SystemDrive", "C:")) / "save-escape.json"
    with pytest.raises(PathNotAllowedError):
        svc.save_edit_modify(sid, path=str(denied), field="gold", value=1, confirm=False)


def test_config_allowed_paths_unlock(tmp_path):
    extra = tmp_path / "mods"
    extra.mkdir()
    target = extra / "f.dat"
    cfg = Config({"safety": {"allowed_paths": [str(extra)]}})
    assert cfg.allowed_paths == [str(extra)]
    svc = ModifierService(cfg)
    session = None
    ok = svc._check_file_path(str(target), session=session, purpose="test")
    assert ok.is_absolute()


# ------------------------------------------------------------- backup guard


def test_backup_id_traversal_refused(tmp_path):
    mgr = BackupManager(tmp_path / "backups")
    with pytest.raises(InvalidArgsError):
        mgr.get("../../evil")
    with pytest.raises(InvalidArgsError):
        mgr.get("..\\..\\evil")
    with pytest.raises(InvalidArgsError):
        mgr.get("a/b")
    # a well-formed id just reports not-found
    with pytest.raises(GameModifierError) as ei:
        mgr.get("bak-deadbeef")
    assert ei.value.code == ErrorCode.BACKUP_NOT_FOUND


# ------------------------------------------------------------- load_batch


def test_load_batch_directory_and_size(tmp_path):
    with pytest.raises(BatchError):
        batch_runner.load_batch(str(tmp_path))  # a directory

    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * (batch_runner._MAX_BATCH_BYTES + 1))
    with pytest.raises(BatchError):
        batch_runner.load_batch(str(big))

    bad = tmp_path / "bad.yaml"
    bad.write_text("operations: [unclosed", encoding="utf-8")
    with pytest.raises(BatchError):
        batch_runner.load_batch(str(bad))


# ---------------------------------------------------- staged confirm_code


def test_modify_high_risk_requires_confirm_code(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]

    # preview marks the staged gate explicitly
    preview = svc.modify(session_id=sid, address=hex(CODE), type="int32", value="1234")
    assert preview["applied"] is False
    assert preview["risk"] == "high"
    assert preview["requires_confirm_code"] is True

    # confirm alone is refused
    with pytest.raises(GameModifierError) as ei:
        svc.modify(session_id=sid, address=hex(CODE), type="int32", value="1234", confirm=True)
    assert ei.value.code == ErrorCode.NOT_CONFIRMED
    assert struct.unpack("<i", fake.read(CODE, 4))[0] == 0x0A0B0C0D  # untouched

    # confirm + confirm_code applies
    out = svc.modify(session_id=sid, address=hex(CODE), type="int32", value="1234",
                     confirm=True, confirm_code=True)
    assert out["applied"] is True
    assert struct.unpack("<i", fake.read(CODE, 4))[0] == 1234


def test_modify_normal_risk_needs_no_confirm_code(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    out = svc.modify(session_id=sid, address=hex(DATA), type="int32", value="777", confirm=True)
    assert out["applied"] is True
    assert struct.unpack("<i", fake.read(DATA, 4))[0] == 777


def test_nl_high_risk_confirm_code(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.gold", base_expr=hex(CODE), type="int32")

    with pytest.raises(GameModifierError) as ei:
        svc.nl(session_id=sid, text="将金币设为8888", confirm=True)
    assert ei.value.code == ErrorCode.NOT_CONFIRMED

    out = svc.nl(session_id=sid, text="将金币设为8888", confirm=True, confirm_code=True)
    assert out["applied"] is True
    assert struct.unpack("<i", fake.read(CODE, 4))[0] == 8888


def test_batch_confirm_code_still_unlocks(service, tmp_path):
    """Regression: batch-level confirm_code releases high-risk ops end-to-end."""

    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    ops = tmp_path / "ops.yaml"
    ops.write_text(yaml.safe_dump({"operations": [
        {"modify": {"address": hex(CODE), "type": "int32", "value": "4321"}},
    ]}), encoding="utf-8")

    # without confirm_code: high-risk op is skipped
    out = svc.batch_run(session_id=sid, path=str(ops), confirm=True)
    assert out["results"][0].get("skipped_reason") == "high_risk_requires_confirm_code"
    assert struct.unpack("<i", fake.read(CODE, 4))[0] == 0x0A0B0C0D

    # with confirm_code: applied (also proves the threaded gate is open)
    out = svc.batch_run(session_id=sid, path=str(ops), confirm=True, confirm_code=True)
    assert out["results"][0].get("applied") is True
    assert struct.unpack("<i", fake.read(CODE, 4))[0] == 4321


def test_template_apply_high_risk_target_skipped(service, tmp_config, tmp_path, monkeypatch):
    """One high-risk template target must not abort the whole apply."""

    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.code_addr", base_expr=hex(CODE), type="int32")
    svc.name_set(session_id=sid, name="player.gold", base_expr=hex(DATA), type="int32")

    tdir = tmp_path / "templates"
    tdir.mkdir()
    (tdir / "t.yaml").write_text(yaml.safe_dump({
        "name": "t", "description": "d",
        "options": {"o": {"label": "o", "targets": [
            {"symbol": "player.gold", "type": "int32", "value": 100},
            {"symbol": "player.code_addr", "type": "int32", "value": 200},
        ]}},
    }), encoding="utf-8")
    tmp_config._data.setdefault("paths", {})["user_templates_dir"] = str(tdir)

    out = svc.template_apply(session_id=sid, name="t", option="o", confirm=True)
    by_symbol = {r.get("symbol"): r for r in out["results"]}
    assert by_symbol["player.gold"]["applied"] is True
    risky = by_symbol["player.code_addr"]
    assert risky["skipped_reason"] == "high_risk_requires_confirm_code"
    assert struct.unpack("<i", fake.read(CODE, 4))[0] == 0x0A0B0C0D  # untouched

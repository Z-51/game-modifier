"""Tests for FileBackupManager + the file_snapshot/file_restore service tools.

Covers both storage layouts (flat = historical il_backup, dir = file_snapshot),
manifest/hash integrity, restore flow, the game-process-running guard and the
session file_hashes artifact used for Steam-update stale warnings.
"""

from __future__ import annotations

import hashlib
import json
import struct

import pytest

from game_modifier import service as svc_mod
from game_modifier.errors import ErrorCode, GameModifierError, InvalidArgsError
from game_modifier.memory import process as procmod
from game_modifier.safety import FileBackupManager
from game_modifier.service import ModifierService


# ---------------------------------------------------------------------------
# FileBackupManager (storage layer)
# ---------------------------------------------------------------------------

class TestFileBackupManager:
    def test_dir_layout_create(self, tmp_path):
        src = tmp_path / "save.dat"
        src.write_bytes(b"gold=100")
        mgr = FileBackupManager(tmp_path / "file_backups")

        m = mgr.create(src, label="before-patch", layout="dir", id_prefix="fbk")
        assert m["backup_id"].startswith("fbk-")
        assert m["source"] == str(src)
        assert m["file"] == "save.dat"
        assert m["size"] == 8
        assert m["label"] == "before-patch"
        assert m["sha256"] == hashlib.sha256(b"gold=100").hexdigest()
        assert (mgr.dir / m["backup_id"] / "save.dat").read_bytes() == b"gold=100"
        manifest_on_disk = json.loads(
            (mgr.dir / m["backup_id"] / "manifest.json").read_text(encoding="utf-8"))
        assert manifest_on_disk == m

    def test_flat_layout_create(self, tmp_path):
        src = tmp_path / "Game.dll"
        src.write_bytes(b"\x4d\x5a")
        mgr = FileBackupManager(tmp_path / "file_backups")

        m = mgr.create(src, layout="flat", id_prefix="ilbk")
        assert m["backup_id"].startswith("ilbk-")
        assert (mgr.dir / f"{m['backup_id']}.dll").read_bytes() == b"\x4d\x5a"
        assert (mgr.dir / f"{m['backup_id']}.json").exists()

    def test_create_missing_source_raises(self, tmp_path):
        mgr = FileBackupManager(tmp_path / "file_backups")
        with pytest.raises(FileNotFoundError):
            mgr.create(tmp_path / "nope.dat")

    def test_load_manifest_across_layouts(self, tmp_path):
        src = tmp_path / "a.cfg"
        src.write_bytes(b"x")
        mgr = FileBackupManager(tmp_path / "file_backups")
        flat = mgr.create(src, layout="flat", id_prefix="ilbk")
        dire = mgr.create(src, layout="dir", id_prefix="fbk")

        mf, bf = mgr.load_manifest(flat["backup_id"])
        assert bf.read_bytes() == b"x"
        md, bd = mgr.load_manifest(dire["backup_id"])
        assert bd.read_bytes() == b"x"
        assert mf["backup_id"] == flat["backup_id"]
        assert md["backup_id"] == dire["backup_id"]

    def test_load_manifest_unknown_or_malicious_id(self, tmp_path):
        mgr = FileBackupManager(tmp_path / "file_backups")
        assert mgr.load_manifest("fbk-does-not-exist") is None
        assert mgr.load_manifest("../etc/passwd") is None
        assert mgr.load_manifest("") is None

    def test_list_backups_newest_first(self, tmp_path):
        src = tmp_path / "a.cfg"
        src.write_bytes(b"x")
        mgr = FileBackupManager(tmp_path / "file_backups")
        m1 = mgr.create(src, layout="flat", id_prefix="ilbk")
        m2 = mgr.create(src, layout="dir", id_prefix="fbk")
        listing = mgr.list_backups()
        assert [m["backup_id"] for m in listing] == [m2["backup_id"], m1["backup_id"]]

    def test_verify_detects_corruption(self, tmp_path):
        src = tmp_path / "a.cfg"
        src.write_bytes(b"payload")
        mgr = FileBackupManager(tmp_path / "file_backups")
        m = mgr.create(src, layout="dir")
        _, bfile = mgr.load_manifest(m["backup_id"])
        assert FileBackupManager.verify(m, bfile) is True
        bfile.write_bytes(b"tampered!")
        assert FileBackupManager.verify(m, bfile) is False
        bfile.unlink()
        assert FileBackupManager.verify(m, bfile) is False

    def test_restore_to_source_and_dest(self, tmp_path):
        src = tmp_path / "a.cfg"
        src.write_bytes(b"original")
        mgr = FileBackupManager(tmp_path / "file_backups")
        m = mgr.create(src, layout="dir")
        src.write_bytes(b"modified")
        _, bfile = mgr.load_manifest(m["backup_id"])

        FileBackupManager.restore_to(m, bfile)
        assert src.read_bytes() == b"original"

        other = tmp_path / "elsewhere.cfg"
        FileBackupManager.restore_to(m, bfile, dest=other)
        assert other.read_bytes() == b"original"


# ---------------------------------------------------------------------------
# service layer: file_snapshot / file_restore
# ---------------------------------------------------------------------------

@pytest.fixture
def file_env(tmp_path, tmp_config, fake_backend_factory, monkeypatch):
    region = bytearray(struct.pack("<i", 1) + b"\x00" * 0x40)
    fake = fake_backend_factory(regions={0x200000: region})
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]

    game_file = tmp_path / "game" / "config.ini"
    game_file.parent.mkdir(parents=True)
    game_file.write_bytes(b"[core]\ngold=100\n")
    return service, sid, game_file


def _audit_ops(service, sid) -> set:
    p = service.store.dir / sid / "audit.jsonl"
    if not p.exists():
        return set()
    return {json.loads(line)["op"] for line in p.read_text(encoding="utf-8").splitlines() if line.strip()}


def test_file_snapshot_missing_file(file_env):
    service, sid, _ = file_env
    with pytest.raises(InvalidArgsError):
        service.file_snapshot(session_id=sid, path=str(service.store.dir / "ghost.bin"))


def test_file_snapshot_success_and_artifacts(file_env):
    service, sid, game_file = file_env
    out = service.file_snapshot(session_id=sid, path=str(game_file), label="pre-mod")
    assert out["ok"] is True
    assert out["backup_id"].startswith("fbk-")
    assert out["source"] == str(game_file)
    assert out["sha256"] == hashlib.sha256(b"[core]\ngold=100\n").hexdigest()
    from pathlib import Path
    assert Path(out["file"]).read_bytes() == b"[core]\ngold=100\n"

    # hash + fingerprint recorded for later Steam-update detection
    session = service._load(sid)
    fh = session.engine["artifacts"]["file_hashes"][str(game_file)]
    assert fh["sha256"] == out["sha256"]
    assert fh["backup_id"] == out["backup_id"]
    assert "file_snapshot" in _audit_ops(service, sid)


def test_file_restore_unknown_backup(file_env):
    service, sid, game_file = file_env
    service.file_snapshot(session_id=sid, path=str(game_file))
    with pytest.raises(GameModifierError) as excinfo:
        service.file_restore(session_id=sid, backup_id="fbk-nope")
    assert excinfo.value.code == ErrorCode.BACKUP_NOT_FOUND
    assert excinfo.value.details["known"]  # known ids listed for recovery


def test_file_restore_preview(file_env):
    service, sid, game_file = file_env
    snap = service.file_snapshot(session_id=sid, path=str(game_file))
    out = service.file_restore(session_id=sid, backup_id=snap["backup_id"])
    assert out["applied"] is False
    assert out["dry_run"] is True
    assert out["process_alive"] is True
    # preview touches nothing
    assert game_file.read_bytes() == b"[core]\ngold=100\n"


def test_file_restore_refused_while_process_alive(file_env):
    service, sid, game_file = file_env
    snap = service.file_snapshot(session_id=sid, path=str(game_file))
    with pytest.raises(InvalidArgsError):
        service.file_restore(session_id=sid, backup_id=snap["backup_id"], confirm=True)


def test_file_restore_after_process_exit(file_env, monkeypatch):
    service, sid, game_file = file_env
    snap = service.file_snapshot(session_id=sid, path=str(game_file))
    game_file.write_bytes(b"corrupted by a bad patch")

    monkeypatch.setattr(procmod, "process_exists", lambda pid: False)
    out = service.file_restore(session_id=sid, backup_id=snap["backup_id"], confirm=True)
    assert out["applied"] is True
    assert out["process_alive"] is False
    assert game_file.read_bytes() == b"[core]\ngold=100\n"
    assert "file_restore" in _audit_ops(service, sid)


def test_file_restore_rejects_tampered_backup(file_env, monkeypatch):
    service, sid, game_file = file_env
    snap = service.file_snapshot(session_id=sid, path=str(game_file))
    mgr = service._file_backup_manager(sid)
    _, bfile = mgr.load_manifest(snap["backup_id"])
    bfile.write_bytes(b"tampered backup")

    monkeypatch.setattr(procmod, "process_exists", lambda pid: False)
    with pytest.raises(GameModifierError):
        service.file_restore(session_id=sid, backup_id=snap["backup_id"], confirm=True)


def test_file_hash_stale_info_detects_update(file_env):
    """After the snapshotted file changes on disk, a stale warning is produced."""
    service, sid, game_file = file_env
    service.file_snapshot(session_id=sid, path=str(game_file))
    session = service._load(sid)
    # unchanged -> no warning
    assert service._file_hash_stale_info(session) is None

    game_file.write_bytes(b"[core]\ngold=999999\n")  # simulated Steam update
    session = service._load(sid)
    stale = service._file_hash_stale_info(session)
    assert stale is not None
    assert stale["path"] == str(game_file)
    assert "reason" in stale and "hint" in stale

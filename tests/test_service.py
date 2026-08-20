"""Service-level integration using the in-memory fake backend."""

from __future__ import annotations

import struct

import pytest

from game_modifier.memory import process as procmod
from game_modifier.memory.base import ModuleInfo
from game_modifier.errors import NeedsScanError
from game_modifier.service import ModifierService


@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    # a single shared fake backend so writes persist across service calls
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x1000)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={0x200000: region}, modules=[mod], name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


def test_attach_and_modify_flow(service):
    svc, fake = service
    info = svc.attach(pid=4242)
    sid = info["session_id"]
    assert info["anti_cheat"]["detected"] is False

    # dry-run
    dry = svc.modify(session_id=sid, address="0x200000", type="int32", value="9999", confirm=False)
    assert dry["applied"] is False and dry["dry_run"] is True
    assert struct.unpack("<i", fake.read(0x200000, 4))[0] == 1000  # unchanged

    # confirmed
    res = svc.modify(session_id=sid, address="0x200000", type="int32", value="9999", confirm=True)
    assert res["applied"] is True and res["verified_value"] == 9999
    assert res["backup_id"]
    assert struct.unpack("<i", fake.read(0x200000, 4))[0] == 9999

    # read back
    rd = svc.read(session_id=sid, address="0x200000", type="int32")
    assert rd["value"] == 9999


def test_nl_via_symbol(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.gold", base_expr="0x200000", type="int32")

    out = svc.nl(session_id=sid, text="将金币设置为1234", confirm=True)
    assert out["ok"] is True and out["verified_value"] == 1234
    assert struct.unpack("<i", fake.read(0x200000, 4))[0] == 1234


def test_nl_needs_scan_when_unmapped(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    with pytest.raises(NeedsScanError):
        svc.nl(session_id=sid, text="将金币设为1", confirm=True)


def test_template_apply_reports_missing_then_applies(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]

    # before mapping: player.gold missing
    res = svc.template_apply(session_id=sid, name="rpg", option="set_gold", params={"amount": 555}, confirm=True)
    assert "player.gold" in res["missing_symbols"]

    # after mapping it applies
    svc.name_set(session_id=sid, name="player.gold", base_expr="0x200000", type="int32")
    res2 = svc.template_apply(session_id=sid, name="rpg", option="set_gold", params={"amount": 555}, confirm=True)
    assert res2["missing_symbols"] == []
    assert struct.unpack("<i", fake.read(0x200000, 4))[0] == 555


def test_freeze_registration_and_backup_restore(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.hp", base_expr="0x200000", type="int32")

    # set to 42 (creates a backup of original 1000), then restore
    res = svc.modify(session_id=sid, symbol="player.hp", value="42", confirm=True, freeze=True)
    assert struct.unpack("<i", fake.read(0x200000, 4))[0] == 42
    assert svc.freeze_list(session_id=sid)["count"] == 1

    restored = svc.backup_restore(session_id=sid, backup_id=res["backup_id"])
    assert restored["restored_count"] == 1
    assert struct.unpack("<i", fake.read(0x200000, 4))[0] == 1000


def test_backup_create_by_symbol(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.gold", base_expr="0x200000", type="int32")
    out = svc.backup_create(session_id=sid, targets=[{"symbol": "player.gold"}], label="manual")
    assert out["entries"] == 1
    listed = svc.backup_list(session_id=sid)
    assert any(b["id"] == out["backup_id"] for b in listed["backups"])


def test_attach_reports_admin_flag(service):
    svc, _ = service
    info = svc.attach(pid=4242)
    assert "is_admin" in info

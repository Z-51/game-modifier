"""Tests for the save_edit module (archive-based games) and session routing."""

from __future__ import annotations

import base64
import json

import pytest

from game_modifier.errors import (
    ErrorCode,
    SaveEditRequiredError,
    SaveFormatUnsupportedError,
)
from game_modifier.save_edit import detect_saves, load_save, modify_save
from game_modifier.save_edit.renpy import RenPyHandler
from game_modifier.session import Session


def _write_save(path, payload, *, b64=False):
    text = json.dumps(payload)
    if b64:
        text = base64.b64encode(text.encode("utf-8")).decode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_rmmz_detect_saves(tmp_path):
    _write_save(tmp_path / "save" / "file1.rmmzsave", {"gold": 100})
    _write_save(tmp_path / "www" / "save" / "file1.json", {"gold": 5})
    saves = detect_saves(str(tmp_path), "rpg-maker")
    paths = [s["path"] for s in saves]
    assert len(saves) == 2
    assert any(p.endswith("file1.rmmzsave") for p in paths)
    assert any(p.endswith("file1.json") for p in paths)
    assert all(s["editable"] for s in saves)


def test_rmmz_load_base64(tmp_path):
    p = tmp_path / "file2.rmmzsave"
    _write_save(p, {"party": {"gold": 250}}, b64=True)
    loaded = load_save(str(p))
    assert loaded["editable"] is True
    assert loaded["encoding"] == "base64"
    assert loaded["data"]["party"]["gold"] == 250


def test_rmmz_modify_field(tmp_path):
    p = tmp_path / "file1.rmmzsave"
    _write_save(p, {"party": {"gold": 100, "items": []}})
    res = modify_save(str(p), "gold", 9999, confirm=True)
    assert res["ok"] is True
    assert res["found"] is True
    assert res["old_value"] == 100
    assert res["new_value"] == 9999
    assert json.loads(p.read_text(encoding="utf-8"))["party"]["gold"] == 9999


def test_rmmz_modify_dry_run(tmp_path):
    p = tmp_path / "file1.rmmzsave"
    _write_save(p, {"gold": 100})
    res = modify_save(str(p), "gold", 5)
    assert res["dry_run"] is True
    assert res["applied"] is False
    # file untouched, no backup
    assert json.loads(p.read_text(encoding="utf-8"))["gold"] == 100
    assert not (tmp_path / "file1.rmmzsave.bak").exists()


def test_rmmz_modify_confirm_writes(tmp_path):
    p = tmp_path / "file1.rmmzsave"
    _write_save(p, {"gold": 100})
    res = modify_save(str(p), "gold", "7777", confirm=True)
    assert res["applied"] is True
    assert res["dry_run"] is False
    assert json.loads(p.read_text(encoding="utf-8"))["gold"] == 7777
    bak = tmp_path / "file1.rmmzsave.bak"
    assert bak.exists()
    assert json.loads(bak.read_text(encoding="utf-8"))["gold"] == 100
    assert res["backup"] == str(bak)


def test_renpy_detect_saves(tmp_path):
    saves_dir = tmp_path / "game" / "saves"
    saves_dir.mkdir(parents=True)
    (saves_dir / "1-1-LT1.save").write_bytes(b"\x80\x02fake-pickle")
    saves = detect_saves(str(tmp_path), "renpy")
    assert len(saves) == 1
    assert saves[0]["path"].endswith("1-1-LT1.save")
    assert saves[0]["editable"] is False


def test_renpy_load_not_editable(tmp_path):
    p = tmp_path / "1-1-LT1.save"
    p.write_bytes(b"\x80\x02fake-pickle")
    loaded = RenPyHandler().load(str(p))
    assert loaded["editable"] is False
    assert "pickle" in loaded["reason"]
    # modify_save must refuse instead of corrupting the pickle
    with pytest.raises(SaveFormatUnsupportedError):
        modify_save(str(p), "gold", 1, confirm=True)


def test_session_save_edit_info_persists():
    info = {"required": True, "engine": "rpg-maker", "note": "use save-edit"}
    session = Session(id="s1", pid=4242, save_edit_info=info)
    restored = Session.from_dict(session.to_dict())
    assert restored.save_edit_info == info
    # older session files without the field still load
    legacy = session.to_dict()
    legacy.pop("save_edit_info")
    assert Session.from_dict(legacy).save_edit_info == {}


def test_unknown_engine_no_saves(tmp_path):
    assert detect_saves(str(tmp_path), "unity-il2cpp") == []
    assert detect_saves(str(tmp_path), "") == []


def test_error_codes_exist():
    assert ErrorCode.SAVE_EDIT_REQUIRED.value == "E_SAVE_EDIT_REQUIRED"
    assert ErrorCode.SAVE_FORMAT_UNSUPPORTED.value == "E_SAVE_FORMAT_UNSUPPORTED"
    err = SaveEditRequiredError()
    assert err.code == ErrorCode.SAVE_EDIT_REQUIRED
    assert "file-based saves" in err.message
    err = SaveFormatUnsupportedError()
    assert err.code == ErrorCode.SAVE_FORMAT_UNSUPPORTED
    assert err.to_dict()["code"] == "E_SAVE_FORMAT_UNSUPPORTED"

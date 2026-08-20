"""Tests for NW.js / RPG Maker / Ren'Py weighted engine detection."""

from __future__ import annotations

from game_modifier import engines
from game_modifier.engines import nwjs


# -------------------------------------------------------- module detection
def test_detect_nwjs_from_nw_dll_module():
    res = engines.detect(modules=["nw.dll", "other.dll"])

    assert res["engine"] == "nwjs"
    assert res["confidence"] >= 0.9
    assert "module:nw.dll" in res["evidence"]


# ----------------------------------------------------- filesystem detection
def test_detect_nwjs_from_filesystem(tmp_path):
    (tmp_path / "nw.dll").write_text("x", encoding="utf-8")
    (tmp_path / "index.html").write_text("<html></html>", encoding="utf-8")

    res = engines.detect(target=str(tmp_path))
    assert res["engine"] == "nwjs"
    assert res["confidence"] >= 0.88


def test_nwjs_beats_unreal_pak(tmp_path):
    # NW.js ships Chromium resource .pak files which must NOT be mistaken
    # for Unreal content paks
    (tmp_path / "nw.dll").write_text("x", encoding="utf-8")
    (tmp_path / "resources.pak").write_text("x", encoding="utf-8")

    res = engines.detect(target=str(tmp_path))
    assert res["engine"] == "nwjs"
    assert res["engine"] != "unreal"


def test_rpg_maker_from_rmmz_core(tmp_path):
    js_dir = tmp_path / "www" / "js"
    js_dir.mkdir(parents=True)
    (js_dir / "rmmz_core.js").write_text("// core", encoding="utf-8")

    res = engines.detect(target=str(tmp_path))
    assert res["engine"] == "rpg-maker"
    assert res["save_edit"] is True


def test_rpg_maker_with_rmmzsave(tmp_path):
    (tmp_path / "file1.rmmzsave").write_text("x", encoding="utf-8")

    res = engines.detect(target=str(tmp_path))
    assert res["engine"] == "rpg-maker"


def test_renpy_from_directory(tmp_path):
    (tmp_path / "renpy").mkdir()
    (tmp_path / "game").mkdir()

    res = engines.detect(target=str(tmp_path))
    assert res["engine"] == "renpy"
    assert res["save_edit"] is True


def test_pak_alone_low_confidence(tmp_path):
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "test.pak").write_text("x", encoding="utf-8")

    res = engines.detect(target=str(tmp_path))
    assert res["engine"] == "unreal"
    assert res["confidence"] <= 0.4


# ------------------------------------------------------ regression guards
def test_existing_unity_detection(tmp_path):
    (tmp_path / "GameAssembly.dll").write_text("x", encoding="utf-8")

    res = engines.detect(target=str(tmp_path))
    assert res["engine"] == "unity-il2cpp"


def test_existing_unreal_shipping(tmp_path):
    (tmp_path / "Game-Win64-Shipping.exe").write_text("x", encoding="utf-8")

    res = engines.detect(target=str(tmp_path))
    assert res["engine"] == "unreal"
    assert res["confidence"] >= 0.9


def test_unknown_engine_empty_dir(tmp_path):
    res = engines.detect(target=str(tmp_path))
    assert res["engine"] == "unknown"


# --------------------------------------------------------------- internals
def test_scan_filesystem_none_when_empty(tmp_path):
    assert nwjs.scan_filesystem(tmp_path) is None


def test_detect_from_modules_none_without_nwjs():
    assert nwjs.detect_from_modules(["kernel32.dll", "user32.dll"]) is None
    assert nwjs.detect_from_modules(None) is None

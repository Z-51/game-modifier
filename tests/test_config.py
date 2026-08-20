"""Configuration merge chain, TOML loading and typed accessors."""

from __future__ import annotations

import pathlib
from pathlib import Path

import pytest

from game_modifier.config import Config, _deep_merge, _load_toml, load_config


# ------------------------------------------------------------------ deep merge
def test_deep_merge_nested_dicts():
    base = {"safety": {"dry_run": True, "auto_backup": True}, "scan": {"alignment": 1}}
    overlay = {"safety": {"dry_run": False}, "output": {"format": "human"}}

    merged = _deep_merge(base, overlay)

    # nested keys are merged, not replaced wholesale
    assert merged["safety"] == {"dry_run": False, "auto_backup": True}
    assert merged["scan"] == {"alignment": 1}
    assert merged["output"] == {"format": "human"}
    # inputs are untouched
    assert base["safety"]["dry_run"] is True


def test_deep_merge_non_dict_override():
    base = {"tools": {"radare2": "r2"}, "list": [1, 2], "n": 1}
    overlay = {"tools": "not-a-dict", "list": [3], "n": None}

    merged = _deep_merge(base, overlay)

    assert merged["tools"] == "not-a-dict"
    assert merged["list"] == [3]
    assert merged["n"] is None


def test_deep_merge_empty_dicts():
    assert _deep_merge({}, {}) == {}
    assert _deep_merge({"a": 1}, {}) == {"a": 1}
    assert _deep_merge({}, {"a": 1}) == {"a": 1}


# ---------------------------------------------------------------- toml loading
def test_load_toml_valid_file(tmp_path):
    path = tmp_path / "cfg.toml"
    path.write_text(
        '[safety]\ndry_run = false\n\n[scan]\nmax_results = 42\n\n[output]\nformat = "human"\n',
        encoding="utf-8",
    )

    data = _load_toml(path)

    assert data["safety"]["dry_run"] is False
    assert data["scan"]["max_results"] == 42
    assert data["output"]["format"] == "human"


def test_load_toml_file_not_found(tmp_path, monkeypatch):
    """``_load_toml`` itself raises; callers guard with ``exists()``."""

    missing = tmp_path / "nope.toml"
    with pytest.raises(FileNotFoundError):
        _load_toml(missing)

    # the optional layers of load_config simply contribute nothing when absent
    monkeypatch.setenv("GAME_MODIFIER_CONFIG", str(missing))
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: tmp_path / "home"))
    cfg = load_config()
    assert isinstance(cfg, Config)
    assert cfg.output_format == "json"  # packaged default survived


# ---------------------------------------------------------------- Config.get
def test_config_get_nested_keys():
    cfg = Config({"a": {"b": {"c": 7}}})

    assert cfg.get("a", "b", "c") == 7
    assert cfg.get("a", "b") == {"c": 7}
    assert cfg.get("a") == {"b": {"c": 7}}


def test_config_get_missing_returns_default():
    cfg = Config({"a": {"b": 1}})

    assert cfg.get("missing") is None
    assert cfg.get("a", "missing", default="fallback") == "fallback"
    # walking *through* a non-dict must not explode
    assert cfg.get("a", "b", "c", default="fallback") == "fallback"
    assert cfg.get(default="whole") == {"a": {"b": 1}}


def test_config_section_exists():
    cfg = Config({"safety": {"dry_run": True}})

    section = cfg.section("safety")
    assert section == {"dry_run": True}
    # section returns a copy, mutating it must not affect the config
    section["dry_run"] = False
    assert cfg.get("safety", "dry_run") is True


def test_config_section_not_exists():
    cfg = Config({"safety": {"dry_run": True}, "scalar": 5})

    assert cfg.section("missing") == {}
    assert cfg.section("scalar") == {}  # non-dict node degrades to {}


# ------------------------------------------------------------- merge chain
def test_load_config_merge_chain(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".game-modifier").mkdir(parents=True)
    (home / ".game-modifier" / "config.toml").write_text(
        '[safety]\ndry_run = false\n\n[output]\nformat = "human"\n\n[scan]\nmax_results = 11\n',
        encoding="utf-8",
    )
    env_cfg = tmp_path / "env.toml"
    env_cfg.write_text('[output]\nformat = "json-pretty"\n\n[scan]\nmax_results = 22\n', encoding="utf-8")
    explicit = tmp_path / "explicit.toml"
    explicit.write_text("[scan]\nmax_results = 33\n", encoding="utf-8")

    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: home))
    monkeypatch.setenv("GAME_MODIFIER_CONFIG", str(env_cfg))

    cfg = load_config(str(explicit))

    assert cfg.scan_max_results == 33        # layer 4 wins
    assert cfg.output_format == "json-pretty"  # layer 3 wins over layer 2
    assert cfg.dry_run is False             # layer 2 wins over packaged default
    assert cfg.auto_backup is True          # untouched packaged default (layer 1)


def test_load_config_explicit_missing_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: tmp_path / "home"))
    monkeypatch.delenv("GAME_MODIFIER_CONFIG", raising=False)

    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "absent.toml"))


# --------------------------------------------------------------- accessors
def test_config_all_properties(tmp_path):
    cfg = Config(
        {
            "safety": {
                "dry_run": False,
                "block_anti_cheat": False,
                "auto_backup": False,
                "require_writable_region": False,
            },
            "scan": {"max_results": 5, "chunk_size": 128, "alignment": 4, "max_region_bytes": 999},
            "output": {"format": "human"},
            "paths": {
                "home": str(tmp_path / "h"),
                "sessions_dir": str(tmp_path / "s"),
                "user_templates_dir": str(tmp_path / "t"),
            },
            "tools": {"radare2": "C:/r2.exe", "search_dirs": {"extra": [tmp_path / "x"]}},
        }
    )

    assert cfg.dry_run is False
    assert cfg.block_anti_cheat is False
    assert cfg.auto_backup is False
    assert cfg.require_writable_region is False
    assert cfg.output_format == "human"
    assert cfg.scan_max_results == 5
    assert cfg.scan_chunk_size == 128
    assert cfg.scan_alignment == 4
    assert cfg.scan_max_region_bytes == 999
    assert cfg.tool_path("radare2") == "C:/r2.exe"
    assert cfg.tool_path("missing") == ""
    assert cfg.tool_search_dirs() == [str(tmp_path / "x")]
    assert cfg.home_dir == tmp_path / "h"
    assert cfg.sessions_dir == tmp_path / "s"
    assert cfg.user_templates_dir == tmp_path / "t"
    assert cfg.as_dict()["output"] == {"format": "human"}


def test_config_property_defaults_when_empty():
    cfg = Config({})

    assert cfg.dry_run is True
    assert cfg.block_anti_cheat is True
    assert cfg.auto_backup is True
    assert cfg.require_writable_region is True
    assert cfg.output_format == "json"
    assert cfg.scan_max_results == 20000
    assert cfg.scan_chunk_size == 4 * 1024 * 1024
    assert cfg.scan_alignment == 4
    assert cfg.scan_max_region_bytes == 0
    assert cfg.tool_search_dirs() == []


def test_config_alignment_never_below_one():
    assert Config({"scan": {"alignment": 0}}).scan_alignment == 1
    assert Config({"scan": {"alignment": -8}}).scan_alignment == 1


def test_config_paths_derive_from_home(tmp_path):
    cfg = Config({"paths": {"home": str(tmp_path / "gm")}})

    assert cfg.sessions_dir == tmp_path / "gm" / "sessions"
    assert cfg.user_templates_dir == tmp_path / "gm" / "templates"


def test_config_ensure_dirs_creates_tree(tmp_path):
    cfg = Config({"paths": {"home": str(tmp_path / "gm")}})

    cfg.ensure_dirs()

    assert cfg.home_dir.is_dir()
    assert cfg.sessions_dir.is_dir()
    assert cfg.user_templates_dir.is_dir()
    # idempotent
    cfg.ensure_dirs()


def test_config_home_dir_falls_back_to_user_home(tmp_path, monkeypatch):
    monkeypatch.setattr(pathlib.Path, "home", staticmethod(lambda: tmp_path / "userhome"))

    assert Config({}).home_dir == Path(tmp_path / "userhome") / ".game-modifier"

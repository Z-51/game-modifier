"""Service-layer tests for UE structure introspection (phases 2+3).

Reuses the synthetic UE memory image from test_ue_introspect.py and the
monkeypatch-``get_backend`` pattern from test_service.py.
"""

from __future__ import annotations

import json

import pytest

from test_ue_introspect import (
    FNAME_HANDLE,
    GNAMES,
    GOBJECTS,
    N_OBJECTS,
    make_ue_backend,
)

from game_modifier import mcp_server
from game_modifier.cli import build_parser, dispatch
from game_modifier.config import Config
from game_modifier.errors import ErrorCode, LayoutUnsupportedError
from game_modifier.memory import process as procmod
from game_modifier.service import ModifierService
from game_modifier.session import Session
from test_mcp_extended import _tool_names


@pytest.fixture
def ue_service(tmp_path, monkeypatch):
    cfg = Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": True,
                   "require_writable_region": True},
        "scan": {"max_results": 1000, "chunk_size": 4096, "alignment": 1, "max_region_bytes": 0},
        "output": {"format": "json"},
        "paths": {"home": str(tmp_path / ".game-modifier")},
        # match the synthetic image: 25 items per chunk, 0x18 stride
        "ue": {"item_stride": 24, "objects_per_chunk": 25, "max_chunks": 512,
               "probe_items": 64, "max_objects": 100000, "batch_gap": 256},
    })
    fake = make_ue_backend()

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(cfg), fake


def _attach(svc) -> str:
    return svc.attach(pid=4242)["session_id"]


# --------------------------------------------------------------- introspect
def test_ue_introspect_persists_layout(ue_service):
    svc, _ = ue_service
    sid = _attach(svc)
    res = svc.ue_introspect(session_id=sid, gobjects=hex(GOBJECTS), gnames=hex(GNAMES))
    assert res["verdict"] == "confirmed"
    assert res["session_id"] == sid
    # non-unreal session engine -> warning but not blocking
    assert "engine_warning" in res

    # persisted into the session file
    reloaded = svc.store.load(sid)
    entry = reloaded.introspect["ue"]
    assert entry["verdict"] == "confirmed"
    assert entry["confidence"] > 0.8
    assert entry["created_at"] > 0
    assert entry["resolved"]["gobjects_array"] == hex(GOBJECTS)
    assert "hypotheses" in entry


def test_ue_introspect_failed_not_persisted(ue_service):
    svc, _ = ue_service
    sid = _attach(svc)
    res = svc.ue_introspect(session_id=sid, gobjects=hex(0x99990000 & 0xFFFFF | 0x400000))
    # unmapped address inside the fake region: probe fails gracefully
    assert res["verdict"] in ("failed", "partial")
    reloaded = svc.store.load(sid)
    if res["verdict"] == "failed":
        assert "ue" not in reloaded.introspect


def test_ue_introspect_cache_hit(ue_service):
    svc, fake = ue_service
    sid = _attach(svc)
    first = svc.ue_introspect(session_id=sid, gobjects=hex(GOBJECTS), gnames=hex(GNAMES))
    assert first["verdict"] == "confirmed"
    reads_after_probe = fake.read_calls

    # second call serves the cache without touching the backend
    second = svc.ue_introspect(session_id=sid, gobjects=hex(GOBJECTS), gnames=hex(GNAMES))
    assert second.get("cached") is True
    assert second["verdict"] == "confirmed"
    assert second["resolved"] == first["resolved"]
    assert fake.read_calls == reads_after_probe

    # force re-probes
    third = svc.ue_introspect(session_id=sid, gobjects=hex(GOBJECTS), gnames=hex(GNAMES), force=True)
    assert third.get("cached") is not True
    assert third["verdict"] == "confirmed"
    assert fake.read_calls > reads_after_probe


# -------------------------------------------------------------------- actors
def test_ue_actors_without_layout_raises(ue_service):
    svc, _ = ue_service
    sid = _attach(svc)
    with pytest.raises(LayoutUnsupportedError) as excinfo:
        svc.ue_actors(session_id=sid)
    assert excinfo.value.code == ErrorCode.LAYOUT_UNSUPPORTED
    assert "ue introspect" in (excinfo.value.hint or "")


def test_ue_actors_with_layout(ue_service):
    svc, _ = ue_service
    sid = _attach(svc)
    svc.ue_introspect(session_id=sid, gobjects=hex(GOBJECTS), gnames=hex(GNAMES))

    res = svc.ue_actors(session_id=sid)
    assert res["by_class"] == {"MyActor": N_OBJECTS}
    assert res["totals"]["actors"] == N_OBJECTS
    assert res["session_id"] == sid

    listed = svc.ue_actors(session_id=sid, limit=10, list_results=True, name_filter="instance")
    assert listed["truncated"] is True
    assert len(listed["actors"]) == 10
    assert listed["actors"][0]["class_name"] == "MyActor"


def test_ue_actors_explicit_gobjects_temporary_probe(ue_service):
    svc, _ = ue_service
    sid = _attach(svc)
    # cache the GNames dialect first, then probe GObjects ad-hoc
    svc.ue_introspect(session_id=sid, gnames=hex(GNAMES))
    res = svc.ue_actors(session_id=sid, gobjects=hex(GOBJECTS))
    assert res["by_class"] == {"MyActor": N_OBJECTS}


# --------------------------------------------------------------------- fname
def test_ue_fname_read_address(ue_service):
    svc, _ = ue_service
    sid = _attach(svc)
    svc.ue_introspect(session_id=sid, gnames=hex(GNAMES))
    out = svc.ue_fname(session_id=sid, address=hex(FNAME_HANDLE))
    assert out["comparison_index"] == 2
    assert out["number"] == 7
    assert out["decoded"] == "MyActor"  # cache has a GNames layout


def test_ue_fname_decode_index(ue_service):
    svc, _ = ue_service
    sid = _attach(svc)
    svc.ue_introspect(session_id=sid, gnames=hex(GNAMES))
    out = svc.ue_fname(session_id=sid, index=1)
    assert out["decoded"] == "Actor"


def test_ue_fname_compare(ue_service):
    svc, _ = ue_service
    sid = _attach(svc)
    svc.ue_introspect(session_id=sid, gnames=hex(GNAMES))
    same = svc.ue_fname(session_id=sid, index=2, compare_index=2)
    assert same["compare"]["equal"] is True
    assert same["compare"]["basis"] == "index"
    assert same["compare"]["decoded_other"] == "MyActor"
    diff = svc.ue_fname(session_id=sid, index=2, compare_index=3)
    assert diff["compare"]["equal"] is False
    assert diff["compare"]["decoded_other"] == "Instance"


def test_ue_fname_decode_without_layout_raises(ue_service):
    svc, _ = ue_service
    sid = _attach(svc)
    with pytest.raises(LayoutUnsupportedError):
        svc.ue_fname(session_id=sid, index=2)


def test_ue_fname_requires_target(ue_service):
    svc, _ = ue_service
    sid = _attach(svc)
    with pytest.raises(Exception) as excinfo:
        svc.ue_fname(session_id=sid)
    assert getattr(excinfo.value, "code", None) == ErrorCode.INVALID_ARGS


# ---------------------------------------------------------- session compat
def test_session_old_json_compat(tmp_path):
    """A session JSON written before the introspect field loads fine."""
    old = {
        "id": "legacy-1", "pid": 1, "process_name": "game.exe",
        "exe_path": "", "arch": "x64", "platform": "windows",
        "engine": {}, "anti_cheat": {}, "modules": {}, "symbols": {},
        "freezes": [], "scan": {}, "save_edit_info": {},
    }
    session = Session.from_dict(old)
    assert session.introspect == {}
    # round-trip: to_dict now carries the field
    assert session.to_dict()["introspect"] == {}

    # via the store as well
    from game_modifier.session import SessionStore
    store = SessionStore(tmp_path)
    store.dir.mkdir(parents=True, exist_ok=True)
    (store.dir / "legacy-1.json").write_text(json.dumps(old), encoding="utf-8")
    loaded = store.load("legacy-1")
    assert loaded.introspect == {}


# ------------------------------------------------------------------- MCP/CLI
def test_mcp_tool_count(tmp_path):
    cfg = tmp_path / "cfg.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    server = mcp_server.build_server(str(cfg))
    names = _tool_names(server)
    assert {"ue_introspect", "ue_actors", "ue_fname",
            "watch_run", "watch_start", "watch_stop", "watch_report"} <= names
    assert len(names) >= 36  # containment-based: parallel feature additions must not break this

    ro = mcp_server.build_server(str(cfg), profile="readonly")
    ro_names = _tool_names(ro)
    assert {"ue_introspect", "ue_actors", "ue_fname", "watch_run", "watch_report"} <= ro_names  # read-only profile includes them
    assert len(ro_names) >= 25


def test_cli_ue_parsing():
    p = build_parser()

    a = p.parse_args(["ue", "introspect", "--session", "s1",
                      "--gobjects", "Game.exe+0x1D2E500", "--gnames", "0x7ff0000",
                      "--gobjects-pattern", "48 8B ??", "--gnames-pattern", "AA BB", "--force"])
    assert a.command == "ue" and a.ue_action == "introspect"
    assert a.session == "s1" and a.gobjects == "Game.exe+0x1D2E500"
    assert a.gnames == "0x7ff0000"
    assert a.gobjects_pattern == "48 8B ??" and a.gnames_pattern == "AA BB"
    assert a.force is True

    a = p.parse_args(["ue", "actors", "--session", "s1", "--gobjects", "0x400",
                      "--limit", "50", "--filter", "inst", "--class", "MyAct", "--list"])
    assert a.ue_action == "actors"
    assert a.limit == 50 and a.name_filter == "inst"
    assert a.class_filter == "MyAct" and a.list_results is True

    a = p.parse_args(["ue", "fname", "--session", "s1",
                      "--address", "0x1000", "--index", "2", "--compare-index", "3"])
    assert a.ue_action == "fname"
    assert a.address == "0x1000" and a.index == 2 and a.compare_index == 3


def test_cli_ue_dispatch():
    p = build_parser()
    calls = {}

    class StubService:
        def ue_introspect(self, **kw):
            calls["introspect"] = kw
            return {"verdict": "confirmed"}

        def ue_actors(self, **kw):
            calls["actors"] = kw
            return {"by_class": {}}

        def ue_fname(self, **kw):
            calls["fname"] = kw
            return {"comparison_index": 2}

    r = dispatch(StubService(), p.parse_args(["ue", "introspect", "--session", "s1", "--gobjects", "0x1"]))
    assert r.command == "ue.introspect" and r.data["verdict"] == "confirmed"
    assert calls["introspect"]["gobjects"] == "0x1"

    r = dispatch(StubService(), p.parse_args(["ue", "actors", "--session", "s1", "--limit", "5"]))
    assert r.command == "ue.actors"
    assert calls["actors"]["limit"] == 5

    r = dispatch(StubService(), p.parse_args(["ue", "fname", "--session", "s1", "--index", "7"]))
    assert r.command == "ue.fname"
    assert calls["fname"]["index"] == 7

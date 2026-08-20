"""Session data model (Symbol / ScanState / Session) and the on-disk store."""

from __future__ import annotations

import json

import pytest

from game_modifier.errors import SessionNotFoundError
from game_modifier.session import ScanState, Session, SessionStore, Symbol


@pytest.fixture
def store(tmp_path):
    return SessionStore(tmp_path / "sessions")


def _session(**kwargs) -> Session:
    defaults = dict(id="game-abcd1234", pid=4242, process_name="game.exe", arch="x64")
    defaults.update(kwargs)
    return Session(**defaults)


# --------------------------------------------------------------------- Symbol
def test_symbol_to_dict():
    sym = Symbol(name="player.gold", base_expr="GameAssembly.dll+0x1234", offsets=[0x10, 0x20],
                 type="int32", description="gold amount")

    assert sym.to_dict() == {
        "name": "player.gold",
        "base_expr": "GameAssembly.dll+0x1234",
        "offsets": ["0x10", "0x20"],  # hex strings for human/agent readability
        "type": "int32",
        "description": "gold amount",
    }


def test_symbol_defaults():
    sym = Symbol(name="hp", base_expr="0x400000")

    assert sym.offsets == []
    assert sym.type == "int32"
    assert sym.description == ""


def test_symbol_roundtrip():
    """set_symbol stores raw ints so get_symbol can rebuild an identical Symbol."""

    sym = Symbol(name="player.hp", base_expr="mod.dll+0x10", offsets=[0x8, 0x18], type="float", description="hp")
    session = _session()

    session.set_symbol(sym)
    restored = session.get_symbol("player.hp")

    assert restored == sym
    # and it survives a JSON round trip of the whole session
    revived = Session.from_dict(json.loads(json.dumps(session.to_dict()))).get_symbol("player.hp")
    assert revived == sym


# ------------------------------------------------------------------ ScanState
def test_scan_state_to_json():
    state = ScanState(type="int32", comparator="exact", count=2, truncated=True,
                      addresses=[0x1000, 0x2000], values={0x1000: 100, 0x2000: 200})

    assert state.to_json() == {
        "type": "int32",
        "comparator": "exact",
        "count": 2,
        "truncated": True,
        "addresses": [0x1000, 0x2000],
        "values": {"4096": 100, "8192": 200},  # JSON object keys must be strings
    }


def test_scan_state_from_json():
    state = ScanState.from_json(
        {
            "type": "float",
            "comparator": "between",
            "count": "1",
            "truncated": 1,
            "addresses": ["4096"],
            "values": {"4096": 1.5},
        }
    )

    assert state.type == "float"
    assert state.comparator == "between"
    assert state.count == 1
    assert state.truncated is True
    assert state.addresses == [4096]
    assert state.values == {4096: 1.5}


def test_scan_state_from_json_empty_gives_defaults():
    state = ScanState.from_json({})

    assert (state.type, state.comparator, state.count, state.truncated) == ("", "", 0, False)
    assert state.addresses == [] and state.values == {}


def test_scan_state_json_roundtrip():
    state = ScanState(type="int64", comparator="gt", count=1, addresses=[7], values={7: 9})

    assert ScanState.from_json(state.to_json()) == state


# ------------------------------------------------------------------- Session
def test_session_set_get_symbol():
    session = _session()

    assert session.get_symbol("nope") is None

    session.set_symbol(Symbol(name="gold", base_expr="0x10", offsets=[0x4]))
    assert session.symbols["gold"]["offsets"] == [0x4]
    assert session.get_symbol("gold").base_expr == "0x10"

    # setting the same name overwrites
    session.set_symbol(Symbol(name="gold", base_expr="0x20", type="int64"))
    assert len(session.symbols) == 1
    assert session.get_symbol("gold").type == "int64"


def test_session_to_from_dict():
    session = _session(exe_path="C:/games/game.exe", platform="windows",
                       engine={"engine": "unity-il2cpp"}, anti_cheat={"detected": False},
                       modules={"game.exe": {"base": 0x400000, "size": 16, "path": "C:/games/game.exe"}},
                       freezes=[{"label": "hp", "address": 0x1000, "type": "int32", "value": 100}],
                       scan=ScanState(type="int32", count=1, addresses=[0x1000], values={0x1000: 100}))
    session.set_symbol(Symbol(name="gold", base_expr="game.exe+0x10", offsets=[0x8]))

    data = session.to_dict()
    assert data["scan"]["values"] == {"4096": 100}

    revived = Session.from_dict(json.loads(json.dumps(data)))

    assert revived.id == session.id
    assert revived.pid == session.pid
    assert revived.process_name == "game.exe"
    assert revived.exe_path == "C:/games/game.exe"
    assert revived.engine == {"engine": "unity-il2cpp"}
    assert revived.anti_cheat == {"detected": False}
    assert revived.modules == session.modules
    assert revived.freezes == session.freezes
    assert revived.scan == session.scan
    assert revived.get_symbol("gold").offsets == [0x8]


def test_session_from_dict_applies_defaults():
    revived = Session.from_dict({"id": "s1", "pid": "77"})

    assert revived.pid == 77
    assert revived.arch == "x64"
    assert revived.process_name == ""
    assert revived.scan == ScanState()
    assert revived.created_at > 0


def test_session_touch_updates_timestamp():
    session = _session(updated_at=0.0)

    session.touch()

    assert session.updated_at > 0.0


def test_session_summary_shape():
    session = _session(engine={"engine": "unreal"}, scan=ScanState(count=5))
    session.set_symbol(Symbol(name="gold", base_expr="0x1"))

    summary = session.summary()

    assert summary["session_id"] == session.id
    assert summary["pid"] == 4242
    assert summary["process"] == "game.exe"
    assert summary["engine"] == "unreal"
    assert summary["symbols"] == 1
    assert summary["scan_candidates"] == 5
    assert summary["updated_at"] == session.updated_at


def test_session_summary_engine_none_when_unset():
    assert _session().summary()["engine"] is None


# -------------------------------------------------------------- SessionStore
def test_session_store_new_id(store):
    sid = store.new_id("MyGame.exe")

    stub, _, suffix = sid.partition("-")
    assert stub == "MyGame"
    assert len(suffix) == 8
    # unsafe characters are stripped and empty names get a stub
    assert store.new_id("my game!.exe").startswith("mygame-")
    assert store.new_id("").startswith("proc-")
    assert store.new_id(None).startswith("proc-")
    # ids are unique per call
    assert store.new_id("MyGame.exe") != sid


def test_session_store_new_id_truncates_long_names(store):
    sid = store.new_id("a" * 40 + ".exe")

    assert sid.split("-")[0] == "a" * 16


def test_session_store_save_load(store):
    session = _session()
    session.set_symbol(Symbol(name="gold", base_expr="game.exe+0x10", offsets=[0x8]))

    store.save(session)

    path = store.dir / f"{session.id}.json"
    assert path.exists()
    assert not list(store.dir.glob("*.tmp"))  # atomic write leaves no temp file

    loaded = store.load(session.id)
    assert loaded.id == session.id
    assert loaded.get_symbol("gold").offsets == [0x8]
    assert loaded.updated_at == session.updated_at  # save() touched then persisted


def test_session_store_save_touches_updated_at(store):
    session = _session(updated_at=0.0)

    store.save(session)

    assert session.updated_at > 0.0
    assert store.load(session.id).updated_at > 0.0


def test_session_store_list(store):
    assert store.list_ids() == []  # missing directory is not an error

    for sid in ("b-2", "a-1", "c-3"):
        store.save(_session(id=sid))

    assert store.list_ids() == ["a-1", "b-2", "c-3"]  # sorted
    assert [s["session_id"] for s in store.list_sessions()] == ["a-1", "b-2", "c-3"]


def test_session_store_list_sessions_skips_corrupt_files(store):
    store.save(_session(id="good-1"))
    (store.dir / "broken-1.json").write_text("{not json", encoding="utf-8")

    assert store.list_ids() == ["broken-1", "good-1"]
    assert [s["session_id"] for s in store.list_sessions()] == ["good-1"]


def test_session_store_delete(store):
    session = _session()
    store.save(session)
    backups = store.backups_dir(session.id)
    backups.mkdir(parents=True)
    (backups / "bak-1.json").write_text("{}", encoding="utf-8")

    assert store.delete(session.id) is True

    assert not (store.dir / f"{session.id}.json").exists()
    assert not (backups / "bak-1.json").exists()
    assert store.delete(session.id) is False  # already gone


def test_session_store_not_exists(store):
    store.save(_session(id="known-1"))

    with pytest.raises(SessionNotFoundError) as excinfo:
        store.load("ghost")

    exc = excinfo.value
    assert exc.code.value == "E_SESSION_NOT_FOUND"
    assert exc.details["session_id"] == "ghost"
    assert exc.details["known"] == ["known-1"]
    assert "attach" in exc.hint


def test_session_store_paths(store):
    assert store.backups_dir("s1") == store.dir / "s1" / "backups"
    assert store.freeze_pid_path("s1") == store.dir / "s1" / "freeze.pid"

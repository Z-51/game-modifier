"""Regression tests for F3 per-session write serialization (review P0-F3).

Covers:
- SessionStore.locked: in-process RLock contention -> E_SESSION_BUSY on timeout
- cross-instance lockfile (the msvcrt layer used between CLI and MCP server
  processes) -> E_SESSION_BUSY while held, released afterwards
- reentrant nesting (batch_run -> modify style composite flows)
- service-level integration: a locked-out op surfaces E_SESSION_BUSY
- concurrent writers no longer lose each other's mutations
- ``*.lock`` files never show up in the session listing
"""

from __future__ import annotations

import struct
import threading

import pytest

from game_modifier import service as svc_mod
from game_modifier.errors import ErrorCode, SessionBusyError
from game_modifier.memory import process as procmod
from game_modifier.memory.base import ModuleInfo
from game_modifier.service import ModifierService
from game_modifier.session import SessionStore

from conftest import FakeBackend


@pytest.fixture
def service(tmp_config, monkeypatch):
    fake = FakeBackend(
        regions={0x1000: bytearray(struct.pack("<i", 1000) + b"\x00" * 0x100)},
        modules=[ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000,
                            path="C:/games/fake.exe")],
        name="fake.exe", pid=4242,
    )
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


def test_in_process_lock_busy(tmp_path):
    store = SessionStore(tmp_path)
    errors = []

    def contender():
        # a *different* thread contends on the RLock (the same thread would
        # re-enter it freely)
        try:
            with store.locked("s1", timeout=0.2):
                pass
        except SessionBusyError as exc:
            errors.append(exc)

    with store.locked("s1"):
        t = threading.Thread(target=contender)
        t.start()
        t.join(timeout=5)
    assert len(errors) == 1
    assert errors[0].code == ErrorCode.SESSION_BUSY


def test_cross_instance_file_lock(tmp_path):
    """Two SessionStore instances (two processes' worth) arbitrate via the
    lockfile: the second one is refused while the first holds it."""

    store_a = SessionStore(tmp_path)
    store_b = SessionStore(tmp_path)
    with store_a.locked("s1"):
        with pytest.raises(SessionBusyError) as ei:
            with store_b.locked("s1", timeout=0.3):
                pass
        assert ei.value.code == ErrorCode.SESSION_BUSY
    # released: the other instance acquires immediately
    with store_b.locked("s1", timeout=0.3):
        pass


def test_lock_is_reentrant_same_thread(tmp_path):
    store = SessionStore(tmp_path)
    with store.locked("s1"):
        with store.locked("s1"):
            with store.locked("s1", timeout=0.1):
                pass  # nested composite flows must not deadlock
    # fully released afterwards
    with store.locked("s1", timeout=0.1):
        pass


def test_lock_file_not_listed_as_session(tmp_path):
    store = SessionStore(tmp_path)
    with store.locked("s1"):
        pass
    assert (tmp_path / "s1.lock").exists()
    assert "s1" not in store.list_ids()
    assert store.list_ids() == []


def test_service_op_surfaces_session_busy(service, tmp_config, monkeypatch):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]

    # shrink the wait so the test stays fast
    orig_locked = SessionStore.locked

    def fast_locked(self, session_id, timeout=0.2):
        return orig_locked(self, session_id, timeout=timeout)

    monkeypatch.setattr(SessionStore, "locked", fast_locked)

    # a *different* store instance holds the cross-process lockfile
    other = SessionStore(svc.store.dir)
    with other.locked(sid):
        with pytest.raises(SessionBusyError) as ei:
            svc.name_set(session_id=sid, name="player.gold", base_expr="0x1000", type="int32")
        assert ei.value.code == ErrorCode.SESSION_BUSY

    # after release the same call succeeds
    out = svc.name_set(session_id=sid, name="player.gold", base_expr="0x1000", type="int32")
    assert out["symbol"] == "player.gold"


def test_concurrent_writers_no_lost_update(service):
    """Two threads x N symbol writes each: with the per-session lock every
    mutation survives (previously a load->save race could drop one)."""

    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    per_thread = 25

    def writer(prefix):
        for i in range(per_thread):
            svc.name_set(session_id=sid, name=f"{prefix}.{i}", base_expr="0x1000", type="int32")

    t1 = threading.Thread(target=writer, args=("a",))
    t2 = threading.Thread(target=writer, args=("b",))
    t1.start()
    t2.start()
    t1.join(timeout=60)
    t2.join(timeout=60)

    session = svc.store.load(sid, restore_candidates=False)
    names = set(session.symbols.keys())
    expected = {f"a.{i}" for i in range(per_thread)} | {f"b.{i}" for i in range(per_thread)}
    assert expected <= names

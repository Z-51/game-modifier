"""Performance-oriented freeze loop tests (pre-resolve cache, dirty check,
adaptive interval, pointer-chain re-resolution)."""

from __future__ import annotations

import struct
import time as time_mod

import pytest

from game_modifier.config import Config
from game_modifier.memory import process as procmod
from game_modifier.memory.base import ModuleInfo
from game_modifier.service import ModifierService

from conftest import FakeBackend

BASE = 0x200000
MOD_BASE = 0x140000000


def _freeze_config(tmp_path):
    return Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": False, "require_writable_region": True},
        "scan": {"max_results": 1000, "chunk_size": 4096, "alignment": 1},
        "freeze": {"adaptive": True, "min_interval": 0.1, "max_interval": 0.8},
        "paths": {"home": str(tmp_path / ".game-modifier")},
    })


def _build(tmp_path, monkeypatch, fake):
    import game_modifier.service as svc_module

    monkeypatch.setattr(svc_module, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(_freeze_config(tmp_path))


def _sleep_recorder(monkeypatch):
    sleeps: list[float] = []

    def _rec(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(time_mod, "sleep", _rec)
    return sleeps


def _count_backend_writes(fake):
    calls = {"writes": 0}
    orig_write = fake.write

    def _w(address, data):
        calls["writes"] += 1
        return orig_write(address, data)

    fake.write = _w
    return calls


# ------------------------------------------------------------------ pre-resolve
def test_freeze_preresolve_cache(tmp_path, monkeypatch):
    """A pure-address target resolves exactly once across the whole loop."""

    fake = FakeBackend(regions={BASE: bytearray(struct.pack("<i", 10) + b"\x00" * 0x40)})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]
    svc.modify(session_id=sid, address=hex(BASE), type="int32", value=42, confirm=True, freeze=True)

    resolves = {"n": 0}
    orig = svc._resolve_target

    def _counting(*a, **kw):
        resolves["n"] += 1
        return orig(*a, **kw)

    monkeypatch.setattr(svc, "_resolve_target", _counting)
    out = svc.freeze_run(session_id=sid, interval=0.0, iterations=3, adaptive=False)

    assert out["loops"] == 3
    assert resolves["n"] == 1, f"pure-address target must resolve once (pre-resolve cache), got {resolves['n']}"
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 42, "value must stay frozen"


def test_freeze_dirty_check_skip_write(tmp_path, monkeypatch):
    """Adaptive mode reads back first and skips the write when the value matches."""

    fake = FakeBackend(regions={BASE: bytearray(struct.pack("<i", 42) + b"\x00" * 0x40)})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]
    svc.modify(session_id=sid, address=hex(BASE), type="int32", value=42, confirm=True, freeze=True)

    writes = _count_backend_writes(fake)
    out = svc.freeze_run(session_id=sid, iterations=2, adaptive=True)

    assert writes["writes"] == 0, "no deviation means no memory write"
    assert out["actual_writes"] == 0
    assert out["skipped_writes"] == 2, "both loops verified the value clean"
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 42


def test_freeze_adaptive_interval(tmp_path, monkeypatch):
    """Consecutive clean cycles double the interval, capped at max_interval."""

    fake = FakeBackend(regions={BASE: bytearray(struct.pack("<i", 42) + b"\x00" * 0x40)})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]
    svc.modify(session_id=sid, address=hex(BASE), type="int32", value=42, confirm=True, freeze=True)

    sleeps = _sleep_recorder(monkeypatch)
    svc.freeze_run(session_id=sid, iterations=6, adaptive=True)

    # min_interval=0.1 doubles per clean cycle: 0.2, 0.4, 0.8, capped at 0.8
    assert sleeps == [0.2, 0.4, 0.8, 0.8, 0.8], f"interval must double up to the cap, got {sleeps}"


def test_freeze_deviation_restore(tmp_path, monkeypatch):
    """A detected deviation snaps the interval back to min_interval."""

    fake = FakeBackend(regions={BASE: bytearray(struct.pack("<i", 42) + b"\x00" * 0x40)})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]
    svc.modify(session_id=sid, address=hex(BASE), type="int32", value=42, confirm=True, freeze=True)

    sleeps = _sleep_recorder(monkeypatch)

    def _drift_once(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 1:
            # the "game" overwrites the frozen value right after the first cycle
            fake.write(BASE, struct.pack("<i", 7))

    monkeypatch.setattr(time_mod, "sleep", _drift_once)
    out = svc.freeze_run(session_id=sid, iterations=3, adaptive=True)

    assert sleeps[0] == pytest.approx(0.2), "first clean cycle doubles the interval"
    assert sleeps[1] == pytest.approx(0.1), "deviation must restore min_interval"
    assert out["actual_writes"] == 1, "the drifted cycle must re-write the value"
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 42, "freeze must win over the game write"


def test_freeze_non_adaptive_unchanged(tmp_path, monkeypatch):
    """adaptive=False keeps the legacy fixed-interval write-every-round loop."""

    fake = FakeBackend(regions={BASE: bytearray(struct.pack("<i", 42) + b"\x00" * 0x40)})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]
    svc.modify(session_id=sid, address=hex(BASE), type="int32", value=42, confirm=True, freeze=True)

    sleeps = _sleep_recorder(monkeypatch)
    writes = _count_backend_writes(fake)
    out = svc.freeze_run(session_id=sid, interval=0.02, iterations=2, adaptive=False)

    assert writes["writes"] == 2, "non-adaptive mode writes every round regardless of drift"
    assert out["actual_writes"] == 2 and out["skipped_writes"] == 0
    assert sleeps == [0.02], "fixed interval, no sleep after the final loop"
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 42


def test_freeze_pointer_chain_reparse(tmp_path, monkeypatch):
    """Pointer-chain targets are re-resolved on every round (address can move)."""

    mod = ModuleInfo(name="fake.exe", base=MOD_BASE, size=0x1000, path="C:/games/fake.exe")
    fake = FakeBackend(
        regions={
            MOD_BASE: bytearray(struct.pack("<Q", BASE) + b"\x00" * 0x40),  # pointer -> BASE
            BASE: bytearray(struct.pack("<i", 10) + b"\x00" * 0x40),
        },
        modules=[mod],
    )
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]
    svc.name_set(session_id=sid, name="player.hp", base_expr="fake.exe+0x0", offsets="0x0", type="int32")
    svc.modify(session_id=sid, symbol="player.hp", value=42, confirm=True, freeze=True)

    resolves = {"n": 0}
    orig = svc._resolve_target

    def _counting(*a, **kw):
        resolves["n"] += 1
        return orig(*a, **kw)

    monkeypatch.setattr(svc, "_resolve_target", _counting)
    out = svc.freeze_run(session_id=sid, interval=0.0, iterations=3, adaptive=False)

    assert resolves["n"] == 3, f"chain target must resolve once per loop, got {resolves['n']}"
    assert out["writes"] == 3
    assert struct.unpack("<i", fake.read(BASE, 4))[0] == 42

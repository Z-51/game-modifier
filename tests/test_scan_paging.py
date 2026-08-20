"""Phase 1.1: scan pagination + scan_candidates (sidecar window reads).

Covers: ScanResult.to_dict paging, service-level offset/limit pass-through,
the scan_candidates service (inline + sidecar paths, bisect range filtering,
legacy v1 sidecar compatibility, no full materialisation) and the CLI wiring.
"""

from __future__ import annotations

import array
import json
import struct

import pytest

from game_modifier.config import Config
from game_modifier.memory import process as procmod
from game_modifier.memory import scanner
from game_modifier.service import ModifierService
from game_modifier.session import ScanState, SessionStore

from conftest import FakeBackend

BASE = 0x200000


def _region_of(values):
    buf = bytearray()
    for v in values:
        buf += struct.pack("<i", v)
    return buf


def _build(tmp_path, monkeypatch, fake, **scan_overrides):
    import game_modifier.service as svc_module

    scan = {"max_results": 20000, "chunk_size": 4096, "alignment": 1}
    scan.update(scan_overrides)
    config = Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": False, "require_writable_region": True},
        "scan": scan,
        "paths": {"home": str(tmp_path / ".game-modifier")},
    })
    monkeypatch.setattr(svc_module, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(config)


# ------------------------------------------------------------- to_dict paging
def test_to_dict_default_behaviour_frozen():
    res = scanner.ScanResult(type="int32", comparator="exact", count=30, truncated=False,
                             addresses=list(range(30)), values={i: i for i in range(30)})
    out = res.to_dict()
    assert len(out["addresses_hex"]) == 20, "default stays: first `sample` (20) addresses"
    assert out["page"] == {"offset": 0, "limit": None}


def test_to_dict_paging_window():
    addrs = [0x1000 + 4 * i for i in range(50)]
    res = scanner.ScanResult(type="int32", comparator="exact", count=50, truncated=False,
                             addresses=addrs, values={a: 7 for a in addrs})
    out = res.to_dict(offset=10, limit=5)
    assert out["addresses_hex"] == [hex(a) for a in addrs[10:15]]
    assert set(out["sample_values"]) == {hex(a) for a in addrs[10:15]}
    assert out["page"] == {"offset": 10, "limit": 5}
    assert out["count"] == 50, "count stays the full candidate total"

    # offset beyond the end yields an empty window, not an error
    assert res.to_dict(offset=100, limit=5)["addresses_hex"] == []


# ------------------------------------------------------- service pass-through
def test_scan_returns_paging_meta(tmp_path, monkeypatch):
    fake = FakeBackend(regions={BASE: _region_of(list(range(40)))})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.scan(session_id=sid, type="int32", value=7, offset=0, limit=3)
    assert out["count"] == 1
    assert out["page"] == {"offset": 0, "limit": 3}
    assert out["candidates_total"] == 1
    assert "region_summary" in out
    assert "candidates_file" not in out, "inline candidate set carries no sidecar reference"

    nxt = svc.scan_next(session_id=sid, value=7, offset=0, limit=1)
    assert nxt["page"] == {"offset": 0, "limit": 1}
    assert nxt["candidates_total"] == 1


# ------------------------------------------------------- scan_candidates inline
def test_scan_candidates_inline(tmp_path, monkeypatch):
    fake = FakeBackend(regions={BASE: _region_of([9] * 12)})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]
    svc.scan(session_id=sid, type="int32", value=9)

    page = svc.scan_candidates(sid, offset=2, limit=5)
    assert page["candidates_total"] == 12
    assert page["addresses_hex"] == [hex(BASE + 4 * i) for i in range(2, 7)]
    assert page["values"] == {hex(BASE + 4 * i): 9 for i in range(2, 7)}

    # bisect range filtering on the ascending inline list
    rng = svc.scan_candidates(sid, offset=0, limit=100, min_addr=BASE + 4 * 4, max_addr=BASE + 4 * 7)
    assert rng["addresses_hex"] == [hex(BASE + 4 * i) for i in range(4, 8)]


def test_scan_candidates_without_scan_raises(tmp_path, monkeypatch):
    fake = FakeBackend(regions={BASE: _region_of([1])})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]

    from game_modifier.errors import NeedsScanError

    with pytest.raises(NeedsScanError):
        svc.scan_candidates(sid)


# ------------------------------------------------------- scan_candidates sidecar
def _sidecar_scan(tmp_path, monkeypatch, n=30):
    fake = FakeBackend(regions={BASE: _region_of([5] * n)})
    svc = _build(tmp_path, monkeypatch, fake, candidates_sidecar_threshold=10)
    sid = svc.attach(pid=4242)["session_id"]
    out = svc.scan(session_id=sid, type="int32", value=5)
    return svc, sid, out


def test_scan_candidates_sidecar_window(tmp_path, monkeypatch):
    svc, sid, out = _sidecar_scan(tmp_path, monkeypatch)
    assert out["candidates_file"] == "scan_candidates.bin"
    assert out["candidates_total"] == 30

    # window read straight from the sidecar (no full materialisation)
    calls = []
    orig = ScanState.load_candidates_file
    ScanState.load_candidates_file = lambda self, path: calls.append(path) or orig(self, path)
    try:
        page = svc.scan_candidates(sid, offset=5, limit=10)
    finally:
        ScanState.load_candidates_file = orig
    assert calls == [], "scan_candidates must not trigger a full sidecar materialisation"

    assert page["candidates_total"] == 30
    assert page["addresses_hex"] == [hex(BASE + 4 * i) for i in range(5, 15)]
    assert page["values"] == {hex(BASE + 4 * i): 5 for i in range(5, 15)}

    # the session JSON still holds only the reference (bypass load)
    raw = json.loads((svc.store.dir / f"{sid}.json").read_text(encoding="utf-8"))
    assert raw["scan"]["candidates_file"] == "scan_candidates.bin"
    assert "addresses" not in raw["scan"]


def test_scan_candidates_sidecar_bisect_range(tmp_path, monkeypatch):
    svc, sid, _ = _sidecar_scan(tmp_path, monkeypatch)
    lo, hi = BASE + 4 * 10, BASE + 4 * 19
    page = svc.scan_candidates(sid, offset=0, limit=100, min_addr=lo, max_addr=hi)
    assert page["addresses_hex"] == [hex(a) for a in range(lo, hi + 4, 4)][:10]

    # offset applies inside the filtered range
    page2 = svc.scan_candidates(sid, offset=3, limit=4, min_addr=lo, max_addr=hi)
    assert page2["addresses_hex"] == [hex(lo + 4 * i) for i in range(3, 7)]


def test_scan_candidates_after_aob_values_null(tmp_path, monkeypatch):
    """AOB candidate sets record no values -> the values field is null."""

    fake = FakeBackend(regions={BASE: bytearray(b"\x00" * 0x10 + b"\xde\xad\xbe\xef" + b"\x00" * 0x10)})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]
    svc.scan_aob(sid, pattern="DE AD BE EF")

    page = svc.scan_candidates(sid, offset=0, limit=10)
    assert page["values"] is None
    assert page["candidates_total"] == 1
    assert page["addresses_hex"] == [hex(BASE + 0x10)]


# ------------------------------------------------- legacy sidecar compatibility
def test_legacy_sidecar_full_load_fallback():
    """load_candidates_file still understands the pre-v2 flat array format."""

    import tempfile
    from pathlib import Path

    addrs = [0x1000 + 8 * i for i in range(7)]
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "scan_candidates.bin"
        with path.open("wb") as fh:
            array.array("Q", addrs).tofile(fh)
        state = ScanState()
        assert state.load_candidates_file(path) is True
        assert state.addresses == addrs
        assert state.sidecar_count(path) == 7


def test_legacy_sidecar_scan_candidates(tmp_path):
    """scan_candidates serves a legacy v1 sidecar (values -> null)."""

    store = SessionStore(tmp_path / "sessions")
    addrs = [0x2000 + 4 * i for i in range(9)]
    sidecar = store.candidates_path("legacy-1")
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    with sidecar.open("wb") as fh:
        array.array("Q", addrs).tofile(fh)

    session = {
        "id": "legacy-1",
        "pid": "4242",
        "process_name": "game.exe",
        "scan": {
            "type": "int32", "comparator": "exact", "count": len(addrs),
            "truncated": False, "values": {},
            "candidates_file": "scan_candidates.bin",
        },
    }
    store.dir.mkdir(parents=True, exist_ok=True)
    (store.dir / "legacy-1.json").write_text(json.dumps(session), encoding="utf-8")

    config = Config({
        "safety": {"dry_run": True},
        "paths": {"home": str(tmp_path)},
    })
    svc = ModifierService(config)
    svc.store = store
    page = svc.scan_candidates("legacy-1", offset=2, limit=4)
    assert page["candidates_total"] == 9
    assert page["addresses_hex"] == [hex(a) for a in addrs[2:6]]
    assert page["values"] is None, "legacy address-only sidecars carry no values"


# ---------------------------------------------------------- sidecar replacement
def test_sidecar_replaced_by_new_scan_not_deleted_eagerly(tmp_path, monkeypatch):
    """A follow-up small scan keeps its candidates inline; the sidecar file is
    replaced only when the new scan itself externalises."""

    svc, sid, _ = _sidecar_scan(tmp_path, monkeypatch)
    sidecar = svc.store.candidates_path(sid)
    first_bytes = sidecar.read_bytes()

    # a refining scan_next that empties the set drops below the threshold ->
    # inline state; candidates_file is no longer reported for the current set
    nxt = svc.scan_next(session_id=sid, comparator="exact", value=999)
    assert nxt["count"] == 0
    assert "candidates_file" not in nxt, "inline state must not reference a stale sidecar"

    # a fresh oversized scan REPLACES the sidecar content
    fake2 = FakeBackend(regions={BASE: _region_of([6] * 25)})
    import game_modifier.service as svc_module

    monkeypatch.setattr(svc_module, "get_backend", lambda: fake2)
    out2 = svc.scan(session_id=sid, type="int32", value=6)
    assert out2["candidates_file"] == "scan_candidates.bin"
    assert sidecar.read_bytes() != first_bytes, "the sidecar must be overwritten, not appended"

"""Scan result caching: region fingerprint, binary candidate sidecar, and
backwards compatibility with pre-fingerprint session files."""

from __future__ import annotations

import json
import struct

from game_modifier.config import Config
from game_modifier.memory import process as procmod
from game_modifier.memory.base import MemoryRegion
from game_modifier.service import ModifierService, _region_fingerprint
from game_modifier.session import ScanState, SessionStore, _CANDIDATES_MAGIC

from conftest import FakeBackend

BASE = 0x200000


def _cache_config(tmp_path, **scan_overrides):
    scan = {"max_results": 20000, "chunk_size": 4096, "alignment": 1}
    scan.update(scan_overrides)
    return Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": False, "require_writable_region": True},
        "scan": scan,
        "paths": {"home": str(tmp_path / ".game-modifier")},
    })


def _build(tmp_path, monkeypatch, fake, **scan_overrides):
    import game_modifier.service as svc_module

    monkeypatch.setattr(svc_module, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(_cache_config(tmp_path, **scan_overrides))


def _region_of(values):
    buf = bytearray()
    for v in values:
        buf += struct.pack("<i", v)
    return buf


# ---------------------------------------------------------------- fingerprint
def test_scan_state_fingerprint():
    """Fingerprint is deterministic per layout and sensitive to base/size."""

    r1 = [MemoryRegion(base=0x1000, size=0x100, readable=True),
          MemoryRegion(base=0x2000, size=0x200, readable=True)]
    fp_a = _region_fingerprint(r1)
    fp_b = _region_fingerprint(list(r1))
    assert fp_a == fp_b and fp_a, "same layout must hash identically"
    assert _region_fingerprint(r1[:1]) != fp_a, "removing a region must change the fingerprint"

    resized = [MemoryRegion(base=0x1000, size=0x180, readable=True), r1[1]]
    moved = [MemoryRegion(base=0x1400, size=0x100, readable=True), r1[1]]
    assert _region_fingerprint(resized) != fp_a, "a size change must change the fingerprint"
    assert _region_fingerprint(moved) != fp_a, "a base change must change the fingerprint"


def test_scan_stores_fingerprint(tmp_path, monkeypatch):
    fake = FakeBackend(regions={BASE: _region_of([7, 8, 9])})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]
    svc.scan(session_id=sid, type="int32", value=7)

    stored = svc.store.load(sid)
    expected = _region_fingerprint(fake.readable_regions())
    assert stored.scan.region_fingerprint == expected, "scan must persist the region fingerprint"


def test_scan_next_cache_stale_flag(tmp_path, monkeypatch):
    """A changed region layout flags the refinement result (no hard error)."""

    fake = FakeBackend(regions={BASE: _region_of([7, 8, 9])})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]
    svc.scan(session_id=sid, type="int32", value=7)

    # same layout: no staleness flag
    same = svc.scan_next(session_id=sid, comparator="exact", value=7)
    assert "cache_stale" not in same

    # the process "allocates" a new region -> layout changes
    fake._regions[0x900000] = bytearray(0x100)
    out = svc.scan_next(session_id=sid, comparator="exact", value=7)
    assert out.get("cache_stale") is True, "fingerprint mismatch must flag the result"
    assert "cache_stale_hint" in out
    assert out["count"] == 1, "the refinement still runs and returns candidates"


# -------------------------------------------------------------------- sidecar
def test_candidates_sidecar(tmp_path, monkeypatch):
    """Oversized candidate sets move to a binary sidecar; JSON keeps a summary."""

    n = 30
    fake = FakeBackend(regions={BASE: _region_of([5] * n)})
    svc = _build(tmp_path, monkeypatch, fake, candidates_sidecar_threshold=10)
    sid = svc.attach(pid=4242)["session_id"]
    out = svc.scan(session_id=sid, type="int32", value=5)
    assert out["count"] == n

    sidecar = svc.store.candidates_path(sid)
    assert sidecar.exists(), "candidates above the threshold must be externalised"
    # v2 two-segment layout: magic + u64 header length + JSON header +
    # addresses (array.array('Q'), 8 bytes each) + values segment
    data = sidecar.read_bytes()
    assert data.startswith(_CANDIDATES_MAGIC), "sidecar must use the v2 format"
    hlen = int.from_bytes(data[len(_CANDIDATES_MAGIC):len(_CANDIDATES_MAGIC) + 8], "little")
    header = json.loads(data[len(_CANDIDATES_MAGIC) + 8:len(_CANDIDATES_MAGIC) + 8 + hlen])
    assert header["format"] == 2 and header["count"] == n
    addr_end = len(_CANDIDATES_MAGIC) + 8 + hlen + n * 8
    assert addr_end + header["values_bytes"] == len(data), "address segment stores 8 bytes per address, then the values segment"

    raw = json.loads((svc.store.dir / f"{sid}.json").read_text(encoding="utf-8"))
    scan_json = raw["scan"]
    assert "addresses" not in scan_json, "addresses must not stay inline next to a sidecar"
    assert scan_json["candidates_file"] == "scan_candidates.bin"
    assert scan_json["count"] == n and scan_json["region_fingerprint"], "summary + fingerprint stay inline"


def test_candidates_restore(tmp_path, monkeypatch):
    """SessionStore.load transparently restores the candidate set from the sidecar."""

    n = 24
    fake = FakeBackend(regions={BASE: _region_of([3] * n)})
    svc = _build(tmp_path, monkeypatch, fake, candidates_sidecar_threshold=10)
    sid = svc.attach(pid=4242)["session_id"]
    svc.scan(session_id=sid, type="int32", value=3)

    loaded = svc.store.load(sid)
    assert loaded.scan.candidates_file == "", "sidecar reference must be consumed on load"
    assert loaded.scan.addresses == [BASE + 4 * i for i in range(n)], "addresses restored byte-exact"

    # the restored set is immediately usable by scan_next
    nxt = svc.scan_next(session_id=sid, comparator="exact", value=3)
    assert nxt["count"] == n


def test_small_scan_no_sidecar(tmp_path, monkeypatch):
    fake = FakeBackend(regions={BASE: _region_of([5, 5])})
    svc = _build(tmp_path, monkeypatch, fake, candidates_sidecar_threshold=10)
    sid = svc.attach(pid=4242)["session_id"]
    svc.scan(session_id=sid, type="int32", value=5)

    assert not svc.store.candidates_path(sid).exists(), "small candidate sets stay inline"
    raw = json.loads((svc.store.dir / f"{sid}.json").read_text(encoding="utf-8"))
    assert raw["scan"]["addresses"] == [BASE, BASE + 4]


# --------------------------------------------------------------- compatibility
def test_old_session_compat(tmp_path):
    """A session file written before the fingerprint/sidecar fields loads cleanly."""

    store = SessionStore(tmp_path / "sessions")
    old = {
        "id": "old-1",
        "pid": "4242",
        "process_name": "game.exe",
        "scan": {
            "type": "int32",
            "comparator": "exact",
            "count": 2,
            "truncated": False,
            "addresses": [0x1000, 0x2000],
            "values": {"4096": 7, "8192": 7},
        },
    }
    (store.dir).mkdir(parents=True, exist_ok=True)
    (store.dir / "old-1.json").write_text(json.dumps(old), encoding="utf-8")

    loaded = store.load("old-1")
    assert loaded.scan.region_fingerprint == "", "missing fingerprint defaults to empty"
    assert loaded.scan.candidates_file == ""
    assert loaded.scan.addresses == [0x1000, 0x2000]
    assert loaded.scan.values == {0x1000: 7, 0x2000: 7}

    # an empty stored fingerprint must never trigger a staleness flag
    state = ScanState.from_json(old["scan"])
    assert state.region_fingerprint == "" and state.to_json()["addresses"] == [0x1000, 0x2000]

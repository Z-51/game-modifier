"""Phase 1.2: region aggregation summary, region pre-filtering, AOB coverage,
stop_on_limit and serial/parallel AOB consistency."""

from __future__ import annotations

import struct

import pytest

from game_modifier.config import Config
from game_modifier.memory import aob, scanner
from game_modifier.memory import process as procmod
from game_modifier.memory.base import MemoryRegion
from game_modifier.service import ModifierService, _aggregate_addresses

from conftest import FakeBackend

BASE = 0x200000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000


class TypedFakeBackend(FakeBackend):
    """FakeBackend whose regions carry explicit ``type`` values."""

    def __init__(self, region_types=None, **kwargs):
        super().__init__(**kwargs)
        self._region_types = region_types or {}

    def regions(self):
        out = []
        for base, buf in self._regions.items():
            out.append(MemoryRegion(base=base, size=len(buf), readable=True, writable=True,
                                    state=0x1000, type=self._region_types.get(base, 0)))
        return out


def _region_of(values):
    buf = bytearray()
    for v in values:
        buf += struct.pack("<i", v)
    return buf


def _build(tmp_path, monkeypatch, fake, **scan_overrides):
    import game_modifier.service as svc_module

    scan = {"max_results": 20000, "chunk_size": 4096, "alignment": 1, "workers": 1}
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


# ------------------------------------------------------- _aggregate_addresses
def test_aggregate_buckets_by_provenance():
    regions = [
        MemoryRegion(base=0x100000, size=0x8000, readable=True, type=0),            # small (<64KB)
        MemoryRegion(base=0x300000, size=0x100000, readable=True, type=MEM_PRIVATE),  # heap (>=256KB? no: 1MB yes)
        MemoryRegion(base=0x500000, size=0x20000, readable=True, type=MEM_MAPPED),   # mapped
        MemoryRegion(base=0x700000, size=0x20000, readable=True, type=MEM_PRIVATE),  # private <256KB -> other
        MemoryRegion(base=0x140000000, size=0x2000, readable=True, type=MEM_IMAGE),  # image span
    ]
    modules = {"game.exe": {"base": 0x140000000, "size": 0x2000, "path": ""}}
    addresses = [0x100010, 0x300010, 0x300020, 0x500010, 0x700010, 0x140000100, 0x999999999]

    summary = _aggregate_addresses(addresses, regions, modules)
    assert summary["candidates"] == 7
    assert summary["regions"] == 5
    assert summary["unmatched"] == 1

    kinds = {b["kind"]: b for b in summary["buckets"]}
    assert kinds["image"]["count"] == 1 and kinds["image"]["module"] == "game.exe"
    assert kinds["heap"]["count"] == 2 and len(kinds["heap"]["samples"]) <= 5
    assert kinds["mapped"]["count"] == 1
    assert kinds["small"]["count"] == 1
    assert kinds["other"]["count"] == 1
    assert all(s.startswith("0x") for s in kinds["heap"]["samples"])


def test_aggregate_budget_caps():
    # 12 module buckets -> capped to 8 with a dropped flag
    regions = [MemoryRegion(base=m * 0x1000000, size=0x1000, readable=True, type=MEM_IMAGE)
               for m in range(1, 13)]
    modules = {f"mod{i}.dll": {"base": i * 0x1000000, "size": 0x1000, "path": ""}
               for i in range(1, 13)}
    addresses = [i * 0x1000000 + 0x10 for i in range(1, 13)]

    summary = _aggregate_addresses(addresses, regions, modules)
    assert len(summary["buckets"]) <= 8
    assert summary.get("dropped") is True

    # serialisation budget holds even for pathological inputs
    import json

    assert len(json.dumps(summary, separators=(",", ":")).encode()) <= 2048


def test_scan_returns_region_summary(tmp_path, monkeypatch):
    fake = FakeBackend(regions={BASE: _region_of([7, 7, 8])})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.scan(session_id=sid, type="int32", value=7)
    rs = out["region_summary"]
    assert rs["candidates"] == 2 and rs["regions"] == 1
    # FakeBackend regions are type=0 and < 64KB -> small bucket
    assert rs["buckets"][0]["kind"] == "small"
    assert rs["buckets"][0]["count"] == 2

    # scan_next and scan_aob carry the summary too
    nxt = svc.scan_next(session_id=sid, value=7)
    assert "region_summary" in nxt
    aob_out = svc.scan_aob(session_id=sid, pattern="07 00")
    assert "region_summary" in aob_out


# ------------------------------------------------------------- region filtering
def test_first_scan_min_max_addr(tmp_path, monkeypatch):
    fake = FakeBackend(regions={0x10000: _region_of([5, 5]), 0x50000: _region_of([5, 5, 5])})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.scan(session_id=sid, type="int32", value=5, min_addr=0x50000)
    assert out["count"] == 3, "only the region overlapping [min_addr, ...] is scanned"
    assert all(int(a, 16) >= 0x50000 for a in out["addresses_hex"])

    out2 = svc.scan(session_id=sid, type="int32", value=5, max_addr=0x10007)
    assert out2["count"] == 2
    assert all(int(a, 16) < 0x50000 for a in out2["addresses_hex"])


def test_first_scan_region_types(tmp_path, monkeypatch):
    fake = TypedFakeBackend(
        region_types={0x10000: MEM_IMAGE, 0x50000: MEM_PRIVATE},
        regions={0x10000: _region_of([3]), 0x50000: _region_of([3, 3])},
    )
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.scan(session_id=sid, type="int32", value=3, region_types=[MEM_PRIVATE])
    assert out["count"] == 2
    assert all(int(a, 16) >= 0x50000 for a in out["addresses_hex"])

    out2 = svc.scan(session_id=sid, type="int32", value=3, region_types=[MEM_IMAGE])
    assert out2["count"] == 1


def test_filter_regions_helper():
    regions = [
        MemoryRegion(base=0x1000, size=0x100, readable=True, type=MEM_IMAGE),
        MemoryRegion(base=0x5000, size=0x100, readable=True, type=MEM_PRIVATE),
    ]
    assert len(scanner.filter_regions(regions)) == 2, "all-None filters keep everything"
    assert scanner.filter_regions(regions, min_addr=0x5000)[0].base == 0x5000
    assert scanner.filter_regions(regions, max_addr=0x10FF)[0].base == 0x1000
    assert scanner.filter_regions(regions, max_addr=0x0FFF) == []
    assert [r.type for r in scanner.filter_regions(regions, region_types=[MEM_PRIVATE])] == [MEM_PRIVATE]


def test_aob_min_max_addr():
    region_a = bytearray(b"\x00" * 8 + b"\xde\xad" + b"\x00" * 8)
    region_b = bytearray(b"\xde\xad" + b"\x00" * 16)
    be = FakeBackend(regions={0x10000: region_a, 0x90000: region_b})

    full = aob.aob_scan(be, "DE AD")
    assert full["count"] == 2

    hi = aob.aob_scan(be, "DE AD", max_addr=0x20000)
    assert hi["addresses"] == [0x10008]
    lo = aob.aob_scan(be, "DE AD", min_addr=0x90000)
    assert lo["addresses"] == [0x90000]


# ------------------------------------------------------------------ coverage
def test_aob_coverage_on_truncation():
    region = bytearray(b"\xaa\xbb" * 64)
    be = FakeBackend(regions={0x10000: region, 0x20000: bytearray(b"\xaa\xbb" * 64)})

    cut = aob.aob_scan(be, "AA BB", max_results=3)
    assert cut["truncated"] is True
    cov = cut["coverage"]
    assert cov["regions_total"] == 2
    assert cov["regions_scanned"] <= 2
    assert 0 <= cov["pct"] <= 100

    full = aob.aob_scan(be, "AA BB")
    assert full["truncated"] is False
    assert "coverage" not in full, "coverage is only appended when truncated"


def test_aob_stop_on_limit_counts_without_collecting():
    region = bytearray(b"\xaa\xbb" * 64)
    be = FakeBackend(regions={0x10000: region, 0x20000: bytearray(b"\xaa\xbb" * 32)})

    # frozen behaviour: stop immediately at the cap
    cut = aob.aob_scan(be, "AA BB", max_results=3, stop_on_limit=False)
    assert cut["count"] == 3 and cut["truncated"] is True

    # stop_on_limit: keeps scanning everything, still collects only the cap
    full = aob.aob_scan(be, "AA BB", max_results=3, stop_on_limit=True)
    assert full["count"] == 3 and full["truncated"] is True
    assert full["scanned_bytes"] == 128 + 64, "both regions fully scanned"
    assert full["coverage"]["regions_scanned"] == 2


# ------------------------------------------------------ parallel consistency
def test_aob_parallel_matches_serial():
    needle = b"\xde\xad\xbe\xef"
    regions = {}
    for i in range(6):
        buf = bytearray(b"\x00" * 16 + (needle + b"\x00" * 24) * (i + 1))
        regions[0x100000 + i * 0x100000] = buf
    be = FakeBackend(regions=regions)

    serial = aob.aob_scan(be, "DE AD BE EF", chunk_size=64)
    parallel = aob.aob_scan(be, "DE AD BE EF", chunk_size=64, workers=3,
                            backend_factory=lambda: be)
    assert parallel["addresses"] == serial["addresses"], "region-order aggregation must be deterministic"
    assert parallel["count"] == serial["count"]
    assert parallel["truncated"] == serial["truncated"]

    # truncated runs stay consistent too (same first-N in region order)
    serial_cut = aob.aob_scan(be, "DE AD BE EF", chunk_size=64, max_results=5)
    parallel_cut = aob.aob_scan(be, "DE AD BE EF", chunk_size=64, max_results=5,
                                workers=3, backend_factory=lambda: be)
    assert parallel_cut["addresses"] == serial_cut["addresses"]
    assert parallel_cut["truncated"] is True


def test_aob_parallel_requires_factory():
    be = FakeBackend(regions={0x10000: bytearray(b"\xde\xad" * 4)})
    with pytest.warns(UserWarning, match="backend_factory"):
        res = aob.aob_scan(be, "DE AD", workers=4, backend_factory=None)
    assert res["count"] == 4, "degrades to single-threaded, result unchanged"


# ------------------------------------------------- scan_aob state persistence
def test_scan_aob_sidecar_via_store_scan_state(tmp_path, monkeypatch):
    """scan_aob now routes through _store_scan_state: oversized AOB candidate
    sets are externalised, and the ScanState keeps type='bytes'."""

    region = bytearray((b"\xca\xfe" + b"\x00" * 6) * 40)
    fake = FakeBackend(regions={BASE: region})
    svc = _build(tmp_path, monkeypatch, fake, candidates_sidecar_threshold=10)
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.scan_aob(sid, pattern="CA FE", max_results=100)
    assert out["count"] == 40
    assert out["candidates_file"] == "scan_candidates.bin"
    assert out["candidates_total"] == 40

    # the session ScanState contract from test_aob.py stays intact
    session = svc.store.load(sid)
    assert session.scan.type == "bytes"
    assert session.scan.addresses == [BASE + 8 * i for i in range(40)]
    assert session.scan.count == 40

    # and the candidates are pageable via scan_candidates (values -> null)
    page = svc.scan_candidates(sid, offset=4, limit=3)
    assert page["addresses_hex"] == [hex(BASE + 8 * i) for i in range(4, 7)]
    assert page["values"] is None


def test_scan_aob_region_filter_service(tmp_path, monkeypatch):
    region_a = bytearray(b"\x00" * 8 + b"\xde\xad" + b"\x00" * 8)
    region_b = bytearray(b"\xde\xad" + b"\x00" * 16)
    fake = FakeBackend(regions={0x10000: region_a, 0x90000: region_b})
    svc = _build(tmp_path, monkeypatch, fake)
    sid = svc.attach(pid=4242)["session_id"]

    out = svc.scan_aob(sid, pattern="DE AD", min_addr=0x90000)
    assert out["count"] == 1
    assert out["addresses_hex"] == [hex(0x90000)]

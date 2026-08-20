"""Tests for the lenient region fingerprint, stale_detail and retain_stale.

Iron rule: ``_region_fingerprint`` is frozen - the lenient variant is a
parallel function gated by ``[scan] fingerprint_mode`` (default strict, i.e.
behavior unchanged). Small regions (<64 KB) only contribute a (count,
total_bytes) aggregate under lenient mode, so allocator churn below 64 KB no
longer flips the scan cache.
"""

from __future__ import annotations

import struct

import pytest

import game_modifier.service as svc
from game_modifier.config import Config
from game_modifier.memory.base import MemoryRegion


def R(base: int, size: int) -> MemoryRegion:
    return MemoryRegion(base=base, size=size, readable=True, writable=True, state=0x1000)


BIG = R(0x10000000, 0x20000)          # 128 KB -> large region
SMALL_A = R(0x200000, 0x100)          # < 64 KB
SMALL_B = R(0x210000, 0x100)          # same size, different base


# ---------------------------------------------------------------------------
# fingerprint functions (unit level)
# ---------------------------------------------------------------------------

class TestFingerprintFunctions:
    def test_strict_flips_on_small_region_change(self):
        assert svc._region_fingerprint([BIG, SMALL_A]) != svc._region_fingerprint([BIG, SMALL_B])

    def test_lenient_stable_on_small_region_churn(self):
        # same count + total bytes -> identical lenient fingerprint
        assert (svc._lenient_region_fingerprint([BIG, SMALL_A])
                == svc._lenient_region_fingerprint([BIG, SMALL_B]))

    def test_lenient_flips_on_large_region_change(self):
        other = [R(0x10000000, 0x30000), SMALL_A]
        assert (svc._lenient_region_fingerprint([BIG, SMALL_A])
                != svc._lenient_region_fingerprint(other))

    def test_lenient_flips_on_small_aggregate_change(self):
        bigger_small = [BIG, R(0x200000, 0x200)]  # total bytes changed
        assert (svc._lenient_region_fingerprint([BIG, SMALL_A])
                != svc._lenient_region_fingerprint(bigger_small))
        more_smalls = [BIG, R(0x200000, 0x80), R(0x300000, 0x80)]  # count changed
        assert (svc._lenient_region_fingerprint([BIG, SMALL_A])
                != svc._lenient_region_fingerprint(more_smalls))

    def test_namespace_prefix_prevents_collision(self):
        regions = [BIG, SMALL_A]
        assert svc._lenient_region_fingerprint(regions) != svc._region_fingerprint(regions)

    def test_fingerprint_for_mode_dispatch(self):
        regions = [BIG, SMALL_A]
        assert svc._fingerprint_for(regions, "lenient") == svc._lenient_region_fingerprint(regions)
        assert svc._fingerprint_for(regions, "strict") == svc._region_fingerprint(regions)
        # unknown modes fall back to strict (behavior freeze)
        assert svc._fingerprint_for(regions, "garbage") == svc._region_fingerprint(regions)

    def test_region_fingerprint_body_untouched_reference(self):
        # golden reference: the frozen implementation is a plain base:size hash
        import hashlib
        h = hashlib.sha1()
        for r in (BIG, SMALL_A):
            h.update(f"{r.base:x}:{r.size:x};".encode())
        assert svc._region_fingerprint([BIG, SMALL_A]) == h.hexdigest()[:16]


class TestStaleDetail:
    def test_small_region_move(self):
        old = [[0x200000, 0x1000], [0x300000, 0x100]]
        new = [R(0x200000, 0x1000), R(0x310000, 0x100)]
        d = svc._stale_detail(old, new)
        assert d == {"regions_added": 1, "regions_removed": 1,
                     "bytes_delta": 0, "large_region_changed": False}

    def test_large_region_change_flagged(self):
        old = [[0x10000000, 0x20000]]
        new = [R(0x10000000, 0x30000)]
        d = svc._stale_detail(old, new)
        assert d["large_region_changed"] is True
        assert d["bytes_delta"] == 0x30000 - 0x20000

    def test_empty_inputs(self):
        d = svc._stale_detail([], [])
        assert d == {"regions_added": 0, "regions_removed": 0,
                     "bytes_delta": 0, "large_region_changed": False}


class TestConfigMode:
    def test_default_is_strict(self, tmp_config):
        assert tmp_config.scan_fingerprint_mode == "strict"

    def test_lenient_opt_in_and_invalid_fallback(self):
        c = Config({"scan": {"fingerprint_mode": "lenient"}})
        assert c.scan_fingerprint_mode == "lenient"
        bad = Config({"scan": {"fingerprint_mode": "bogus"}})
        assert bad.scan_fingerprint_mode == "strict"


# ---------------------------------------------------------------------------
# service integration: scan -> layout churn -> scan_next
# ---------------------------------------------------------------------------

from game_modifier import service as svc_mod  # noqa: E402
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402


def _make_config(tmp_path, mode=None):
    scan = {"max_results": 1000, "chunk_size": 4096, "alignment": 1, "max_region_bytes": 0}
    if mode:
        scan["fingerprint_mode"] = mode
    return Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": True,
                   "require_writable_region": True},
        "scan": scan,
        "output": {"format": "json"},
        "paths": {"home": str(tmp_path / ".game-modifier")},
        "tools": {"search_dirs": {"extra": []}},
    })


@pytest.fixture
def churn_env(tmp_path, fake_backend_factory, monkeypatch):
    """Service whose small side region can be MOVED (count/bytes preserved)."""
    main = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x100)
    small = bytearray(0x100)
    fake = fake_backend_factory(regions={0x200000: main, 0x300000: small})

    def make(mode=None):
        monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
        monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
        monkeypatch.setattr(procmod, "list_processes", lambda: [])
        # one shared home so sessions survive a config/mode switch
        service = ModifierService(_make_config(tmp_path / "home", mode))
        sid = service.attach(pid=4242)["session_id"]
        return service, sid

    def move_small():
        buf = fake._regions.pop(0x300000)
        fake._regions[0x310000] = buf

    return make, move_small


def test_strict_mode_small_churn_flips_stale(churn_env):
    make, move_small = churn_env
    service, sid = make(None)  # default strict
    service.scan(session_id=sid, type="int32", value="1000")
    move_small()
    out = service.scan_next(session_id=sid, value="1000")
    assert out["cache_stale"] is True
    assert "cache_stale_hint" in out
    assert set(out["stale_detail"]) == {"regions_added", "regions_removed",
                                        "bytes_delta", "large_region_changed"}
    assert out["stale_detail"]["large_region_changed"] is False
    assert "retained_stale" not in out


def test_lenient_mode_small_churn_does_not_flip(churn_env):
    make, move_small = churn_env
    service, sid = make("lenient")
    service.scan(session_id=sid, type="int32", value="1000")
    move_small()
    out = service.scan_next(session_id=sid, value="1000")
    assert "cache_stale" not in out
    assert "stale_detail" not in out


def test_retain_stale_flag(churn_env):
    make, move_small = churn_env
    service, sid = make(None)
    service.scan(session_id=sid, type="int32", value="1000")
    move_small()
    out = service.scan_next(session_id=sid, value="1000", retain_stale=True)
    assert out["cache_stale"] is True
    assert out["retained_stale"] is True
    assert "retain_stale" in out["cache_stale_hint"]
    # refinement still ran on the retained candidate set
    assert out["count"] >= 1


def test_mode_switch_conservatively_stale(churn_env, tmp_path):
    """Switching fingerprint modes between scans must flag stale (never silent)."""
    make, _ = churn_env
    service, sid = make(None)
    service.scan(session_id=sid, type="int32", value="1000")
    # layout unchanged, mode changed -> a second service on the same home
    # (get_backend/procmod already monkeypatched by make()) must flag stale
    service2 = ModifierService(_make_config(tmp_path / "home", "lenient"))
    out = service2.scan_next(session_id=sid, value="1000")
    assert out["cache_stale"] is True


def test_conditional_keys_registered_in_surface_lock(churn_env):
    """stale_detail/retained_stale are registered conditional scan_next keys."""
    from test_surface_lock import SERVICE_CONDITIONAL_KEYS, SERVICE_RESULT_KEYS
    assert {"stale_detail", "retained_stale"} <= SERVICE_CONDITIONAL_KEYS["scan_next"]

    make, move_small = churn_env
    service, sid = make(None)
    service.scan(session_id=sid, type="int32", value="1000")
    move_small()
    out = service.scan_next(session_id=sid, value="1000", retain_stale=True)
    allowed = SERVICE_RESULT_KEYS["scan_next"] | SERVICE_CONDITIONAL_KEYS["scan_next"]
    assert set(out.keys()) <= allowed

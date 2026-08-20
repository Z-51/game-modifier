"""Task #44: batch_run result persistence/pagination + scan parallelism/progress.

Covers:
- full batch results persisted to sessions/<id>/batch_results/<ts>.json
- offset/limit windowing of the inline results (backward-compatible keys)
- confirm writes keep old_value/backup_id per item
- workers=1 vs workers=4 scan consistency (FakeBackend)
- first_scan progress_cb counts (serial + parallel paths)
- CLI batch run --offset/--limit parsing
- MCP batch_run tool registers offset/limit parameters
"""

from __future__ import annotations

import json
import struct

import pytest
import yaml

from game_modifier.cli import build_parser
from game_modifier.memory import process as procmod
from game_modifier.memory import scanner
from game_modifier.memory.base import ModuleInfo
from game_modifier.service import ModifierService


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

REGION_BASE = 0x200000
REGION_SIZE = 0x400  # 256 int32 slots


@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    # shared fake backend so writes persist across service calls
    region = bytearray(b"\x00" * REGION_SIZE)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={REGION_BASE: region}, modules=[mod], name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


def _write_batch_yaml(tmp_path, n_ops: int = 63) -> str:
    ops = [
        {"modify": {"address": hex(REGION_BASE + i * 8), "value": str(100 + i), "type": "int32"}}
        for i in range(n_ops)
    ]
    batch = tmp_path / "ops.yaml"
    batch.write_text(yaml.safe_dump({"operations": ops}), encoding="utf-8")
    return str(batch)


# ---------------------------------------------------------------------------
# batch_run persistence / pagination / compatibility
# ---------------------------------------------------------------------------

def test_batch_results_persisted(service, tmp_path):
    svc, _fake = service
    sid = svc.attach(pid=4242)["session_id"]
    summary = svc.batch_run(session_id=sid, path=_write_batch_yaml(tmp_path, 63))

    assert summary["results_total"] == 63
    assert len(summary["results"]) == 63  # limit=0 keeps everything inline
    rf = summary["results_file"]
    assert rf, "batch results must be persisted to disk"
    assert "batch_results" in rf.replace("\\", "/")

    # the persisted file holds the complete result set
    full = svc.store.read_batch_result(rf)
    assert len(full["results"]) == 63
    assert full["results_total"] == 63
    assert full["ok_count"] == 63
    # raw JSON round-trip agrees too
    assert json.loads(open(rf, encoding="utf-8").read())["executed"] == 63


def test_batch_pagination(service, tmp_path):
    svc, _fake = service
    sid = svc.attach(pid=4242)["session_id"]
    batch = _write_batch_yaml(tmp_path, 63)

    win = svc.batch_run(session_id=sid, path=batch, offset=10, limit=5)
    assert len(win["results"]) == 5
    assert win["results"][0]["index"] == 10
    assert win["results"][-1]["index"] == 14
    assert win["offset"] == 10 and win["limit"] == 5
    assert win["results_total"] == 63  # full count always reported

    # offset only (limit=0) returns the tail; persisted file stays complete
    tail = svc.batch_run(session_id=sid, path=batch, offset=60, limit=0)
    assert len(tail["results"]) == 3
    assert tail["results"][0]["index"] == 60
    assert len(svc.store.read_batch_result(tail["results_file"])["results"]) == 63


def test_batch_return_compat(service, tmp_path):
    svc, _fake = service
    sid = svc.attach(pid=4242)["session_id"]
    summary = svc.batch_run(session_id=sid, path=_write_batch_yaml(tmp_path, 5), confirm=True)

    # pre-existing return keys must all still be present (regression contract)
    for key in ("total", "executed", "ok_count", "error_count", "stopped_early",
                "results", "session_id", "confirm"):
        assert key in summary, f"existing key {key!r} missing from batch_run result"
    assert summary["total"] == 5
    assert summary["executed"] == 5
    assert summary["ok_count"] == 5
    assert summary["error_count"] == 0
    assert summary["stopped_early"] is False
    assert summary["session_id"] == sid
    assert summary["confirm"] is True
    # per-item stable fields
    for item in summary["results"]:
        assert item["op"] == "modify"
        assert item["action"] == "modify"
        assert item["error_code"] is None


def test_batch_old_value_preserved(service, tmp_path):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    # seed one slot with a non-zero old value
    fake.write(REGION_BASE + 16, struct.pack("<i", 555))
    summary = svc.batch_run(session_id=sid, path=_write_batch_yaml(tmp_path, 3), confirm=True)

    assert summary["confirm"] is True
    for item in summary["results"]:
        assert item.get("applied") is True
        assert "old_value" in item, "confirmed modify results must carry old_value"
        assert item.get("backup_id"), "confirmed modify results must carry backup_id"
    # the seeded slot reports its real pre-write value for recovery
    seeded = next(r for r in summary["results"] if r["address_hex"] == hex(REGION_BASE + 16))
    assert seeded["old_value"] == 555


# ---------------------------------------------------------------------------
# scan workers consistency + progress callback
# ---------------------------------------------------------------------------

def _scan_regions() -> dict:
    """Four deterministic regions with a handful of int32 targets (0x1E61)."""
    regions = {}
    for ri, base in enumerate((0x100000, 0x200000, 0x300000, 0x400000)):
        buf = bytearray(b"\x11" * 0x800)
        for slot in range(ri + 1):  # 1..4 hits per region
            struct.pack_into("<i", buf, slot * 16, 7777)
        regions[base] = buf
    return regions


def test_scan_workers_consistency(fake_backend_factory):
    regions = _scan_regions()
    ref = scanner.first_scan(fake_backend_factory(regions=regions), "int32", 7777, alignment=4, workers=1)
    assert ref.count == 10  # 1+2+3+4 hits

    factory = lambda: fake_backend_factory(regions=regions)  # noqa: E731 - fresh backend per worker
    par = scanner.first_scan(factory(), "int32", 7777, alignment=4,
                             workers=4, backend_factory=factory)
    assert par.addresses == ref.addresses, "workers=4 must match workers=1 candidate order"
    assert par.values == ref.values
    assert par.count == ref.count
    assert par.scanned_regions == ref.scanned_regions
    assert par.scanned_bytes == ref.scanned_bytes


def test_scan_progress_cb(fake_backend_factory):
    regions = _scan_regions()

    # serial path
    events: list[dict] = []
    res = scanner.first_scan(fake_backend_factory(regions=regions), "int32", 7777,
                             alignment=4, workers=1, progress_cb=events.append)
    assert len(events) == 4
    assert [e["regions_done"] for e in events] == [1, 2, 3, 4]
    assert all(e["regions_total"] == 4 for e in events)
    assert events[-1]["bytes_scanned"] == res.scanned_bytes
    assert events[-1]["hits"] == res.count == 10

    # parallel path: completion-order counters converge on the same totals
    pevents: list[dict] = []
    factory = lambda: fake_backend_factory(regions=regions)  # noqa: E731
    par = scanner.first_scan(factory(), "int32", 7777, alignment=4,
                             workers=4, backend_factory=factory, progress_cb=pevents.append)
    assert len(pevents) == 4
    assert pevents[-1]["regions_done"] == pevents[-1]["regions_total"] == 4
    assert pevents[-1]["bytes_scanned"] == par.scanned_bytes
    assert pevents[-1]["hits"] == par.count == 10

    # callback errors must not break the scan
    def _boom(_p):
        raise RuntimeError("bad callback")

    res2 = scanner.first_scan(fake_backend_factory(regions=regions), "int32", 7777,
                              alignment=4, progress_cb=_boom)
    assert res2.count == 10


# ---------------------------------------------------------------------------
# CLI + MCP plumbing
# ---------------------------------------------------------------------------

def test_cli_batch_pagination_parsing():
    parser = build_parser()
    args = parser.parse_args(["batch", "run", "--session", "s1",
                              "--offset", "5", "--limit", "10", "ops.yaml"])
    assert args.offset == 5
    assert args.limit == 10
    assert args.file == "ops.yaml"
    # defaults
    args = parser.parse_args(["batch", "run", "--session", "s1", "ops.yaml"])
    assert args.offset == 0 and args.limit == 0
    # scan gained --progress
    sargs = parser.parse_args(["scan", "--session", "s1", "--value", "5", "--progress"])
    assert sargs.progress is True


def test_mcp_batch_params(tmp_path):
    mcp_server = pytest.importorskip("game_modifier.mcp_server")
    pytest.importorskip("mcp")
    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    server = mcp_server.build_server(str(cfg))

    # locate the registered batch_run tool across FastMCP versions
    tm = getattr(server, "_tool_manager", None)
    tool = tm._tools.get("batch_run") if tm is not None and hasattr(tm, "_tools") else None
    schema = None
    if tool is not None:
        for attr in ("parameters", "input_schema", "inputSchema"):
            val = getattr(tool, attr, None)
            if callable(val):
                try:
                    val = val()
                except Exception:
                    continue
            if isinstance(val, dict) and "properties" in val:
                schema = val
                break
    if schema is None:
        import asyncio

        listed = asyncio.run(server.list_tools())
        t = next(t for t in listed if t.name == "batch_run")
        schema = getattr(t, "inputSchema", None) or getattr(t, "parameters", None)
    assert schema is not None, "batch_run tool schema not found"

    props = schema["properties"]
    assert "offset" in props, "batch_run tool must expose offset"
    assert "limit" in props, "batch_run tool must expose limit"
    # existing params stay registered
    for key in ("session", "file", "confirm", "stop_on_error"):
        assert key in props

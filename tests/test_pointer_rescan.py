"""Pointer-path rescan refinement + sidecar persistence tests (phase 2.2)."""

from __future__ import annotations

import asyncio
import json

import pytest

from conftest import FakeBackend

import game_modifier.analysis.pointerscan as psmod
import game_modifier.service as svcmod
from game_modifier.analysis import find_pointer_paths, rescan_paths
from game_modifier.errors import ErrorCode, LayoutUnsupportedError
from game_modifier.memory import process as procmod
from game_modifier.memory.base import MemoryRegion
from game_modifier.service import ModifierService
from game_modifier.session import Session, SessionStore

STATIC = 0x300000  # static storage holding a pointer into the heap
HEAP = 0x200000  # heap region holding a pointer to the target
TARGET = 0x400010  # the value address we want a chain to
TARGET2 = TARGET + 0x5000  # where the object "moves" after a layout change


def p64(v: int) -> bytes:
    return v.to_bytes(8, "little")


class ScanBackend(FakeBackend):
    """FakeBackend whose regions are readable/writable but not executable."""

    def regions(self):
        return [
            MemoryRegion(base=base, size=len(buf), readable=True, writable=True, executable=False, state=0x1000)
            for base, buf in self._regions.items()
        ]


def make_chain_backend(target: int = TARGET) -> ScanBackend:
    """Build: STATIC+8 -> HEAP+0x30 (+8 offset), HEAP+0x30 -> ``target``."""

    static = bytearray(0x40)
    static[0x08:0x10] = p64(HEAP + 0x28)  # points at HEAP+0x30 minus 8
    heap = bytearray(0x100)
    heap[0x30:0x38] = p64(target)
    return ScanBackend(regions={STATIC: static, HEAP: heap})


def discover_paths(backend: ScanBackend, target: int = TARGET) -> list[dict]:
    res = find_pointer_paths(backend, target, max_depth=2, max_paths=100, timeout=30.0)
    assert len(res["paths"]) >= 2
    return res["paths"]


# ------------------------------------------------------------------ rescan core
def test_rescan_validates_paths():
    backend = make_chain_backend()
    paths = discover_paths(backend)
    res = rescan_paths(backend, paths, TARGET, timeout=30.0)
    assert res["valid_count"] == len(paths)
    assert res["invalid_count"] == 0
    assert res["truncated"] is False
    bases = {p["base"] for p in res["paths"]}
    assert hex(HEAP + 0x30) in bases
    assert hex(STATIC + 0x08) in bases
    assert all("stability" in p for p in res["paths"])


def test_rescan_drops_stale():
    backend = make_chain_backend()
    paths = discover_paths(backend)
    # the object relocates: both chain hops now land at TARGET2
    backend.write(HEAP + 0x30, p64(TARGET2))
    # against the old address every path is stale
    stale = rescan_paths(backend, paths, TARGET, timeout=30.0)
    assert stale["valid_count"] == 0
    assert stale["invalid_count"] == len(paths)
    # against the new address they all validate again
    fresh = rescan_paths(backend, paths, TARGET2, timeout=30.0)
    assert fresh["valid_count"] == len(paths)
    assert fresh["invalid_count"] == 0


def test_rescan_sorting():
    backend = make_chain_backend()
    paths = discover_paths(backend)
    # feed the deep path first; survivors must come back shallow-first
    paths.sort(key=lambda p: -int(p["depth"]))
    res = rescan_paths(backend, paths, TARGET, timeout=30.0)
    depths = [p["depth"] for p in res["paths"]]
    assert depths == sorted(depths)
    assert res["paths"][0]["depth"] == 1


def test_rescan_timeout_partial(monkeypatch):
    backend = make_chain_backend()
    paths = discover_paths(backend)
    clock = [0.0]

    def fake_monotonic():
        value = clock[0]
        clock[0] += 1.0  # each call advances a full second -> instant expiry
        return value

    monkeypatch.setattr(psmod.time, "monotonic", fake_monotonic)
    res = rescan_paths(backend, paths, TARGET, timeout=0.5)
    assert res["truncated"] is True
    assert res["valid_count"] <= len(paths)
    assert "elapsed" in res


# ------------------------------------------------------------------- sidecar IO
def test_paths_sidecar_roundtrip(tmp_path):
    store = SessionStore(tmp_path / "sessions")
    paths = [
        {"base": hex(HEAP + 0x30), "offsets": [0], "depth": 1},
        {"base": hex(STATIC + 0x08), "offsets": [8, 0], "depth": 2, "stability": 1.0},
    ]
    store.write_pointer_paths("sid-1", paths)
    assert store.pointer_paths_path("sid-1").exists()
    assert store.read_pointer_paths("sid-1") == paths


def test_paths_sidecar_missing(tmp_path):
    store = SessionStore(tmp_path / "sessions")
    assert store.read_pointer_paths("never-written") == []


def test_pointer_scan_meta_persist():
    sess = Session(id="meta-1", pid=42)
    sess.pointer_scan_meta = {"count": 3, "created_at": 123.0, "file": "pointer_paths.bin"}
    data = sess.to_dict()
    assert data["pointer_scan_meta"]["count"] == 3
    back = Session.from_dict(json.loads(json.dumps(data)))
    assert back.pointer_scan_meta == sess.pointer_scan_meta
    # legacy session JSON without the field stays loadable
    legacy = {"id": "old-1", "pid": 7}
    assert Session.from_dict(legacy).pointer_scan_meta == {}


# -------------------------------------------------------------- service wiring
@pytest.fixture
def scan_service(tmp_config, monkeypatch):
    backend = make_chain_backend()
    monkeypatch.setattr(svcmod, "get_backend", lambda: backend)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config)


def test_service_pointer_rescan(scan_service):
    sid = scan_service.attach(pid=4242)["session_id"]
    # nothing saved yet -> typed error with a recovery hint
    with pytest.raises(LayoutUnsupportedError) as excinfo:
        scan_service.pointer_rescan(session_id=sid, address=hex(TARGET))
    assert excinfo.value.code == ErrorCode.LAYOUT_UNSUPPORTED
    assert excinfo.value.hint

    # discover + persist, then rescan validates and refreshes the sidecar
    scan_service.pointer_scan(session_id=sid, address=hex(TARGET), max_depth=2, max_paths=100)
    saved = scan_service.store.read_pointer_paths(sid)
    assert len(saved) >= 2

    res = scan_service.pointer_rescan(session_id=sid, address=hex(TARGET))
    assert res["valid_count"] == len(saved)
    assert res["invalid_count"] == 0
    assert res["rescanned"] == len(saved)
    assert res["session_id"] == sid
    meta = scan_service.store.load(sid).pointer_scan_meta
    assert meta["count"] == res["valid_count"]
    assert meta["file"] == "pointer_paths.bin"
    assert scan_service.store.read_pointer_paths(sid) == res["paths"]


def test_service_pointer_scan_externalizes_large_results(scan_service, monkeypatch):
    sid = scan_service.attach(pid=4242)["session_id"]
    monkeypatch.setattr(svcmod, "_POINTER_PATHS_INLINE_LIMIT", 1)
    res = scan_service.pointer_scan(session_id=sid, address=hex(TARGET), max_depth=2, max_paths=100)
    assert res["paths_file"] is True
    assert res["paths_total"] >= 2
    assert res["paths_sample"] == res["paths"]
    assert len(res["paths_sample"]) <= 20
    # full set still recoverable from the sidecar
    assert len(scan_service.store.read_pointer_paths(sid)) == res["paths_total"]


# ------------------------------------------------------------------- CLI / MCP
def test_cli_rescan_flag():
    from game_modifier.cli import build_parser

    ns = build_parser().parse_args(
        ["pointer-scan", "--session", "s1", "--address", "0x400010", "--rescan"]
    )
    assert ns.rescan is True
    ns2 = build_parser().parse_args(["pointer-scan", "--session", "s1", "--address", "0x400010"])
    assert ns2.rescan is False


def test_mcp_pointer_scan_rescan_param(tmp_path):
    mcp = pytest.importorskip("mcp")  # noqa: F841 - optional dependency
    from game_modifier import mcp_server

    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    server = mcp_server.build_server(str(cfg), profile="readonly")
    tools = asyncio.run(server.list_tools())
    tool = next(t for t in tools if t.name == "pointer_scan")
    props = tool.inputSchema.get("properties", {})
    assert "rescan" in props
    assert props["rescan"].get("default") is False
    # original parameters untouched
    assert {"session", "address", "max_depth", "max_paths"} <= set(props)

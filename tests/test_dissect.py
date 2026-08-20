"""Structure dissect tests (CE-style field inference) on FakeBackend."""

from __future__ import annotations

import struct

import pytest

from conftest import FakeBackend

from game_modifier.analysis import dissect_structure
from game_modifier.cli import build_parser
from game_modifier.memory import process as procmod
from game_modifier.memory.base import MemoryRegion
from game_modifier.service import ModifierService

CODE = 0x100000
HEAP = 0x200000
TARGET = 0x300000

INST_ADDRS = [HEAP, HEAP + 0x100, HEAP + 0x200]

# field offsets inside each fake instance
OFF_VTABLE = 0x00
OFF_INT = 0x08
OFF_FLOAT = 0x10
OFF_BOOL = 0x18
OFF_PTR = 0x20


def p64(v: int) -> bytes:
    return v.to_bytes(8, "little")


class DissectBackend(FakeBackend):
    """FakeBackend with per-region executable/writable flags."""

    def __init__(self, flags=None, **kwargs):
        super().__init__(**kwargs)
        self._flags = flags or {}

    def regions(self):
        out = []
        for base, buf in self._regions.items():
            f = self._flags.get(base, {})
            out.append(
                MemoryRegion(
                    base=base,
                    size=len(buf),
                    readable=f.get("readable", True),
                    writable=f.get("writable", True),
                    executable=f.get("executable", False),
                    state=0x1000,
                )
            )
        return out


def make_dissect_backend(instances: int = 3) -> DissectBackend:
    """Heap holding ``instances`` fake objects:

    +0x00 vtable ptr (into executable CODE), +0x08 varying int count,
    +0x10 float32, +0x18 bool, +0x20 heap pointer, rest zero padding.
    """

    heap = bytearray(0x1000)
    int_values = [100, 250, 777]
    float_values = [3.14, 2.5, 100.25]
    bool_values = [1, 0, 1]
    for i in range(instances):
        inst = i * 0x100
        heap[inst + OFF_VTABLE : inst + OFF_VTABLE + 8] = p64(CODE + 0x20)
        heap[inst + OFF_INT : inst + OFF_INT + 8] = p64(int_values[i % len(int_values)])
        heap[inst + OFF_FLOAT : inst + OFF_FLOAT + 4] = struct.pack("<f", float_values[i % len(float_values)])
        heap[inst + OFF_BOOL : inst + OFF_BOOL + 8] = p64(bool_values[i % len(bool_values)])
        heap[inst + OFF_PTR : inst + OFF_PTR + 8] = p64(TARGET + 0x10)
    return DissectBackend(
        regions={CODE: bytearray(0x1000), HEAP: heap, TARGET: bytearray(0x1000)},
        flags={CODE: {"executable": True, "writable": False}},
    )


def _by_offset(res: dict) -> dict:
    return {f["offset"]: f for f in res["fields"]}


def test_dissect_vtable_slot():
    backend = make_dissect_backend()
    res = dissect_structure(backend, INST_ADDRS)
    fields = _by_offset(res)
    vt = fields[OFF_VTABLE]
    assert vt["guessed_type"] == "vtable"
    assert vt["confidence"] > 0.5
    assert "executable" in vt["reason"]
    assert vt["sample_values"] == [hex(CODE + 0x20)] * 3


def test_dissect_pointer_fields():
    backend = make_dissect_backend()
    res = dissect_structure(backend, INST_ADDRS)
    fields = _by_offset(res)
    ptr = fields[OFF_PTR]
    assert ptr["guessed_type"] == "ptr"
    assert ptr["confidence"] > 0.5
    assert ptr["sample_values"] == [hex(TARGET + 0x10)] * 3
    assert "readable regions" in ptr["reason"]


def test_dissect_float_field():
    backend = make_dissect_backend()
    res = dissect_structure(backend, INST_ADDRS)
    fields = _by_offset(res)
    fl = fields[OFF_FLOAT]
    assert fl["guessed_type"] == "float"
    assert fl["confidence"] > 0.5
    assert len(fl["sample_values"]) == 3
    assert abs(fl["sample_values"][0] - 3.14) < 1e-4
    assert abs(fl["sample_values"][2] - 100.25) < 1e-4


def test_dissect_bool_field():
    backend = make_dissect_backend()
    res = dissect_structure(backend, INST_ADDRS)
    fields = _by_offset(res)
    bl = fields[OFF_BOOL]
    assert bl["guessed_type"] == "bool"
    assert bl["sample_values"] == [1, 0, 1]
    # all-zero slots are padding, never bool
    zero = [f for f in res["fields"] if f["offset"] > OFF_PTR and all(v == 0 for v in f["sample_values"])]
    assert zero and all(f["guessed_type"] == "unknown" for f in zero)


def test_dissect_multi_instance():
    backend = make_dissect_backend()
    res = dissect_structure(backend, INST_ADDRS)
    assert res["instances_used"] == 3
    assert res["instances_skipped"] == 0
    assert res["size_analyzed"] == 256
    fields = _by_offset(res)
    # int field varies across instances -> flagged in the reason
    int_field = fields[OFF_INT]
    assert int_field["guessed_type"] == "int"
    assert int_field["sample_values"] == [100, 250, 777]
    assert "vary across instances" in int_field["reason"]
    # multi-instance agreement lifts confidence close to the 0.9 ceiling
    assert fields[OFF_PTR]["confidence"] > 0.6
    assert all(f["confidence"] <= 0.9 for f in res["fields"])


def test_dissect_single_instance_cap():
    backend = make_dissect_backend(instances=1)
    res = dissect_structure(backend, [HEAP])
    assert res["instances_used"] == 1
    fields = _by_offset(res)
    assert fields[OFF_VTABLE]["guessed_type"] == "vtable"
    assert fields[OFF_PTR]["guessed_type"] == "ptr"
    assert all(f["confidence"] <= 0.6 for f in res["fields"])
    # and multi-instance dissection of the same fields scores strictly higher
    multi = dissect_structure(backend, INST_ADDRS)
    multi_fields = _by_offset(multi)
    assert multi_fields[OFF_PTR]["confidence"] > fields[OFF_PTR]["confidence"]


def test_dissect_unreadable_graceful():
    backend = make_dissect_backend(instances=1)
    res = dissect_structure(backend, [HEAP, 0xDEAD0000])
    assert res["instances_used"] == 1
    assert res["instances_skipped"] == 1
    fields = _by_offset(res)
    assert fields[OFF_VTABLE]["guessed_type"] == "vtable"
    assert "skipped" in res["reason"]
    # every address unreadable -> empty field table, no exception
    empty = dissect_structure(backend, [0xDEAD0000, 0xDEAD1000])
    assert empty["instances_used"] == 0
    assert empty["fields"] == []


# ------------------------------------------------------------- service wiring
@pytest.fixture
def dissect_service(tmp_config, monkeypatch):
    backend = make_dissect_backend()
    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: backend)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), backend


def test_service_dissect(dissect_service):
    service, _ = dissect_service
    sid = service.attach(pid=4242)["session_id"]
    # single instance address
    res = service.dissect(sid, address=hex(HEAP))
    assert res["session_id"] == sid
    assert res["instances_used"] == 1
    assert any(f["guessed_type"] == "vtable" for f in res["fields"])
    # comma-separated multi-instance string
    res2 = service.dissect(sid, addresses=",".join(hex(a) for a in INST_ADDRS))
    assert res2["instances_used"] == 3
    # no address at all -> E_INVALID_ARGS
    from game_modifier.errors import InvalidArgsError

    with pytest.raises(InvalidArgsError):
        service.dissect(sid)


# --------------------------------------------------------------- CLI parsing
def test_cli_dissect_parsing():
    parser = build_parser()
    args = parser.parse_args(["dissect", "--session", "s1", "--address", "0x200000"])
    assert args.command == "dissect" and args.address == "0x200000" and args.size == 256
    args = parser.parse_args(
        ["dissect", "--session", "s1", "--addresses", "0x200000,0x200100", "--size", "128"])
    assert args.addresses == "0x200000,0x200100" and args.size == 128


# ------------------------------------------------------------ MCP registration
def test_mcp_dissect_registered(tmp_path):
    pytest.importorskip("mcp")
    from game_modifier import mcp_server

    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    def _tool_names(server) -> set:
        tm = getattr(server, "_tool_manager", None)
        if tm is not None and hasattr(tm, "_tools"):
            return set(tm._tools.keys())
        import asyncio

        return {t.name for t in asyncio.run(server.list_tools())}

    default_names = _tool_names(mcp_server.build_server(str(cfg)))
    readonly_names = _tool_names(mcp_server.build_server(str(cfg), profile="readonly"))
    assert "dissect" in default_names
    assert "dissect" in readonly_names  # read-only: available in both profiles

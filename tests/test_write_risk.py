"""Task #52: modify dry-run explicit status + batch write-risk grading.

Covers:
- modify dry-run returns status="dry_run_preview" (+ hint), confirmed writes
  return status="applied" (additive: applied/dry_run keys unchanged)
- _classify_write_risk: data region -> normal, executable -> high,
  unknown/unqueryable -> conservative high
- batch dry-run: per-item risk + risk_breakdown summary (+ hint on high)
- staged confirmation: confirm=True only applies risk=normal writes;
  high-risk items are skipped (skipped_reason) unless confirm_code=True
- read operations are unaffected by the risk gate
- existing batch_run return keys stay intact (regression contract)
- CLI batch run --confirm-code flag + MCP batch_run confirm_code parameter
"""

from __future__ import annotations

import struct

import pytest
import yaml

from game_modifier.cli import build_parser
from game_modifier.memory import process as procmod
from game_modifier.memory.base import MemoryRegion, ModuleInfo
from game_modifier.service import ModifierService

from conftest import FakeBackend


DATA = 0x200000  # writable, non-executable data region
CODE = 0x400000  # executable (RWX) code region


class RiskBackend(FakeBackend):
    """FakeBackend with per-region executable/writable flags on query/regions."""

    def __init__(self, flags=None, **kwargs):
        super().__init__(**kwargs)
        self._flags = flags or {}

    def _region_for(self, address: int):
        base, buf = self._find(address)
        if buf is None:
            return None
        f = self._flags.get(base, {})
        return MemoryRegion(
            base=base,
            size=len(buf),
            readable=f.get("readable", True),
            writable=f.get("writable", True),
            executable=f.get("executable", False),
            state=0x1000,
        )

    def query(self, address: int):
        return self._region_for(address)

    def regions(self):
        return [self._region_for(base) for base in self._regions]


@pytest.fixture
def service(tmp_config, monkeypatch):
    data = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x100)
    code = bytearray(struct.pack("<i", 0x0A0B0C0D) + b"\x00" * 0x100)
    fake = RiskBackend(
        regions={DATA: data, CODE: code},
        flags={DATA: {"writable": True, "executable": False},
               CODE: {"writable": True, "executable": True}},
        modules=[ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")],
        name="fake.exe", pid=4242,
    )

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


def _batch_yaml(tmp_path, ops) -> str:
    p = tmp_path / "ops.yaml"
    p.write_text(yaml.safe_dump({"operations": ops}), encoding="utf-8")
    return str(p)


# ----------------------------------------------------------------- modify status

def test_modify_dry_run_status_field(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    dry = svc.modify(session_id=sid, address=hex(DATA), type="int32", value="5", confirm=False)
    assert dry["status"] == "dry_run_preview"
    assert dry["applied"] is False and dry["dry_run"] is True  # legacy keys kept
    assert dry["hint"]  # explicit preview hint present
    assert dry["risk"] == "normal"
    assert struct.unpack("<i", fake.read(DATA, 4))[0] == 1000  # untouched


def test_modify_applied_status(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    res = svc.modify(session_id=sid, address=hex(DATA), type="int32", value="77", confirm=True)
    assert res["status"] == "applied"
    assert res["applied"] is True and res["dry_run"] is False
    assert struct.unpack("<i", fake.read(DATA, 4))[0] == 77


# ---------------------------------------------------------------- risk classify

def test_classify_risk_data_region(service):
    svc, fake = service
    svc.attach(pid=4242)
    assert svc._classify_write_risk(fake, DATA + 0x10, 4) == "normal"


def test_classify_risk_code_region(service):
    svc, fake = service
    svc.attach(pid=4242)
    assert svc._classify_write_risk(fake, CODE + 0x10, 4) == "high"


def test_classify_risk_unknown(service):
    svc, fake = service
    svc.attach(pid=4242)
    # unmapped address: query() -> None and regions() finds nothing -> high
    assert svc._classify_write_risk(fake, 0x900000, 4) == "high"


# --------------------------------------------------------------- batch grading

def test_batch_dry_run_risk_breakdown(service, tmp_path):
    svc, _fake = service
    sid = svc.attach(pid=4242)["session_id"]
    ops = [
        {"modify": {"address": hex(DATA), "value": "1", "type": "int32"}},
        {"modify": {"address": hex(CODE), "value": "2", "type": "int32"}},
        {"modify": {"address": hex(DATA + 8), "value": "3", "type": "int32"}},
    ]
    summary = svc.batch_run(session_id=sid, path=_batch_yaml(tmp_path, ops))

    assert summary["confirm"] is False
    risks = [r.get("risk") for r in summary["results"]]
    assert risks == ["normal", "high", "normal"]
    assert summary["risk_breakdown"] == {"high": 1, "normal": 2}
    # a high-risk item in the preview triggers a warning hint
    assert summary.get("hint") and "confirm_code" in summary["hint"]
    # nothing was written
    for item in summary["results"]:
        assert item.get("applied") is False
        assert item.get("status") == "dry_run_preview"


def test_batch_confirm_data_only(service, tmp_path):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    ops = [
        {"modify": {"address": hex(DATA), "value": "111", "type": "int32"}},
        {"modify": {"address": hex(CODE), "value": "222", "type": "int32"}},
    ]
    summary = svc.batch_run(session_id=sid, path=_batch_yaml(tmp_path, ops), confirm=True)

    applied = summary["results"][0]
    assert applied.get("applied") is True and applied.get("status") == "applied"
    assert struct.unpack("<i", fake.read(DATA, 4))[0] == 111

    skipped = summary["results"][1]
    assert skipped.get("skipped") is True
    assert skipped.get("skipped_reason") == "high_risk_requires_confirm_code"
    assert skipped.get("applied") is False
    assert skipped.get("ok") is True  # a skip is not a failure
    assert struct.unpack("<i", fake.read(CODE, 4))[0] == 0x0A0B0C0D  # code untouched

    assert summary["skipped_high_risk"] == 1
    assert summary["error_count"] == 0
    assert summary["risk_breakdown"]["high"] == 1
    assert "confirm_code" in summary.get("hint", "")


def test_batch_confirm_code_all(service, tmp_path):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    ops = [
        {"modify": {"address": hex(DATA), "value": "111", "type": "int32"}},
        {"modify": {"address": hex(CODE), "value": "222", "type": "int32"}},
    ]
    summary = svc.batch_run(session_id=sid, path=_batch_yaml(tmp_path, ops),
                            confirm=True, confirm_code=True)

    assert summary["confirm_code"] is True
    assert summary["ok_count"] == 2 and summary["error_count"] == 0
    for item in summary["results"]:
        assert item.get("applied") is True
        assert item.get("skipped") is not True
    assert struct.unpack("<i", fake.read(DATA, 4))[0] == 111
    assert struct.unpack("<i", fake.read(CODE, 4))[0] == 222  # code write released


def test_batch_reads_unaffected(service, tmp_path):
    svc, _fake = service
    sid = svc.attach(pid=4242)["session_id"]
    ops = [
        {"read": {"address": hex(DATA), "type": "int32"}},
        {"modify": {"address": hex(DATA), "value": "9", "type": "int32"}},
    ]
    summary = svc.batch_run(session_id=sid, path=_batch_yaml(tmp_path, ops), confirm=True)

    rd = summary["results"][0]
    assert rd["ok"] is True and rd["value"] == 1000
    assert rd.get("skipped") is not True
    assert rd.get("skipped_reason") is None
    # the write next to it still goes through (normal-risk data region)
    assert summary["results"][1].get("applied") is True


def test_batch_return_compat(service, tmp_path):
    svc, _fake = service
    sid = svc.attach(pid=4242)["session_id"]
    ops = [{"modify": {"address": hex(DATA), "value": "1", "type": "int32"}}]
    summary = svc.batch_run(session_id=sid, path=_batch_yaml(tmp_path, ops), confirm=True)

    for key in ("total", "executed", "ok_count", "error_count", "stopped_early",
                "results", "session_id", "confirm", "results_total", "results_file"):
        assert key in summary, f"existing key {key!r} missing from batch_run result"
    item = summary["results"][0]
    assert item["op"] == "modify" and item["action"] == "modify"
    assert item["error_code"] is None


# ------------------------------------------------------------ CLI + MCP wiring

def test_cli_confirm_code_flag():
    parser = build_parser()
    args = parser.parse_args(["batch", "run", "--session", "s1", "ops.yaml",
                              "--confirm", "--confirm-code"])
    assert args.confirm is True
    assert args.confirm_code is True
    # default stays off (backward compatible)
    args = parser.parse_args(["batch", "run", "--session", "s1", "ops.yaml"])
    assert args.confirm_code is False


def test_mcp_batch_confirm_code_param(tmp_path):
    mcp_server = pytest.importorskip("game_modifier.mcp_server")
    pytest.importorskip("mcp")
    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    server = mcp_server.build_server(str(cfg))

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
    assert "confirm_code" in props, "batch_run tool must expose confirm_code"
    # existing params stay registered
    for key in ("session", "file", "confirm", "stop_on_error", "offset", "limit"):
        assert key in props

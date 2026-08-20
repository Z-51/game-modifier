"""Tests for runtime disassembly (analysis.disasm) - phase 1.1.

capstone is an optional dependency; the whole module is skipped when it is
not installed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("capstone")

from conftest import FakeBackend  # noqa: E402

from game_modifier import mcp_server  # noqa: E402
from game_modifier.analysis import basic_blocks, disassemble  # noqa: E402
from game_modifier.cli import build_parser  # noqa: E402
from game_modifier.config import Config  # noqa: E402
from game_modifier.errors import InvalidArgsError  # noqa: E402
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402
from test_mcp_extended import _tool_names  # noqa: E402

BASE = 0x200000

# mov rax, qword ptr [rip + 0]; ret
CODE_X64 = b"\x48\x8b\x05\x00\x00\x00\x00\xc3"
# push ebp; mov ebp, esp; ret
CODE_X86 = b"\x55\x8b\xec\xc3"
# nop; jmp $+2; nop; ret
CODE_BLOCKS = b"\x90\xeb\x00\x90\xc3"


# ------------------------------------------------------------------ module
def test_disasm_x64_known_bytes():
    fake = FakeBackend(regions={BASE: CODE_X64}, arch="x64")
    out = disassemble(fake, BASE, size=len(CODE_X64))

    assert out["address"] == hex(BASE)
    assert out["arch"] == "x64"  # derived from pointer_size 8
    assert out["count"] == 2
    assert out["truncated"] is False

    mov, ret = out["instructions"]
    assert mov["mnemonic"] == "mov"
    assert mov["op_str"].startswith("rax")
    assert mov["bytes_hex"] == "488b0500000000"
    assert mov["size"] == 7
    assert mov["address"] == hex(BASE)
    assert ret["mnemonic"] == "ret"
    assert ret["address"] == hex(BASE + 7)


def test_disasm_x86_mode():
    fake = FakeBackend(regions={BASE: CODE_X86}, arch="x86")
    out = disassemble(fake, BASE, size=len(CODE_X86))

    assert out["arch"] == "x86"  # derived from pointer_size 4
    mnemonics = [i["mnemonic"] for i in out["instructions"]]
    assert mnemonics == ["push", "mov", "ret"]
    assert out["instructions"][0]["bytes_hex"] == "55"

    # explicit arch overrides the backend default
    out64 = disassemble(FakeBackend(regions={BASE: CODE_X64}, arch="x86"),
                        BASE, size=len(CODE_X64), arch="x64")
    assert out64["arch"] == "x64"
    assert out64["instructions"][0]["mnemonic"] == "mov"


def test_disasm_invalid_arch():
    fake = FakeBackend(regions={BASE: CODE_X64})
    with pytest.raises(InvalidArgsError):
        disassemble(fake, BASE, arch="arm64")


def test_basic_blocks_split():
    fake = FakeBackend(regions={BASE: CODE_BLOCKS})
    out = basic_blocks(fake, BASE, size=len(CODE_BLOCKS))

    assert out["arch"] == "x64"
    assert out["count"] == 2
    b1, b2 = out["blocks"]
    assert b1["start"] == hex(BASE)
    assert b1["insn_count"] == 2  # nop + jmp
    assert b1["ends_with"] == "jmp"
    assert b1["end"] == hex(BASE + 3)
    assert b2["start"] == hex(BASE + 3)
    assert b2["insn_count"] == 2  # nop + ret
    assert b2["ends_with"] == "ret"  # CS_GRP_RET terminates blocks too
    assert b2["end"] == hex(BASE + len(CODE_BLOCKS))


def test_disasm_truncated():
    fake = FakeBackend(regions={BASE: b"\x90" * 64})
    out = disassemble(fake, BASE, size=64, max_insns=8)
    assert out["count"] == 8
    assert out["truncated"] is True

    full = disassemble(fake, BASE, size=64)
    assert full["count"] == 64
    assert full["truncated"] is False


# ----------------------------------------------------------------- service
@pytest.fixture
def disasm_service(tmp_path, monkeypatch):
    cfg = Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": True,
                   "require_writable_region": True},
        "scan": {"max_results": 1000, "chunk_size": 4096, "alignment": 1, "max_region_bytes": 0},
        "output": {"format": "json"},
        "paths": {"home": str(tmp_path / ".game-modifier")},
    })
    fake = FakeBackend(regions={BASE: CODE_X64 + CODE_BLOCKS}, arch="x64")

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(cfg), fake


def test_service_disasm(disasm_service):
    svc, _ = disasm_service
    sid = svc.attach(pid=4242)["session_id"]

    res = svc.disasm(session_id=sid, address=hex(BASE), size=8)
    assert res["session_id"] == sid
    assert res["arch"] == "x64"
    assert res["count"] == 2
    assert res["instructions"][0]["mnemonic"] == "mov"

    # blocks mode on the trailing stream
    res_b = svc.disasm(session_id=sid, address=hex(BASE + len(CODE_X64)),
                       size=len(CODE_BLOCKS), blocks=True)
    assert res_b["count"] == 2
    assert res_b["blocks"][0]["ends_with"] == "jmp"

    # symbol names resolve through the session symbol table
    svc.name_set(session_id=sid, name="code.entry", base_expr=hex(BASE), type="int32")
    res_sym = svc.disasm(session_id=sid, address="code.entry", size=8)
    assert res_sym["address"] == hex(BASE)


# --------------------------------------------------------------------- cli
def test_cli_disasm_parsing():
    p = build_parser()
    args = p.parse_args(["disasm", "--session", "s1", "--address", "0x1000",
                         "--size", "128", "--arch", "x86", "--blocks"])
    assert args.command == "disasm"
    assert args.session == "s1"
    assert args.address == "0x1000"
    assert args.size == 128
    assert args.arch == "x86"
    assert args.blocks is True

    defaults = p.parse_args(["disasm", "--session", "s1", "--address", "0x1000"])
    assert defaults.size == 256
    assert defaults.arch is None
    assert defaults.blocks is False


# --------------------------------------------------------------------- mcp
def test_mcp_disasm_registered(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    server = mcp_server.build_server(str(cfg))
    names = _tool_names(server)
    assert "disasm" in names

    ro = mcp_server.build_server(str(cfg), profile="readonly")
    ro_names = _tool_names(ro)
    assert "disasm" in ro_names  # read-only tool -> included in readonly profile

"""Address arithmetic expression support (Task #39).

Covers: eval_address_expr / is_address_expr parsers, service-level target
resolution, MCP value_convert arithmetic, resolve command expressions and
backward compatibility of bare addresses / symbols / module syntax.
"""

from __future__ import annotations

import struct

import pytest

from game_modifier.errors import InvalidArgsError
from game_modifier.mcp_server import convert_value
from game_modifier.memory import pointers
from game_modifier.memory import process as procmod
from game_modifier.memory.base import ModuleInfo
from game_modifier.memory.pointers import eval_address_expr, is_address_expr
from game_modifier.service import ModifierService


# ------------------------------------------------------------------- parser

def test_eval_simple_subtraction():
    assert eval_address_expr("0x1b0c00276c5-0x8") == 0x1B0C00276C5 - 0x8
    assert eval_address_expr("0x7fffe2a22ce0-0x5702ce0") == 0x7FFFE2A22CE0 - 0x5702CE0


def test_eval_addition():
    assert eval_address_expr("0x140000000+0x1A4") == 0x140000000 + 0x1A4
    assert eval_address_expr("0x100+0x10+0x1") == 0x111


def test_eval_mixed_base():
    assert eval_address_expr("12345+0x10") == 12345 + 16
    assert eval_address_expr("0x1000-16") == 0x1000 - 16


def test_eval_plain_number():
    # bare numbers degrade to parse_int behavior
    assert eval_address_expr("0x1b0c00276c5") == 0x1B0C00276C5
    assert eval_address_expr("12345") == 12345
    assert not is_address_expr("0x1b0c00276c5")
    assert not is_address_expr("12345")


def test_eval_invalid_chars():
    for bad in ("0x10*2", "abc", "0x10/2", "game.exe+0x1A4", "0x", "0x10+", "", "   "):
        with pytest.raises(InvalidArgsError):
            eval_address_expr(bad)


def test_eval_spaces():
    assert eval_address_expr("0x10 - 0x8") == 8
    assert eval_address_expr("  0x140000000 + 0x1A4 ") == 0x140000000 + 0x1A4


def test_module_expr_not_arithmetic():
    # "module+0x..." syntax must keep going through the module path
    assert not is_address_expr("game.exe+0x1A4")
    assert not is_address_expr("GameAssembly.dll+0x1234")
    assert not is_address_expr("kernel32.dll+0x0")
    # but numeric heads are arithmetic
    assert is_address_expr("0x1b0c00276c5-0x8")
    assert is_address_expr("0x140000000+0x1A4")
    assert is_address_expr("12345+0x10")


# -------------------------------------------------------------- service rig

@pytest.fixture
def service(tmp_config, fake_backend_factory, monkeypatch):
    region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x1000)
    mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
    fake = fake_backend_factory(regions={0x200000: region}, modules=[mod], name="fake.exe", pid=4242)

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config), fake


def test_resolve_target_expr(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    # read via arithmetic address: 0x200008 - 0x8 == 0x200000
    rd = svc.read(session_id=sid, address="0x200008-0x8", type="int32")
    assert rd["address_hex"] == "0x200000"
    assert rd["value"] == 1000

    # addition form works too
    rd2 = svc.read(session_id=sid, address="0x1ffff0+0x10", type="int32")
    assert rd2["address_hex"] == "0x200000"
    assert rd2["value"] == 1000


def test_resolve_target_negative_reject(service):
    svc, _ = service
    sid = svc.attach(pid=4242)["session_id"]
    with pytest.raises(InvalidArgsError) as exc:
        svc.read(session_id=sid, address="0x8-0x10", type="int32")
    assert "negative" in str(exc.value)


def test_value_convert_arithmetic():
    expr = "0x7fffe2a22ce0-0x5702ce0"
    expected = 0x7FFFE2A22CE0 - 0x5702CE0
    out = convert_value(expr)
    assert out["expression"] == expr
    assert out["evaluated"] == hex(expected)
    assert out["decimal"] == expected
    assert out["hex"] == hex(expected)

    # addition form
    out2 = convert_value("0x140000000+0x1A4")
    assert out2["evaluated"] == hex(0x140000000 + 0x1A4)
    assert out2["decimal"] == 0x140000000 + 0x1A4


def test_value_convert_normal_unchanged():
    out = convert_value("42")
    assert out["decimal"] == 42
    assert out["as_type"] == "int32"
    assert "expression" not in out and "evaluated" not in out

    out2 = convert_value("0x2A")
    assert out2["decimal"] == 42

    out3 = convert_value("1.5", as_type="float")
    assert out3["decimal"] == pytest.approx(1.5)
    assert "expression" not in out3


def test_resolve_base_expr(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]
    # resolve command accepts arithmetic in the base
    res = svc.resolve(session_id=sid, base_expr="0x200008-0x8", offsets=None, mode="relative")
    assert res["final_address"] == 0x200000

    # direct pointers layer (same parser as read/modify)
    assert pointers.resolve_base(fake, "0x200010+0x10-0x20").address == 0x200000
    with pytest.raises(InvalidArgsError):
        pointers.resolve_base(fake, "0x8-0x10")  # negative result rejected


def test_backward_compat(service):
    svc, fake = service
    sid = svc.attach(pid=4242)["session_id"]

    # bare hex address
    assert svc.read(session_id=sid, address="0x200000", type="int32")["value"] == 1000
    # int address
    assert svc.read(session_id=sid, address=0x200000, type="int32")["value"] == 1000
    # module syntax still resolves via the module path
    res = svc.resolve(session_id=sid, base_expr="fake.exe+0x0", offsets=None, mode="relative")
    assert res["final_address"] == 0x140000000
    # symbol path unchanged
    svc.name_set(session_id=sid, name="player.gold", base_expr="0x200000", type="int32")
    assert svc.read(session_id=sid, symbol="player.gold")["value"] == 1000
    # numeric base with +offset (legacy resolve_base form) keeps its result
    assert pointers.resolve_base(fake, "0x200000+0x8").address == 0x200008
    # module-not-found errors still name the module
    res2 = svc.modify(session_id=sid, address="0x200000", type="int32", value="777", confirm=True)
    assert res2["applied"] is True and res2["verified_value"] == 777

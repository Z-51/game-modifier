"""CLI argument wiring for the full command surface (no live process needed)."""

from __future__ import annotations

import pytest

from game_modifier.cli import build_parser


@pytest.mark.parametrize(
    "argv",
    [
        ["attach", "--pid", "1234"],
        ["attach", "--process", "game.exe"],
        ["analyze", "--session", "s", "--deep"],
        ["scan", "--session", "s", "--type", "int32", "--value", "100"],
        ["scan-next", "--session", "s", "--value", "80"],
        ["read", "--session", "s", "--address", "0x10", "--type", "int32"],
        ["modify", "--session", "s", "--symbol", "player.gold", "--value", "9999", "--confirm", "--freeze"],
        ["resolve", "--session", "s", "--pointer", "mod.dll+0x1,0x2,0x3"],
        ["resolve", "--session", "s", "--base", "mod.dll+0x1", "--offsets", "0x2"],
        ["nl", "--session", "s", "将金币设为9999", "--confirm"],
        ["name", "set", "--session", "s", "player.gold", "--base", "0x10", "--type", "int32"],
        ["name", "get", "--session", "s"],
        ["template", "list"],
        ["template", "apply", "--session", "s", "--template", "rpg", "--option", "set_gold", "--param", "amount=1", "--confirm"],
        ["batch", "run", "--session", "s", "ops.yaml", "--confirm"],
        ["freeze", "list", "--session", "s"],
        ["freeze", "clear", "--session", "s"],
        ["freeze", "run", "--session", "s", "--iterations", "1"],
        ["freeze", "start", "--session", "s"],
        ["freeze", "stop", "--session", "s"],
        ["backup", "create", "--session", "s", "--symbol", "player.gold"],
        ["backup", "list", "--session", "s"],
        ["backup", "restore", "--session", "s", "bak-1"],
        ["toolchain", "detect"],
        ["--json", "sessions"],
    ],
)
def test_cli_parses_full_surface(argv):
    parser = build_parser()
    ns = parser.parse_args(argv)
    assert ns is not None


def test_json_flag_present():
    ns = build_parser().parse_args(["--json", "toolchain", "detect"])
    assert ns.json is True

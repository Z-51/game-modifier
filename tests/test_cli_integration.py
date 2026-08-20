"""CLI end-to-end wiring with a stubbed service layer.

The service is replaced by a recorder so these tests exercise the real argparse
surface, dispatch mapping, error translation and output rendering without ever
touching a live process or the filesystem.
"""

from __future__ import annotations

import argparse
import json

import pytest

from game_modifier import __version__, cli
from game_modifier.config import Config
from game_modifier.errors import ErrorCode, GameModifierError, SessionNotFoundError


class FakeService:
    """Records every service call and returns canned payloads."""

    def __init__(self, config) -> None:
        self.config = config
        self.calls: list[tuple[str, dict]] = []
        self.returns: dict[str, object] = {}
        self.raises: BaseException | None = None

    def __getattr__(self, name: str):
        if name.startswith("__"):
            raise AttributeError(name)

        def _call(**kwargs):
            self.calls.append((name, kwargs))
            if self.raises is not None:
                raise self.raises
            return self.returns.get(name, {"called": name})

        return _call

    # convenience assertions -------------------------------------------------
    def last(self) -> tuple[str, dict]:
        assert self.calls, "no service call was made"
        return self.calls[-1]


class CliRun:
    def __init__(self, code: int, out: str, err: str) -> None:
        self.code = code
        self.out = out
        self.err = err

    @property
    def payload(self) -> dict:
        return json.loads(self.out)


class Harness:
    def __init__(self, service: FakeService, capsys) -> None:
        self.service = service
        self._capsys = capsys

    def run(self, argv: list[str]) -> CliRun:
        code = cli.main(argv)
        captured = self._capsys.readouterr()
        return CliRun(code, captured.out, captured.err)


@pytest.fixture
def harness(tmp_path, monkeypatch, capsys):
    config = Config(
        {
            "safety": {"dry_run": True},
            "output": {"format": "json"},
            "paths": {"home": str(tmp_path / ".game-modifier")},
        }
    )
    service = FakeService(config)

    monkeypatch.setattr(cli, "load_config", lambda path=None: config)
    monkeypatch.setattr(cli, "ModifierService", lambda cfg: service)

    return Harness(service, capsys)


# ---------------------------------------------------------------------- attach
def test_cli_attach_e2e(harness):
    harness.service.returns["attach"] = {
        "session_id": "game-abcd1234",
        "pid": 4242,
        "process": "game.exe",
        "engine": {"engine": "unity-il2cpp"},
    }

    run = harness.run(["attach", "--pid", "4242"])

    assert run.code == 0
    assert run.payload == {
        "ok": True,
        "command": "attach",
        "data": harness.service.returns["attach"],
    }
    assert harness.service.last() == (
        "attach",
        {"pid": 4242, "name": None, "exe": None, "title": None, "allow_anti_cheat": False},
    )


def test_cli_attach_by_process_name_and_override(harness):
    harness.run(["attach", "--process", "game.exe", "--allow-anti-cheat"])

    name, kwargs = harness.service.last()
    assert name == "attach"
    assert kwargs["name"] == "game.exe"
    assert kwargs["pid"] is None
    assert kwargs["allow_anti_cheat"] is True


# ---------------------------------------------------------------------- modify
def test_cli_modify_dry_run(harness):
    harness.service.returns["modify"] = {
        "applied": False,
        "dry_run": True,
        "address": "0x140001000",
        "old_value": 100,
        "new_value": 9999,
    }

    run = harness.run(["modify", "--session", "s1", "--symbol", "player.gold", "--value", "9999"])

    assert run.code == 0
    assert run.payload["ok"] is True
    assert run.payload["data"]["dry_run"] is True
    assert harness.service.last() == (
        "modify",
        {
            "session_id": "s1",
            "symbol": "player.gold",
            "address": None,
            "type": None,
            "value": "9999",
            "offsets": None,
            "mode": None,
            "confirm": False,
            "freeze": False,
            "confirm_code": False,
        },
    )


def test_cli_modify_confirm(harness):
    harness.service.returns["modify"] = {"applied": True, "dry_run": False, "new_value": 9999}

    run = harness.run(
        [
            "modify", "--session", "s1", "--address", "0x140001000", "--type", "int32",
            "--offsets", "0x10,0x20", "--value", "9999", "--confirm", "--freeze",
        ]
    )

    assert run.code == 0
    assert run.payload["data"]["applied"] is True
    _, kwargs = harness.service.last()
    assert kwargs["confirm"] is True
    assert kwargs["freeze"] is True
    assert kwargs["address"] == "0x140001000"
    assert kwargs["offsets"] == "0x10,0x20"
    assert kwargs["type"] == "int32"


# -------------------------------------------------------------------------- nl
def test_cli_nl_e2e(harness):
    harness.service.returns["nl"] = {
        "intent": {"action": "set", "field": "gold", "value": 9999, "confidence": 0.9, "raw": "将金币设为9999"},
        "applied": True,
    }

    run = harness.run(["nl", "--session", "s1", "将金币设为9999", "--confirm"])

    assert run.code == 0
    assert run.payload["command"] == "nl"
    assert run.payload["data"]["intent"]["field"] == "gold"
    assert harness.service.last() == ("nl", {"session_id": "s1", "text": "将金币设为9999",
                                             "confirm": True, "confirm_code": False})
    assert "将金币设为9999" in run.out  # unicode is not escaped


# ------------------------------------------------------------------------ scan
def test_cli_scan_e2e(harness):
    harness.service.returns["scan"] = {"count": 2, "addresses": ["0x1000", "0x2000"], "truncated": False}

    run = harness.run(["scan", "--session", "s1", "--type", "int32", "--value", "100"])

    assert run.code == 0
    assert run.payload["data"]["count"] == 2
    assert harness.service.last() == (
        "scan",
        {"session_id": "s1", "type": "int32", "value": "100", "comparator": "exact", "value2": None},
    )


def test_cli_scan_next_uses_previous_candidates(harness):
    harness.service.returns["scan_next"] = {"count": 1}

    run = harness.run(["scan-next", "--session", "s1", "--comparator", "lt", "--value", "80"])

    assert run.code == 0
    assert run.payload["command"] == "scan-next"
    assert harness.service.last() == (
        "scan_next",
        {"session_id": "s1", "comparator": "lt", "value": "80", "value2": None},
    )


def test_cli_scan_candidates_exact_kwargs(harness):
    harness.service.returns["scan_candidates"] = {"candidates_total": 10, "addresses_hex": []}

    run = harness.run(["scan-candidates", "--session", "s1"])

    assert run.code == 0
    assert run.payload["command"] == "scan-candidates"
    assert harness.service.last() == (
        "scan_candidates",
        {"session_id": "s1", "offset": 0, "limit": 100, "min_addr": None, "max_addr": None},
    )


def test_cli_scan_candidates_addr_parsing(harness):
    harness.service.returns["scan_candidates"] = {"candidates_total": 3}

    run = harness.run([
        "scan-candidates", "--session", "s1", "--offset", "10", "--limit", "25",
        "--min-addr", "0x200000", "--max-addr", "4194304",
    ])

    assert run.code == 0
    assert harness.service.last() == (
        "scan_candidates",
        {"session_id": "s1", "offset": 10, "limit": 25,
         "min_addr": 0x200000, "max_addr": 4194304},
    )


def test_cli_resolve_pointer_is_split_into_base_and_offsets(harness):
    harness.service.returns["resolve"] = {"address": "0x140001000"}

    run = harness.run(["resolve", "--session", "s1", "--pointer", "mod.dll+0x1234,0x10,0x20"])

    assert run.code == 0
    assert harness.service.last() == (
        "resolve",
        {"session_id": "s1", "base_expr": "mod.dll+0x1234", "offsets": "0x10,0x20",
         "mode": "pointer_chain", "deref_last": True},
    )


# ------------------------------------------------------------------- rendering
def test_cli_error_json_output(harness):
    harness.service.raises = SessionNotFoundError(
        "session not found: 'ghost'",
        details={"session_id": "ghost", "known": []},
        hint="Run `game-modifier attach` first.",
    )

    run = harness.run(["read", "--session", "ghost", "--address", "0x10"])

    assert run.code == 1
    payload = run.payload
    assert payload["ok"] is False
    assert payload["command"] == "read"
    assert "data" not in payload
    assert payload["error"]["code"] == ErrorCode.SESSION_NOT_FOUND.value
    assert payload["error"]["details"]["session_id"] == "ghost"
    assert payload["error"]["hint"]


def test_cli_unexpected_exception_becomes_internal_error(harness):
    harness.service.raises = RuntimeError("kaboom")

    run = harness.run(["sessions"])

    assert run.code == 1
    assert run.payload["error"]["code"] == "E_INTERNAL"
    assert run.payload["error"]["message"] == "RuntimeError: kaboom"


def test_cli_keyboard_interrupt_is_reported_as_success(harness):
    harness.service.raises = KeyboardInterrupt()

    run = harness.run(["freeze", "run", "--session", "s1"])

    assert run.code == 0
    assert run.payload["data"] == {"interrupted": True}


def test_cli_human_output(harness):
    harness.service.returns["list_sessions"] = [{"session_id": "game-abcd1234", "pid": 4242}]

    run = harness.run(["--format", "human", "sessions"])

    assert run.code == 0
    assert run.out.startswith("[OK] sessions\n")
    assert '"session_id": "game-abcd1234"' in run.out


def test_cli_human_output_for_errors(harness):
    harness.service.raises = GameModifierError("needs --confirm", code=ErrorCode.NOT_CONFIRMED, hint="add --confirm")

    run = harness.run(["--format", "human", "modify", "--session", "s1", "--symbol", "gold", "--value", "1"])

    assert run.code == 1
    assert run.out.startswith("[ERROR] modify\n")
    assert "  code: E_NOT_CONFIRMED\n" in run.out
    assert "  hint: add --confirm\n" in run.out


def test_cli_json_pretty_and_json_flag(harness):
    pretty = harness.run(["--format", "json-pretty", "sessions"])
    assert '\n  "ok": true' in pretty.out

    # --json wins over --format
    compact = harness.run(["--json", "--format", "human", "sessions"])
    assert compact.out.count("\n") == 1
    assert compact.payload["ok"] is True


def test_cli_uses_config_output_format(tmp_path, monkeypatch, capsys):
    config = Config({"output": {"format": "human"}, "paths": {"home": str(tmp_path)}})
    monkeypatch.setattr(cli, "load_config", lambda path=None: config)
    monkeypatch.setattr(cli, "ModifierService", lambda cfg: FakeService(cfg))

    assert cli.main(["sessions"]) == 0
    assert capsys.readouterr().out.startswith("[OK] sessions\n")


# ------------------------------------------------------------------- meta args
def test_cli_version(harness):
    run = harness.run(["--version"])

    assert run.code == 0
    assert run.payload == {"ok": True, "command": "version", "data": {"version": __version__}}
    assert harness.service.calls == []  # no service work for --version


def test_cli_no_command_shows_help(harness):
    run = harness.run([])

    assert run.code == 2
    assert run.out == ""
    assert "usage: game-modifier" in run.err
    assert harness.service.calls == []


def test_cli_invalid_args(harness):
    # attach requires exactly one target selector
    with pytest.raises(SystemExit) as excinfo:
        harness.run(["attach"])
    assert excinfo.value.code == 2

    with pytest.raises(SystemExit):
        harness.run(["attach", "--pid", "1", "--process", "game.exe"])

    with pytest.raises(SystemExit):
        harness.run(["modify", "--value", "1"])  # --session is required

    with pytest.raises(SystemExit):
        harness.run(["--format", "xml", "sessions"])  # not a supported format

    assert harness.service.calls == []


def test_cli_resolve_without_base_is_structured_error(harness):
    run = harness.run(["resolve", "--session", "s1"])

    assert run.code == 1
    assert run.payload["error"]["code"] == "E_INVALID_ARGS"
    assert "provide --base or --pointer" in run.payload["error"]["message"]
    assert harness.service.calls == []


def test_cli_config_error_is_structured(tmp_path, monkeypatch, capsys):
    def _boom(path=None):
        raise FileNotFoundError("config file not found: nope.toml")

    monkeypatch.setattr(cli, "load_config", _boom)

    code = cli.main(["--config", "nope.toml", "sessions"])

    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"]["code"] == "E_INVALID_ARGS"
    assert "config error" in payload["error"]["message"]


def test_cli_unknown_command_dispatch(harness):
    result = cli.dispatch(harness.service, argparse.Namespace(command="bogus"))

    assert result.ok is False
    assert result.error["code"] == "E_INVALID_ARGS"
    assert result.exit_code == 1


def test_cli_parse_params_helper():
    assert cli._parse_params(["a=1", " b = two ", "novalue", "c=x=y"]) == {"a": "1", "b": "two", "c": "x=y"}
    assert cli._parse_params([]) == {}
    assert cli._parse_params(None) == {}


def test_cli_name_set_mode_reaches_real_service(tmp_path):
    """Regression: `name set --mode` passed mode= to a service signature that
    rejected it (TypeError at dispatch time). Dispatch against the real
    ModifierService to prove the parameter is accepted and persisted."""

    from game_modifier.service import ModifierService
    from game_modifier.session import Session

    config = Config(
        {"output": {"format": "json"}, "paths": {"home": str(tmp_path / ".game-modifier")}}
    )
    service = ModifierService(config)
    service.store.save(Session(id="s-mode", pid=4242))

    ns = cli.build_parser().parse_args(
        ["name", "set", "--session", "s-mode", "player.gold",
         "--base", "mod.dll+0x10", "--mode", "pointer_chain"]
    )
    result = cli.dispatch(service, ns)  # must not raise TypeError

    assert result.ok is True
    assert result.data["mode"] == "pointer_chain"
    sym = service.name_get(session_id="s-mode", name="player.gold")
    assert sym["mode"] == "pointer_chain"


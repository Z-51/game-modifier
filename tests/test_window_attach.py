"""Attach by window title (stage 3).

``EnumWindows`` cannot be driven deterministically in a test run, so the window
enumeration hook is monkeypatched and only the pid de-duplication / resolution
logic above it is exercised.
"""

from __future__ import annotations

import pytest

from game_modifier.errors import ErrorCode, GameModifierError, ProcessNotFoundError
from game_modifier.memory import process as procmod
from game_modifier.memory.process import ProcInfo
from game_modifier.service import ModifierService


def _fake_enum(monkeypatch, windows):
    """Install a fake ``find_windows_by_title`` on the process module."""

    monkeypatch.setattr(procmod, "find_windows_by_title", lambda pattern: list(windows), raising=False)


def _fake_get_process(monkeypatch, known=None):
    def _get(pid):
        if known is not None and pid not in known:
            return None
        return ProcInfo(pid=pid, name=f"game{pid}.exe", exe=f"C:/games/game{pid}.exe")

    monkeypatch.setattr(procmod, "get_process", _get)


# ---------------------------------------------------------------- process layer
def test_find_by_window_title_single_match(monkeypatch):
    _fake_enum(monkeypatch, [{"hwnd": 1234, "pid": 5678, "title": "My RPG Game"}])
    _fake_get_process(monkeypatch)

    matches = procmod.find_by_window_title("rpg")
    assert [m.pid for m in matches] == [5678]
    assert matches[0].name == "game5678.exe"


def test_find_by_window_title_no_match(monkeypatch):
    _fake_enum(monkeypatch, [])
    _fake_get_process(monkeypatch)

    assert procmod.find_by_window_title("nothing here") == []


def test_find_by_window_title_dedupes_pids(monkeypatch):
    _fake_enum(monkeypatch, [
        {"hwnd": 1, "pid": 100, "title": "Game - main"},
        {"hwnd": 2, "pid": 100, "title": "Game - console"},
    ])
    _fake_get_process(monkeypatch)

    matches = procmod.find_by_window_title("game")
    assert [m.pid for m in matches] == [100]


def test_find_by_window_title_multiple_processes(monkeypatch):
    _fake_enum(monkeypatch, [
        {"hwnd": 1, "pid": 100, "title": "Game client"},
        {"hwnd": 2, "pid": 200, "title": "Game launcher"},
    ])
    _fake_get_process(monkeypatch)

    assert [m.pid for m in procmod.find_by_window_title("game")] == [100, 200]


def test_find_by_window_title_skips_dead_pids(monkeypatch):
    _fake_enum(monkeypatch, [
        {"hwnd": 1, "pid": 100, "title": "Game"},
        {"hwnd": 2, "pid": 999, "title": "Game ghost"},
    ])
    _fake_get_process(monkeypatch, known={100})

    assert [m.pid for m in procmod.find_by_window_title("game")] == [100]


# ---------------------------------------------------------------- service layer
def test_resolve_pid_by_title(monkeypatch, tmp_config):
    service = ModifierService(tmp_config)
    monkeypatch.setattr(procmod, "find_by_window_title", lambda t: [ProcInfo(pid=4242, name="game.exe")])

    assert service._resolve_pid(title="My Game") == 4242


def test_resolve_pid_title_not_found(monkeypatch, tmp_config):
    service = ModifierService(tmp_config)
    monkeypatch.setattr(procmod, "find_by_window_title", lambda t: [])

    with pytest.raises(ProcessNotFoundError) as excinfo:
        service._resolve_pid(title="Missing")
    assert excinfo.value.details["title_pattern"] == "Missing"


def test_resolve_pid_title_multiple_raises(monkeypatch, tmp_config):
    service = ModifierService(tmp_config)
    monkeypatch.setattr(procmod, "find_by_window_title", lambda t: [
        ProcInfo(pid=1, name="a.exe"), ProcInfo(pid=2, name="b.exe"),
    ])

    with pytest.raises(GameModifierError) as excinfo:
        service._resolve_pid(title="Game")
    assert excinfo.value.code == ErrorCode.INVALID_ARGS
    assert [c["pid"] for c in excinfo.value.details["candidates"]] == [1, 2]


def test_resolve_pid_without_any_selector_mentions_title(tmp_config):
    service = ModifierService(tmp_config)

    with pytest.raises(GameModifierError) as excinfo:
        service._resolve_pid()
    assert "--title" in str(excinfo.value)


def test_attach_forwards_title(monkeypatch, tmp_config):
    service = ModifierService(tmp_config)
    seen = {}

    def _resolve(**kwargs):
        seen.update(kwargs)
        raise ProcessNotFoundError("stop here")

    monkeypatch.setattr(service, "_resolve_pid", _resolve)
    with pytest.raises(ProcessNotFoundError):
        service.attach(title="My Game")
    assert seen["title"] == "My Game"


# -------------------------------------------------------------------------- CLI
def test_cli_attach_title_argument():
    from game_modifier.cli import build_parser

    args = build_parser().parse_args(["attach", "--title", "My Game"])
    assert args.title == "My Game"
    assert args.pid is None and args.process is None


def test_cli_title_exclusive_with_pid():
    from game_modifier.cli import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(["attach", "--title", "X", "--pid", "123"])

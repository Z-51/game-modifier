"""Template loading/expansion and batch validation."""

from __future__ import annotations

import pytest

from game_modifier import templates as tpl
from game_modifier import batch as batchmod
from game_modifier.errors import TemplateNotFoundError, BatchError


def test_builtin_templates_present():
    names = {t["name"] for t in tpl.list_templates()}
    assert {"rpg", "action", "strategy"} <= names


def test_load_and_options():
    t = tpl.load_template("action")
    assert "infinite_ammo" in t["options"]
    opt = tpl.get_option(t, "infinite_ammo")
    assert all("symbol" in tg for tg in opt.targets)


def test_expand_with_param():
    t = tpl.load_template("rpg")
    targets = tpl.expand_option(t, "set_gold", {"amount": 12345})
    assert targets[0]["symbol"] == "player.gold"
    assert targets[0]["value"] == 12345
    assert targets[0]["strategy"] == "set"


def test_expand_freeze_strategy():
    t = tpl.load_template("action")
    targets = tpl.expand_option(t, "infinite_health")
    assert targets[0]["strategy"] == "freeze"
    assert targets[0]["value"] == "max"


def test_missing_template():
    with pytest.raises(TemplateNotFoundError):
        tpl.load_template("nope")


def test_batch_validation_ok():
    data = {"operations": [{"nl": "将金币设为1"}, {"modify": {"symbol": "x", "value": 1}}]}
    assert batchmod.validate_batch(data)["operations"]


def test_batch_requires_single_action():
    with pytest.raises(BatchError):
        batchmod.validate_batch({"operations": [{"nl": "x", "modify": {}}]})


def test_batch_run_executor_counts():
    ops = [{"nl": "a"}, {"nl": "b"}, {"nl": "c"}]

    def execute(i, step):
        return {"ok": i != 1}  # second one fails

    summary = batchmod.run(ops, execute, stop_on_error=True)
    assert summary["ok_count"] == 1
    assert summary["error_count"] == 1
    assert summary["executed"] == 2  # stopped early

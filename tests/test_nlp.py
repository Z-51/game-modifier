"""Deterministic NLP intent parsing (Chinese + English)."""

from __future__ import annotations

import pytest

from game_modifier.nlp import parse
from game_modifier.nlp.intents import MAX
from game_modifier.nlp.lexicon import extract_number, parse_cn_number
from game_modifier.errors import NlpUnresolvedError


def test_set_gold():
    i = parse("将游戏金币设置为9999")
    assert i.action == "set" and i.field == "gold" and i.value == 9999
    assert i.value_type == "int32"


def test_set_move_speed_float():
    i = parse("将人物移速设置成5")
    assert i.action == "set" and i.field == "move_speed"
    assert i.value == 5 and i.value_type == "float"


def test_infinite_ammo_is_freeze():
    i = parse("无限弹药")
    assert i.action == "freeze" and i.field == "ammo" and i.value == MAX


def test_add_exp():
    i = parse("增加500经验")
    assert i.action == "add" and i.field == "exp" and i.value == 500


def test_english_set():
    i = parse("set health to 100")
    assert i.action == "set" and i.field == "health" and i.value == 100


def test_implicit_set():
    i = parse("金币9999")
    assert i.action == "set" and i.field == "gold" and i.value == 9999


def test_unlock_items():
    i = parse("获取一个该游戏全物品中的某一个物品")
    assert i.action == "unlock" and i.value == "items"


def test_get_action():
    i = parse("查看当前金币")
    assert i.action == "get" and i.field == "gold"


def test_chinese_numerals():
    assert parse_cn_number("九千九百九十九") == 9999
    assert parse_cn_number("一万") == 10000
    val, kind = extract_number("九千九百九十九金币")
    assert val == 9999 and kind == "int"


def test_unresolved_raises():
    with pytest.raises(NlpUnresolvedError):
        parse("你好呀今天天气不错")

"""Deep coverage of the deterministic NLP layer: lexicon, numbers, intents."""

from __future__ import annotations

import pytest

from game_modifier.errors import NlpUnresolvedError
from game_modifier.nlp import lexicon as lex
from game_modifier.nlp import parse
from game_modifier.nlp.intents import ACTIONS, MAX, MIN

# one unambiguous trigger term per semantic field
FIELD_PHRASES = {
    "gold": "金币",
    "gem": "钻石",
    "health": "血量",
    "mana": "法力",
    "stamina": "体力",
    "move_speed": "移动速度",
    "attack": "攻击力",
    "defense": "防御力",
    "ammo": "弹药",
    "level": "等级",
    "exp": "经验",
    "score": "分数",
    "lives": "生命数",
    "skill_points": "技能点",
    "durability": "耐久度",
    "attribute_points": "属性点",
}


# ------------------------------------------------------------- unresolved input
def test_parse_empty_string_raises():
    with pytest.raises(NlpUnresolvedError) as excinfo:
        parse("")

    exc = excinfo.value
    assert exc.code.value == "E_NLP_UNRESOLVED"
    assert exc.details["detected_field"] is None
    assert exc.details["detected_number"] is None
    # the error is actionable: it lists what the layer understands
    assert set(exc.details["hint_supported_fields"]) == set(lex.FIELDS)
    assert exc.hint


def test_parse_whitespace_only_raises():
    for text in ("   ", "\t\n", "　"):
        with pytest.raises(NlpUnresolvedError):
            parse(text)


def test_parse_number_without_field():
    """A bare number has no target, so it must not be guessed into a write."""

    with pytest.raises(NlpUnresolvedError) as excinfo:
        parse("9999")

    assert excinfo.value.details["detected_number"] == 9999
    assert excinfo.value.details["detected_field"] is None


def test_parse_none_input_raises():
    with pytest.raises(NlpUnresolvedError):
        parse(None)


# -------------------------------------------------------------------- fields
def test_parse_all_16_fields():
    assert set(FIELD_PHRASES) == set(lex.FIELDS)
    assert len(lex.FIELDS) == 16

    for field, term in FIELD_PHRASES.items():
        intent = parse(f"将{term}设为100")
        assert intent.field == field, f"{term!r} -> {intent.field!r}, expected {field!r}"
        assert intent.action == "set"
        assert intent.value == 100
        assert intent.matched["field_term"] == term


def test_parse_english_fields():
    assert parse("set health to 100").field == "health"
    assert parse("set ammo to 30").field == "ammo"
    assert parse("SET GOLD TO 500").field == "gold"  # matching is case-insensitive


def test_parse_prefers_the_most_specific_term():
    # "生命数" (lives) is longer than "生命" (health) and therefore wins
    assert parse("将生命数设为3").field == "lives"
    assert parse("将生命值设为3").field == "health"


def test_parse_value_type_from_field_default():
    assert parse("将移动速度设为5").value_type == "float"   # field default
    assert parse("将金币设为5").value_type == "int32"       # field default
    assert parse("将金币设为5.5").value_type == "float"     # a float literal wins


# ------------------------------------------------------------------- actions
def test_parse_all_7_actions():
    cases = {
        "set": ("将金币设为9999", 9999),
        "add": ("增加500经验", 500),
        "sub": ("减少50血量", 50),
        "freeze": ("无限弹药", MAX),
        "get": ("查看当前金币", None),
        "unlock": ("解锁所有关卡", "levels"),
    }
    for expected_action, (text, expected_value) in cases.items():
        intent = parse(text)
        assert intent.action == expected_action, f"{text!r} -> {intent.action!r}"
        assert intent.value == expected_value
        assert intent.action in ACTIONS

    # max/min cues are normalised onto "set" with a symbolic value
    assert (parse("血量拉满").action, parse("血量拉满").value) == ("set", MAX)
    assert (parse("金币清零").action, parse("金币清零").value) == ("set", MIN)


def test_parse_freeze_without_value_freezes_current():
    intent = parse("锁定金币")

    assert intent.action == "freeze"
    assert intent.value is None  # freeze whatever is there right now
    assert intent.matched["action_term"] == "锁定"


def test_parse_freeze_with_explicit_value():
    intent = parse("锁定金币为1000")

    assert intent.action == "freeze" and intent.value == 1000


def test_parse_unlock_targets():
    for text, target in (
        ("解锁所有关卡", "levels"),
        ("解锁全部道具", "items"),
        ("解锁所有成就", "achievements"),
        ("解锁所有角色", "characters"),
        ("解锁全部地图", "maps"),
    ):
        intent = parse(text)
        assert intent.action == "unlock"
        assert intent.value == target
        assert intent.field == f"unlock_{target}"
        assert intent.matched["unlock_target"] == target


def test_parse_intent_flags_and_dict():
    intent = parse("将金币设为9999")

    assert intent.is_write is True
    assert intent.needs_value is True
    payload = intent.to_dict()
    assert payload["action"] == "set"
    assert payload["field"] == "gold"
    assert payload["value"] == 9999
    assert payload["raw"] == "将金币设为9999"
    assert payload["confidence"] == 0.9

    read_only = parse("查看金币")
    assert read_only.is_write is False and read_only.needs_value is False


# --------------------------------------------------------------- confidence
def test_parse_confidence_scoring():
    explicit_set = parse("将金币设为9999").confidence      # strongest cue
    add = parse("增加500经验").confidence
    freeze = parse("无限弹药").confidence
    maxed = parse("血量拉满").confidence
    explicit_get = parse("查看金币").confidence
    implicit_set = parse("金币9999").confidence
    bare_field = parse("金币").confidence

    assert explicit_set == 0.9
    assert add == parse("减少50血量").confidence == 0.85
    assert freeze == 0.75
    assert maxed == explicit_get == 0.7
    assert implicit_set == 0.6
    assert bare_field == 0.4
    assert explicit_set > add > freeze > maxed > implicit_set > bare_field
    # an unknown target weakens a freeze considerably
    assert parse("冻结").confidence == 0.4


# ---------------------------------------------------------------- normalize
def test_normalize_fullwidth():
    assert lex.normalize("９９９９") == "9999"
    assert lex.normalize("１．５") == "1.5"
    assert lex.normalize("１，０００") == "1,000"
    assert lex.normalize("  金币  ") == "金币"  # trimmed
    assert lex.normalize("") == ""
    assert lex.normalize(None) == ""
    # a full-width number is parsed end-to-end
    assert parse("将金币设为９９９９").value == 9999


# ------------------------------------------------------------ chinese numbers
def test_cn_number_all_units():
    assert lex.parse_cn_number("十") == 10
    assert lex.parse_cn_number("一百") == 100
    assert lex.parse_cn_number("一千") == 1000
    assert lex.parse_cn_number("一万") == 10000
    assert lex.parse_cn_number("一亿") == 100000000
    # bare digits and zero
    assert lex.parse_cn_number("五") == 5
    assert lex.parse_cn_number("零") == 0
    assert lex.parse_cn_number("〇") == 0


def test_cn_number_complex():
    assert lex.parse_cn_number("九千九百九十九") == 9999
    assert lex.parse_cn_number("二十三") == 23
    assert lex.parse_cn_number("三万五千") == 35000
    assert lex.parse_cn_number("十五") == 15
    # surrounding non-numeral characters are ignored
    assert lex.parse_cn_number("把金币改成一千") == 1000
    assert lex.parse_cn_number("") is None
    assert lex.parse_cn_number("金币") is None


def test_cn_number_liang_vs_er():
    assert lex.parse_cn_number("两") == lex.parse_cn_number("二") == 2
    assert lex.parse_cn_number("两百") == lex.parse_cn_number("二百") == 200
    assert lex.parse_cn_number("两万三千") == lex.parse_cn_number("二万三千") == 23000


# ------------------------------------------------------------ number extraction
def test_extract_number_float():
    assert lex.extract_number("将移速改为1.5") == (1.5, "float")
    assert lex.extract_number("0.25") == (0.25, "float")
    assert lex.extract_number("-2.5") == (-2.5, "float")
    # thousands separators are stripped, integers stay ints
    assert lex.extract_number("金币1,000") == (1000, "int")
    assert lex.extract_number("hp 100") == (100, "int")


def test_extract_number_no_number():
    assert lex.extract_number("金币") == (None, None)
    assert lex.extract_number("set gold") == (None, None)
    assert lex.extract_number("") == (None, None)
    assert lex.extract_number(None) == (None, None)


def test_extract_number_prefers_arabic_over_chinese():
    assert lex.extract_number("九千金币改成100") == (100, "int")
    assert lex.extract_number("九千九百九十九金币") == (9999, "int")

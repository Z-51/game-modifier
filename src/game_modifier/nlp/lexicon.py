"""Lexicon and number parsing for the Chinese/English NLP processor.

Everything here is deterministic (dictionary + regex). That is deliberate: the
whole point of the NLP layer is to let an agent pass one short phrase like
"将金币设为9999" without spending tokens reasoning about it or writing code.
Users can extend fields via the session symbol table and templates.
"""

from __future__ import annotations

import re

# --- semantic fields ----------------------------------------------------------
# field -> (default data type, list of trigger terms). The default type is only
# a hint; a symbol-table entry or explicit --type always wins.
FIELDS: dict[str, tuple[str, list[str]]] = {
    "gold": ("int32", ["金币", "金錢", "金钱", "钱", "钱币", "硬币", "coin", "coins", "gold", "money", "gil"]),
    "gem": ("int32", ["钻石", "宝石", "钻", "gem", "gems", "diamond", "crystal"]),
    "health": ("int32", ["生命", "血量", "血", "血条", "生命值", "hp", "health", "hitpoints"]),
    "mana": ("int32", ["法力", "魔法", "蓝", "蓝量", "mp", "mana"]),
    "stamina": ("int32", ["体力", "耐力", "精力", "stamina", "energy", "能量"]),
    "move_speed": ("float", ["移速", "移动速度", "行走速度", "速度", "movespeed", "move speed", "speed"]),
    "attack": ("int32", ["攻击", "攻击力", "攻击力度", "伤害", "atk", "attack", "damage", "dmg"]),
    "defense": ("int32", ["防御", "防御力", "护甲", "def", "defense", "defence", "armor"]),
    "ammo": ("int32", ["弹药", "子弹", "弹夹", "弹匣", "ammo", "ammunition", "bullets", "rounds"]),
    "level": ("int32", ["等级", "级别", "人物等级", "lv", "lvl", "level"]),
    "exp": ("int32", ["经验", "经验值", "exp", "xp", "experience"]),
    "score": ("int32", ["分数", "得分", "积分", "score", "points"]),
    "lives": ("int32", ["生命数", "命数", "剩余生命", "lives"]),
    "skill_points": ("int32", ["技能点", "技能点数", "skill point", "skill points", "sp"]),
    "durability": ("int32", ["耐久", "耐久度", "durability"]),
    "attribute_points": ("int32", ["属性点", "属性点数", "attribute point", "attribute points"]),
}

# --- actions ------------------------------------------------------------------
# order matters: more specific / stronger cues first.
SET_TERMS = ["设置为", "设置成", "设定为", "设定成", "修改为", "修改成", "改为", "改成", "调成", "调为", "变成", "置为", "设为", "设成", "设置", "set to", "set", "="]
ADD_TERMS = ["增加", "加上", "添加", "多给", "增添", "add", "increase", "增"]
SUB_TERMS = ["减少", "扣除", "降低", "减掉", "减去", "subtract", "decrease", "减"]
FREEZE_TERMS = ["无限", "无敌", "锁定", "冻结", "固定", "永久", "unlimited", "infinite", "freeze", "lock", "god mode", "godmode"]
GET_TERMS = ["获取", "读取", "查看", "查询", "显示", "看看", "查", "get", "read", "show", "view"]
UNLOCK_TERMS = ["解锁", "开启所有", "全部解锁", "解锁全部", "unlock all", "unlock"]
MAX_TERMS = ["最大", "拉满", "满值", "满", "max", "maximum"]
MIN_TERMS = ["清零", "归零", "最小", "min", "zero"]

# terms that select "all levels / all items" style unlock templates
UNLOCK_TARGET_TERMS = {
    "levels": ["关卡", "关", "level", "levels", "stage", "stages", "章节"],
    "items": ["物品", "道具", "装备", "item", "items", "equipment"],
    "achievements": ["成就", "achievement", "achievements"],
    "characters": ["角色", "人物", "character", "characters"],
    "maps": ["地图", "map", "maps"],
}

# --- number parsing -----------------------------------------------------------
_FULLWIDTH = {ord("０") + i: ord("0") + i for i in range(10)}
_FULLWIDTH[ord("．")] = ord(".")
_FULLWIDTH[ord("，")] = ord(",")

_CN_DIGITS = {"零": 0, "〇": 0, "一": 1, "二": 2, "两": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
_CN_UNITS = {"十": 10, "百": 100, "千": 1000, "万": 10000, "亿": 100000000}

_ARABIC = re.compile(r"[-+]?\d[\d,]*\.?\d*")


def normalize(text: str) -> str:
    return (text or "").translate(_FULLWIDTH).strip()


def parse_cn_number(text: str) -> int | None:
    """Parse a Chinese-numeral integer such as 九千九百九十九. Best effort."""

    if not text:
        return None
    total = 0
    section = 0
    number = 0
    seen = False
    for ch in text:
        if ch in _CN_DIGITS:
            number = _CN_DIGITS[ch]
            seen = True
        elif ch in _CN_UNITS:
            unit = _CN_UNITS[ch]
            seen = True
            if unit >= 10000:
                section = (section + number) * unit
                total += section
                section = 0
            else:
                if number == 0:
                    number = 1
                section += number * unit
            number = 0
        else:
            # non-numeral char -> stop accumulating this run
            continue
    if not seen:
        return None
    return total + section + number


def extract_number(text: str):
    """Return (value, kind) where kind is 'int' | 'float' | None."""

    norm = normalize(text)
    m = _ARABIC.search(norm)
    if m:
        token = m.group(0).replace(",", "")
        if token in ("+", "-", ".", ""):
            pass
        elif "." in token:
            try:
                return float(token), "float"
            except ValueError:
                pass
        else:
            try:
                return int(token), "int"
            except ValueError:
                pass
    cn = parse_cn_number(norm)
    if cn is not None and any(c in norm for c in _CN_DIGITS) :
        return cn, "int"
    return None, None

"""Engine detection/parsers and toolchain detection."""

from __future__ import annotations

from game_modifier import engines
from game_modifier.engines import unity, unreal
from game_modifier import toolchain
from game_modifier.toolchain import windbg
from game_modifier.errors import ToolNotFoundError
import pytest

DUMP_CS = """// Namespace: Game.Core
public class PlayerState : MonoBehaviour // TypeDefIndex: 42
{
    public int gold; // 0x18
    public float moveSpeed; // 0x1C
    public static PlayerState Instance; // 0x0
}

// Namespace: Game.Weapons
public class Weapon // TypeDefIndex: 43
{
    public int ammo; // 0x24
}
"""

SCRIPT_JSON = {
    "ScriptMethod": [
        {"Address": 0x123456, "Name": "Game.Core.PlayerState$$AddGold"},
        {"Address": 0x223456, "Name": "Game.Weapons.Weapon$$Reload"},
    ],
    "ScriptString": [],
}

UE_OFFSETS = "namespace Offsets { constexpr auto GObjects = 0x1D2E500; constexpr auto GNames = 0x1D2C980; }"


def test_detect_unity_from_modules():
    res = engines.detect_from_modules([{"name": "GameAssembly.dll"}, {"name": "UnityPlayer.dll"}])
    assert res["engine"] == engines.UNITY_IL2CPP


def test_detect_unreal_from_modules():
    res = engines.detect_from_modules([{"name": "MyGame-Win64-Shipping.exe"}])
    assert res["engine"] == engines.UNREAL


def test_parse_dump_cs_fields():
    fields = unity.parse_dump_cs(DUMP_CS)
    gold = unity.find_field(fields, "PlayerState", "gold")
    assert gold and gold["offset"] == 0x18
    ammo = unity.find_field(fields, "Weapon", "ammo")
    assert ammo and ammo["offset"] == 0x24
    inst = unity.find_field(fields, "PlayerState", "Instance")
    assert inst and inst["static"] is True


def test_parse_script_json():
    parsed = unity.parse_script_json(SCRIPT_JSON)
    assert parsed["method_count"] == 2
    assert parsed["methods"]["Game.Weapons.Weapon$$Reload"] == 0x223456


def test_parse_ue_offsets():
    parsed = unreal.parse_offsets(UE_OFFSETS)
    assert parsed["offsets"]["GObjects"] == 0x1D2E500
    assert parsed["offsets"]["GNames"] == 0x1D2C980


def test_ue_project_name():
    assert unreal.project_name_from_shipping("Foo-Win64-Shipping.exe") == "Foo"


def test_toolchain_detect_structure(tmp_config):
    d = toolchain.detect_all(tmp_config)
    assert "tools" in d and "radare2" in d["tools"]
    assert isinstance(d["available"], list)


def test_metadata_version_parses_header(tmp_path):
    """global-metadata.dat header: magic 0xFAB11BAF + version int."""
    path = tmp_path / "global-metadata.dat"
    path.write_bytes((0xFAB11BAF).to_bytes(4, "little") + (39).to_bytes(4, "little") + b"\x00" * 16)
    assert toolchain.metadata_version(str(path)) == 39


def test_metadata_version_bad_magic_is_none(tmp_path):
    path = tmp_path / "bad.dat"
    path.write_bytes(b"NOTIL2CPP" + b"\x00" * 16)
    assert toolchain.metadata_version(str(path)) is None
    assert toolchain.metadata_version(str(tmp_path / "missing.dat")) is None


def test_recommended_dumper_routes_by_version(tmp_path):
    """v39 (Unity 6) must route to the Rust dumper; v29 to the official one."""
    path = tmp_path / "global-metadata.dat"
    path.write_bytes((0xFAB11BAF).to_bytes(4, "little") + (39).to_bytes(4, "little") + b"\x00" * 16)
    res = toolchain.recommended_unity_dumper(str(path))
    assert res["dumper"] == "il2cppdumper_rs", f"v39 must route to Rust dumper, got {res['dumper']}"
    assert res["metadata_version"] == 39

    path.write_bytes((0xFAB11BAF).to_bytes(4, "little") + (29).to_bytes(4, "little") + b"\x00" * 16)
    res = toolchain.recommended_unity_dumper(str(path))
    assert res["dumper"] == "il2cppdumper", f"v29 must route to official dumper, got {res['dumper']}"

    # no metadata path -> default to the Rust dumper (superset coverage)
    res = toolchain.recommended_unity_dumper()
    assert res["dumper"] == "il2cppdumper_rs"


def test_detect_all_includes_rs_dumper(tmp_config):
    d = toolchain.detect_all(tmp_config)
    assert "il2cppdumper_rs" in d["tools"], "registry must include the Rust dumper spec"


def test_toolchain_config_override(tmp_path):
    # a config that points radare2 at an existing file should be "found"
    fake_tool = tmp_path / "radare2.exe"
    fake_tool.write_text("x")
    from game_modifier.config import Config

    cfg = Config({"tools": {"radare2": str(fake_tool), "search_dirs": {"extra": []}}})
    res = toolchain.detect_tool("radare2", cfg)
    assert res["found"] and res["path"] == str(fake_tool)


def test_unreal_run_dumper_missing_tool():
    with pytest.raises(ToolNotFoundError):
        unreal.run_dumper("", "1234", "out")


def test_windbg_parse_db():
    sample = "00000001`40000000  0f 27 00 00 00 00 00 00-00 00 00 00 00 00 00 00  .'.............."
    data = windbg.parse_db(sample)
    assert data[:4] == b"\x0f\x27\x00\x00"
    assert len(data) == 16

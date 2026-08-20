"""Deep coverage of engine detection and the Unity/Unreal artifact parsers."""

from __future__ import annotations

import json

from game_modifier import engines
from game_modifier.engines import unity, unreal
# the package exports ``detect`` as a *function*, so reach the private folder
# scanners through the submodule path instead.
from game_modifier.engines.detect import _scan_unity, _scan_unreal
from game_modifier.memory.base import ModuleInfo

DUMP_CS = """// Namespace: Game.Core
public class PlayerState : MonoBehaviour // TypeDefIndex: 42
{
    // Fields
    public int gold; // 0x18
    public float moveSpeed; // 0x1C
    private readonly List<Item> items; // 0x20
    public static PlayerState Instance; // 0x0

    // Methods
    public void AddGold(int amount) { }
}

// Namespace:
public struct Vec2
{
    public float x; // 0x10
}

// Namespace: Game.Weapons
public class Weapon
{
    public int ammo; // 0x24
}
"""


def _modules(*names):
    return [{"name": n} for n in names]


# --------------------------------------------------------------- module-based
def test_detect_unity_mono():
    res = engines.detect_from_modules(_modules("kernel32.dll", "mono-2.0-bdwgc.dll", "UnityPlayer.dll"))

    assert res["engine"] == engines.UNITY_MONO
    assert res["confidence"] == 0.85
    assert res["evidence"] == ["module:mono runtime", "module:UnityPlayer.dll"]

    # the newer MonoBleedingEdge runtime is recognised as well, but only as
    # part of a Unity game (UnityPlayer.dll present)
    bleeding = engines.detect_from_modules(_modules("MonoBleedingEdge.dll", "UnityPlayer.dll"))
    assert bleeding["engine"] == engines.UNITY_MONO

    # UnityPlayer.dll alone is only weak evidence of a Mono title
    weak = engines.detect_from_modules(_modules("UnityPlayer.dll"))
    assert weak["engine"] == engines.UNITY_MONO
    assert weak["confidence"] == 0.6


def test_detect_mono_runtime_alone_is_not_unity():
    """mono-2.0 is a generic runtime (Godot, .NET apps); without
    UnityPlayer.dll it must NOT be reported as a Unity Mono game."""
    res = engines.detect_from_modules(_modules("mono-2.0-bdwgc.dll", "kernel32.dll"))
    assert res["engine"] != engines.UNITY_MONO, f"mono runtime alone mis-detected as Unity: {res}"

    bleeding = engines.detect_from_modules(_modules("MonoBleedingEdge.dll"))
    assert bleeding["engine"] != engines.UNITY_MONO

    # evidence should still record the runtime, just not claim Unity
    assert any("mono" in e for e in res["evidence"])


def test_detect_unity_il2cpp():
    res = engines.detect_from_modules(_modules("UnityPlayer.dll", "GameAssembly.dll"))

    assert res["engine"] == engines.UNITY_IL2CPP
    assert res["confidence"] == 0.9
    assert res["evidence"] == ["module:GameAssembly.dll"]
    # Il2Cpp wins over a Mono runtime that happens to be loaded too
    mixed = engines.detect_from_modules(_modules("mono-2.0-bdwgc.dll", "GameAssembly.dll"))
    assert mixed["engine"] == engines.UNITY_IL2CPP


def test_detect_unreal_ue4(tmp_path):
    # a live UE4SS loader is a strong Unreal signal
    res = engines.detect_from_modules(_modules("UE4SS.dll"))
    assert res["engine"] == engines.UNREAL
    assert res["confidence"] == 0.85
    assert res["evidence"] == ["module:ue4ss.dll"]

    # on disk: shipping exe + Engine dir
    (tmp_path / "Engine").mkdir()
    (tmp_path / "MyGame-Win64-Shipping.exe").write_text("x", encoding="utf-8")
    fs = engines.detect(target=str(tmp_path))
    assert fs["engine"] == engines.UNREAL
    assert fs["confidence"] == 0.9
    assert fs["artifacts"]["shipping_exe"].endswith("MyGame-Win64-Shipping.exe")
    assert "dir:Engine" in fs["evidence"]

    assert unreal.project_name_from_shipping(fs["artifacts"]["shipping_exe"]) == "MyGame"
    assert unreal.guess_version(text="EngineVersion 4.27.2") == "4.27.2"


def test_detect_unreal_ue5(tmp_path):
    res = engines.detect_from_modules(_modules("Lyra-Win64-Shipping.exe"))

    assert res["engine"] == engines.UNREAL
    assert res["evidence"] == ["module:lyra-win64-shipping.exe"]
    assert unreal.guess_version(exe_name="Lyra-UE5.3-Win64-Shipping.exe") == "5.3"
    assert unreal.guess_version(text="built with UnrealEngine 5.1") == "5.1"
    assert unreal.guess_version(exe_name="game.exe", text="no version here") is None

    # a pak-only layout is Unreal but with lower confidence
    (tmp_path / "Content" / "Paks").mkdir(parents=True)
    (tmp_path / "Content" / "Paks" / "pakchunk0.pak").write_text("x", encoding="utf-8")
    fs = engines.detect(target=str(tmp_path))
    assert fs["engine"] == engines.UNREAL
    assert fs["confidence"] == 0.35
    assert fs["artifacts"]["pak_dir"].endswith("Paks")
    assert "file:1 .pak" in fs["evidence"]


def test_detect_unknown_engine():
    res = engines.detect_from_modules(_modules("kernel32.dll", "user32.dll", "game.exe"))

    assert res["engine"] == engines.UNKNOWN
    assert res["confidence"] == 0.0
    assert res["evidence"] == []


def test_detect_accepts_moduleinfo_dicts_and_strings(sample_module):
    assert engines.detect_from_modules([sample_module])["engine"] == engines.UNITY_IL2CPP
    assert engines.detect_from_modules(["GameAssembly.dll"])["engine"] == engines.UNITY_IL2CPP
    assert engines.detect_from_modules([{"name": "GameAssembly.dll", "path": "C:/g/GameAssembly.dll"}])["engine"] == engines.UNITY_IL2CPP
    assert engines.detect_from_modules([ModuleInfo(name="UnityPlayer.dll", base=0, size=0)])["engine"] == engines.UNITY_MONO
    # unsupported entry shapes are ignored rather than crashing
    assert engines.detect_from_modules([42, None])["engine"] == engines.UNKNOWN


# ----------------------------------------------------------------- merging
def test_detect_confidence_merge(tmp_path):
    """The richer filesystem result wins when it is at least as confident."""

    data_dir = tmp_path / "MyGame_Data"
    (data_dir / "il2cpp_data" / "Metadata").mkdir(parents=True)
    (data_dir / "il2cpp_data" / "Metadata" / "global-metadata.dat").write_text("x", encoding="utf-8")
    (tmp_path / "GameAssembly.dll").write_text("x", encoding="utf-8")

    merged = engines.detect(target=str(tmp_path), modules=_modules("mono-2.0-bdwgc.dll"))

    assert merged["engine"] == engines.UNITY_IL2CPP  # fs 0.95 beats modules 0.85
    assert merged["confidence"] == 0.95
    assert merged["artifacts"]["global_metadata"].endswith("global-metadata.dat")
    assert merged["artifacts"]["data_dir"] == str(data_dir)
    assert merged["game_dir"] == str(tmp_path)


def test_detect_module_result_wins_but_keeps_fs_evidence(tmp_path):
    (tmp_path / "UnityPlayer.dll").write_text("x", encoding="utf-8")

    merged = engines.detect(target=str(tmp_path), modules=_modules("GameAssembly.dll"))

    assert merged["engine"] == engines.UNITY_IL2CPP
    assert merged["confidence"] == 0.9  # module confidence retained
    assert merged["evidence"] == ["module:GameAssembly.dll", "file:UnityPlayer.dll"]
    assert merged["game_dir"] == str(tmp_path)


def test_detect_target_file_uses_parent_dir(tmp_path):
    exe = tmp_path / "MyGame.exe"
    exe.write_text("x", encoding="utf-8")
    managed = tmp_path / "MyGame_Data" / "Managed"
    managed.mkdir(parents=True)
    (managed / "Assembly-CSharp.dll").write_text("x", encoding="utf-8")

    res = engines.detect(target=str(exe))

    assert res["engine"] == engines.UNITY_MONO
    assert res["confidence"] == 0.9
    assert res["game_dir"] == str(tmp_path)
    assert res["artifacts"]["assembly_csharp"].endswith("Assembly-CSharp.dll")


def test_detect_nonexistent_target_is_ignored():
    res = engines.detect(target="Z:/definitely/not/here", modules=_modules("GameAssembly.dll"))

    assert res["engine"] == engines.UNITY_IL2CPP
    assert "game_dir" not in res


# ------------------------------------------------------------- unity parsers
def test_unity_parse_dump_cs():
    fields = unity.parse_dump_cs(DUMP_CS)

    gold = unity.find_field(fields, "PlayerState", "gold")
    assert gold["namespace"] == "Game.Core"
    assert gold["class"] == "PlayerState"
    assert gold["type"] == "int"
    assert gold["offset"] == 0x18
    assert gold["offset_hex"] == "0x18"
    assert gold["static"] is False

    assert unity.find_field(fields, "PlayerState", "moveSpeed")["offset"] == 0x1C
    assert unity.find_field(fields, "PlayerState", "Instance")["static"] is True
    # class scope follows the dump order
    assert unity.find_field(fields, "Weapon", "ammo")["namespace"] == "Game.Weapons"
    assert unity.find_field(fields, "Vec2", "x")["offset"] == 0x10
    # lookups are case-insensitive, misses return None
    assert unity.find_field(fields, "playerstate", "GOLD")["offset"] == 0x18
    assert unity.find_field(fields, "PlayerState", "nope") is None
    assert unity.find_field(fields, "Nope", "gold") is None
    # methods are not mistaken for fields
    assert all(f["field"] != "AddGold" for f in fields)


def test_unity_parse_dump_cs_max_fields_and_empty():
    assert len(unity.parse_dump_cs(DUMP_CS, max_fields=2)) == 2
    assert unity.parse_dump_cs("") == []
    # fields outside any class are skipped
    assert unity.parse_dump_cs("    public int stray; // 0x8") == []


def test_unity_parse_script_json_from_file(tmp_path):
    payload = {
        "ScriptMethod": [
            {"Address": 0x123456, "Name": "Game.Core.PlayerState$$AddGold"},
            {"Address": None, "Name": "Broken"},
        ],
        "ScriptString": [{"Address": 0x900, "Value": "gold"}],
    }
    path = tmp_path / "script.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    for source in (payload, json.dumps(payload), str(path), path):
        parsed = unity.parse_script_json(source)
        assert parsed["method_count"] == 1  # the entry without an address is dropped
        assert parsed["methods"]["Game.Core.PlayerState$$AddGold"] == 0x123456
        assert parsed["string_count"] == 1


def test_unity_locate_artifacts(tmp_path):
    (tmp_path / "GameAssembly.dll").write_text("x", encoding="utf-8")

    artifacts = unity.locate_artifacts(str(tmp_path))

    assert artifacts["game_assembly"].endswith("GameAssembly.dll")
    assert unity.locate_artifacts(str(tmp_path / "empty")) == {}


# ------------------------------------------------------------ unreal parsers
def test_unreal_parse_offsets():
    text = """
    namespace Offsets {
        constexpr auto GObjects = 0x1D2E500;
        constexpr auto GNames   = 0x1D2C980;
        GWorld: 0x1D30A18
        ProcessEvent = 123456
        GMalloc = ???
    }
    """

    parsed = unreal.parse_offsets(text)

    assert parsed["offsets"]["GObjects"] == 0x1D2E500
    assert parsed["offsets"]["GNames"] == 0x1D2C980
    assert parsed["offsets"]["GWorld"] == 0x1D30A18
    assert parsed["offsets"]["ProcessEvent"] == 123456  # decimal accepted
    assert "GMalloc" not in parsed["offsets"]           # unparseable value not matched
    assert parsed["count"] == 4
    assert parsed["offsets_hex"]["GObjects"] == "0x1d2e500"

    empty = unreal.parse_offsets("nothing to see here")
    assert empty == {"count": 0, "offsets": {}, "offsets_hex": {}}


def test_unreal_project_name_from_shipping():
    assert unreal.project_name_from_shipping("C:/g/Binaries/Win64/MyGame-Win64-Shipping.exe") == "MyGame"
    assert unreal.project_name_from_shipping("mygame-win64-shipping.exe") == "mygame"
    assert unreal.project_name_from_shipping("MyGame.exe") is None


def test_unreal_analyze(tmp_path):
    binaries = tmp_path / "Binaries" / "Win64"
    binaries.mkdir(parents=True)
    (binaries / "Lyra-Win64-Shipping.exe").write_text("x", encoding="utf-8")

    res = unreal.analyze(str(tmp_path))

    assert res["engine"] == engines.UNREAL
    assert res["project"] == "Lyra"
    assert res["version_guess"] is None  # no version in the exe name
    assert res["artifacts"]["shipping_exe"].endswith("Lyra-Win64-Shipping.exe")
    assert res["notes"]


# ------------------------------------------------------------- degenerate input
def test_detect_empty_modules():
    for modules in ([], None, ()):
        res = engines.detect_from_modules(modules)
        assert res["engine"] == engines.UNKNOWN
        assert res["confidence"] == 0.0
        assert res["evidence"] == []

    # detect() with nothing at all still returns the stable envelope
    res = engines.detect()
    assert res == {"engine": engines.UNKNOWN, "confidence": 0.0, "evidence": [], "artifacts": {}}


def test_detect_empty_game_dir(tmp_path):
    res = engines.detect(target=str(tmp_path))

    assert res["engine"] == engines.UNKNOWN
    assert res["artifacts"] == {}
    assert res["game_dir"] == str(tmp_path)
    assert _scan_unity(tmp_path) is None
    assert _scan_unreal(tmp_path) is None

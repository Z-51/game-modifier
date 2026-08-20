"""Tests for Unity custom-encrypted save support: Base64( DES-CBC( JSON ) ).

Requires pycryptodome (the ``crypto`` optional group); the whole module is
skipped when it is absent so a base install never fails here.
"""

from __future__ import annotations

import base64
import json
import struct

import pytest

pytest.importorskip("Crypto", reason="pycryptodome (game-modifier[crypto]) not installed")

from Crypto.Cipher import DES  # noqa: E402

from game_modifier import mcp_server  # noqa: E402
from game_modifier.cli import build_parser  # noqa: E402
from game_modifier.errors import (  # noqa: E402
    ErrorCode,
    InvalidArgsError,
    SaveFormatUnsupportedError,
)
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory.base import ModuleInfo  # noqa: E402
from game_modifier.save_edit import detect_saves, load_save, modify_save  # noqa: E402
from game_modifier.save_edit.renpy import RenPyHandler  # noqa: E402
from game_modifier.save_edit.unity import UnityHandler  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402

KEY = "8bytekey"  # exactly 8 bytes -> no truncation/padding needed
IV = "ivbytes8"


# ---------------------------------------------------------------------------
# helpers / fixtures
# ---------------------------------------------------------------------------

def _write_encrypted(path, payload, key=KEY, iv=None):
    """Build a real Base64(DES-CBC(JSON)) save like the game would."""

    kb = key.encode("utf-8")
    ivb = (iv or key).encode("utf-8") if isinstance(iv or key, str) else (iv or key)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    pad = 8 - len(data) % 8
    cipher = DES.new(kb, DES.MODE_CBC, ivb)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        base64.b64encode(cipher.encrypt(data + bytes([pad]) * pad)).decode("ascii"),
        encoding="utf-8",
    )


def _decrypt(path, key=KEY, iv=None):
    kb = key.encode("utf-8")
    ivb = (iv or key).encode("utf-8") if isinstance(iv or key, str) else (iv or key)
    raw = base64.b64decode(path.read_text(encoding="utf-8").strip())
    cipher = DES.new(kb, DES.MODE_CBC, ivb)
    plain = cipher.decrypt(raw)
    return json.loads(plain[: -plain[-1]].decode("utf-8"))


@pytest.fixture
def unity_save(tmp_path):
    p = tmp_path / "player.sav"
    payload = {"player": {"name": "旅行者", "gold": 100}, "version": 3}
    _write_encrypted(p, payload)
    return p, payload


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


@pytest.fixture
def mcp_config_path(tmp_path):
    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    return str(cfg)


# ---------------------------------------------------------------------------
# 1. detection
# ---------------------------------------------------------------------------

def test_detect_unity_encrypted(tmp_path, unity_save):
    p, _ = unity_save
    # non-candidates must be ignored: plain JSON .dat, Ren'Py pickle .save, .bak
    (tmp_path / "config.dat").write_text('{"plain": true}', encoding="utf-8")
    (tmp_path / "legacy.save").write_bytes(b"\x80\x02fake-pickle")
    (tmp_path / "player.sav.bak").write_text("backup", encoding="utf-8")

    found = UnityHandler().detect(str(tmp_path))
    assert len(found) == 1
    entry = found[0]
    assert entry["path"] == str(p)
    assert entry["engine"] == "unity-encrypted"
    assert entry["editable"] == "with_key"

    # detect_saves surfaces unity candidates for any engine (merged, deduped)
    merged = detect_saves(str(tmp_path), "rpg-maker")
    assert [e["engine"] for e in merged] == ["unity-encrypted"]
    assert detect_saves(str(p), "unity-encrypted")[0]["engine"] == "unity-encrypted"


# ---------------------------------------------------------------------------
# 2-3. load / modify
# ---------------------------------------------------------------------------

def test_load_decrypt_parse(unity_save):
    p, payload = unity_save
    loaded = load_save(str(p), key=KEY)
    assert loaded["editable"] is True
    assert loaded["encoding"] == "des-cbc-base64"
    assert loaded["data"] == payload
    assert loaded["data"]["player"]["name"] == "旅行者"  # Chinese survives the round trip


def test_load_with_explicit_iv(tmp_path):
    p = tmp_path / "iv.dat"
    _write_encrypted(p, {"gold": 7}, iv=IV)
    loaded = load_save(str(p), key=KEY, iv=IV)
    assert loaded["data"]["gold"] == 7


def test_modify_field(unity_save):
    _, payload = unity_save
    handler = UnityHandler()
    res = handler.modify(payload, "player.gold", 9999)
    assert res["found"] is True
    assert res["old_value"] == 100
    assert payload["player"]["gold"] == 9999
    # undotted search still works
    res = handler.modify(payload, "version", 4)
    assert res["found"] is True and res["old_value"] == 3


# ---------------------------------------------------------------------------
# 4-5. save round trip + backup
# ---------------------------------------------------------------------------

def test_save_roundtrip(unity_save):
    p, _ = unity_save
    res = modify_save(str(p), "player.gold", "9999", confirm=True, key=KEY)
    assert res["ok"] is True and res["applied"] is True
    assert res["new_value"] == 9999
    # file is base64 again, decrypts to the modified value
    assert _decrypt(p)["player"]["gold"] == 9999
    # and loads back through the public API
    assert load_save(str(p), key=KEY)["data"]["player"]["gold"] == 9999


def test_backup_created(unity_save):
    p, payload = unity_save
    res = modify_save(str(p), "player.gold", 1, confirm=True, key=KEY)
    bak = p.with_suffix(p.suffix + ".bak")
    assert res["backup"] == str(bak)
    assert bak.exists()
    assert _decrypt(bak) == payload  # backup holds the original ciphertext contents


# ---------------------------------------------------------------------------
# 6-7. error handling
# ---------------------------------------------------------------------------

def test_wrong_key_error(unity_save):
    p, _ = unity_save
    handler = UnityHandler()
    try:
        loaded = handler.load(str(p), key="wrongkey")
    except SaveFormatUnsupportedError as exc:
        info = exc.to_dict()
        assert info["code"] == ErrorCode.SAVE_FORMAT_UNSUPPORTED.value
        assert info.get("hint")  # actionable hint, not a crash
        return
    # if the wrong key happened to produce valid padding, the payload is still
    # unusable -> must be reported as not editable, never garbage-edited
    assert loaded["editable"] is False
    assert loaded["reason"]


def test_corrupt_base64_error(tmp_path):
    p = tmp_path / "broken.sav"
    p.write_text("!!!not-base64!!!", encoding="utf-8")
    with pytest.raises(SaveFormatUnsupportedError) as exc_info:
        load_save(str(p), key=KEY)
    assert "base64" in exc_info.value.message

    # valid base64 but wrong block alignment
    p2 = tmp_path / "misaligned.sav"
    p2.write_text(base64.b64encode(b"\x01\x02\x03").decode("ascii"), encoding="utf-8")
    with pytest.raises(SaveFormatUnsupportedError):
        load_save(str(p2), key=KEY)


def test_dependency_missing_hint(monkeypatch):
    import builtins

    import game_modifier.save_edit.unity as unity_mod
    from game_modifier.errors import DependencyMissingError

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "Crypto.Cipher":
            raise ImportError("No module named 'Crypto'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(DependencyMissingError) as exc_info:
        unity_mod._des_module()
    assert "crypto" in (exc_info.value.to_dict().get("hint") or "")


# ---------------------------------------------------------------------------
# 8-10. service layer: dry-run, missing-key hint, key never persisted
# ---------------------------------------------------------------------------

def test_dry_run_no_write(service, unity_save):
    svc, _ = service
    p, payload = unity_save
    sid = svc.attach(pid=4242)["session_id"]
    before = p.read_text(encoding="utf-8")

    res = svc.save_edit_modify(session_id=sid, path=str(p), field="player.gold",
                               value="9999", key=KEY)  # confirm defaults to False
    assert res["dry_run"] is True and res["applied"] is False
    assert p.read_text(encoding="utf-8") == before
    assert not p.with_suffix(p.suffix + ".bak").exists()

    # confirm writes and audits (without leaking the key, see below)
    res = svc.save_edit_modify(session_id=sid, path=str(p), field="player.gold",
                               value="9999", confirm=True, key=KEY)
    assert res["applied"] is True
    assert _decrypt(p)["player"]["gold"] == 9999


def test_missing_key_hint(service, unity_save):
    svc, _ = service
    p, _ = unity_save
    sid = svc.attach(pid=4242)["session_id"]
    with pytest.raises(InvalidArgsError) as exc_info:
        svc.save_edit_modify(session_id=sid, path=str(p), field="player.gold",
                             value="9", confirm=True)
    info = exc_info.value.to_dict()
    assert info["code"] == ErrorCode.INVALID_ARGS.value
    assert "--key" in exc_info.value.message or "--key" in (info.get("hint") or "")


def test_key_not_persisted(service, tmp_path, tmp_config):
    svc, _ = service
    p = tmp_path / "player.sav"
    _write_encrypted(p, {"player": {"gold": 100}}, iv=IV)
    sid = svc.attach(pid=4242)["session_id"]
    svc.save_edit_modify(session_id=sid, path=str(p), field="player.gold",
                         value="9999", confirm=True, key=KEY, iv=IV)

    home = tmp_config.home_dir
    from pathlib import Path
    root = Path(home)
    assert root.exists()
    leaked = []
    for f in root.rglob("*"):
        if f.is_file():
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if KEY in content or IV in content:
                leaked.append(str(f))
    assert not leaked, f"key material persisted in: {leaked}"


# ---------------------------------------------------------------------------
# 11-12. CLI / MCP surfaces
# ---------------------------------------------------------------------------

def test_cli_key_param():
    parser = build_parser()
    args = parser.parse_args([
        "save-edit", "modify", "--session", "s1", "--path", "player.sav",
        "--field", "gold", "--value", "9", "--key", KEY, "--iv", IV, "--confirm",
    ])
    assert args.key == KEY
    assert args.iv == IV
    assert args.confirm is True
    # key/iv stay optional (backward compatible)
    args = parser.parse_args([
        "save-edit", "modify", "--session", "s1", "--path", "f.rmmzsave",
        "--field", "gold", "--value", "9",
    ])
    assert args.key is None and args.iv is None


def test_mcp_key_param(mcp_config_path):
    pytest.importorskip("mcp")
    server = mcp_server.build_server(mcp_config_path)
    tool = server._tool_manager._tools["save_edit_modify"]
    props = tool.parameters["properties"]
    assert "key" in props and "iv" in props
    assert tool.parameters.get("required", []) and "key" not in tool.parameters["required"]


# ---------------------------------------------------------------------------
# 13. regression: existing handlers unchanged
# ---------------------------------------------------------------------------

def test_existing_handlers_unchanged(tmp_path):
    # RMMZ: plain + base64 JSON still work without any key material
    p = tmp_path / "file1.rmmzsave"
    p.write_text(json.dumps({"party": {"gold": 100}}), encoding="utf-8")
    res = modify_save(str(p), "gold", 777, confirm=True)
    assert res["applied"] is True
    assert json.loads(p.read_text(encoding="utf-8"))["party"]["gold"] == 777
    assert (tmp_path / "file1.rmmzsave.bak").exists()

    # Ren'Py: still detect-only, refuses to edit
    rp = tmp_path / "1-1.save"
    rp.write_bytes(b"\x80\x02fake-pickle")
    loaded = RenPyHandler().load(str(rp))
    assert loaded["editable"] is False
    with pytest.raises(SaveFormatUnsupportedError):
        modify_save(str(rp), "gold", 1, confirm=True)

    # passing an (ignored) key to a plain RMMZ save keeps working
    p2 = tmp_path / "file2.rmmzsave"
    p2.write_text(json.dumps({"gold": 5}), encoding="utf-8")
    res2 = modify_save(str(p2), "gold", 6, confirm=True, key=KEY)
    assert res2["applied"] is True

"""Tests for Task #54: il2cpp dump validation + game-update staleness detection.

Covers unity_lookup.validate_dump / fingerprint_binary / check_dump_freshness,
the service-level closed loop (il2cpp_dump records a binary fingerprint and
validates outputs, il2cpp_lookup surfaces stale_warning, analyze reports
dump_stale, fresh dumps are reused unless forced) and the dumper selection
fallback between il2cppdumper / il2cppdumper_rs.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path

import pytest

from game_modifier.config import Config
from game_modifier.engines import unity_lookup
from game_modifier.errors import InvalidArgsError, ToolNotFoundError
from game_modifier.service import ModifierService
from game_modifier.session import Session

SAMPLE_METHODS = [
    {"Address": 0x1000, "Name": "Player.Update", "Signature": "void Player.Update(Player* this)"},
    {"Address": 0x4E85670, "Name": "Dictionary.TryAdd", "Signature": "bool Dictionary.TryAdd(dict* this, k, v)"},
]

_HEAD_BYTES = 64 * 1024


# ----------------------------------------------------------------- fixtures
@pytest.fixture
def svc(tmp_path):
    cfg = Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": True,
                   "require_writable_region": True},
        "scan": {"max_results": 1000, "chunk_size": 4096, "alignment": 1, "max_region_bytes": 0},
        "output": {"format": "json"},
        "paths": {"home": str(tmp_path / ".game-modifier")},
        "tools": {"search_dirs": {"extra": []}},
    })
    return ModifierService(cfg)


def _make_session(svc, sid="s-fresh", engine=None, exe_path="C:/games/Game.exe"):
    session = Session(id=sid, pid=4242, process_name="Game.exe",
                      exe_path=exe_path, engine=engine or {})
    svc.store.save(session)
    return session


def _write_script_json(path: Path, methods=SAMPLE_METHODS):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"ScriptMethod": methods, "ScriptString": []}),
                    encoding="utf-8")
    unity_lookup._MEMO.clear()
    return path


def _fake_binary(path: Path, size: int = _HEAD_BYTES + 4096, seed: int = 0):
    data = bytes((i + seed) % 256 for i in range(min(size, 4096)))
    path.write_bytes(data * ((size // len(data)) + 1))
    path.write_bytes(path.read_bytes()[:size])
    return path


# ------------------------------------------------------------ validate_dump
def test_validate_dump_ok(tmp_path):
    sj = _write_script_json(tmp_path / "script.json")
    dc = tmp_path / "dump.cs"
    dc.write_text("// Namespace: Global\npublic class Player {}", encoding="utf-8")

    res = unity_lookup.validate_dump(str(sj), dump_cs_path=str(dc))
    assert res["valid"] is True
    assert res["methods"] == len(SAMPLE_METHODS)
    assert res["errors"] == []


def test_validate_dump_corrupt(tmp_path):
    # 1) not valid JSON
    bad = tmp_path / "bad.json"
    bad.write_text('{"ScriptMethod": [ oops', encoding="utf-8")
    res = unity_lookup.validate_dump(str(bad))
    assert res["valid"] is False and res["methods"] == 0
    assert any("not valid JSON" in e for e in res["errors"])

    # 2) missing ScriptMethod key
    nokey = tmp_path / "nokey.json"
    nokey.write_text(json.dumps({"ScriptString": []}), encoding="utf-8")
    res = unity_lookup.validate_dump(str(nokey))
    assert res["valid"] is False
    assert any("ScriptMethod" in e for e in res["errors"])

    # 3) empty ScriptMethod list
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"ScriptMethod": []}), encoding="utf-8")
    res = unity_lookup.validate_dump(str(empty))
    assert res["valid"] is False and any("empty" in e for e in res["errors"])

    # 4) missing script.json
    res = unity_lookup.validate_dump(str(tmp_path / "missing.json"))
    assert res["valid"] is False and any("not found" in e for e in res["errors"])

    # 5) empty dump.cs flags an error
    good = _write_script_json(tmp_path / "good.json")
    dc = tmp_path / "dump.cs"
    dc.write_text("", encoding="utf-8")
    res = unity_lookup.validate_dump(str(good), dump_cs_path=str(dc))
    assert res["valid"] is False and any("dump.cs is empty" in e for e in res["errors"])


# ---------------------------------------------------------- fingerprinting
def test_fingerprint_binary(tmp_path):
    ga = _fake_binary(tmp_path / "GameAssembly.dll")
    fp = unity_lookup.fingerprint_binary(str(ga))
    st = ga.stat()
    assert fp["path"] == str(ga)
    assert fp["size"] == st.st_size
    assert fp["mtime"] == st.st_mtime
    expected = hashlib.sha256(ga.read_bytes()[:_HEAD_BYTES]).hexdigest()
    assert fp["head_hash"] == expected

    # bytes beyond the first 64 KB do not affect the (fast) head hash
    raw = bytearray(ga.read_bytes())
    raw[-1] ^= 0xFF
    ga.write_bytes(bytes(raw))
    os.utime(ga, (fp["mtime"], fp["mtime"]))
    fp2 = unity_lookup.fingerprint_binary(str(ga))
    assert fp2["head_hash"] == expected and fp2["size"] == fp["size"]

    with pytest.raises(InvalidArgsError):
        unity_lookup.fingerprint_binary(str(tmp_path / "nope.dll"))


def test_check_freshness_ok(tmp_path):
    ga = _fake_binary(tmp_path / "GameAssembly.dll")
    fp = unity_lookup.fingerprint_binary(str(ga))
    res = unity_lookup.check_dump_freshness(str(ga), fp)
    assert res["fresh"] is True and res["reason"] == "ok"


def test_check_freshness_changed(tmp_path):
    ga = _fake_binary(tmp_path / "GameAssembly.dll")
    fp = unity_lookup.fingerprint_binary(str(ga))

    # size change (game update appended data) -> size_changed wins first
    ga.write_bytes(ga.read_bytes() + b"UPDATE")
    res = unity_lookup.check_dump_freshness(str(ga), fp)
    assert res["fresh"] is False and res["reason"] == "size_changed"

    # same size, same mtime, different head bytes -> hash_changed
    ga.write_bytes(b"\x00" * fp["size"])
    os.utime(ga, (fp["mtime"], fp["mtime"]))
    res = unity_lookup.check_dump_freshness(str(ga), fp)
    assert res["fresh"] is False and res["reason"] == "hash_changed"

    # identical content, touched mtime -> mtime_changed
    orig = bytes((i % 256) for i in range(4096))
    blob = (orig * ((fp["size"] // len(orig)) + 1))[: fp["size"]]
    ga.write_bytes(blob)
    fp_same = dict(fp, head_hash=hashlib.sha256(blob[:_HEAD_BYTES]).hexdigest())
    os.utime(ga, (fp["mtime"] + 100, fp["mtime"] + 100))
    res = unity_lookup.check_dump_freshness(str(ga), fp_same)
    assert res["fresh"] is False and res["reason"] == "mtime_changed"

    # binary deleted -> binary_missing; empty fingerprint -> no_fingerprint
    ga.unlink()
    res = unity_lookup.check_dump_freshness(str(ga), fp)
    assert res["fresh"] is False and res["reason"] == "binary_missing"
    res = unity_lookup.check_dump_freshness(str(tmp_path / "y.dll"), {})
    assert res["fresh"] is False and res["reason"] == "no_fingerprint"


# ------------------------------------------------------------- service layer
def _mock_dumper_stack(monkeypatch, svc_mod, out_writer):
    """Mock the toolchain recommendation + the dumper subprocess wrapper."""

    monkeypatch.setattr(svc_mod.toolchain, "recommended_unity_dumper",
                        lambda meta, cfg: {"dumper": "il2cppdumper_rs",
                                           "metadata_version": None,
                                           "found": True,
                                           "path": "C:/tools/il2cpp_dumper.exe",
                                           "hint": ""})

    calls = []

    def fake_run_cli(dumper_path, target, out, *, timeout=120.0):
        calls.append({"dumper_path": dumper_path, "target": target,
                      "out": out, "timeout": timeout})
        outputs = out_writer(Path(out))
        return {"ok": True, "outputs": outputs, "returncode": 0,
                "out_dir": str(out), "elapsed": 0.05}

    monkeypatch.setattr(svc_mod.engines.unity, "run_dumper_cli", fake_run_cli)
    return calls


def test_il2cpp_dump_records_fingerprint(svc, tmp_path, monkeypatch):
    import game_modifier.service as svc_mod

    ga = _fake_binary(tmp_path / "GameAssembly.dll")
    session = _make_session(svc, engine={"artifacts": {"game_assembly": str(ga)}})

    def out_writer(out: Path):
        out.mkdir(parents=True, exist_ok=True)
        _write_script_json(out / "script.json")
        (out / "dump.cs").write_text("// dump", encoding="utf-8")
        return {"script.json": str(out / "script.json"),
                "dump.cs": str(out / "dump.cs")}

    _mock_dumper_stack(monkeypatch, svc_mod, out_writer)

    res = svc.il2cpp_dump(session.id, out_dir=str(tmp_path / "dump"))
    assert res["ok"] is True and res["associated"] is True
    assert res["validation"]["valid"] is True
    assert res["validation"]["methods"] == len(SAMPLE_METHODS)

    expected_head = hashlib.sha256(ga.read_bytes()[:_HEAD_BYTES]).hexdigest()
    fp = res["binary_fingerprint"]
    assert fp["path"] == str(ga) and fp["head_hash"] == expected_head

    reloaded = svc.store.load(session.id)
    arts = reloaded.engine["artifacts"]
    assert arts["binary_fingerprint"]["head_hash"] == expected_head
    assert arts["binary_fingerprint"]["size"] == ga.stat().st_size
    assert reloaded.engine["il2cpp_dump"]["methods"] == len(SAMPLE_METHODS)


def test_il2cpp_dump_refuses_corrupt_output(svc, tmp_path, monkeypatch):
    import game_modifier.service as svc_mod

    ga = _fake_binary(tmp_path / "GameAssembly.dll")
    session = _make_session(svc, sid="s-corrupt",
                            engine={"artifacts": {"game_assembly": str(ga)}})

    def out_writer(out: Path):
        out.mkdir(parents=True, exist_ok=True)
        (out / "script.json").write_text('{"ScriptMethod": [broken', encoding="utf-8")
        return {"script.json": str(out / "script.json")}

    _mock_dumper_stack(monkeypatch, svc_mod, out_writer)

    res = svc.il2cpp_dump(session.id, out_dir=str(tmp_path / "dump"))
    assert res["ok"] is False and res["associated"] is False
    assert res["errors"] and "not valid JSON" in res["errors"][0]

    # corrupt output must NOT be associated with the session
    reloaded = svc.store.load(session.id)
    assert "script_json" not in (reloaded.engine.get("artifacts") or {})
    assert "binary_fingerprint" not in (reloaded.engine.get("artifacts") or {})


def test_il2cpp_lookup_stale_warning(svc, tmp_path, monkeypatch):
    ga = _fake_binary(tmp_path / "GameAssembly.dll")
    fp = unity_lookup.fingerprint_binary(str(ga))
    sj = _write_script_json(tmp_path / "dump" / "script.json")

    _make_session(svc, sid="s-stale", engine={"artifacts": {
        "game_assembly": str(ga),
        "script_json": str(sj),
        "binary_fingerprint": fp,
    }})

    # fresh binary -> no warning
    res = svc.il2cpp_lookup("s-stale", rva="0x1000")
    assert res["matched"] == "exact" and "stale_warning" not in res

    # game update (size change) -> non-blocking stale_warning
    ga.write_bytes(ga.read_bytes() + b"PATCHED")
    res = svc.il2cpp_lookup("s-stale", rva="0x1000")
    assert res["matched"] == "exact"  # lookup itself still works
    assert res["stale_warning"]["reason"] == "size_changed"
    assert "il2cpp dump" in res["stale_warning"]["hint"]

    # force skips the freshness check
    res = svc.il2cpp_lookup("s-stale", rva="0x1000", force=True)
    assert "stale_warning" not in res


def test_il2cpp_dump_reuse_fresh(svc, tmp_path, monkeypatch):
    import game_modifier.service as svc_mod

    ga = _fake_binary(tmp_path / "GameAssembly.dll")
    fp = unity_lookup.fingerprint_binary(str(ga))
    sj = _write_script_json(tmp_path / "dump" / "script.json")

    _make_session(svc, sid="s-reuse", engine={"artifacts": {
        "game_assembly": str(ga),
        "script_json": str(sj),
        "binary_fingerprint": fp,
    }})

    def out_writer(out: Path):
        out.mkdir(parents=True, exist_ok=True)
        _write_script_json(out / "script.json")
        return {"script.json": str(out / "script.json")}

    calls = _mock_dumper_stack(monkeypatch, svc_mod, out_writer)

    # fingerprint still fresh -> reuse, dumper not invoked
    res = svc.il2cpp_dump("s-reuse", out_dir=str(tmp_path / "again"))
    assert res["ok"] is True and res["reused"] is True and res["fresh"] is True
    assert res["outputs"]["script.json"] == str(sj)
    assert "force" in res["hint"] or "force" in res["hint"].lower()
    assert calls == []

    # force bypasses the reuse shortcut and re-runs the dumper
    res = svc.il2cpp_dump("s-reuse", out_dir=str(tmp_path / "again"), force=True)
    assert res["ok"] is True and res.get("reused") is not True
    assert len(calls) == 1

    # stale fingerprint -> no reuse, re-dump with previous_stale note
    stale_fp = dict(fp, size=fp["size"] + 1)
    session = svc.store.load("s-reuse")
    session.engine["artifacts"]["binary_fingerprint"] = stale_fp
    svc.store.save(session)
    res = svc.il2cpp_dump("s-reuse", out_dir=str(tmp_path / "again2"))
    assert res["ok"] is True and res.get("reused") is not True
    assert res["previous_stale"] == "size_changed"
    assert len(calls) == 2


def test_analyze_stale_hint(svc, tmp_path, monkeypatch):
    ga = _fake_binary(tmp_path / "GameAssembly.dll")
    fp = unity_lookup.fingerprint_binary(str(ga))
    sj = _write_script_json(tmp_path / "dump" / "script.json")
    exe = tmp_path / "Game.exe"
    exe.write_bytes(b"MZ-fake-exe")

    _make_session(svc, sid="s-analyze", exe_path=str(exe), engine={"artifacts": {
        "game_assembly": str(ga),
        "script_json": str(sj),
        "binary_fingerprint": fp,
    }})

    class _FakeBackend:
        def modules(self):
            return []

        def close(self):
            pass

    # no live process needed: analyze's backend hop is stubbed out
    monkeypatch.setattr(ModifierService, "_open",
                        lambda self, session: _FakeBackend())

    # fresh dump -> no dump_stale key
    res = svc.analyze(session_id="s-analyze")
    assert "dump_stale" not in res

    # simulate a game update -> advisory dump_stale hint
    ga.write_bytes(ga.read_bytes() + b"PATCHED")
    res = svc.analyze(session_id="s-analyze")
    assert res["dump_stale"]["reason"] == "size_changed"
    assert "il2cpp dump" in res["dump_stale"]["hint"]


# ------------------------------------------------- dumper selection fallback
def _write_metadata(path: Path, version: int):
    path.write_bytes(struct.pack("<II", 0xFAB11BAF, version) + b"\x00" * 16)
    return path


def test_dumper_selection_fallback(svc, tmp_path, monkeypatch):
    import game_modifier.service as svc_mod
    from game_modifier.toolchain import registry

    # metadata-version routing of the recommendation itself
    rec = registry.recommended_unity_dumper(str(_write_metadata(tmp_path / "m29.dat", 29)))
    assert rec["dumper"] == "il2cppdumper" and rec["metadata_version"] == 29
    rec = registry.recommended_unity_dumper(str(_write_metadata(tmp_path / "m32.dat", 32)))
    assert rec["dumper"] == "il2cppdumper_rs" and rec["metadata_version"] == 32
    rec = registry.recommended_unity_dumper(None)
    assert rec["dumper"] == "il2cppdumper_rs" and rec["metadata_version"] is None

    # service falls back to the other dumper family when the recommended
    # one is missing
    ga = _fake_binary(tmp_path / "GameAssembly.dll")
    _make_session(svc, sid="s-fallback",
                  engine={"artifacts": {"game_assembly": str(ga)}})

    monkeypatch.setattr(svc_mod.toolchain, "recommended_unity_dumper",
                        lambda meta, cfg: {"dumper": "il2cppdumper_rs",
                                           "metadata_version": None,
                                           "found": False, "path": None,
                                           "hint": "install rs dumper"})
    fallback_exe = tmp_path / "Il2CppDumper.exe"
    fallback_exe.write_bytes(b"MZ-fake")
    monkeypatch.setattr(svc_mod.toolchain, "detect_tool",
                        lambda name, cfg=None: {"name": name, "found": True,
                                                "path": str(fallback_exe)})

    calls = []

    def fake_run_cli(dumper_path, target, out, *, timeout=120.0):
        calls.append({"dumper_path": dumper_path, "target": target})
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)
        _write_script_json(out / "script.json")
        return {"ok": True, "outputs": {"script.json": str(out / "script.json")},
                "returncode": 0, "out_dir": str(out), "elapsed": 0.05}

    monkeypatch.setattr(svc_mod.engines.unity, "run_dumper_cli", fake_run_cli)

    res = svc.il2cpp_dump("s-fallback", out_dir=str(tmp_path / "dump"))
    assert res["ok"] is True
    assert calls[0]["dumper_path"] == str(fallback_exe)

    # neither dumper family installed -> ToolNotFoundError with both hints
    _make_session(svc, sid="s-none",
                  engine={"artifacts": {"game_assembly": str(ga)}})
    monkeypatch.setattr(svc_mod.toolchain, "detect_tool",
                        lambda name, cfg=None: {"name": name, "found": False})
    with pytest.raises(ToolNotFoundError) as exc:
        svc.il2cpp_dump("s-none")
    assert "Il2CppDumper" in exc.value.hint
    assert "il2cpp-dumper-rs" in exc.value.hint

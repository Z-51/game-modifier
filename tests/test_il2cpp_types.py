"""Tests for the Unity il2cpp runtime type decoders (string/List/Dictionary).

Builds a synthetic il2cpp memory image over the shared FakeBackend: standard
x64 runtime layouts (Il2CppString length@0x10 + UTF-16 chars@0x14, Il2CppArray
bounds@0x10/max_length@0x18/items@0x20, List _items@0x10/_size@0x18,
Dictionary entries@0x18/count@0x20 with 24-byte entries).
"""

from __future__ import annotations

import struct

import pytest

from conftest import FakeBackend

from game_modifier import mcp_server
from game_modifier.cli import build_parser, dispatch
from game_modifier.config import Config
from game_modifier.engines import unity_introspect
from game_modifier.memory import process as procmod
from game_modifier.service import ModifierService
from test_mcp_extended import _tool_names

BASE = 0x10000000


def p64(v):
    return struct.pack("<Q", v)


def p32(v):
    return struct.pack("<i", v)


def f32(v):
    return struct.pack("<f", v)


# ---- addresses inside the synthetic image ----------------------------------
STR_HELLO = BASE + 0x100
STR_CN = BASE + 0x200
STR_LONG = BASE + 0x300
STR_BAD = BASE + 0x400
ARR_PTR = BASE + 0x500        # ptr array, elements inline at +0x20
LIST_PTR = BASE + 0x600       # List<object> -> ARR_PTR, _size=3
LIST_I32 = BASE + 0x640       # List<int> -> ARR_I32, _size=3
LIST_F32 = BASE + 0x680       # List<float> -> ARR_F32, _size=3
ARR_I32 = BASE + 0x700
ARR_F32 = BASE + 0x800
DICT = BASE + 0x900           # count=2, 4 slots (2 free)
DICT_ENTRIES = BASE + 0x960
DICT2 = BASE + 0xA00          # count=3, all live (limit tests)
DICT2_ENTRIES = BASE + 0xA60
STR_MOD = BASE + 0xB00        # modified runtime: length@0x18, chars@0x1C

_OBJ_HDR = p64(0xDEAD0001) + p64(0)  # klass + monitor


def _put_string(img, off, text, length_off=0x10, chars_off=0x14):
    hdr = bytearray(0x20)
    hdr[0:16] = _OBJ_HDR
    data = text.encode("utf-16-le")
    struct.pack_into("<i", hdr, length_off, len(text))
    img[off : off + len(hdr)] = hdr
    img[off + chars_off : off + chars_off + len(data)] = data


def _put_array(img, off, max_length, data=b""):
    img[off : off + 0x10] = _OBJ_HDR
    img[off + 0x10 : off + 0x18] = p64(0)              # bounds
    img[off + 0x18 : off + 0x20] = p64(max_length)     # max_length
    if data:
        img[off + 0x20 : off + 0x20 + len(data)] = data


def _dict_entry(hash_code, nxt, key, value):
    return p32(hash_code) + p32(nxt) + p64(key) + p64(value)


def make_il2cpp_image() -> bytearray:
    img = bytearray(0x2000)

    # strings
    _put_string(img, 0x100, "Hello")
    _put_string(img, 0x200, "你好世界")
    _put_string(img, 0x300, "ABCDEFGHIJ")
    img[0x400 : 0x410] = _OBJ_HDR
    img[0x410 : 0x414] = p32(-1)  # suspicious length

    # ptr array: 3 live pointers + a trailing NULL
    _put_array(img, 0x500, 4, p64(0xAA0) + p64(0xBB0) + p64(0xCC0) + p64(0))

    # lists
    for list_off, arr, size in ((0x600, ARR_PTR, 3), (0x640, ARR_I32, 3), (0x680, ARR_F32, 3)):
        img[list_off : list_off + 0x10] = _OBJ_HDR
        img[list_off + 0x10 : list_off + 0x18] = p64(arr)      # _items
        img[list_off + 0x18 : list_off + 0x1C] = p32(size)     # _size
        img[list_off + 0x1C : list_off + 0x20] = p32(1)        # _version

    _put_array(img, 0x700, 3, p32(11) + p32(22) + p32(33))
    _put_array(img, 0x800, 3, f32(1.5) + f32(-2.5) + f32(3.25))

    # dictionary: slot0 live (end of chain, next=-1 but hashCode kept),
    # slot1 free, slot2 live, slot3 free-list slot
    img[0x900 : 0x910] = _OBJ_HDR
    img[0x910 : 0x918] = p64(BASE + 0x940)          # buckets
    img[0x918 : 0x920] = p64(DICT_ENTRIES)          # entries
    img[0x920 : 0x924] = p32(2)                     # count
    _put_array(img, 0x960, 4,
               _dict_entry(7, -1, 0x2000, 0x2100) +
               _dict_entry(0, -1, 0, 0) +
               _dict_entry(9, 0, 0x2200, 0x2300) +
               _dict_entry(0, 1, 0, 0))

    # second dictionary: 3 live entries (limit/truncation tests)
    img[0xA00 : 0xA10] = _OBJ_HDR
    img[0xA10 : 0xA18] = p64(BASE + 0xA40)
    img[0xA18 : 0xA20] = p64(DICT2_ENTRIES)
    img[0xA20 : 0xA24] = p32(3)
    _put_array(img, 0xA60, 3,
               _dict_entry(1, -1, 0x3000, 0x4000) +
               _dict_entry(2, 0, 0x3100, 0x4100) +
               _dict_entry(3, 1, 0x3200, 0x4200))

    # modified-runtime string: length@0x18, chars@0x1C
    _put_string(img, 0xB00, "Mod", length_off=0x18, chars_off=0x1C)
    return img


@pytest.fixture
def il2cpp_backend():
    return FakeBackend(regions={BASE: make_il2cpp_image()})


# ------------------------------------------------------------------- strings
def test_read_string_basic(il2cpp_backend):
    out = unity_introspect.read_string(il2cpp_backend, STR_HELLO)
    assert out["ok"] is True
    assert out["address"] == hex(STR_HELLO)
    assert out["length"] == 5
    assert out["value"] == "Hello"
    assert out["truncated"] is False


def test_read_string_chinese(il2cpp_backend):
    out = unity_introspect.read_string(il2cpp_backend, STR_CN)
    assert out["ok"] is True
    assert out["length"] == 4
    assert out["value"] == "你好世界"


def test_read_string_truncated(il2cpp_backend):
    out = unity_introspect.read_string(il2cpp_backend, STR_LONG, max_chars=4)
    assert out["ok"] is True
    assert out["length"] == 10
    assert out["value"] == "ABCD"
    assert out["truncated"] is True


def test_read_string_bad_length(il2cpp_backend):
    # negative declared length -> suspicious layout, no crash
    out = unity_introspect.read_string(il2cpp_backend, STR_BAD)
    assert out["ok"] is False
    assert "suspicious" in out["reason"]
    assert out["length"] == -1

    # unmapped address -> graceful failure as well
    out2 = unity_introspect.read_string(il2cpp_backend, BASE + 0x1FF000)
    assert out2["ok"] is False
    assert out2["reason"]


def test_read_array_header(il2cpp_backend):
    out = unity_introspect.read_array_header(il2cpp_backend, ARR_PTR)
    assert out["ok"] is True
    assert out["bounds"] is None
    assert out["max_length"] == 4
    assert out["items"] == hex(ARR_PTR + 0x20)


# --------------------------------------------------------------------- lists
def test_read_list_ptr(il2cpp_backend):
    out = unity_introspect.read_list(il2cpp_backend, LIST_PTR)
    assert out["ok"] is True
    assert out["size"] == 3
    assert out["max_length"] == 4
    assert out["elements"] == ["0xaa0", "0xbb0", "0xcc0"]
    assert out["truncated"] is False


def test_read_list_typed(il2cpp_backend):
    out_i = unity_introspect.read_list(il2cpp_backend, LIST_I32, elem_type="int32")
    assert out_i["ok"] is True
    assert out_i["elements"] == [11, 22, 33]

    out_f = unity_introspect.read_list(il2cpp_backend, LIST_F32, elem_type="float")
    assert out_f["ok"] is True
    assert out_f["elements"] == [1.5, -2.5, 3.25]


def test_read_list_limit(il2cpp_backend):
    out = unity_introspect.read_list(il2cpp_backend, LIST_PTR, limit=2)
    assert out["ok"] is True
    assert out["size"] == 3
    assert out["elements"] == ["0xaa0", "0xbb0"]
    assert out["truncated"] is True


# --------------------------------------------------------------- dictionaries
def test_read_dict_entries(il2cpp_backend):
    out = unity_introspect.read_dict(il2cpp_backend, DICT)
    assert out["ok"] is True
    assert out["count"] == 2
    # 24-byte stepping skips the two free slots (hashCode == 0) but keeps the
    # live end-of-chain entry whose next is also -1
    assert out["entries"] == [
        {"key_ptr": "0x2000", "value_ptr": "0x2100", "hash_code": 7},
        {"key_ptr": "0x2200", "value_ptr": "0x2300", "hash_code": 9},
    ]
    assert out["truncated"] is False


def test_read_dict_limit(il2cpp_backend):
    out = unity_introspect.read_dict(il2cpp_backend, DICT2, limit=2)
    assert out["ok"] is True
    assert out["count"] == 3
    assert len(out["entries"]) == 2
    assert out["entries"][0]["key_ptr"] == "0x3000"
    assert out["truncated"] is True


# ------------------------------------------------------------------- layout
def test_layout_override(il2cpp_backend):
    # the modified-runtime string decodes only with the overridden offsets
    out = unity_introspect.read_string(
        il2cpp_backend, STR_MOD,
        layout={"string_length_off": 0x18, "string_chars_off": 0x1C})
    assert out["ok"] is True
    assert out["value"] == "Mod"
    assert out["length"] == 3


# ------------------------------------------------------------------- service
@pytest.fixture
def il2cpp_service(tmp_path, monkeypatch):
    cfg = Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": True,
                   "require_writable_region": True},
        "scan": {"max_results": 1000, "chunk_size": 4096, "alignment": 1, "max_region_bytes": 0},
        "output": {"format": "json"},
        "paths": {"home": str(tmp_path / ".game-modifier")},
    })
    fake = FakeBackend(regions={BASE: make_il2cpp_image()})

    import game_modifier.service as svc

    monkeypatch.setattr(svc, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(cfg), fake


def test_service_il2cpp_string(il2cpp_service):
    svc, _ = il2cpp_service
    sid = svc.attach(pid=4242)["session_id"]

    # plain hex address
    out = svc.il2cpp_string(session_id=sid, address=hex(STR_HELLO))
    assert out["ok"] is True
    assert out["value"] == "Hello"
    assert out["session_id"] == sid

    # address arithmetic expression resolves to the same object
    out2 = svc.il2cpp_string(session_id=sid, address=f"{hex(STR_HELLO + 0x10)}-0x10")
    assert out2["ok"] is True
    assert out2["value"] == "Hello"

    # list through the service as well
    out3 = svc.il2cpp_list(session_id=sid, address=hex(LIST_I32), elem_type="int32")
    assert out3["elements"] == [11, 22, 33]


# ------------------------------------------------------------------ CLI/MCP
def test_cli_il2cpp_parsing():
    p = build_parser()

    a = p.parse_args(["il2cpp", "string", "--session", "s1",
                      "--address", "0x10000100", "--max-chars", "64"])
    assert a.command == "il2cpp" and a.il2cpp_action == "string"
    assert a.session == "s1" and a.address == "0x10000100" and a.max_chars == 64

    a = p.parse_args(["il2cpp", "list", "--session", "s1", "--address", "0x200",
                      "--elem-type", "int32", "--limit", "5"])
    assert a.il2cpp_action == "list"
    assert a.elem_type == "int32" and a.limit == 5

    a = p.parse_args(["il2cpp", "dict", "--session", "s1", "--address", "0x300", "--limit", "7"])
    assert a.il2cpp_action == "dict" and a.limit == 7

    # defaults
    a = p.parse_args(["il2cpp", "list", "--session", "s1", "--address", "0x1"])
    assert a.elem_type == "ptr" and a.limit == 100


def test_cli_il2cpp_dispatch():
    p = build_parser()
    calls = {}

    class StubService:
        def il2cpp_string(self, **kw):
            calls["string"] = kw
            return {"ok": True, "value": "Hello"}

        def il2cpp_list(self, **kw):
            calls["list"] = kw
            return {"ok": True, "elements": []}

        def il2cpp_dict(self, **kw):
            calls["dict"] = kw
            return {"ok": True, "entries": []}

    r = dispatch(StubService(), p.parse_args(["il2cpp", "string", "--session", "s1",
                                              "--address", "0x100", "--max-chars", "32"]))
    assert r.command == "il2cpp.string" and r.data["value"] == "Hello"
    assert calls["string"]["max_chars"] == 32

    r = dispatch(StubService(), p.parse_args(["il2cpp", "list", "--session", "s1",
                                              "--address", "0x200", "--elem-type", "float",
                                              "--limit", "8"]))
    assert r.command == "il2cpp.list"
    assert calls["list"]["elem_type"] == "float" and calls["list"]["limit"] == 8

    r = dispatch(StubService(), p.parse_args(["il2cpp", "dict", "--session", "s1",
                                              "--address", "0x300"]))
    assert r.command == "il2cpp.dict"
    assert calls["dict"]["limit"] == 100


def test_mcp_il2cpp_registered(tmp_path):
    cfg = tmp_path / "cfg.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")

    names = _tool_names(mcp_server.build_server(str(cfg)))
    assert {"il2cpp_string", "il2cpp_list", "il2cpp_dict"} <= names

    ro_names = _tool_names(mcp_server.build_server(str(cfg), profile="readonly"))
    assert {"il2cpp_string", "il2cpp_list", "il2cpp_dict"} <= ro_names

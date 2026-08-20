"""Tests for the scan() ``encoding`` parameter (review §2.3 UTF-16 visibility).

encoding='utf16le' maps onto the pre-existing ``string_utf16`` scanner type
(types.py untouched); it is only valid for string scans. Default remains
utf8 so the frozen behavior is preserved.
"""

from __future__ import annotations

import pytest

from game_modifier import service as svc_mod
from game_modifier.errors import InvalidArgsError
from game_modifier.memory import process as procmod
from game_modifier.service import ModifierService


@pytest.fixture
def scan_env(tmp_config, fake_backend_factory, monkeypatch):
    # region: utf16 "HP" at +0x10, utf8 "HP" at +0x30
    region = bytearray(0x80)
    region[0x10:0x14] = "HP".encode("utf-16-le")
    region[0x30:0x32] = "HP".encode("utf-8")
    fake = fake_backend_factory(regions={0x200000: region})
    monkeypatch.setattr(svc_mod, "get_backend", lambda: fake)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]
    return service, sid


def test_encoding_default_utf8_unchanged(scan_env):
    service, sid = scan_env
    out = service.scan(session_id=sid, type="string", value="HP")
    assert out["count"] == 1  # only the utf8 copy matches
    assert out["type"] == "string"


def test_encoding_utf16le_maps_to_string_utf16(scan_env):
    service, sid = scan_env
    out = service.scan(session_id=sid, type="string", value="HP", encoding="utf16le")
    assert out["count"] == 1  # only the wide copy matches
    assert out["type"] == "string_utf16"
    addr = out["addresses_hex"][0]
    assert int(addr, 16) == 0x200010


def test_encoding_utf16le_case_and_space_normalized(scan_env):
    service, sid = scan_env
    out = service.scan(session_id=sid, type="string", value="HP", encoding=" UTF16LE ")
    assert out["type"] == "string_utf16"
    assert out["count"] == 1


def test_encoding_utf16le_rejected_for_non_string(scan_env):
    service, sid = scan_env
    with pytest.raises(InvalidArgsError):
        service.scan(session_id=sid, type="int32", value="1", encoding="utf16le")


def test_encoding_unknown_rejected(scan_env):
    service, sid = scan_env
    with pytest.raises(InvalidArgsError):
        service.scan(session_id=sid, type="string", value="HP", encoding="utf32")

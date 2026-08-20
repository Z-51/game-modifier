"""Result envelopes, JSON/human rendering and the fallback serializer."""

from __future__ import annotations

import io
import json

from game_modifier.errors import ErrorCode, GameModifierError, SessionNotFoundError
from game_modifier.output import Result, _default, emit


def _capture(result: Result, fmt: str) -> tuple[str, int]:
    buf = io.StringIO()
    code = emit(result, fmt=fmt, stream=buf)
    return buf.getvalue(), code


# ------------------------------------------------------------------- builders
def test_result_success_no_data():
    res = Result.success("sessions")

    assert res.ok is True
    assert res.command == "sessions"
    assert res.data is None
    assert res.warnings == []
    assert res.error is None


def test_result_success_with_data():
    res = Result.success("read", {"value": 100}, warnings=["dry-run"])

    assert res.ok is True
    assert res.data == {"value": 100}
    assert res.warnings == ["dry-run"]


def test_result_failure_with_code():
    res = Result.failure("scan", ErrorCode.NEEDS_SCAN, "scan first")

    assert res.ok is False
    assert res.data is None
    assert res.error == {"code": "E_NEEDS_SCAN", "message": "scan first"}

    # a plain string code is accepted too
    raw = Result.failure("scan", "E_CUSTOM", "boom")
    assert raw.error["code"] == "E_CUSTOM"


def test_result_failure_with_hint():
    res = Result.failure("modify", ErrorCode.NOT_CONFIRMED, "needs --confirm", hint="pass --confirm")

    assert res.error["hint"] == "pass --confirm"
    assert "details" not in res.error


def test_result_failure_with_details_and_warnings():
    res = Result.failure(
        "modify",
        ErrorCode.INVALID_ADDRESS,
        "bad address",
        details={"address": "0x0"},
        warnings=["region not writable"],
    )

    assert res.error["details"] == {"address": "0x0"}
    assert res.warnings == ["region not writable"]


def test_result_from_exception_uses_error_payload():
    exc = SessionNotFoundError("missing", details={"session_id": "s1"}, hint="attach first")

    res = Result.from_exception("read", exc)

    assert res.ok is False
    assert res.error == {
        "code": "E_SESSION_NOT_FOUND",
        "message": "missing",
        "hint": "attach first",
        "details": {"session_id": "s1"},
    }


def test_result_warn_appends_and_chains():
    res = Result.success("scan").warn("a").warn("b")

    assert res.warnings == ["a", "b"]


# --------------------------------------------------------------------- to_dict
def test_result_to_dict_ok_format():
    payload = Result.success("read", {"value": 1}).to_dict()

    assert payload == {"ok": True, "command": "read", "data": {"value": 1}}
    # no data -> empty object, never null, and never an "error" key
    assert Result.success("detach").to_dict() == {"ok": True, "command": "detach", "data": {}}


def test_result_to_dict_error_format():
    payload = Result.failure("read", ErrorCode.READ_FAILED, "nope").to_dict()

    assert payload == {"ok": False, "command": "read", "error": {"code": "E_READ_FAILED", "message": "nope"}}
    assert "data" not in payload

    # an ok=False result with no error dict still yields a code
    bare = Result(command="x", ok=False).to_dict()
    assert bare["error"] == {"code": "E_INTERNAL", "message": "unknown"}


def test_result_to_dict_includes_warnings_only_when_present():
    assert "warnings" not in Result.success("read", {}).to_dict()
    assert Result.success("read", {}).warn("careful").to_dict()["warnings"] == ["careful"]


def test_result_exit_code():
    assert Result.success("read").exit_code == 0
    assert Result.failure("read", ErrorCode.INTERNAL, "boom").exit_code == 1


# ----------------------------------------------------------------------- emit
def test_emit_json_format():
    out, code = _capture(Result.success("read", {"value": 100}), "json")

    assert code == 0
    assert out.endswith("\n")
    assert "\n" not in out[:-1]  # compact: single line
    assert json.loads(out) == {"ok": True, "command": "read", "data": {"value": 100}}


def test_emit_json_keeps_unicode_readable():
    out, _ = _capture(Result.success("nl", {"raw": "将金币设为9999"}), "json")

    assert "将金币设为9999" in out


def test_emit_json_pretty():
    out, code = _capture(Result.success("read", {"value": 100}), "json-pretty")

    assert code == 0
    assert '\n  "ok": true' in out
    assert json.loads(out)["data"] == {"value": 100}


def test_emit_human_success():
    out, code = _capture(Result.success("scan", {"count": 3}).warn("truncated"), "human")

    assert code == 0
    assert out.startswith("[OK] scan\n")
    assert '"count": 3' in out
    assert "  warning: truncated\n" in out


def test_emit_human_error():
    res = Result.failure(
        "modify",
        ErrorCode.ADDRESS_NOT_WRITABLE,
        "region is read-only",
        details={"address": "0x140000000"},
        hint="pick another address",
    )

    out, code = _capture(res, "human")

    assert code == 1
    assert out.startswith("[ERROR] modify\n")
    assert "  code: E_ADDRESS_NOT_WRITABLE\n" in out
    assert "  message: region is read-only\n" in out
    assert "  hint: pick another address\n" in out
    assert '"address": "0x140000000"' in out


def test_emit_unknown_format_falls_back_to_human():
    out, _ = _capture(Result.success("sessions", []), "table")

    assert out.startswith("[OK] sessions\n")


# --------------------------------------------------------------- serializer
def test_default_serializer_bytes():
    assert _default(b"\x0f\x27") == "0f27"
    out, _ = _capture(Result.success("backup", {"bytes": b"\xde\xad"}), "json")
    assert json.loads(out)["data"]["bytes"] == "dead"


def test_default_serializer_set_tuple():
    assert _default({1}) == [1]
    assert _default((1, 2)) == [1, 2]
    assert sorted(_default({"a", "b"})) == ["a", "b"]


def test_default_serializer_uses_to_dict():
    exc = GameModifierError("boom", code=ErrorCode.INTERNAL)

    assert _default(exc) == {"code": "E_INTERNAL", "message": "boom"}


def test_default_serializer_falls_back_to_str():
    class Weird:
        def __str__(self) -> str:
            return "weird!"

    assert _default(Weird()) == "weird!"
    out, _ = _capture(Result.success("x", {"obj": Weird()}), "json")
    assert json.loads(out)["data"]["obj"] == "weird!"

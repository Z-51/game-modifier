"""Error taxonomy: codes, base behaviour and subclass defaults."""

from __future__ import annotations

import pytest

from game_modifier import errors as err
from game_modifier.errors import ErrorCode, GameModifierError

# every code declared by the taxonomy, grouped as in the module
EXPECTED_CODES = {
    # process / session
    "PROCESS_NOT_FOUND": "E_PROCESS_NOT_FOUND",
    "ACCESS_DENIED": "E_ACCESS_DENIED",
    "SESSION_NOT_FOUND": "E_SESSION_NOT_FOUND",
    "PROCESS_EXITED": "E_PROCESS_EXITED",
    "SESSION_BUSY": "E_SESSION_BUSY",
    # safety / guard
    "ANTI_CHEAT": "E_ANTI_CHEAT",
    "NOT_CONFIRMED": "E_NOT_CONFIRMED",
    "DRY_RUN": "E_DRY_RUN",
    "PROFILE_RESTRICTED": "E_PROFILE_RESTRICTED",
    "PATH_NOT_ALLOWED": "E_PATH_NOT_ALLOWED",
    # memory
    "INVALID_ADDRESS": "E_INVALID_ADDRESS",
    "ADDRESS_NOT_WRITABLE": "E_ADDRESS_NOT_WRITABLE",
    "READ_FAILED": "E_READ_FAILED",
    "WRITE_FAILED": "E_WRITE_FAILED",
    "INVALID_TYPE": "E_INVALID_TYPE",
    "VALUE_OUT_OF_RANGE": "E_VALUE_OUT_OF_RANGE",
    "INVALID_POINTER": "E_INVALID_POINTER",
    # resolution
    "NEEDS_SCAN": "E_NEEDS_SCAN",
    "SYMBOL_NOT_FOUND": "E_SYMBOL_NOT_FOUND",
    "NLP_UNRESOLVED": "E_NLP_UNRESOLVED",
    # tooling / engines
    "TOOL_NOT_FOUND": "E_TOOL_NOT_FOUND",
    "TOOL_FAILED": "E_TOOL_FAILED",
    "ENGINE_UNKNOWN": "E_ENGINE_UNKNOWN",
    # il-tool subprocess (Task #64)
    "IL_TOOL_MISSING": "E_IL_TOOL_MISSING",
    "IL_PATCH_FAILED": "E_IL_PATCH_FAILED",
    "IL_VERIFY_FAILED": "E_IL_VERIFY_FAILED",
    "IL_ASSEMBLY_NOT_FOUND": "E_IL_ASSEMBLY_NOT_FOUND",
    "IL_METHOD_NOT_FOUND": "E_IL_METHOD_NOT_FOUND",
    # templates / batch
    "TEMPLATE_NOT_FOUND": "E_TEMPLATE_NOT_FOUND",
    "TEMPLATE_INVALID": "E_TEMPLATE_INVALID",
    "BATCH_ERROR": "E_BATCH_ERROR",
    "BACKUP_NOT_FOUND": "E_BACKUP_NOT_FOUND",
    # save editing (archive-based games)
    "SAVE_EDIT_REQUIRED": "E_SAVE_EDIT_REQUIRED",
    "SAVE_FORMAT_UNSUPPORTED": "E_SAVE_FORMAT_UNSUPPORTED",
    # scan / analysis
    "PATTERN_NOT_FOUND": "E_PATTERN_NOT_FOUND",
    "LAYOUT_UNSUPPORTED": "E_LAYOUT_UNSUPPORTED",
    "SCAN_TIMEOUT": "E_SCAN_TIMEOUT",
    "SCAN_CACHE_STALE": "E_SCAN_CACHE_STALE",
    # generic
    "UNSUPPORTED_OS": "E_UNSUPPORTED_OS",
    "INVALID_ARGS": "E_INVALID_ARGS",
    "DEPENDENCY_MISSING": "E_DEPENDENCY_MISSING",
    "INTERNAL": "E_INTERNAL",
}

# subclass -> the code it must default to
SUBCLASS_CODES = {
    err.ProcessNotFoundError: ErrorCode.PROCESS_NOT_FOUND,
    err.AccessDeniedError: ErrorCode.ACCESS_DENIED,
    err.SessionNotFoundError: ErrorCode.SESSION_NOT_FOUND,
    err.SessionBusyError: ErrorCode.SESSION_BUSY,
    err.AntiCheatError: ErrorCode.ANTI_CHEAT,
    err.NotConfirmedError: ErrorCode.NOT_CONFIRMED,
    err.ProfileRestrictedError: ErrorCode.PROFILE_RESTRICTED,
    err.PathNotAllowedError: ErrorCode.PATH_NOT_ALLOWED,
    err.InvalidAddressError: ErrorCode.INVALID_ADDRESS,
    err.InvalidTypeError: ErrorCode.INVALID_TYPE,
    err.ValueOutOfRangeError: ErrorCode.VALUE_OUT_OF_RANGE,
    err.ReadFailedError: ErrorCode.READ_FAILED,
    err.WriteFailedError: ErrorCode.WRITE_FAILED,
    err.NeedsScanError: ErrorCode.NEEDS_SCAN,
    err.SymbolNotFoundError: ErrorCode.SYMBOL_NOT_FOUND,
    err.NlpUnresolvedError: ErrorCode.NLP_UNRESOLVED,
    err.ToolNotFoundError: ErrorCode.TOOL_NOT_FOUND,
    err.IlToolMissingError: ErrorCode.IL_TOOL_MISSING,
    err.IlPatchFailedError: ErrorCode.IL_PATCH_FAILED,
    err.IlVerifyFailedError: ErrorCode.IL_VERIFY_FAILED,
    err.TemplateNotFoundError: ErrorCode.TEMPLATE_NOT_FOUND,
    err.BatchError: ErrorCode.BATCH_ERROR,
    err.UnsupportedOSError: ErrorCode.UNSUPPORTED_OS,
    err.DependencyMissingError: ErrorCode.DEPENDENCY_MISSING,
    err.InvalidArgsError: ErrorCode.INVALID_ARGS,
    err.SaveEditRequiredError: ErrorCode.SAVE_EDIT_REQUIRED,
    err.SaveFormatUnsupportedError: ErrorCode.SAVE_FORMAT_UNSUPPORTED,
    err.PatternNotFoundError: ErrorCode.PATTERN_NOT_FOUND,
    err.LayoutUnsupportedError: ErrorCode.LAYOUT_UNSUPPORTED,
    err.ScanTimeoutError: ErrorCode.SCAN_TIMEOUT,
    err.ScanCacheStaleError: ErrorCode.SCAN_CACHE_STALE,
}


# ------------------------------------------------------------------ ErrorCode
def test_error_code_enum_all_values():
    assert {member.name: member.value for member in ErrorCode} == EXPECTED_CODES
    # codes are unique and share the stable E_ prefix
    values = [m.value for m in ErrorCode]
    assert len(set(values)) == len(values)
    assert all(v.startswith("E_") for v in values)


def test_error_code_is_str_enum():
    # str mixin keeps codes usable directly in string contexts / JSON
    assert isinstance(ErrorCode.INTERNAL, str)
    assert ErrorCode.INTERNAL == "E_INTERNAL"
    assert ErrorCode("E_NEEDS_SCAN") is ErrorCode.NEEDS_SCAN


# ----------------------------------------------------------- base exception
def test_game_modifier_error_base():
    exc = GameModifierError("boom")

    assert isinstance(exc, Exception)
    assert exc.message == "boom"
    assert exc.code is ErrorCode.INTERNAL
    assert exc.details == {}
    assert exc.hint is None


def test_game_modifier_error_to_dict():
    assert GameModifierError("boom").to_dict() == {"code": "E_INTERNAL", "message": "boom"}


def test_game_modifier_error_with_hint():
    exc = GameModifierError("boom", hint="try harder")

    assert exc.hint == "try harder"
    assert exc.to_dict() == {"code": "E_INTERNAL", "message": "boom", "hint": "try harder"}


def test_game_modifier_error_with_details():
    exc = GameModifierError("boom", code=ErrorCode.NEEDS_SCAN, details={"type": "int32"}, hint="scan")

    assert exc.code is ErrorCode.NEEDS_SCAN
    assert exc.to_dict() == {
        "code": "E_NEEDS_SCAN",
        "message": "boom",
        "hint": "scan",
        "details": {"type": "int32"},
    }


def test_game_modifier_error_empty_extras_are_omitted():
    exc = GameModifierError("boom", details={}, hint="")

    assert exc.to_dict() == {"code": "E_INTERNAL", "message": "boom"}


def test_explicit_code_overrides_subclass_default():
    exc = err.ReadFailedError("boom", code=ErrorCode.ACCESS_DENIED)

    assert exc.code is ErrorCode.ACCESS_DENIED
    # class attribute stays intact for other instances
    assert err.ReadFailedError("other").code is ErrorCode.READ_FAILED


# ------------------------------------------------------------------ subclasses
@pytest.mark.parametrize("cls,code", list(SUBCLASS_CODES.items()), ids=lambda v: getattr(v, "__name__", str(v)))
def test_all_subclasses_default_code(cls, code):
    exc = cls("msg")

    assert exc.code is code
    # code/message are the stable contract fields; key subclasses may now add
    # a DEFAULT_HINT, so we assert on the guaranteed fields rather than strict
    # dict equality (hint presence is covered by tests/test_error_hints.py).
    payload = exc.to_dict()
    assert payload["code"] == code.value
    assert payload["message"] == "msg"


def test_error_inheritance():
    for cls in SUBCLASS_CODES:
        assert issubclass(cls, GameModifierError)
        assert issubclass(cls, Exception)

    # a single except clause catches the whole family
    with pytest.raises(GameModifierError):
        raise err.SymbolNotFoundError("nope")

    # sibling classes are distinct
    with pytest.raises(err.NeedsScanError):
        raise err.NeedsScanError("scan")
    assert not issubclass(err.NeedsScanError, err.SymbolNotFoundError)


def test_subclass_list_covers_module_exports():
    declared = {
        obj
        for obj in vars(err).values()
        if isinstance(obj, type) and issubclass(obj, GameModifierError) and obj is not GameModifierError
    }

    assert declared == set(SUBCLASS_CODES)


# ------------------------------------------------------------------ str/repr
def test_error_str_representation():
    assert str(GameModifierError("boom")) == "boom"
    assert str(err.AntiCheatError("EAC detected", details={"systems": ["eac"]})) == "EAC detected"
    assert "AntiCheatError" in repr(err.AntiCheatError("EAC detected"))
    assert GameModifierError("boom").args == ("boom",)

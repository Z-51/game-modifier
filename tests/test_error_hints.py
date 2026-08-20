"""Executable-hint coverage for the typed error taxonomy (Task #46).

Key error codes now carry actionable, agent-facing hints. The contract is
additive: error-code values, exception hierarchy and the ``to_dict`` shape are
unchanged — we only *fill in* the existing ``hint`` field. These tests lock in:

1. every key subclass ships a non-empty default hint,
2. an explicit ``hint=`` always overrides the class default,
3. ``to_dict`` still surfaces the hint without altering the payload contract,
4. real service-layer paths (bad address / scan timeout / process exited)
   produce the expected guidance,
5. the stable error-code values and class hierarchy are untouched (regression).
"""

from __future__ import annotations

import pytest

import game_modifier.analysis.pointerscan as psmod
import game_modifier.service as svcmod
from game_modifier import errors as err
from game_modifier.errors import ErrorCode, GameModifierError
from game_modifier.memory import process as procmod
from game_modifier.service import ModifierService

from conftest import FakeBackend


# Key subclasses that MUST carry a default, actionable hint.
KEY_HINT_CLASSES = [
    err.InvalidAddressError,
    err.ScanTimeoutError,
    err.NeedsScanError,
    err.SymbolNotFoundError,
    err.LayoutUnsupportedError,
    err.AntiCheatError,
    err.ToolNotFoundError,
    err.DependencyMissingError,
    err.PatternNotFoundError,
    err.SaveFormatUnsupportedError,
    err.ProfileRestrictedError,
]


# ---------------------------------------------------------------- 1. defaults
@pytest.mark.parametrize("cls", KEY_HINT_CLASSES, ids=lambda c: c.__name__)
def test_default_hints_present(cls):
    exc = cls("something went wrong")

    assert exc.hint, f"{cls.__name__} must ship a default hint"
    assert isinstance(exc.hint, str)
    assert exc.hint.strip()
    # the hint is surfaced through the structured payload too
    assert exc.to_dict()["hint"] == exc.hint


def test_base_class_has_no_default_hint():
    # the generic base stays hint-free unless one is supplied explicitly
    assert GameModifierError("boom").hint is None
    assert GameModifierError("boom").DEFAULT_HINT is None


# ----------------------------------------------------- 2. explicit priority
@pytest.mark.parametrize("cls", KEY_HINT_CLASSES, ids=lambda c: c.__name__)
def test_explicit_hint_priority(cls):
    default = cls("x").hint
    custom = "a very specific, contextual hint"
    exc = cls("x", hint=custom)

    assert exc.hint == custom
    assert exc.hint != default
    # the class default stays intact for subsequent instances
    assert cls("y").hint == default


# --------------------------------------------------------- 3. to_dict shape
def test_error_to_dict_hint():
    exc = err.InvalidAddressError("bad addr")
    payload = exc.to_dict()

    # contract fields are always present
    assert payload["code"] == ErrorCode.INVALID_ADDRESS.value
    assert payload["message"] == "bad addr"
    # hint is an additive, optional field
    assert payload["hint"] == exc.hint

    # without a hint (base class) the key is simply omitted
    assert "hint" not in GameModifierError("boom").to_dict()


# --------------------------------------- 4. service: invalid address guidance
@pytest.fixture
def address_service(tmp_config, monkeypatch):
    backend = FakeBackend(regions={0x1000: bytearray(0x40)})
    monkeypatch.setattr(svcmod, "get_backend", lambda: backend)
    monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])
    return ModifierService(tmp_config)


def test_invalid_address_hint_content(address_service):
    sid = address_service.attach(pid=4242)["session_id"]

    # an unknown module in a "module+offset" expression -> E_INVALID_ADDRESS
    with pytest.raises(err.InvalidAddressError) as excinfo:
        address_service.read(session_id=sid, address="ghost.dll+0x10")

    exc = excinfo.value
    assert exc.code == ErrorCode.INVALID_ADDRESS
    assert exc.hint
    # the hint must explain the supported formats + where to inspect symbols
    assert "0x" in exc.hint
    assert "name set" in exc.hint
    assert "session info" in exc.hint
    assert exc.to_dict()["hint"] == exc.hint


# ------------------------------------------------ 5. service: scan timeout
def test_scan_timeout_hint(monkeypatch):
    # force an instant expiry inside the pointer scanner
    clock = [1000.0]

    def fake_monotonic():
        value = clock[0]
        clock[0] += 1.0
        return value

    monkeypatch.setattr(psmod.time, "monotonic", fake_monotonic)

    backend = FakeBackend(regions={0x2000: bytearray(0x80)})
    with pytest.raises(err.ScanTimeoutError) as excinfo:
        psmod.find_pointer_paths(backend, 0x2010, max_depth=3, max_paths=50, timeout=0.5)

    exc = excinfo.value
    assert exc.code == ErrorCode.SCAN_TIMEOUT
    assert exc.hint
    # guidance points at the async escape hatch
    assert "pointer-scan --async" in exc.hint
    assert "job status" in exc.hint


# ----------------------------------------------- 6. service: process exited
def test_process_exited_hint(tmp_config, monkeypatch):
    backend = FakeBackend(regions={0x1000: bytearray(0x40)})
    monkeypatch.setattr(svcmod, "get_backend", lambda: backend)
    monkeypatch.setattr(procmod, "list_processes", lambda: [])

    alive = {"flag": True}
    monkeypatch.setattr(procmod, "process_exists", lambda pid: alive["flag"])

    service = ModifierService(tmp_config)
    sid = service.attach(pid=4242)["session_id"]

    # the target now exits -> the next backend open must raise E_PROCESS_EXITED
    alive["flag"] = False
    with pytest.raises(GameModifierError) as excinfo:
        service.read(session_id=sid, address="0x1000")

    exc = excinfo.value
    assert exc.code == ErrorCode.PROCESS_EXITED
    assert exc.hint
    assert "attach" in exc.hint
    assert exc.to_dict()["hint"] == exc.hint


# ----------------------------------------- 7. stable contract (no regression)
EXPECTED_CODE_VALUES = {
    "PROCESS_NOT_FOUND": "E_PROCESS_NOT_FOUND",
    "ACCESS_DENIED": "E_ACCESS_DENIED",
    "SESSION_NOT_FOUND": "E_SESSION_NOT_FOUND",
    "PROCESS_EXITED": "E_PROCESS_EXITED",
    "SESSION_BUSY": "E_SESSION_BUSY",
    "ANTI_CHEAT": "E_ANTI_CHEAT",
    "NOT_CONFIRMED": "E_NOT_CONFIRMED",
    "DRY_RUN": "E_DRY_RUN",
    "PROFILE_RESTRICTED": "E_PROFILE_RESTRICTED",
    "PATH_NOT_ALLOWED": "E_PATH_NOT_ALLOWED",
    "INVALID_ADDRESS": "E_INVALID_ADDRESS",
    "ADDRESS_NOT_WRITABLE": "E_ADDRESS_NOT_WRITABLE",
    "READ_FAILED": "E_READ_FAILED",
    "WRITE_FAILED": "E_WRITE_FAILED",
    "INVALID_TYPE": "E_INVALID_TYPE",
    "VALUE_OUT_OF_RANGE": "E_VALUE_OUT_OF_RANGE",
    "INVALID_POINTER": "E_INVALID_POINTER",
    "NEEDS_SCAN": "E_NEEDS_SCAN",
    "SYMBOL_NOT_FOUND": "E_SYMBOL_NOT_FOUND",
    "NLP_UNRESOLVED": "E_NLP_UNRESOLVED",
    "TOOL_NOT_FOUND": "E_TOOL_NOT_FOUND",
    "TOOL_FAILED": "E_TOOL_FAILED",
    "ENGINE_UNKNOWN": "E_ENGINE_UNKNOWN",
    "IL_TOOL_MISSING": "E_IL_TOOL_MISSING",
    "IL_PATCH_FAILED": "E_IL_PATCH_FAILED",
    "IL_VERIFY_FAILED": "E_IL_VERIFY_FAILED",
    "IL_ASSEMBLY_NOT_FOUND": "E_IL_ASSEMBLY_NOT_FOUND",
    "IL_METHOD_NOT_FOUND": "E_IL_METHOD_NOT_FOUND",
    "TEMPLATE_NOT_FOUND": "E_TEMPLATE_NOT_FOUND",
    "TEMPLATE_INVALID": "E_TEMPLATE_INVALID",
    "BATCH_ERROR": "E_BATCH_ERROR",
    "BACKUP_NOT_FOUND": "E_BACKUP_NOT_FOUND",
    "SAVE_EDIT_REQUIRED": "E_SAVE_EDIT_REQUIRED",
    "SAVE_FORMAT_UNSUPPORTED": "E_SAVE_FORMAT_UNSUPPORTED",
    "PATTERN_NOT_FOUND": "E_PATTERN_NOT_FOUND",
    "LAYOUT_UNSUPPORTED": "E_LAYOUT_UNSUPPORTED",
    "SCAN_TIMEOUT": "E_SCAN_TIMEOUT",
    "SCAN_CACHE_STALE": "E_SCAN_CACHE_STALE",
    "UNSUPPORTED_OS": "E_UNSUPPORTED_OS",
    "INVALID_ARGS": "E_INVALID_ARGS",
    "DEPENDENCY_MISSING": "E_DEPENDENCY_MISSING",
    "INTERNAL": "E_INTERNAL",
}

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


def test_existing_error_contract():
    # every code value is unchanged
    assert {m.name: m.value for m in ErrorCode} == EXPECTED_CODE_VALUES

    # hierarchy + default codes unchanged
    for cls, code in SUBCLASS_CODES.items():
        assert issubclass(cls, GameModifierError)
        assert cls("m").code is code

    # adding hints must not create/remove subclasses
    declared = {
        obj
        for obj in vars(err).values()
        if isinstance(obj, type) and issubclass(obj, GameModifierError) and obj is not GameModifierError
    }
    assert declared == set(SUBCLASS_CODES)

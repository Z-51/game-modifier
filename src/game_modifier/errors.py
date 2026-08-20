"""Typed error taxonomy with stable machine-readable codes.

Agents rely on the ``code`` field to decide the next action without parsing
prose, which keeps token usage low. Every recoverable failure carries a code,
a short human message and an optional ``details`` payload (for example, the
concrete scan parameters an agent should use next).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional


class ErrorCode(str, Enum):
    """Stable error codes returned in structured output."""

    # process / session
    PROCESS_NOT_FOUND = "E_PROCESS_NOT_FOUND"
    ACCESS_DENIED = "E_ACCESS_DENIED"
    SESSION_NOT_FOUND = "E_SESSION_NOT_FOUND"
    PROCESS_EXITED = "E_PROCESS_EXITED"
    SESSION_BUSY = "E_SESSION_BUSY"

    # safety / guard
    ANTI_CHEAT = "E_ANTI_CHEAT"
    NOT_CONFIRMED = "E_NOT_CONFIRMED"
    DRY_RUN = "E_DRY_RUN"  # informational, not a hard failure
    PROFILE_RESTRICTED = "E_PROFILE_RESTRICTED"
    PATH_NOT_ALLOWED = "E_PATH_NOT_ALLOWED"

    # memory
    INVALID_ADDRESS = "E_INVALID_ADDRESS"
    ADDRESS_NOT_WRITABLE = "E_ADDRESS_NOT_WRITABLE"
    READ_FAILED = "E_READ_FAILED"
    WRITE_FAILED = "E_WRITE_FAILED"
    INVALID_TYPE = "E_INVALID_TYPE"
    VALUE_OUT_OF_RANGE = "E_VALUE_OUT_OF_RANGE"
    INVALID_POINTER = "E_INVALID_POINTER"

    # resolution
    NEEDS_SCAN = "E_NEEDS_SCAN"
    SYMBOL_NOT_FOUND = "E_SYMBOL_NOT_FOUND"
    NLP_UNRESOLVED = "E_NLP_UNRESOLVED"

    # tooling / engines
    TOOL_NOT_FOUND = "E_TOOL_NOT_FOUND"
    TOOL_FAILED = "E_TOOL_FAILED"
    ENGINE_UNKNOWN = "E_ENGINE_UNKNOWN"
    IL_TOOL_MISSING = "E_IL_TOOL_MISSING"
    IL_PATCH_FAILED = "E_IL_PATCH_FAILED"
    IL_VERIFY_FAILED = "E_IL_VERIFY_FAILED"
    IL_ASSEMBLY_NOT_FOUND = "E_IL_ASSEMBLY_NOT_FOUND"
    IL_METHOD_NOT_FOUND = "E_IL_METHOD_NOT_FOUND"

    # templates / batch
    TEMPLATE_NOT_FOUND = "E_TEMPLATE_NOT_FOUND"
    TEMPLATE_INVALID = "E_TEMPLATE_INVALID"
    BATCH_ERROR = "E_BATCH_ERROR"
    BACKUP_NOT_FOUND = "E_BACKUP_NOT_FOUND"

    # save editing (archive-based games)
    SAVE_EDIT_REQUIRED = "E_SAVE_EDIT_REQUIRED"
    SAVE_FORMAT_UNSUPPORTED = "E_SAVE_FORMAT_UNSUPPORTED"

    # scan / analysis
    PATTERN_NOT_FOUND = "E_PATTERN_NOT_FOUND"
    LAYOUT_UNSUPPORTED = "E_LAYOUT_UNSUPPORTED"
    SCAN_TIMEOUT = "E_SCAN_TIMEOUT"
    SCAN_CACHE_STALE = "E_SCAN_CACHE_STALE"

    # generic
    UNSUPPORTED_OS = "E_UNSUPPORTED_OS"
    INVALID_ARGS = "E_INVALID_ARGS"
    DEPENDENCY_MISSING = "E_DEPENDENCY_MISSING"
    INTERNAL = "E_INTERNAL"


class GameModifierError(Exception):
    """Base exception carrying a stable code plus optional structured details."""

    code: ErrorCode = ErrorCode.INTERNAL

    # Class-level fallback hint used when a raise site does not pass an
    # explicit ``hint=``. Subclasses for frequently raised, actionable codes
    # override this so agents always receive a next-step instruction. An
    # explicit ``hint=`` argument always wins over the class default.
    DEFAULT_HINT: Optional[str] = None

    def __init__(
        self,
        message: str,
        *,
        code: Optional[ErrorCode] = None,
        details: Optional[dict[str, Any]] = None,
        hint: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        self.details = details or {}
        self.hint = hint if hint is not None else self.DEFAULT_HINT

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code.value, "message": self.message}
        if self.hint:
            payload["hint"] = self.hint
        if self.details:
            payload["details"] = self.details
        return payload


# --- Specific, frequently raised subclasses ----------------------------------


class ProcessNotFoundError(GameModifierError):
    code = ErrorCode.PROCESS_NOT_FOUND


class AccessDeniedError(GameModifierError):
    code = ErrorCode.ACCESS_DENIED


class SessionNotFoundError(GameModifierError):
    code = ErrorCode.SESSION_NOT_FOUND


class SessionBusyError(GameModifierError):
    """Raised when another thread/process holds the session write lock."""

    code = ErrorCode.SESSION_BUSY
    DEFAULT_HINT = (
        "该会话正被另一个操作占用（如进行中的扫描/批处理）。稍候重试；"
        "用 job list 查看后台任务，必要时 job cancel 后重试。"
    )


class AntiCheatError(GameModifierError):
    code = ErrorCode.ANTI_CHEAT
    DEFAULT_HINT = (
        "检测到反作弊系统。本工具仅限单机/离线游戏，请立即停止操作，不要尝试绕过或注入；"
        "改用合法离线模式或单机存档编辑（save-edit）。"
    )


class NotConfirmedError(GameModifierError):
    code = ErrorCode.NOT_CONFIRMED


class ProfileRestrictedError(GameModifierError):
    """Raised when the active profile / runtime safety level blocks a confirmed write."""

    code = ErrorCode.PROFILE_RESTRICTED
    DEFAULT_HINT = (
        "当前安全档位禁止确认写入。改用 confirm=false（status=preview 预览），"
        "或通过 safety_set_level(level='normal') / --profile default 恢复写权限。"
    )


class PathNotAllowedError(GameModifierError):
    """Raised when a file path falls outside the allowed policy boundary."""

    code = ErrorCode.PATH_NOT_ALLOWED
    DEFAULT_HINT = (
        "路径不在允许范围内。results_read 只能读 sessions/<id>/ 内的文件；"
        "文件类写工具受 [safety].allowed_paths 白名单约束"
        "（在 ~/.game-modifier/config.toml 中追加路径即可解锁）。"
    )


class InvalidAddressError(GameModifierError):
    code = ErrorCode.INVALID_ADDRESS
    DEFAULT_HINT = (
        "支持格式: 十六进制 '0x7ff...'、十进制、符号名（name set 定义）、"
        "'模块名+0x偏移'、算术表达式 '0x100-0x8'。用 session info 查看已定义符号与模块列表。"
    )


class InvalidTypeError(GameModifierError):
    code = ErrorCode.INVALID_TYPE


class ValueOutOfRangeError(GameModifierError):
    code = ErrorCode.VALUE_OUT_OF_RANGE


class ReadFailedError(GameModifierError):
    code = ErrorCode.READ_FAILED


class WriteFailedError(GameModifierError):
    code = ErrorCode.WRITE_FAILED


class NeedsScanError(GameModifierError):
    code = ErrorCode.NEEDS_SCAN
    DEFAULT_HINT = (
        "先执行首扫: scan --session <id> --type int32 --value <当前值>，"
        "游戏中改变数值后用 scan-next 缩小候选。"
    )


class SymbolNotFoundError(GameModifierError):
    code = ErrorCode.SYMBOL_NOT_FOUND
    DEFAULT_HINT = (
        "符号未定义。用 name set 创建: name set <name> --session <id> "
        "--base <addr或模块+偏移> --type int32；用 name get 查看现有符号。"
    )


class NlpUnresolvedError(GameModifierError):
    code = ErrorCode.NLP_UNRESOLVED


class ToolNotFoundError(GameModifierError):
    code = ErrorCode.TOOL_NOT_FOUND
    DEFAULT_HINT = (
        "外部工具未安装或不在 PATH。运行 toolchain detect 查看缺失项，"
        "安装对应工具，或在 config [tools] 段显式配置路径。"
    )


class IlToolMissingError(ToolNotFoundError):
    """Raised when the il-tool subprocess binary cannot be located."""

    code = ErrorCode.IL_TOOL_MISSING
    DEFAULT_HINT = (
        "il-tool 二进制缺失。运行 iltool/build.ps1（需要 .NET 8 SDK）发布到 "
        "src/game_modifier/data/il-tool/，或在 config [tools] 段设置 il_tool 指向 "
        "il-tool.exe；用 toolchain detect 检查 dotnet/il_tool 状态。"
    )


class IlPatchFailedError(GameModifierError):
    """Raised when an il-tool patch op is refused or cannot be applied."""

    code = ErrorCode.IL_PATCH_FAILED
    DEFAULT_HINT = (
        "IL 补丁失败。用 dump 查看方法体确认返回类型/调用点是否匹配所选 op；"
        "mul_before_ret/insert_before_ret 仅支持数值返回类型，"
        "insert_after_call 需要 args.method 体内存在匹配 patch.target 的调用。"
    )


class IlVerifyFailedError(GameModifierError):
    """Raised when the read-back IL does not match the expected opcode pattern."""

    code = ErrorCode.IL_VERIFY_FAILED
    DEFAULT_HINT = (
        "读回校验失败：方法 IL 与期望 opcode 模式不一致。检查 details 中的 "
        "expected/actual 序列；确认 patch 已写入目标文件且 method 选择器定位正确。"
    )


class TemplateNotFoundError(GameModifierError):
    code = ErrorCode.TEMPLATE_NOT_FOUND


class BatchError(GameModifierError):
    code = ErrorCode.BATCH_ERROR


class UnsupportedOSError(GameModifierError):
    code = ErrorCode.UNSUPPORTED_OS


class DependencyMissingError(GameModifierError):
    code = ErrorCode.DEPENDENCY_MISSING
    DEFAULT_HINT = (
        "缺少可选 Python 依赖。按需安装分组: pip install game-modifier[all]（全部）"
        "或 pip install game-modifier[disasm]（仅 capstone 反汇编）。"
    )


class InvalidArgsError(GameModifierError):
    code = ErrorCode.INVALID_ARGS


class SaveEditRequiredError(GameModifierError):
    """Raised when game uses file-based saves and memory modification is ineffective."""

    code = ErrorCode.SAVE_EDIT_REQUIRED

    def __init__(self, message="this game uses file-based saves", **kwargs):
        super().__init__(message, code=ErrorCode.SAVE_EDIT_REQUIRED, **kwargs)


class SaveFormatUnsupportedError(GameModifierError):
    """Raised when the save file format is not supported."""

    code = ErrorCode.SAVE_FORMAT_UNSUPPORTED
    DEFAULT_HINT = (
        "存档格式暂不支持编辑（压缩 / Ren'Py pickle 等）。当前支持 RPG Maker (rmmzsave) "
        "明文存档；不要对同一存档重试，改用内存扫描或等待格式支持。"
    )

    def __init__(self, message="save format not supported", **kwargs):
        super().__init__(message, code=ErrorCode.SAVE_FORMAT_UNSUPPORTED, **kwargs)


class PatternNotFoundError(GameModifierError):
    """Raised when an AOB/signature pattern scan finds no match."""

    code = ErrorCode.PATTERN_NOT_FOUND
    DEFAULT_HINT = (
        "AOB 无命中。检查: 1) 模式字节是否正确（用 disasm 确认指令字节）"
        "2) 通配符 ?? 使用 3) 游戏版本更新会导致特征码失效。"
    )


class LayoutUnsupportedError(GameModifierError):
    """Raised when a memory/data layout cannot be interpreted."""

    code = ErrorCode.LAYOUT_UNSUPPORTED
    DEFAULT_HINT = (
        "布局信息缺失。UE: 先运行 ue introspect --gobjects <偏移> 探测；"
        "il2cpp: 先运行 il2cpp dump 生成 script.json。"
    )


class ScanTimeoutError(GameModifierError):
    """Raised when a scan exceeds its configured time budget."""

    code = ErrorCode.SCAN_TIMEOUT
    DEFAULT_HINT = (
        "缩小扫描范围后重试: 1) 用 scan-next 渐进过滤而非全量首扫 "
        "2) 降低 max_results 3) 指针定位改用 pointer-scan --async 后台执行"
        "（无30s硬超时）并用 job status 轮询。"
    )


class ScanCacheStaleError(GameModifierError):
    """Raised when cached scan results no longer match the live process."""

    code = ErrorCode.SCAN_CACHE_STALE

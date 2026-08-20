"""MCP server exposing game-modifier as structured tools.

Both Claude Code and Codex can talk to this server over stdio. Tools mirror the
CLI but take/return structured JSON, which is the most token-efficient contract
for an agent: it calls ``modify``/``nl``/``template_apply`` with typed args and
gets a compact JSON result, never parsing prose or writing memory code.

Requires the optional ``mcp`` package (``pip install game-modifier[mcp]``). The
module imports fine without it; only ``main()`` needs it, so the rest of the
package (and tests) are unaffected.
"""

from __future__ import annotations

import argparse
import functools
import json
import struct
import sys
from typing import Optional

from . import batch as batchmod
from .config import load_config
from .errors import ErrorCode, GameModifierError
from .memory import pointers
from .memory import types as vt
from .output import Result
from .service import ModifierService


def _import_fastmcp():
    """Locate FastMCP across mcp v1.x, v2.x and the standalone fastmcp package."""

    try:
        from mcp.server.fastmcp import FastMCP  # mcp v1.x
        return FastMCP
    except ImportError:
        pass
    try:
        from mcp.server import FastMCP  # re-exported in newer mcp releases
        return FastMCP
    except ImportError:
        pass
    try:
        from mcp import FastMCP  # possible mcp v2.x top-level export
        return FastMCP
    except ImportError:
        pass
    try:
        from fastmcp import FastMCP  # standalone fastmcp package (FastMCP 2.x)
        return FastMCP
    except ImportError:
        pass
    raise ModuleNotFoundError(
        "Could not import FastMCP from any known location "
        "(mcp.server.fastmcp, mcp.server, mcp, fastmcp)."
    )


def _envelope(command: str, fn, **kwargs) -> dict:
    try:
        data = fn(**kwargs)
        return Result.success(command, data).to_dict()
    except GameModifierError as exc:
        return Result.from_exception(command, exc).to_dict()
    except Exception as exc:  # pragma: no cover - defensive
        return Result.failure(command, "E_INTERNAL", f"{type(exc).__name__}: {exc}").to_dict()


# ---------------------------------------------------------------------------
# Output throttling (ida-pro-mcp pattern): oversized JSON replies are shrunk
# to a preview so a huge scan can never blow the agent's context window.
# Small results pass through untouched.
# ---------------------------------------------------------------------------

MAX_OUTPUT_CHARS = 50000
LIST_DEFAULT_LIMIT = 1000


def _json_size(obj) -> int:
    try:
        return len(json.dumps(obj, ensure_ascii=False, default=str))
    except Exception:
        return 0


def _truncate_output(envelope: dict, max_chars: int = MAX_OUTPUT_CHARS) -> dict:
    """Shrink an oversized ``_envelope`` result to a preview.

    For list-shaped payloads (e.g. scan candidates) the first K items are kept
    and the original counts are reported via ``totals`` plus a
    ``preview_note``. Results under the limit are returned unchanged.
    """

    if _json_size(envelope) <= max_chars:
        return envelope

    out = dict(envelope)
    data = out.get("data")
    if not isinstance(data, dict):
        out["data"] = {
            "preview_note": f"result exceeded the {max_chars}-char output limit and was truncated",
            "original_chars": _json_size(envelope),
        }
        return out

    new_data = dict(data)
    for key, val in data.items():
        if not isinstance(val, list) or not val:
            continue
        keep = len(val)
        while keep > 1:
            candidate = max(1, keep // 2)
            probe = dict(new_data)
            probe[key] = val[:candidate]
            if _json_size({**out, "data": probe}) <= max_chars:
                keep = candidate
                break
            keep = candidate
        new_data[key] = val[:keep]
        new_data.setdefault("totals", {})[key] = len(val)
    new_data["preview_note"] = (
        f"result exceeded the {max_chars}-char output limit; lists were truncated "
        "to a preview - `totals` holds the original item counts"
    )
    out["data"] = new_data
    return out


def _limit_list(data: dict, key: str, limit: int = LIST_DEFAULT_LIMIT) -> dict:
    """Cap one list field of a result dict (additive: only fires over limit)."""

    val = data.get(key)
    if not isinstance(val, list) or len(val) <= limit:
        return data
    out = dict(data)
    out[key] = val[:limit]
    out[f"{key}_total"] = len(val)
    out["preview_note"] = f"{key} truncated to the first {limit} entries"
    return out


def _compact_batch_output(envelope: dict, max_chars: int = MAX_OUTPUT_CHARS) -> dict:
    """Shrink an oversized batch_run reply to a summary + persistence hint.

    Unlike the generic ``_truncate_output`` bisect, this keeps the batch
    summary fields intact and points the caller at ``results_file`` (the full
    result is always persisted by the service) or offset/limit pagination.
    Small replies pass through untouched.
    """

    if _json_size(envelope) <= max_chars:
        return envelope
    data = envelope.get("data")
    if not isinstance(data, dict):
        return envelope
    data = dict(data)
    results = data.get("results") or []
    data["results_total"] = data.get("results_total") or len(results)
    preview = results[:10]
    data["results"] = preview
    note = f"batch results exceeded the {max_chars}-char limit; showing the first {len(preview)} of {data['results_total']} items"
    if data.get("results_file"):
        note += (f"; full results persisted at {data['results_file']} "
                 "(read that file, or call batch_run again with offset/limit to page through results)")
    data["preview_note"] = note
    out = dict(envelope)
    out["data"] = data
    return out


# ---------------------------------------------------------------------------
# value_convert: pure decimal/hex/bytes/float bit-pattern conversion so the
# LLM never has to do base arithmetic itself (hallucination-free).
# ---------------------------------------------------------------------------

def convert_value(value: str, as_type: str = "int32") -> dict:
    """Convert ``value`` between decimal/hex/bytes/float bit patterns.

    Input forms: ``"42"`` (decimal), ``"0x2A"`` (hex), ``"1.5"`` (float), or
    an address arithmetic expression such as ``"0x7fffe2a22ce0-0x5702ce0"``
    (only ``+``/``-``; evaluated first, result carries extra
    ``expression``/``evaluated`` fields).
    No memory backend is involved - this is a pure struct/types computation.
    """

    dt = vt.resolve_type(as_type)
    if dt.kind not in ("int", "uint", "float", "bool"):
        raise GameModifierError(
            f"value_convert supports numeric types only, got {as_type!r}",
            code=ErrorCode.INVALID_ARGS,
            details={"supported": ["int8", "uint8", "int16", "uint16", "int32",
                                   "uint32", "int64", "uint64", "float", "double", "bool"]},
        )
    raw = str(value).strip()
    expression: Optional[str] = None
    evaluated_num: Optional[int] = None
    if pointers.is_address_expr(raw):
        # address arithmetic: evaluate first, then convert the result like a
        # normal number (wide addresses auto-promote past 32-bit types).
        evaluated_num = pointers.eval_address_expr(raw)
        expression = raw
        raw = str(evaluated_num)
        if dt.kind in ("int", "uint"):
            try:
                lo, hi = vt.value_range(dt.name)
                if not (lo <= evaluated_num <= hi):
                    dt = vt.resolve_type("uint64" if evaluated_num >= 0 else "int64")
            except Exception:
                pass
    encoded = vt.encode_value(dt.name, raw)
    decoded = vt.decode_value(dt.name, encoded)
    bits = int.from_bytes(encoded, "little")

    out = {
        "input": value,
        "as_type": dt.name,
        "decimal": decoded,
        "bytes_le": encoded.hex(),
        "bytes_be": encoded[::-1].hex(),
    }
    if expression is not None:
        out["expression"] = expression
        out["evaluated"] = hex(evaluated_num)  # type: ignore[arg-type]
    if dt.kind == "float":
        out["float_bits"] = hex(bits)
    else:
        out["hex"] = hex(bits)
        # reinterpret the same bit pattern as a float of matching width
        if len(encoded) == 4:
            out["float_bits"] = {"as_float32": struct.unpack("<f", encoded)[0]}
        elif len(encoded) == 8:
            out["float_bits"] = {"as_float64": struct.unpack("<d", encoded)[0]}
    try:
        out["ascii"] = encoded.decode("ascii") if all(32 <= b < 127 for b in encoded) else None
    except Exception:
        out["ascii"] = None
    return out


# ---------------------------------------------------------------------------
# Tool groups: on-demand registration so a lean server only ships the tools
# an agent actually needs (each tool description+schema costs context tokens
# on every call). build_server(groups=...) filters by these groups;
# tools_catalog stays registered in every configuration.
# ---------------------------------------------------------------------------

TOOL_GROUPS: dict[str, list[str]] = {
    "core": [
        "attach", "analyze", "sessions", "session_info", "session_survey",
        "session_snapshot", "session_snapshots", "session_restore",
        "detach", "value_convert", "toolchain_detect", "audit_tail",
        "session_notes", "results_read",
    ],
    "scan": ["scan", "scan_next", "scan_aob", "scan_candidates", "read", "resolve", "pointer_scan"],
    "modify": [
        "modify", "nl", "name_set", "name_get", "name_chain", "name_clear_temp",
        "freeze_list", "freeze_start", "freeze_stop",
        "backup_create", "backup_list", "backup_restore",
        "batch_run", "batch_preview", "template_list", "template_show", "template_apply",
        "save_edit_detect", "save_edit_modify",
    ],
    "analysis": [
        "layout_analyze", "heap_scan", "disasm", "xrefs", "dissect",
        "watch_run", "watch_start", "watch_stop", "watch_report", "find_writers",
    ],
    "ue": ["ue_introspect", "ue_actors", "ue_fname"],
    "il2cpp": ["il2cpp_string", "il2cpp_list", "il2cpp_dict", "il2cpp_lookup", "il2cpp_dump"],
    "il": ["il_analyze", "il_dump", "il_callers", "il_patch", "il_verify", "il_backup", "il_restore"],
    "mono": ["mono_dump", "mono_symbol", "mono_string", "mono_list", "mono_dict",
             "mono_static", "mono_heap_scan"],
    "jobs": ["job_status", "job_list", "job_cancel"],
    "macros": ["macro_list", "macro_show", "macro_define", "macro_run", "macro_delete"],
    "safety": ["safety_get_level", "safety_set_level", "file_snapshot", "file_restore"],
}


# ---------------------------------------------------------------------------
# Multi-level profiles: finer-grained tool gating than the original
# default/readonly switch. 'default' and 'readonly' keep their historical
# behavior exactly; the extra tiers are additive registrations defined below.
# ---------------------------------------------------------------------------

PROFILES: dict[str, str] = {
    "default": "全部工具（现有行为）",
    "readonly": "只读工具（现有行为，注册时排除写工具）",
    "dry-run": "只读 + 写工具强制 dry-run（confirm=true 被服务端拒绝）",
    "symbols": "只读 + 符号管理 + 会话快照 + macro 定义/列表",
    "limited": "只读 + modify/nl（受 max_write_bytes 与风险分级约束）+ 符号管理，排除 batch/freeze/template 批量写",
}

# write tools as gated by the historical readonly profile (regression anchor)
WRITE_TOOLS = {
    "modify", "nl", "name_set", "name_chain", "name_clear_temp",
    "template_apply", "batch_run", "freeze_start", "freeze_stop",
    "watch_start", "watch_stop", "find_writers",
    "backup_create", "backup_restore", "save_edit_modify",
    "session_snapshot", "session_restore", "detach", "job_cancel",
    "macro_define", "macro_run", "macro_delete", "il2cpp_dump",
    "il_patch", "il_backup", "il_restore", "mono_dump",
    "file_snapshot", "file_restore",
    "safety_set_level",
}

# read-only tools registered under every profile
READONLY_TOOLS = {
    "attach", "analyze", "scan", "scan_next", "scan_aob", "scan_candidates",
    "read", "resolve",
    "name_get", "template_list", "template_show", "save_edit_detect",
    "macro_list", "macro_show", "backup_list", "freeze_list",
    "watch_run", "watch_report",
    "session_info", "sessions", "session_survey", "session_snapshots",
    "audit_tail", "value_convert", "toolchain_detect", "session_notes",
    "layout_analyze", "heap_scan", "dissect", "pointer_scan",
    "job_status", "job_list",
    "ue_introspect", "ue_actors", "ue_fname", "disasm", "xrefs",
    "il2cpp_string", "il2cpp_list", "il2cpp_dict", "il2cpp_lookup",
    "il_analyze", "il_dump", "il_callers", "il_verify", "mono_symbol",
    "mono_string", "mono_list", "mono_dict", "mono_static", "mono_heap_scan",
    "safety_get_level", "batch_preview", "results_read",
}

# symbols profile: symbol management + session snapshots + macro define/delete
SYMBOLS_EXTRA_TOOLS = {
    "name_set", "name_chain", "name_clear_temp",
    "session_snapshot", "session_restore",
    "macro_define", "macro_delete",
}

# limited profile: single-op writes + symbol management; batch/freeze/template
# bulk writes stay excluded
LIMITED_EXTRA_TOOLS = SYMBOLS_EXTRA_TOOLS | {"modify", "nl"}


def dry_run_confirm_guard(command: str, fn):
    """Wrap a write tool for the dry-run profile: confirm=True is refused with
    an E_PROFILE_RESTRICTED envelope, confirm=False previews run normally.

    ``fn`` is the already-envelope-returning tool implementation, so the
    pass-through returns its envelope untouched (no double wrapping).
    """

    @functools.wraps(fn)  # inherit the signature so FastMCP builds the right schema
    def wrapped(**kwargs):
        if kwargs.get("confirm"):
            return Result.failure(
                command, "E_PROFILE_RESTRICTED",
                "dry-run profile blocks confirmed writes",
                hint=("use status=preview (confirm=false) or restart the server "
                      "with --profile default"),
            ).to_dict()
        return fn(**kwargs)

    wrapped.__name__ = command  # FastMCP derives the tool name from __name__
    return wrapped


def build_server(config_path: Optional[str] = None, profile: str = "default",
                 groups: Optional[list[str]] = None):
    """Construct the FastMCP server with the requested tools registered.

    ``profile='readonly'`` registers only read-only tools (no modify/nl/
    name_set/name_chain/name_clear_temp/template_apply/batch_run/freeze_start/
    freeze_stop/watch_start/watch_stop/backup_create/backup_restore/
    save_edit_modify/job_cancel/detach), for safe deployments.

    ``groups=None`` (default) registers every tool - fully backward
    compatible. ``groups=["core", "scan", ...]`` registers only the listed
    groups (the profile gating still applies on top, so a group's writable
    tools stay gated). Unknown group names raise ``ValueError`` listing the
    valid ones. ``tools_catalog`` is always registered and helps agents pick
    groups for a lean server.

    Profiles beyond the historical default/readonly pair (see ``PROFILES``):
    'dry-run' registers write tools but refuses confirm=true calls; 'symbols'
    adds symbol/snapshot/macro-definition management; 'limited' additionally
    allows modify/nl single-op writes.
    """

    FastMCP = _import_fastmcp()  # imported lazily

    profile = (profile or "default").strip().lower()
    if profile not in PROFILES:
        raise ValueError(
            f"unknown profile: {profile!r} (supported: {', '.join(PROFILES)})")
    profile_mode = profile
    writable = profile_mode == "default"  # historical full-write mode only

    allowed: Optional[set[str]] = None
    if groups is not None:
        selected: list[str] = []
        for g in groups:
            g = str(g or "").strip().lower()
            if g:
                selected.append(g)
        if not selected:
            raise ValueError(
                f"no tool groups selected (valid groups: {', '.join(TOOL_GROUPS)})")
        unknown = [g for g in selected if g not in TOOL_GROUPS]
        if unknown:
            raise ValueError(
                f"unknown tool group(s): {', '.join(sorted(set(unknown)))} "
                f"(valid groups: {', '.join(TOOL_GROUPS)})")
        allowed = set()
        for g in selected:
            allowed.update(TOOL_GROUPS[g])

    config = load_config(config_path)
    service = ModifierService(config)
    mcp = FastMCP("game-modifier")

    def _tool(name: str):
        """Conditional registration: skips tools outside the selected groups."""

        def deco(fn):
            if allowed is None or name in allowed:
                mcp.tool()(fn)
            return fn

        return deco

    @mcp.tool()
    def tools_catalog() -> dict:
        """List all tool groups and their tools (helps agents choose --groups for a lean server)."""
        total = len({t for tools in TOOL_GROUPS.values() for t in tools})
        return {
            "groups": TOOL_GROUPS,
            "total_tools": total,
            "tip": "start server with --groups core,scan to reduce context",
        }

    @_tool("attach")
    def attach(pid: Optional[int] = None, process: Optional[str] = None, exe: Optional[str] = None, window_title: Optional[str] = None, allow_anti_cheat: bool = False) -> dict:
        """Attach to a running single-player game process; returns a reusable session_id + engine/anti-cheat detection."""
        return _envelope("attach", service.attach, pid=pid, name=process, exe=exe, title=window_title, allow_anti_cheat=allow_anti_cheat)

    @_tool("analyze")
    def analyze(session: Optional[str] = None, target: Optional[str] = None, deep: bool = False) -> dict:
        """Detect engine (Unity Il2Cpp / Mono / Unreal) and available RE tools; optional radare2 static analysis."""
        return _envelope("analyze", service.analyze, session_id=session, target=target, deep=deep)

    @_tool("scan")
    def scan(session: str, type: str = "int32", value: Optional[str] = None, comparator: str = "exact",
             value2: Optional[str] = None, offset: Optional[int] = None, limit: Optional[int] = None,
             min_addr: Optional[int] = None, max_addr: Optional[int] = None,
             region_types: Optional[list] = None, encoding: str = "utf8") -> dict:
        """First value scan across readable memory. Comparators: exact/gt/gte/lt/lte/between/unknown.

        String scans support UTF-16: pass encoding='utf16le' with type='string' to scan
        wide (UTF-16LE) strings (encoding defaults to 'utf8'; UTF-16 is only valid for
        string scans).

        Runs with [scan] workers (default 4) parallel region threads when numpy is
        available; degrades to single-threaded automatically otherwise. The candidate
        set is identical either way. Progress is tracked internally (the MCP reply is
        delivered once the scan completes; use the CLI --progress for live updates).
        offset/limit page the returned address window (the full set stays in the
        session; browse it with scan_candidates). min_addr/max_addr/region_types
        restrict which regions are scanned (region_types = Windows MEM_* values,
        e.g. 16777216 image / 131072 private / 262144 mapped)."""
        return _truncate_output(_envelope("scan", service.scan, session_id=session, type=type, value=value,
                                          comparator=comparator, value2=value2,
                                          offset=offset or 0, limit=limit,
                                          min_addr=min_addr, max_addr=max_addr, region_types=region_types,
                                          encoding=encoding))

    @_tool("scan_next")
    def scan_next(session: str, comparator: str = "exact", value: Optional[str] = None,
                  value2: Optional[str] = None, offset: Optional[int] = None, limit: Optional[int] = None,
                  retain_stale: bool = False) -> dict:
        """Refine the previous scan. Adds changed/unchanged/increased/decreased comparators.

        offset/limit page the returned address window (browse the full set with
        scan_candidates). When the region layout changed since the previous scan the
        reply carries cache_stale=true (+ stale_detail breakdown); pass
        retain_stale=true to explicitly keep refining the old candidate set anyway
        (the reply is then flagged retained_stale=true)."""
        return _truncate_output(_envelope("scan_next", service.scan_next, session_id=session, comparator=comparator,
                                          value=value, value2=value2, offset=offset or 0, limit=limit,
                                          retain_stale=retain_stale))

    @_tool("scan_aob")
    def scan_aob(session: str, pattern: str, max_results: int = 1000,
                 offset: Optional[int] = None, limit: Optional[int] = None,
                 min_addr: Optional[int] = None, max_addr: Optional[int] = None,
                 stop_on_limit: bool = False) -> dict:
        """AOB pattern scan with ?? wildcards for signature-based address location.

        min_addr/max_addr restrict the scanned address range; offset/limit page the
        returned address window; stop_on_limit=true keeps scanning past max_results
        (only counting extra matches) instead of truncating immediately."""
        return _truncate_output(_envelope("scan_aob", service.scan_aob, session_id=session, pattern=pattern,
                                          max_results=max_results, offset=offset or 0, limit=limit,
                                          min_addr=min_addr, max_addr=max_addr, stop_on_limit=stop_on_limit))

    @_tool("scan_candidates")
    def scan_candidates(session: str, offset: int = 0, limit: int = 100,
                        min_addr: Optional[int] = None, max_addr: Optional[int] = None) -> dict:
        """Page the current scan candidate set (read-only, O(limit)).

        Serves windows straight from the candidate sidecar without materialising
        the full set; min_addr/max_addr filter by ascending address (bisect).
        values is null for scans that recorded no values (e.g. scan_aob)."""
        return _envelope("scan_candidates", service.scan_candidates, session_id=session,
                         offset=offset, limit=limit, min_addr=min_addr, max_addr=max_addr)

    @_tool("read")
    def read(session: str, symbol: Optional[str] = None, address: Optional[str] = None, type: Optional[str] = None,
             offsets: Optional[str] = None, mode: Optional[str] = None) -> dict:
        """Read a value by symbol name or address (+optional offsets like '0x10,0x20').

        mode: 'relative' (default for bare addresses - offsets are plain additions, correct for
        struct field offsets), 'pointer_chain' (Cheat Engine - dereference then add offset, use
        with 'module.dll+0x10,0x20') or 'field_chain' (add offset then dereference - nested
        struct fields like gem.__data.MainPowerData)."""
        return _envelope("read", service.read, session_id=session, symbol=symbol, address=address, type=type,
                         offsets=offsets, mode=mode)

    if writable:
        @_tool("modify")
        def modify(session: str, value: str, symbol: Optional[str] = None, address: Optional[str] = None, type: Optional[str] = None,
                   offsets: Optional[str] = None, mode: Optional[str] = None, confirm: bool = False, freeze: bool = False,
                   confirm_code: bool = False) -> dict:
            """Write a value (dry-run unless confirm=true). Auto-backs-up originals; optional freeze.

            mode: 'relative' (default for bare addresses - offsets are plain additions),
            'pointer_chain' (dereference then add offset) or 'field_chain' (add offset then
            dereference - nested struct fields).
            High-risk targets (executable/read-only/unknown regions) additionally need
            confirm_code=true - the same staged confirmation batch_run has."""
            return _envelope("modify", service.modify, session_id=session, symbol=symbol, address=address, type=type,
                             value=value, offsets=offsets, mode=mode, confirm=confirm, freeze=freeze,
                             confirm_code=confirm_code)

    @_tool("resolve")
    def resolve(session: str, base: str, offsets: Optional[str] = None, mode: str = "pointer_chain",
                deref_last: bool = True) -> dict:
        """Resolve a pointer path (e.g. 'GameAssembly.dll+0x1234' with offsets) to a final address.

        base also accepts address arithmetic like '0x1b0c00276c5-0x8' (only +/-).
        mode 'pointer_chain' (default): addr = read(addr) + offset (Cheat Engine style, pointer
        arrays / linked structures); 'relative': offsets are added directly (struct field offsets
        on an absolute address); 'field_chain': addr = read(addr + offset) (nested struct fields,
        e.g. gem.__data.MainPowerData.mPowerType).
        deref_last (field_chain only): true (default) also dereferences the final offset step;
        false stops after adding the last offset, yielding the address of a value-typed field."""
        return _envelope("resolve", service.resolve, session_id=session, base_expr=base, offsets=offsets, mode=mode,
                         deref_last=deref_last)

    if writable:
        @_tool("nl")
        def nl(session: str, text: str, confirm: bool = False, confirm_code: bool = False) -> dict:
            """Natural-language modify (Chinese/English), e.g. '将金币设为9999'. Maps to the session symbol table.

            High-risk targets (executable/read-only/unknown regions) additionally need
            confirm_code=true on top of confirm=true."""
            return _envelope("nl", service.nl, session_id=session, text=text, confirm=confirm, confirm_code=confirm_code)

        @_tool("name_set")
        def name_set(session: str, name: str, base: str, type: str = "int32", offsets: Optional[str] = None, mode: Optional[str] = None, description: str = "", temp: bool = False) -> dict:
            """Define a symbolic address (e.g. player.gold = module+offsets) for reuse by name/nl/templates.

            mode: 'relative' (default for bare addresses), 'pointer_chain' or 'field_chain'
            (nested struct field paths).
            temp: mark as transient (removable via name_clear_temp)."""
            return _envelope("name_set", service.name_set, session_id=session, name=name, base_expr=base, offsets=offsets, mode=mode, type=type, description=description, temp=temp)

        @_tool("name_chain")
        def name_chain(session: str, name: str, base: str, offsets: Optional[str] = None, type: str = "uint64", temp: bool = True,
                       mode: Optional[str] = None) -> dict:
            """Walk a multi-level pointer chain (read-only memory access) and register every
            intermediate as a symbol: <name>.step0 (resolved base), <name>.step1..N-1
            (each dereference), <name> (final address).

            base: e.g. 'Game.exe+0x1A4'; offsets: e.g. '0x10,0x28,0x0'.
            mode: 'pointer_chain' (default, deref+offset) or 'field_chain' (offset+deref,
            nested struct fields).
            temp: intermediates default to transient (name_clear_temp removes them); temp=false persists.
            On a mid-chain failure the registered step symbols are kept and the error
            details carry failed_step + the partial steps list (resume from the last good step)."""
            return _envelope("name_chain", service.name_chain, session_id=session, name=name, base=base, offsets=offsets, type=type, temp=temp, mode=mode)

        @_tool("name_clear_temp")
        def name_clear_temp(session: str) -> dict:
            """Remove all temp symbols (e.g. chain intermediates); persistent symbols are kept."""
            return _envelope("name_clear_temp", service.name_clear_temp, session_id=session)

    @_tool("name_get")
    def name_get(session: str, name: Optional[str] = None) -> dict:
        """List all symbols, or show one by name."""
        env = _envelope("name_get", service.name_get, session_id=session, name=name)
        if env.get("ok") and name is None and isinstance(env.get("data"), dict):
            env["data"] = _limit_list(env["data"], "symbols")
        return env

    @_tool("template_list")
    def template_list() -> dict:
        """List predefined genre templates (rpg/action/strategy) and their options."""
        return _envelope("template_list", service.template_list)

    @_tool("template_show")
    def template_show(name: str) -> dict:
        """Show a template's options and targets."""
        return _envelope("template_show", service.template_show, name=name)

    if writable:
        @_tool("template_apply")
        def template_apply(session: str, template: str, option: str, params: Optional[dict] = None, confirm: bool = False) -> dict:
            """Apply a template option (e.g. action/infinite_ammo). Reports unmapped symbols to scan first."""
            return _envelope("template_apply", service.template_apply, session_id=session, name=template, option=option, params=params, confirm=confirm)

        @_tool("batch_run")
        def batch_run(session: str, file: Optional[str] = None, yaml: Optional[str] = None,
                      confirm: bool = False, stop_on_error: bool = True,
                      offset: int = 0, limit: int = 0, confirm_code: bool = False) -> dict:
            """Run a batch of many operations in one call (nl/modify/template/scan/read/...).

            Source: file=<path to a YAML file> OR yaml=<inline YAML text> - exactly
            one of the two (passing both/neither returns a structured E_INVALID_ARGS).

            The complete result is always persisted to sessions/<id>/batch_results/
            (path returned as results_file). For large batches use offset/limit to page
            the inline results window (limit=0 returns all; when oversized the reply is
            shrunk to a summary - read results_file or page with offset/limit).

            Write-risk grading: with confirm=true only risk=normal writes (writable
            data regions) are applied; high-risk targets (executable/read-only/unknown
            regions) are skipped with skipped_reason=high_risk_requires_confirm_code
            unless confirm_code=true releases them too. Dry-run previews report a
            per-item risk field plus a risk_breakdown summary. Call batch_preview
            first to pre-flight the ops without executing anything."""
            return _truncate_output(_compact_batch_output(
                _envelope("batch_run", service.batch_run, session_id=session, path=file,
                          yaml_text=yaml,
                          confirm=confirm, stop_on_error=stop_on_error, offset=offset, limit=limit,
                          confirm_code=confirm_code)))

    # batch_preview is READ-ONLY: registered under every profile (parse +
    # validate + per-op risk pre-flight, nothing is executed)
    @_tool("batch_preview")
    def batch_preview(session: str, file: Optional[str] = None, yaml: Optional[str] = None) -> dict:
        """Pre-flight a batch WITHOUT executing it (read-only): parse + validate +
        per-op write-risk grading (high/normal/none) + estimated_write_bytes total.

        Source: file=<path> OR yaml=<inline YAML text> (exactly one). Use it to budget
        a batch's write volume and spot high-risk targets before calling batch_run."""
        return _truncate_output(_envelope("batch_preview", service.batch_preview,
                                          session_id=session, path=file, yaml_text=yaml))

    # session notes: get is read-only (every profile); set/delete mutate
    # sessions/<id>/notes.jsonl and are gated like symbols-tier write tools
    # (refused server-side on the readonly profile)
    _NOTE_WRITE_PROFILES = {"default", "dry-run", "symbols", "limited"}

    @_tool("session_notes")
    def session_notes(session: str, action: str = "get", key: Optional[str] = None,
                      value: Optional[str] = None) -> dict:
        """Per-session key/value notes (append-only notes.jsonl, outside the session JSON).

        action='get': read one key, or omit key for all notes (read-only).
        action='set': store key=value (a later set overwrites); action='delete': remove
        a key (a missing key returns not_found=true instead of an error).
        set/delete are write operations and are refused on the readonly profile."""
        if str(action or "get").strip().lower() in ("set", "delete") and \
                profile_mode not in _NOTE_WRITE_PROFILES:
            return Result.failure(
                "session_notes", "E_PROFILE_RESTRICTED",
                f"profile '{profile_mode}' allows session_notes get only",
                hint="restart the server with --profile symbols (or default/limited/dry-run) to edit notes",
            ).to_dict()
        return _envelope("session_notes", service.session_notes, session_id=session,
                         action=action, key=key, value=value)


    # --------------------------------------------------------------- macros
    @_tool("macro_list")
    def macro_list(session: str) -> dict:
        """List reusable macros defined for a session (name/description/params/operation count). Read-only."""
        return _envelope("macro_list", service.macro_list, session_id=session)

    @_tool("macro_show")
    def macro_show(session: str, name: str) -> dict:
        """Show one macro's full definition (params declaration + operations). Read-only."""
        return _envelope("macro_show", service.macro_show, session_id=session, name=name)

    if writable:
        @_tool("macro_define")
        def macro_define(session: str, name: str, definition: str, description: str = "") -> dict:
            """Define a reusable parameterized macro for this session.

            definition: YAML string (JSON works too) with 'params' (name ->
            {description, required, default}) and 'operations' - a batch-runner
            compatible list using ${param} placeholders, e.g.
            'params: {base: {required: true}}\\noperations:\\n  - read: {address: "${base}"}'"""
            return _envelope("macro_define", service.macro_define, session_id=session,
                             name=name, definition=definition, description=description)

        @_tool("macro_run")
        def macro_run(session: str, name: str, params: Optional[dict] = None,
                      confirm: bool = False, stop_on_error: bool = True,
                      confirm_code: bool = False) -> dict:
            """Run a stored macro: ${param} substitution then batch-pipeline execution.

            params: JSON object as dict (or JSON string). Missing required params ->
            E_INVALID_ARGS listing them. Writes stay dry-run unless confirm=true.
            Results inherit batch_run persistence (results_file) and write-risk
            grading (confirm_code=true releases high-risk writes too)."""
            parsed: Optional[dict] = None
            if params is not None:
                if isinstance(params, str):
                    try:
                        parsed = json.loads(params)
                    except Exception:
                        raise GameModifierError(
                            f"macro_run params must be a JSON object string, got: {params!r}",
                            code=ErrorCode.INVALID_ARGS,
                        )
                else:
                    parsed = dict(params)
                if not isinstance(parsed, dict):
                    raise GameModifierError(
                        "macro_run params must be a JSON object of name -> value",
                        code=ErrorCode.INVALID_ARGS,
                    )
            return _truncate_output(_compact_batch_output(
                _envelope("macro_run", service.macro_run, session_id=session, name=name,
                          params=parsed, confirm=confirm, stop_on_error=stop_on_error,
                          confirm_code=confirm_code)))

        @_tool("macro_delete")
        def macro_delete(session: str, name: str) -> dict:
            """Delete a stored macro definition."""
            return _envelope("macro_delete", service.macro_delete, session_id=session, name=name)

    @_tool("save_edit_detect")
    def save_edit_detect(session: str) -> dict:
        """List editable save files for save-file based games (RPG Maker / Ren'Py) instead of memory scanning."""
        return _envelope("save_edit_detect", service.save_edit_detect, session_id=session)

    if writable:
        @_tool("save_edit_modify")
        def save_edit_modify(session: str, file: str, field: str, value: str, confirm: bool = False,
                             key: Optional[str] = None, iv: Optional[str] = None) -> dict:
            """Edit one field in a save file (dry-run unless confirm=true); the original file is backed up first.

            Unity custom-encrypted saves (Base64(DES-CBC(JSON)), reported as
            'unity-encrypted' by save_edit_detect) require ``key`` recovered
            from the game code; ``iv`` is optional (defaults to the key). The
            key is used in memory only and never written to session state."""
            return _envelope("save_edit_modify", service.save_edit_modify, session_id=session, path=file, field=field, value=value, confirm=confirm, key=key, iv=iv)

    @_tool("watch_run")
    def watch_run(session: str, address: str, type: str = "int32", interval: float = 0.1, iterations: int = 100) -> dict:
        """Poll an address in the foreground and record value changes (when + old/new). Read-only.

        Polling-based 'find what changes': locates WHEN a value changes, not WHO writes it."""
        return _envelope("watch_run", service.watch_run, session_id=session, address=address, type=type,
                         interval=interval, iterations=iterations)

    @_tool("watch_report")
    def watch_report(session: str, limit: int = 50) -> dict:
        """Show the value-change history recorded by the background watch worker (most recent last)."""
        return _envelope("watch_report", service.watch_report, session_id=session, limit=limit)

    @_tool("freeze_list")
    def freeze_list(session: str) -> dict:
        """List registered value freezes for a session."""
        return _envelope("freeze_list", service.freeze_list, session_id=session)

    if writable:
        @_tool("watch_start")
        def watch_start(session: str, address: str, type: str = "int32", interval: float = 0.1) -> dict:
            """Start polling an address in a background process; changes are appended to sessions/<id>/watch.jsonl."""
            return _envelope("watch_start", service.watch_start, session_id=session, address=address, type=type, interval=interval)

        @_tool("watch_stop")
        def watch_stop(session: str) -> dict:
            """Stop the background watch process for a session."""
            return _envelope("watch_stop", service.watch_stop, session_id=session)

        @_tool("find_writers")
        def find_writers(session: str, address: str, size: int = 4, duration: float = 5.0, max_hits: int = 20) -> dict:
            """Find which code writes to an address using hardware breakpoints (DR0-3). Briefly suspends target threads."""
            return _envelope("find_writers", service.find_writers, session_id=session, address=address,
                             size=size, duration=duration, max_hits=max_hits)

        @_tool("freeze_start")
        def freeze_start(session: str, interval: float = 0.05) -> dict:
            """Start enforcing registered freezes in a background process."""
            return _envelope("freeze_start", service.freeze_start, session_id=session, interval=interval)

        @_tool("freeze_stop")
        def freeze_stop(session: str) -> dict:
            """Stop the background freeze process for a session."""
            return _envelope("freeze_stop", service.freeze_stop, session_id=session)

        @_tool("backup_create")
        def backup_create(session: str, symbol: Optional[str] = None, address: Optional[str] = None,
                          type: Optional[str] = None, offsets: Optional[str] = None, mode: Optional[str] = None,
                          size: Optional[int] = None, label: str = "") -> dict:
            """Snapshot original bytes at a symbol/address so a later change can be reverted."""
            target: dict = {}
            if symbol:
                target["symbol"] = symbol
            if address:
                target["address"] = address
            if type:
                target["type"] = type
            if offsets:
                target["offsets"] = offsets
            if mode:
                target["mode"] = mode
            if size:
                target["size"] = size
            return _envelope("backup_create", service.backup_create, session_id=session, targets=[target], label=label)

    @_tool("backup_list")
    def backup_list(session: str) -> dict:
        """List backups (original byte snapshots) for a session."""
        env = _envelope("backup_list", service.backup_list, session_id=session)
        if env.get("ok") and isinstance(env.get("data"), dict):
            env["data"] = _limit_list(env["data"], "backups")
        return env

    if writable:
        @_tool("backup_restore")
        def backup_restore(session: str, backup_id: str) -> dict:
            """Restore original bytes from a backup."""
            return _envelope("backup_restore", service.backup_restore, session_id=session, backup_id=backup_id)

    @_tool("toolchain_detect")
    def toolchain_detect() -> dict:
        """Detect installed reverse-engineering tools (radare2/x64dbg/cdb/Il2CppDumper/...)."""
        return _envelope("toolchain_detect", service.toolchain_detect)

    @_tool("sessions")
    def sessions() -> dict:
        """List all saved sessions."""
        env = _envelope("sessions", service.list_sessions)
        if env.get("ok") and isinstance(env.get("data"), dict):
            env["data"] = _limit_list(env["data"], "sessions")
        return env

    @_tool("session_info")
    def session_info(session: str) -> dict:
        """Show one session (engine, anti-cheat, symbols, freezes, alive)."""
        return _envelope("session_info", service.session_info, session_id=session)

    @_tool("session_survey")
    def session_survey(session: str) -> dict:
        """One-call session reconnaissance: engine, top modules, symbols, freezes, backups, toolchain and health."""
        return _envelope("session_survey", service.session_survey, session_id=session)

    @_tool("session_snapshots")
    def session_snapshots(session: str) -> dict:
        """List session state snapshots (name/created_at/size). Read-only."""
        return _envelope("session_snapshots", service.session_snapshots, session_id=session)

    @_tool("audit_tail")
    def audit_tail(session: str, limit: int = 50) -> dict:
        """Show the most recent write-operation audit entries (what was changed, when, backup ids)."""
        return _envelope("audit_tail", service.audit_tail, session_id=session, limit=limit)

    @_tool("results_read")
    def results_read(session: str, path: str, offset: int = 0, limit: int = 400) -> dict:
        """Read a persisted session result file (read-only, paged by lines).

        Many tools spill full payloads to sessions/<id>/ (il_dump/il_analyze -> il/*.json,
        batch_run -> batch_results/, jobs -> jobs/, scans -> scan_results/) and return only
        a summary with out_file/results_file. Pass that path here (absolute or relative to
        the session dir) to read it back - the only sanctioned file-read channel for pure
        MCP clients. Paths outside sessions/<id>/ are refused (E_PATH_NOT_ALLOWED)."""
        return _envelope("results_read", service.results_read, session_id=session,
                         path=path, offset=offset, limit=limit)

    @_tool("value_convert")
    def value_convert(value: str, as_type: str = "int32") -> dict:
        """Convert between decimal/hex/bytes/float bit patterns (no process access).

        Input: "42", "0x2A", "1010", a float string, or address arithmetic
        like "0x7fffe2a22ce0-0x5702ce0" (only +/-; adds `expression`/`evaluated`
        fields). Output carries decimal/hex/bytes_le/bytes_be/float_bits/ascii
        so the agent never computes base conversions or address math itself."""
        return _envelope("value_convert", convert_value, value=value, as_type=as_type)

    if writable:
        @_tool("session_snapshot")
        def session_snapshot(session: str, name: str) -> dict:
            """Save a named snapshot of the current session state (symbols, scan summary, engine verdict).

            Snapshots live at sessions/<id>/snapshots/<name>.json; restore with session_restore."""
            return _envelope("session_snapshot", service.session_snapshot, session_id=session, name=name)

        @_tool("session_restore")
        def session_restore(session: str, name: str) -> dict:
            """Restore a session snapshot by name. The current state is auto-archived as
            snapshots/<name>.pre-restore.json first; after restoring, re-validate addresses
            (the game process may have moved on - re-attach/analyze if needed)."""
            return _envelope("session_restore", service.session_restore, session_id=session, name=name)

        @_tool("detach")
        def detach(session: str) -> dict:
            """Delete a session."""
            return _envelope("detach", service.detach, session_id=session)

    # --- layout analysis tools (phase 3) -----------------------------------
    @_tool("layout_analyze")
    def layout_analyze(session: str, what: str = "vtables", module: Optional[str] = None, address: Optional[str] = None) -> dict:
        """Memory layout analysis. what: 'vtables' (clusters of pointers into code), 'rtti' (MSVC .?AV class names),
        'class' (field layout of instances of a vtable - pass its address). Read-only; results carry confidence+reason."""
        return _envelope("layout_analyze", service.layout_analyze, session_id=session, module=module, what=what, address=address)

    @_tool("heap_scan")
    def heap_scan(session: str, vtable_addr: Optional[str] = None, max_results: int = 500) -> dict:
        """Enumerate heap object candidates (aligned pointer-shaped slots); optionally filter to objects of one vtable."""
        return _envelope("heap_scan", service.heap_scan, session_id=session, vtable_addr=vtable_addr, max_results=max_results)

    @_tool("dissect")
    def dissect(session: str, address: Optional[str] = None, addresses: Optional[str] = None, size: int = 256) -> dict:
        """Auto-dissect object structure: infer field types (vtable/ptr/int/float/bool) at pointer-aligned offsets. Read-only.

        address = one instance; addresses = comma-separated instances of the same class (raises per-field confidence).
        Each field carries offset/guessed_type/confidence/sample_values/reason; unreadable instances are skipped gracefully."""
        return _truncate_output(_envelope("dissect", service.dissect, session_id=session,
                                          address=address, addresses=addresses, size=size))

    @_tool("pointer_scan")
    def pointer_scan(session: str, address: str, max_depth: Optional[int] = None, max_paths: Optional[int] = None,
                     rescan: bool = False, async_run: bool = False, timeout: Optional[float] = None) -> dict:
        """Reverse pointer scan: discover pointer chains (base + offsets) reaching the target address.
        Defaults from [analysis] config; raises E_SCAN_TIMEOUT when the time budget is exceeded.

        rescan=true re-validates the session's previously saved paths against ``address``
        instead of a fresh scan (drops stale paths, sorts survivors by depth/stability);
        raises E_LAYOUT_UNSUPPORTED when no paths were saved yet.

        async_run=true starts the scan as a background job and returns a job_id immediately:
        no 30s hard timeout (timeout = optional wall-clock cap, default unlimited), results are
        persisted even on cancellation. Poll job_status, stop with job_cancel."""
        if rescan:
            return _envelope("pointer_scan", service.pointer_rescan, session_id=session, address=address)
        if async_run:
            return _envelope("pointer_scan", service.pointer_scan_async, session_id=session, address=address,
                             max_depth=max_depth, max_paths=max_paths, timeout=timeout)
        return _envelope("pointer_scan", service.pointer_scan, session_id=session, address=address, max_depth=max_depth, max_paths=max_paths)

    # --- background job tools (async pointer_scan etc.) ---------------------
    @_tool("job_status")
    def job_status(job_id: str, session: Optional[str] = None) -> dict:
        """Poll a background job (e.g. a pointer_scan started with async_run=true). Read-only.

        running -> live progress (phase/depth_reached/paths_found); done -> results_file +
        paths_total + paths_sample; failed/cancelled -> error (partial results persisted too).
        Pass session when the server restarted so persisted results can still be found."""
        return _envelope("job_status", service.job_status, job_id=job_id, session_id=session)

    @_tool("job_list")
    def job_list(session: Optional[str] = None) -> dict:
        """List background jobs (id/kind/status/progress), optionally filtered by session. Read-only."""
        return _envelope("job_list", service.job_list, session_id=session)

    if writable:
        @_tool("job_cancel")
        def job_cancel(job_id: str) -> dict:
            """Request cancellation of a running background job; the worker stops at its next
            checkpoint and persists its partial results before finishing as cancelled."""
            return _envelope("job_cancel", service.job_cancel, job_id=job_id)

    # --- UE structure introspection tools (read-only) -----------------------
    @_tool("ue_introspect")
    def ue_introspect(session: str, gobjects: Optional[str] = None, gnames: Optional[str] = None,
                      gobjects_pattern: Optional[str] = None, gnames_pattern: Optional[str] = None,
                      force: bool = False) -> dict:
        """Probe UE GObjects/FNamePool memory layouts. Returns hypothesis report with confidence+evidence. Read-only.

        gobjects/gnames accept 'Game.exe+0x1D2E500' expressions or bare addresses; patterns only yield
        candidates (never auto-adopted). A confirmed verdict is cached per session (force=true re-probes)."""
        return _envelope("ue_introspect", service.ue_introspect, session_id=session, gobjects=gobjects,
                         gnames=gnames, gobjects_pattern=gobjects_pattern, gnames_pattern=gnames_pattern,
                         force=force)

    @_tool("ue_actors")
    def ue_actors(session: str, limit: int = 100, name_filter: Optional[str] = None,
                  class_filter: Optional[str] = None, list_results: bool = False) -> dict:
        """Enumerate UE Actor instances via the cached GObjects layout (run ue_introspect first). Read-only.

        Default output aggregates by_class counts; list_results=true adds a per-actor detail list."""
        env = _envelope("ue_actors", service.ue_actors, session_id=session, limit=limit,
                        name_filter=name_filter, class_filter=class_filter, list_results=list_results)
        if env.get("ok") and isinstance(env.get("data"), dict):
            env["data"] = _limit_list(env["data"], "actors")
        return _truncate_output(env)

    @_tool("ue_fname")
    def ue_fname(session: str, address: Optional[str] = None, index: Optional[int] = None,
                 compare_index: Optional[int] = None) -> dict:
        """Read/decode/compare a UE FName. Read-only.

        address reads the raw 8-byte handle (decoded too when a cached GNames layout exists);
        index decodes a name-pool index (needs a cached GNames layout); compare_index compares two indices."""
        return _envelope("ue_fname", service.ue_fname, session_id=session, address=address,
                         index=index, compare_index=compare_index)

    # --- runtime disassembly tool (read-only, optional capstone) ------------
    @_tool("disasm")
    def disasm(session: str, address: str, size: int = 256, arch: Optional[str] = None, blocks: bool = False) -> dict:
        """Disassemble code at address. Requires capstone (pip install game-modifier[disasm]). Read-only.

        address accepts a symbol name, '0x..' or 'module+0x..' expression; blocks=true splits the stream into basic blocks."""
        return _truncate_output(_envelope("disasm", service.disasm, session_id=session, address=address,
                                          size=size, arch=arch, blocks=blocks))

    # --- cross-reference query tool (read-only, radare2 primary + pure-Python fallback) ---
    @_tool("xrefs")
    def xrefs(session: str, address: str, direction: str = "to", binary: Optional[str] = None,
              aligned: bool = True) -> dict:
        """Query cross-references for an address. Read-only.

        Primary path: radare2 static analysis of the on-disk binary
        (backend_kind='radare2'). When radare2 is missing or fails, a pure-Python
        live-memory scan answers automatically (backend='python'): every readable
        region is searched for 4/8-byte slots holding the target address; each hit
        carries a region label (image = code/data sections, heap = private
        allocations). aligned=true (default) applies a 4/8-byte alignment filter to
        suppress false positives; aligned=false scans every byte offset.

        direction='to' lists who references the address (axt), 'from' lists what it
        references (axf; radare2 path only). Runtime absolute addresses are converted
        to RVAs via the session module table; binary overrides the target file."""
        return _truncate_output(_envelope("xrefs", service.xrefs, session_id=session, address=address,
                                          direction=direction, binary=binary, aligned=aligned))

    # --- Unity il2cpp runtime type decoders (read-only) ---------------------
    @_tool("il2cpp_string")
    def il2cpp_string(session: str, address: str, max_chars: int = 4096) -> dict:
        """Decode an Il2CppString at address in one call (UTF-16; length@0x10 + chars@0x14). Read-only.

        address accepts a symbol, '0x..', address arithmetic ('0x..+/-0x..') or 'module+0x..'.
        value is capped at max_chars code units (truncated=true flags the cut); a wrong address
        returns ok=false with a reason instead of raising."""
        return _envelope("il2cpp_string", service.il2cpp_string, session_id=session,
                         address=address, max_chars=max_chars)

    @_tool("il2cpp_list")
    def il2cpp_list(session: str, address: str, elem_type: str = "ptr", limit: int = 100) -> dict:
        """Read a System.Collections.Generic.List<T> at address (_items + _size -> elements). Read-only.

        elem_type selects the element decoder: 'ptr' yields hex address strings (feed them back into
        il2cpp_string when they point at strings); int32/int64/float/... yield numbers. truncated=true
        when _size exceeds limit."""
        return _truncate_output(_envelope("il2cpp_list", service.il2cpp_list, session_id=session,
                                          address=address, elem_type=elem_type, limit=limit))

    @_tool("il2cpp_dict")
    def il2cpp_dict(session: str, address: str, limit: int = 100) -> dict:
        """Read a System.Collections.Generic.Dictionary<K,V> at address (24-byte entry table, free slots skipped). Read-only.

        Each entry carries key_ptr/value_ptr hex pointers - decode them with il2cpp_string when they
        point at Il2CppString objects. truncated=true when count exceeds the reported entries."""
        return _truncate_output(_envelope("il2cpp_dict", service.il2cpp_dict, session_id=session,
                                          address=address, limit=limit))

    # --- Unity il2cpp dump integration: RVA lookup (read-only) + dumper ---
    @_tool("il2cpp_lookup")
    def il2cpp_lookup(session: str, rva: str, script_json: Optional[str] = None,
                      tolerance: int = 0, force_index: bool = False,
                      force: bool = False) -> dict:
        """Reverse-lookup an RVA to its IL2CPP method name via the Il2CppDumper script.json index. Read-only.

        rva accepts '0x4E85670', decimal, or +/- address arithmetic (e.g. '0x7ff6a12b8560-0x7ff69c432ef0').
        script_json defaults to the dump associated with the session by il2cpp_dump; the RVA index is
        sidecar-cached (script.json.idx) so repeated lookups on a 300MB+ dump are sub-second.
        tolerance>0 resolves an RVA inside a function body to the nearest function start within tolerance
        bytes (matched='exact'|'nearest'|'none'). force_index=true rebuilds the index cache.
        When the dump recorded a binary fingerprint, the game binary is re-checked: a changed binary
        (game update) adds a non-blocking stale_warning - re-run il2cpp_dump instead of trusting old
        RVAs (force=true skips the freshness check)."""
        return _envelope("il2cpp_lookup", service.il2cpp_lookup, session_id=session, rva=rva,
                         script_json=script_json, tolerance=tolerance, force_index=force_index,
                         force=force)

    # --- Mono IL tool family (il-tool subprocess) ---------------------------
    @_tool("il_analyze")
    def il_analyze(session: str, assembly: Optional[str] = None,
                   type_filter: Optional[str] = None,
                   member_filter: Optional[str] = None) -> dict:
        """Enumerate types/methods/fields of a managed assembly via il-tool (Mono games). Read-only.

        assembly defaults to the session's Assembly-CSharp.dll (module table, then the exe dir).
        type_filter narrows by type name substring; large outputs spill to sessions/<id>/il/
        (returned as out_file) unless member_filter is set - then the member-filtered result
        stays inline. Use il_dump for one method body, il_callers for reference scans."""
        return _truncate_output(_envelope("il_analyze", service.il_analyze, session_id=session,
                                          assembly=assembly, type_filter=type_filter,
                                          member_filter=member_filter))

    @_tool("il_dump")
    def il_dump(session: str, method: str, type: Optional[str] = None,
                assembly: Optional[str] = None) -> dict:
        """Render the IL instruction stream of one method body via il-tool. Read-only.

        method is the method name (type narrows overloads); the full listing spills to
        sessions/<id>/il/ (out_file) - the inline reply keeps the instruction_count summary.
        Feed the opcode names into il_verify's expect pattern after a patch."""
        return _envelope("il_dump", service.il_dump, session_id=session,
                         method=method, type=type, assembly=assembly)

    @_tool("il_callers")
    def il_callers(session: str, method: Optional[str] = None, type: Optional[str] = None,
                   assembly: Optional[str] = None, max_results: int = 0) -> dict:
        """Scan the whole assembly for call/callvirt/ldftn references to a target via il-tool. Read-only.

        The target substring is method (preferred) or type; caller_count/out_file come back
        inline, the full caller table spills to sessions/<id>/il/. max_results>0 caps the scan."""
        return _envelope("il_callers", service.il_callers, session_id=session,
                         method=method, type=type, assembly=assembly, max_results=max_results)

    @_tool("il_verify")
    def il_verify(session: str, method: str, expect: Optional[dict] = None,
                  type: Optional[str] = None, assembly: Optional[str] = None) -> dict:
        """Read back a method's IL and compare the opcode sequence against an expected pattern. Read-only.

        expect is an opcode list (contiguous subsequence match) or {"expected":[...], "exact":bool};
        use it as the post-patch gate for il_patch. A mismatch returns ok=false (E_IL_VERIFY_FAILED)
        with the expected/actual sequences in details."""
        return _envelope("il_verify", service.il_verify, session_id=session,
                         method=method, expect=expect, type=type, assembly=assembly)

    @_tool("mono_symbol")
    def mono_symbol(session: str, query: str, assembly: Optional[str] = None, limit: int = 50) -> dict:
        """Look up types/methods in the mono index by name or RVA (the il2cpp_lookup counterpart for Mono games). Read-only.

        Name queries match case-insensitively as substrings; queries starting with '0x' match the
        method rva_hex exactly. Requires an index built by mono_dump (the error hint says so).
        limit caps the inline match list (truncated=true when cut)."""
        return _envelope("mono_symbol", service.mono_symbol, session_id=session,
                         query=query, assembly=assembly, limit=limit)

    @_tool("mono_string")
    def mono_string(session: str, address: str, max_chars: int = 4096,
                    arch: Optional[str] = None) -> dict:
        """Decode a Mono System.String at address (arch-aware layout: x86 length@0x8/chars@0xC, x64 0x10/0x14). Read-only.

        Reuses the shared il2cpp string decoder with the Mono layout override. address accepts a
        session symbol, hex/decimal address, address arithmetic or a module+0x.. expression.
        arch overrides the process architecture ('x86'/'x64', default: attached process)."""
        return _envelope("mono_string", service.mono_string, session_id=session,
                         address=address, max_chars=max_chars, arch=arch)

    @_tool("mono_list")
    def mono_list(session: str, address: str, elem_type: str = "ptr", limit: int = 100) -> dict:
        """Read a Mono List<T> at address (_items + _size -> elements; same managed layout as IL2CPP). Read-only.

        elem_type selects the element decoder (ptr yields hex address strings; int32/int64/float/...
        yield numbers). Address forms match mono_string."""
        return _envelope("mono_list", service.mono_list, session_id=session,
                         address=address, elem_type=elem_type, limit=limit)

    @_tool("mono_dict")
    def mono_dict(session: str, address: str, limit: int = 100) -> dict:
        """Read a Mono Dictionary<K,V> at address (entry table walk, free slots skipped; same layout as IL2CPP). Read-only.

        Each entry carries key_ptr/value_ptr hex pointers (decode with mono_string when they point
        at System.String objects). Address forms match mono_string."""
        return _envelope("mono_dict", service.mono_dict, session_id=session,
                         address=address, limit=limit)

    @_tool("mono_static")
    def mono_static(session: str, arch: Optional[str] = None, max_results: int = 200,
                    min_addr: Optional[int] = None, max_addr: Optional[int] = None) -> dict:
        """Locate static fields by scanning Mono JIT code for ldsfld artifacts. Read-only.

        Matches the machine code the Mono JIT emits for ldsfld (x86: A1/8B 0D + absolute address;
        x64: RIP-relative 8B 05/48 8B 05) inside executable regions, keeping only hits whose field
        address resolves into mapped memory. Each hit carries code_addr/field_addr/opcode plus
        confidence + reason. min_addr/max_addr restrict the scanned regions; max_results caps hits."""
        return _envelope("mono_static", service.mono_static, session_id=session,
                         arch=arch, max_results=max_results, min_addr=min_addr, max_addr=max_addr)

    @_tool("mono_heap_scan")
    def mono_heap_scan(session: str, vtable_addr: Optional[str] = None, max_results: int = 500) -> dict:
        """Enumerate heap object candidates with an optional Mono vtable filter. Read-only.

        Without vtable_addr every pointer-shaped aligned slot is a candidate; pass a Mono class
        vtable (e.g. from dissect/layout_analyze) to keep only objects of that class. The reply
        also lists mono runtime modules found in the session."""
        return _envelope("mono_heap_scan", service.mono_heap_scan, session_id=session,
                         vtable_addr=vtable_addr, max_results=max_results)

    if writable:
        @_tool("il2cpp_dump")
        def il2cpp_dump(session: str, out_dir: Optional[str] = None, timeout: float = 120.0,
                        force: bool = False) -> dict:
            """Run the installed Il2CppDumper (auto-selected by metadata version) and associate its outputs. Runs an external process.

            On success script.json/dump.cs paths plus a fingerprint of the dumped game binary are stored
            in the session's engine artifacts, so il2cpp_lookup works with no extra arguments and later
            calls can detect a game update; outputs land in out_dir (default sessions/<id>/il2cpp_dump).
            Corrupt dumps (unparseable script.json / empty ScriptMethod) are refused with an errors
            breakdown instead of being associated. When an existing dump's fingerprint is still fresh the
            run is skipped with reused=true - pass force=true to re-dump anyway. Raises E_TOOL_NOT_FOUND
            with install hints for both dumper families when no dumper is installed."""
            return _envelope("il2cpp_dump", service.il2cpp_dump, session_id=session,
                             out_dir=out_dir, timeout=timeout, force=force)

        @_tool("il_patch")
        def il_patch(session: str, op: str, method: str, type: Optional[str] = None,
                     value: Optional[float] = None, target: Optional[str] = None,
                     assembly: Optional[str] = None, out_assembly: Optional[str] = None,
                     confirm: bool = False) -> dict:
            """Patch one managed-assembly method body via il-tool and write the modified assembly back. Runs an external process.

            op: replace_body / mul_before_ret (value=倍率, parameterized - re-run with a new value to tune) /
            insert_before_ret / insert_after_call (target=called method name). confirm=false returns a
            dry-run preview; confirm=true takes an automatic file backup first (backup_id in the reply,
            restorable via il_restore), applies the patch and records it in audit.jsonl. Verify the
            result with il_verify (opcode read-back)."""
            return _envelope("il_patch", service.il_patch, session_id=session, op=op, method=method,
                             type=type, value=value, target=target, assembly=assembly,
                             out_assembly=out_assembly, confirm=confirm)

        @_tool("il_backup")
        def il_backup(session: str, assembly: Optional[str] = None, label: str = "") -> dict:
            """File-level backup of a managed assembly before patching (sha256 recorded, audited). Runs an external process.

            The copy lands in sessions/<id>/file_backups/ with a JSON manifest; the returned backup_id
            feeds il_restore. il_patch does this automatically before every confirmed patch."""
            return _envelope("il_backup", service.il_backup, session_id=session,
                             assembly=assembly, label=label)

        @_tool("il_restore")
        def il_restore(session: str, backup_id: str, confirm: bool = False) -> dict:
            """Restore a file backup taken by il_backup. Runs an external process.

            confirm=false previews what would be restored (plus whether the game process is still
            alive); confirm=true re-checks the backup's sha256, copies it back over the source file
            and audits the operation. A still-running game needs a restart for the restore to take
            effect (warning in the reply)."""
            return _envelope("il_restore", service.il_restore, session_id=session,
                             backup_id=backup_id, confirm=confirm)

        @_tool("mono_dump")
        def mono_dump(session: str, assembly: Optional[str] = None, force: bool = False,
                      timeout: float = 120.0) -> dict:
            """Build the full type/method index of a managed assembly via il-tool (Mono games). Runs an external process.

            Produces sessions/<id>/mono_dump/<assembly>.index.json plus a fingerprint sidecar
            (size/mtime/head-hash - Steam-update detection); while the fingerprint is fresh the run
            is skipped with reused=true (force=true rebuilds). The index is associated with the
            session so mono_symbol works without extra arguments - the il2cpp_dump counterpart for
            Mono games."""
            return _envelope("mono_dump", service.mono_dump, session_id=session,
                             assembly=assembly, force=force, timeout=timeout)

        @_tool("file_snapshot")
        def file_snapshot(session: str, path: str, label: str = "") -> dict:
            """Snapshot any game file into the session's file backup store (sha256 recorded, audited).

            The copy lands in sessions/<id>/file_backups/<backup_id>/<原名> with a JSON manifest
            (source/sha256/timestamp/label); the returned backup_id feeds file_restore. The file's
            hash + fingerprint are also recorded in the session artifacts, so il_analyze/il_verify
            can flag a later game/Steam update with a non-blocking stale_warning."""
            return _envelope("file_snapshot", service.file_snapshot, session_id=session,
                             path=path, label=label)

        @_tool("file_restore")
        def file_restore(session: str, backup_id: str, confirm: bool = False) -> dict:
            """Restore a file snapshot taken by file_snapshot.

            confirm=false previews what would be restored (plus whether the game process is still
            alive); confirm=true refuses while the game process is running (close the game first),
            re-checks the backup sha256, then copies it back over the source file and audits the
            operation."""
            return _envelope("file_restore", service.file_restore, session_id=session,
                             backup_id=backup_id, confirm=confirm)

    # ---------------------------------------------------------------
    # Multi-level profile registrations (additive; default/readonly are
    # handled by the historical blocks above and stay byte-for-byte identical)
    # ---------------------------------------------------------------
    if profile_mode == "dry-run":
        # write tools stay registered, but every confirm=true call is refused
        # server-side (E_PROFILE_RESTRICTED); confirm=false previews run.
        # NB: wrap FIRST, then register - @_tool registers whatever object it
        # receives, so the guard must be applied before decoration.
        def _modify_dryrun(session: str, value: str, symbol: Optional[str] = None, address: Optional[str] = None, type: Optional[str] = None,
                           offsets: Optional[str] = None, mode: Optional[str] = None, confirm: bool = False, freeze: bool = False,
                           confirm_code: bool = False) -> dict:
            """Write a value (dry-run profile: confirm=true is refused server-side)."""
            return _envelope("modify", service.modify, session_id=session, symbol=symbol, address=address, type=type,
                             value=value, offsets=offsets, mode=mode, confirm=confirm, freeze=freeze,
                             confirm_code=confirm_code)

        _tool("modify")(dry_run_confirm_guard("modify", _modify_dryrun))

        def _nl_dryrun(session: str, text: str, confirm: bool = False, confirm_code: bool = False) -> dict:
            """Natural-language modify (dry-run profile: confirm=true is refused server-side)."""
            return _envelope("nl", service.nl, session_id=session, text=text, confirm=confirm, confirm_code=confirm_code)

        _tool("nl")(dry_run_confirm_guard("nl", _nl_dryrun))

        def _template_apply_dryrun(session: str, template: str, option: str, params: Optional[dict] = None, confirm: bool = False) -> dict:
            """Apply a template option (dry-run profile: confirm=true is refused server-side)."""
            return _envelope("template_apply", service.template_apply, session_id=session, name=template, option=option, params=params, confirm=confirm)

        _tool("template_apply")(dry_run_confirm_guard("template_apply", _template_apply_dryrun))

        def _batch_run_dryrun(session: str, file: Optional[str] = None, yaml: Optional[str] = None,
                              confirm: bool = False, stop_on_error: bool = True,
                              offset: int = 0, limit: int = 0, confirm_code: bool = False) -> dict:
            """Run a batch (dry-run profile: confirm=true is refused server-side).

            Source: file=<path> OR yaml=<inline YAML text> (exactly one)."""
            # The call-level guard only inspects kwargs, but service.batch_run
            # merges a document-level confirm/confirm_code over them - parse
            # the batch up front so a self-elevating document is refused here
            # too instead of reaching the real write path.
            doc: Optional[dict] = None
            try:
                if yaml is not None:
                    doc = batchmod.load_batch_text(yaml)
                elif file is not None:
                    doc = batchmod.load_batch(file)
            except GameModifierError:
                doc = None  # malformed/missing source: service raises the real error
            if doc is not None and (bool(doc.get("confirm")) or bool(doc.get("confirm_code"))):
                return Result.failure(
                    "batch_run", "E_PROFILE_RESTRICTED",
                    "dry-run profile blocks confirmed writes (the batch document "
                    "carries confirm/confirm_code)",
                    hint=("Remove confirm/confirm_code from the batch document to get a "
                          "preview, or restart the server with --profile default."),
                ).to_dict()
            return _truncate_output(_compact_batch_output(
                _envelope("batch_run", service.batch_run, session_id=session, path=file,
                          yaml_text=yaml,
                          confirm=confirm, stop_on_error=stop_on_error, offset=offset, limit=limit,
                          confirm_code=confirm_code)))

        _tool("batch_run")(dry_run_confirm_guard("batch_run", _batch_run_dryrun))

        def _save_edit_modify_dryrun(session: str, file: str, field: str, value: str, confirm: bool = False,
                                     key: Optional[str] = None, iv: Optional[str] = None) -> dict:
            """Edit one save-file field (dry-run profile: confirm=true is refused server-side).

            Unity encrypted saves (Base64(DES-CBC(JSON))) need ``key`` from the
            game code (``iv`` optional, defaults to the key); the key is never
            persisted."""
            return _envelope("save_edit_modify", service.save_edit_modify, session_id=session, path=file, field=field, value=value, confirm=confirm, key=key, iv=iv)

        _tool("save_edit_modify")(dry_run_confirm_guard("save_edit_modify", _save_edit_modify_dryrun))

        def _macro_run_dryrun(session: str, name: str, params: Optional[dict] = None,
                              confirm: bool = False, stop_on_error: bool = True,
                              confirm_code: bool = False) -> dict:
            """Run a stored macro (dry-run profile: confirm=true is refused server-side)."""
            return _truncate_output(_compact_batch_output(
                _envelope("macro_run", service.macro_run, session_id=session, name=name,
                          params=params, confirm=confirm, stop_on_error=stop_on_error,
                          confirm_code=confirm_code)))

        _tool("macro_run")(dry_run_confirm_guard("macro_run", _macro_run_dryrun))

        def _il_patch_dryrun(session: str, op: str, method: str, type: Optional[str] = None,
                             value: Optional[float] = None, target: Optional[str] = None,
                             assembly: Optional[str] = None, out_assembly: Optional[str] = None,
                             confirm: bool = False) -> dict:
            """Patch one method body (dry-run profile: confirm=true is refused server-side)."""
            return _envelope("il_patch", service.il_patch, session_id=session, op=op, method=method,
                             type=type, value=value, target=target, assembly=assembly,
                             out_assembly=out_assembly, confirm=confirm)

        _tool("il_patch")(dry_run_confirm_guard("il_patch", _il_patch_dryrun))

        def _il_restore_dryrun(session: str, backup_id: str, confirm: bool = False) -> dict:
            """Restore an il_backup file backup (dry-run profile: confirm=true is refused server-side)."""
            return _envelope("il_restore", service.il_restore, session_id=session,
                             backup_id=backup_id, confirm=confirm)

        _tool("il_restore")(dry_run_confirm_guard("il_restore", _il_restore_dryrun))

        def _file_restore_dryrun(session: str, backup_id: str, confirm: bool = False) -> dict:
            """Restore a file_snapshot backup (dry-run profile: confirm=true is refused server-side)."""
            return _envelope("file_restore", service.file_restore, session_id=session,
                             backup_id=backup_id, confirm=confirm)

        _tool("file_restore")(dry_run_confirm_guard("file_restore", _file_restore_dryrun))

    if profile_mode in ("dry-run", "symbols", "limited"):
        # symbol management: session symbol table edits, no game-memory writes
        @_tool("name_set")
        def name_set(session: str, name: str, base: str, type: str = "int32", offsets: Optional[str] = None, mode: Optional[str] = None, description: str = "", temp: bool = False) -> dict:
            """Define a symbolic address (e.g. player.gold = module+offsets) for reuse by name/nl/templates."""
            return _envelope("name_set", service.name_set, session_id=session, name=name, base_expr=base, offsets=offsets, mode=mode, type=type, description=description, temp=temp)

        @_tool("name_chain")
        def name_chain(session: str, name: str, base: str, offsets: Optional[str] = None, type: str = "uint64", temp: bool = True,
                       mode: Optional[str] = None) -> dict:
            """Walk a multi-level pointer chain and register every intermediate as <name>.stepN.

            mode: 'pointer_chain' (default, deref+offset) or 'field_chain' (offset+deref,
            nested struct fields)."""
            return _envelope("name_chain", service.name_chain, session_id=session, name=name, base=base, offsets=offsets, type=type, temp=temp, mode=mode)

        @_tool("name_clear_temp")
        def name_clear_temp(session: str) -> dict:
            """Remove all temp symbols (e.g. chain intermediates); persistent symbols are kept."""
            return _envelope("name_clear_temp", service.name_clear_temp, session_id=session)

        # session state snapshots (mutate session JSON only, never game memory)
        @_tool("session_snapshot")
        def session_snapshot(session: str, name: str) -> dict:
            """Save a named snapshot of the current session state."""
            return _envelope("session_snapshot", service.session_snapshot, session_id=session, name=name)

        @_tool("session_restore")
        def session_restore(session: str, name: str) -> dict:
            """Restore a session snapshot by name (current state auto-archived first)."""
            return _envelope("session_restore", service.session_restore, session_id=session, name=name)

        # macro definition management (definitions only; macro_run stays gated)
        @_tool("macro_define")
        def macro_define(session: str, name: str, definition: str, description: str = "") -> dict:
            """Define a reusable parameterized macro for this session."""
            return _envelope("macro_define", service.macro_define, session_id=session,
                             name=name, definition=definition, description=description)

        @_tool("macro_delete")
        def macro_delete(session: str, name: str) -> dict:
            """Delete a stored macro definition."""
            return _envelope("macro_delete", service.macro_delete, session_id=session, name=name)

    if profile_mode == "limited":
        # single-op writes allowed (still bounded by max_write_bytes and the
        # confirm gate); batch/freeze/template bulk writes stay unregistered
        @_tool("modify")
        def modify(session: str, value: str, symbol: Optional[str] = None, address: Optional[str] = None, type: Optional[str] = None,
                   offsets: Optional[str] = None, mode: Optional[str] = None, confirm: bool = False, freeze: bool = False,
                   confirm_code: bool = False) -> dict:
            """Write a value (limited profile: single-op writes only, dry-run unless confirm=true).

            High-risk targets (executable/read-only/unknown regions) additionally need
            confirm_code=true on top of confirm=true."""
            return _envelope("modify", service.modify, session_id=session, symbol=symbol, address=address, type=type,
                             value=value, offsets=offsets, mode=mode, confirm=confirm, freeze=freeze,
                             confirm_code=confirm_code)

        @_tool("nl")
        def nl(session: str, text: str, confirm: bool = False, confirm_code: bool = False) -> dict:
            """Natural-language modify (limited profile: single-op writes only)."""
            return _envelope("nl", service.nl, session_id=session, text=text, confirm=confirm, confirm_code=confirm_code)

    # ------------------------------------------------------ runtime safety gear
    @_tool("safety_get_level")
    def safety_get_level() -> dict:
        """Show the runtime safety level ({'level': 'normal'|'dry_run_only', 'source': ...}). Read-only.

        'dry_run_only' refuses every confirmed write (modify/nl/batch) with
        E_PROFILE_RESTRICTED while dry-run previews keep working."""
        return _envelope("safety_get_level", service.safety_get_level)

    if writable:
        @_tool("safety_set_level")
        def safety_set_level(level: str) -> dict:
            """Switch the runtime safety level: 'dry_run_only' forces all writes into dry-run
            (confirm=true refused with E_PROFILE_RESTRICTED); 'normal' restores standard confirm
            gating. Process-scoped only - never persisted to disk."""
            return _envelope("safety_set_level", service.safety_set_level, level=level)

    return mcp


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="game-modifier-mcp", description="game-modifier MCP server")
    parser.add_argument("--config", default=None, help="path to a config.toml override")
    parser.add_argument("--profile", default="default", choices=tuple(PROFILES),
                        help="tool profile: 'readonly' read-only tools only; 'dry-run' write tools "
                             "forced dry-run; 'symbols' read-only + symbol/snapshot management; "
                             "'limited' read-only + modify/nl single-op writes")
    parser.add_argument("--groups", default=None,
                        help="comma-separated tool groups to register (e.g. 'core,scan'); "
                             "default registers every tool. See the tools_catalog tool for the list")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    groups = None
    if args.groups:
        groups = [g.strip() for g in args.groups.split(",") if g.strip()]
    try:
        server = build_server(args.config, profile=args.profile, groups=groups)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    except ModuleNotFoundError:
        sys.stderr.write(
            "The 'mcp' package is required to run the MCP server.\n"
            "Install it with: pip install game-modifier[mcp]  (or: pip install mcp)\n"
        )
        return 1
    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

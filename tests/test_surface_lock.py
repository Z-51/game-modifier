"""Surface lock: six-dimensional golden snapshots of the MCP tool surface (Task #62, phase 0).

This module is the executable definition of "behavior freeze" for the MCP
server: every assertion is an EXACT-equality check against a hardcoded golden
snapshot (no self-deriving assertions). Any change to tool names, parameter
schemas, profile gating, registration constants or service result keys will
fail here loudly and must be consciously re-locked (update the snapshot
constants deliberately - never silently).

Dimensions:
  1. default profile registered tool name set (exact)
  2. per-tool inputSchema snapshot (params / types / required, exact)
  3. readonly / dry-run / symbols / limited profile tool sets (exact)
  4. WRITE_TOOLS / READONLY_TOOLS / SYMBOLS_EXTRA_TOOLS / LIMITED_EXTRA_TOOLS (exact)
  5. service method result dict key sets (attach/analyze/scan/scan_next/scan_aob/batch_run)
  6. registered write-tool parameter symmetry across profiles

Snapshot taken after the confirm_code drift fix (dry-run batch_run/macro_run
wrappers carry confirm_code like the default registrations).
"""

from __future__ import annotations

import asyncio
import json
import struct

import pytest

# the mcp package is optional; skip this whole module when absent
pytest.importorskip("mcp")

from game_modifier import mcp_server  # noqa: E402
from game_modifier.memory import process as procmod  # noqa: E402
from game_modifier.memory.base import ModuleInfo  # noqa: E402
from game_modifier.service import ModifierService  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def mcp_config_path(tmp_path):
    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    return str(cfg)


def _tool_names(server) -> set[str]:
    tm = getattr(server, "_tool_manager", None)
    if tm is not None and hasattr(tm, "_tools"):
        return set(tm._tools.keys())
    return {t.name for t in asyncio.run(server.list_tools())}


def _norm_schema(sch: dict) -> tuple[list[str], dict[str, str]]:
    """Normalize one JSON-schema inputSchema to (sorted required, param->type).

    Mirrors the probe used when the golden snapshot was taken: plain ``type``
    strings are kept, Optional params surface as ``anyOf:<type>,null``.
    """
    props: dict[str, str] = {}
    for pname, psch in (sch.get("properties") or {}).items():
        if "type" in psch:
            props[pname] = psch["type"]
        elif "anyOf" in psch:
            props[pname] = "anyOf:" + ",".join(x.get("type", "null") for x in psch["anyOf"])
        else:  # pragma: no cover - defensive, never hit by the current surface
            props[pname] = json.dumps(psch, sort_keys=True)
    return sorted(sch.get("required") or []), props


def _live_schemas(server) -> dict[str, tuple[list[str], dict[str, str]]]:
    tools = asyncio.run(server.list_tools())
    return {t.name: _norm_schema(t.inputSchema) for t in tools}


# ---------------------------------------------------------------------------
# golden snapshot constants (hardcoded - update deliberately, never derive)
# ---------------------------------------------------------------------------

# --- dimension 1: default profile surface (83 grouped tools + tools_catalog)
# phase 3 registrations: batch_preview (readonly batch pre-flight, modify group),
# session_notes (notes.jsonl key/value store, core group) - added deliberately.
DEFAULT_PROFILE_TOOLS = {
    # core
    "attach", "analyze", "sessions", "session_info", "session_survey",
    "session_snapshot", "session_snapshots", "session_restore",
    "detach", "value_convert", "toolchain_detect", "audit_tail",
    "session_notes", "results_read",
    # scan
    "scan", "scan_next", "scan_aob", "scan_candidates", "read", "resolve", "pointer_scan",
    # modify
    "modify", "nl", "name_set", "name_get", "name_chain", "name_clear_temp",
    "freeze_list", "freeze_start", "freeze_stop",
    "backup_create", "backup_list", "backup_restore",
    "batch_run", "batch_preview", "template_list", "template_show", "template_apply",
    "save_edit_detect", "save_edit_modify",
    # analysis
    "layout_analyze", "heap_scan", "disasm", "xrefs", "dissect",
    "watch_run", "watch_start", "watch_stop", "watch_report", "find_writers",
    # ue
    "ue_introspect", "ue_actors", "ue_fname",
    # il2cpp
    "il2cpp_string", "il2cpp_list", "il2cpp_dict", "il2cpp_lookup", "il2cpp_dump",
    # il (Mono IL tool family via il-tool)
    "il_analyze", "il_dump", "il_callers", "il_patch", "il_verify",
    "il_backup", "il_restore",
    # mono (Mono index build + symbol lookup + runtime introspection)
    "mono_dump", "mono_symbol",
    "mono_string", "mono_list", "mono_dict", "mono_static", "mono_heap_scan",
    # jobs
    "job_status", "job_list", "job_cancel",
    # macros
    "macro_list", "macro_show", "macro_define", "macro_run", "macro_delete",
    # safety
    "safety_get_level", "safety_set_level",
    "file_snapshot", "file_restore",
    # always registered
    "tools_catalog",
}

# --- dimension 3: per-profile surfaces (tools_catalog included everywhere)
READONLY_PROFILE_TOOLS = {
    "analyze", "attach", "audit_tail", "backup_list", "batch_preview", "disasm", "dissect",
    "freeze_list", "heap_scan", "il2cpp_dict", "il2cpp_list", "il2cpp_lookup",
    "il2cpp_string", "il_analyze", "il_callers", "il_dump", "il_verify",
    "job_list", "job_status", "layout_analyze",
    "macro_list", "macro_show",
    "mono_dict", "mono_heap_scan", "mono_list", "mono_static", "mono_string",
    "mono_symbol", "name_get", "pointer_scan",
    "read", "resolve", "results_read",
    "safety_get_level", "save_edit_detect", "scan", "scan_aob",
    "scan_candidates", "scan_next",
    "session_info", "session_notes", "session_snapshots", "session_survey", "sessions",
    "template_list", "template_show", "toolchain_detect", "tools_catalog",
    "ue_actors", "ue_fname", "ue_introspect", "value_convert",
    "watch_report", "watch_run", "xrefs",
}

DRYRUN_PROFILE_TOOLS = READONLY_PROFILE_TOOLS | {
    "batch_run", "file_restore", "il_patch", "il_restore",
    "macro_define", "macro_delete", "macro_run", "modify",
    "name_chain", "name_clear_temp", "name_set", "nl", "save_edit_modify",
    "session_restore", "session_snapshot", "template_apply",
}

SYMBOLS_PROFILE_TOOLS = READONLY_PROFILE_TOOLS | {
    "macro_define", "macro_delete", "name_chain", "name_clear_temp",
    "name_set", "session_restore", "session_snapshot",
}

LIMITED_PROFILE_TOOLS = SYMBOLS_PROFILE_TOOLS | {"modify", "nl"}

# --- dimension 4: module-level gating constants
WRITE_TOOLS_SNAPSHOT = {
    "backup_create", "backup_restore", "batch_run", "detach",
    "file_restore", "file_snapshot", "find_writers",
    "freeze_start", "freeze_stop", "il2cpp_dump",
    "il_backup", "il_patch", "il_restore", "mono_dump",
    "job_cancel",
    "macro_define", "macro_delete", "macro_run", "modify", "name_chain",
    "name_clear_temp", "name_set", "nl", "safety_set_level",
    "save_edit_modify", "session_restore", "session_snapshot",
    "template_apply", "watch_start", "watch_stop",
}

READONLY_TOOLS_SNAPSHOT = {
    "analyze", "attach", "audit_tail", "backup_list", "batch_preview", "disasm", "dissect",
    "freeze_list", "heap_scan", "il2cpp_dict", "il2cpp_list", "il2cpp_lookup",
    "il2cpp_string", "il_analyze", "il_callers", "il_dump", "il_verify",
    "job_list", "job_status", "layout_analyze",
    "macro_list", "macro_show",
    "mono_dict", "mono_heap_scan", "mono_list", "mono_static", "mono_string",
    "mono_symbol", "name_get", "pointer_scan",
    "read", "resolve", "results_read",
    "safety_get_level", "save_edit_detect", "scan", "scan_aob",
    "scan_candidates", "scan_next",
    "session_info", "session_notes", "session_snapshots", "session_survey", "sessions",
    "template_list", "template_show", "toolchain_detect", "ue_actors",
    "ue_fname", "ue_introspect", "value_convert", "watch_report",
    "watch_run", "xrefs",
}

SYMBOLS_EXTRA_TOOLS_SNAPSHOT = {
    "macro_define", "macro_delete", "name_chain", "name_clear_temp",
    "name_set", "session_restore", "session_snapshot",
}

LIMITED_EXTRA_TOOLS_SNAPSHOT = SYMBOLS_EXTRA_TOOLS_SNAPSHOT | {"modify", "nl"}

# --- dimension 2: per-tool inputSchema snapshot of the default server.
# value = (sorted required params, {param: schema type string})
TOOL_SCHEMAS = {
    "tools_catalog": ([], {}),
    "attach": ([], {"pid": "anyOf:integer,null", "process": "anyOf:string,null",
                    "exe": "anyOf:string,null", "window_title": "anyOf:string,null",
                    "allow_anti_cheat": "boolean"}),
    "analyze": ([], {"session": "anyOf:string,null", "target": "anyOf:string,null",
                     "deep": "boolean"}),
    "scan": (["session"], {"session": "string", "type": "string",
                           "value": "anyOf:string,null", "comparator": "string",
                           "value2": "anyOf:string,null",
                           "offset": "anyOf:integer,null", "limit": "anyOf:integer,null",
                           "min_addr": "anyOf:integer,null", "max_addr": "anyOf:integer,null",
                           "region_types": "anyOf:array,null", "encoding": "string"}),
    "scan_next": (["session"], {"session": "string", "comparator": "string",
                                "value": "anyOf:string,null", "value2": "anyOf:string,null",
                                "offset": "anyOf:integer,null", "limit": "anyOf:integer,null",
                                "retain_stale": "boolean"}),
    "scan_aob": (["pattern", "session"], {"session": "string", "pattern": "string",
                                          "max_results": "integer",
                                          "offset": "anyOf:integer,null", "limit": "anyOf:integer,null",
                                          "min_addr": "anyOf:integer,null", "max_addr": "anyOf:integer,null",
                                          "stop_on_limit": "boolean"}),
    "scan_candidates": (["session"], {"session": "string", "offset": "integer", "limit": "integer",
                                      "min_addr": "anyOf:integer,null", "max_addr": "anyOf:integer,null"}),
    "read": (["session"], {"session": "string", "symbol": "anyOf:string,null",
                           "address": "anyOf:string,null", "type": "anyOf:string,null",
                           "offsets": "anyOf:string,null", "mode": "anyOf:string,null"}),
    "modify": (["session", "value"], {"session": "string", "value": "string",
                                      "symbol": "anyOf:string,null", "address": "anyOf:string,null",
                                      "type": "anyOf:string,null", "offsets": "anyOf:string,null",
                                      "mode": "anyOf:string,null", "confirm": "boolean",
                                      "freeze": "boolean", "confirm_code": "boolean"}),
    "resolve": (["base", "session"], {"session": "string", "base": "string",
                                      "offsets": "anyOf:string,null", "mode": "string",
                                      "deref_last": "boolean"}),
    "nl": (["session", "text"], {"session": "string", "text": "string",
                                 "confirm": "boolean", "confirm_code": "boolean"}),
    "name_set": (["base", "name", "session"], {"session": "string", "name": "string",
                                               "base": "string", "type": "string",
                                               "offsets": "anyOf:string,null", "mode": "anyOf:string,null",
                                               "description": "string", "temp": "boolean"}),
    "name_chain": (["base", "name", "session"], {"session": "string", "name": "string",
                                                 "base": "string", "offsets": "anyOf:string,null",
                                                 "type": "string", "temp": "boolean",
                                                 "mode": "anyOf:string,null"}),
    "name_clear_temp": (["session"], {"session": "string"}),
    "name_get": (["session"], {"session": "string", "name": "anyOf:string,null"}),
    "template_list": ([], {}),
    "template_show": (["name"], {"name": "string"}),
    "template_apply": (["option", "session", "template"], {"session": "string", "template": "string",
                                                           "option": "string", "params": "anyOf:object,null",
                                                           "confirm": "boolean"}),
    "batch_run": (["session"], {"session": "string",
                                "file": "anyOf:string,null", "yaml": "anyOf:string,null",
                                "confirm": "boolean", "stop_on_error": "boolean",
                                "offset": "integer", "limit": "integer",
                                "confirm_code": "boolean"}),
    "batch_preview": (["session"], {"session": "string",
                                    "file": "anyOf:string,null", "yaml": "anyOf:string,null"}),
    "session_notes": (["session"], {"session": "string", "action": "string",
                                    "key": "anyOf:string,null", "value": "anyOf:string,null"}),
    "macro_list": (["session"], {"session": "string"}),
    "macro_show": (["name", "session"], {"session": "string", "name": "string"}),
    "macro_define": (["definition", "name", "session"], {"session": "string", "name": "string",
                                                         "definition": "string", "description": "string"}),
    "macro_run": (["name", "session"], {"session": "string", "name": "string",
                                        "params": "anyOf:object,null", "confirm": "boolean",
                                        "stop_on_error": "boolean", "confirm_code": "boolean"}),
    "macro_delete": (["name", "session"], {"session": "string", "name": "string"}),
    "save_edit_detect": (["session"], {"session": "string"}),
    "save_edit_modify": (["field", "file", "session", "value"],
                         {"session": "string", "file": "string", "field": "string",
                          "value": "string", "confirm": "boolean",
                          "key": "anyOf:string,null", "iv": "anyOf:string,null"}),
    "watch_run": (["address", "session"], {"session": "string", "address": "string",
                                           "type": "string", "interval": "number",
                                           "iterations": "integer"}),
    "watch_report": (["session"], {"session": "string", "limit": "integer"}),
    "freeze_list": (["session"], {"session": "string"}),
    "watch_start": (["address", "session"], {"session": "string", "address": "string",
                                             "type": "string", "interval": "number"}),
    "watch_stop": (["session"], {"session": "string"}),
    "find_writers": (["address", "session"], {"session": "string", "address": "string",
                                              "size": "integer", "duration": "number",
                                              "max_hits": "integer"}),
    "freeze_start": (["session"], {"session": "string", "interval": "number"}),
    "freeze_stop": (["session"], {"session": "string"}),
    "backup_create": (["session"], {"session": "string", "symbol": "anyOf:string,null",
                                    "address": "anyOf:string,null", "type": "anyOf:string,null",
                                    "offsets": "anyOf:string,null", "mode": "anyOf:string,null",
                                    "size": "anyOf:integer,null", "label": "string"}),
    "backup_list": (["session"], {"session": "string"}),
    "backup_restore": (["backup_id", "session"], {"session": "string", "backup_id": "string"}),
    "toolchain_detect": ([], {}),
    "sessions": ([], {}),
    "session_info": (["session"], {"session": "string"}),
    "session_survey": (["session"], {"session": "string"}),
    "session_snapshots": (["session"], {"session": "string"}),
    "audit_tail": (["session"], {"session": "string", "limit": "integer"}),
    "results_read": (["path", "session"], {"session": "string", "path": "string",
                                           "offset": "integer", "limit": "integer"}),
    "value_convert": (["value"], {"value": "string", "as_type": "string"}),
    "session_snapshot": (["name", "session"], {"session": "string", "name": "string"}),
    "session_restore": (["name", "session"], {"session": "string", "name": "string"}),
    "detach": (["session"], {"session": "string"}),
    "layout_analyze": (["session"], {"session": "string", "what": "string",
                                     "module": "anyOf:string,null", "address": "anyOf:string,null"}),
    "heap_scan": (["session"], {"session": "string", "vtable_addr": "anyOf:string,null",
                                "max_results": "integer"}),
    "dissect": (["session"], {"session": "string", "address": "anyOf:string,null",
                              "addresses": "anyOf:string,null", "size": "integer"}),
    "pointer_scan": (["address", "session"], {"session": "string", "address": "string",
                                              "max_depth": "anyOf:integer,null",
                                              "max_paths": "anyOf:integer,null",
                                              "rescan": "boolean", "async_run": "boolean",
                                              "timeout": "anyOf:number,null"}),
    "job_status": (["job_id"], {"job_id": "string", "session": "anyOf:string,null"}),
    "job_list": ([], {"session": "anyOf:string,null"}),
    "job_cancel": (["job_id"], {"job_id": "string"}),
    "ue_introspect": (["session"], {"session": "string", "gobjects": "anyOf:string,null",
                                    "gnames": "anyOf:string,null",
                                    "gobjects_pattern": "anyOf:string,null",
                                    "gnames_pattern": "anyOf:string,null", "force": "boolean"}),
    "ue_actors": (["session"], {"session": "string", "limit": "integer",
                                "name_filter": "anyOf:string,null",
                                "class_filter": "anyOf:string,null", "list_results": "boolean"}),
    "ue_fname": (["session"], {"session": "string", "address": "anyOf:string,null",
                               "index": "anyOf:integer,null", "compare_index": "anyOf:integer,null"}),
    "disasm": (["address", "session"], {"session": "string", "address": "string",
                                        "size": "integer", "arch": "anyOf:string,null",
                                        "blocks": "boolean"}),
    # xrefs: MCP/CLI deliberately do NOT expose the service-level
    # ``fallback=false`` opt-out (radare2 missing -> silent pure-Python
    # fallback, distinguished via data.backend). Reviewed decision: keep the
    # golden schema frozen instead of re-locking a new parameter.
    "xrefs": (["address", "session"], {"session": "string", "address": "string",
                                       "direction": "string", "binary": "anyOf:string,null",
                                       "aligned": "boolean"}),
    "il2cpp_string": (["address", "session"], {"session": "string", "address": "string",
                                               "max_chars": "integer"}),
    "il2cpp_list": (["address", "session"], {"session": "string", "address": "string",
                                             "elem_type": "string", "limit": "integer"}),
    "il2cpp_dict": (["address", "session"], {"session": "string", "address": "string",
                                             "limit": "integer"}),
    "il2cpp_lookup": (["rva", "session"], {"session": "string", "rva": "string",
                                           "script_json": "anyOf:string,null", "tolerance": "integer",
                                           "force_index": "boolean", "force": "boolean"}),
    "il2cpp_dump": (["session"], {"session": "string", "out_dir": "anyOf:string,null",
                                  "timeout": "number", "force": "boolean"}),
    # il (Mono IL tool family)
    "il_analyze": (["session"], {"session": "string", "assembly": "anyOf:string,null",
                                 "type_filter": "anyOf:string,null", "member_filter": "anyOf:string,null"}),
    "il_dump": (["method", "session"], {"session": "string", "method": "string",
                                        "type": "anyOf:string,null", "assembly": "anyOf:string,null"}),
    "il_callers": (["session"], {"session": "string", "method": "anyOf:string,null",
                                 "type": "anyOf:string,null", "assembly": "anyOf:string,null",
                                 "max_results": "integer"}),
    "il_patch": (["method", "op", "session"], {"session": "string", "op": "string", "method": "string",
                                               "type": "anyOf:string,null", "value": "anyOf:number,null",
                                               "target": "anyOf:string,null", "assembly": "anyOf:string,null",
                                               "out_assembly": "anyOf:string,null", "confirm": "boolean"}),
    "il_verify": (["method", "session"], {"session": "string", "method": "string",
                                          "expect": "anyOf:object,null", "type": "anyOf:string,null",
                                          "assembly": "anyOf:string,null"}),
    "il_backup": (["session"], {"session": "string", "assembly": "anyOf:string,null", "label": "string"}),
    "il_restore": (["backup_id", "session"], {"session": "string", "backup_id": "string",
                                              "confirm": "boolean"}),
    # mono
    "mono_dump": (["session"], {"session": "string", "assembly": "anyOf:string,null",
                                "force": "boolean", "timeout": "number"}),
    "mono_symbol": (["query", "session"], {"session": "string", "query": "string",
                                           "assembly": "anyOf:string,null", "limit": "integer"}),
    "mono_string": (["address", "session"], {"session": "string", "address": "string",
                                             "max_chars": "integer", "arch": "anyOf:string,null"}),
    "mono_list": (["address", "session"], {"session": "string", "address": "string",
                                           "elem_type": "string", "limit": "integer"}),
    "mono_dict": (["address", "session"], {"session": "string", "address": "string",
                                           "limit": "integer"}),
    "mono_static": (["session"], {"session": "string", "arch": "anyOf:string,null",
                                  "max_results": "integer",
                                  "min_addr": "anyOf:integer,null", "max_addr": "anyOf:integer,null"}),
    "mono_heap_scan": (["session"], {"session": "string", "vtable_addr": "anyOf:string,null",
                                     "max_results": "integer"}),
    "file_snapshot": (["path", "session"], {"session": "string", "path": "string",
                                            "label": "string"}),
    "file_restore": (["backup_id", "session"], {"session": "string", "backup_id": "string",
                                                "confirm": "boolean"}),
    "safety_get_level": ([], {}),
    "safety_set_level": (["level"], {"level": "string"}),
}

# --- dimension 5: service method result key sets (FakeBackend golden state)
SERVICE_RESULT_KEYS = {
    "attach": {"anti_cheat", "arch", "engine", "engine_detail", "is_admin",
               "module_count", "pid", "process", "save_edit", "scan_candidates",
               "session_id", "symbols", "updated_at"},
    "analyze": {"deep", "engine", "next_steps", "process", "session_id", "toolchain"},
    # phase 1.1/1.2 registrations: page / candidates_total / region_summary are
    # unconditional appends; candidates_file / coverage are conditional (see
    # SERVICE_CONDITIONAL_KEYS below and the dedicated registration tests).
    # phase 3: results_file (persisted full candidate set, scan_results/<ts>.json)
    "scan": {"addresses_hex", "candidates_total", "comparator", "count", "page",
             "region_summary", "results_file", "sample_values",
             "scanned_bytes", "scanned_regions", "truncated", "type"},
    "scan_next": {"addresses_hex", "candidates_total", "comparator", "count", "page",
                  "region_summary", "sample_values",
                  "scanned_bytes", "scanned_regions", "truncated", "type"},
    "scan_aob": {"addresses_hex", "candidates_total", "count", "page", "pattern",
                 "region_summary", "results_file",
                 "scanned_bytes", "scanned_regions", "session_id", "truncated"},
    "scan_candidates": {"addresses_hex", "candidates_total", "limit", "offset",
                        "session_id", "values"},
    "batch_run": {"confirm", "confirm_code", "error_count", "executed",
                  "ok_count", "results", "results_file", "results_total",
                  "risk_breakdown", "session_id", "stopped_early", "total"},
}

# conditional keys: only present under specific runtime conditions; each is
# registered here and asserted by a dedicated test (never silently appended)
SERVICE_CONDITIONAL_KEYS = {
    "scan": {"candidates_file"},
    "scan_next": {"candidates_file", "cache_stale", "cache_stale_hint",
                  "stale_detail", "retained_stale"},
    "scan_aob": {"candidates_file", "coverage"},
}

# --- dimension 6: which profiles register each key write tool
WRITE_TOOL_PROFILES = {
    "modify": ["default", "dry-run", "limited"],
    "nl": ["default", "dry-run", "limited"],
    "batch_run": ["default", "dry-run"],
    "macro_run": ["default", "dry-run"],
    "name_set": ["default", "dry-run", "symbols", "limited"],
    "save_edit_modify": ["default", "dry-run"],
    "template_apply": ["default", "dry-run"],
    "il_patch": ["default", "dry-run"],
    "il_restore": ["default", "dry-run"],
    "file_restore": ["default", "dry-run"],
}


# ---------------------------------------------------------------------------
# dimension 1: default profile tool name set
# ---------------------------------------------------------------------------

class TestDefaultSurface:
    def test_default_tool_names_exact(self, mcp_config_path):
        names = _tool_names(mcp_server.build_server(mcp_config_path))
        assert names == DEFAULT_PROFILE_TOOLS

    def test_default_surface_cardinality(self, mcp_config_path):
        names = _tool_names(mcp_server.build_server(mcp_config_path))
        # 84 grouped tools + tools_catalog (always registered)
        assert len(names) == 85
        assert "tools_catalog" in names


# ---------------------------------------------------------------------------
# dimension 2: per-tool inputSchema snapshot
# ---------------------------------------------------------------------------

class TestSchemaSnapshot:
    def test_all_tool_schemas_exact(self, mcp_config_path):
        server = mcp_server.build_server(mcp_config_path)
        live = _live_schemas(server)
        assert set(live) == set(TOOL_SCHEMAS), (
            "tool set drifted; re-lock the schema snapshot deliberately")
        for name, expected in TOOL_SCHEMAS.items():
            assert live[name] == expected, f"schema drift in tool {name!r}: {live[name]!r} != {expected!r}"

    def test_schema_snapshot_covers_default_surface(self):
        assert set(TOOL_SCHEMAS) == DEFAULT_PROFILE_TOOLS

    def test_confirm_code_present_on_batch_and_macro(self):
        # the drift fix is part of the frozen surface
        assert "confirm_code" in TOOL_SCHEMAS["batch_run"][1]
        assert "confirm_code" in TOOL_SCHEMAS["macro_run"][1]


# ---------------------------------------------------------------------------
# dimension 3: four restricted profile tool sets
# ---------------------------------------------------------------------------

class TestProfileSurfaces:
    @pytest.mark.parametrize("profile,expected", [
        ("readonly", READONLY_PROFILE_TOOLS),
        ("dry-run", DRYRUN_PROFILE_TOOLS),
        ("symbols", SYMBOLS_PROFILE_TOOLS),
        ("limited", LIMITED_PROFILE_TOOLS),
    ])
    def test_profile_tool_names_exact(self, mcp_config_path, profile, expected):
        names = _tool_names(mcp_server.build_server(mcp_config_path, profile=profile))
        assert names == expected


# ---------------------------------------------------------------------------
# dimension 4: module-level gating constants
# ---------------------------------------------------------------------------

class TestGatingConstants:
    def test_write_tools_exact(self):
        assert mcp_server.WRITE_TOOLS == WRITE_TOOLS_SNAPSHOT

    def test_readonly_tools_exact(self):
        assert mcp_server.READONLY_TOOLS == READONLY_TOOLS_SNAPSHOT

    def test_symbols_extra_tools_exact(self):
        assert mcp_server.SYMBOLS_EXTRA_TOOLS == SYMBOLS_EXTRA_TOOLS_SNAPSHOT

    def test_limited_extra_tools_exact(self):
        assert mcp_server.LIMITED_EXTRA_TOOLS == LIMITED_EXTRA_TOOLS_SNAPSHOT

    def test_write_readonly_partition(self):
        # disjoint, and together they cover every grouped tool exactly once
        assert not (mcp_server.WRITE_TOOLS & mcp_server.READONLY_TOOLS)
        grouped = {t for tools in mcp_server.TOOL_GROUPS.values() for t in tools}
        assert mcp_server.WRITE_TOOLS | mcp_server.READONLY_TOOLS == grouped


# ---------------------------------------------------------------------------
# dimension 5: service method result key sets
# ---------------------------------------------------------------------------

class TestServiceResultKeys:
    @pytest.fixture
    def service(self, tmp_config, fake_backend_factory, monkeypatch):
        region = bytearray(struct.pack("<i", 1000) + b"\x00" * 0x1000)
        mod = ModuleInfo(name="fake.exe", base=0x140000000, size=0x1000, path="C:/games/fake.exe")
        fake = fake_backend_factory(regions={0x200000: region}, modules=[mod],
                                    name="fake.exe", pid=4242)
        import game_modifier.service as svc

        monkeypatch.setattr(svc, "get_backend", lambda: fake)
        monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
        monkeypatch.setattr(procmod, "list_processes", lambda: [])
        return ModifierService(tmp_config)

    def test_service_result_keys_exact(self, service, tmp_path):
        sid = service.attach(pid=4242)["session_id"]

        results = {
            "attach": service.attach(pid=4242),
            "analyze": service.analyze(session_id=sid),
            "scan": service.scan(session_id=sid, type="int32", value="1000"),
            "scan_next": service.scan_next(session_id=sid, value="1000"),
            "scan_aob": service.scan_aob(session_id=sid, pattern="E8 03"),
            "scan_candidates": service.scan_candidates(sid, offset=0, limit=10),
        }

        batch = tmp_path / "ops.yaml"
        batch.write_text(
            "operations:\n"
            '  - modify: {address: "0x200000", type: int32, value: 111}\n',
            encoding="utf-8")
        results["batch_run"] = service.batch_run(session_id=sid, path=str(batch), confirm=False)

        for method, data in results.items():
            assert set(data.keys()) == SERVICE_RESULT_KEYS[method], (
                f"{method}() result keys drifted: new keys must be registered "
                f"explicitly in SERVICE_RESULT_KEYS")

    def test_conditional_key_candidates_file_registered(self, tmp_path, monkeypatch):
        """candidates_file appears iff the sidecar exists (registered key)."""

        from game_modifier.config import Config
        from conftest import FakeBackend

        n = 30
        region = bytearray(b"".join(struct.pack("<i", 5) for _ in range(n)))
        fake = FakeBackend(regions={0x200000: region})
        config = Config({
            "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": False,
                       "require_writable_region": True},
            "scan": {"max_results": 20000, "chunk_size": 4096, "alignment": 1,
                     "candidates_sidecar_threshold": 10},
            "paths": {"home": str(tmp_path / ".game-modifier")},
        })
        import game_modifier.service as svc
        from game_modifier.memory import process as procmod

        monkeypatch.setattr(svc, "get_backend", lambda: fake)
        monkeypatch.setattr(procmod, "process_exists", lambda pid: True)
        monkeypatch.setattr(procmod, "list_processes", lambda: [])
        service = ModifierService(config)
        sid = service.attach(pid=4242)["session_id"]

        out = service.scan(session_id=sid, type="int32", value=5)
        allowed = SERVICE_RESULT_KEYS["scan"] | SERVICE_CONDITIONAL_KEYS["scan"]
        assert set(out.keys()) <= allowed
        assert "candidates_file" in out, "sidecar-backed scan must register candidates_file"

    def test_conditional_key_coverage_registered(self, service):
        """coverage appears on truncated AOB results (registered key)."""

        sid = service.attach(pid=4242)["session_id"]
        # the 0x1000-byte zero tail contains many "00 00" matches -> truncate
        out = service.scan_aob(session_id=sid, pattern="00 00", max_results=2)
        allowed = SERVICE_RESULT_KEYS["scan_aob"] | SERVICE_CONDITIONAL_KEYS["scan_aob"]
        assert set(out.keys()) <= allowed
        assert out["truncated"] is True
        assert "coverage" in out and set(out["coverage"]) == {"regions_scanned", "regions_total", "pct"}


# ---------------------------------------------------------------------------
# dimension 6: write-tool registration symmetry across profiles
# ---------------------------------------------------------------------------

class TestWriteToolSymmetry:
    @pytest.mark.parametrize("tool,profiles", sorted(WRITE_TOOL_PROFILES.items()))
    def test_param_schema_symmetric_across_profiles(self, mcp_config_path, tool, profiles):
        schemas = {}
        for prof in profiles:
            server = mcp_server.build_server(mcp_config_path, profile=prof)
            tools = {t.name: t for t in asyncio.run(server.list_tools())}
            assert tool in tools, f"{tool!r} missing from profile {prof!r}"
            schemas[prof] = _norm_schema(tools[tool].inputSchema)

        baseline_profile, baseline = profiles[0], schemas[profiles[0]]
        for prof in profiles[1:]:
            assert schemas[prof] == baseline, (
                f"{tool!r} schema drift between profiles {baseline_profile!r} "
                f"and {prof!r}: {schemas[prof]!r} != {baseline!r}")

    def test_symmetric_tools_match_golden_schema(self, mcp_config_path):
        # each registered version also equals the golden default-profile snapshot
        for tool, profiles in WRITE_TOOL_PROFILES.items():
            for prof in profiles:
                server = mcp_server.build_server(mcp_config_path, profile=prof)
                tools = {t.name: t for t in asyncio.run(server.list_tools())}
                live = _norm_schema(tools[tool].inputSchema)
                assert live == TOOL_SCHEMAS[tool], (
                    f"{tool!r} under profile {prof!r} drifted from the golden schema")

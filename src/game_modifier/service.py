"""High-level service orchestration.

``ModifierService`` is the single place where sessions, the memory backend,
safety, NLP, engines, toolchain, templates and batch come together. Both the
CLI and the MCP server are thin wrappers over this class, so behavior stays
consistent and token-efficient (structured dict returns, session reuse,
symbolic addresses).
"""

from __future__ import annotations

import bisect
import functools
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from .config import Config
from .errors import (
    ErrorCode,
    GameModifierError,
    InvalidArgsError,
    IlPatchFailedError,
    IlVerifyFailedError,
    LayoutUnsupportedError,
    NeedsScanError,
    PathNotAllowedError,
    ProcessNotFoundError,
    ProfileRestrictedError,
    SymbolNotFoundError,
    ToolNotFoundError,
    UnsupportedOSError,
)
from .memory import aob, pointers, scanner, xrefs_fallback
from .memory import types as vt
from .memory.base import MemoryBackend, get_backend
from .memory import process as procmod
from .nlp import parse as nlp_parse
from .nlp.intents import MAX, MIN
from . import engines
from .engines import il_tool as il_tool_bridge
from .engines import mono_layout
from .engines import unity_lookup
from . import toolchain
from . import templates as tpl
from . import batch as batchmod
from .analysis import (
    basic_blocks,
    disassemble,
    dissect_structure,
    find_pointer_paths,
    find_rtti_classes,
    find_vtables,
    infer_class_layout,
    rescan_paths,
    scan_heap_objects,
)
from .analysis.alignment import build_intervals, in_intervals
from .jobs import JOBS
from .safety import (
    BackupManager,
    default_save_roots,
    detect_anti_cheat,
    validate_address,
    validate_file_path,
    validate_write_span,
)
from .session import ScanState, Session, SessionStore, Symbol

# pointer-scan persistence: paths above this count stay in the sidecar and
# the reply carries only a sample; below it the full list is kept inline.
_POINTER_PATHS_INLINE_LIMIT = 500
_POINTER_PATHS_SAMPLE = 20


def _default_mode(base_expr: str) -> str:
    """Pick the pointer mode that matches the caller's intent.

    A bare absolute address (``0x...`` / decimal) with offsets almost always
    means "struct field offset" -> relative. A ``module.dll+0x...`` expression
    means a pointer chain -> pointer_chain (dereference at each step).
    """
    expr = base_expr.strip()
    head = expr.split("+", 1)[0].strip() if "+" in expr else expr
    if head.lower().startswith("0x") or head.isdigit() or (head.startswith("-") and head[1:].isdigit()):
        return "relative"
    return "pointer_chain"


def _region_fingerprint(regions) -> str:
    """Stable hash of the readable region layout (base/size list).

    Used to detect a stale scan candidate cache: if the process memory layout
    changed between scans, previously collected candidates may be meaningless.
    """

    h = hashlib.sha1()
    for r in regions:
        h.update(f"{r.base:x}:{r.size:x};".encode())
    return h.hexdigest()[:16]


def _lenient_region_fingerprint(regions) -> str:
    """Lenient variant of :func:`_region_fingerprint` (parallel, additive).

    Large regions (>= 64 KB) are hashed individually by (base, size); small
    regions only contribute a (count, total_bytes) aggregate - allocator
    churn below 64 KB no longer flips the fingerprint. The ``lenient1:``
    namespace prefix guarantees a lenient hash never collides with a strict
    one. ``_region_fingerprint`` itself stays frozen (regression anchor).
    """

    h = hashlib.sha1()
    h.update(b"lenient1:")
    small_count = 0
    small_bytes = 0
    for r in regions:
        if r.size >= _SMALL_REGION_BYTES:
            h.update(f"{r.base:x}:{r.size:x};".encode())
        else:
            small_count += 1
            small_bytes += r.size
    h.update(f"s:{small_count:x}:{small_bytes:x}".encode())
    return h.hexdigest()[:16]


def _fingerprint_for(regions, mode: str) -> str:
    """Region-layout fingerprint under the configured mode."""

    return _lenient_region_fingerprint(regions) if mode == "lenient" else _region_fingerprint(regions)


def _stale_detail(old_layout, regions) -> dict:
    """Confidence signal describing HOW the region layout changed.

    ``old_layout`` is the [base, size] list recorded with the previous scan;
    ``regions`` the live region objects. Large-region changes (>= 64 KB) are
    the strongest staleness evidence; small-region churn is usually harmless.
    """

    old = {(int(b), int(s)) for b, s in (old_layout or [])}
    new = {(int(r.base), int(r.size)) for r in (regions or [])}
    added = new - old
    removed = old - new
    changed = added | removed
    return {
        "regions_added": len(added),
        "regions_removed": len(removed),
        "bytes_delta": sum(s for _, s in added) - sum(s for _, s in removed),
        "large_region_changed": any(s >= _SMALL_REGION_BYTES for _, s in changed),
    }


# Windows MEM_* region type constants used by the region summary bucketing
_MEM_IMAGE = 0x1000000
_MEM_MAPPED = 0x40000
_MEM_PRIVATE = 0x20000
# summary bucket budgets (token control): at most 8 buckets, 5 sample
# addresses per bucket, and the whole serialised summary stays under 2 KB.
_SUMMARY_MAX_BUCKETS = 8
_SUMMARY_SAMPLES_PER_BUCKET = 5
_SUMMARY_MAX_BYTES = 2048
_HEAP_MIN_BYTES = 256 * 1024
_SMALL_REGION_BYTES = 64 * 1024


def _aggregate_addresses(addresses, regions, modules) -> dict:
    """Bucket candidate addresses by memory-layout provenance.

    Two-pointer merge over the (ascending) candidate list and the (sorted)
    region table - O(N + R): each candidate lands in at most one bucket:

    * ``image``  - inside a loaded module's span (per-module buckets)
    * ``heap``   - PRIVATE region >= 256 KB (aggregated into one bucket)
    * ``mapped`` - MEM_MAPPED regions (aggregated into one bucket)
    * ``small``  - regions < 64 KB (aggregated into one bucket)
    * ``other``  - everything else (only when budget allows)

    Output is budget-capped: <= 8 buckets, <= 5 hex samples per bucket, and
    the serialised dict stays under ~2 KB (buckets are dropped, never
    truncated silently without the ``dropped`` flag).
    """

    regions = sorted(regions or [], key=lambda r: r.base)
    spans = sorted(((m["base"], m["base"] + m.get("size", 0), name)
                    for name, m in (modules or {}).items()), key=lambda t: t[0])
    mod_bases = [s[0] for s in spans]

    buckets: dict[str, dict] = {}

    def _bucket(key: str, label: str, region_base: int) -> dict:
        b = buckets.get(key)
        if b is None:
            b = {"kind": label, "count": 0, "samples": [], "_base": region_base}
            buckets[key] = b
        return b

    def _add(b: dict, addr: int) -> None:
        b["count"] += 1
        if len(b["samples"]) < _SUMMARY_SAMPLES_PER_BUCKET:
            b["samples"].append(hex(addr))

    unmatched = 0
    ri = 0
    nr = len(regions)
    for addr in addresses:
        # advance the region pointer to the first region that can contain addr
        while ri < nr and regions[ri].end <= addr:
            ri += 1
        region = regions[ri] if ri < nr and regions[ri].base <= addr < regions[ri].end else None
        if region is None:
            unmatched += 1
            continue
        # module span lookup (binary search over module bases)
        mi = bisect.bisect_right(mod_bases, addr) - 1
        if mi >= 0 and addr < spans[mi][1]:
            _add(_bucket(f"image:{spans[mi][2]}", "image", spans[mi][0]), addr)
            buckets[f"image:{spans[mi][2]}"]["module"] = spans[mi][2]
            continue
        if region.type == _MEM_PRIVATE and region.size >= _HEAP_MIN_BYTES:
            _add(_bucket("heap", "heap", region.base), addr)
        elif region.type == _MEM_MAPPED:
            _add(_bucket("mapped", "mapped", region.base), addr)
        elif region.size < _SMALL_REGION_BYTES:
            _add(_bucket("small", "small", region.base), addr)
        else:
            _add(_bucket("other", "other", region.base), addr)

    ordered = sorted(buckets.values(), key=lambda b: b["_base"])
    out_buckets = []
    for b in ordered:
        entry = {"kind": b["kind"], "count": b["count"], "samples": b["samples"]}
        if "module" in b:
            entry["module"] = b["module"]
        out_buckets.append(entry)
    dropped = False
    if len(out_buckets) > _SUMMARY_MAX_BUCKETS:
        out_buckets = out_buckets[:_SUMMARY_MAX_BUCKETS]
        dropped = True

    summary = {
        "candidates": len(addresses),
        "regions": len(regions),
        "buckets": out_buckets,
    }
    if unmatched:
        summary["unmatched"] = unmatched
    if dropped:
        summary["dropped"] = True
    # hard serialisation budget: shed samples, then whole buckets
    while len(json.dumps(summary, separators=(",", ":")).encode("utf-8")) > _SUMMARY_MAX_BYTES:
        trimmed = False
        for b in summary["buckets"]:
            if b["samples"]:
                b["samples"] = b["samples"][: len(b["samples"]) // 2]
                trimmed = True
        if not trimmed:
            if len(summary["buckets"]) <= 1:
                summary["buckets"] = []
                break
            summary["buckets"] = summary["buckets"][: len(summary["buckets"]) - 1]
            summary["dropped"] = True
    return summary


# macro parameter placeholders: ${name} tokens inside operation strings.
# Semantics mirror templates.loader._sub_value: a string that is exactly one
# placeholder receives the raw (non-string preserved) parameter value;
# embedded occurrences are spliced in via str().
_MACRO_PARAM_RE = re.compile(r"\$\{(\w+)\}")
_MACRO_FULL_RE = re.compile(r"^\s*\$\{(\w+)\}\s*$")
_MACRO_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def _session_op(fn):
    """Serialize a session-mutating service op (review P0-F3).

    Acquires the per-session lock (in-process RLock + cross-process lockfile)
    for the whole load -> mutate -> save sequence, so two writers can no
    longer interleave and silently drop each other's changes. Composite flows
    (batch_run -> modify, macro_run -> nl) re-enter the same session's RLock
    safely; the file lock is only taken at the outermost nesting level.
    Read-only ops are deliberately NOT wrapped (they never save the session).
    """

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        sid = kwargs.get("session_id")
        if sid is None and args and isinstance(args[0], str):
            sid = args[0]
        if not sid:
            return fn(self, *args, **kwargs)
        with self.store.locked(str(sid)):
            return fn(self, *args, **kwargs)

    return wrapper


class ModifierService:
    def __init__(self, config: Config) -> None:
        self.config = config
        config.ensure_dirs()
        self.store = SessionStore(config.sessions_dir)
        # runtime safety level (process-scoped; see the "runtime safety level"
        # block below - never persisted to disk)
        self._runtime_safety_level = "normal"

    # ================================================= runtime safety level
    # Independent safety block: process-scoped safety gear that forces every
    # confirmed write (modify / nl / batch) into a refusal while active.
    # Only the public entry points carry a front gate (_safety_write_gate);
    # execution internals (_modify_on / _batch_execute) stay untouched.
    SAFETY_LEVELS = ("normal", "dry_run_only")

    def safety_get_level(self) -> dict:
        """Return the current runtime safety level.

        ``{"level": "normal"|"dry_run_only", "source": "runtime"|"default"}``
        """

        level = getattr(self, "_runtime_safety_level", "normal")
        return {
            "level": level,
            "source": "runtime" if level != "normal" else "default",
        }

    def safety_set_level(self, *, level: str) -> dict:
        """Switch the runtime safety level (process-scoped, not persisted).

        ``dry_run_only`` forces every modify/nl/batch write into dry-run:
        ``confirm=True`` is refused with E_PROFILE_RESTRICTED, ``confirm=False``
        previews still work. ``normal`` restores the standard confirm gating.
        """

        if level not in self.SAFETY_LEVELS:
            raise InvalidArgsError(
                f"unknown safety level: {level!r}",
                details={"supported": list(self.SAFETY_LEVELS)},
                hint="Use safety_set_level(level='normal') or level='dry_run_only'.",
            )
        previous = getattr(self, "_runtime_safety_level", "normal")
        self._runtime_safety_level = level
        return {"level": level, "previous": previous, "persisted": False}

    def _safety_write_gate(self, confirm: bool, command: str) -> None:
        """Front gate for write entry points; raises when a confirmed write
        runs under the ``dry_run_only`` runtime level. Previews pass through."""

        if getattr(self, "_runtime_safety_level", "normal") == "dry_run_only" and confirm:
            raise ProfileRestrictedError(
                "runtime safety level 'dry_run_only' blocks confirmed writes",
                details={"command": command, "level": "dry_run_only"},
                hint=("Call with confirm=false for a dry-run preview, or restore "
                      "writing with safety_set_level(level='normal')."),
            )

    # ---------------------------------------------------------- path policy
    def _allowed_file_roots(self, session: Optional[Session] = None) -> list:
        """Allow-list roots for file-touching tools (smart default).

        Always includes the sessions dir and the common save locations; when
        a session is attached its game directory (exe parent / detected
        game_dir) is added; ``[safety].allowed_paths`` appends user roots.
        The OS system directory is hard-denied inside validate_file_path.
        """

        roots: list[Path] = [self.store.dir]
        if session is not None:
            exe = (session.exe_path or "").strip()
            if exe:
                roots.append(Path(exe).parent)
            game_dir = (session.engine or {}).get("game_dir")
            if game_dir:
                roots.append(Path(str(game_dir)))
        roots.extend(default_save_roots())
        for extra in self.config.allowed_paths:
            roots.append(Path(extra))
        return roots

    def _check_file_path(self, path, *, session: Optional[Session] = None,
                         purpose: str = "file operation") -> Path:
        """Policy-check a user-supplied file path (E_PATH_NOT_ALLOWED on miss)."""

        return validate_file_path(
            path, allowed_roots=self._allowed_file_roots(session), purpose=purpose)

    # ================================================================= attach
    def attach(
        self,
        *,
        pid: Optional[int] = None,
        name: Optional[str] = None,
        exe: Optional[str] = None,
        title: Optional[str] = None,
        allow_anti_cheat: bool = False,
    ) -> dict:
        resolved_pid = self._resolve_pid(pid=pid, name=name, exe=exe, title=title)
        backend = get_backend()
        info = backend.open(resolved_pid)
        try:
            module_names = [m.name for m in info.modules]
            proc_names = [p.name for p in procmod.list_processes()]
            ac = detect_anti_cheat(module_names, proc_names)

            if ac["detected"] and self.config.block_anti_cheat and not allow_anti_cheat:
                raise GameModifierError(
                    f"anti-cheat detected: {', '.join(ac['systems'])}. Refusing to attach.",
                    code=ErrorCode.ANTI_CHEAT,
                    details=ac,
                    hint="This tool is for single-player/offline games only. Do not use it online.",
                )

            engine = engines.detect(target=info.exe_path, modules=info.modules)

            # 存档型游戏检测与分流
            save_edit_info = {}
            if engine.get("save_edit"):
                save_edit_info = {
                    "required": True,
                    "engine": engine["engine"],
                    "note": "此游戏基于存档文件，内存修改可能无效。建议使用 save-edit 命令。",
                }

            sid = self.store.new_id(info.name)
            session = Session(
                id=sid,
                pid=info.pid,
                process_name=info.name,
                exe_path=info.exe_path,
                arch=info.arch,
                platform="windows",
                engine=engine,
                anti_cheat=ac,
                modules={m.name: m.to_dict() for m in info.modules},
                save_edit_info=save_edit_info,
            )
            self.store.save(session)
        finally:
            backend.close()

        data = session.summary()
        data["engine_detail"] = session.engine
        data["anti_cheat"] = session.anti_cheat
        data["module_count"] = len(session.modules)
        data["is_admin"] = procmod.is_admin()
        data["save_edit"] = session.save_edit_info
        return data

    def _resolve_pid(self, *, pid=None, name=None, exe=None, title=None) -> int:
        if pid is not None:
            if not procmod.process_exists(int(pid)):
                raise ProcessNotFoundError(
                    f"no process with pid {pid}",
                    details={"pid": pid},
                    hint="该 pid 不存在或已退出。用 sessions 查看现有会话，或重新 attach（--process/--exe/--title）。",
                )
            return int(pid)
        if name:
            matches = procmod.find_by_name(name)
            if not matches:
                raise ProcessNotFoundError(
                    f"no process named {name!r}",
                    details={"name": name},
                    hint="未找到同名进程。多进程/通用 exe 名游戏请改用 attach --title '<窗口标题>' 匹配，或用 sessions 查看。",
                )
            if len(matches) > 1:
                raise GameModifierError(
                    f"multiple processes named {name!r}; specify --pid",
                    code=ErrorCode.INVALID_ARGS,
                    details={"candidates": [m.to_dict() for m in matches]},
                )
            return matches[0].pid
        if exe:
            matches = procmod.find_by_exe(exe)
            if not matches:
                raise ProcessNotFoundError(
                    f"no running process for exe {exe!r}",
                    details={"exe": exe},
                    hint="未找到该 exe 的运行进程。确认游戏已启动；多进程游戏可改用 attach --title '<窗口标题>'。",
                )
            return matches[0].pid
        if title:
            matches = procmod.find_by_window_title(title)
            if not matches:
                raise ProcessNotFoundError(
                    f"no window with title matching {title!r}",
                    details={"title_pattern": title},
                    hint="无匹配窗口标题的进程。检查标题正则/通配是否正确，确认游戏窗口已打开；用 sessions 查看已有会话。",
                )
            if len(matches) > 1:
                raise GameModifierError(
                    f"multiple processes match title {title!r}; specify --pid",
                    code=ErrorCode.INVALID_ARGS,
                    details={"candidates": [m.to_dict() for m in matches]},
                )
            return matches[0].pid
        raise GameModifierError(
            "attach requires --pid, --process, --exe or --title", code=ErrorCode.INVALID_ARGS
        )

    # ============================================================ backend open
    def _open(self, session: Session) -> MemoryBackend:
        if not procmod.process_exists(session.pid):
            raise GameModifierError(
                f"process {session.pid} is no longer running",
                code=ErrorCode.PROCESS_EXITED,
                details={"pid": session.pid},
                hint=(
                    "目标进程已退出。重新 attach 后重跑定位链: attach → （scan/name set 重建符号）。"
                    "若使用符号表，模块基址变化会自动适应。"
                ),
            )
        backend = get_backend()
        info = backend.open(session.pid)
        # refresh module bases (stable within a pid, but keep session current)
        session.modules = {m.name: m.to_dict() for m in info.modules}
        return backend

    def _load(self, session_id: str) -> Session:
        return self.store.load(session_id)

    # ================================================================ analyze
    @_session_op
    def analyze(self, *, session_id: Optional[str] = None, target: Optional[str] = None, deep: bool = False) -> dict:
        result: dict[str, Any] = {"deep": deep}
        modules = None
        exe_path = target

        if session_id:
            session = self._load(session_id)
            backend = self._open(session)
            try:
                modules = backend.modules()
                exe_path = session.exe_path or target
                result["session_id"] = session_id
                result["process"] = session.process_name
            finally:
                backend.close()

        engine = engines.detect(target=exe_path, modules=modules)
        result["engine"] = engine

        tools = toolchain.detect_all(self.config)
        result["toolchain"] = {"available": tools["available"]}

        # optional static analysis of the main binary via radare2
        bin_path = exe_path or engine.get("artifacts", {}).get("game_assembly")
        if deep and bin_path:
            r2_path = self.config.tool_path("radare2") or (tools["tools"].get("radare2", {}) or {}).get("path")
            try:
                result["static"] = toolchain.radare2.analyze(bin_path, r2_path=r2_path, deep=True)
            except GameModifierError as exc:
                result["static_error"] = exc.to_dict()

        # engine-specific artifact locations to guide next steps
        eng = engine.get("engine")
        if eng == engines.UNITY_IL2CPP:
            # route the dumper recommendation by the metadata version so an
            # agent on a Unity 6 title is not pointed at the stale official
            # Il2CppDumper (metadata v31 cap) again.
            meta_path = engine.get("artifacts", {}).get("global_metadata")
            rec = toolchain.recommended_unity_dumper(meta_path, self.config)
            dumper_hint = (
                f"Use {rec['dumper']} (metadata v{rec['metadata_version']}) - "
                + (f"found at {rec['path']}." if rec["found"] else f"not installed. {rec['hint']}")
            )
            result["dumper_recommendation"] = rec
            result["next_steps"] = [
                f"Run the IL2CPP dumper on GameAssembly.dll + global-metadata.dat. {dumper_hint}",
                "Map fields to symbols with `name set`, then modify by symbol.",
            ]
        elif eng == engines.UNREAL:
            result["next_steps"] = ["Use a UE dumper for GObjects/GNames, then resolve addresses with `resolve`."]
        else:
            result["next_steps"] = ["Use `scan`/`scan-next` to locate the value, then `name set` to save it."]

        # stale il2cpp dump awareness (advisory only, never blocks): when the
        # session carries an associated dump + binary fingerprint, re-check the
        # game binary so an agent sees a game update before trusting old RVAs.
        if session_id:
            stale = self._dump_stale_info(session)
            if stale:
                result["dump_stale"] = stale
        return result

    # ================================================================= scan
    @_session_op
    def scan(
        self,
        *,
        session_id: str,
        type: str,
        value=None,
        comparator: str = "exact",
        value2=None,
        progress_cb: Optional[Callable[[dict], None]] = None,
        offset: int = 0,
        limit: Optional[int] = None,
        min_addr: Optional[int] = None,
        max_addr: Optional[int] = None,
        region_types: Optional[list[int]] = None,
        encoding: str = "utf8",
    ) -> dict:
        session = self._load(session_id)
        backend = self._open(session)
        workers = self.config.scan_workers
        # encoding visibility (review §2.3): utf16le maps onto the existing
        # string_utf16 scanner type; only string scans accept it.
        enc = str(encoding or "utf8").strip().lower()
        if enc == "utf16le":
            dt = vt.resolve_type(type)
            if dt.kind != "string":
                raise InvalidArgsError(
                    "encoding=utf16le is only valid for string scans",
                    details={"type": str(type), "encoding": enc},
                    hint="utf16le 仅适用于字符串扫描；数值类型请去掉 encoding 参数。",
                )
            type = "string_utf16"
        elif enc != "utf8":
            raise InvalidArgsError(
                f"unsupported encoding: {encoding!r}",
                details={"supported": ["utf8", "utf16le"]},
                hint="encoding 仅支持 utf8（默认）与 utf16le。",
            )
        fp_mode = self.config.scan_fingerprint_mode
        region_layout: list = []
        try:
            region_layout = list(backend.readable_regions())
            fingerprint = _fingerprint_for(region_layout, fp_mode)
            res = scanner.first_scan(
                backend,
                type,
                value,
                comparator=comparator,
                value2=value2,
                max_results=self.config.scan_max_results,
                chunk_size=self.config.scan_chunk_size,
                alignment=self.config.scan_alignment,
                max_region_bytes=self.config.scan_max_region_bytes,
                workers=workers,
                # parallel scan needs an independent backend per worker thread;
                # each worker opens (and closes) its own handle via _open
                backend_factory=(lambda: self._open(session)) if workers > 1 else None,
                progress_cb=progress_cb,
                min_addr=min_addr,
                max_addr=max_addr,
                region_types=region_types,
            )
        finally:
            backend.close()
        self._store_scan_state(session, res, fingerprint, mode=fp_mode, region_layout=region_layout)
        self.store.save(session)
        out = res.to_dict(offset=offset, limit=limit)
        self._scan_output_meta(session, out, region_layout)
        out["results_file"] = self._persist_scan_result(session_id, res)
        return out

    def _persist_scan_result(self, session_id: str, res) -> Optional[str]:
        """Persist the FULL candidate set of a finished scan (best-effort).

        Writes ``sessions/<id>/scan_results/<ts>.json`` via the atomic
        temp+rename path; the reply only gains a ``results_file`` pointer, so
        the paged inline window (``page``/``candidates_total``/
        ``candidates_file``) keeps working untouched. Persistence failure
        never breaks the scan itself (returns ``None`` instead).
        """

        payload = {
            "session_id": session_id,
            "type": getattr(res, "type", None),
            "comparator": getattr(res, "comparator", None),
            "count": getattr(res, "count", 0),
            "truncated": bool(getattr(res, "truncated", False)),
            "addresses_hex": [hex(a) for a in getattr(res, "addresses", [])],
            "scanned_regions": getattr(res, "scanned_regions", 0),
            "scanned_bytes": getattr(res, "scanned_bytes", 0),
        }
        values = getattr(res, "values", None)
        payload["values"] = ({hex(a): v for a, v in values.items()} if values else None)
        try:
            return self.store.save_scan_result(session_id, payload)
        except Exception:
            return None

    def _store_scan_state(self, session: Session, res, fingerprint: str,
                          mode: str = "strict", region_layout: Optional[list] = None) -> None:
        """Persist a ScanState, externalising oversized candidate sets.

        Candidate lists above ``[scan] candidates_sidecar_threshold`` move to a
        compact two-segment sidecar (``sessions/<id>/scan_candidates.bin``,
        addresses + values); the session JSON then only keeps the summary and
        a ``candidates_file`` reference (restored transparently by
        :meth:`SessionStore.load`).

        Sidecar semantics: a sidecar is REPLACED whenever a new scan exceeds
        the threshold; a small follow-up scan never deletes an existing
        sidecar eagerly - :meth:`_scan_output_meta` reports ``candidates_file``
        only while the current ScanState actually externalises its addresses,
        so ``scan_candidates`` can always serve windowed reads from the latest
        candidate set's authoritative storage.
        """

        state = ScanState(
            type=res.type,
            comparator=res.comparator,
            count=res.count,
            truncated=res.truncated,
            addresses=list(res.addresses),
            values=res.values,
            region_fingerprint=fingerprint,
            region_layout=[[int(r.base), int(r.size)] for r in (region_layout or [])],
            fingerprint_mode=str(mode or "strict"),
        )
        sidecar = self.store.candidates_path(session.id)
        threshold = self.config.scan_candidates_sidecar_threshold
        if threshold > 0 and len(state.addresses) > threshold:
            state.write_candidates_file(sidecar)
            state.candidates_file = sidecar.name
        session.scan = state

    def _scan_output_meta(self, session: Session, out: dict, region_layout: list) -> None:
        """Append candidates_total / candidates_file / region_summary (pure appends)."""

        state = session.scan
        out["candidates_total"] = state.count
        # report the sidecar reference only while the CURRENT candidate set is
        # externalised (a small follow-up scan keeps its addresses inline)
        if state.candidates_file:
            out["candidates_file"] = state.candidates_file
        out["region_summary"] = _aggregate_addresses(state.addresses, region_layout, session.modules)

    @_session_op
    def scan_next(self, *, session_id: str, comparator: str = "exact", value=None, value2=None,
                  offset: int = 0, limit: Optional[int] = None, retain_stale: bool = False) -> dict:
        session = self._load(session_id)
        if not session.scan.addresses:
            raise NeedsScanError(
                "no previous scan for this session",
                details={"session_id": session_id},
                hint="Run `scan` first to establish a candidate set.",
            )
        backend = self._open(session)
        cache_stale = False
        old_layout = list(session.scan.region_layout or [])
        fp_mode = self.config.scan_fingerprint_mode
        region_layout: list = []
        try:
            region_layout = list(backend.readable_regions())
            fingerprint = _fingerprint_for(region_layout, fp_mode)
            # cache validation: a stored fingerprint mismatching the current
            # region layout means the candidates may be stale. Not fatal - the
            # refinement still runs, but the result is flagged so the agent
            # can restart the scan if the numbers look wrong. A fingerprint
            # mode switch (strict <-> lenient) is conservatively stale too.
            stored_mode = session.scan.fingerprint_mode or "strict"
            if session.scan.region_fingerprint and (
                    stored_mode != fp_mode
                    or session.scan.region_fingerprint != fingerprint):
                cache_stale = True
            res = scanner.next_scan(
                backend,
                session.scan.type,
                session.scan.addresses,
                comparator=comparator,
                value=value,
                value2=value2,
                previous=session.scan.values,
                use_batch_read=True,
                batch_gap=self.config.scan_batch_gap,
            )
        finally:
            backend.close()
        self._store_scan_state(session, res, fingerprint, mode=fp_mode, region_layout=region_layout)
        self.store.save(session)
        out = res.to_dict(offset=offset, limit=limit)
        self._scan_output_meta(session, out, region_layout)
        if cache_stale:
            out["cache_stale"] = True
            out["cache_stale_hint"] = (
                "region layout changed since the previous scan (E_SCAN_CACHE_STALE); "
                "candidates may be stale - consider a fresh `scan` if results look wrong"
            )
            if old_layout:
                out["stale_detail"] = _stale_detail(old_layout, region_layout)
            if retain_stale:
                # explicit opt-in: keep refining the old candidate set despite
                # the layout change (risk-flagged, never silent).
                out["retained_stale"] = True
                out["cache_stale_hint"] = (
                    "region layout changed since the previous scan (E_SCAN_CACHE_STALE); "
                    "retain_stale=true kept the old candidate set - results carry a "
                    "staleness risk, re-run `scan` if the numbers look wrong"
                )
        return out

    @_session_op
    def scan_aob(self, session_id: str, *, pattern: str, max_results: int = 1000,
                 offset: int = 0, limit: Optional[int] = None,
                 min_addr: Optional[int] = None, max_addr: Optional[int] = None,
                 stop_on_limit: bool = False) -> dict:
        """AOB pattern scan (hex bytes with ?? wildcards) across readable memory.

        The candidate set is stored via :meth:`_store_scan_state`
        (type='bytes', comparator='aob') so a later `scan-next` can refine it
        with changed/unchanged and oversized candidate sets are externalised
        to the sidecar like any other scan.
        """

        session = self._load(session_id)
        backend = self._open(session)
        workers = self.config.scan_workers
        fp_mode = self.config.scan_fingerprint_mode
        region_layout: list = []
        try:
            region_layout = list(backend.readable_regions())
            fingerprint = _fingerprint_for(region_layout, fp_mode)
            res = aob.aob_scan(
                backend,
                pattern,
                max_results=max_results,
                chunk_size=self.config.scan_aob_chunk_size,
                min_addr=min_addr,
                max_addr=max_addr,
                stop_on_limit=stop_on_limit,
                workers=workers,
                backend_factory=(lambda: self._open(session)) if workers > 1 else None,
            )
        finally:
            backend.close()
        addresses = res["addresses"]
        scan_res = scanner.ScanResult(
            type="bytes",
            comparator="aob",
            count=res["count"],
            truncated=res["truncated"],
            addresses=addresses,
            values={},
            scanned_regions=res.get("scanned_regions", 0),
            scanned_bytes=res.get("scanned_bytes", 0),
        )
        self._store_scan_state(session, scan_res, fingerprint, mode=fp_mode, region_layout=region_layout)
        self.store.save(session)
        out = {k: v for k, v in res.items() if k not in ("addresses", "addresses_hex")}
        out["session_id"] = session_id
        # page the inline address sample like the other scan entry points
        # (defaults reproduce the historical first-20 sample)
        page_offset = max(0, offset)
        window_len = max(0, limit) if limit is not None else 20
        window = addresses[page_offset:page_offset + window_len]
        out["addresses_hex"] = [hex(a) for a in window]
        out["page"] = {"offset": page_offset, "limit": limit}
        self._scan_output_meta(session, out, region_layout)
        if res.get("coverage"):
            out["coverage"] = res["coverage"]
        out["results_file"] = self._persist_scan_result(session_id, scan_res)
        return out

    def scan_candidates(self, session_id: str, *, offset: int = 0, limit: int = 100,
                        min_addr: Optional[int] = None, max_addr: Optional[int] = None) -> dict:
        """Page the current scan candidate set (read-only).

        Serves windows straight from the binary sidecar with an O(limit)
        seek+read when the candidate set is externalised (no full
        materialisation); inline sets are sliced with ``bisect`` range
        filtering. ``values`` is ``null`` when the scan recorded no values
        (e.g. AOB scans or legacy address-only sidecars).
        """

        # bypass load: keep the sidecar reference instead of materialising it
        session = self.store.load(session_id, restore_candidates=False)
        if not session.scan.addresses and not session.scan.candidates_file:
            raise NeedsScanError(
                "no scan candidates for this session",
                details={"session_id": session_id},
                hint="Run `scan` or `scan-aob` first.",
            )
        offset = max(0, int(offset))
        limit = max(0, int(limit))

        if session.scan.candidates_file:
            path = self.store.candidates_path(session_id)
            if not path.exists():
                raise NeedsScanError(
                    "candidate sidecar is missing",
                    details={"session_id": session_id, "candidates_file": session.scan.candidates_file},
                    hint="Run a fresh `scan` to rebuild the candidate set.",
                )
            total, addrs, values = session.scan.read_candidates_window(
                path, offset=offset, limit=limit, min_addr=min_addr, max_addr=max_addr)
        else:
            addrs_all = session.scan.addresses
            total = len(addrs_all)
            lo = bisect.bisect_left(addrs_all, min_addr) if min_addr is not None else 0
            hi = bisect.bisect_right(addrs_all, max_addr) if max_addr is not None else total
            lo, hi = max(0, lo), max(lo, min(hi, total))
            start = lo + offset
            addrs = addrs_all[start:min(hi, start + limit)]
            stored = session.scan.values
            values = {a: stored[a] for a in addrs if a in stored} if stored else None

        return {
            "session_id": session_id,
            "candidates_total": total,
            "offset": offset,
            "limit": limit,
            "addresses_hex": [hex(a) for a in addrs],
            "values": ({hex(a): v for a, v in values.items()} if values is not None else None),
        }

    # ================================================================ resolve
    def resolve(self, *, session_id: str, base_expr: str, offsets=None, mode: str = "pointer_chain",
                deref_last: bool = True) -> dict:
        session = self._load(session_id)
        backend = self._open(session)
        try:
            return pointers.resolve_pointer(backend, base_expr, offsets, mode=mode, deref_last=deref_last)
        finally:
            backend.close()

    def _resolve_target(self, backend: MemoryBackend, session: Session, *, symbol=None, address=None, offsets=None, type=None, mode=None):
        if symbol:
            sym = session.get_symbol(symbol)
            if not sym:
                raise SymbolNotFoundError(
                    f"symbol not defined: {symbol!r}",
                    details={"symbol": symbol, "known": sorted(session.symbols.keys())},
                    hint="Define it with `name set`, or pass an explicit --address.",
                )
            base_expr = sym.base_expr
            use_offsets = offsets if offsets is not None else sym.offsets
            use_type = type or sym.type
            use_mode = mode or sym.mode or _default_mode(base_expr)
        elif address is not None:
            if isinstance(address, str) and pointers.is_address_expr(address):
                # arithmetic like "0x1b0c00276c5-0x8": evaluate before any
                # module/symbol path; module syntax ("game.exe+0x1A4") never
                # matches is_address_expr.
                evaluated = pointers.eval_address_expr(address)
                if evaluated < 0:
                    raise InvalidArgsError(
                        "address expression evaluates to negative",
                        details={"address": address, "evaluated": evaluated},
                    )
                base_expr = hex(evaluated)
            else:
                base_expr = address if isinstance(address, str) else hex(int(address))
            use_offsets = offsets
            use_type = type or "int32"
            use_mode = mode or _default_mode(base_expr)
        else:
            raise GameModifierError("need a symbol or address", code=ErrorCode.INVALID_ARGS)
        info = pointers.resolve_pointer(backend, base_expr, use_offsets, mode=use_mode)
        info["type"] = use_type
        info["symbol"] = symbol
        info["mode"] = use_mode
        return info

    # ================================================================== read
    def read(self, *, session_id: str, symbol=None, address=None, type=None, offsets=None, mode=None) -> dict:
        session = self._load(session_id)
        backend = self._open(session)
        try:
            target = self._resolve_target(backend, session, symbol=symbol, address=address, offsets=offsets, type=type, mode=mode)
            use_type = target["type"]
            size = vt.type_size(use_type) or 64
            validate_address(backend, target["final_address"], size)
            data = backend.read(target["final_address"], size)
            current = vt.decode_value(use_type, data)
        finally:
            backend.close()
        return {
            "address_hex": target["final_address_hex"],
            "type": use_type,
            "value": current,
            "symbol": symbol,
            "mode": target.get("mode"),
        }

    # ================================================================ modify
    @_session_op
    def modify(
        self,
        *,
        session_id: str,
        symbol=None,
        address=None,
        type=None,
        value=None,
        offsets=None,
        mode=None,
        confirm: bool = False,
        freeze: bool = False,
        label: str = "",
        confirm_code: bool = False,
    ) -> dict:
        """Write one value. High-risk targets (executable / read-only / unknown
        regions) additionally require ``confirm_code=True`` (CLI
        ``--confirm-code``) on top of ``confirm=True`` - the same staged
        confirmation batch_run has always had, now applied to single writes.
        """

        self._safety_write_gate(confirm, "modify")
        session = self._load(session_id)
        backend = self._open(session)
        try:
            result = self._modify_on(backend, session, symbol=symbol, address=address, type=type,
                                     value=value, offsets=offsets, mode=mode, confirm=confirm,
                                     freeze=freeze, label=label, confirm_code=confirm_code)
        finally:
            backend.close()
            self.store.save(session)
        if confirm and result.get("applied"):
            self._audit_log(session, "modify",
                            {"symbol": symbol, "address": address, "type": type, "value": value,
                             "offsets": offsets, "freeze": freeze, "label": label},
                            result)
        return result

    def _modify_on(self, backend, session, *, symbol, address, type, value, offsets, mode,
                   confirm, freeze, label, confirm_code: bool = False):
        target = self._resolve_target(backend, session, symbol=symbol, address=address, offsets=offsets, type=type, mode=mode)
        use_type = target["type"]
        final = target["final_address"]
        size = vt.type_size(use_type) or 0

        # read current (for old->new report, backup, and freeze-at-current)
        current = None
        region = validate_address(
            backend, final, max(size, 1),
            require_writable=self.config.require_writable_region,
        )
        try:
            if size:
                current = vt.decode_value(use_type, backend.read(final, size))
        except Exception:
            current = None

        resolved_value = self._resolve_value(use_type, value, current=current, freeze=freeze)
        encoded = vt.encode_value(use_type, resolved_value)
        if not size:
            size = len(encoded)
        validate_write_span(size, self.config.max_write_bytes)

        warnings = []
        if region is not None and not region.writable:
            warnings.append("target region is not marked writable; write will retry via VirtualProtectEx")

        # write-risk grading for the target address (additive output field)
        risk = self._classify_write_risk(backend, final, size)

        out = {
            "address_hex": hex(final),
            "type": use_type,
            "old_value": current,
            "new_value": resolved_value,
            "symbol": symbol,
            "freeze": freeze,
            "bytes": encoded.hex(),
        }

        if not confirm:
            out["applied"] = False
            out["dry_run"] = True
            out["status"] = "dry_run_preview"
            out["hint"] = ("这是预览，未实际写入。确认后重跑加 --confirm 执行写入。"
                           "(Re-run with confirm=true / CLI --confirm to apply.)")
            out["risk"] = risk
            if risk == "high":
                out["requires_confirm_code"] = True
                out["hint"] = ("这是预览，未实际写入。目标位于高风险区域（代码段/只读/未知）；"
                               "确认无误后需同时加 confirm=true 与 confirm_code=true"
                               "（CLI: --confirm --confirm-code）才会写入。")
            out["impact"] = {
                "address_hex": hex(final),
                "size": size,
                "old_value": current,
                "new_value": resolved_value,
                "region": region.to_dict() if region is not None else None,
                "backup_would_create": bool(self.config.auto_backup and current is not None),
            }
            if warnings:
                out["warnings"] = warnings
            return {"ok": True, **out}

        # staged confirmation: high-risk single writes need confirm_code too
        # (mirrors the batch_run gate instead of only annotating the risk).
        if risk == "high" and not confirm_code:
            raise GameModifierError(
                "high-risk write target (executable / read-only / unknown region) "
                "requires confirm_code=true",
                code=ErrorCode.NOT_CONFIRMED,
                details={"address_hex": hex(final), "risk": risk,
                         "region": region.to_dict() if region is not None else None},
                hint=("目标是高风险写（代码 patch 级别）。确认影响范围后加 "
                      "confirm_code=true（CLI: --confirm --confirm-code）重试；"
                      "否则先用 confirm=false 预览。"),
            )

        # backup then write
        backup_id = None
        if self.config.auto_backup and current is not None:
            mgr = BackupManager(self.store.backups_dir(session.id))
            rec = mgr.create(backend, [{"address": final, "size": size, "note": label or symbol or ""}], label=label)
            backup_id = rec["id"]

        written = backend.write(final, encoded)
        # verify
        verified = None
        try:
            verified = vt.decode_value(use_type, backend.read(final, size))
        except Exception:
            pass

        if freeze:
            self._register_freeze(session, symbol=symbol, address=address if symbol is None else None,
                                  offsets=offsets, type=use_type, value=resolved_value, label=label)

        out.update({
            "applied": True,
            "dry_run": False,
            "status": "applied",
            "risk": risk,
            "bytes_written": written,
            "verified_value": verified,
            "backup_id": backup_id,
        })
        if warnings:
            out["warnings"] = warnings
        return {"ok": True, **out}

    def _classify_write_risk(self, backend, address: int, size: int) -> str:
        """按目标地址所在内存区域分类写风险。

        - 区域可执行（代码段）→ ``"high"``（代码 patch，危险）
        - 区域可写非可执行（数据段/堆）→ ``"normal"``
        - 区域只读/未知 → ``"high"``（可能触发保护或崩溃）

        优先使用 ``backend.query(address)``，失败时回退到 ``regions()`` 匹配；
        两者都无法确定时保守返回 ``"high"``。
        """

        region = None
        try:
            region = backend.query(address)
        except Exception:
            region = None
        if region is None:
            try:
                for r in backend.regions():
                    if r.contains(address, max(1, size)):
                        region = r
                        break
            except Exception:
                region = None
        if region is None:
            return "high"
        if region.executable:
            return "high"
        if region.writable:
            return "normal"
        return "high"

    def _resolve_value(self, type_name: str, value, *, current=None, freeze=False):
        """Map numbers and MAX/MIN tokens to a concrete value.

        For a freeze at MAX we keep the *current* value (true "infinite" - never
        decreases); for a set at MAX we use the type's maximum.
        """

        if value in (MAX, "max", "MAX"):
            if freeze and current is not None:
                return current
            return self._type_max(type_name)
        if value in (MIN, "min", "MIN"):
            return self._type_min(type_name)
        if value is None:
            if current is not None:
                return current
            raise GameModifierError("no value provided", code=ErrorCode.INVALID_ARGS)
        return vt.decode_value(type_name, vt.encode_value(type_name, value))

    @staticmethod
    def _type_max(type_name: str):
        rng = vt.value_range(type_name)
        if rng:
            return rng[1]
        return 1_000_000_000.0  # sane large float

    @staticmethod
    def _type_min(type_name: str):
        rng = vt.value_range(type_name)
        if rng:
            return max(rng[0], 0)
        return 0.0

    # ================================================================ freeze
    def _register_freeze(self, session, *, symbol, address, offsets, type, value, label):
        entry = {
            "label": label or symbol or (hex(address) if isinstance(address, int) else address),
            "symbol": symbol,
            "address": address,
            "offsets": list(offsets) if offsets else [],
            "type": type,
            "value": value,
        }
        # replace any existing freeze on the same target
        session.freezes = [f for f in session.freezes if not (f.get("symbol") == symbol and f.get("address") == address)]
        session.freezes.append(entry)

    def freeze_list(self, *, session_id: str) -> dict:
        session = self._load(session_id)
        return {"session_id": session_id, "count": len(session.freezes), "freezes": session.freezes}

    def freeze_clear(self, *, session_id: str) -> dict:
        session = self._load(session_id)
        n = len(session.freezes)
        session.freezes = []
        self.store.save(session)
        return {"session_id": session_id, "cleared": n}

    def _freeze_prepare_targets(self, backend: MemoryBackend, session: Session) -> list[dict]:
        """Classify and pre-resolve freeze entries before the enforcement loop.

        Pure-address targets (no pointer chain: relative base, no offsets) are
        resolved once and their ``(final_address, encoded_bytes)`` cached for
        the whole loop; pointer-chain targets are re-resolved every round
        because their final address can move.
        """

        targets: list[dict] = []
        for f in session.freezes:
            sym = session.get_symbol(f["symbol"]) if f.get("symbol") else None
            base_expr = sym.base_expr if sym else (f.get("address") if isinstance(f.get("address"), str)
                                                   else hex(f["address"]) if f.get("address") is not None else None)
            offsets = f.get("offsets") or []
            mode = _default_mode(base_expr) if base_expr else "pointer_chain"
            pure = base_expr is not None and mode == "relative" and not offsets
            entry = {"freeze": f, "pure": pure, "addr": None,
                     "encoded": vt.encode_value(f["type"], f["value"])}
            if pure:
                try:
                    target = self._resolve_target(backend, session, symbol=f.get("symbol"),
                                                  address=f.get("address"), offsets=offsets, type=f.get("type"))
                    entry["addr"] = target["final_address"]
                except Exception:
                    entry["addr"] = None  # retry resolution inside the loop
            targets.append(entry)
        return targets

    def freeze_run(self, *, session_id: str, interval: float = 0.05, iterations: int = 0,
                   stop_event=None, adaptive: Optional[bool] = None) -> dict:
        """Foreground freeze loop enforcing all registered frozen values.

        Runs until ``iterations`` reached (0 = until interrupted / stop_event).

        Optimisations over the naive write-every-round loop:

        * pure-address targets are resolved once and cached
          (``(final_address, encoded_bytes)``); only a failed write triggers a
          re-resolve. Pointer-chain targets keep per-round resolution.
        * ``adaptive`` (default: ``[freeze] adaptive`` config, or the
          ``GAME_MODIFIER_FREEZE_ADAPTIVE=0/1`` env override): every cycle
          reads the targets back with ``read_many`` and only writes the ones
          that drifted. Consecutive clean cycles double the sleep interval up
          to ``[freeze] max_interval``; any drift snaps back to
          ``[freeze] min_interval``. ``adaptive=False`` keeps the legacy
          fixed-interval write-every-round behaviour.

        ``writes`` counts enforcement actions per target per loop (a write, or
        a verified-clean skip in adaptive mode) so legacy call sites keep
        their accounting; ``actual_writes`` / ``skipped_writes`` break it down.
        """

        session = self._load(session_id)
        if not session.freezes:
            return {"session_id": session_id, "frozen": 0, "note": "no freezes registered"}

        if adaptive is None:
            env = os.environ.get("GAME_MODIFIER_FREEZE_ADAPTIVE", "").strip().lower()
            if env in ("0", "1", "true", "false", "yes", "no"):
                adaptive = env in ("1", "true", "yes")
            else:
                adaptive = self.config.freeze_adaptive
        min_iv = max(self.config.freeze_min_interval, 0.0)
        max_iv = max(self.config.freeze_max_interval, min_iv)
        cur_iv = min_iv if adaptive else interval

        backend = self._open(session)
        writes = 0          # enforcement actions (writes + verified-clean skips)
        actual_writes = 0   # real memory writes issued
        skipped_writes = 0  # adaptive dirty-check found the value already correct
        loops = 0
        clean_streak = 0
        try:
            targets = self._freeze_prepare_targets(backend, session)
            while True:
                drifted: list[dict] = []
                if adaptive:
                    # dirty check: batch read-back, only drifted targets get written
                    readback: dict[int, bytes] = {}
                    by_size: dict[int, list[int]] = {}
                    for t in targets:
                        addr = self._freeze_resolve_addr(backend, session, t)
                        if addr is None:
                            continue
                        t["addr_now"] = addr
                        by_size.setdefault(len(t["encoded"]), []).append(addr)
                    for size, addrs in by_size.items():
                        try:
                            readback.update(backend.read_many(addrs, size))
                        except Exception:
                            pass
                    for t in targets:
                        addr = t.get("addr_now")
                        if addr is None:
                            continue
                        if readback.get(addr) != t["encoded"]:
                            drifted.append(t)
                        else:
                            writes += 1
                            skipped_writes += 1
                else:
                    drifted = []
                    for t in targets:
                        addr = self._freeze_resolve_addr(backend, session, t)
                        if addr is None:
                            continue
                        t["addr_now"] = addr
                        drifted.append(t)

                for t in drifted:
                    addr = t.get("addr_now")
                    if addr is None:
                        continue
                    try:
                        backend.write(addr, t["encoded"])
                        writes += 1
                        actual_writes += 1
                    except Exception:
                        # cached address went stale: re-resolve once and retry
                        if t["pure"]:
                            t["addr"] = None
                            addr = self._freeze_resolve_addr(backend, session, t)
                            if addr is None:
                                continue
                            try:
                                backend.write(addr, t["encoded"])
                                writes += 1
                                actual_writes += 1
                            except Exception:
                                continue
                        else:
                            continue

                if adaptive:
                    if drifted:
                        clean_streak = 0
                        cur_iv = min_iv
                    else:
                        clean_streak += 1
                        cur_iv = min(max_iv, cur_iv * 2)

                loops += 1
                if iterations and loops >= iterations:
                    break
                if stop_event is not None and stop_event.is_set():
                    break
                time.sleep(cur_iv if adaptive else interval)
        finally:
            backend.close()
        return {
            "session_id": session_id,
            "frozen": len(session.freezes),
            "loops": loops,
            "writes": writes,
            "actual_writes": actual_writes,
            "skipped_writes": skipped_writes,
            "adaptive": adaptive,
        }

    def _freeze_resolve_addr(self, backend: MemoryBackend, session: Session, t: dict) -> Optional[int]:
        """Current-round final address for one prepared freeze target.

        Pure-address targets use the cached resolution (lazily filled when the
        initial pre-resolve failed); pointer chains resolve every round.
        """

        f = t["freeze"]
        if t["pure"]:
            if t["addr"] is None:
                try:
                    target = self._resolve_target(backend, session, symbol=f.get("symbol"),
                                                  address=f.get("address"), offsets=f.get("offsets"), type=f.get("type"))
                    t["addr"] = target["final_address"]
                except Exception:
                    return None
            return t["addr"]
        try:
            target = self._resolve_target(backend, session, symbol=f.get("symbol"),
                                          address=f.get("address"), offsets=f.get("offsets"), type=f.get("type"))
            return target["final_address"]
        except Exception:
            return None

    @_session_op
    def freeze_start(self, *, session_id: str, interval: float = 0.05, adaptive: Optional[bool] = None) -> dict:
        """Start enforcing freezes in a detached background process.

        ``adaptive`` (None = ``[freeze] adaptive`` config default) is handed to
        the worker via the ``GAME_MODIFIER_FREEZE_ADAPTIVE`` environment
        variable, so no CLI plumbing is needed.
        """

        session = self._load(session_id)
        if not session.freezes:
            return {"session_id": session_id, "started": False, "note": "no freezes registered"}

        pid_path = self.store.freeze_pid_path(session_id)
        existing = self._read_freeze_pid(session_id)
        if existing and procmod.process_exists(existing):
            return {"session_id": session_id, "started": False, "already_running_pid": existing}

        cmd = [sys.executable, "-m", "game_modifier", "freeze", "run",
               "--session", session_id, "--interval", str(interval)]
        creationflags = 0
        if sys.platform.startswith("win"):
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
        env = dict(os.environ)
        if adaptive is not None:
            env["GAME_MODIFIER_FREEZE_ADAPTIVE"] = "1" if adaptive else "0"
        proc = subprocess.Popen(  # noqa: S603 - our own module
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=creationflags,
            close_fds=True,
            env=env,
        )
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text(str(proc.pid), encoding="utf-8")
        out = {"session_id": session_id, "started": True, "worker_pid": proc.pid, "interval": interval, "frozen": len(session.freezes)}
        if adaptive is not None:
            out["adaptive"] = adaptive
        return out

    @_session_op
    def freeze_stop(self, *, session_id: str) -> dict:
        self._load(session_id)  # validate session exists
        pid = self._read_freeze_pid(session_id)
        pid_path = self.store.freeze_pid_path(session_id)
        if not pid:
            return {"session_id": session_id, "stopped": False, "note": "no running freeze worker"}
        stopped = False
        try:
            import psutil  # type: ignore

            if psutil.pid_exists(pid):
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(timeout=3)
                except Exception:
                    p.kill()
                stopped = True
        except Exception:
            try:
                os.kill(pid, 15)
                stopped = True
            except Exception:
                stopped = False
        if pid_path.exists():
            pid_path.unlink()
        return {"session_id": session_id, "stopped": stopped, "worker_pid": pid}

    def _read_freeze_pid(self, session_id: str) -> Optional[int]:
        pid_path = self.store.freeze_pid_path(session_id)
        if not pid_path.exists():
            return None
        try:
            return int(pid_path.read_text(encoding="utf-8").strip())
        except Exception:
            return None

    # ================================================================ watch
    # Polling-based "find what changes": periodically read an address back and
    # record when the value changed (before/after). Locates *when* a value
    # moves, not *who* wrote it (hardware breakpoints are a later phase).

    WATCH_MAX_CHANGES = 50  # cap on the in-memory change list (output hygiene)

    def watch_run(self, session_id: str, *, address: str, type: str = "int32",
                  interval: float = 0.1, iterations: int = 100,
                  jsonl_path: Optional[str] = None, stop_event=None) -> dict:
        """Foreground polling watch: read the value back in a loop, log changes.

        ``iterations`` = 0 runs until interrupted / ``stop_event`` (used by the
        background worker, which also passes ``jsonl_path`` so every change is
        appended to ``sessions/<id>/watch.jsonl``).

        The in-memory ``changes`` list keeps only the most recent
        ``WATCH_MAX_CHANGES`` entries; ``change_count`` counts every change.
        """

        session = self._load(session_id)
        backend = self._open(session)
        changes: list[dict] = []
        change_count = 0
        loops = 0
        sleep_iv = max(interval, 0.0)
        try:
            target = self._resolve_target(backend, session, address=address, type=type)
            use_type = target["type"]
            final = target["final_address"]
            size = vt.type_size(use_type) or 4
            try:
                prev = vt.decode_value(use_type, backend.read(final, size))
            except Exception as exc:
                return {
                    "ok": False,
                    "address_hex": hex(final),
                    "type": use_type,
                    "error": {
                        "code": ErrorCode.READ_FAILED.value,
                        "message": f"cannot read {hex(final)}: {exc}",
                    },
                }

            initial = prev
            read_failed = False
            while True:
                if iterations and loops >= iterations:
                    break
                if stop_event is not None and stop_event.is_set():
                    break
                time.sleep(sleep_iv)
                loops += 1
                try:
                    cur = vt.decode_value(use_type, backend.read(final, size))
                except Exception:
                    read_failed = True  # region/process went away: report what we have
                    break
                if cur != prev:
                    change_count += 1
                    rec = {"iteration": loops, "ts": time.time(), "old": prev, "new": cur}
                    changes.append(rec)
                    if len(changes) > self.WATCH_MAX_CHANGES:
                        changes.pop(0)
                    if jsonl_path:
                        try:
                            p = Path(jsonl_path)
                            p.parent.mkdir(parents=True, exist_ok=True)
                            with p.open("a", encoding="utf-8") as fh:
                                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        except Exception:
                            pass  # logging must never kill the watch loop
                    prev = cur
        finally:
            backend.close()

        out = {
            "address_hex": hex(final),
            "type": use_type,
            "iterations": loops,
            "initial_value": initial,
            "final_value": prev,
            "changes": changes,
            "change_count": change_count,
            "stable": change_count == 0,
        }
        if read_failed:
            out["note"] = "stopped early: read failed (process exited or region unmapped)"
        return out

    def watch_start(self, session_id: str, *, address: str, type: str = "int32",
                    interval: float = 0.1) -> dict:
        """Start watching an address in a detached background process.

        The worker runs ``watch run`` with iterations=0 and appends every
        change record to ``sessions/<id>/watch.jsonl``.
        """

        self._load(session_id)  # validate session exists
        existing = self._read_watch_pid(session_id)
        if existing and procmod.process_exists(existing):
            return {"session_id": session_id, "started": False, "already_running_pid": existing}

        jsonl_path = self.store.watch_jsonl_path(session_id)
        cmd = [sys.executable, "-m", "game_modifier", "watch", "run",
               "--session", session_id, "--address", address, "--type", type,
               "--interval", str(interval), "--iterations", "0", "--log", str(jsonl_path)]
        creationflags = 0
        if sys.platform.startswith("win"):
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
        proc = subprocess.Popen(  # noqa: S603 - our own module
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=creationflags,
            close_fds=True,
        )
        pid_path = self.store.watch_pid_path(session_id)
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text(str(proc.pid), encoding="utf-8")
        return {
            "session_id": session_id, "started": True, "worker_pid": proc.pid,
            "address": address, "type": type, "interval": interval,
            "log": str(jsonl_path),
        }

    def watch_stop(self, session_id: str) -> dict:
        self._load(session_id)  # validate session exists
        pid = self._read_watch_pid(session_id)
        pid_path = self.store.watch_pid_path(session_id)
        if not pid:
            return {"session_id": session_id, "stopped": False, "note": "no running watch worker"}
        stopped = False
        try:
            import psutil  # type: ignore

            if psutil.pid_exists(pid):
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(timeout=3)
                except Exception:
                    p.kill()
                stopped = True
        except Exception:
            try:
                os.kill(pid, 15)
                stopped = True
            except Exception:
                stopped = False
        if pid_path.exists():
            pid_path.unlink()
        return {"session_id": session_id, "stopped": stopped, "worker_pid": pid}

    def _read_watch_pid(self, session_id: str) -> Optional[int]:
        pid_path = self.store.watch_pid_path(session_id)
        if not pid_path.exists():
            return None
        try:
            return int(pid_path.read_text(encoding="utf-8").strip())
        except Exception:
            return None

    def watch_report(self, session_id: str, *, limit: int = 50) -> dict:
        """Read the change history recorded by the background watch worker."""

        self._load(session_id)  # validate session exists
        path = self.store.watch_jsonl_path(session_id)
        entries: list[dict] = []
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    continue  # skip corrupted lines
        recent = entries[-limit:] if limit > 0 else entries
        return {
            "session_id": session_id,
            "change_count": len(entries),
            "returned": len(recent),
            "changes": recent,
        }

    # ================================================ find-writers (phase 2.1)
    # Hardware write watchpoints: precise upgrade of the polling watch. Uses
    # DR0-DR3 debug registers to capture the instruction (RIP) writing an address.

    def find_writers(self, session_id: str, *, address: str, size: int = 4,
                     duration: float = 5.0, max_hits: int = 20) -> dict:
        """Find which code writes to ``address`` via hardware breakpoints.

        ``address`` accepts a session symbol name, a hex/decimal address or a
        ``module+0x..`` expression. Sampling briefly suspends target threads
        and is capped at ``duration`` seconds; debug registers are restored.
        Refused for anti-cheat sessions (single-player use only).
        """

        if not sys.platform.startswith("win"):
            raise UnsupportedOSError(
                "find-writers requires Windows debug registers",
                hint="Hardware write watchpoints are only supported on Windows.",
            )
        if size not in (1, 2, 4, 8):
            raise InvalidArgsError(f"unsupported watchpoint size: {size}", details={"supported": [1, 2, 4, 8]})

        session = self._load(session_id)
        ac = session.anti_cheat or {}
        if ac.get("detected"):
            raise GameModifierError(
                "find-writers refused: anti-cheat detected in this session",
                code=ErrorCode.ANTI_CHEAT,
                details=ac,
                hint="Hardware breakpoints debug the target process; never use this on anti-cheat protected games.",
            )

        backend = self._open(session)
        try:
            base_expr = address
            sym = session.get_symbol(address) if isinstance(address, str) else None
            if sym is not None:
                base_expr = sym.base_expr
            final = pointers.resolve_base(backend, base_expr).address
        finally:
            backend.close()

        from .memory import watchpoint as wp  # lazy: Windows-only module

        out = wp.find_writers(session.pid, final, size=size, duration=duration, max_hits=max_hits)
        out["session_id"] = session_id
        return out

    # =================================================================== nl
    @_session_op
    def nl(self, *, session_id: str, text: str, confirm: bool = False,
           confirm_code: bool = False) -> dict:
        self._safety_write_gate(confirm, "nl")
        session = self._load(session_id)
        intent = nlp_parse(text)
        out: dict[str, Any] = {"intent": intent.to_dict()}

        if intent.action == "unlock":
            out["ok"] = False
            out["resolution"] = "template_or_scan"
            out["error"] = {
                "code": ErrorCode.NEEDS_SCAN.value,
                "message": f"unlock ({intent.value}) is game-specific; apply a template option or scan the flag.",
                "hint": "Use `template apply` with an unlock option, or scan the unlock flag then `name set`.",
            }
            return out

        symbol_name = self._map_field_to_symbol(session, intent.field)
        if symbol_name is None:
            raise NeedsScanError(
                f"no symbol mapped for field {intent.field!r}",
                details={
                    "field": intent.field,
                    "suggested_type": intent.value_type,
                    "known_symbols": sorted(session.symbols.keys()),
                    "next": {
                        "scan": {"type": intent.value_type, "value": intent.value if isinstance(intent.value, (int, float)) else None},
                        "then": f"name set {intent.field or 'player.value'} <address> --type {intent.value_type}",
                    },
                },
                hint="Scan for the current value, then map it with `name set`; afterwards this phrase resolves automatically.",
            )

        backend = self._open(session)
        try:
            if intent.action == "get":
                target = self._resolve_target(backend, session, symbol=symbol_name)
                size = vt.type_size(target["type"]) or 64
                data = backend.read(target["final_address"], size)
                out["ok"] = True
                out["result"] = {"symbol": symbol_name, "address_hex": target["final_address_hex"], "value": vt.decode_value(target["type"], data)}
                return out

            value = intent.value
            freeze = intent.action == "freeze"
            # add/sub adjust relative to current
            if intent.action in ("add", "sub"):
                target = self._resolve_target(backend, session, symbol=symbol_name)
                size = vt.type_size(target["type"]) or 4
                cur = vt.decode_value(target["type"], backend.read(target["final_address"], size))
                value = cur + intent.value if intent.action == "add" else cur - intent.value

            res = self._modify_on(
                backend, session,
                symbol=symbol_name, address=None, type=intent.value_type,
                value=value, offsets=None, mode=None, confirm=confirm, freeze=freeze,
                label=f"nl:{intent.field}", confirm_code=confirm_code,
            )
            out.update(res)
            return out
        finally:
            backend.close()
            self.store.save(session)

    @staticmethod
    def _map_field_to_symbol(session: Session, field: Optional[str]) -> Optional[str]:
        if not field:
            return None
        candidates = [field, f"player.{field}", f"weapon.{field}", f"resource.{field}"]
        for c in candidates:
            if c in session.symbols:
                return c
        # reverse: a symbol whose leaf name matches the field
        for name in session.symbols:
            if name.split(".")[-1] == field:
                return name
        return None

    # =============================================================== name/symbol
    @_session_op
    def name_set(self, *, session_id: str, name: str, base_expr: str, offsets=None, type: str = "int32", description: str = "", mode: Optional[str] = None, temp: bool = False) -> dict:
        session = self._load(session_id)
        vt.resolve_type(type)  # validate
        if mode is not None and mode not in pointers.VALID_MODES:
            raise GameModifierError(
                f"unknown pointer mode: {mode!r}",
                code=ErrorCode.INVALID_ARGS,
                details={"supported": list(pointers.VALID_MODES)},
            )
        off = pointers.parse_offsets(offsets)
        session.set_symbol(Symbol(name=name, base_expr=base_expr, offsets=off, type=type,
                                  description=description, mode=mode or "", temp=bool(temp)))
        self.store.save(session)
        out = {"symbol": name, "base_expr": base_expr, "offsets": [hex(o) for o in off], "type": type}
        if mode:
            out["mode"] = mode
        if temp:
            out["temp"] = True
        return out

    def name_get(self, *, session_id: str, name: Optional[str] = None, include_temp: bool = True) -> dict:
        session = self._load(session_id)
        if name:
            sym = session.get_symbol(name)
            if not sym:
                raise SymbolNotFoundError(f"symbol not defined: {name!r}", details={"known": sorted(session.symbols.keys())})
            return sym.to_dict()
        names = sorted(session.symbols)
        if not include_temp:
            names = [n for n in names if not session.symbols[n].get("temp")]
        return {"symbols": [session.get_symbol(n).to_dict() for n in names]}

    @_session_op
    def name_clear_temp(self, *, session_id: str) -> dict:
        """Remove all temp symbols (e.g. chain intermediates); persistent symbols are kept."""

        session = self._load(session_id)
        removed = sorted(n for n, raw in session.symbols.items() if raw.get("temp"))
        for n in removed:
            del session.symbols[n]
        if removed:
            self.store.save(session)
        return {"removed": removed, "count": len(removed), "kept": len(session.symbols)}

    @_session_op
    def name_chain(self, session_id: str, *, name: str, base: str, offsets=None,
                   type: str = "uint64", temp: bool = True, mode: Optional[str] = None) -> dict:
        """Walk a multi-level pointer chain and register every intermediate as a symbol.

        Example: ``name_chain(name="mgr", base="Game.exe+0x1A4", offsets="0x10,0x28,0x0")``
        registers ``mgr.step0`` (resolved base), ``mgr.step1`` / ``mgr.step2`` (each
        dereference result) and ``mgr`` (final address). Intermediates default to
        ``temp=True`` (removable via ``name_clear_temp``); pass ``temp=False`` to persist.

        ``mode`` selects the offset semantics: ``None``/``"pointer_chain"`` walks
        deref+offset (Cheat Engine style, pointer arrays / linked structures);
        ``"field_chain"`` walks offset+deref (nested struct fields such as
        ``gem.__data.MainPowerData``); the final offset step is never dereferenced
        so ``name`` itself addresses the final object/value. ``"relative"`` is not
        meaningful for a chain and is rejected.

        On a mid-chain failure the already-registered step symbols are kept (session
        saved) and the error carries ``failed_step`` + the partial ``steps`` list, so a
        later run can resume inspection from the last good intermediate.
        """

        session = self._load(session_id)
        vt.resolve_type(type)  # validate
        chain_mode = mode or "pointer_chain"
        if chain_mode not in ("pointer_chain", "field_chain"):
            raise GameModifierError(
                f"unknown pointer mode for name_chain: {mode!r}",
                code=ErrorCode.INVALID_ARGS,
                details={"supported": ["pointer_chain", "field_chain"]},
            )
        off = pointers.parse_offsets(offsets)
        backend = self._open(session)
        steps: list[dict] = []

        def _register(step_name: str, addr: int) -> None:
            session.set_symbol(Symbol(name=step_name, base_expr=hex(addr), offsets=[],
                                      type=type, mode="relative", temp=bool(temp),
                                      description=f"chain intermediate of {name}"))
            steps.append({"symbol": step_name, "address": hex(addr), "address_value": addr})

        try:
            base_info = pointers.resolve_base(backend, base)
            addr = base_info.address
            _register(f"{name}.step0", addr)
            for i, o in enumerate(off):
                if chain_mode == "field_chain":
                    # offset first, then dereference (nested struct fields);
                    # the final offset step is left un-dereferenced so ``name``
                    # addresses the final object/value directly
                    addr = addr + o
                    if i + 1 >= len(off):
                        break
                    read_at = addr
                else:
                    read_at = addr
                try:
                    ptr = pointers.read_pointer(backend, read_at)
                except (GameModifierError, RuntimeError, OSError) as exc:
                    # keep the intermediates resolved so far for resume-from-breakpoint
                    self.store.save(session)
                    raise GameModifierError(
                        f"pointer chain broken at offset[{i}]: cannot read pointer at {hex(read_at)}",
                        code=ErrorCode.INVALID_POINTER,
                        details={"failed_step": i, "read_at": hex(read_at), "steps": steps,
                                 "registered": [s["symbol"] for s in steps]},
                        hint=("已注册的中间符号已保留（见 details.registered），"
                              "可从最后一个 step 符号继续排查（name get / resolve --base <step地址>）。"),
                    ) from exc
                if chain_mode == "field_chain":
                    addr = ptr
                else:
                    addr = ptr + o
                # the last offset produces the final address, registered as ``name`` itself
                if i + 1 < len(off):
                    _register(f"{name}.step{i + 1}", addr)
        finally:
            backend.close()

        session.set_symbol(Symbol(name=name, base_expr=hex(addr), offsets=[], type=type,
                                  mode="relative", temp=bool(temp),
                                  description=f"chain final of {base} [{','.join(hex(o) for o in off)}]"))
        steps.append({"symbol": name, "address": hex(addr), "address_value": addr})
        self.store.save(session)
        return {
            "symbol": name,
            "final": hex(addr),
            "final_address": addr,
            "steps": steps,
            "depth": len(off),
            "temp": bool(temp),
        }

    # ================================================================ template
    def template_list(self) -> dict:
        return {"templates": tpl.list_templates(self.config.user_templates_dir)}

    def template_show(self, *, name: str) -> dict:
        template = tpl.load_template(name, self.config.user_templates_dir)
        options = {}
        for key in template.get("options", {}):
            opt = tpl.get_option(template, key)
            options[key] = {"label": opt.label, "description": opt.description, "params": opt.params, "targets": opt.targets}
        return {"name": template.get("name"), "description": template.get("description"), "game_types": template.get("game_types", []), "options": options}

    @_session_op
    def template_apply(self, *, session_id: str, name: str, option: str, params: Optional[dict] = None, confirm: bool = False) -> dict:
        session = self._load(session_id)
        template = tpl.load_template(name, self.config.user_templates_dir)
        targets = tpl.expand_option(template, option, params or {})
        backend = self._open(session)
        results = []
        missing = []
        try:
            for t in targets:
                symbol = t.get("symbol")
                address = t.get("address")
                if symbol and symbol not in session.symbols:
                    missing.append(symbol)
                    results.append({"ok": False, "symbol": symbol, "error": {"code": ErrorCode.SYMBOL_NOT_FOUND.value, "message": f"symbol {symbol!r} not mapped"}})
                    continue
                strategy = t.get("strategy", "set")
                try:
                    res = self._modify_on(
                        backend, session,
                        symbol=symbol, address=address, type=t.get("type"),
                        value=t.get("value"), offsets=t.get("offsets"), mode=t.get("mode"),
                        confirm=confirm, freeze=(strategy == "freeze"),
                        label=t.get("note", ""),
                    )
                except GameModifierError as exc:
                    # a high-risk single target must not abort the whole
                    # template - mark it skipped (batch_run semantics).
                    if exc.code == ErrorCode.NOT_CONFIRMED:
                        results.append({
                            "ok": True, "skipped": True,
                            "skipped_reason": "high_risk_requires_confirm_code",
                            "risk": "high", "applied": False,
                            "symbol": symbol, "address": address,
                            "error_code": exc.code.value, "message": exc.message,
                        })
                        continue
                    raise
                results.append(res)
        finally:
            backend.close()
            self.store.save(session)
        out = {
            "template": name,
            "option": option,
            "applied": confirm,
            "targets": len(targets),
            "missing_symbols": missing,
            "results": results,
            "hint": None if not missing else "Map missing symbols with `name set` (scan the value first).",
        }
        if confirm:
            applied = [r for r in results if r.get("applied")]
            if applied:
                first_backup = next((r.get("backup_id") for r in applied if r.get("backup_id")), None)
                self._audit_log(session, "template_apply",
                                {"template": name, "option": option, "params": params},
                                {"ok": not missing, "applied": len(applied), "backup_id": first_backup})
        return out

    # ================================================================= batch
    @_session_op
    def batch_run(self, *, session_id: str, path: Optional[str] = None, yaml_text: Optional[str] = None,
                  confirm: bool = False, stop_on_error: bool = True,
                  offset: int = 0, limit: int = 0, confirm_code: bool = False) -> dict:
        """Run a batch of operations from a file path or inline YAML text.

        ``path`` and ``yaml_text`` are mutually exclusive (passing both, or
        neither, raises a structured E_INVALID_ARGS). The full result is
        always persisted to ``sessions/<id>/batch_results/<timestamp>.json``
        (returned as ``results_file``); the inline ``results`` list can be
        windowed with ``offset``/``limit`` (``limit=0`` keeps all results
        inline).

        Write-risk grading (additive): with ``confirm=True`` only
        ``risk=normal`` writes (writable data regions) are applied; high-risk
        targets (executable/read-only/unknown regions) are skipped and marked
        ``skipped_reason="high_risk_requires_confirm_code"`` unless
        ``confirm_code=True`` (CLI: ``--confirm-code``) releases them too.
        """

        session = self._load(session_id)  # validate the session exists
        if path and yaml_text:
            raise InvalidArgsError(
                "batch_run accepts either a file path or inline yaml, not both",
                details={"path": str(path), "yaml_chars": len(str(yaml_text))},
                hint="去掉 yaml 参数（用文件）或去掉 file 参数（用内联 YAML）。",
            )
        if not path and not yaml_text:
            raise InvalidArgsError(
                "batch_run needs a batch source: pass file=<path> or yaml=<inline text>",
                details={},
                hint="提供 file 参数指向 YAML 文件，或用 yaml 参数直接内联批处理文本。",
            )
        if path:
            self._check_file_path(path, session=session, purpose="batch_run(file=)")
        data = batchmod.load_batch_text(yaml_text) if yaml_text else batchmod.load_batch(path)
        confirm = bool(data.get("confirm", confirm))
        confirm_code = bool(data.get("confirm_code", confirm_code))
        stop_on_error = bool(data.get("stop_on_error", stop_on_error))
        self._safety_write_gate(confirm, "batch_run")
        return self._batch_execute(session_id, data["operations"], confirm=confirm,
                                   confirm_code=confirm_code,
                                   stop_on_error=stop_on_error, offset=offset, limit=limit)

    def batch_preview(self, *, session_id: str, path: Optional[str] = None,
                      yaml_text: Optional[str] = None) -> dict:
        """Parse + validate a batch and pre-flight every step WITHOUT executing.

        Read-only (no writes, no confirm needed): each write-ish step runs
        through the same :meth:`_batch_step_risk` grading used at execution
        time, so the reply lists per-op ``risk`` (high/normal/none/unknown)
        plus an ``estimated_write_bytes`` total (sum of resolvable write
        target sizes). Answers review §6.2: agents can budget a batch's write
        volume before committing to ``batch_run``.

        ``path`` / ``yaml_text`` are mutually exclusive, mirroring
        :meth:`batch_run`.
        """

        session = self._load(session_id)
        if path and yaml_text:
            raise InvalidArgsError(
                "batch_preview accepts either a file path or inline yaml, not both",
                details={"path": str(path), "yaml_chars": len(str(yaml_text))},
                hint="去掉 yaml 参数（用文件）或去掉 file 参数（用内联 YAML）。",
            )
        if not path and not yaml_text:
            raise InvalidArgsError(
                "batch_preview needs a batch source: pass file=<path> or yaml=<inline text>",
                details={},
                hint="提供 file 参数指向 YAML 文件，或用 yaml 参数直接内联批处理文本。",
            )
        if path:
            self._check_file_path(path, session=session, purpose="batch_preview(file=)")
        data = batchmod.load_batch_text(yaml_text) if yaml_text else batchmod.load_batch(path)
        ops: list[dict] = []
        estimated_bytes = 0
        for index, step in enumerate(data["operations"]):
            action = batchmod.step_action(step)
            payload = step[action]
            item: dict = {"index": index, "action": action}
            if isinstance(payload, dict):
                for key in ("symbol", "address", "template", "name", "base"):
                    if payload.get(key) is not None:
                        item["target"] = str(payload[key])
                        break
            risk: Optional[str] = None
            if action in ("modify", "nl"):
                try:
                    risk = self._batch_step_risk(session, action, payload)
                except Exception:
                    risk = None  # unresolvable pre-flight: execution will report it
            item["risk"] = risk or "none"
            # estimate the write size for resolvable modify targets
            if action == "modify" and isinstance(payload, dict):
                try:
                    backend = self._open(session)
                    try:
                        target = self._resolve_target(
                            backend, session,
                            symbol=payload.get("symbol"), address=payload.get("address"),
                            offsets=payload.get("offsets"), type=payload.get("type"),
                            mode=payload.get("mode"),
                        )
                    finally:
                        backend.close()
                    size = vt.type_size(target["type"]) or 4
                    item["write_bytes"] = size
                    estimated_bytes += size
                except Exception:
                    item["write_bytes"] = None
            ops.append(item)
        risk_breakdown = {"high": 0, "normal": 0, "none": 0}
        for item in ops:
            risk_breakdown[item["risk"]] = risk_breakdown.get(item["risk"], 0) + 1
        return {
            "session_id": session_id,
            "source": "yaml" if yaml_text else "file",
            "confirm": bool(data.get("confirm", False)),
            "confirm_code": bool(data.get("confirm_code", False)),
            "stop_on_error": bool(data.get("stop_on_error", True)),
            "ops": ops,
            "total": len(ops),
            "risk_breakdown": risk_breakdown,
            "estimated_write_bytes": estimated_bytes,
            "hint": ("预检不执行任何写入；确认 risk_breakdown/estimated_write_bytes "
                     "后再调用 batch_run。"),
        }


    def _batch_step_risk(self, session, action: str, payload) -> Optional[str]:
        """Best-effort pre-execution write risk of a batch step.

        Returns ``"high"`` / ``"normal"`` for resolvable write targets, or
        ``None`` when the step is not a write (or its target cannot be
        resolved yet - the real execution path then reports the actual
        error). Raises on backend/resolution failures; callers decide how to
        fall back.
        """

        backend = self._open(session)
        try:
            if action == "modify":
                target = self._resolve_target(
                    backend, session,
                    symbol=payload.get("symbol"), address=payload.get("address"),
                    offsets=payload.get("offsets"), type=payload.get("type"),
                    mode=payload.get("mode"),
                )
            elif action == "nl":
                text = payload if isinstance(payload, str) else payload.get("text")
                intent = nlp_parse(text)
                if intent.action in ("get", "unlock"):
                    return None  # read-only / non-writable intent
                symbol_name = self._map_field_to_symbol(session, intent.field)
                if symbol_name is None:
                    return None  # let nl() raise the usual NeedsScanError
                target = self._resolve_target(backend, session, symbol=symbol_name)
            else:
                return None
            size = vt.type_size(target["type"]) or 4
            return self._classify_write_risk(backend, target["final_address"], size)
        finally:
            backend.close()

    def _batch_execute(self, session_id: str, operations: list[dict], *, confirm: bool,
                       stop_on_error: bool, offset: int = 0, limit: int = 0,
                       extra: Optional[dict] = None, confirm_code: bool = False) -> dict:
        """Shared execution core for ``batch_run`` and ``macro_run``.

        ``extra`` (e.g. macro name/params) is merged into the summary before
        persistence so ``results_file`` carries the same context as the reply.

        ``confirm_code`` gates high-risk writes: with ``confirm=True`` and
        ``confirm_code=False`` only ``risk=normal`` writes are applied;
        high-risk items are skipped (``skipped_reason``) and reported in the
        summary instead of counting as failures.
        """

        offset = max(0, int(offset))
        limit = max(0, int(limit))
        session = self._load(session_id)
        confirm_code = bool(confirm_code)

        def _execute(index: int, step: dict) -> dict:
            action = batchmod.step_action(step)
            payload = step[action]
            if action in ("modify", "nl") and confirm and not confirm_code:
                try:
                    risk = self._batch_step_risk(session, action, payload)
                except Exception:
                    risk = None  # unresolvable now: keep the original error path
                if risk == "high":
                    return {
                        "ok": True,
                        "skipped": True,
                        "skipped_reason": "high_risk_requires_confirm_code",
                        "risk": "high",
                        "applied": False,
                        "symbol": payload.get("symbol") if isinstance(payload, dict) else None,
                        "address": payload.get("address") if isinstance(payload, dict) else None,
                    }
            if action == "nl":
                return self.nl(session_id=session_id, text=payload if isinstance(payload, str) else payload.get("text"), confirm=confirm, confirm_code=confirm_code)
            if action == "modify":
                return self.modify(session_id=session_id, confirm=confirm, confirm_code=confirm_code, **_modify_kwargs(payload))
            if action == "template":
                return self.template_apply(session_id=session_id, name=payload["template"], option=payload["option"], params=payload.get("params"), confirm=confirm)
            if action == "read":
                return {"ok": True, **self.read(session_id=session_id, **_read_kwargs(payload))}
            if action == "resolve":
                resolve_kwargs: dict = {}
                if payload.get("mode") is not None:
                    resolve_kwargs["mode"] = payload["mode"]
                if payload.get("deref_last") is not None:
                    resolve_kwargs["deref_last"] = bool(payload["deref_last"])
                return {"ok": True, **self.resolve(session_id=session_id, base_expr=payload["base"], offsets=payload.get("offsets"), **resolve_kwargs)}
            if action == "scan":
                return {"ok": True, **self.scan(session_id=session_id, type=payload["type"], value=payload.get("value"), comparator=payload.get("comparator", "exact"), value2=payload.get("value2"))}
            if action == "scan_next":
                return {"ok": True, **self.scan_next(session_id=session_id, comparator=payload.get("comparator", "exact"), value=payload.get("value"), value2=payload.get("value2"))}
            if action == "name":
                return {"ok": True, **self.name_set(session_id=session_id, name=payload["name"], base_expr=payload["base"], offsets=payload.get("offsets"), type=payload.get("type", "int32"), description=payload.get("description", ""), mode=payload.get("mode"))}
            if action == "backup":
                return {"ok": True, **self.backup_create(session_id=session_id, targets=payload.get("targets", []))}
            return {"ok": False, "error": {"code": ErrorCode.INVALID_ARGS.value, "message": f"unknown action {action}"}}

        summary = batchmod.run(operations, _execute, stop_on_error=stop_on_error)
        # normalise per-item results to {op, ok, error_code} so an agent can
        # branch on stable fields (additive: index/action/summary unchanged)
        for item in summary["results"]:
            item.setdefault("op", item.get("action"))
            err = item.get("error")
            if isinstance(err, dict):
                item["error_code"] = err.get("code")
            else:
                item["error_code"] = None if item.get("ok") else ErrorCode.INTERNAL.value
        summary["session_id"] = session_id
        summary["confirm"] = confirm
        summary["confirm_code"] = confirm_code
        # write-risk summary (additive): aggregated from per-item ``risk`` fields
        risk_items = [r for r in summary["results"] if isinstance(r.get("risk"), str)]
        if risk_items:
            breakdown = {"high": 0, "normal": 0}
            for r in risk_items:
                breakdown[r["risk"]] = breakdown.get(r["risk"], 0) + 1
            summary["risk_breakdown"] = breakdown
        skipped_high = sum(1 for r in summary["results"]
                           if r.get("skipped_reason") == "high_risk_requires_confirm_code")
        if skipped_high:
            summary["skipped_high_risk"] = skipped_high
            summary["hint"] = (f"{skipped_high} 个高风险写操作被跳过（目标位于代码段/只读/未知区域）；"
                               "确认无误后加 confirm_code=true（CLI: --confirm-code）重跑可放行。")
        elif not confirm and summary.get("risk_breakdown", {}).get("high"):
            summary["hint"] = ("预览中存在高风险写操作（目标位于代码段/只读/未知区域）；"
                               "confirm=true 时这些项默认被跳过，需额外 confirm_code=true"
                               "（CLI: --confirm-code）才会写入。")
        if extra:
            summary.update(extra)
        # Persist the complete result set (pre-pagination) so an oversized
        # reply can always be recovered from disk without re-running the batch.
        summary["results_total"] = len(summary["results"])
        try:
            results_file = self.store.save_batch_result(session_id, summary)
        except Exception:
            results_file = None
        summary["results_file"] = results_file
        # windowed view: keep the reply small while the full data stays on disk
        if limit > 0 or offset > 0:
            summary["results"] = summary["results"][offset : offset + limit] if limit > 0 else summary["results"][offset:]
            summary["offset"] = offset
            summary["limit"] = limit
        return summary

    # ================================================================= macro
    @_session_op
    def macro_define(self, session_id: str, *, name: str, definition, description: str = "") -> dict:
        """Define a reusable parameterized macro.

        ``definition`` is a mapping or a YAML string with ``params`` (name ->
        {description, required, default}) and ``operations`` - a batch-runner
        compatible operation list using ``${param}`` placeholders. Operations
        are validated with the same rules as batch files (``validate_batch``).
        """

        self._load(session_id)  # validate the session exists
        if not name or not _MACRO_NAME_RE.match(name):
            raise InvalidArgsError(
                f"invalid macro name: {name!r}",
                details={"name": name},
                hint="Macro names may contain letters, digits, '_', '-' and '.' and must start with a letter, digit or '_'.",
            )
        if isinstance(definition, str):
            try:
                definition = yaml.safe_load(definition)
            except yaml.YAMLError as exc:
                raise InvalidArgsError(f"macro definition is not valid YAML: {exc}")
        if not isinstance(definition, dict):
            raise InvalidArgsError(
                "macro definition must be a mapping with an 'operations' list",
                hint="Provide params + operations, e.g. operations: [{read: {address: \"${base}\"}}]",
            )
        definition = dict(definition)
        try:
            batchmod.validate_batch({"operations": definition.get("operations")})
        except GameModifierError as exc:
            raise InvalidArgsError(
                f"invalid macro operations: {exc}",
                details=getattr(exc, "details", {}) or {},
                hint=f"Each operation must select exactly one action of {sorted(batchmod.STEP_KEYS)}.",
            )
        params_decl = definition.get("params")
        if params_decl is not None and not isinstance(params_decl, dict):
            raise InvalidArgsError("macro 'params' must be a mapping of name -> {description, required, default}")
        definition["name"] = name
        if description:
            definition["description"] = description
        definition.setdefault("description", "")
        path = self.store.save_macro(session_id, name, definition)
        return {
            "name": name,
            "path": str(path),
            "params": sorted((params_decl or {}).keys()),
            "operations": len(definition["operations"]),
            "description": definition["description"],
        }

    def macro_list(self, session_id: str) -> dict:
        """List all macros stored for the session (summary only)."""

        self._load(session_id)
        macros = []
        for mname in self.store.list_macros(session_id):
            data = self.store.load_macro(session_id, mname) or {}
            macros.append({
                "name": mname,
                "description": data.get("description", ""),
                "params": sorted((data.get("params") or {}).keys()),
                "operations": len(data.get("operations") or []),
            })
        return {"session_id": session_id, "count": len(macros), "macros": macros}

    def macro_show(self, session_id: str, *, name: str) -> dict:
        """Return the full definition of one macro."""

        self._load(session_id)
        data = self.store.load_macro(session_id, name)
        if data is None:
            raise InvalidArgsError(
                f"macro not found: {name!r}",
                details={"name": name, "known": self.store.list_macros(session_id)},
                hint="Use `macro list` to see defined macros, or `macro define` to create one.",
            )
        return {"session_id": session_id, "name": name, "definition": data}

    @_session_op
    def macro_run(self, session_id: str, *, name: str, params: Optional[dict] = None,
                  confirm: bool = False, stop_on_error: bool = True,
                  offset: int = 0, limit: int = 0, confirm_code: bool = False) -> dict:
        """Run a stored macro: substitute ``${param}`` then execute via the batch pipeline.

        - declared ``required`` params missing from ``params`` -> InvalidArgsError listing them
        - declared ``default`` values apply when the caller omits the param
        - write operations remain gated by ``confirm`` (dry-run by default)
        - results inherit batch_run persistence/pagination (``results_file``)
        - ``confirm_code`` inherits the batch_run write-risk grading: with
          ``confirm=True`` high-risk writes stay skipped unless it is set

        Built-in placeholders available in operations: ``${session}`` (the
        session id) and ``${i}`` (the operation index).
        """

        self._safety_write_gate(confirm, "macro_run")
        self._load(session_id)
        definition = self.store.load_macro(session_id, name)
        if definition is None:
            raise InvalidArgsError(
                f"macro not found: {name!r}",
                details={"name": name, "known": self.store.list_macros(session_id)},
                hint="Use `macro list` to see defined macros.",
            )
        decl = definition.get("params") or {}
        if not isinstance(decl, dict):
            raise InvalidArgsError(f"macro {name!r} has an invalid 'params' declaration")
        provided: dict = dict(params or {})
        missing: list[str] = []
        for pname, spec in decl.items():
            if pname in provided:
                continue
            spec = spec if isinstance(spec, dict) else {}
            if "default" in spec:
                provided[pname] = spec["default"]
            elif spec.get("required"):
                missing.append(pname)
        if missing:
            raise InvalidArgsError(
                f"missing required macro parameter(s): {', '.join(sorted(missing))}",
                details={"missing": sorted(missing), "declared": decl},
                hint="Supply them via params, e.g. --params base=0x100,count=5 (CLI) or params={'base': ...} (MCP).",
            )
        # built-ins available to every macro
        provided.setdefault("session", session_id)
        unresolved: set[str] = set()
        operations = []
        for idx, step in enumerate(definition.get("operations") or []):
            step_params = dict(provided)
            step_params.setdefault("i", idx)  # ${i} = operation index
            operations.append(self._sub_macro(step, step_params, unresolved))
        if unresolved:
            raise InvalidArgsError(
                f"unresolved macro placeholder(s): {', '.join(sorted(unresolved))}",
                details={"missing": sorted(unresolved)},
                hint="These ${param} placeholders have no declared default - pass them explicitly.",
            )
        summary = self._batch_execute(
            session_id, operations, confirm=confirm, stop_on_error=stop_on_error,
            offset=offset, limit=limit, confirm_code=confirm_code,
            extra={"macro": name,
                   "macro_params": {k: v for k, v in provided.items() if k != "session"}},
        )
        return summary

    @staticmethod
    def _sub_macro(node, params: dict, missing: set):
        """Recursively substitute ``${param}`` placeholders in a macro node.

        Mirrors ``templates.loader._sub_value``: a string that is exactly one
        placeholder gets the raw parameter value (non-strings preserved);
        embedded occurrences are spliced via ``str()``. Unknown keys are
        collected into ``missing``.
        """

        if isinstance(node, str):
            full = _MACRO_FULL_RE.match(node)
            if full:
                key = full.group(1)
                if key in params:
                    return params[key]
                missing.add(key)
                return node
            if _MACRO_PARAM_RE.search(node):
                def _repl(match):
                    key = match.group(1)
                    if key not in params:
                        missing.add(key)
                        return match.group(0)
                    return str(params[key])
                return _MACRO_PARAM_RE.sub(_repl, node)
            return node
        if isinstance(node, dict):
            return {k: ModifierService._sub_macro(v, params, missing) for k, v in node.items()}
        if isinstance(node, list):
            return [ModifierService._sub_macro(v, params, missing) for v in node]
        return node

    @_session_op
    def macro_delete(self, session_id: str, *, name: str) -> dict:
        """Remove a stored macro definition."""

        self._load(session_id)
        deleted = self.store.delete_macro(session_id, name)
        return {"session_id": session_id, "name": name, "deleted": deleted,
                "known": self.store.list_macros(session_id)}

    # ================================================================ backup
    @_session_op
    def backup_create(self, *, session_id: str, targets: list[dict], label: str = "") -> dict:
        session = self._load(session_id)
        backend = self._open(session)
        try:
            norm = []
            for t in targets:
                info = self._resolve_target(backend, session, symbol=t.get("symbol"), address=t.get("address"), offsets=t.get("offsets"), type=t.get("type"), mode=t.get("mode"))
                size = vt.type_size(info["type"]) or int(t.get("size", 8))
                norm.append({"address": info["final_address"], "size": size, "note": t.get("symbol") or ""})
            mgr = BackupManager(self.store.backups_dir(session.id))
            rec = mgr.create(backend, norm, label=label)
        finally:
            backend.close()
        return {"backup_id": rec["id"], "entries": len(rec["entries"])}

    def backup_list(self, *, session_id: str) -> dict:
        self._load(session_id)  # validate the session exists
        mgr = BackupManager(self.store.backups_dir(session_id))
        return {"session_id": session_id, "backups": mgr.list_backups()}

    @_session_op
    def backup_restore(self, *, session_id: str, backup_id: str) -> dict:
        session = self._load(session_id)
        backend = self._open(session)
        try:
            mgr = BackupManager(self.store.backups_dir(session.id))
            return mgr.restore(backend, backup_id)
        finally:
            backend.close()

    # ============================================================= toolchain
    def toolchain_detect(self) -> dict:
        return toolchain.detect_all(self.config)

    # ============================================================== sessions
    def list_sessions(self) -> dict:
        return {"sessions": self.store.list_sessions()}

    def session_info(self, *, session_id: str) -> dict:
        session = self._load(session_id)
        data = session.summary()
        data["engine"] = session.engine
        data["anti_cheat"] = session.anti_cheat
        data["symbols"] = sorted(session.symbols.keys())
        data["freezes"] = len(session.freezes)
        data["alive"] = procmod.process_exists(session.pid)
        return data

    def session_survey(self, *, session_id: str) -> dict:
        """One-call session reconnaissance report.

        Aggregates what ``attach`` -> ``analyze`` -> ``session_info`` would
        otherwise take three round-trips to collect: engine, top modules,
        named symbols, freezes, backups, toolchain availability and health.
        """

        session = self._load(session_id)
        modules = sorted(
            session.modules.items(),
            key=lambda kv: (kv[1] or {}).get("size") or 0,
            reverse=True,
        )
        try:
            backups = BackupManager(self.store.backups_dir(session_id)).list_backups()
        except Exception:
            backups = []
        try:
            tools = toolchain.detect_all(self.config)
            toolchain_available = tools.get("available")
        except Exception:
            toolchain_available = []
        return {
            "session_id": session_id,
            "summary": session.summary(),
            "engine": session.engine,
            "anti_cheat": session.anti_cheat,
            "alive": procmod.process_exists(session.pid),
            "module_count": len(session.modules),
            "modules_top": [dict(m, name=n) for n, m in modules[:10]],
            "symbols": sorted(session.symbols.keys()),
            "freezes": list(session.freezes),
            "backups": backups,
            "scan": {
                "count": session.scan.count,
                "type": session.scan.type,
                "truncated": session.scan.truncated,
            },
            "save_edit": session.save_edit_info,
            "toolchain_available": toolchain_available,
        }

    # ------------------------------------------------------ session snapshots
    @_session_op
    def session_snapshot(self, session_id: str, *, name: str) -> dict:
        """Save a named snapshot of the current session state (symbols, scan
        summary, engine verdict, ...). Snapshots are plain copies of the
        session JSON under ``sessions/<id>/snapshots/``."""

        self._load(session_id)
        try:
            path = self.store.save_snapshot(session_id, name)
        except ValueError as exc:
            raise InvalidArgsError(str(exc), details={"name": name})
        return {
            "session_id": session_id,
            "name": name,
            "path": str(path),
            "snapshots": self.store.list_snapshots(session_id),
        }

    def session_snapshots(self, session_id: str) -> dict:
        """List all snapshots stored for a session (read-only)."""

        self._load(session_id)
        return {"session_id": session_id, "snapshots": self.store.list_snapshots(session_id)}

    @_session_op
    def session_restore(self, session_id: str, *, name: str) -> dict:
        """Restore a snapshot over the current session state.

        The current state is archived to ``snapshots/<name>.pre-restore.json``
        before the restore, so a bad restore can be undone by restoring the
        ``<name>.pre-restore`` snapshot itself.
        """

        self._load(session_id)
        if not self.store.restore_snapshot(session_id, name):
            raise GameModifierError(
                f"snapshot not found: {name!r}",
                code=ErrorCode.INVALID_ARGS,
                details={"session_id": session_id,
                         "known": [e["name"] for e in self.store.list_snapshots(session_id)]},
                hint="Save a snapshot first: `session snapshot <name> --session <id>`.",
            )
        return {
            "session_id": session_id,
            "name": name,
            "restored": True,
            "pre_restore_backup": str(self.store.pre_restore_backup_path(session_id, name)),
            "note": "session state was rolled back; the game process may have moved on "
                    "(addresses/modules can drift) - re-run `attach`/`analyze` or re-validate "
                    "pointer chains before writing",
        }

    @_session_op
    def detach(self, *, session_id: str) -> dict:
        existed = self.store.delete(session_id)
        return {"session_id": session_id, "deleted": existed}

    # ============================================================= save edit
    def save_edit_detect(self, session_id: str) -> dict:
        session = self._load(session_id)
        engine_name = session.save_edit_info.get("engine") or session.engine.get("engine", "")
        game_dir = session.engine.get("game_dir") or session.exe_path
        from .save_edit import detect_saves
        saves = detect_saves(str(game_dir), engine_name)
        return {"saves": saves, "engine": engine_name}

    @_session_op
    def save_edit_modify(self, session_id: str, *, path: str, field: str, value,
                         confirm: bool = False, key=None, iv=None) -> dict:
        session = self._load(session_id)  # validate the session exists
        self._check_file_path(path, session=session, purpose="save_edit_modify")
        from .save_edit import modify_save
        # key/iv are forwarded in memory only (Unity encrypted saves); they are
        # deliberately excluded from the audit record and session state.
        result = modify_save(path, field, value, confirm=confirm, key=key, iv=iv)
        if confirm and result.get("ok") and result.get("applied"):
            self._audit_log(session, "save_edit_modify",
                            {"path": path, "field": field, "value": value}, result)
        return result

    # ================================================================= audit
    def _audit_log(self, session: Session, op: str, args: dict, result: dict) -> None:
        """Append one JSONL record to ``sessions/<id>/audit.jsonl``.

        Best-effort: a write failure here never blocks the main operation.
        """

        try:
            entry = {
                "ts": time.time(),
                "op": op,
                "args": args,
                "ok": bool(result.get("ok", True)),
                "backup_id": result.get("backup_id"),
            }
            path = self.store.audit_path(session.id)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except Exception:
            pass

    def audit_tail(self, *, session_id: str, limit: int = 50) -> dict:
        """Return the most recent audit entries (newest last)."""

        self._load(session_id)  # validate the session exists
        path = self.store.audit_path(session_id)
        entries: list[dict] = []
        if path.exists():
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        continue
            except Exception:
                pass
        limit = max(1, int(limit))
        return {"session_id": session_id, "count": len(entries), "entries": entries[-limit:]}

    # ======================================================== results_read ==
    # Hard cap on a single results_read payload (chars, post-window). Keeps
    # the reply far below the MCP layer's own 50k-char throttle.
    _RESULTS_READ_MAX_CHARS = 40000
    # Files larger than this are refused outright - they are almost always a
    # mistake (binary sidecars, multi-MB dumps); page a smaller artifact or
    # use scan_candidates-style dedicated tools instead.
    _RESULTS_READ_MAX_BYTES = 32 * 1024 * 1024

    def _session_file_resolve(self, session_id: str, path: str) -> Path:
        """Resolve ``path`` against the session directory, refusing escapes.

        Absolute paths and ``..`` segments are fine syntactically, but the
        fully resolved target MUST stay inside ``sessions/<id>/`` (results_read
        is a read-back channel for session-owned artifacts, not a general
        file-read tool). Symlinks are resolved before the containment check.
        """

        root = (self.store.dir / session_id).resolve()
        raw = Path(str(path).strip())
        if not str(path).strip():
            raise InvalidArgsError("results_read requires a non-empty path")
        candidate = raw if raw.is_absolute() else (root / raw)
        resolved = candidate.resolve()
        if resolved != root and root not in resolved.parents:
            raise PathNotAllowedError(
                f"path is outside the session directory: {path!r}",
                details={"session_dir": str(root), "resolved": str(resolved)},
                hint="results_read 只能读取该会话 sessions/<id>/ 目录下的产物文件"
                     "（il/、batch_results/、jobs/、snapshots/、scan_results/ 等）。",
            )
        return resolved

    def results_read(self, session_id: str, *, path: str, offset: int = 0,
                     limit: int = 400) -> dict:
        """Read back a persisted result file that belongs to this session (read-only).

        Many tools spill their full payload to disk and return only a summary
        (``il_dump``/``il_analyze``/``il_callers`` -> ``sessions/<id>/il/``,
        ``batch_run`` -> ``batch_results/``, background jobs -> ``jobs/``,
        scans -> ``scan_results/``). A pure-MCP client has no host file tool,
        so this is the sanctioned read-back channel: pass the ``out_file`` /
        ``results_file`` value (absolute or relative to the session dir),
        page with ``offset``/``limit`` (lines), and never touch anything
        outside ``sessions/<id>/`` (refused with ``E_PATH_NOT_ALLOWED``).
        """

        self._load(session_id)  # validate the session exists
        resolved = self._session_file_resolve(session_id, path)
        root = (self.store.dir / session_id).resolve()
        if not resolved.is_file():
            available: list[str] = []
            if root.is_dir():
                for f in sorted(root.rglob("*")):
                    if f.is_file():
                        try:
                            available.append(str(f.relative_to(root)))
                        except ValueError:
                            continue
                    if len(available) >= 50:
                        break
            raise InvalidArgsError(
                f"no such file in session directory: {path!r}",
                details={"session_dir": str(root), "available": available},
                hint="从工具的 out_file / results_file 字段取得路径；available 列出了该会话现有的产物文件。",
            )
        size = resolved.stat().st_size
        if size > self._RESULTS_READ_MAX_BYTES:
            raise InvalidArgsError(
                f"file too large to read back ({size} bytes > {self._RESULTS_READ_MAX_BYTES})",
                details={"path": str(resolved), "size": size},
                hint="该文件超过 32MB（通常是二进制 sidecar）。大结果请用专用分页工具"
                     "（scan_candidates / batch_run offset+limit）或缩小产物规模。",
            )
        text = resolved.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        total_lines = len(lines)
        offset = max(0, int(offset))
        limit = int(limit)
        window = lines[offset: offset + limit] if limit > 0 else lines[offset:]
        body = "\n".join(window)
        truncated = False
        if len(body) > self._RESULTS_READ_MAX_CHARS:
            body = body[: self._RESULTS_READ_MAX_CHARS]
            truncated = True
        rel = str(resolved.relative_to(root)) if root in resolved.parents or resolved == root else str(resolved)
        out: dict[str, Any] = {
            "session_id": session_id,
            "path": str(resolved),
            "session_relative_path": rel,
            "size_bytes": size,
            "total_lines": total_lines,
            "offset": offset,
            "returned_lines": len(window),
            "content": body,
        }
        if truncated:
            out["truncated"] = True
            out["preview_note"] = (f"窗口超过 {self._RESULTS_READ_MAX_CHARS} 字符被截断；"
                                   "减小 limit 或用 offset 分页。")
        if offset + len(window) < total_lines:
            out["has_more"] = True
            out["next_offset"] = offset + len(window)
        return out

    # ================================================================= notes
    def _read_notes(self, session_id: str) -> dict:
        """Replay ``sessions/<id>/notes.jsonl`` into the effective key->value map."""

        notes: dict = {}
        path = self.store.notes_path(session_id)
        if path.exists():
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except Exception:
                        continue
                    key = entry.get("key")
                    if not key:
                        continue
                    if entry.get("op") == "delete":
                        notes.pop(str(key), None)
                    else:
                        notes[str(key)] = entry.get("value")
            except Exception:
                pass
        return notes

    def _append_note(self, session_id: str, entry: dict) -> None:
        """Append one JSONL record to ``notes.jsonl`` (audit.jsonl pattern)."""

        entry = {"ts": time.time(), **entry}
        path = self.store.notes_path(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")

    @_session_op
    def session_notes(self, *, session_id: str, action: str = "get",
                      key: Optional[str] = None, value=None) -> dict:
        """Per-session key/value notes stored as append-only JSONL.

        Storage lives in ``sessions/<id>/notes.jsonl`` (audit.jsonl style) -
        deliberately OUTSIDE the session JSON so a note edit never rewrites
        the whole session file.

        - ``get`` (read-only): omit ``key`` for every note, or pass one key.
        - ``set``: appends an entry; a later ``set`` on the same key wins.
        - ``delete``: appends a tombstone; deleting a missing key returns
          ``not_found=true`` instead of raising.
        """

        self._load(session_id)  # validate the session exists
        act = str(action or "get").strip().lower()
        if act not in ("get", "set", "delete"):
            raise InvalidArgsError(
                f"unknown session_notes action: {action!r}",
                details={"supported": ["get", "set", "delete"]},
            )
        notes = self._read_notes(session_id)
        if act == "get":
            if key is None:
                return {"session_id": session_id, "action": "get",
                        "notes": notes, "count": len(notes)}
            k = str(key)
            return {"session_id": session_id, "action": "get", "key": k,
                    "found": k in notes, "value": notes.get(k)}
        if key is None or str(key).strip() == "":
            raise InvalidArgsError(
                "session_notes set/delete requires a non-empty key",
                details={"action": act},
            )
        k = str(key)
        if act == "set":
            self._append_note(session_id, {"key": k, "value": value})
            notes[k] = value
            return {"session_id": session_id, "action": "set", "key": k,
                    "value": value, "count": len(notes)}
        # delete
        existed = k in notes
        self._append_note(session_id, {"key": k, "op": "delete"})
        if existed:
            notes.pop(k, None)
        return {"session_id": session_id, "action": "delete", "key": k,
                "deleted": existed, "not_found": not existed, "count": len(notes)}

    # ======================================================= layout analysis
    def layout_analyze(self, session_id: str, *, module: Optional[str] = None, what: str = "vtables", address: Optional[str] = None) -> dict:
        """Memory layout analysis: vtables / RTTI class names / class layout.

        ``what='class'`` requires ``address`` (a vtable address, e.g. from a
        previous ``what='vtables'`` run). All operations are read-only.
        """

        session = self._load(session_id)
        backend = self._open(session)
        try:
            if what == "vtables":
                data = find_vtables(backend, module_name=module)
            elif what == "rtti":
                data = find_rtti_classes(backend)
            elif what == "class":
                if not address:
                    raise GameModifierError(
                        "layout --what class requires a vtable address",
                        code=ErrorCode.INVALID_ARGS,
                        hint="Pass --address 0x... (a vtable candidate from `layout --what vtables`).",
                    )
                data = infer_class_layout(backend, pointers.parse_int(address))
            else:
                raise GameModifierError(
                    f"unknown layout analysis: {what!r}",
                    code=ErrorCode.INVALID_ARGS,
                    details={"supported": ["vtables", "rtti", "class", "heap"]},
                )
        finally:
            backend.close()
        data["what"] = what
        return data

    def heap_scan(self, session_id: str, *, vtable_addr: Optional[str] = None, max_results: int = 500) -> dict:
        """Enumerate heap object candidates, optionally filtered by vtable."""

        session = self._load(session_id)
        backend = self._open(session)
        try:
            vt_addr = pointers.parse_int(vtable_addr) if vtable_addr else None
            return scan_heap_objects(backend, vtable_addr=vt_addr, max_results=max_results)
        finally:
            backend.close()

    def dissect(self, session_id: str, *, address: Optional[str] = None,
                addresses=None, size: int = 256) -> dict:
        """Auto-dissect an object structure from one or more instance addresses.

        ``address`` / ``addresses`` accept session symbol names, hex/decimal
        addresses or ``module+0x..`` expressions (``addresses`` may be a list
        or a comma-separated string). Field types are inferred heuristically
        at pointer-aligned offsets; multi-instance input raises confidence.
        Read-only throughout.
        """

        exprs: list[str] = []
        if address:
            exprs.append(str(address).strip())
        if isinstance(addresses, str):
            exprs.extend(p.strip() for p in addresses.split(",") if p.strip())
        elif addresses:
            exprs.extend(str(p).strip() for p in addresses if str(p).strip())
        exprs = list(dict.fromkeys(e for e in exprs if e))
        if not exprs:
            raise InvalidArgsError(
                "dissect requires --address or --addresses",
                hint="Pass one or more instance addresses of the same class.",
            )

        session = self._load(session_id)
        backend = self._open(session)
        try:
            addrs: list[int] = []
            for expr in exprs:
                base_expr = expr
                sym = session.get_symbol(expr)
                if sym is not None:
                    base_expr = sym.base_expr
                addrs.append(pointers.resolve_base(backend, base_expr).address)
            result = dissect_structure(backend, addrs, size=int(size))
        finally:
            backend.close()
        result["session_id"] = session_id
        return result

    @_session_op
    def pointer_scan(self, session_id: str, *, address: str, max_depth: Optional[int] = None, max_paths: Optional[int] = None) -> dict:
        """Reverse pointer-path discovery towards ``address``.

        Limits default to the ``[analysis]`` config section
        (pointer_scan_max_depth / pointer_scan_max_paths / scan_timeout).
        Discovered paths are persisted to the session's ``pointer_paths.bin``
        sidecar (for later ``pointer_rescan``); above
        ``_POINTER_PATHS_INLINE_LIMIT`` the reply only carries a sample.
        """

        session = self._load(session_id)
        backend = self._open(session)
        try:
            target = pointers.parse_int(address)
            result = find_pointer_paths(
                backend,
                target,
                max_depth=max_depth if max_depth is not None else self.config.pointer_scan_max_depth,
                max_paths=max_paths if max_paths is not None else self.config.pointer_scan_max_paths,
                timeout=float(self.config.scan_timeout),
            )
        finally:
            backend.close()
        paths = result.get("paths") or []
        if paths:
            self.store.write_pointer_paths(session_id, paths)
            session.pointer_scan_meta = {
                "count": len(paths),
                "created_at": time.time(),
                "file": self.store.pointer_paths_path(session_id).name,
                "address": hex(target),
            }
            self.store.save(session)
        if len(paths) > _POINTER_PATHS_INLINE_LIMIT:
            sample = paths[:_POINTER_PATHS_SAMPLE]
            result["paths"] = sample
            result["paths_file"] = True
            result["paths_sample"] = sample
            result["paths_total"] = len(paths)
        return result

    def pointer_rescan(self, session_id: str, *, address: str, timeout: Optional[float] = None) -> dict:
        """Re-validate the session's saved pointer paths against ``address``.

        Loads paths from the ``pointer_paths.bin`` sidecar, drops stale ones
        via :func:`rescan_paths`, then persists the survivors and updates
        ``pointer_scan_meta``. Raises ``E_LAYOUT_UNSUPPORTED`` when the
        session has no saved paths yet.
        """

        session = self._load(session_id)
        paths = self.store.read_pointer_paths(session_id)
        if not paths:
            raise LayoutUnsupportedError(
                "no saved pointer paths for this session",
                details={"session_id": session_id},
                hint="run `pointer-scan --session <id> --address 0x...` first, then rescan",
            )
        backend = self._open(session)
        try:
            target = pointers.parse_int(address)
            result = rescan_paths(backend, paths, target, timeout=float(timeout if timeout is not None else self.config.scan_timeout))
        finally:
            backend.close()
        # keep only surviving paths in the sidecar; refresh the summary
        self.store.write_pointer_paths(session_id, result["paths"])
        meta = dict(session.pointer_scan_meta or {})
        meta.update({
            "count": result["valid_count"],
            "updated_at": time.time(),
            "file": self.store.pointer_paths_path(session_id).name,
            "address": hex(target),
        })
        session.pointer_scan_meta = meta
        self.store.save(session)
        result["session_id"] = session_id
        result["rescanned"] = len(paths)
        return result

    # ======================================================= background jobs
    @_session_op
    def pointer_scan_async(self, session_id: str, *, address: str,
                           max_depth: Optional[int] = None, max_paths: Optional[int] = None,
                           timeout: Optional[float] = None) -> dict:
        """Start a pointer scan in a background job; returns immediately.

        Unlike the synchronous :meth:`pointer_scan` there is no 30s hard
        timeout by default (``timeout`` is an optional upper bound; ``None``
        means unbounded). Results are persisted to
        ``sessions/<id>/jobs/<job_id>.json`` so partial work survives even
        when the scan is cancelled. Poll :meth:`job_status` with the
        returned ``job_id``; :meth:`job_cancel` stops the scan gracefully.
        """

        session = self._load(session_id)
        target = pointers.parse_int(address)
        depth = max_depth if max_depth is not None else self.config.pointer_scan_max_depth
        paths_cap = max_paths if max_paths is not None else self.config.pointer_scan_max_paths
        time_budget = float(timeout) if timeout is not None else float("inf")

        job_id = JOBS.new_id()
        persist_path = self.store.jobs_dir(session_id) / f"{job_id}.json"

        def _worker(progress, cancel):
            backend = self._open(session)
            try:
                result = find_pointer_paths(
                    backend,
                    target,
                    max_depth=depth,
                    max_paths=paths_cap,
                    timeout=time_budget,
                    progress_cb=progress,
                    cancel_cb=cancel,
                )
            finally:
                backend.close()
            # same persistence as the sync scan so pointer_rescan can reuse
            # the discovered paths (partial results included on cancellation)
            found = result.get("paths") or []
            if found:
                self.store.write_pointer_paths(session_id, found)
                meta = {
                    "count": len(found),
                    "created_at": time.time(),
                    "file": self.store.pointer_paths_path(session_id).name,
                    "address": hex(target),
                    "job_id": job_id,
                    "cancelled": bool(result.get("cancelled")),
                }
                # the worker may have run for minutes while other ops mutated
                # the session - merge into a fresh copy under the lock instead
                # of overwriting with this stale object (lost-update fix, F3).
                try:
                    with self.store.locked(session_id):
                        fresh = self.store.load(session_id, restore_candidates=False)
                        fresh.pointer_scan_meta = meta
                        self.store.save(fresh)
                except GameModifierError:
                    pass  # session deleted mid-scan: keep the sidecar results
            return result

        job = JOBS.submit("pointer_scan", session_id, _worker,
                          persist_path=persist_path, job_id=job_id)
        return {
            "job_id": job.id,
            "status": job.status,
            "session_id": session_id,
            "address": hex(target),
            "hint": "poll with job_status; cancel with job_cancel",
        }

    def job_status(self, job_id: str, *, session_id: Optional[str] = None) -> dict:
        """Query a background job's status/progress/results.

        - running   -> ``{"status": "running", "progress": {...}}``
        - done      -> ``{"status": "done", "results_file", "paths_total", "paths_sample"}``
        - failed/cancelled -> status + error (partial results persisted too)

        When the in-process registry no longer knows the id (e.g. the
        process was restarted), a persisted result file under
        ``sessions/<session_id>/jobs/`` is served as ``done``.
        """

        job = JOBS.get(job_id)
        if job is None:
            if session_id:
                path = self.store.jobs_dir(session_id) / f"{job_id}.json"
                if path.exists():
                    out = {"job_id": job_id, "session_id": session_id,
                           "status": "done", "results_file": str(path)}
                    out.update(self._summarise_job_results(path))
                    return out
            raise GameModifierError(
                f"unknown job: {job_id!r}",
                code=ErrorCode.INVALID_ARGS,
                hint="List jobs with `job list [--session <id>]`; jobs are in-process "
                     "(a restarted server only knows jobs started since it came up).",
            )

        out = {
            "job_id": job.id,
            "kind": job.kind,
            "session_id": job.session_id,
            "status": job.status,
            "created_at": job.created_at,
            "finished_at": job.finished_at,
        }
        if job.status in ("pending", "running"):
            out["progress"] = dict(job.progress)
        if job.error:
            out["error"] = job.error
        if job.status in ("done", "cancelled") and job.results_file:
            out["results_file"] = job.results_file
            out.update(self._summarise_job_results(Path(job.results_file)))
        return out

    @staticmethod
    def _summarise_job_results(path: Path) -> dict:
        """Compact summary of a persisted job result file (never raises)."""

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {"results_note": "result file unreadable"}
        if not isinstance(data, dict):
            return {"result": data}
        out: dict = {}
        paths = data.get("paths")
        if isinstance(paths, list):
            out["paths_total"] = len(paths)
            out["paths_sample"] = paths[:_POINTER_PATHS_SAMPLE]
        for key in ("truncated", "cancelled", "elapsed", "confidence"):
            if key in data:
                out[key] = data[key]
        return out

    def job_cancel(self, job_id: str) -> dict:
        """Request cooperative cancellation of a running job.

        The worker observes the flag at its next checkpoint and persists its
        partial results before finishing with status ``cancelled``.
        """

        job = JOBS.get(job_id)
        if job is None:
            raise GameModifierError(
                f"unknown job: {job_id!r}",
                code=ErrorCode.INVALID_ARGS,
                hint="List jobs with `job list [--session <id>]`.",
            )
        requested = JOBS.cancel(job_id)
        return {
            "job_id": job_id,
            "cancel_requested": requested,
            "status": job.status,
            "note": None if requested else "job already finished; nothing to cancel",
        }

    def job_list(self, session_id: Optional[str] = None) -> dict:
        """List background jobs (optionally filtered by session)."""

        jobs = JOBS.list(session_id)
        return {"count": len(jobs), "jobs": [j.to_dict() for j in jobs]}

    # ====================================================== UE introspection
    def _ue_cfg(self) -> dict:
        """Defaults from the ``[ue]`` config section."""

        return {
            "item_stride": int(self.config.get("ue", "item_stride", default=24)),
            "objects_per_chunk": int(self.config.get("ue", "objects_per_chunk", default=65536)),
            "max_chunks": int(self.config.get("ue", "max_chunks", default=512)),
            "probe_items": int(self.config.get("ue", "probe_items", default=64)),
            "max_objects": int(self.config.get("ue", "max_objects", default=100000)),
            "batch_gap": int(self.config.get("ue", "batch_gap", default=256)),
        }

    @staticmethod
    def _ue_engine_warning(session: Session) -> Optional[str]:
        engine = (session.engine or {}).get("engine")
        if engine != engines.UNREAL:
            return f"session engine is {engine!r}, not 'unreal'; UE introspection results may not apply"
        return None

    @_session_op
    def ue_introspect(self, session_id: str, *, gobjects=None, gnames=None,
                      gobjects_pattern=None, gnames_pattern=None, force: bool = False) -> dict:
        """Probe UE GObjects/FNamePool layouts (read-only) and cache the result.

        ``gobjects`` / ``gnames`` accept ``Module.exe+0x...`` expressions or
        bare addresses. A confirmed verdict is cached in the session and
        served directly on later calls unless ``force`` re-probes.
        """

        session = self._load(session_id)
        cached = session.introspect.get("ue")
        if cached and cached.get("verdict") == "confirmed" and not force:
            out = dict(cached)
            out["cached"] = True
            out["session_id"] = session_id
            warn = self._ue_engine_warning(session)
            if warn:
                out["engine_warning"] = warn
            return out

        cfg = self._ue_cfg()
        backend = self._open(session)
        try:
            g_addr = pointers.resolve_base(backend, gobjects).address if gobjects else None
            n_addr = pointers.resolve_base(backend, gnames).address if gnames else None
            res = engines.ue_introspect.introspect(
                backend, gobjects=g_addr, gnames=n_addr,
                gobjects_pattern=gobjects_pattern, gnames_pattern=gnames_pattern,
                item_stride=cfg["item_stride"], probe_items=cfg["probe_items"],
                timeout=float(self.config.scan_timeout),
                objects_per_chunk=cfg["objects_per_chunk"], max_chunks=cfg["max_chunks"],
            )
        finally:
            backend.close()

        if res.get("verdict") != "failed":
            session.introspect["ue"] = {
                "resolved": res.get("resolved", {}),
                "hypotheses": res.get("hypotheses", {}),
                "verdict": res.get("verdict"),
                "confidence": res.get("confidence"),
                "created_at": time.time(),
            }
            self.store.save(session)
        out = dict(res)
        out["session_id"] = session_id
        warn = self._ue_engine_warning(session)
        if warn:
            out["engine_warning"] = warn
        return out

    def ue_actors(self, session_id: str, *, gobjects=None, limit: int = 100,
                  name_filter=None, class_filter=None, list_results: bool = False) -> dict:
        """Enumerate UE Actor instances over GObjects (read-only).

        Layout source priority: explicit ``gobjects`` (temporary probe, the
        cached GNames dialect is reused for name decoding when available) >
        the ``session.introspect['ue']`` cache.
        """

        session = self._load(session_id)
        cached = session.introspect.get("ue")
        if not gobjects and not cached:
            raise LayoutUnsupportedError(
                "no UE layout available for this session",
                details={"session_id": session_id},
                hint="run `ue introspect` first (or pass --gobjects explicitly)",
            )
        cfg = self._ue_cfg()
        backend = self._open(session)
        try:
            if gobjects:
                addr = pointers.resolve_base(backend, gobjects).address
                layout = engines.ue_introspect.introspect(
                    backend, gobjects=addr,
                    item_stride=cfg["item_stride"], probe_items=cfg["probe_items"],
                    timeout=float(self.config.scan_timeout),
                    objects_per_chunk=cfg["objects_per_chunk"], max_chunks=cfg["max_chunks"],
                )
                # reuse the cached FNamePool dialect so names still decode
                fname_hyp = (cached or {}).get("hypotheses", {}).get("fname_pool")
                own = (layout.get("hypotheses", {}).get("fname_pool") or {}).get("chosen")
                if fname_hyp and not own:
                    layout.setdefault("hypotheses", {})["fname_pool"] = fname_hyp
            else:
                layout = cached
            res = engines.ue_introspect.enumerate_actors(
                backend, layout,
                limit=int(limit), name_filter=name_filter, class_filter=class_filter,
                timeout=float(self.config.scan_timeout),
                max_objects=cfg["max_objects"], batch_gap=cfg["batch_gap"],
                list_results=bool(list_results),
            )
        finally:
            backend.close()
        res["session_id"] = session_id
        return res

    def ue_fname(self, session_id: str, *, address=None, index=None, compare_index=None) -> dict:
        """Read / decode / compare FName handles (read-only).

        ``address`` reads the raw 8-byte handle (decoded too when a cached
        GNames layout exists); ``index`` decodes a name-pool index (requires
        the cached GNames layout); ``compare_index`` + ``index`` compares two
        indices by the pure-integer rule.
        """

        session = self._load(session_id)
        if address is None and index is None:
            raise GameModifierError(
                "ue fname requires --address or --index",
                code=ErrorCode.INVALID_ARGS,
                hint="Pass --address 0x... to read a FName struct, or --index N to decode a name-pool index.",
            )
        cached = session.introspect.get("ue")
        out: dict[str, Any] = {"session_id": session_id}
        backend = self._open(session)
        try:
            if address is not None:
                addr = pointers.resolve_base(backend, address).address
                handle = engines.ue_introspect.read_fname(backend, addr)
                out["address_hex"] = hex(addr)
                out["comparison_index"] = handle["comparison_index"]
                out["number"] = handle["number"]
                if cached:
                    try:
                        out["decoded"] = engines.ue_introspect.decode_fname(
                            backend, cached, handle["comparison_index"])
                    except Exception:
                        pass
            if index is not None:
                fname_hyp = (cached or {}).get("hypotheses", {}).get("fname_pool") or {}
                if not cached or not fname_hyp.get("chosen"):
                    raise LayoutUnsupportedError(
                        "no cached GNames layout to decode an FName index",
                        details={"session_id": session_id},
                        hint="run `ue introspect --gnames ...` first",
                    )
                out["index"] = int(index)
                out["decoded"] = engines.ue_introspect.decode_fname(backend, cached, int(index))
                if compare_index is not None:
                    cmp = engines.ue_introspect.compare_fname(
                        {"comparison_index": int(index)},
                        {"comparison_index": int(compare_index)},
                    )
                    out["compare"] = {"index": int(index), "compare_index": int(compare_index), **cmp}
                    try:
                        out["compare"]["decoded_other"] = engines.ue_introspect.decode_fname(
                            backend, cached, int(compare_index))
                    except Exception:
                        pass
        finally:
            backend.close()
        return out

    # ================================================================ disasm
    def disasm(self, session_id: str, *, address: str, size: int = 256,
               arch: str = None, blocks: bool = False) -> dict:
        """Disassemble code at ``address`` (read-only; requires capstone).

        ``address`` accepts a session symbol name, a hex/decimal address or a
        ``module+0x..`` expression. ``blocks=True`` splits the stream into
        basic blocks instead of returning a flat instruction list.
        """

        session = self._load(session_id)
        backend = self._open(session)
        try:
            base_expr = address
            sym = session.get_symbol(address) if isinstance(address, str) else None
            if sym is not None:
                base_expr = sym.base_expr
            addr = pointers.resolve_base(backend, base_expr).address
            if blocks:
                out = basic_blocks(backend, addr, size=int(size))
            else:
                out = disassemble(backend, addr, size=int(size), arch=arch)
        finally:
            backend.close()
        out["session_id"] = session_id
        return out

    # ================================================================ xrefs
    def xrefs(self, session_id: str, *, address: str, direction: str = "to",
              binary: str = None, aligned: bool = True, fallback: bool = True) -> dict:
        """Query cross-references for an address (read-only).

        Primary path: radare2 static analysis of the on-disk binary
        (``backend_kind='radare2'``; behavior frozen). When radare2 is
        unavailable or fails and ``fallback=true`` (default), a pure-Python
        live-memory scan answers "who holds a pointer to this address"
        (``backend='python'``): every readable region is searched for 4/8-byte
        slots equal to the runtime address, with a 4/8-byte alignment filter
        by default (``aligned=false`` disables it, more hits, more noise) and
        per-hit region labels (image vs heap vs mapped).

        ``address`` accepts a hex/decimal address or a ``module+0x..``
        expression; runtime absolute addresses are converted to RVAs using
        the session module table (r2 analyzes the on-disk binary). ``binary``
        overrides the target binary path (default: the session exe).
        """

        if direction not in ("to", "from"):
            raise InvalidArgsError(
                f"unknown xref direction: {direction!r}",
                details={"supported": ["to", "from"]},
            )
        session = self._load(session_id)  # module table only - no backend open

        # resolve the expression against the session module table
        expr = str(address).strip()
        sym = session.get_symbol(expr)
        if sym is not None:
            expr = sym.base_expr

        norm = {name.lower(): (name, info) for name, info in session.modules.items()}

        def _module_for(token: str):
            key = token.lower()
            for cand in (key, key + ".dll", key + ".exe"):
                if cand in norm:
                    return norm[cand]
            return None

        module_name: Optional[str] = None
        rva: Optional[int] = None
        abs_addr: Optional[int] = None  # runtime address for the python fallback
        plus = expr.find("+")
        head = expr[:plus].strip() if plus != -1 else expr
        tail = expr[plus + 1:].strip() if plus != -1 else ""

        if head.lower().startswith("0x") or head.lstrip("-").isdigit():
            addr = pointers.parse_int(head) + (pointers.parse_int(tail) if tail else 0)
            abs_addr = addr
            # absolute runtime address -> RVA by subtracting the owning base
            for name, info in session.modules.items():
                base = int(info.get("base", 0))
                size = int(info.get("size", 0))
                if base and base <= addr < base + max(size, 1):
                    module_name, rva = name, addr - base
                    break
            if rva is None:
                rva = addr  # unmapped: pass through as-is
        else:
            found = _module_for(head)
            if not found:
                raise InvalidArgsError(
                    f"module not found: {head!r}",
                    details={"module": head, "known_modules": sorted(session.modules)[:40]},
                )
            module_name, info = found
            base = int(info.get("base", 0))
            rva = pointers.parse_int(tail) if tail else 0
            abs_addr = base + rva

        bin_path = binary or session.exe_path

        def _python_fallback(reason: str) -> dict:
            """Live-memory pointer-slot scan (read-only, no radare2 needed)."""

            target = abs_addr if abs_addr is not None else rva
            workers = self.config.scan_workers
            backend = self._open(session)
            try:
                arch = getattr(getattr(backend, "info", None), "arch", "x64") or "x64"
                fb = xrefs_fallback.find_xrefs(
                    backend, int(target), arch=arch, aligned=bool(aligned),
                    workers=workers,
                    backend_factory=(lambda: self._open(session)) if workers > 1 else None,
                )
            finally:
                backend.close()
            res = {
                "backend": "python",
                "backend_kind": "python",
                "session_id": session_id,
                "address": hex(int(target)),
                "direction": direction,
                **fb,
                "fallback_reason": reason,
                "hint": ("纯 Python 内存扫描兜底：列出所有持有该地址的 4/8 字节槽位；"
                         "region 标注区分 image（代码/数据段）与 heap（私有堆区）。"
                         "误报偏多时保持 aligned=true（默认）。"),
            }
            if module_name:
                res["module"] = module_name
            if rva is not None:
                res["rva"] = hex(rva)
            if bin_path:
                res["binary"] = bin_path
            return res

        if bin_path:
            try:
                tools = toolchain.detect_all(self.config)
                r2_path = self.config.tool_path("radare2") or \
                    (tools["tools"].get("radare2", {}) or {}).get("path")
                res = toolchain.radare2.xrefs_at(bin_path, rva, direction=direction, r2_path=r2_path)
            except Exception as exc:
                if not fallback:
                    raise
                return _python_fallback(f"{type(exc).__name__}: {exc}")
            # additive classification; the frozen backend field (r2pipe/
            # subprocess) is preserved untouched
            res["backend_kind"] = "radare2"
            res["session_id"] = session_id
            res["binary"] = bin_path
            if module_name:
                res["module"] = module_name
            res["rva"] = hex(rva)
            return res

        if fallback:
            return _python_fallback("no binary path available for radare2 analysis")
        raise InvalidArgsError(
            "no binary to analyze",
            hint="Pass --binary <path> or attach a session with a known exe path.",
        )


    # ====================================================== il2cpp (Unity) ==
    _STALE_DUMP_HINT = (
        "游戏二进制已变化（可能已更新），RVA 可能失效。建议重跑 il2cpp dump。"
    )

    def _il2cpp_target_binary(self, session: Session) -> Optional[str]:
        """Locate the binary an il2cpp dump is keyed against.

        Preference order: GameAssembly.dll from engine artifacts (found by
        ``analyze``), then a ``GameAssembly.dll`` module from the session's
        module map, then the main executable. Returns only paths that exist
        on disk (``None`` otherwise) so callers can fingerprint/validate
        safely.
        """

        arts = (session.engine or {}).get("artifacts", {}) or {}
        candidates: list[str] = []
        if arts.get("game_assembly"):
            candidates.append(str(arts["game_assembly"]))
        for name, m in (session.modules or {}).items():
            if name.lower() == "gameassembly.dll":
                mp = (m or {}).get("path")
                if mp:
                    candidates.append(str(mp))
        if session.exe_path:
            candidates.append(str(session.exe_path))
        for c in candidates:
            if c and Path(c).exists():
                return c
        return None

    def _dump_stale_info(self, session: Session) -> Optional[dict]:
        """Freshness check for the session's il2cpp dump; ``None`` when there
        is nothing to check (no dump / no fingerprint / binary not locatable)
        or the dump is still fresh."""

        arts = (session.engine or {}).get("artifacts", {}) or {}
        fp = arts.get("binary_fingerprint")
        if not (arts.get("script_json") and fp):
            return None
        bin_path = self._il2cpp_target_binary(session)
        if not bin_path:
            return None
        fresh = unity_lookup.check_dump_freshness(bin_path, fp)
        if fresh.get("fresh"):
            return None
        return {"reason": fresh.get("reason"), "binary": bin_path,
                "hint": self._STALE_DUMP_HINT}

    def _file_hash_stale_info(self, session: Session, path: Optional[str] = None) -> Optional[dict]:
        """Steam-update detection for files recorded by ``file_snapshot``.

        Mirrors :meth:`_dump_stale_info`: advisory only, never blocks. When
        the session carries a ``file_hashes`` artifact and the on-disk file's
        fingerprint (size/mtime/head-hash) no longer matches the snapshot,
        returns ``{"reason", "path", "recorded_sha256", "hint"}`` so callers
        can attach a non-blocking ``stale_warning``.
        """

        arts = (session.engine or {}).get("artifacts", {}) or {}
        fhs = arts.get("file_hashes") or {}
        if not fhs:
            return None
        want = str(Path(str(path))) if path else None
        for key, rec in fhs.items():
            if want and str(Path(key)) != want:
                continue
            if not (rec and Path(key).exists()):
                continue
            fresh = unity_lookup.check_dump_freshness(key, rec.get("fingerprint") or {})
            if fresh.get("fresh"):
                continue
            return {
                "reason": fresh.get("reason"),
                "path": key,
                "recorded_sha256": rec.get("sha256"),
                "hint": ("该文件在 file_snapshot 之后发生了变化（可能是游戏/平台更新）。"
                         "相关分析结果可能已过时，必要时重新 file_snapshot 并复查。"),
            }
        return None

    def il2cpp_lookup(self, session_id: str, *, rva: str, script_json: str = None,
                      tolerance=0, force_index: bool = False,
                      force: bool = False) -> dict:
        """Reverse-map an RVA to its IL2CPP method name via the dump's index.

        ``rva`` accepts a hex/decimal value or a ``+``/``-`` address
        expression (evaluated first). ``script_json`` defaults to the path
        associated with the session by ``analyze``/``il2cpp_dump``; the index
        is sidecar-cached next to the dump, so repeat lookups are sub-second.

        When the session recorded a binary fingerprint at dump time, the
        game binary is re-checked: a changed binary (game update) attaches a
        non-blocking ``stale_warning`` to the result (``force`` skips the
        check). Read-only.
        """

        session = self._load(session_id)
        path = script_json or (session.engine.get("artifacts", {}) or {}).get("script_json")
        if not path:
            raise InvalidArgsError(
                "no script.json associated with this session",
                details={"session_id": session_id},
                hint="Run `il2cpp dump` first (it associates script.json automatically) "
                     "or pass --script-json <path>.",
            )
        if not Path(str(path)).exists():
            raise InvalidArgsError(
                f"script.json not found: {path}",
                details={"script_json": str(path)},
                hint="Re-run `il2cpp dump` or pass a valid --script-json path.",
            )

        rva_int = pointers.eval_address_expr(str(rva).strip())
        if rva_int < 0:
            raise InvalidArgsError("rva must be non-negative", details={"rva": str(rva)})
        if isinstance(tolerance, str):
            tol = pointers.eval_address_expr(tolerance.strip()) if tolerance.strip() else 0
        else:
            tol = int(tolerance or 0)
        if tol < 0:
            raise InvalidArgsError("tolerance must be non-negative", details={"tolerance": str(tolerance)})

        res = unity_lookup.lookup_rva(path, rva_int, tolerance=tol, force=bool(force_index))
        res["session_id"] = session_id
        res["script_json"] = str(path)
        if not force:
            stale = self._dump_stale_info(session)
            if stale:
                res["stale_warning"] = stale
        return res

    @_session_op
    def il2cpp_dump(self, session_id: str, *, out_dir: str = None,
                    timeout: float = 120.0, force: bool = False) -> dict:
        """Run the installed Il2CppDumper and associate its outputs with the session.

        The dumper binary is located via the toolchain registry (metadata
        version routing: official dumper for <= v31, il2cpp-dumper-rs beyond).
        On success the produced ``script.json`` / ``dump.cs`` paths are stored
        under ``session.engine['artifacts']`` so ``il2cpp_lookup`` works
        without extra arguments.

        Outputs are validated before association (``script.json`` parseable +
        non-empty ``ScriptMethod``): a corrupt dump is refused with an
        ``errors`` breakdown instead of being associated. The game binary
        (GameAssembly.dll or the main exe) is fingerprinted and stored under
        ``artifacts.binary_fingerprint`` so later lookups/analyzes can detect
        a game update. When an existing dump's fingerprint is still fresh the
        run is skipped with a reuse hint unless ``force`` re-dumps anyway.
        Runs an external process (side effect).
        """

        session = self._load(session_id)
        arts = session.engine.get("artifacts", {}) or {}
        meta_path = arts.get("global_metadata")

        # reuse shortcut: a fresh dump (fingerprint unchanged) needs no re-run
        prev_stale = self._dump_stale_info(session)
        fp = arts.get("binary_fingerprint")
        if not force and arts.get("script_json") and fp and prev_stale is None:
            return {
                "ok": True,
                "reused": True,
                "fresh": True,
                "associated": True,
                "outputs": {name: arts[key]
                            for key, name in (("script_json", "script.json"),
                                              ("dump_cs", "dump.cs"),
                                              ("stringliteral_json", "stringliteral.json"))
                            if arts.get(key)},
                "binary": fp.get("path"),
                "session_id": session_id,
                "hint": "现有转储指纹仍然新鲜，已复用。使用 force/--force 强制重新转储。",
            }

        rec = toolchain.recommended_unity_dumper(meta_path, self.config)
        dumper_path = rec.get("path") if rec.get("found") else None
        dumper_name = rec.get("dumper")
        if not dumper_path:
            # fall back to the other known dumper family before giving up
            alt = "il2cppdumper" if rec.get("dumper") == "il2cppdumper_rs" else "il2cppdumper_rs"
            alt_info = toolchain.detect_tool(alt, self.config)
            if alt_info.get("found"):
                dumper_path, dumper_name = alt_info["path"], alt
            else:
                raise ToolNotFoundError(
                    "no IL2CPP dumper installed",
                    details={"recommended": rec.get("dumper"),
                             "metadata_version": rec.get("metadata_version")},
                    hint=(
                        f"{rec.get('hint') or 'Install an IL2CPP dumper.'} "
                        "Alternatively install the other dumper family: "
                        "Il2CppDumper (https://github.com/Perfare/Il2CppDumper, metadata<=31) "
                        "or il2cpp-dumper-rs (https://github.com/rodroidmods/il2cpp-dumper-rs, "
                        "metadata v16-v39), and set tools.il2cppdumper / tools.il2cppdumper_rs."
                    ),
                )

        target = arts.get("game_assembly") or session.exe_path
        if not target:
            raise InvalidArgsError(
                "no dump target available",
                details={"session_id": session_id},
                hint="Attach a session whose game dir contains GameAssembly.dll, "
                     "or run `analyze --target <game-dir>` first.",
            )
        out = Path(out_dir) if out_dir else self.store.dir / session_id / "il2cpp_dump"

        res = engines.unity.run_dumper_cli(dumper_path, target, str(out), timeout=float(timeout))
        if not res.get("ok"):
            raise GameModifierError(
                res.get("error") or "Il2CppDumper failed",
                code=ErrorCode.TOOL_FAILED,
                details={k: res.get(k) for k in ("returncode", "stderr_tail", "out_dir", "timeout") if res.get(k) is not None},
                hint=res.get("hint"),
            )

        outputs = res.get("outputs", {})

        # validate before association: never attach a corrupt dump to the session.
        # The check runs whenever script.json is present on disk (real dumper
        # output always is); a missing file only happens in legacy/mocked
        # flows and keeps the old associate-anyway behavior.
        validation = None
        sj_path = outputs.get("script.json")
        if sj_path and Path(sj_path).exists():
            validation = unity_lookup.validate_dump(
                sj_path, dump_cs_path=outputs.get("dump.cs"))
            if not validation["valid"]:
                return {
                    "ok": False,
                    "associated": False,
                    "validation": validation,
                    "errors": validation["errors"],
                    "out_dir": res.get("out_dir"),
                    "dumper": dumper_name,
                    "session_id": session_id,
                    "hint": "转储产物验证失败，未关联损坏产物。检查 dumper 输出后重跑 "
                            "il2cpp dump --force。",
                }

        # fingerprint the dumped binary so future calls can detect game updates
        fingerprint = None
        bin_target = self._il2cpp_target_binary(session)
        if bin_target:
            try:
                fingerprint = unity_lookup.fingerprint_binary(bin_target)
            except GameModifierError:
                fingerprint = None

        engine = dict(session.engine or {})
        new_arts = dict(engine.get("artifacts", {}) or {})
        for key, name in (("script_json", "script.json"), ("dump_cs", "dump.cs"),
                          ("stringliteral_json", "stringliteral.json")):
            if outputs.get(name):
                new_arts[key] = outputs[name]
        if fingerprint:
            new_arts["binary_fingerprint"] = fingerprint
        engine["artifacts"] = new_arts
        engine["il2cpp_dump"] = {
            "out_dir": res.get("out_dir"),
            "dumper": dumper_name,
            "elapsed": res.get("elapsed"),
            "created_at": time.time(),
            "binary": fingerprint.get("path") if fingerprint else None,
            "methods": (validation or {}).get("methods", 0),
        }
        session.engine = engine
        self.store.save(session)

        out_res = {
            "ok": True,
            "outputs": outputs,
            "elapsed": res.get("elapsed"),
            "associated": True,
            "dumper": dumper_name,
            "out_dir": res.get("out_dir"),
            "session_id": session_id,
        }
        if validation is not None:
            out_res["validation"] = validation
        if fingerprint:
            out_res["binary_fingerprint"] = fingerprint
        if prev_stale:
            out_res["previous_stale"] = prev_stale["reason"]
        return out_res

    # ======================================= Unity il2cpp runtime type decoders
    def _il2cpp_resolve(self, backend: MemoryBackend, session: Session, address: str) -> int:
        """Resolve symbol / hex / module+0x.. / +/- expression for il2cpp decoders."""

        base_expr = address
        sym = session.get_symbol(address) if isinstance(address, str) else None
        if sym is not None:
            base_expr = sym.base_expr
        return pointers.resolve_base(backend, base_expr).address

    def il2cpp_string(self, session_id: str, *, address: str, max_chars: int = 4096) -> dict:
        """Decode an ``Il2CppString`` at ``address`` (read-only).

        One call replaces the manual length@0x10 / chars@0x14 UTF-16 dance.
        ``address`` accepts a session symbol, hex/decimal address, address
        arithmetic (``0x..+/-0x..``) or a ``module+0x..`` expression.
        """

        session = self._load(session_id)
        backend = self._open(session)
        try:
            addr = self._il2cpp_resolve(backend, session, address)
            out = engines.unity_introspect.read_string(backend, addr, max_chars=int(max_chars))
        finally:
            backend.close()
        out["session_id"] = session_id
        return out

    def il2cpp_list(self, session_id: str, *, address: str, elem_type: str = "ptr",
                    limit: int = 100) -> dict:
        """Read a ``List<T>`` at ``address`` (read-only): _items + _size -> elements.

        ``elem_type`` selects the element decoder (``ptr`` yields hex address
        strings; ``int32``/``int64``/``float``/... yield numbers). Address
        forms match :meth:`il2cpp_string`.
        """

        session = self._load(session_id)
        backend = self._open(session)
        try:
            addr = self._il2cpp_resolve(backend, session, address)
            out = engines.unity_introspect.read_list(
                backend, addr, elem_type=elem_type, limit=int(limit))
        finally:
            backend.close()
        out["session_id"] = session_id
        return out

    def il2cpp_dict(self, session_id: str, *, address: str, limit: int = 100) -> dict:
        """Read a ``Dictionary<K,V>`` at ``address`` (read-only).

        Steps the 24-byte entry table, skipping free slots; each entry carries
        ``key_ptr``/``value_ptr`` hex pointers (decode with ``il2cpp string``
        when they point at Il2CppString objects). Address forms match
        :meth:`il2cpp_string`.
        """

        session = self._load(session_id)
        backend = self._open(session)
        try:
            addr = self._il2cpp_resolve(backend, session, address)
            out = engines.unity_introspect.read_dict(backend, addr, limit=int(limit))
        finally:
            backend.close()
        out["session_id"] = session_id
        return out

    # ================================================== Mono / IL tool family
    # Patch ops registered in il-tool (see iltool/src/IlTool/Patch/PatchOps.cs).
    _IL_PATCH_OPS = ("replace_body", "mul_before_ret", "insert_before_ret", "insert_after_call")

    def _il_resolve_assembly(self, session: Session, assembly: Optional[str]) -> str:
        """Resolve the managed assembly for il_* calls.

        Explicit ``assembly`` wins (must exist); otherwise look for
        ``Assembly-CSharp.dll`` in the session module table, then next to the
        game exe / in ``<exe>_Data/Managed`` (classic Unity Mono layout).
        """

        if assembly:
            p = Path(str(assembly))
            if not p.exists():
                raise GameModifierError(
                    f"assembly not found: {assembly}",
                    code=ErrorCode.IL_ASSEMBLY_NOT_FOUND,
                    details={"assembly": str(assembly)},
                    hint="检查路径拼写，或用显式绝对路径重传 assembly。",
                )
            return str(p)

        for name, info in (session.modules or {}).items():
            if str(name).lower() == "assembly-csharp.dll":
                path = (info or {}).get("path") or ""
                if path and Path(path).exists():
                    return str(path)

        exe = session.exe_path or ""
        if exe:
            base = Path(str(exe))
            candidates = (
                base.parent / "Assembly-CSharp.dll",
                base.parent / "Managed" / "Assembly-CSharp.dll",
                base.parent / f"{base.stem}_Data" / "Managed" / "Assembly-CSharp.dll",
            )
            for cand in candidates:
                try:
                    if cand.exists():
                        return str(cand)
                except OSError:
                    continue

        raise GameModifierError(
            "no managed assembly found for this session",
            code=ErrorCode.IL_ASSEMBLY_NOT_FOUND,
            details={"session_id": session.id, "exe_path": exe},
            hint=("会话模块表和 exe 目录都找不到 Assembly-CSharp.dll。"
                  "显式传 assembly=<路径>（通常在 <游戏目录>/<exe名>_Data/Managed/ 下）。"),
        )

    def _il_out_path(self, session_id: str, tag: str) -> str:
        """Unique large-output sink under ``sessions/<id>/il/``."""

        d = self.store.dir / session_id / "il"
        d.mkdir(parents=True, exist_ok=True)
        return str(d / f"{tag}-{int(time.time() * 1000):x}.json")

    def _il_run(self, request: dict, *, timeout: float = 120.0) -> dict:
        """Run il-tool and convert a failure envelope into a typed error."""

        res = il_tool_bridge.run_il_tool(request, timeout=timeout, config=self.config)
        if not res.get("ok"):
            err = res.get("error") or {}
            code_str = str(err.get("code") or "")
            message = err.get("message") or "il-tool failed"
            details = dict(err.get("details") or {})
            for key in ("returncode", "stderr_tail", "elapsed", "timeout"):
                if res.get(key) is not None:
                    details[key] = res.get(key)
            if code_str == ErrorCode.IL_PATCH_FAILED.value:
                raise IlPatchFailedError(message, details=details, hint=res.get("hint"))
            if code_str == ErrorCode.IL_VERIFY_FAILED.value:
                raise IlVerifyFailedError(message, details=details, hint=res.get("hint"))
            code = (ErrorCode.IL_ASSEMBLY_NOT_FOUND if code_str == ErrorCode.IL_ASSEMBLY_NOT_FOUND.value
                    else ErrorCode.IL_METHOD_NOT_FOUND if code_str == ErrorCode.IL_METHOD_NOT_FOUND.value
                    else ErrorCode.TOOL_FAILED)
            raise GameModifierError(message, code=code, details=details, hint=res.get("hint"))
        return res.get("data") or {}

    def il_analyze(self, session_id: str, *, assembly: Optional[str] = None,
                   type_filter: Optional[str] = None,
                   member_filter: Optional[str] = None) -> dict:
        """Enumerate types / methods / fields of a managed assembly (read-only).

        ``assembly`` defaults to the session's ``Assembly-CSharp.dll``. Large
        outputs spill to ``sessions/<id>/il/`` (returned as ``out_file``);
        passing ``member_filter`` keeps the (post-filtered) result inline.
        """

        session = self._load(session_id)
        asm = self._il_resolve_assembly(session, assembly)
        args: dict[str, Any] = {}
        if type_filter:
            args["filter"] = str(type_filter)

        if member_filter:
            data = self._il_run({"command": "analyze", "assembly": asm, "args": args})
            needle = str(member_filter).lower()
            for t in data.get("types") or []:
                t["methods"] = [m for m in (t.get("methods") or [])
                                if needle in str(m.get("name", "")).lower()]
                t["fields"] = [f for f in (t.get("fields") or [])
                               if needle in str(f.get("name", "")).lower()]
            data["types"] = [t for t in data["types"] if t["methods"] or t["fields"]]
            data["type_count"] = len(data["types"])
            out: dict[str, Any] = {"ok": True, "session_id": session_id, "assembly": asm}
            out.update(data)
            stale = self._file_hash_stale_info(session, asm)
            if stale:
                out["stale_warning"] = stale
            return out

        out_file = self._il_out_path(session_id, "analyze")
        # F4: full-assembly enumeration is the expensive call - cache it by
        # assembly fingerprint (size + mtime + head sha256, the same scheme
        # il2cpp_dump uses for game-update detection). A game patch changes
        # the fingerprint and silently re-runs; a deleted out file re-runs too.
        cache_path: Optional[Path] = None
        try:
            fp = unity_lookup.fingerprint_binary(asm)
            key = hashlib.sha256(json.dumps(
                {"asm": fp["path"], "size": fp["size"], "mtime": fp["mtime"],
                 "head": fp["head_hash"], "filter": args.get("filter", "")},
                sort_keys=True).encode("utf-8")).hexdigest()[:24]
            cache_path = (self.store.dir / session_id / "il"
                          / "analyze-cache" / f"{key}.json")
        except Exception:
            cache_path = None  # unfingerprintable: just run without caching
        if cache_path is not None and cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                cdata = cached.get("data") or {}
                if cdata.get("out_file") and Path(cdata["out_file"]).exists():
                    out = {"ok": True, "session_id": session_id, **cdata}
                    out["assembly"] = asm
                    out["cached"] = True
                    stale = self._file_hash_stale_info(session, asm)
                    if stale:
                        out["stale_warning"] = stale
                    return out
            except Exception:
                pass  # corrupt cache entry: fall through to a fresh run
        data = self._il_run({"command": "analyze", "assembly": asm, "args": args, "out": out_file})
        out = {"ok": True, "session_id": session_id, **data}
        out["assembly"] = asm  # file path wins over the tool's assembly full name
        if cache_path is not None:
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = cache_path.with_suffix(".tmp")
                tmp.write_text(json.dumps({"data": data}, ensure_ascii=False),
                               encoding="utf-8")
                os.replace(tmp, cache_path)
            except Exception:
                pass  # caching is best-effort; the reply is already complete
        stale = self._file_hash_stale_info(session, asm)
        if stale:
            out["stale_warning"] = stale
        return out

    # dump results at or below this instruction count are returned inline
    # (no spill file); larger dumps spill to sessions/<id>/il/ as before and
    # can be read back with results_read.
    _IL_DUMP_INLINE_MAX = 200

    def il_dump(self, session_id: str, *, method: str, type: Optional[str] = None,
                assembly: Optional[str] = None) -> dict:
        """Render the IL instruction stream of one method body (read-only).

        Small dumps (<= ``_IL_DUMP_INLINE_MAX`` instructions) return the full
        ``instructions`` list inline - no spill file, no second read. Larger
        dumps spill to ``sessions/<id>/il/`` (``out_file``) and the inline
        reply keeps the summary; read it back with ``results_read``.
        """

        session = self._load(session_id)
        asm = self._il_resolve_assembly(session, assembly)
        if not method:
            raise InvalidArgsError("il_dump requires method",
                                   hint="先用 il_analyze 找到方法名，再传 method（可加 type 精确定位）。")
        args: dict[str, Any] = {"method": str(method)}
        if type:
            args["type"] = str(type)
        data = self._il_run({"command": "dump", "assembly": asm, "args": args})
        count = int(data.get("instruction_count") or 0)
        if count > self._IL_DUMP_INLINE_MAX:
            # spill the full payload (same JSON shape il-tool's own "out"
            # writer produced) and keep only the summary inline.
            out_file = self._il_out_path(session_id, "dump")
            tmp = Path(out_file + ".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, out_file)
            data = {
                "out_file": out_file,
                "instruction_count": count,
                "method": data.get("method"),
                "declaring_type": data.get("declaring_type"),
                "rva_hex": data.get("rva_hex"),
                "inline_note": (f"指令流共 {count} 条，已落盘到 out_file；"
                                "用 results_read 读取完整列表。"),
            }
        out = {"ok": True, "session_id": session_id, **data}
        out["assembly"] = asm
        return out

    def il_callers(self, session_id: str, *, assembly: Optional[str] = None,
                   type: Optional[str] = None, method: Optional[str] = None,
                   max_results: int = 0) -> dict:
        """Scan the whole assembly for call/callvirt/ldftn references (read-only).

        The target substring is ``method`` (preferred) or ``type``; results
        spill to ``sessions/<id>/il/`` (``out_file``).
        """

        session = self._load(session_id)
        asm = self._il_resolve_assembly(session, assembly)
        target = method or type
        if not target:
            raise InvalidArgsError("il_callers requires method or type as the reference target",
                                   hint="传 method=目标方法名（或 type=目标类型名）做引用扫描。")
        args: dict[str, Any] = {"target": str(target)}
        if int(max_results) > 0:
            args["max_results"] = int(max_results)
        out_file = self._il_out_path(session_id, "callers")
        data = self._il_run({"command": "callers", "assembly": asm, "args": args, "out": out_file})
        return {"ok": True, "session_id": session_id, "assembly": asm, **data}

    @_session_op
    def il_patch(self, session_id: str, *, op: str, method: str, type: Optional[str] = None,
                 value=None, target: Optional[str] = None, assembly: Optional[str] = None,
                 out_assembly: Optional[str] = None, confirm: bool = False) -> dict:
        """Patch one method body and write the modified assembly back.

        Ops: ``replace_body`` / ``mul_before_ret`` (value=倍率，参数化，重打即可调整) /
        ``insert_before_ret`` / ``insert_after_call`` (target=被调方法名)。
        With ``confirm=False`` returns a dry-run preview; with ``confirm=True``
        an automatic file-level backup is taken first (``backup_id``), then the
        patch is applied and audited. Runs an external process (side effect).
        """

        self._safety_write_gate(confirm, "il_patch")
        session = self._load(session_id)
        asm = self._il_resolve_assembly(session, assembly)
        if op not in self._IL_PATCH_OPS:
            raise InvalidArgsError(
                f"unsupported patch op: {op!r}",
                details={"supported": list(self._IL_PATCH_OPS)},
                hint="op 必须是 replace_body / mul_before_ret / insert_before_ret / insert_after_call 之一。",
            )
        if not method:
            raise InvalidArgsError("il_patch requires method",
                                   hint="传 method=要补丁的方法名（可加 type 精确定位）。")

        patch: dict[str, Any] = {"op": op}
        if value is not None:
            patch["value"] = value
        if target is not None:
            patch["target"] = str(target)

        if not confirm:
            return {
                "ok": True,
                "applied": False,
                "dry_run": True,
                "status": "dry_run_preview",
                "session_id": session_id,
                "assembly": asm,
                "planned": {"op": op, "method": method, "type": type,
                            "value": value, "target": target,
                            "out_assembly": out_assembly or asm},
                "hint": ("这是预览，未修改程序集。确认后重跑加 confirm=true（CLI --confirm）执行补丁；"
                         "执行前会自动文件备份（il_backup）。"),
            }

        backup = self.il_backup(session_id, assembly=asm, label=f"auto-pre-patch:{op}")
        args: dict[str, Any] = {"method": str(method)}
        if type:
            args["type"] = str(type)
        if out_assembly:
            args["out_assembly"] = str(out_assembly)
        patch_args = {"assembly": asm, "op": op, "method": method, "type": type,
                      "value": value, "target": target,
                      "out_assembly": out_assembly,
                      "backup_id": backup.get("backup_id")}
        try:
            data = self._il_run({"command": "patch", "assembly": asm, "args": args, "patch": patch})
        except GameModifierError as exc:
            # a confirmed patch that fails after the backup was taken still
            # leaves an audit trail (ok=false + backup_id + error code)
            fail_args = dict(patch_args)
            fail_args["error_code"] = exc.code.value
            self._audit_log(session, "il_patch", fail_args,
                            {"ok": False, "backup_id": backup.get("backup_id")})
            raise
        result = {"ok": True, "applied": True, "session_id": session_id, "assembly": asm,
                  "backup_id": backup.get("backup_id"), **data}
        self._audit_log(session, "il_patch", patch_args, result)
        return result

    def il_verify(self, session_id: str, *, method: str, expect=None,
                  type: Optional[str] = None, assembly: Optional[str] = None) -> dict:
        """Read back a method's IL and compare opcodes against an expected pattern.

        ``expect`` is either an opcode list (contiguous subsequence match) or
        ``{"expected": [...], "exact": bool}``. A mismatch raises
        ``IlVerifyFailedError`` carrying the expected/actual sequences.
        """

        session = self._load(session_id)
        asm = self._il_resolve_assembly(session, assembly)
        if not method:
            raise InvalidArgsError("il_verify requires method")
        if expect is None:
            raise InvalidArgsError("il_verify requires expect (opcode pattern)",
                                   hint='例: expect=["mul"] 或 {"expected":["mul","ret"],"exact":false}。')
        if isinstance(expect, (list, tuple)):
            exp = {"expected": [str(x) for x in expect]}
        elif isinstance(expect, dict):
            exp = dict(expect)
            if not isinstance(exp.get("expected"), (list, tuple)):
                raise InvalidArgsError("expect dict must carry an 'expected' opcode list")
            exp["expected"] = [str(x) for x in exp["expected"]]
        else:
            raise InvalidArgsError("expect must be a list of opcode names or a dict")
        args: dict[str, Any] = {"method": str(method), **exp}
        if type:
            args["type"] = str(type)
        data = self._il_run({"command": "verify", "assembly": asm, "args": args})
        out = {"ok": True, "session_id": session_id, "assembly": asm, **data}
        stale = self._file_hash_stale_info(session, asm)
        if stale:
            out["stale_warning"] = stale
        return out

    def _file_backup_manager(self, session_id: str):
        """Shared file-backup store for this session (il_* + file_snapshot)."""

        from .safety import FileBackupManager

        return FileBackupManager(self.store.dir / session_id / "file_backups")

    @_session_op
    def il_backup(self, session_id: str, *, assembly: Optional[str] = None,
                  label: str = "") -> dict:
        """File-level backup of a managed assembly before patching.

        The copy lands in ``sessions/<id>/file_backups/`` with a ``.json``
        manifest (source path, sha256, size, label) and is recorded in
        ``audit.jsonl``. Returns ``backup_id`` for :meth:`il_restore`.
        Storage is delegated to :class:`FileBackupManager` (flat layout -
        the external return shape is unchanged).
        """

        session = self._load(session_id)
        asm = self._il_resolve_assembly(session, assembly)
        src = Path(asm)
        mgr = self._file_backup_manager(session_id)
        manifest = mgr.create(src, label=label, layout="flat", id_prefix="ilbk")
        dest = mgr.dir / str(manifest["file"])
        result = {"ok": True, "session_id": session_id, "backup_id": manifest["backup_id"],
                  "file": str(dest), "sha256": manifest["sha256"], "size": manifest["size"],
                  "source": manifest["source"], "label": manifest["label"]}
        self._audit_log(session, "il_backup",
                        {"assembly": str(src), "label": manifest["label"]}, result)
        return result

    @_session_op
    def il_restore(self, session_id: str, *, backup_id: str, confirm: bool = False) -> dict:
        """Restore a file backup taken by :meth:`il_backup`.

        ``confirm=False`` returns a preview (what would be restored + whether
        the game process is still alive); ``confirm=True`` re-checks the
        backup's sha256, copies it back over the source file and audits the
        operation. Runs an external process (side effect).
        """

        self._safety_write_gate(confirm, "il_restore")
        session = self._load(session_id)
        mgr = self._file_backup_manager(session_id)
        found = mgr.load_manifest(backup_id)
        if found is None:
            known = sorted(m["backup_id"] for m in mgr.list_backups())
            raise GameModifierError(
                f"backup not found: {backup_id!r}",
                code=ErrorCode.BACKUP_NOT_FOUND,
                details={"backup_id": backup_id, "known": known},
                hint="用 il_backup 列表中的 backup_id 重试，或先 il_backup 建立备份。",
            )
        manifest, backup_file = found

        source = str(manifest.get("source") or "")
        alive = procmod.process_exists(session.pid)
        if not confirm:
            return {
                "ok": True,
                "applied": False,
                "dry_run": True,
                "status": "dry_run_preview",
                "session_id": session_id,
                "backup_id": backup_id,
                "source": source,
                "sha256": manifest.get("sha256"),
                "process_alive": alive,
                "hint": ("这是预览，未恢复文件。确认后重跑加 confirm=true（CLI --confirm）执行恢复。"
                         + ("注意：游戏进程仍在运行，恢复后需重启游戏才会生效。" if alive else "")),
            }

        if not backup_file.exists():
            raise GameModifierError(
                f"backup file missing on disk: {backup_file.name}",
                code=ErrorCode.BACKUP_NOT_FOUND,
                details={"backup_id": backup_id},
            )
        if not mgr.verify(manifest, backup_file):
            raise GameModifierError(
                "backup file sha256 mismatch - refusing to restore",
                code=ErrorCode.BACKUP_NOT_FOUND,
                details={"backup_id": backup_id, "expected_sha256": manifest.get("sha256")},
                hint="备份文件已被改动；不要恢复，重新从游戏原始文件做备份。",
            )
        mgr.restore_to(manifest, backup_file)
        result = {"ok": True, "applied": True, "session_id": session_id,
                  "backup_id": backup_id, "source": source,
                  "process_alive": alive}
        if alive:
            result["warning"] = "游戏进程仍在运行，恢复的文件需重启游戏后生效。"
        self._audit_log(session, "il_restore",
                        {"backup_id": backup_id, "source": source}, result)
        return result

    # --------------------------------------------------- file snapshot tools
    @_session_op
    def file_snapshot(self, session_id: str, *, path: str, label: str = "") -> dict:
        """Snapshot any game file into the session's file backup store (write op).

        The copy lands in ``sessions/<id>/file_backups/<backup_id>/<原名>``
        with a JSON manifest (source path / sha256 / timestamp / label) via
        the shared :class:`FileBackupManager`, and the file's sha256 +
        fingerprint are recorded in the session artifacts (``file_hashes``)
        so ``il_analyze`` / ``il_verify`` can flag a later game/Steam update
        with a non-blocking ``stale_warning``. Audited in ``audit.jsonl``.
        """

        session = self._load(session_id)
        src = self._check_file_path(path, session=session, purpose="file_snapshot")
        if not src.is_file():
            raise InvalidArgsError(
                f"file not found: {path!r}",
                details={"path": str(path)},
                hint="传一个存在的文件绝对路径（游戏存档/配置/程序集等）。",
            )
        mgr = self._file_backup_manager(session_id)
        manifest = mgr.create(src, label=label, layout="dir", id_prefix="fbk")

        # record hash + fingerprint for later update detection (advisory)
        try:
            fp = unity_lookup.fingerprint_binary(str(src))
        except Exception:
            fp = {}
        arts = session.engine.setdefault("artifacts", {})
        fhs = arts.setdefault("file_hashes", {})
        fhs[str(src)] = {
            "sha256": manifest["sha256"],
            "fingerprint": fp,
            "backup_id": manifest["backup_id"],
            "created_at": manifest["created_at"],
        }
        self.store.save(session)

        result = {"ok": True, "session_id": session_id,
                  "backup_id": manifest["backup_id"],
                  "file": str(mgr.dir / manifest["backup_id"] / str(manifest["file"])),
                  "source": manifest["source"],
                  "sha256": manifest["sha256"], "size": manifest["size"],
                  "label": manifest["label"]}
        self._audit_log(session, "file_snapshot",
                        {"path": str(src), "label": manifest["label"]}, result)
        return result

    @_session_op
    def file_restore(self, session_id: str, *, backup_id: str, confirm: bool = False) -> dict:
        """Restore a file snapshot taken by :meth:`file_snapshot` (write op).

        ``confirm=False`` returns a preview (what would be restored + whether
        the game process is still alive). ``confirm=True`` refuses while the
        game process is running (restoring under a live process corrupts the
        in-memory copy), re-checks the backup sha256, then copies it back
        over the source file (temp + rename) and audits the operation.
        """

        self._safety_write_gate(confirm, "file_restore")
        session = self._load(session_id)
        mgr = self._file_backup_manager(session_id)
        found = mgr.load_manifest(backup_id)
        if found is None:
            known = sorted(m["backup_id"] for m in mgr.list_backups())
            raise GameModifierError(
                f"backup not found: {backup_id!r}",
                code=ErrorCode.BACKUP_NOT_FOUND,
                details={"backup_id": backup_id, "known": known},
                hint="用 file_snapshot 返回的 backup_id 重试，或先 file_snapshot 建立快照。",
            )
        manifest, backup_file = found
        source = str(manifest.get("source") or "")
        alive = procmod.process_exists(session.pid)
        # the restore target comes from an on-disk manifest - re-validate it
        # against the path policy (the manifest could have been edited).
        self._check_file_path(source, session=session, purpose="file_restore")
        if not confirm:
            return {
                "ok": True,
                "applied": False,
                "dry_run": True,
                "status": "dry_run_preview",
                "session_id": session_id,
                "backup_id": backup_id,
                "source": source,
                "sha256": manifest.get("sha256"),
                "process_alive": alive,
                "hint": ("这是预览，未恢复文件。确认后重跑加 confirm=true（CLI --confirm）执行恢复。"
                         + ("注意：恢复要求游戏进程已退出，请先关闭游戏。" if alive else "")),
            }

        if alive:
            raise InvalidArgsError(
                "game process is still running - close it before restoring files",
                details={"session_id": session_id, "pid": session.pid},
                hint="先关闭游戏进程（或 detach 前结束游戏），再以 confirm=true 重试 file_restore。",
            )
        if not backup_file.exists():
            raise GameModifierError(
                f"backup file missing on disk: {backup_file.name}",
                code=ErrorCode.BACKUP_NOT_FOUND,
                details={"backup_id": backup_id},
            )
        if not mgr.verify(manifest, backup_file):
            raise GameModifierError(
                "backup file sha256 mismatch - refusing to restore",
                code=ErrorCode.BACKUP_NOT_FOUND,
                details={"backup_id": backup_id, "expected_sha256": manifest.get("sha256")},
                hint="备份文件已被改动；不要恢复，重新从游戏原始文件做快照。",
            )
        mgr.restore_to(manifest, backup_file)
        result = {"ok": True, "applied": True, "session_id": session_id,
                  "backup_id": backup_id, "source": source,
                  "process_alive": alive}
        self._audit_log(session, "file_restore",
                        {"backup_id": backup_id, "source": source}, result)
        return result

    # --------------------------------------------------------- mono index flow
    @_session_op
    def mono_dump(self, session_id: str, *, assembly: Optional[str] = None,
                  force: bool = False, timeout: float = 120.0) -> dict:
        """Build the full type/method index of a managed assembly (Mono games).

        Produces ``sessions/<id>/mono_dump/<assembly>.index.json`` plus a
        ``.meta.json`` sidecar carrying an assembly fingerprint (size/mtime/
        head-hash, Steam-update detection). When the fingerprint is still
        fresh the run is skipped with a reuse hint unless ``force`` rebuilds.
        The index path is stored under ``session.engine['artifacts']`` so
        :meth:`mono_symbol` works without extra arguments. Runs an external
        process (side effect).
        """

        session = self._load(session_id)
        asm = self._il_resolve_assembly(session, assembly)
        stem = Path(asm).stem
        mdir = self.store.dir / session_id / "mono_dump"
        mdir.mkdir(parents=True, exist_ok=True)
        index_path = mdir / f"{stem}.index.json"
        meta_path = mdir / f"{stem}.index.meta.json"

        meta: dict = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8")) or {}
            except Exception:
                meta = {}
        if not force and index_path.exists() and meta:
            fresh = unity_lookup.check_dump_freshness(asm, meta.get("fingerprint") or {})
            if fresh.get("fresh"):
                return {
                    "ok": True,
                    "reused": True,
                    "fresh": True,
                    "session_id": session_id,
                    "assembly": asm,
                    "index": str(index_path),
                    "type_count": meta.get("type_count"),
                    "method_count": meta.get("method_count"),
                    "field_count": meta.get("field_count"),
                    "hint": "现有索引指纹仍然新鲜，已复用。使用 force/--force 强制重建索引。",
                }

        res = il_tool_bridge.run_il_tool(
            {"command": "index", "assembly": asm, "out": str(index_path)},
            timeout=float(timeout), config=self.config)
        if not res.get("ok"):
            err = res.get("error") or {}
            code_str = str(err.get("code") or "")
            code = (ErrorCode.IL_ASSEMBLY_NOT_FOUND
                    if code_str == ErrorCode.IL_ASSEMBLY_NOT_FOUND.value else ErrorCode.TOOL_FAILED)
            raise GameModifierError(
                err.get("message") or "il-tool index failed",
                code=code,
                details={k: res.get(k) for k in ("returncode", "stderr_tail", "elapsed") if res.get(k) is not None},
                hint=res.get("hint"),
            )
        data = res.get("data") or {}

        fp = unity_lookup.fingerprint_binary(asm)
        meta = {
            "assembly": asm,
            "index": str(index_path),
            "fingerprint": fp,
            "created_at": time.time(),
            "type_count": data.get("type_count"),
            "method_count": data.get("method_count"),
            "field_count": data.get("field_count"),
        }
        tmp = meta_path.with_suffix(".meta.tmp")
        tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(meta_path)

        arts = session.engine.setdefault("artifacts", {})
        arts["mono_index"] = {"index": str(index_path), "meta": str(meta_path), "assembly": asm}
        self.store.save(session)

        return {
            "ok": True,
            "session_id": session_id,
            "assembly": asm,
            "index": str(index_path),
            "type_count": data.get("type_count"),
            "method_count": data.get("method_count"),
            "field_count": data.get("field_count"),
            "binary_fingerprint": fp,
            "elapsed": res.get("elapsed"),
        }

    def mono_symbol(self, session_id: str, *, query: str,
                    assembly: Optional[str] = None, limit: int = 50) -> dict:
        """Look up types / methods in the mono index by name or RVA (read-only).

        The symmetric counterpart of ``il2cpp_lookup`` for Mono games: name
        matches are case-insensitive substrings; queries starting with ``0x``
        match the method ``rva_hex``. Requires an index built by
        :meth:`mono_dump` (the error hint tells you to run it first).
        """

        session = self._load(session_id)
        if not query:
            raise InvalidArgsError("mono_symbol requires query")

        index_path: Optional[Path] = None
        if assembly:
            index_path = self.store.dir / session_id / "mono_dump" / f"{Path(str(assembly)).stem}.index.json"
        else:
            arts = session.engine.get("artifacts", {}) or {}
            mono = arts.get("mono_index") or {}
            if mono.get("index"):
                index_path = Path(str(mono["index"]))
        if index_path is None or not Path(index_path).exists():
            raise InvalidArgsError(
                "mono index not found",
                details={"session_id": session_id},
                hint="先运行 mono dump（MCP: mono_dump）为 Assembly-CSharp.dll 建立索引，再查询。",
            )

        try:
            index = json.loads(Path(index_path).read_text(encoding="utf-8"))
        except Exception as exc:
            raise InvalidArgsError(
                f"mono index unreadable: {exc}",
                hint="索引文件损坏；重新运行 mono dump（可加 force）重建。",
            ) from exc

        q = str(query).lower()
        is_rva = q.startswith("0x")
        matches: list[dict] = []
        cap = max(1, int(limit))

        for ns, types in (index.get("namespaces") or {}).items():
            for t in types or []:
                tfn = str(t.get("full_name", ""))
                if not is_rva and q in tfn.lower():
                    matches.append({"kind": "type", "namespace": ns, "full_name": tfn})
                    if len(matches) >= cap:
                        break
                for m in t.get("methods") or []:
                    if is_rva:
                        if str(m.get("rva_hex", "")).lower() == q:
                            matches.append({"kind": "method", "type": tfn, "namespace": ns, **m})
                    elif q in str(m.get("name", "")).lower() or q in str(m.get("full_name", "")).lower():
                        matches.append({"kind": "method", "type": tfn, "namespace": ns, **m})
                    if len(matches) >= cap:
                        break
                if len(matches) >= cap:
                    break
            if len(matches) >= cap:
                break

        return {
            "ok": True,
            "session_id": session_id,
            "query": str(query),
            "index": str(index_path),
            "count": len(matches),
            "truncated": len(matches) >= cap,
            "matches": matches,
        }

    # ====================================== Mono runtime inspection tool group
    # Runtime decoders reuse the parameterised il2cpp_types decoders with a
    # Mono layout override (System.String only; List/Dictionary layouts match
    # IL2CPP) - zero duplicated decode code.
    def _mono_arch(self, backend: MemoryBackend, arch: Optional[str]) -> str:
        info = getattr(backend, "info", None)
        return mono_layout.normalize_arch(arch or (getattr(info, "arch", None) if info else None))

    def mono_string(self, session_id: str, *, address: str, max_chars: int = 4096,
                    arch: Optional[str] = None) -> dict:
        """Decode a Mono ``System.String`` at ``address`` (read-only).

        Applies the per-architecture Mono layout (x86: length@0x8/chars@0xC;
        x64: length@0x10/chars@0x14) on top of the shared il2cpp string
        decoder. ``arch`` overrides the process architecture (default: the
        attached process). Address forms match :meth:`il2cpp_string`.
        """

        session = self._load(session_id)
        backend = self._open(session)
        try:
            a = self._mono_arch(backend, arch)
            addr = self._il2cpp_resolve(backend, session, address)
            out = engines.unity_introspect.read_string(
                backend, addr, layout=mono_layout.MONO_LAYOUTS[a], max_chars=int(max_chars))
        finally:
            backend.close()
        out["session_id"] = session_id
        out["arch"] = a
        return out

    def mono_list(self, session_id: str, *, address: str, elem_type: str = "ptr",
                  limit: int = 100) -> dict:
        """Read a Mono ``List<T>`` at ``address`` (read-only).

        Mono ``List<T>`` uses the same managed layout as IL2CPP, so the
        shared decoder runs unchanged. Address forms match
        :meth:`il2cpp_string`; ``elem_type``/``limit`` match
        :meth:`il2cpp_list`.
        """

        session = self._load(session_id)
        backend = self._open(session)
        try:
            a = self._mono_arch(backend, None)
            addr = self._il2cpp_resolve(backend, session, address)
            out = engines.unity_introspect.read_list(
                backend, addr, elem_type=elem_type, limit=int(limit))
        finally:
            backend.close()
        out["session_id"] = session_id
        out["arch"] = a
        return out

    def mono_dict(self, session_id: str, *, address: str, limit: int = 100) -> dict:
        """Read a Mono ``Dictionary<K,V>`` at ``address`` (read-only).

        Same managed layout as IL2CPP - shared decoder, no override.
        Address forms match :meth:`il2cpp_string`.
        """

        session = self._load(session_id)
        backend = self._open(session)
        try:
            a = self._mono_arch(backend, None)
            addr = self._il2cpp_resolve(backend, session, address)
            out = engines.unity_introspect.read_dict(backend, addr, limit=int(limit))
        finally:
            backend.close()
        out["session_id"] = session_id
        out["arch"] = a
        return out

    def mono_static(self, session_id: str, *, arch: Optional[str] = None,
                    max_results: int = 200, min_addr: Optional[int] = None,
                    max_addr: Optional[int] = None) -> dict:
        """Locate static fields by scanning JIT code for ldsfld artifacts (read-only).

        The Mono JIT lowers ``ldsfld`` to ``A1/8B 0D <abs32>`` on x86 and to
        RIP-relative ``8B 05/48 8B 05 <rel32>`` on x64; this scans every
        executable region for those byte patterns (bytes.find anchoring) and
        keeps only hits whose field address resolves into a mapped region
        (pointer-legitimacy filter). Each hit carries ``confidence``/``reason``.
        Region-level parallelism follows the aob scanner (one backend handle
        per worker). Read-only throughout.
        """

        from concurrent.futures import ThreadPoolExecutor

        session = self._load(session_id)
        backend = self._open(session)
        workers = self.config.scan_workers
        try:
            arch_n = self._mono_arch(backend, arch)
            all_regions = list(backend.readable_regions())
            code_regions = [r for r in all_regions if getattr(r, "executable", False)]
            if min_addr is not None:
                code_regions = [r for r in code_regions if r.base + r.size > int(min_addr)]
            if max_addr is not None:
                code_regions = [r for r in code_regions if r.base <= int(max_addr)]
            starts, ends = build_intervals([(r.base, r.base + r.size) for r in all_regions])
            module_spans = []
            for m in (session.modules or {}).values():
                mb = int((m or {}).get("base", 0) or 0)
                ms = int((m or {}).get("size", 0) or 0)
                if ms > 0:
                    module_spans.append((mb, mb + ms))
        finally:
            backend.close()

        cap = max(1, int(max_results))

        def _scan_one(region, be):
            try:
                data = be.read(region.base, region.size)
            except Exception:
                return []
            return mono_layout.scan_region_ldsfld(
                data, region.base, arch_n,
                lambda p: in_intervals(starts, ends, p),
                module_spans=module_spans, max_results=cap)

        hits: list[dict] = []
        if workers > 1 and len(code_regions) > 1:
            def _worker(pair):
                idx, region = pair
                wbe = self._open(session)
                try:
                    return idx, _scan_one(region, wbe)
                finally:
                    wbe.close()

            parts: dict[int, list] = {}
            with ThreadPoolExecutor(max_workers=min(workers, len(code_regions))) as ex:
                for idx, part in ex.map(_worker, list(enumerate(code_regions))):
                    parts[idx] = part
            for idx in range(len(code_regions)):
                hits.extend(parts.get(idx) or [])
                if len(hits) >= cap:
                    hits = hits[:cap]
                    break
        else:
            be = self._open(session)
            try:
                for region in code_regions:
                    hits.extend(_scan_one(region, be))
                    if len(hits) >= cap:
                        hits = hits[:cap]
                        break
            finally:
                be.close()

        return {
            "ok": True,
            "session_id": session_id,
            "arch": arch_n,
            "count": len(hits),
            "truncated": len(hits) >= cap,
            "hits": hits,
            "scanned_regions": len(code_regions),
        }

    def mono_heap_scan(self, session_id: str, *, vtable_addr: Optional[str] = None,
                       max_results: int = 500) -> dict:
        """Enumerate heap object candidates with an optional Mono vtable filter.

        Reuses ``scan_heap_objects``: pass ``vtable_addr`` (a Mono class
        vtable, e.g. from ``dissect``/``layout_analyze``) to keep only
        objects of that class; without it every pointer-shaped slot is a
        candidate. The reply lists mono runtime modules found in the session
        so the agent can sanity-check vtable provenance. Read-only.
        """

        session = self._load(session_id)
        backend = self._open(session)
        try:
            vt_addr = pointers.parse_int(vtable_addr) if vtable_addr else None
            res = scan_heap_objects(backend, vtable_addr=vt_addr, max_results=max_results)
        finally:
            backend.close()
        res["ok"] = True
        res["session_id"] = session_id
        mono_modules = sorted(name for name in (session.modules or {})
                              if "mono" in str(name).lower())
        res["mono_modules"] = mono_modules
        if vt_addr is None:
            res["hint"] = ("无 vtable 过滤时结果为指针形状候选；用 vtable_addr 传入 Mono 类的 "
                           "vtable（dissect/layout_analyze 可得）可精确筛选某类实例。")
        return res


# --- small helpers to normalize batch payload keys --------------------------
def _modify_kwargs(payload: dict) -> dict:
    return {
        "symbol": payload.get("symbol"),
        "address": payload.get("address"),
        "type": payload.get("type"),
        "value": payload.get("value"),
        "offsets": payload.get("offsets"),
        "freeze": bool(payload.get("freeze", False)),
        "label": payload.get("label", ""),
    }


def _read_kwargs(payload: dict) -> dict:
    return {
        "symbol": payload.get("symbol"),
        "address": payload.get("address"),
        "type": payload.get("type"),
        "offsets": payload.get("offsets"),
    }

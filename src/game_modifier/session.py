"""Persistent sessions.

Each CLI invocation is a separate process, so ``attach`` writes a session file
that later commands reuse. This is a core token-saving mechanism: the agent
attaches once, then references a short ``session_id`` instead of re-sending the
process, module map and symbolic addresses on every call.

A session stores the process identity, cached module bases, a symbolic address
table (``player.gold`` -> base+offsets+type), the last scan candidate set, and
the anti-cheat / engine detection results.
"""

from __future__ import annotations

import array
import bisect
import gzip
import json
import re
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from .errors import ErrorCode, GameModifierError, SessionBusyError, SessionNotFoundError

try:
    import msvcrt  # Windows byte-range lock for cross-process session locking
except ImportError:  # pragma: no cover - non-Windows fallback (best-effort)
    msvcrt = None

_SAFE = re.compile(r"[^a-zA-Z0-9_.-]")
# candidate sidecar v2: magic + u8 header length + JSON header + addr segment
# + optional values segment. Files without the magic are legacy v1 (a flat
# array.array('Q') of addresses) and fall back to the full-load path.
_CANDIDATES_MAGIC = b"GMSC2"
# process-local cache of parsed sidecar values segments, keyed by
# (path, mtime_ns, size). Paging through one candidate set must not re-parse
# the (potentially multi-MB) JSON values blob on every window read; small
# insertion-ordered LRU so a handful of sessions stay hot without growing
# unboundedly.
_VALUES_CACHE: dict[tuple, dict] = {}
_VALUES_CACHE_MAX = 8
# retention for persisted scan/batch result files: keep the newest N per dir
_RESULT_KEEP = 10
# macro names become file names (<name>.yaml) - keep them strictly safe
_MACRO_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
# snapshot names become file names (<name>.json) - same strict rules
_SNAPSHOT_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
# suffix of the automatic pre-restore backup (excluded from listings)
_PRE_RESTORE_SUFFIX = ".pre-restore.json"


@dataclass
class Symbol:
    name: str
    base_expr: str
    offsets: list[int] = field(default_factory=list)
    type: str = "int32"
    description: str = ""
    # pointer resolution semantics: "" = auto, "relative" | "pointer_chain"
    mode: str = ""
    # transient symbol (e.g. pointer-chain intermediate); cleared by
    # ``name clear-temp`` while persistent symbols survive.
    temp: bool = False

    def to_dict(self) -> dict:
        data = {
            "name": self.name,
            "base_expr": self.base_expr,
            "offsets": [hex(o) for o in self.offsets],
            "type": self.type,
            "description": self.description,
        }
        if self.mode:
            data["mode"] = self.mode
        if self.temp:
            data["temp"] = True
        return data


@dataclass
class ScanState:
    type: str = ""
    comparator: str = ""
    count: int = 0
    truncated: bool = False
    addresses: list[int] = field(default_factory=list)
    values: dict[int, Any] = field(default_factory=dict)
    # hash of the region layout (base/size list) captured during the scan;
    # used to detect a stale candidate cache after the process memory layout
    # changed. Empty for sessions created before this field existed.
    region_fingerprint: str = ""
    # relative path of an external candidate file (array.array('Q') binary)
    # used when the candidate set is too large to keep inline in the JSON.
    candidates_file: str = ""
    # region layout ([base, size] pairs) captured with the fingerprint; used
    # to build the ``stale_detail`` confidence signal when the cache goes
    # stale. Empty for sessions created before this field existed.
    region_layout: list = field(default_factory=list)
    # fingerprint mode active when the fingerprint was computed
    # ("strict" | "lenient"); empty means legacy strict.
    fingerprint_mode: str = ""

    def to_json(self) -> dict:
        data = {
            "type": self.type,
            "comparator": self.comparator,
            "count": self.count,
            "truncated": self.truncated,
            "addresses": self.addresses,
            "values": {str(a): v for a, v in self.values.items()},
        }
        if self.region_fingerprint:
            data["region_fingerprint"] = self.region_fingerprint
        if self.region_layout:
            data["region_layout"] = self.region_layout
        if self.fingerprint_mode:
            data["fingerprint_mode"] = self.fingerprint_mode
        if self.candidates_file:
            # sidecar holds the addresses; keep only the reference + summary
            data.pop("addresses")
            data["candidates_file"] = self.candidates_file
        return data

    @classmethod
    def from_json(cls, data: dict) -> "ScanState":
        if not data:
            return cls()
        vals = {int(k): v for k, v in (data.get("values") or {}).items()}
        layout: list = []
        for item in data.get("region_layout", []) or []:
            try:
                layout.append([int(item[0]), int(item[1])])
            except (TypeError, ValueError, IndexError):
                continue
        return cls(
            type=data.get("type", ""),
            comparator=data.get("comparator", ""),
            count=int(data.get("count", 0)),
            truncated=bool(data.get("truncated", False)),
            addresses=[int(a) for a in data.get("addresses", [])],
            values=vals,
            region_fingerprint=str(data.get("region_fingerprint", "") or ""),
            candidates_file=str(data.get("candidates_file", "") or ""),
            region_layout=layout,
            fingerprint_mode=str(data.get("fingerprint_mode", "") or ""),
        )

    # ------------------------------------------------------- sidecar storage
    def write_candidates_file(self, path: Path) -> None:
        """Persist candidates as a two-segment sidecar (addresses + values).

        Layout: ``GMSC2`` magic, u64 header length, JSON header
        ``{"format": 2, "count": N, "values_bytes": M}``, then ``N`` addresses
        as ``array.array('Q')`` and ``M`` bytes of JSON values (keys are the
        decimal address strings; omitted when there are no values).
        """

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        values_blob = b""
        if self.values:
            values_blob = json.dumps(
                {str(a): v for a, v in self.values.items()},
                ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
        header = json.dumps(
            {"format": 2, "count": len(self.addresses), "values_bytes": len(values_blob)},
            separators=(",", ":"),
        ).encode("utf-8")
        with path.open("wb") as fh:
            fh.write(_CANDIDATES_MAGIC)
            fh.write(len(header).to_bytes(8, "little"))
            fh.write(header)
            array.array("Q", self.addresses).tofile(fh)
            if values_blob:
                fh.write(values_blob)

    @staticmethod
    def _read_sidecar_header(fh) -> Optional[dict]:
        """Read a v2 sidecar header; ``None`` for legacy/corrupt files."""

        try:
            magic = fh.read(len(_CANDIDATES_MAGIC))
            if magic != _CANDIDATES_MAGIC:
                return None
            hlen = int.from_bytes(fh.read(8), "little")
            if not 0 < hlen <= 4096:
                return None
            header = json.loads(fh.read(hlen).decode("utf-8"))
            if isinstance(header, dict) and isinstance(header.get("count"), int):
                return header
        except Exception:
            pass
        return None

    def load_candidates_file(self, path: Path) -> bool:
        """Restore ``addresses`` (and ``values``) from a sidecar.

        Understands the v2 two-segment format and falls back to the legacy
        flat ``array.array('Q')`` layout for files written before the upgrade.
        A file carrying the ``GMSC2`` magic with an unreadable header is a
        corrupt v2 sidecar and raises a structured error instead of being
        silently misread as a flat v1 address array.
        """

        path = Path(path)
        try:
            with path.open("rb") as fh:
                magic = fh.read(len(_CANDIDATES_MAGIC))
        except OSError:
            return False
        if magic == _CANDIDATES_MAGIC:
            try:
                with path.open("rb") as fh:
                    header = self._read_sidecar_header(fh)
                    if header is None:
                        raise GameModifierError(
                            "candidate sidecar claims the GMSC2 format but its header is unreadable",
                            code=ErrorCode.SCAN_CACHE_STALE,
                            details={"path": str(path)},
                            hint="The sidecar is corrupt; run a fresh `scan` to rebuild the candidate set.",
                        )
                    count = int(header["count"])
                    arr = array.array("Q")
                    arr.frombytes(fh.read(count * arr.itemsize))
                    self.addresses = list(arr)
                    vlen = int(header.get("values_bytes") or 0)
                    if vlen > 0:
                        try:
                            vals = json.loads(fh.read(vlen).decode("utf-8"))
                            self.values = {int(k): v for k, v in vals.items()}
                        except Exception:
                            pass
                    return True
            except GameModifierError:
                raise
            except Exception:
                return False
        # legacy v1: flat address array
        try:
            with path.open("rb") as fh:
                arr = array.array("Q")
                n = path.stat().st_size // arr.itemsize
                arr.fromfile(fh, n)
                self.addresses = list(arr)
            return True
        except Exception:
            return False

    def sidecar_count(self, path: Path) -> int:
        """Candidate count recorded in the sidecar (O(1) header read).

        Returns ``-1`` when the file is missing/unreadable (including a
        corrupt ``GMSC2`` sidecar whose header no longer parses); for legacy
        v1 files the count is derived from the file size.
        """

        path = Path(path)
        try:
            with path.open("rb") as fh:
                header = self._read_sidecar_header(fh)
                if header is not None:
                    return int(header["count"])
                fh.seek(0)
                if fh.read(len(_CANDIDATES_MAGIC)) == _CANDIDATES_MAGIC:
                    return -1
            return path.stat().st_size // 8
        except Exception:
            return -1

    def read_candidates_window(
        self,
        path: Path,
        offset: int = 0,
        limit: Optional[int] = None,
        min_addr: Optional[int] = None,
        max_addr: Optional[int] = None,
    ) -> tuple[int, list[int], Optional[dict[int, Any]]]:
        """Read a candidate window straight from the sidecar (zero-copy-ish).

        Uses ``fh.seek`` + a bounded ``read`` so the cost is O(limit) instead
        of materialising the full candidate set. Address-range filters exploit
        the ascending order via ``bisect`` over blockwise reads. The parsed
        values segment is cached per ``(path, mtime, size)`` so paging does
        not re-parse the JSON blob on every window read.

        Returns ``(total, addresses, values)`` where ``values`` is ``None``
        when the sidecar carries no values segment (legacy v1 files or scans
        that recorded no values).
        """

        path = Path(path)
        offset = max(0, offset)
        with path.open("rb") as fh:
            header = self._read_sidecar_header(fh)
            itemsize = array.array("Q").itemsize
            if header is None:
                fh.seek(0)
                if fh.read(len(_CANDIDATES_MAGIC)) == _CANDIDATES_MAGIC:
                    # corrupt v2 sidecar: never misread it as a flat v1 array
                    raise GameModifierError(
                        "candidate sidecar claims the GMSC2 format but its header is unreadable",
                        code=ErrorCode.SCAN_CACHE_STALE,
                        details={"path": str(path)},
                        hint="The sidecar is corrupt; run a fresh `scan` to rebuild the candidate set.",
                    )
                # legacy v1: flat address array, no values segment
                total = path.stat().st_size // itemsize
                addr_base = 0
                values_blob_len = 0
            else:
                total = int(header["count"])
                addr_base = fh.tell()
                values_blob_len = int(header.get("values_bytes") or 0)

            lo, hi = 0, total
            if min_addr is not None or max_addr is not None:
                lo, hi = self._sidecar_addr_bounds(fh, addr_base, total, itemsize, min_addr, max_addr)

            start = lo + offset
            end = hi if limit is None else min(hi, start + max(0, limit))
            if start >= end:
                return total, [], ({} if values_blob_len > 0 else None)
            fh.seek(addr_base + start * itemsize)
            arr = array.array("Q")
            arr.frombytes(fh.read((end - start) * itemsize))
            addrs = list(arr)

            values: Optional[dict[int, Any]] = None
            if values_blob_len > 0:
                all_vals = self._cached_values(path, fh, addr_base + total * itemsize, values_blob_len)
                wanted = set(addrs)
                values = {int(k): all_vals[k] for k in all_vals if int(k) in wanted}
            return total, addrs, values

    @staticmethod
    def _cached_values(path: Path, fh, blob_offset: int, blob_len: int) -> dict:
        """Parsed values segment, memoised per ``(path, mtime_ns, size)``."""

        st = path.stat()
        key = (str(path), st.st_mtime_ns, st.st_size)
        cached = _VALUES_CACHE.get(key)
        if cached is not None:
            return cached
        fh.seek(blob_offset)
        try:
            parsed = json.loads(fh.read(blob_len).decode("utf-8"))
            if not isinstance(parsed, dict):
                parsed = {}
        except Exception:
            parsed = {}
        _VALUES_CACHE[key] = parsed
        while len(_VALUES_CACHE) > _VALUES_CACHE_MAX:
            _VALUES_CACHE.pop(next(iter(_VALUES_CACHE)))
        return parsed

    @staticmethod
    def _sidecar_addr_bounds(fh, addr_base: int, total: int, itemsize: int,
                             min_addr: Optional[int], max_addr: Optional[int]) -> tuple[int, int]:
        """Locate ``[lo, hi)`` indices for the address range via blockwise bisect."""

        block = 4096
        lo, hi = 0, total

        def _read_block(b: int) -> list[int]:
            n = min(block, total - b * block)
            if n <= 0:
                return []
            fh.seek(addr_base + b * block * itemsize)
            arr = array.array("Q")
            arr.frombytes(fh.read(n * itemsize))
            return list(arr)

        if min_addr is not None:
            lo = total
            for b in range(0, (total + block - 1) // block):
                chunk = _read_block(b)
                if not chunk:
                    break
                if chunk[-1] < min_addr:
                    continue
                lo = b * block + bisect.bisect_left(chunk, min_addr)
                break
        if max_addr is not None:
            hi = 0
            for b in range((total + block - 1) // block - 1, -1, -1):
                chunk = _read_block(b)
                if not chunk:
                    continue
                if chunk[0] > max_addr:
                    continue
                hi = b * block + bisect.bisect_right(chunk, max_addr)
                break
        return lo, max(lo, hi)


@dataclass
class Session:
    id: str
    pid: int
    process_name: str = ""
    exe_path: str = ""
    arch: str = "x64"
    platform: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    engine: dict = field(default_factory=dict)
    anti_cheat: dict = field(default_factory=dict)
    modules: dict[str, dict] = field(default_factory=dict)  # name -> {base,size,path}
    symbols: dict[str, dict] = field(default_factory=dict)  # name -> Symbol.to_dict
    freezes: list = field(default_factory=list)  # [{label,symbol,address,offsets,type,value}]
    scan: ScanState = field(default_factory=ScanState)
    save_edit_info: dict = field(default_factory=dict)  # set when the game is save-file based
    # engine structure introspection results, e.g.
    # {"ue": {"resolved": {...}, "hypotheses": {...}, "verdict": ..., "confidence": ..., "created_at": ts}}
    introspect: dict = field(default_factory=dict)
    # pointer-scan result summary; the full path list lives in the
    # ``pointer_paths.bin`` sidecar (see SessionStore.write_pointer_paths).
    # e.g. {"count": n, "created_at": ts, "file": "pointer_paths.bin", "address": "0x..."}
    pointer_scan_meta: dict = field(default_factory=dict)

    # ------------------------------------------------------------- symbols
    def set_symbol(self, sym: Symbol) -> None:
        self.symbols[sym.name] = {
            "name": sym.name,
            "base_expr": sym.base_expr,
            "offsets": sym.offsets,
            "type": sym.type,
            "description": sym.description,
            "mode": sym.mode,
            "temp": sym.temp,
        }

    def get_symbol(self, name: str) -> Optional[Symbol]:
        raw = self.symbols.get(name)
        if not raw:
            return None
        return Symbol(
            name=raw["name"],
            base_expr=raw["base_expr"],
            offsets=[int(o) for o in raw.get("offsets", [])],
            type=raw.get("type", "int32"),
            description=raw.get("description", ""),
            mode=raw.get("mode", ""),
            temp=bool(raw.get("temp", False)),
        )

    def touch(self) -> None:
        self.updated_at = time.time()

    # ------------------------------------------------------------- (de)serialize
    def to_dict(self) -> dict:
        data = asdict(self)
        data["scan"] = self.scan.to_json()
        data["save_edit_info"] = self.save_edit_info
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        scan = ScanState.from_json(data.get("scan") or {})
        return cls(
            id=data["id"],
            pid=int(data["pid"]),
            process_name=data.get("process_name", ""),
            exe_path=data.get("exe_path", ""),
            arch=data.get("arch", "x64"),
            platform=data.get("platform", ""),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            engine=data.get("engine", {}),
            anti_cheat=data.get("anti_cheat", {}),
            modules=data.get("modules", {}),
            symbols=data.get("symbols", {}),
            freezes=data.get("freezes", []),
            scan=scan,
            save_edit_info=data.get("save_edit_info", {}),
            introspect=data.get("introspect", {}),
            pointer_scan_meta=data.get("pointer_scan_meta", {}) or {},
        )

    def summary(self) -> dict:
        return {
            "session_id": self.id,
            "pid": self.pid,
            "process": self.process_name,
            "arch": self.arch,
            "engine": self.engine.get("engine") if self.engine else None,
            "symbols": len(self.symbols),
            "scan_candidates": self.scan.count,
            "updated_at": self.updated_at,
        }


class SessionStore:
    def __init__(self, sessions_dir: Path) -> None:
        self.dir = Path(sessions_dir)
        # F3 write serialization: per-session in-process RLocks (threads of one
        # server process) + a cross-process lockfile (CLI vs MCP server). See
        # locked() below; ``*.lock`` files are excluded from list_ids (``*.json``).
        self._locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()
        self._file_lock_depth: dict[str, int] = {}

    def _path(self, session_id: str) -> Path:
        return self.dir / f"{session_id}.json"

    def _thread_lock(self, session_id: str) -> threading.RLock:
        with self._locks_guard:
            lock = self._locks.get(session_id)
            if lock is None:
                lock = threading.RLock()
                self._locks[session_id] = lock
            return lock

    @contextmanager
    def locked(self, session_id: str, timeout: float = 10.0):
        """Exclusive access to one session's persisted state.

        Two layers: an in-process per-session ``threading.RLock`` (reentrant,
        so composite flows like batch_run -> modify nest safely) and a
        cross-process byte-range lock on ``<session_id>.lock`` (msvcrt). The
        file lock is acquired only at the outermost nesting level of this
        process. Raises :class:`SessionBusyError` after ``timeout`` seconds.
        """

        timeout = max(0.1, float(timeout))
        lock = self._thread_lock(session_id)
        if not lock.acquire(timeout=timeout):
            raise SessionBusyError(
                f"session is busy (in-process lock held): {session_id}",
                details={"session_id": session_id, "waited_s": timeout},
            )
        fh = None
        try:
            depth = self._file_lock_depth.get(session_id, 0)
            if depth == 0 and msvcrt is not None:
                self.dir.mkdir(parents=True, exist_ok=True)
                fh = (self.dir / f"{session_id}.lock").open("a+b")
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        fh.seek(0)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            fh.close()
                            fh = None
                            raise SessionBusyError(
                                f"session is busy (locked by another process): {session_id}",
                                details={"session_id": session_id, "waited_s": timeout},
                            )
                        time.sleep(0.05)
            self._file_lock_depth[session_id] = depth + 1
            try:
                yield
            finally:
                self._file_lock_depth[session_id] -= 1
                if fh is not None:
                    try:
                        fh.seek(0)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                    fh.close()
        finally:
            lock.release()

    def backups_dir(self, session_id: str) -> Path:
        return self.dir / session_id / "backups"

    def freeze_pid_path(self, session_id: str) -> Path:
        return self.dir / session_id / "freeze.pid"

    def watch_pid_path(self, session_id: str) -> Path:
        return self.dir / session_id / "watch.pid"

    def watch_jsonl_path(self, session_id: str) -> Path:
        """JSONL append-only change history for the background watch worker."""
        return self.dir / session_id / "watch.jsonl"

    def candidates_path(self, session_id: str) -> Path:
        return self.dir / session_id / "scan_candidates.bin"

    def pointer_paths_path(self, session_id: str) -> Path:
        """Sidecar holding discovered pointer paths (gzip JSONL)."""
        return self.dir / session_id / "pointer_paths.bin"

    def write_pointer_paths(self, session_id: str, paths: list[dict]) -> None:
        """Persist pointer-scan paths as gzip-compressed JSON lines."""

        path = self.pointer_paths_path(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            for p in paths or []:
                fh.write(json.dumps(p, ensure_ascii=False) + "\n")

    def read_pointer_paths(self, session_id: str) -> list[dict]:
        """Load paths written by :meth:`write_pointer_paths`; empty when absent/corrupt."""

        path = self.pointer_paths_path(session_id)
        if not path.exists():
            return []
        try:
            out: list[dict] = []
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        out.append(json.loads(line))
            return out
        except Exception:
            return []

    def batch_results_dir(self, session_id: str) -> Path:
        """Directory holding persisted batch_run results for a session."""
        return self.dir / session_id / "batch_results"

    def _prune_result_dir(self, rdir: Path, keep: int = _RESULT_KEEP,
                          current: Optional[Path] = None) -> None:
        """Best-effort retention: keep only the newest ``keep`` result files.

        Runs after every persist so scan/batch result directories never grow
        without bound; ``current`` (the file just written) is always exempt,
        and a failure here never breaks the persist itself.
        """

        try:
            files = [p for p in rdir.glob("*.json")
                     if not p.name.endswith(".tmp") and p != current]
            if len(files) + 1 <= keep:
                return
            files.sort(key=lambda p: (p.stat().st_mtime, p.name), reverse=True)
            for stale in files[keep - 1:]:
                try:
                    stale.unlink()
                except OSError:
                    pass
        except OSError:
            pass

    def save_batch_result(self, session_id: str, result: dict) -> str:
        """Persist a full batch_run result; returns the file path (str).

        File name embeds a millisecond timestamp plus a short unique suffix so
        consecutive batches in the same second never collide. Only the newest
        ``_RESULT_KEEP`` results are retained; the rest are pruned.
        """

        bdir = self.batch_results_dir(session_id)
        bdir.mkdir(parents=True, exist_ok=True)
        name = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}.json"
        path = bdir / name
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
        self._prune_result_dir(bdir, current=path)
        return str(path)

    def read_batch_result(self, path: str) -> dict:
        """Load a batch result written by :meth:`save_batch_result`."""

        with Path(path).open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def scan_results_dir(self, session_id: str) -> Path:
        """Directory holding persisted scan result sets for a session."""
        return self.dir / session_id / "scan_results"

    def save_scan_result(self, session_id: str, result: dict) -> str:
        """Persist a full scan candidate set; returns the file path (str).

        Same atomic temp+rename template as :meth:`save_batch_result`: the
        file name embeds a millisecond timestamp plus a short unique suffix so
        consecutive scans in the same second never collide. Only the newest
        ``_RESULT_KEEP`` results are retained; the rest are pruned.
        """

        sdir = self.scan_results_dir(session_id)
        sdir.mkdir(parents=True, exist_ok=True)
        name = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}.json"
        path = sdir / name
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
        self._prune_result_dir(sdir, current=path)
        return str(path)

    def read_scan_result(self, path: str) -> dict:
        """Load a scan result written by :meth:`save_scan_result`."""

        with Path(path).open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def notes_path(self, session_id: str) -> Path:
        """JSONL append-only session notes (audit.jsonl-style, outside the session JSON)."""
        return self.dir / session_id / "notes.jsonl"

    def audit_path(self, session_id: str) -> Path:
        """JSONL append-only audit trail for write operations."""
        return self.dir / session_id / "audit.jsonl"

    def jobs_dir(self, session_id: str) -> Path:
        """Directory holding background-job result files (``<job_id>.json``)."""
        return self.dir / session_id / "jobs"

    # ---------------------------------------------------------------- macros
    def macros_dir(self, session_id: str) -> Path:
        """Directory holding reusable macro definitions (``<name>.yaml``)."""
        return self.dir / session_id / "macros"

    def save_macro(self, session_id: str, name: str, definition: dict) -> Path:
        """Persist one macro definition as ``macros/<name>.yaml``."""

        if not name or not _MACRO_NAME.match(name):
            raise ValueError(f"invalid macro name: {name!r} (allowed: letters, digits, '_', '-', '.')")
        mdir = self.macros_dir(session_id)
        mdir.mkdir(parents=True, exist_ok=True)
        path = mdir / f"{name}.yaml"
        tmp = path.with_suffix(".yaml.tmp")
        tmp.write_text(yaml.safe_dump(definition, allow_unicode=True, sort_keys=False), encoding="utf-8")
        tmp.replace(path)
        return path

    def load_macro(self, session_id: str, name: str) -> Optional[dict]:
        """Load a macro definition; ``None`` when it does not exist/corrupt."""

        if not name or not _MACRO_NAME.match(name):
            return None
        path = self.macros_dir(session_id) / f"{name}.yaml"
        if not path.exists():
            return None
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def list_macros(self, session_id: str) -> list[str]:
        """Sorted names of all macros stored for the session."""

        mdir = self.macros_dir(session_id)
        if not mdir.exists():
            return []
        return sorted(p.stem for p in mdir.glob("*.yaml"))

    def delete_macro(self, session_id: str, name: str) -> bool:
        """Remove one macro file; returns whether it existed."""

        if not name or not _MACRO_NAME.match(name):
            return False
        path = self.macros_dir(session_id) / f"{name}.yaml"
        if not path.exists():
            return False
        path.unlink()
        return True

    # ----------------------------------------------------------- snapshots
    def snapshots_dir(self, session_id: str) -> Path:
        """Directory holding session state snapshots (``<name>.json``)."""
        return self.dir / session_id / "snapshots"

    def save_snapshot(self, session_id: str, name: str) -> Path:
        """Copy the current session JSON into ``snapshots/<name>.json``.

        Raises ``ValueError`` for unsafe names and ``FileNotFoundError`` when
        the session JSON does not exist yet.
        """

        if not name or not _SNAPSHOT_NAME.match(name):
            raise ValueError(f"invalid snapshot name: {name!r} (allowed: letters, digits, '_', '-', '.')")
        src = self._path(session_id)
        if not src.exists():
            raise FileNotFoundError(f"session not found: {session_id!r}")
        sdir = self.snapshots_dir(session_id)
        sdir.mkdir(parents=True, exist_ok=True)
        path = sdir / f"{name}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_bytes(src.read_bytes())
        tmp.replace(path)
        return path

    def load_snapshot(self, session_id: str, name: str) -> Optional[dict]:
        """Load one snapshot as a dict; ``None`` when absent/corrupt/unsafe name."""

        if not name or not _SNAPSHOT_NAME.match(name):
            return None
        path = self.snapshots_dir(session_id) / f"{name}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def list_snapshots(self, session_id: str) -> list[dict]:
        """List snapshots as ``[{name, created_at, size}]`` (newest last).

        The automatic ``.pre-restore`` backups are excluded.
        """

        sdir = self.snapshots_dir(session_id)
        if not sdir.exists():
            return []
        out: list[dict] = []
        for p in sdir.glob("*.json"):
            if p.name.endswith(_PRE_RESTORE_SUFFIX) or p.name.endswith(".tmp"):
                continue
            try:
                st = p.stat()
            except OSError:  # pragma: no cover - racing deletes
                continue
            out.append({"name": p.stem, "created_at": st.st_mtime, "size": st.st_size})
        out.sort(key=lambda e: e["name"])
        return out

    def pre_restore_backup_path(self, session_id: str, name: str) -> Path:
        """Where :meth:`restore_snapshot` archives the pre-restore state."""
        return self.snapshots_dir(session_id) / f"{name}{_PRE_RESTORE_SUFFIX}"

    def restore_snapshot(self, session_id: str, name: str) -> bool:
        """Overwrite the current session JSON with the named snapshot.

        The current state is archived to ``snapshots/<name>.pre-restore.json``
        first so a bad restore can always be undone. Returns ``False`` when
        the snapshot does not exist (or the name is unsafe).
        """

        if not name or not _SNAPSHOT_NAME.match(name):
            return False
        snap = self.snapshots_dir(session_id) / f"{name}.json"
        if not snap.exists():
            return False
        current = self._path(session_id)
        if current.exists():
            backup = self.pre_restore_backup_path(session_id, name)
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_bytes(current.read_bytes())
        tmp = current.with_suffix(".json.tmp")
        tmp.write_bytes(snap.read_bytes())
        current.parent.mkdir(parents=True, exist_ok=True)
        tmp.replace(current)
        return True

    def new_id(self, process_name: str) -> str:
        stub = _SAFE.sub("", (process_name or "proc").split(".")[0])[:16] or "proc"
        return f"{stub}-{uuid.uuid4().hex[:8]}"

    def save(self, session: Session) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        session.touch()
        tmp = self._path(session.id).with_suffix(".json.tmp")
        tmp.write_text(json.dumps(session.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self._path(session.id))

    def load(self, session_id: str, *, restore_candidates: bool = True) -> Session:
        path = self._path(session_id)
        if not path.exists():
            raise SessionNotFoundError(
                f"session not found: {session_id!r}",
                details={"session_id": session_id, "known": self.list_ids()},
                hint="Run `game-modifier attach` first, then reuse the returned session_id.",
            )
        session = Session.from_dict(json.loads(path.read_text(encoding="utf-8")))
        # restore large candidate sets from their binary sidecar (the JSON
        # only keeps a summary + reference). ``restore_candidates=False`` is
        # the bypass used by scan_candidates: it keeps the reference intact
        # so the window can be served with an O(limit) sidecar read instead
        # of materialising the whole candidate set.
        if restore_candidates and session.scan.candidates_file:
            if session.scan.load_candidates_file(self.candidates_path(session_id)):
                session.scan.candidates_file = ""  # inline again; re-externalised on next save if needed
            else:
                session.scan.addresses = []
        return session

    def list_ids(self) -> list[str]:
        if not self.dir.exists():
            return []
        return sorted(p.stem for p in self.dir.glob("*.json"))

    def list_sessions(self) -> list[dict]:
        out = []
        for sid in self.list_ids():
            try:
                out.append(self.load(sid).summary())
            except Exception:
                continue
        return out

    def delete(self, session_id: str) -> bool:
        path = self._path(session_id)
        existed = path.exists()
        if existed:
            path.unlink()
        # also drop backups dir
        bdir = self.dir / session_id
        if bdir.exists():
            for f in bdir.rglob("*"):
                if f.is_file():
                    f.unlink()
        return existed

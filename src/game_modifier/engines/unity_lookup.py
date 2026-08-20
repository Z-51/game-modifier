"""RVA -> method name lookup over Il2CppDumper ``script.json`` dumps.

Real-world ``script.json`` files routinely exceed 300 MB (a 389 MB dump with
~200k methods is common), so re-parsing the dump on every reverse-lookup is
prohibitively slow. This module builds a compact RVA index once and persists
it as a gzip-compressed JSON sidecar (``script.json.idx`` next to the source)
keyed by a ``(size, mtime)`` fingerprint: matching fingerprint = sub-second
cache load, changed source = transparent rebuild.

The index keeps three parallel sorted arrays (addresses / names / signatures)
so exact matches and "nearest function start within tolerance" lookups are a
binary search, never a linear walk.
"""

from __future__ import annotations

import bisect
import gzip
import hashlib
import json
import time
from pathlib import Path
from typing import Optional

from ..errors import InvalidArgsError

_INDEX_VERSION = 1
# small process-level memo so repeated lookups in one CLI/MCP invocation do
# not even touch the sidecar; keyed by resolved path, bounded to a few dumps.
_MEMO: dict[str, tuple[tuple[int, float], list[int], list[str], list[str]]] = {}
_MEMO_LIMIT = 2


def _fingerprint(path: Path) -> tuple[int, float]:
    st = path.stat()
    return (st.st_size, st.st_mtime)


def index_path_for(script_json_path) -> Path:
    """Sidecar location for a dump: ``<dir>/<name>.idx`` next to the source."""

    p = Path(str(script_json_path))
    return p.with_name(p.name + ".idx")


def _extract_methods(data: dict) -> tuple[list[int], list[str], list[str]]:
    """Pull ``ScriptMethod[]`` entries into parallel sorted arrays."""

    rows: list[tuple[int, str, str]] = []
    for m in (data.get("ScriptMethod") or []):
        addr = m.get("Address")
        name = m.get("Name")
        if addr is None or name is None:
            continue
        rows.append((int(addr), str(name), str(m.get("Signature") or "")))
    rows.sort(key=lambda r: r[0])
    addrs = [r[0] for r in rows]
    names = [r[1] for r in rows]
    sigs = [r[2] for r in rows]
    return addrs, names, sigs


def _write_sidecar(idx_path: Path, fp: tuple[int, float],
                   addrs: list[int], names: list[str], sigs: list[str]) -> bool:
    payload = {
        "version": _INDEX_VERSION,
        "fingerprint": {"size": fp[0], "mtime": fp[1]},
        "methods": len(addrs),
        "addresses": addrs,
        "names": names,
        "signatures": sigs,
    }
    try:
        with gzip.open(idx_path, "wt", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"))
        return True
    except OSError:
        return False  # read-only dir: keep the in-memory index, skip persistence


def _read_sidecar(idx_path: Path, fp: tuple[int, float]) -> Optional[tuple[list[int], list[str], list[str]]]:
    try:
        with gzip.open(idx_path, "rt", encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception:
        return None
    if payload.get("version") != _INDEX_VERSION:
        return None
    sfp = payload.get("fingerprint") or {}
    if sfp.get("size") != fp[0] or sfp.get("mtime") != fp[1]:
        return None
    try:
        addrs = [int(a) for a in payload["addresses"]]
        names = [str(n) for n in payload["names"]]
        sigs = [str(s) for s in payload["signatures"]]
    except (KeyError, TypeError, ValueError):
        return None
    if not (len(addrs) == len(names) == len(sigs)):
        return None
    return addrs, names, sigs


def build_index(script_json_path: str, *, force: bool = False) -> dict:
    """Build (or reuse) the RVA -> method-name index for a ``script.json``.

    A valid sidecar fingerprint short-circuits the full parse (<1s on a 389 MB
    dump); otherwise the dump is loaded once with ``json.load`` (a few seconds)
    and the index is persisted for next time.

    Returns ``{"methods", "index_path", "cached", "elapsed"}``.
    """

    path = Path(str(script_json_path))
    if not path.exists():
        raise InvalidArgsError(
            f"script.json not found: {script_json_path}",
            details={"script_json": str(script_json_path)},
            hint="Check the path, or run `il2cpp dump` to produce a fresh dump.",
        )

    t0 = time.monotonic()
    fp = _fingerprint(path)
    idx_path = index_path_for(path)

    if not force:
        memo = _MEMO.get(str(path.resolve()))
        if memo and memo[0] == fp:
            return {
                "methods": len(memo[1]),
                "index_path": str(idx_path),
                "cached": True,
                "elapsed": round(time.monotonic() - t0, 3),
                "source": {"size": fp[0], "mtime": fp[1]},
            }
        if idx_path.exists():
            loaded = _read_sidecar(idx_path, fp)
            if loaded is not None:
                _memo_put(path, fp, *loaded)
                return {
                    "methods": len(loaded[0]),
                    "index_path": str(idx_path),
                    "cached": True,
                    "elapsed": round(time.monotonic() - t0, 3),
                    "source": {"size": fp[0], "mtime": fp[1]},
                }

    # full (re)build
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InvalidArgsError(
            f"could not parse script.json: {exc}",
            details={"script_json": str(script_json_path)},
        ) from exc
    if not isinstance(data, dict):
        raise InvalidArgsError(
            "script.json root is not an object",
            details={"script_json": str(script_json_path)},
        )
    addrs, names, sigs = _extract_methods(data)
    _write_sidecar(idx_path, fp, addrs, names, sigs)
    _memo_put(path, fp, addrs, names, sigs)
    return {
        "methods": len(addrs),
        "index_path": str(idx_path),
        "cached": False,
        "elapsed": round(time.monotonic() - t0, 3),
        "source": {"size": fp[0], "mtime": fp[1]},
    }


def _memo_put(path: Path, fp: tuple[int, float],
              addrs: list[int], names: list[str], sigs: list[str]) -> None:
    key = str(path.resolve())
    _MEMO[key] = (fp, addrs, names, sigs)
    while len(_MEMO) > _MEMO_LIMIT:
        _MEMO.pop(next(iter(_MEMO)), None)


def _load_index(script_json_path: str, *, force: bool = False) -> tuple[list[int], list[str], list[str]]:
    info = build_index(script_json_path, force=force)
    path = Path(str(script_json_path)).resolve()
    memo = _MEMO.get(str(path))
    if memo is None:  # pragma: no cover - build_index always populates the memo
        raise InvalidArgsError(
            "index build did not complete",
            details={"script_json": str(script_json_path)},
        )
    _, addrs, names, sigs = memo
    return addrs, names, sigs


def lookup_rva(script_json_path: str, rva: int, *, tolerance: int = 0,
               force: bool = False) -> dict:
    """Reverse-map an RVA to the owning IL2CPP method.

    Exact matches win; with ``tolerance > 0`` an RVA inside a function body
    resolves to the nearest function start at or below it (function-start
    semantics) when within ``tolerance`` bytes.

    Returns ``{"rva", "name", "signature", "matched"}`` with
    ``matched`` = ``exact`` | ``nearest`` | ``none``.
    """

    addrs, names, sigs = _load_index(script_json_path, force=force)
    rva = int(rva)
    tolerance = int(tolerance or 0)

    out: dict = {"rva": hex(rva), "name": None, "signature": None, "matched": "none"}
    if not addrs:
        return out

    i = bisect.bisect_left(addrs, rva)
    if i < len(addrs) and addrs[i] == rva:
        out.update(name=names[i], signature=sigs[i] or None, matched="exact",
                   method_rva=hex(addrs[i]))
        return out

    if tolerance > 0:
        j = bisect.bisect_right(addrs, rva) - 1
        if j >= 0 and (rva - addrs[j]) <= tolerance:
            out.update(name=names[j], signature=sigs[j] or None, matched="nearest",
                       method_rva=hex(addrs[j]), offset=hex(rva - addrs[j]))
    return out


# ---------------------------------------------------------------------------
# Dump validation + game-binary freshness (Task #54)
# ---------------------------------------------------------------------------

_HEAD_BYTES = 64 * 1024  # fingerprint hashes only the first 64 KB (fast)


def validate_dump(script_json_path: str, *, dump_cs_path: str = None) -> dict:
    """Validate the integrity of dumper outputs before associating them.

    Checks (never raises; every problem lands in ``errors``):

    * ``script.json`` exists, parses as JSON, and carries a non-empty
      ``ScriptMethod`` list (an empty/absent key means the dump is unusable
      for RVA lookups);
    * ``dump_cs_path``, when given *and* present on disk, is non-empty.

    Returns ``{"valid": bool, "methods": int, "errors": [...]}``.
    """

    errors: list[str] = []
    methods = 0
    path = Path(str(script_json_path))
    if not path.exists():
        errors.append(f"script.json not found: {script_json_path}")
    else:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            data = None
            errors.append(f"script.json is not valid JSON: {exc}")
        if data is not None:
            if not isinstance(data, dict):
                errors.append("script.json root is not a JSON object")
            elif "ScriptMethod" not in data:
                errors.append("script.json lacks the ScriptMethod key")
            else:
                rows = data.get("ScriptMethod")
                if not isinstance(rows, list) or not rows:
                    errors.append("script.json ScriptMethod is empty")
                else:
                    methods = len(rows)

    if dump_cs_path:
        dc = Path(str(dump_cs_path))
        if dc.exists():
            try:
                if dc.stat().st_size == 0:
                    errors.append(f"dump.cs is empty: {dump_cs_path}")
            except OSError as exc:
                errors.append(f"cannot stat dump.cs: {exc}")

    return {"valid": not errors, "methods": methods, "errors": errors}


def fingerprint_binary(binary_path: str) -> dict:
    """Fingerprint a game binary without reading the whole file.

    Returns ``{"path", "size", "mtime", "head_hash"}`` where ``head_hash``
    is the sha256 of the first 64 KB. Raises ``InvalidArgsError`` when the
    file does not exist or cannot be read.
    """

    p = Path(str(binary_path))
    if not p.exists():
        raise InvalidArgsError(
            f"binary not found: {binary_path}",
            details={"binary": str(binary_path)},
            hint="Check the path to GameAssembly.dll / the game executable.",
        )
    try:
        st = p.stat()
        with open(p, "rb") as fh:
            head = fh.read(_HEAD_BYTES)
    except OSError as exc:
        raise InvalidArgsError(
            f"cannot read binary: {exc}",
            details={"binary": str(binary_path)},
        ) from exc
    return {
        "path": str(binary_path),
        "size": st.st_size,
        "mtime": st.st_mtime,
        "head_hash": hashlib.sha256(head).hexdigest(),
    }


def check_dump_freshness(game_binary_path: str, recorded_fingerprint: dict) -> dict:
    """Compare the current game binary against the fingerprint recorded at
    dump time.

    Advisory only (never raises, never blocks): returns
    ``{"fresh": bool, "reason": "ok|size_changed|mtime_changed|hash_changed|
    binary_missing|no_fingerprint"}``. A ``False`` verdict means RVAs from
    the associated dump may no longer be valid (the game likely updated).
    """

    recorded = recorded_fingerprint or {}
    if not recorded:
        return {"fresh": False, "reason": "no_fingerprint"}
    p = Path(str(game_binary_path))
    if not p.exists():
        return {"fresh": False, "reason": "binary_missing"}
    try:
        st = p.stat()
    except OSError:
        return {"fresh": False, "reason": "binary_missing"}
    if recorded.get("size") is not None and st.st_size != recorded.get("size"):
        return {"fresh": False, "reason": "size_changed"}
    if recorded.get("mtime") is not None and st.st_mtime != recorded.get("mtime"):
        return {"fresh": False, "reason": "mtime_changed"}
    try:
        with open(p, "rb") as fh:
            head_hash = hashlib.sha256(fh.read(_HEAD_BYTES)).hexdigest()
    except OSError:
        return {"fresh": False, "reason": "binary_missing"}
    if recorded.get("head_hash") and head_hash != recorded.get("head_hash"):
        return {"fresh": False, "reason": "hash_changed"}
    return {"fresh": True, "reason": "ok"}

"""UE GObjects / FNamePool structure probing (read-only).

Given a candidate ``TUObjectArray`` address this module validates the layout
instead of trusting dumper offsets:

1. a 64-byte header read produces candidate ``(Objects-pointer, NumElements)``
   offset pairs filtered by pointer shape + element-count sanity;
2. each candidate is scored over sampled items for candidate ``FUObjectItem``
   strides (Object pointer shape pass-rate + SerialNumber monotonicity at
   +0x10);
3. the chunk pointer table is verified by reading each chunk pointer and
   probing that the target is readable.

The FNamePool is probed similarly: the block pointer table is located inside
the header, then entry ``(stride, string_offset)`` dialects are scored by the
printable-ASCII ratio of decoded sample strings (wide/UTF-16 included).

Probe failures never raise - they degrade to ``verdict="failed"`` with
evidence. Only the time budget raises :class:`ScanTimeoutError` (carrying the
partial progress). Every result carries ``confidence`` (0.0-0.95) + evidence.
"""

from __future__ import annotations

import time

from ...analysis.alignment import looks_like_pointer
from ...errors import PatternNotFoundError, ScanTimeoutError
from ...memory import aob

# defaults (overridable through the [ue] config section at the service layer)
DEFAULT_ITEM_STRIDE = 0x18
_STRIDE_CANDIDATES_EXTRA = (0x18, 0x20)
_MAX_NUM_ELEMENTS = 10_000_000
DEFAULT_OBJECTS_PER_CHUNK = 65536
DEFAULT_MAX_CHUNKS = 512
DEFAULT_FNAME_PER_CHUNK = 16384
_FNAME_STRIDES = (0xC, 0x10, 0x18)
_FNAME_STRING_OFFSETS = (2, 8)
_FNAME_SAMPLES = 8
_FNAME_MAX_LEN = 24
_AOB_CANDIDATE_LIMIT = 8


# --------------------------------------------------------------------- helpers
def _u64(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off : off + 8], "little")


def _i32(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off : off + 4], "little", signed=True)


def _u32(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off : off + 4], "little")


def _printable_ratio(raw: bytes) -> float:
    if not raw:
        return 0.0
    good = sum(1 for c in raw if 0x20 <= c <= 0x7E)
    return good / len(raw)


# -------------------------------------------------------------------- probing
def _header_candidates(header: bytes, regions, modules, psize: int) -> list[dict]:
    """Candidate (Objects ptr offset, NumElements offset) pairs from the header."""

    out: list[dict] = []
    for ptr_off in range(0, len(header) - psize + 1, psize):
        value = int.from_bytes(header[ptr_off : ptr_off + psize], "little")
        if not looks_like_pointer(value, regions, modules, psize):
            continue
        for num_off in range(0, len(header) - 4 + 1, 4):
            if ptr_off <= num_off < ptr_off + psize:
                continue  # overlapping fields cannot be distinct members
            num = _i32(header, num_off)
            if 0 < num < _MAX_NUM_ELEMENTS:
                out.append({"ptr_offset": ptr_off, "chunk_table": value,
                            "num_offset": num_off, "num_elements": num})
            if len(out) >= 16:
                return out
    return out


def _score_stride(data: bytes, n: int, stride: int, regions, modules, psize: int) -> dict:
    """Score one stride over ``n`` contiguous items in ``data``.

    Object pointer shape at item+0 plus SerialNumber (int32 at item+0x10)
    monotonicity across the sample.
    """

    ptr_hits = 0
    serial_ok = 0
    prev_serial = None
    scored = 0
    for i in range(n):
        off = i * stride
        if off + 0x14 > len(data):
            break
        scored += 1
        obj = _u64(data, off)
        if looks_like_pointer(obj, regions, modules, psize):
            ptr_hits += 1
        serial = _i32(data, off + 0x10)
        if prev_serial is None or serial >= prev_serial:
            serial_ok += 1
        prev_serial = serial
    if scored == 0:
        return {"pointer_hits": 0, "serial_ok": 0, "n": 0, "score": 0.0}
    return {
        "pointer_hits": ptr_hits,
        "serial_ok": serial_ok,
        "n": scored,
        "score": (ptr_hits + serial_ok) / (2.0 * scored),
    }


def _probe_gobjects(backend, addr: int, regions, modules, psize: int,
                    item_stride, probe_items: int, objects_per_chunk: int,
                    max_chunks: int) -> tuple[dict, dict]:
    """Probe one TUObjectArray candidate. Returns (item_stride_hyp, chunks_hyp)."""

    stride_hyp = {"chosen": None, "candidates": [], "confidence": 0.0, "evidence": []}
    chunks_hyp = {"confidence": 0.0, "evidence": []}
    resolved_extra: dict = {}

    try:
        header = backend.read(addr, 64)
    except Exception:
        stride_hyp["evidence"].append(f"无法读取 TUObjectArray 头部 @ {hex(addr)}")
        return stride_hyp, chunks_hyp
    if len(header) < 64:
        stride_hyp["evidence"].append(f"头部读取不完整 @ {hex(addr)} ({len(header)}/64 字节)")
        return stride_hyp, chunks_hyp

    combos = _header_candidates(header, regions, modules, psize)
    if not combos:
        stride_hyp["evidence"].append("头部未发现 (指针, NumElements) 候选组合")
        return stride_hyp, chunks_hyp

    strides: list[int] = []
    for s in (item_stride or DEFAULT_ITEM_STRIDE, *_STRIDE_CANDIDATES_EXTRA):
        s = int(s)
        if s >= 0x10 and s not in strides:
            strides.append(s)
    max_stride = max(strides)

    # score every (header combo, stride) pair; the combo only decides where
    # the chunk table + element count live, the stride scoring decides the rest
    best = None
    all_cands: list[dict] = []
    for combo in combos[:4]:
        chunk_table = combo["chunk_table"]
        num = combo["num_elements"]
        chunk_count = min(max_chunks, (num + objects_per_chunk - 1) // objects_per_chunk)
        try:
            table = backend.read(chunk_table, max(1, chunk_count) * psize)
        except Exception:
            continue
        # gather sample items across chunks (one contiguous read per chunk)
        buffers: list[tuple[int, bytes]] = []
        chunk_ptrs: list[int] = []
        valid_chunks = 0
        for ci in range(chunk_count):
            if (ci + 1) * psize > len(table):
                break
            cp = int.from_bytes(table[ci * psize : (ci + 1) * psize], "little")
            chunk_ptrs.append(cp)
            if not looks_like_pointer(cp, regions, modules, psize):
                continue
            try:
                backend.read(cp, psize)  # target must be readable
            except Exception:
                continue
            valid_chunks += 1
            items_here = min(objects_per_chunk, num - ci * objects_per_chunk)
            take = min(items_here, max(1, probe_items))
            try:
                buffers.append((take, backend.read(cp, take * max_stride)))
            except Exception:
                continue
        if not buffers:
            continue

        for stride in strides:
            total = {"pointer_hits": 0, "serial_ok": 0, "n": 0}
            for take, data in buffers:
                part = _score_stride(data, take, stride, regions, modules, psize)
                total["pointer_hits"] += part["pointer_hits"]
                total["serial_ok"] += part["serial_ok"]
                total["n"] += part["n"]
            score = ((total["pointer_hits"] + total["serial_ok"]) / (2.0 * total["n"])) if total["n"] else 0.0
            cand = {
                "stride": stride,
                "score": round(score, 3),
                "pointer_shape": f"{total['pointer_hits']}/{total['n']} 条目具指针形状",
                "serial_monotonic": f"{total['serial_ok']}/{total['n']}",
            }
            all_cands.append(cand)
            cand_full = dict(cand, _combo=combo, _chunk_ptrs=chunk_ptrs,
                             _valid_chunks=valid_chunks, _chunk_count=chunk_count)
            if best is None or cand_full["score"] > best["score"]:
                best = cand_full

    if best is None:
        stride_hyp["evidence"].append("所有候选的 chunk 表均不可读")
        return stride_hyp, chunks_hyp

    chosen_combo = best.pop("_combo")
    chunk_ptrs = best.pop("_chunk_ptrs")
    valid_chunks = best.pop("_valid_chunks")
    chunk_count = best.pop("_chunk_count")
    stride_hyp["candidates"] = all_cands
    stride_hyp["chosen"] = best["stride"]
    stride_hyp["confidence"] = min(0.95, round(best["score"], 3))
    stride_hyp["evidence"].append(
        f"{best['pointer_shape']} (步长 {hex(best['stride'])}); SerialNumber 单调 {best['serial_monotonic']}"
    )

    chunks_hyp["confidence"] = min(0.95, round(valid_chunks / chunk_count, 3)) if chunk_count else 0.0
    chunks_hyp["evidence"].append(f"{valid_chunks}/{chunk_count} chunk 指针可读")
    chunks_hyp["chunk_count"] = chunk_count

    resolved_extra.update({
        "chunk_table": chosen_combo["chunk_table"],
        "num_elements": chosen_combo["num_elements"],
        "ptr_offset": chosen_combo["ptr_offset"],
        "num_offset": chosen_combo["num_offset"],
        "chunk_ptrs": chunk_ptrs,
    })
    stride_hyp["_resolved"] = resolved_extra
    return stride_hyp, chunks_hyp


def _probe_fname_pool(backend, addr: int, regions, modules, psize: int) -> dict:
    """Probe one FNamePool candidate. Returns the ``fname_pool`` hypothesis."""

    hyp = {"chosen": None, "candidates": [], "confidence": 0.0, "evidence": [],
           "per_chunk": DEFAULT_FNAME_PER_CHUNK}
    try:
        header = backend.read(addr, 64)
    except Exception:
        hyp["evidence"].append(f"无法读取 FNamePool 头部 @ {hex(addr)}")
        return hyp

    # locate the block pointer table inside the header
    blocks_address = None
    for off in range(0, len(header) - 8 + 1, 8):
        value = _u64(header, off)
        if looks_like_pointer(value, regions, modules, psize):
            blocks_address = value
            break
    if blocks_address is None:
        hyp["evidence"].append("头部未发现块表指针")
        return hyp

    try:
        block0 = _u64(backend.read(blocks_address, 8))
    except Exception:
        hyp["evidence"].append(f"块表不可读 @ {hex(blocks_address)}")
        return hyp
    if not looks_like_pointer(block0, regions, modules, psize):
        hyp["evidence"].append("块表首项不是指针形状")
        return hyp
    try:
        window = backend.read(block0, _FNAME_SAMPLES * max(_FNAME_STRIDES) + _FNAME_MAX_LEN)
    except Exception:
        hyp["evidence"].append(f"块0不可读 @ {hex(block0)}")
        return hyp

    best = None
    for stride in _FNAME_STRIDES:
        for soff in _FNAME_STRING_OFFSETS:
            ratios: list[float] = []
            for i in range(_FNAME_SAMPLES):
                start = i * stride + soff
                if start >= len(window):
                    break
                end = window.find(b"\x00", start, start + _FNAME_MAX_LEN)
                end = end if end != -1 else min(start + _FNAME_MAX_LEN, len(window))
                raw = window[start:end]
                if len(raw) >= 2:
                    ratios.append(_printable_ratio(raw))
            if not ratios:
                continue
            score = sum(ratios) / len(ratios)
            cand = {"entry_stride": stride, "string_offset": soff,
                    "score": round(score, 3), "samples": len(ratios)}
            hyp["candidates"].append({k: v for k, v in cand.items()})
            if best is None or cand["score"] > best["score"]:
                best = cand

    if best is None or best["score"] < 0.5:
        hyp["evidence"].append("无候选 entry 布局能解码出可打印字符串")
        return hyp

    # wide-char probe at the chosen dialect: UTF-16 wins only when clearly better
    wide_score = 0.0
    soff = best["string_offset"]
    ratios = []
    for i in range(_FNAME_SAMPLES):
        start = i * best["entry_stride"] + soff
        chars = []
        for j in range(start, min(start + _FNAME_MAX_LEN * 2, len(window) - 1), 2):
            unit = window[j : j + 2]
            if unit == b"\x00\x00":
                break
            chars.append(unit[0] if unit[1] == 0 else 0)
        if len(chars) >= 2:
            ratios.append(sum(1 for c in chars if 0x20 <= c <= 0x7E) / len(chars))
    if ratios:
        wide_score = sum(ratios) / len(ratios)
    wide = wide_score > best["score"] + 0.15

    hyp["chosen"] = {
        "blocks_address": blocks_address,
        "entry_stride": best["entry_stride"],
        "string_offset": best["string_offset"],
        "wide": wide,
    }
    hyp["confidence"] = min(0.95, round(max(best["score"], wide_score), 3))
    hyp["evidence"].append(
        f"块0采样 {best['samples']} 条目可打印比例 {best['score']:.2f} "
        f"(步长 {hex(best['entry_stride'])}, 字符串偏移 +{best['string_offset']}, wide={wide})"
    )
    return hyp


# ------------------------------------------------------------------ main entry
def introspect(backend, *, gobjects=None, gnames=None,
               gobjects_pattern=None, gnames_pattern=None,
               item_stride=None, probe_items: int = 64, timeout: float = 30.0,
               objects_per_chunk: int = DEFAULT_OBJECTS_PER_CHUNK,
               max_chunks: int = DEFAULT_MAX_CHUNKS) -> dict:
    """Probe GObjects / FNamePool layouts at the given absolute addresses.

    ``gobjects`` / ``gnames`` are already-resolved absolute addresses (the
    service layer runs ``resolve_base``); when missing but a pattern is given,
    an AOB scan yields candidates only - they are never adopted automatically.

    Returns ``{"verdict": "confirmed|partial|failed", "confidence": float,
    "hypotheses": {...}, "resolved": {...}, "candidates": {...}}``. Probe
    failures degrade to ``verdict="failed"`` + evidence; only exceeding
    ``timeout`` raises :class:`ScanTimeoutError` (with partial progress).
    """

    deadline = time.monotonic() + float(timeout)
    started = time.monotonic()
    psize = backend.pointer_size
    regions = list(backend.readable_regions())
    modules = backend.modules()

    result: dict = {
        "verdict": "failed",
        "confidence": 0.0,
        "hypotheses": {},
        "resolved": {},
        "candidates": {},
    }

    def _check(stage: str) -> None:
        if time.monotonic() >= deadline:
            raise ScanTimeoutError(
                f"UE introspection exceeded {timeout}s at {stage}",
                details={
                    "timeout": timeout,
                    "stage": stage,
                    "partial": {
                        "verdict": result["verdict"],
                        "hypotheses": list(result["hypotheses"].keys()),
                        "resolved": dict(result["resolved"]),
                    },
                },
                hint="Retry with a smaller probe_items or a larger timeout.",
            )

    # ---------------- pattern-only candidate discovery (never auto-adopted)
    for key, addr, pattern in (("gobjects", gobjects, gobjects_pattern),
                               ("gnames", gnames, gnames_pattern)):
        if addr is None and pattern:
            _check(f"aob:{key}")
            try:
                res = aob.aob_scan(backend, pattern, max_results=_AOB_CANDIDATE_LIMIT)
                result["candidates"][key] = [hex(a) for a in res["addresses"]]
            except PatternNotFoundError:
                result["candidates"][key] = []

    # --------------------------------------------------------------- GObjects
    if gobjects is not None:
        _check("gobjects")
        stride_hyp, chunks_hyp = _probe_gobjects(
            backend, int(gobjects), regions, modules, psize,
            item_stride, max(4, int(probe_items)),
            max(1, int(objects_per_chunk)), max(1, int(max_chunks)),
        )
        result["hypotheses"]["item_stride"] = stride_hyp
        result["hypotheses"]["chunks"] = chunks_hyp
        extra = stride_hyp.pop("_resolved", None)
        if extra:
            result["resolved"].update({
                "gobjects_array": hex(int(gobjects)),
                "chunk_ptrs": hex(extra["chunk_table"]),
                "num_elements": extra["num_elements"],
                "item_stride": stride_hyp["chosen"],
                "objects_per_chunk": int(objects_per_chunk),
                "max_chunks": int(max_chunks),
                "objects_ptr_offset": extra["ptr_offset"],
                "num_elements_offset": extra["num_offset"],
            })

    # ---------------------------------------------------------------- FNamePool
    if gnames is not None:
        _check("gnames")
        fname_hyp = _probe_fname_pool(backend, int(gnames), regions, modules, psize)
        result["hypotheses"]["fname_pool"] = fname_hyp
        if fname_hyp.get("chosen"):
            result["resolved"]["gnames_blocks"] = hex(fname_hyp["chosen"]["blocks_address"])

    # ------------------------------------------------------------------ verdict
    parts: list[float] = []
    for key in ("item_stride", "chunks", "fname_pool"):
        hyp = result["hypotheses"].get(key)
        if hyp:
            parts.append(float(hyp.get("confidence", 0.0)))
    if parts:
        result["confidence"] = min(0.95, round(sum(parts) / len(parts), 3))
    if gobjects is None and gnames is None and result["candidates"]:
        result["hypotheses"]["note"] = {
            "confidence": 0.0,
            "evidence": ["仅提供 AOB 候选地址，未自动采信；请核对后作为 gobjects/gnames 传入"],
        }
    if parts and min(parts) >= 0.8:
        result["verdict"] = "confirmed"
    elif parts and max(parts) >= 0.5:
        result["verdict"] = "partial"
    else:
        result["verdict"] = "failed"
    result["elapsed"] = round(time.monotonic() - started, 3)
    return result

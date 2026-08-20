"""Multi-level pointer resolution and pointer-path parsing.

Convention (matches Cheat Engine): given a base address ``B`` and offsets
``[o0, o1, ... on]`` the final address is computed by dereferencing at each
step and adding the offset; the last offset is added but not dereferenced::

    addr = B
    for o in offsets:
        addr = read_pointer(addr) + o
    return addr

An empty offset list means ``B`` is already the value address.

Three resolution modes are supported:

* ``pointer_chain`` (default, Cheat Engine): dereference at every step, then
  add the offset (``addr = read(addr) + o``). Use for
  ``module.dll+0x10,0x20``-style pointer paths (pointer arrays / linked
  structures).
* ``relative``: offsets are plain additions to the base address (no
  dereference). Use for struct field offsets on an absolute address, e.g.
  reading the 4th int of a struct at ``0x1234`` with ``offsets=0xC``.
* ``field_chain``: add the offset first, then dereference
  (``addr = read(addr + o)``) - the semantics of nested struct field access
  such as ``gem.__data.MainPowerData.mPowerType``. The last step also
  dereferences by default (yielding the object the field points to); pass
  ``deref_last=False`` to stop after adding the final offset so the result
  is the address of a value-typed field itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..errors import ErrorCode, GameModifierError, InvalidArgsError, InvalidAddressError
from .base import MemoryBackend

# every accepted pointer mode (kept in one place so error messages and upper
# layers stay in sync)
VALID_MODES = ("pointer_chain", "relative", "field_chain")

_HEX = re.compile(r"^[+-]?(0x)?[0-9a-fA-F]+$")


def parse_int(token: str) -> int:
    token = token.strip()
    if not token:
        raise InvalidArgsError("empty numeric token")
    neg = token.startswith("-")
    if neg or token.startswith("+"):
        token = token[1:]
    try:
        val = int(token, 16) if (token.lower().startswith("0x") or _looks_hex(token)) else int(token, 10)
    except ValueError as exc:
        raise InvalidArgsError(f"cannot parse integer: {token!r}") from exc
    return -val if neg else val


def _looks_hex(token: str) -> bool:
    t = token.lower().lstrip("0x")
    return bool(t) and any(c in "abcdef" for c in t) and all(c in "0123456789abcdef" for c in t)


def parse_offsets(tokens) -> list[int]:
    if tokens is None:
        return []
    if isinstance(tokens, str):
        tokens = re.split(r"[,\s]+", tokens.strip())
    out: list[int] = []
    for t in tokens:
        t = str(t).strip()
        if t:
            out.append(parse_int(t))
    return out


@dataclass
class ResolvedBase:
    address: int
    module: Optional[str] = None
    static_offset: int = 0


def resolve_base(backend: MemoryBackend, base_expr: str) -> ResolvedBase:
    """Resolve ``module.dll+0x1234`` / ``0x7ff...`` / ``module.dll`` to an address."""

    expr = base_expr.strip()
    if not expr:
        raise InvalidArgsError("empty base expression")

    # arithmetic expressions like "0x1b0c00276c5-0x8" take precedence; module
    # syntax ("game.exe+0x1A4") never reaches this branch because its head is
    # not a plain number.
    if is_address_expr(expr):
        addr = eval_address_expr(expr)
        if addr < 0:
            raise InvalidArgsError(
                "address expression evaluates to negative",
                details={"base_expr": base_expr, "evaluated": addr},
            )
        return ResolvedBase(address=addr)

    # split into module part + optional +offset (module names may contain '.')
    module_name: Optional[str] = None
    static_offset = 0
    plus = expr.find("+")
    head = expr[:plus].strip() if plus != -1 else expr
    tail = expr[plus + 1 :].strip() if plus != -1 else ""

    if _HEX.match(head) and not _is_module_like(head):
        base_addr = parse_int(head)
    else:
        module_name = head
        module = backend.find_module(module_name)
        if not module:
            raise InvalidAddressError(
                f"module not found: {module_name!r}",
                details={"module": module_name, "known_modules": [m.name for m in backend.modules()[:40]]},
            )
        base_addr = module.base

    if tail:
        static_offset = parse_int(tail)
    return ResolvedBase(address=base_addr + static_offset, module=module_name, static_offset=static_offset)


# --- Address arithmetic expressions ------------------------------------------
# Safe, eval-free parser for expressions like "0x1b0c00276c5-0x8" or
# "0x140000000+0x1A4". Only +/- operators and hex/decimal numbers are
# allowed; anything else raises InvalidArgsError.

_NUM = r"(?:0[xX][0-9a-fA-F]+|\d+)"
_PLAIN_NUM = re.compile(rf"^{_NUM}$")
_EXPR_ALLOWED = re.compile(r"^[0-9a-fA-FxX+\-\s]+$")
_EXPR_TOKEN = re.compile(rf"({_NUM})|([+\-])")
_EXPR_ERR_MSG = (
    "address expression supports only +/- operators and hex/decimal numbers "
    "(地址表达式仅支持 +/- 与十六进制/十进制数字)"
)


def is_address_expr(text) -> bool:
    """True if ``text`` is an arithmetic address expression like ``0x10-0x8``.

    Module-relative syntax (``game.exe+0x1A4``) is *not* arithmetic: the part
    before the first ``+``/``-`` operator must itself be a plain hex/decimal
    number. A bare number with no operator is not an expression either (it
    degrades to :func:`parse_int` behavior when evaluated anyway).
    """

    if not isinstance(text, str):
        return False
    t = text.strip()
    if not t:
        return False
    core = t[1:] if t[0] in "+-" else t
    if "+" not in core and "-" not in core:
        return False
    head = re.split(r"[+\-]", core, maxsplit=1)[0].strip()
    return bool(_PLAIN_NUM.fullmatch(head))


def eval_address_expr(expr: str) -> int:
    """Evaluate an address arithmetic expression; only ``+`` and ``-`` allowed.

    Supported forms::

        "0x1b0c00276c5-0x8"        -> subtraction
        "0x140000000+0x1A4"        -> addition
        "12345+0x10"               -> decimal mixed with hex
        "0x10 - 0x8"               -> whitespace tolerated
        "0x1b0c00276c5" / "12345"  -> plain numbers degrade to parse_int

    Python ``eval``/``exec`` are never used: the input is charset-checked,
    tokenized with a regex and summed left-to-right. The result may be
    negative; callers validate address validity. Invalid input raises
    :class:`InvalidArgsError`.
    """

    if not isinstance(expr, str):
        raise InvalidArgsError(
            _EXPR_ERR_MSG,
            details={"input": repr(expr)},
        )
    text = expr.strip()
    if not text or not _EXPR_ALLOWED.match(text):
        raise InvalidArgsError(_EXPR_ERR_MSG, details={"input": expr})

    compact = "".join(text.split())
    tokens: list[str] = []
    pos = 0
    for m in _EXPR_TOKEN.finditer(compact):
        if m.start() != pos:  # gap -> an unsupported character sequence
            raise InvalidArgsError(_EXPR_ERR_MSG, details={"input": expr})
        tokens.append(m.group(1) if m.group(1) else m.group(2))
        pos = m.end()
    if pos != len(compact) or not tokens:
        raise InvalidArgsError(_EXPR_ERR_MSG, details={"input": expr})

    # optional single leading unary sign, then number (op number)* left-to-right
    i = 0
    sign = 1
    if tokens[0] in "+-":
        if tokens[0] == "-":
            sign = -1
        i = 1
    if i >= len(tokens) or tokens[i] in "+-":
        raise InvalidArgsError(_EXPR_ERR_MSG, details={"input": expr})
    result = sign * parse_int(tokens[i])
    i += 1
    while i < len(tokens):
        op = tokens[i]
        if op not in "+-" or i + 1 >= len(tokens) or tokens[i + 1] in "+-":
            raise InvalidArgsError(_EXPR_ERR_MSG, details={"input": expr})
        operand = parse_int(tokens[i + 1])
        result = result + operand if op == "+" else result - operand
        i += 2
    return result


def _is_module_like(token: str) -> bool:
    # Treat tokens containing a dot + alpha as module names, not pure hex.
    return "." in token or token.lower().endswith((".dll", ".exe", ".so"))


def read_pointer(backend: MemoryBackend, address: int) -> int:
    size = backend.pointer_size
    data = backend.read(address, size)
    if len(data) < size:
        raise InvalidAddressError(f"could not read pointer at {hex(address)}")
    return int.from_bytes(data[:size], "little")


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


def resolve_pointer(backend: MemoryBackend, base_expr: str, offsets=None, *, mode: Optional[str] = None,
                    deref_last: bool = True) -> dict:
    """Resolve a full pointer path and return a structured trace.

    ``mode="pointer_chain"`` dereferences at each step (Cheat Engine semantics:
    ``addr = read(addr) + o``).
    ``mode="relative"`` treats offsets as plain additions to the base address
    (no dereference) - correct for struct field offsets on an absolute address.
    ``mode="field_chain"`` walks nested struct fields (``addr = read(addr + o)``);
    every intermediate step dereferences, and the final step dereferences too
    unless ``deref_last=False`` (then the result is the address of a
    value-typed field itself). ``deref_last`` is only consulted by
    ``field_chain``.
    ``mode=None`` auto-selects: bare absolute addresses default to ``relative``
    (the common case for struct fields), ``module.dll+0x..`` forms default to
    ``pointer_chain``.
    """

    if mode is None:
        mode = _default_mode(base_expr)
    if mode not in VALID_MODES:
        raise InvalidArgsError(
            f"unknown pointer mode: {mode!r}",
            details={"supported": list(VALID_MODES)},
        )
    base = resolve_base(backend, base_expr)
    off_list = parse_offsets(offsets)
    trace: list[dict] = [{"stage": "base", "address_hex": hex(base.address), "module": base.module}]
    addr = base.address
    if mode == "relative":
        for off in off_list:
            addr = addr + off
            trace.append(
                {
                    "stage": "relative",
                    "offset_hex": hex(off),
                    "address_hex": hex(addr),
                }
            )
    elif mode == "field_chain":
        last = len(off_list) - 1
        for i, off in enumerate(off_list):
            before = addr
            addr = addr + off
            entry = {
                "stage": f"offset[{i}]",
                "step": i,
                "op": "offset",
                "offset_hex": hex(off),
                "addr_before_hex": hex(before),
            }
            if i < last or deref_last:
                read_at = addr
                try:
                    ptr = read_pointer(backend, read_at)
                except (GameModifierError, RuntimeError, OSError) as exc:
                    # keep the already-walked steps so callers can resume from
                    # the last good intermediate (same contract as name_chain)
                    trace.append(entry | {"address_hex": hex(addr), "addr_after_hex": hex(addr),
                                          "error": str(exc)})
                    raise GameModifierError(
                        f"field chain broken at offset[{i}]: cannot read pointer at {hex(read_at)}",
                        code=ErrorCode.INVALID_POINTER,
                        details={"failed_step": i, "read_at": hex(read_at), "trace": trace},
                        hint=("结构体字段链在第 %d 步解引用失败。trace 已保留成功步骤，"
                              "可从最后一个有效地址继续排查（resolve --base <addr_before>）。" % i),
                    ) from exc
                addr = ptr
                entry["read_at_hex"] = hex(read_at)
                entry["deref_hex"] = hex(ptr)
                entry["op"] = "offset+deref"
            entry["address_hex"] = hex(addr)
            entry["addr_after_hex"] = hex(addr)
            trace.append(entry)
    else:
        for i, off in enumerate(off_list):
            read_at = addr
            ptr = read_pointer(backend, read_at)
            addr = ptr + off
            trace.append(
                {
                    "stage": f"offset[{i}]",
                    "read_at_hex": hex(read_at),
                    "deref_hex": hex(ptr),
                    "offset_hex": hex(off),
                    "address_hex": hex(addr),
                }
            )
    return {
        "base_expr": base_expr,
        "offsets": [hex(o) for o in off_list],
        "mode": mode,
        "final_address": addr,
        "final_address_hex": hex(addr),
        "trace": trace,
    }

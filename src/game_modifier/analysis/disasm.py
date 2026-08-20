"""Runtime disassembly via capstone (optional dependency). Read-only.

capstone is imported lazily so the rest of the package works without it;
install with ``pip install game-modifier[disasm]``. All functions only read
memory through the backend - they never write.
"""

from __future__ import annotations

from typing import Optional

from ..errors import DependencyMissingError, InvalidArgsError
from ..memory.base import MemoryBackend

_INSTALL_HINT = "install capstone with: pip install game-modifier[disasm]"


def _capstone():
    """Import capstone lazily, raising a typed error when absent."""
    try:
        import capstone
    except ImportError as exc:  # pragma: no cover - exercised only without capstone
        raise DependencyMissingError(
            "capstone is not installed",
            hint=_INSTALL_HINT,
        ) from exc
    return capstone


def _arch_spec(cs, arch: Optional[str], pointer_size: int):
    """Map a friendly arch name to (CS_ARCH_*, CS_MODE_*, normalized name)."""
    if arch is None:
        arch = "x86" if pointer_size == 4 else "x64"
    arch = str(arch).strip().lower()
    specs = {
        "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32, "x86"),
        "x64": (cs.CS_ARCH_X86, cs.CS_MODE_64, "x64"),
    }
    if arch not in specs:
        raise InvalidArgsError(
            f"unsupported disasm arch: {arch!r}",
            details={"supported": sorted(specs)},
            hint="pass --arch x86 or --arch x64 (default: derived from process pointer size)",
        )
    return specs[arch]


def _open_disassembler(cs, arch: Optional[str], backend: MemoryBackend, *, detail: bool = False):
    cs_arch, cs_mode, name = _arch_spec(cs, arch, backend.pointer_size)
    md = cs.Cs(cs_arch, cs_mode)
    if detail:
        md.detail = True
    return md, name


def disassemble(
    backend: MemoryBackend,
    address: int,
    *,
    size: int = 256,
    arch: Optional[str] = None,
    max_insns: int = 64,
) -> dict:
    """Disassemble ``size`` bytes of code at ``address``.

    Returns ``{"address", "arch", "instructions", "count", "truncated"}``.
    ``arch`` defaults from the backend pointer size (8 -> x64, 4 -> x86).
    Raises :class:`DependencyMissingError` when capstone is not installed.
    """
    cs = _capstone()
    if size <= 0:
        raise InvalidArgsError(f"size must be positive, got {size}")
    if max_insns <= 0:
        raise InvalidArgsError(f"max_insns must be positive, got {max_insns}")

    data = backend.read(address, size)
    md, name = _open_disassembler(cs, arch, backend)

    instructions: list[dict] = []
    truncated = False
    for insn in md.disasm(data, address):
        if len(instructions) >= max_insns:
            truncated = True
            break
        instructions.append(
            {
                "address": hex(insn.address),
                "size": insn.size,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes_hex": insn.bytes.hex(),
            }
        )

    return {
        "address": hex(address),
        "arch": name,
        "instructions": instructions,
        "count": len(instructions),
        "truncated": truncated,
    }


def basic_blocks(
    backend: MemoryBackend,
    address: int,
    *,
    size: int = 512,
    arch: Optional[str] = None,
    max_insns: int = 128,
) -> dict:
    """Split an instruction stream into basic blocks.

    A block ends after any jump (``CS_GRP_JUMP``), call (``CS_GRP_CALL``) or
    return (``CS_GRP_RET``) instruction. Returns ``{"address", "arch", "blocks", "count", "truncated"}``
    where each block carries ``start``/``end`` (``end`` is exclusive),
    ``insn_count`` and ``ends_with`` (terminator mnemonic, ``"fallthrough"``
    when the block ended because the stream did, ``"truncated"`` when the
    ``max_insns`` budget cut the stream mid-block).
    """
    cs = _capstone()
    if size <= 0:
        raise InvalidArgsError(f"size must be positive, got {size}")
    if max_insns <= 0:
        raise InvalidArgsError(f"max_insns must be positive, got {max_insns}")

    data = backend.read(address, size)
    md, name = _open_disassembler(cs, arch, backend, detail=True)

    blocks: list[dict] = []
    current_start: Optional[int] = None
    current_last = None
    current_count = 0
    seen = 0
    truncated = False

    def flush(ends_with: str) -> None:
        nonlocal current_start, current_last, current_count
        if current_count and current_start is not None and current_last is not None:
            blocks.append(
                {
                    "start": hex(current_start),
                    "end": hex(current_last.address + current_last.size),
                    "insn_count": current_count,
                    "ends_with": ends_with,
                }
            )
        current_start = None
        current_last = None
        current_count = 0

    for insn in md.disasm(data, address):
        if seen >= max_insns:
            truncated = True
            break
        seen += 1
        if current_start is None:
            current_start = insn.address
        current_last = insn
        current_count += 1
        if (insn.group(cs.CS_GRP_JUMP) or insn.group(cs.CS_GRP_CALL)
                or insn.group(cs.CS_GRP_RET)):
            flush(insn.mnemonic)
    flush("truncated" if truncated else "fallthrough")

    return {
        "address": hex(address),
        "arch": name,
        "blocks": blocks,
        "count": len(blocks),
        "truncated": truncated,
    }

"""Mono runtime object layout tables + JIT static-field reference scanning.

Mono's ``System.String`` object layout differs between 32-bit and 64-bit
runtimes (the 8-byte object header on x86 shifts ``length``/``chars``
upwards relative to IL2CPP's 16-byte header); ``List<T>`` and
``Dictionary<K,V>`` use managed references whose layout matches the IL2CPP
decoders, so those reuse :mod:`il2cpp_types` unchanged.

``find_ldsfld_hits`` scans raw JIT-compiled code bytes for the machine-code
artifacts the Mono JIT emits for ``ldsfld`` on static fields:

* x86:  ``A1 <abs32>``      (mov eax, [addr]) and
        ``8B 0D <abs32>``   (mov ecx, [addr])
* x64:  ``8B 05 <rel32>``   (mov eax, [rip+disp]) and
        ``48 8B 05 <rel32>`` (mov rax, [rip+disp]) - RIP-relative target

The scan is anchored with ``bytes.find`` (fast C-level search); pointer
legitimacy filtering happens at the service layer, which owns the region
table. Every hit carries ``confidence`` + ``reason`` so callers can rank.
"""

from __future__ import annotations

import struct
from typing import Callable, Optional

# Mono System.String offsets per architecture. List/Dictionary layouts are
# identical to IL2CPP (managed reference fields) - decode them with the
# existing il2cpp_types decoders (no layout override needed).
MONO_LAYOUTS: dict[str, dict[str, int]] = {
    "x86": {"string_length_off": 0x8, "string_chars_off": 0xC},
    "x64": {"string_length_off": 0x10, "string_chars_off": 0x14},
}

_DEFAULT_ARCH = "x64"


def mono_layout(arch: Optional[str]) -> dict[str, int]:
    """Return the Mono layout table for ``arch`` (unknown -> x64)."""

    a = str(arch or "").strip().lower()
    return dict(MONO_LAYOUTS.get(a) or MONO_LAYOUTS[_DEFAULT_ARCH])


def normalize_arch(arch: Optional[str]) -> str:
    """Canonicalise a backend arch string to 'x86' / 'x64'."""

    a = str(arch or "").strip().lower()
    if a in ("x86", "i386", "i686", "win32", "32", "32-bit"):
        return "x86"
    return "x64"


# (signature, immediate offset within the instruction, instruction size)
_X86_PROBES = (
    (b"\xa1", 1, 5, "A1"),        # mov eax, [abs32]
    (b"\x8b\x0d", 2, 5, "8B0D"),  # mov ecx, [abs32]
)
_X64_PROBES = (
    (b"\x8b\x05", 2, 6, "8B05"),      # mov eax, [rip+disp32]
    (b"\x48\x8b\x05", 3, 7, "488B05"),  # mov rax, [rip+disp32]
)


def find_ldsfld_hits(data: bytes, base: int, arch: str) -> list[dict]:
    """Locate ldsfld JIT artifacts inside one chunk of code bytes.

    Pure byte scan - no pointer validation here. Returns a list of
    ``{"code_addr", "field_addr", "opcode"}`` dicts ordered by code address.
    ``base`` is the runtime address of ``data[0]``.
    """

    arch = normalize_arch(arch)
    probes = _X86_PROBES if arch == "x86" else _X64_PROBES
    hits: list[dict] = []
    for sig, imm_off, size, opcode in probes:
        start = 0
        n = len(data)
        while True:
            i = data.find(sig, start)
            if i < 0 or i + size > n:
                break
            start = i + 1
            imm = data[i + imm_off:i + imm_off + 4]
            if arch == "x86":
                field_addr = int.from_bytes(imm, "little")
            else:
                # RIP-relative: disp32 is relative to the NEXT instruction
                disp = struct.unpack("<i", imm)[0]
                field_addr = (base + i + size + disp) & 0xFFFFFFFFFFFFFFFF
            hits.append({
                "code_addr": base + i,
                "field_addr": field_addr,
                "opcode": opcode,
            })
    hits.sort(key=lambda h: h["code_addr"])
    return hits


def scan_region_ldsfld(data: bytes, base: int, arch: str,
                       is_valid: Callable[[int], bool],
                       module_spans: Optional[list[tuple[int, int]]] = None,
                       max_results: int = 500) -> list[dict]:
    """Scan one region and keep only hits whose field address is legitimate.

    ``is_valid`` is a pointer-legitimacy predicate (service layer builds it
    from the live region table). Hits surviving the filter carry
    ``confidence`` / ``reason``: a field inside a loaded module ranks higher
    (static fields live in the module's data section on Mono AOT / loader
    pre-init) than one in a generic mapped region.
    """

    spans = sorted(module_spans or [])

    def _in_module(addr: int) -> bool:
        for b, e in spans:
            if b <= addr < e:
                return True
        return False

    out: list[dict] = []
    for h in find_ldsfld_hits(data, base, arch):
        if not is_valid(h["field_addr"]):
            continue
        in_mod = _in_module(h["field_addr"])
        out.append({
            "code_addr": hex(h["code_addr"]),
            "field_addr": hex(h["field_addr"]),
            "opcode": h["opcode"],
            "confidence": 0.9 if in_mod else 0.6,
            "reason": ("field address resolves inside a loaded module "
                       "(typical static field slot)" if in_mod else
                       "field address resolves inside a mapped region"),
        })
        if len(out) >= max_results:
            break
    return out

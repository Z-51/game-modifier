"""Validation helpers used before any read/write."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from ..errors import (
    GameModifierError,
    InvalidAddressError,
    InvalidArgsError,
    PathNotAllowedError,
    ErrorCode,
)
from ..memory import types as vt
from ..memory.base import MemoryBackend, MemoryRegion


def validate_type(type_name: str) -> vt.DataType:
    return vt.resolve_type(type_name)  # raises InvalidTypeError


def validate_value(type_name: str, value):
    """Return the canonical stored value, raising on range/type errors."""

    encoded = vt.encode_value(type_name, value)  # raises ValueOutOfRange / InvalidType
    return vt.decode_value(type_name, encoded)


def encoded_size(type_name: str, value) -> int:
    dt = vt.resolve_type(type_name)
    if dt.size is not None:
        return dt.size
    return len(vt.encode_value(type_name, value))


def validate_address(
    backend: MemoryBackend,
    address: int,
    size: int,
    *,
    require_writable: bool = False,
) -> Optional[MemoryRegion]:
    """Ensure ``[address, address+size)`` lies in a committed region.

    When ``require_writable`` is set the region must also be writable.
    Returns the region (or ``None`` when the backend cannot query, e.g. a fake
    backend in tests).
    """

    if address <= 0:
        raise InvalidAddressError(
            f"invalid address {hex(address) if address else address}",
            details={"address": address},
        )
    region = backend.query(address)
    if region is None:
        # query() failing means the address is not in any mapped region
        # (VirtualQueryEx returns info even for free pages, so None == invalid).
        raise InvalidAddressError(
            f"address {hex(address)} is not in a mapped region",
            details={"address": address, "address_hex": hex(address)},
        )
    if not region.contains(address, size):
        raise InvalidAddressError(
            f"address range {hex(address)}..{hex(address + size)} spans outside a committed region",
            details={"address": address, "size": size, "region": region.to_dict()},
        )
    if not region.readable:
        raise InvalidAddressError(
            f"address {hex(address)} is not in a readable region",
            details={"region": region.to_dict()},
        )
    if require_writable and not region.writable:
        raise GameModifierError(
            f"address {hex(address)} is not in a writable region",
            code=ErrorCode.ADDRESS_NOT_WRITABLE,
            details={"region": region.to_dict()},
            hint="The value may be in read-only memory; the write path will retry with VirtualProtectEx.",
        )
    return region


def validate_write_span(size: int, max_write_bytes: int) -> None:
    """Reject write spans larger than ``max_write_bytes``.

    Single value writes are a few bytes at most; a multi-kilobyte write is
    almost certainly a misuse (bad pointer math) and is refused outright.
    Raises :class:`InvalidArgsError` when the limit is exceeded.
    """

    if size > max_write_bytes:
        raise InvalidArgsError(
            f"write of {size} bytes exceeds the {max_write_bytes} byte safety limit",
            details={"size": size, "max_write_bytes": max_write_bytes},
            hint="Check the address/type; large contiguous writes are not supported.",
        )


def resolve_write_mode(config_dry_run: bool, confirm: bool) -> str:
    """Return ``"apply"`` when the write should really happen, else ``"dry_run"``.

    Writes only apply when the caller explicitly confirms. When dry-run is
    disabled in config, confirmation is still required for safety.
    """

    return "apply" if confirm else "dry_run"


# --------------------------------------------------------------------- paths
# File-path policy (review P0-F2): file-touching tools (file_snapshot /
# file_restore / save_edit_modify / batch file=) accept user-supplied paths,
# so every path is normalized (``..`` + symlink collapse) and checked against
# an allow-list before use. The OS system directory is a hard deny - no
# allow-list entry can ever release it.


def _norm(path) -> str:
    """Canonical absolute form for containment checks (case-insensitive)."""

    return os.path.normcase(str(Path(path).expanduser().resolve()))


def _system_roots() -> list[Path]:
    """Hard-deny roots: the OS directory tree is never a legitimate target."""

    return [Path(os.environ.get("SystemRoot") or r"C:\Windows")]


def default_save_roots() -> list[Path]:
    """Locations game saves legitimately live in (smart default allow-list)."""

    home = Path.home()
    roots = [
        home / "Documents",
        home / "Saved Games",
        home / "AppData" / "Roaming",
        home / "AppData" / "Local",
        home / "AppData" / "LocalLow",  # Unity PlayerPrefs/saves
    ]
    # Steam cloud saves in the default install location (non-default Steam
    # library roots can be added via [safety].allowed_paths).
    pf86 = os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"
    roots.append(Path(pf86) / "Steam" / "userdata")
    return roots


def _under(norm_path: str, norm_root: str) -> bool:
    """True when ``norm_path`` is ``norm_root`` itself or inside it.

    Both inputs are ``_norm`` outputs (absolute, case-normalized). A drive
    root (``c:\\``) already ends with the separator - appending another one
    would make every containment check miss, so handle it explicitly.
    """

    if norm_path == norm_root:
        return True
    prefix = norm_root if norm_root.endswith(os.sep) else norm_root + os.sep
    return norm_path.startswith(prefix)


def validate_file_path(path, *, allowed_roots, purpose: str = "file operation") -> Path:
    """Normalize ``path`` and require it to live under one of ``allowed_roots``.

    Raises :class:`PathNotAllowedError` (``E_PATH_NOT_ALLOWED``) otherwise.
    Returns the resolved :class:`Path` on success. The check is purely
    syntactic (containment after normalization), so it works for paths that
    do not exist yet (e.g. a save file about to be created).
    """

    raw = str(path or "").strip()
    if not raw:
        raise InvalidArgsError(f"{purpose}: empty path")
    resolved = Path(raw).expanduser().resolve()
    norm = _norm(resolved)
    for root in _system_roots():
        if _under(norm, _norm(root)):
            raise PathNotAllowedError(
                f"{purpose}: refusing a path inside the OS system directory: {raw!r}",
                details={"path": raw, "resolved": str(resolved), "system_root": str(root)},
                hint="系统目录（%SystemRoot%）永不放行，无法用配置解锁。",
            )
    for root in allowed_roots or []:
        try:
            r = _norm(root)
        except Exception:
            continue
        if _under(norm, r):
            return resolved
    raise PathNotAllowedError(
        f"{purpose}: path is outside the allowed roots: {raw!r}",
        details={
            "path": raw,
            "resolved": str(resolved),
            "allowed_roots": [str(r) for r in (allowed_roots or [])],
        },
        hint=("默认放行：游戏目录、sessions 目录、常见存档位置"
              "（Documents/AppData/Saved Games/Steam userdata）。"
              "其他位置请在 ~/.game-modifier/config.toml 的 [safety] "
              "allowed_paths = [...] 中追加后重试。"),
    )

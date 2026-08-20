"""Safety subsystem: validation, anti-cheat guard, backup/restore."""

from __future__ import annotations

from .guard import ANTI_CHEAT_SIGNATURES, detect_anti_cheat
from .validation import (
    default_save_roots,
    encoded_size,
    resolve_write_mode,
    validate_address,
    validate_file_path,
    validate_type,
    validate_value,
    validate_write_span,
)
from .backup import BackupManager
from .file_backup import FileBackupManager

__all__ = [
    "detect_anti_cheat",
    "ANTI_CHEAT_SIGNATURES",
    "validate_type",
    "validate_value",
    "validate_address",
    "validate_write_span",
    "validate_file_path",
    "default_save_roots",
    "encoded_size",
    "resolve_write_mode",
    "BackupManager",
    "FileBackupManager",
]

"""Backup and restore of original bytes before writes.

A backup is a small JSON file listing ``(address, original_bytes)`` snapshots.
It is created automatically before an applied write (when ``safety.auto_backup``
is on) so any modification can be reverted with ``backup restore``.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path

from ..errors import GameModifierError, ErrorCode, InvalidArgsError
from ..memory.base import MemoryBackend

# backup ids become file names - keep them strictly safe (path-traversal
# guard: an id like "../../x" must never resolve outside the backups dir)
_BACKUP_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


class BackupManager:
    def __init__(self, backups_dir: Path) -> None:
        self.dir = Path(backups_dir)

    def _path(self, backup_id: str) -> Path:
        if not _BACKUP_ID.match(str(backup_id or "")):
            raise InvalidArgsError(
                f"invalid backup id: {backup_id!r}",
                details={"backup_id": str(backup_id)},
                hint="backup_id 只允许字母/数字/_/.-（且不以 . 开头）。",
            )
        return self.dir / f"{backup_id}.json"

    def new_id(self) -> str:
        return f"bak-{uuid.uuid4().hex[:10]}"

    def create(self, backend: MemoryBackend, targets: list[dict], *, label: str = "") -> dict:
        """Snapshot original bytes at each target ``{address, size}``.

        Returns the backup record (also persisted to disk).
        """

        self.dir.mkdir(parents=True, exist_ok=True)
        entries = []
        for t in targets:
            address = int(t["address"])
            size = int(t["size"])
            try:
                original = backend.read(address, size)
            except Exception as exc:  # pragma: no cover - best effort snapshot
                original = b""
                entries.append(
                    {
                        "address": address,
                        "size": size,
                        "original_hex": "",
                        "error": str(exc),
                    }
                )
                continue
            entries.append(
                {
                    "address": address,
                    "size": len(original),
                    "original_hex": original.hex(),
                    "note": t.get("note", ""),
                }
            )
        record = {
            "id": self.new_id(),
            "label": label,
            "created_at": time.time(),
            "entries": entries,
        }
        self._path(record["id"]).write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return record

    def get(self, backup_id: str) -> dict:
        path = self._path(backup_id)
        if not path.exists():
            raise GameModifierError(
                f"backup not found: {backup_id!r}",
                code=ErrorCode.BACKUP_NOT_FOUND,
                details={"backup_id": backup_id, "known": self.list_ids()},
            )
        return json.loads(path.read_text(encoding="utf-8"))

    def list_ids(self) -> list[str]:
        if not self.dir.exists():
            return []
        return sorted(p.stem for p in self.dir.glob("*.json"))

    def list_backups(self) -> list[dict]:
        out = []
        for bid in self.list_ids():
            try:
                rec = self.get(bid)
                out.append(
                    {
                        "id": rec["id"],
                        "label": rec.get("label", ""),
                        "created_at": rec.get("created_at"),
                        "entries": len(rec.get("entries", [])),
                    }
                )
            except Exception:
                continue
        return out

    def restore(self, backend: MemoryBackend, backup_id: str) -> dict:
        record = self.get(backup_id)
        restored, failed = [], []
        for entry in record.get("entries", []):
            hexdata = entry.get("original_hex") or ""
            if not hexdata:
                continue
            address = int(entry["address"])
            data = bytes.fromhex(hexdata)
            try:
                written = backend.write(address, data)
                restored.append({"address_hex": hex(address), "bytes": written})
            except Exception as exc:
                failed.append({"address_hex": hex(address), "error": str(exc)})
        return {
            "backup_id": backup_id,
            "restored": restored,
            "failed": failed,
            "restored_count": len(restored),
            "failed_count": len(failed),
        }

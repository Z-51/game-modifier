"""Shared file-level backup storage (``sessions/<id>/file_backups/``).

``FileBackupManager`` is the single storage layer behind both the il_*
assembly backups (flat layout, historical) and the generic ``file_snapshot``
tool (directory layout):

* ``flat`` layout: ``file_backups/<backup_id><source suffix>`` +
  ``file_backups/<backup_id>.json`` manifest (byte-for-byte the layout
  ``il_backup`` has always produced).
* ``dir`` layout:  ``file_backups/<backup_id>/<original name>`` +
  ``file_backups/<backup_id>/manifest.json``.

Manifest keys are identical across layouts (``backup_id`` / ``source`` /
``file`` / ``sha256`` / ``size`` / ``label`` / ``created_at``) so restore
paths and audit trails stay uniform. All copies are streamed (1 MiB chunks)
with a running sha256; nothing is held in memory whole.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Optional

_CHUNK = 1024 * 1024
# backup ids become directory / file names - keep them strictly safe
_BACKUP_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def _sha256_stream(path: Path) -> tuple[str, int]:
    """Return ``(hexdigest, size)`` while streaming the file once."""

    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    return h.hexdigest(), size


class FileBackupManager:
    """Create / locate / restore file backups under one ``file_backups`` dir."""

    def __init__(self, base_dir: Path):
        self.dir = Path(base_dir)

    # ---------------------------------------------------------------- create
    def create(self, source: Path, *, label: str = "", layout: str = "dir",
               id_prefix: str = "fbk") -> dict:
        """Copy ``source`` into the store and write its JSON manifest.

        Returns the manifest dict. ``layout='flat'`` reproduces the
        historical il_backup layout; ``layout='dir'`` keeps the original
        file name inside a per-backup directory.
        """

        source = Path(source)
        if not source.is_file():
            raise FileNotFoundError(f"source file not found: {source}")
        backup_id = f"{id_prefix}-{int(time.time() * 1000):x}-{uuid.uuid4().hex[:6]}"
        self.dir.mkdir(parents=True, exist_ok=True)

        if layout == "flat":
            dest = self.dir / f"{backup_id}{source.suffix}"
            manifest_name = f"{backup_id}.json"
            manifest_path = self.dir / manifest_name
        else:
            bdir = self.dir / backup_id
            bdir.mkdir(parents=True, exist_ok=True)
            dest = bdir / source.name
            manifest_name = source.name
            manifest_path = bdir / "manifest.json"

        # a source that carries the manifest's own name (manifest.json under
        # the dir layout, any *.json file under the flat layout) would make
        # the manifest overwrite the payload copy - rename the payload and
        # keep the manifest's ``file`` field pointing at the real storage name.
        if dest == manifest_path:
            dest = dest.with_name(dest.name + ".payload")

        h = hashlib.sha256()
        size = 0
        with source.open("rb") as fin, dest.open("wb") as fout:
            while True:
                chunk = fin.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                h.update(chunk)
                fout.write(chunk)

        manifest = {
            "backup_id": backup_id,
            "source": str(source),
            "file": dest.name,
            "sha256": h.hexdigest(),
            "size": size,
            "label": str(label or ""),
            "created_at": time.time(),
        }
        tmp = manifest_path.with_suffix(manifest_path.suffix + ".tmp")
        tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(manifest_path)
        return manifest

    # ---------------------------------------------------------------- lookup
    def load_manifest(self, backup_id: str) -> Optional[tuple[dict, Path]]:
        """Find a backup by id across both layouts.

        Returns ``(manifest, backup_file_path)`` or ``None``. Flat manifests
        are checked first (historical il_backup ids), then dir layouts.
        """

        backup_id = str(backup_id or "")
        if not _BACKUP_ID.match(backup_id):
            return None
        # flat layout: <backup_id>.json next to <backup_id><suffix>
        flat = self.dir / f"{backup_id}.json"
        for candidate in (flat, self.dir / backup_id / "manifest.json"):
            if not candidate.exists():
                continue
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not (isinstance(data, dict) and data.get("backup_id") == backup_id):
                continue
            fname = str(data.get("file") or "")
            if not fname:
                continue
            bfile = candidate.parent / fname if candidate.name == "manifest.json" else self.dir / fname
            return data, bfile
        return None

    def list_backups(self) -> list[dict]:
        """List every manifest in the store (both layouts), newest first."""

        out: list[dict] = []
        if not self.dir.exists():
            return out
        paths: list[Path] = sorted(self.dir.glob("*.json"))
        paths += sorted(self.dir.glob("*/manifest.json"))
        for p in paths:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(data, dict) and data.get("backup_id"):
                out.append(data)
        out.sort(key=lambda m: float(m.get("created_at") or 0), reverse=True)
        return out

    # --------------------------------------------------------------- restore
    @staticmethod
    def verify(manifest: dict, backup_file: Path) -> bool:
        """Re-hash the stored copy and compare against the manifest sha256."""

        try:
            digest, _size = _sha256_stream(Path(backup_file))
        except OSError:
            return False
        return digest == str(manifest.get("sha256") or "")

    @staticmethod
    def restore_to(manifest: dict, backup_file: Path, dest: Optional[Path] = None) -> Path:
        """Copy the verified backup back over its source (temp + rename)."""

        target = Path(dest) if dest else Path(str(manifest.get("source") or ""))
        if not str(target):
            raise ValueError("manifest carries no source path")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".restore.tmp")
        with Path(backup_file).open("rb") as fin, tmp.open("wb") as fout:
            while True:
                chunk = fin.read(_CHUNK)
                if not chunk:
                    break
                fout.write(chunk)
        tmp.replace(target)
        return target

"""Configuration loading and path resolution.

Load order (later overrides earlier):
  1. packaged ``data/default.toml``
  2. ``~/.game-modifier/config.toml`` (if present)
  3. file referenced by ``$GAME_MODIFIER_CONFIG`` (if set)
  4. explicit ``--config`` path passed to the CLI

The result is a small ``Config`` wrapper with typed accessors and helpers that
resolve the on-disk locations for sessions and user templates.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

try:  # Python 3.11+
    import tomllib as _toml
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    import tomli as _toml  # type: ignore

_PACKAGED_DEFAULT = Path(__file__).with_name("data") / "default.toml"


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in overlay.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        return _toml.load(fh)


class Config:
    """Thin wrapper around the merged config dictionary."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    # ---------------------------------------------------------------- access
    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self._data
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node

    def section(self, name: str) -> dict[str, Any]:
        node = self._data.get(name, {})
        return dict(node) if isinstance(node, dict) else {}

    def as_dict(self) -> dict[str, Any]:
        return dict(self._data)

    # ------------------------------------------------------------- shortcuts
    @property
    def dry_run(self) -> bool:
        return bool(self.get("safety", "dry_run", default=True))

    @property
    def block_anti_cheat(self) -> bool:
        return bool(self.get("safety", "block_anti_cheat", default=True))

    @property
    def auto_backup(self) -> bool:
        return bool(self.get("safety", "auto_backup", default=True))

    @property
    def require_writable_region(self) -> bool:
        return bool(self.get("safety", "require_writable_region", default=True))

    @property
    def max_write_bytes(self) -> int:
        return int(self.get("safety", "max_write_bytes", default=4096))

    @property
    def allowed_paths(self) -> list[str]:
        """Extra allow-list roots for file-touching tools (see safety.validation)."""

        raw = self.get("safety", "allowed_paths", default=[])
        if isinstance(raw, (str, os.PathLike)):
            raw = [raw]
        if not isinstance(raw, list):
            return []
        return [str(p) for p in raw if str(p).strip()]

    @property
    def output_format(self) -> str:
        return str(self.get("output", "format", default="json"))

    @property
    def scan_max_results(self) -> int:
        return int(self.get("scan", "max_results", default=20000))

    @property
    def scan_chunk_size(self) -> int:
        return int(self.get("scan", "chunk_size", default=4 * 1024 * 1024))

    @property
    def scan_alignment(self) -> int:
        # Default to the type's natural alignment (4 for the common dword
        # case). Scanning every byte (alignment=1) is ~4x slower for no
        # benefit on aligned values and was the default before 2026-08.
        return max(1, int(self.get("scan", "alignment", default=4)))

    @property
    def scan_max_region_bytes(self) -> int:
        return int(self.get("scan", "max_region_bytes", default=0))

    @property
    def scan_aob_chunk_size(self) -> int:
        return int(self.get("scan", "aob_chunk_size", default=4 * 1024 * 1024))

    @property
    def scan_workers(self) -> int:
        return max(1, int(self.get("scan", "workers", default=4)))

    @property
    def scan_batch_gap(self) -> int:
        return int(self.get("scan", "batch_gap", default=64))

    @property
    def scan_candidates_sidecar_threshold(self) -> int:
        return int(self.get("scan", "candidates_sidecar_threshold", default=5000))

    @property
    def scan_fingerprint_mode(self) -> str:
        """Region-layout fingerprint mode for the scan candidate cache.

        ``strict`` (default, historical behavior): every region change flips
        the fingerprint. ``lenient``: only regions >= 64 KB are hashed
        individually; smaller regions contribute an aggregate only, so small
        allocator churn no longer invalidates the candidate cache.
        """

        mode = str(self.get("scan", "fingerprint_mode", default="strict")).strip().lower()
        return mode if mode in ("strict", "lenient") else "strict"

    # --------------------------------------------------------------- analysis
    @property
    def pointer_scan_max_depth(self) -> int:
        return int(self.get("analysis", "pointer_scan_max_depth", default=2))

    @property
    def pointer_scan_max_paths(self) -> int:
        return int(self.get("analysis", "pointer_scan_max_paths", default=500))

    @property
    def scan_timeout(self) -> int:
        return int(self.get("analysis", "scan_timeout", default=30))

    # ----------------------------------------------------------------- freeze
    @property
    def freeze_adaptive(self) -> bool:
        return bool(self.get("freeze", "adaptive", default=True))

    @property
    def freeze_min_interval(self) -> float:
        return float(self.get("freeze", "min_interval", default=0.05))

    @property
    def freeze_max_interval(self) -> float:
        return float(self.get("freeze", "max_interval", default=1.0))

    def tool_path(self, name: str) -> str:
        return str(self.get("tools", name, default="") or "")

    def tool_search_dirs(self) -> list[str]:
        extra = self.get("tools", "search_dirs", "extra", default=[])
        return [str(p) for p in extra] if isinstance(extra, list) else []

    # ----------------------------------------------------------------- paths
    @property
    def home_dir(self) -> Path:
        configured = self.get("paths", "home", default="") or ""
        if configured:
            return Path(configured).expanduser()
        return Path.home() / ".game-modifier"

    @property
    def sessions_dir(self) -> Path:
        configured = self.get("paths", "sessions_dir", default="") or ""
        base = Path(configured).expanduser() if configured else self.home_dir / "sessions"
        return base

    @property
    def user_templates_dir(self) -> Path:
        configured = self.get("paths", "user_templates_dir", default="") or ""
        return Path(configured).expanduser() if configured else self.home_dir / "templates"

    def ensure_dirs(self) -> None:
        for path in (self.home_dir, self.sessions_dir, self.user_templates_dir):
            path.mkdir(parents=True, exist_ok=True)


def load_config(explicit_path: Optional[str] = None) -> Config:
    """Build a :class:`Config` from the merge chain described in the module docstring."""

    data: dict[str, Any] = {}
    if _PACKAGED_DEFAULT.exists():
        data = _load_toml(_PACKAGED_DEFAULT)

    user_cfg = Path.home() / ".game-modifier" / "config.toml"
    if user_cfg.exists():
        data = _deep_merge(data, _load_toml(user_cfg))

    env_cfg = os.environ.get("GAME_MODIFIER_CONFIG")
    if env_cfg and Path(env_cfg).exists():
        data = _deep_merge(data, _load_toml(Path(env_cfg)))

    if explicit_path:
        p = Path(explicit_path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"config file not found: {explicit_path}")
        data = _deep_merge(data, _load_toml(p))

    return Config(data)

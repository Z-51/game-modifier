"""Unity custom-encrypted save support: Base64( DES-CBC( JSON ) ).

Many standalone Unity games serialize player state to JSON and then wrap it
in a homegrown scheme: ``Base64( DES-CBC( JSON ) )`` with the key (and often
the IV) hardcoded in the game code. The key/IV are game-specific and must be
supplied by the caller (recovered from the game's assemblies); they are only
used in memory and never persisted to session state.

DES needs an 8-byte key; when the IV is omitted it defaults to the key
itself, which matches the most common Unity implementations.
"""

from __future__ import annotations

import base64
import binascii
import json
import shutil
import warnings
from pathlib import Path
from typing import Any, Optional

from ..errors import (
    DependencyMissingError,
    InvalidArgsError,
    SaveFormatUnsupportedError,
)
from .rmmz import _find_and_set

_NOT_FOUND = object()

# Extensions commonly used by Unity custom save systems. ``.save`` is
# deliberately excluded: it belongs to Ren'Py in the path-based dispatch.
_CANDIDATE_SUFFIXES = {".sav", ".dat"}

# Content sniffing in detect() reads at most this many bytes.
_MAX_SNIFF_BYTES = 4 * 1024 * 1024

_BASE64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

_MISSING_KEY_MESSAGE = "该存档为 Unity 加密格式（Base64(DES-CBC(JSON))），需要提供密钥"
_MISSING_KEY_HINT = (
    "密钥来自游戏代码逆向（Il2Cpp dump / 反编译）。"
    "CLI 使用 --key <密钥>（可选 --iv），MCP 传 key/iv 参数；密钥不落盘。"
)
_CRYPTO_HINT = 'pip install "game-modifier[crypto]"'


def _des_module():
    """Lazily import pycryptodome's DES; degrade gracefully when absent."""

    try:
        from Crypto.Cipher import DES
    except ImportError:
        raise DependencyMissingError(
            "pycryptodome is required for Unity encrypted saves (DES-CBC)",
            hint=_CRYPTO_HINT,
        )
    return DES


def _normalize_block_material(value, *, kind: str) -> bytes:
    """Coerce a key/IV argument to exactly 8 bytes (DES block size).

    Strings are UTF-8 encoded; short material is zero-padded, long material
    truncated (with a warning), mirroring how these games typically derive
    the block material from hardcoded strings.
    """

    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raise InvalidArgsError(
            f"{kind} must be a str or bytes value",
            details={"got": type(value).__name__},
            hint=_MISSING_KEY_HINT,
        )
    if not raw:
        raise InvalidArgsError(
            f"empty {kind} for Unity encrypted save",
            hint=_MISSING_KEY_HINT,
        )
    if len(raw) > 8:
        warnings.warn(
            f"Unity save {kind} longer than 8 bytes truncated to the first 8 bytes",
            stacklevel=3,
        )
        raw = raw[:8]
    elif len(raw) < 8:
        raw = raw + b"\x00" * (8 - len(raw))
    return raw


def _pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("ciphertext length is not a multiple of the block size")
    pad = data[-1]
    if not 1 <= pad <= block_size or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad]


def _pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    pad = block_size - len(data) % block_size
    return data + bytes([pad]) * pad


class UnityHandler:
    """Detect / load / modify Unity custom-encrypted saves.

    Same interface as :class:`RMMZHandler`, except ``load`` / ``save``
    require the game-specific ``key`` (and optional ``iv``).
    """

    # path-based dispatch marks this handler as key-gated
    requires_key = True

    # ------------------------------------------------------------- detect
    def detect(self, game_dir: str) -> list[dict]:
        """Find Unity encrypted save candidates by extension + content.

        A candidate is a ``*.sav`` / ``*.dat`` file whose content is pure
        base64 text decoding to a multiple of the 8-byte DES block size.
        """

        root = Path(game_dir)
        if root.is_file():
            root = root.parent
        if not root.is_dir():
            return []
        found: list[dict] = []
        seen: set[str] = set()
        for hit in sorted(root.rglob("*")):
            if not hit.is_file() or hit.suffix.lower() not in _CANDIDATE_SUFFIXES:
                continue
            if hit.name.endswith(".bak"):
                continue
            key = str(hit.resolve())
            if key in seen:
                continue
            seen.add(key)
            if not self._looks_encrypted(hit):
                continue
            found.append({
                "path": str(hit),
                "engine": "unity-encrypted",
                "format": "des-cbc-base64",
                "size": hit.stat().st_size,
                "editable": "with_key",
            })
        return found

    @staticmethod
    def _looks_encrypted(path: Path) -> bool:
        try:
            if path.stat().st_size > _MAX_SNIFF_BYTES:
                return False
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return False
        if not text or any(ch not in _BASE64_ALPHABET for ch in text if not ch.isspace()):
            return False
        try:
            decoded = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            return False
        return len(decoded) >= 8 and len(decoded) % 8 == 0

    # --------------------------------------------------------------- load
    def load(self, path: str, *, key: Optional[Any] = None, iv: Optional[Any] = None) -> dict:
        """Base64 decode -> DES-CBC decrypt -> JSON parse.

        Falls back to returning the raw decrypted text (marked not editable)
        when the payload is not JSON. A wrong key surfaces as a clear
        :class:`SaveFormatUnsupportedError` instead of garbage data.
        """

        p = Path(path)
        if key is None:
            raise InvalidArgsError(
                _MISSING_KEY_MESSAGE,
                details={"path": str(p)},
                hint=_MISSING_KEY_HINT,
            )
        DES = _des_module()
        key_b = _normalize_block_material(key, kind="key")
        iv_b = _normalize_block_material(iv if iv is not None else key, kind="iv")

        raw = p.read_text(encoding="utf-8", errors="replace").strip()
        try:
            ciphertext = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            raise SaveFormatUnsupportedError(
                f"save file is not valid base64: {p.name}",
                details={"path": str(p)},
                hint="文件可能已损坏，或不是 Base64(DES-CBC(JSON)) 格式；先从 .bak 恢复。",
            )
        if len(ciphertext) < 8 or len(ciphertext) % 8:
            raise SaveFormatUnsupportedError(
                f"decoded payload is not a multiple of the DES block size: {p.name}",
                details={"path": str(p), "length": len(ciphertext)},
                hint="文件可能已损坏，或不是 DES-CBC 加密；先从 .bak 恢复。",
            )

        cipher = DES.new(key_b, DES.MODE_CBC, iv_b)
        try:
            plain = _pkcs7_unpad(cipher.decrypt(ciphertext))
        except ValueError:
            raise SaveFormatUnsupportedError(
                f"cannot decrypt save (PKCS#7 padding invalid): {p.name}",
                details={"path": str(p)},
                hint="密钥/IV 很可能不对——向用户确认密钥（来自游戏代码）后重试。",
            )
        try:
            text = plain.decode("utf-8")
        except UnicodeDecodeError:
            raise SaveFormatUnsupportedError(
                f"decrypted payload is not UTF-8 text: {p.name}",
                details={"path": str(p)},
                hint="密钥/IV 很可能不对——向用户确认密钥（来自游戏代码）后重试。",
            )

        try:
            data: Any = json.loads(text)
        except ValueError:
            # decrypted, but not JSON: surface the raw text, refuse to edit
            return {
                "path": str(p),
                "data": text,
                "encoding": "des-cbc-base64",
                "editable": False,
                "reason": "decrypted payload is not JSON",
            }
        return {"path": str(p), "data": data, "encoding": "des-cbc-base64", "editable": True}

    # ------------------------------------------------------------- modify
    def modify(self, data: Any, field: str, value: Any) -> dict:
        """Same field semantics as RMMZHandler (dotted paths supported)."""

        old: Any = _NOT_FOUND
        if "." in field:
            node = data
            parts = field.split(".")
            for part in parts[:-1]:
                node = node.get(part) if isinstance(node, dict) else None
                if node is None:
                    break
            if isinstance(node, dict) and parts[-1] in node:
                old = node[parts[-1]]
                node[parts[-1]] = value
        else:
            old = _find_and_set(data, field, value)
        found = old is not _NOT_FOUND
        return {
            "found": found,
            "field": field,
            "old_value": old if found else None,
            "new_value": value,
        }

    # --------------------------------------------------------------- save
    def save(self, path: str, data: Any, *, key: Optional[Any] = None,
             iv: Optional[Any] = None, backup: bool = True) -> dict:
        """JSON serialize -> PKCS7 pad -> DES-CBC encrypt -> Base64 encode.

        With ``backup=True`` the original file is copied to ``<name>.bak``
        first, matching the RMMZ handler. The key is only used in memory and
        never written anywhere.
        """

        p = Path(path)
        if key is None:
            raise InvalidArgsError(
                _MISSING_KEY_MESSAGE,
                details={"path": str(p)},
                hint=_MISSING_KEY_HINT,
            )
        DES = _des_module()
        key_b = _normalize_block_material(key, kind="key")
        iv_b = _normalize_block_material(iv if iv is not None else key, kind="iv")

        backup_path: Optional[Path] = None
        if backup and p.exists():
            backup_path = p.with_suffix(p.suffix + ".bak")
            shutil.copy2(p, backup_path)

        text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        cipher = DES.new(key_b, DES.MODE_CBC, iv_b)
        ciphertext = cipher.encrypt(_pkcs7_pad(text.encode("utf-8")))
        p.write_text(base64.b64encode(ciphertext).decode("ascii"), encoding="utf-8")
        return {"path": str(p), "backup": str(backup_path) if backup_path else None}

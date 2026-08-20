"""Unity il2cpp runtime type introspection: decode Il2CppString / List / Dictionary.

All read-only; every function degrades to ``{"ok": False, "reason": ...}``
instead of raising, so a wrong address costs one cheap call.

* :func:`read_string` decodes an ``Il2CppString`` (length@0x10, UTF-16
  chars@0x14) in a single call.
* :func:`read_array_header` exposes the ``Il2CppArray`` bounds / max_length /
  items pointer triple.
* :func:`read_list` walks ``List<T>`` (``_items`` + ``_size``) and decodes
  elements by type (``ptr`` / ``int32`` / ``float`` / ...).
* :func:`read_dict` steps the ``Dictionary<K,V>`` 24-byte entry table,
  skipping free slots, and reports key/value pointers.

All offsets are overridable per call via ``layout=`` for modified runtimes.
"""

from __future__ import annotations

from .il2cpp_types import (
    DEFAULT_LAYOUT,
    read_array_header,
    read_dict,
    read_list,
    read_string,
)

__all__ = [
    "DEFAULT_LAYOUT",
    "read_string",
    "read_array_header",
    "read_list",
    "read_dict",
]

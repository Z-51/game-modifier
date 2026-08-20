"""Backend abstraction for reading/writing another process's memory.

``base`` defines the data structures (regions, modules, process info) and the
``MemoryBackend`` interface. Concrete backends live alongside it:

* ``windows.py`` - ctypes over kernel32 (primary target)
* future: Linux (process_vm_readv/ptrace), macOS (mach vm)

Keeping the interface abstract lets the scanner, pointer resolver, safety layer
and tests share one contract, and lets a ``FakeBackend`` stand in during tests.
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..errors import UnsupportedOSError


@dataclass
class MemoryRegion:
    base: int
    size: int
    protect: int = 0
    state: int = 0
    type: int = 0
    readable: bool = False
    writable: bool = False
    executable: bool = False

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, address: int, length: int = 1) -> bool:
        return self.base <= address and (address + length) <= self.end

    def to_dict(self) -> dict:
        return {
            "base": self.base,
            "base_hex": hex(self.base),
            "size": self.size,
            "readable": self.readable,
            "writable": self.writable,
            "executable": self.executable,
        }


@dataclass
class ModuleInfo:
    name: str
    base: int
    size: int
    path: str = ""

    @property
    def end(self) -> int:
        return self.base + self.size

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "base": self.base,
            "base_hex": hex(self.base),
            "size": self.size,
            "path": self.path,
        }


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe_path: str = ""
    arch: str = "x64"  # "x64" | "x86"
    modules: list[ModuleInfo] = field(default_factory=list)

    @property
    def pointer_size(self) -> int:
        return 4 if self.arch == "x86" else 8

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "arch": self.arch,
            "pointer_size": self.pointer_size,
            "module_count": len(self.modules),
        }


class MemoryBackend(ABC):
    """Interface for attaching to and manipulating a process's memory."""

    def __init__(self) -> None:
        self.info: Optional[ProcessInfo] = None

    # ------------------------------------------------------------- lifecycle
    @abstractmethod
    def open(self, pid: int) -> ProcessInfo:
        """Attach to ``pid`` and populate :attr:`info`."""

    @abstractmethod
    def close(self) -> None:
        ...

    @abstractmethod
    def is_alive(self) -> bool:
        ...

    # -------------------------------------------------------------- read/write
    @abstractmethod
    def read(self, address: int, size: int) -> bytes:
        ...

    @abstractmethod
    def write(self, address: int, data: bytes) -> int:
        ...

    def read_many(self, addresses: list[int], size: int) -> dict[int, bytes]:
        """Default: sequential read. Optimized backends may override."""
        out = {}
        for addr in addresses:
            try:
                out[addr] = self.read(addr, size)
            except Exception:
                pass
        return out

    # ----------------------------------------------------------------- layout
    @abstractmethod
    def regions(self) -> list[MemoryRegion]:
        ...

    @abstractmethod
    def query(self, address: int) -> Optional[MemoryRegion]:
        ...

    def modules(self) -> list[ModuleInfo]:
        return list(self.info.modules) if self.info else []

    def find_module(self, name: str) -> Optional[ModuleInfo]:
        if not self.info:
            return None
        needle = name.lower()
        for mod in self.info.modules:
            if mod.name.lower() == needle:
                return mod
        # allow "GameAssembly" to match "GameAssembly.dll"
        for mod in self.info.modules:
            if mod.name.lower().split(".")[0] == needle.split(".")[0]:
                return mod
        return None

    @property
    def pointer_size(self) -> int:
        return self.info.pointer_size if self.info else 8

    # ----------------------------------------------------------- convenience
    def readable_regions(self) -> Iterable[MemoryRegion]:
        for region in self.regions():
            if region.readable:
                yield region

    def __enter__(self) -> "MemoryBackend":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def get_backend() -> MemoryBackend:
    """Return the appropriate backend for the current OS."""

    if sys.platform.startswith("win"):
        from .windows import WindowsMemoryBackend

        return WindowsMemoryBackend()
    raise UnsupportedOSError(
        f"memory backend not implemented for platform {sys.platform!r}",
        hint="Windows is supported in this release; Linux/macOS backends are planned.",
    )

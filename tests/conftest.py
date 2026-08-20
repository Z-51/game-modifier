"""Shared pytest fixtures and an in-memory fake backend.

The fake backend implements the ``MemoryBackend`` contract over plain
bytearrays so the scanner, pointer resolver, safety layer and service can be
tested deterministically without a real process.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# make the src/ layout importable without installation
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from game_modifier.config import Config  # noqa: E402
from game_modifier.memory.base import MemoryBackend, MemoryRegion, ModuleInfo, ProcessInfo  # noqa: E402


class FakeBackend(MemoryBackend):
    """In-memory backend. ``regions`` maps base address -> bytearray."""

    def __init__(self, regions=None, modules=None, arch="x64", pid=4242, name="fake.exe"):
        super().__init__()
        self._regions: dict[int, bytearray] = {}
        for base, data in (regions or {}).items():
            self._regions[base] = bytearray(data)
        self._modules = modules or []
        self._arch = arch
        self._pid = pid
        self._name = name
        self._alive = True
        # auto-open
        self.open(pid)

    def open(self, pid: int) -> ProcessInfo:
        self.info = ProcessInfo(pid=pid, name=self._name, exe_path=f"C:/games/{self._name}", arch=self._arch, modules=list(self._modules))
        return self.info

    def close(self) -> None:
        pass

    def is_alive(self) -> bool:
        return self._alive

    def _find(self, address: int):
        for base, buf in self._regions.items():
            if base <= address < base + len(buf):
                return base, buf
        return None, None

    def read(self, address: int, size: int) -> bytes:
        base, buf = self._find(address)
        if buf is None:
            raise RuntimeError(f"unmapped read at {hex(address)}")
        off = address - base
        return bytes(buf[off:off + size])

    def write(self, address: int, data: bytes) -> int:
        base, buf = self._find(address)
        if buf is None:
            raise RuntimeError(f"unmapped write at {hex(address)}")
        off = address - base
        buf[off:off + len(data)] = data
        return len(data)

    def query(self, address: int):
        base, buf = self._find(address)
        if buf is None:
            return None
        return MemoryRegion(base=base, size=len(buf), readable=True, writable=True, executable=False, state=0x1000)

    def regions(self):
        return [MemoryRegion(base=base, size=len(buf), readable=True, writable=True, state=0x1000) for base, buf in self._regions.items()]


@pytest.fixture
def fake_backend_factory():
    def _make(**kwargs):
        return FakeBackend(**kwargs)
    return _make


@pytest.fixture
def tmp_config(tmp_path):
    return Config({
        "safety": {"dry_run": True, "block_anti_cheat": True, "auto_backup": True,
                   "require_writable_region": True,
                   # the test playground: file-touching tools may operate under tmp_path
                   "allowed_paths": [str(tmp_path)]},
        "scan": {"max_results": 1000, "chunk_size": 4096, "alignment": 1, "max_region_bytes": 0},
        "output": {"format": "json"},
        "paths": {"home": str(tmp_path / ".game-modifier")},
        "tools": {"search_dirs": {"extra": []}},
    })


@pytest.fixture
def sample_module():
    return ModuleInfo(name="GameAssembly.dll", base=0x140000000, size=0x1000000, path="C:/games/GameAssembly.dll")

"""WindowsMemoryBackend partial-read behaviour.

A short read (0 < bytes_read < requested) used to be returned silently
truncated; the caller then decoded a corrupt value without any error. The
backend must treat a partial read exactly like a failed read.
"""

from __future__ import annotations

import ctypes

import pytest

from game_modifier.errors import ReadFailedError
from game_modifier.memory.windows import WindowsMemoryBackend


class _FakeK32:
    """Minimal kernel32 stand-in: ReadProcessMemory writes n_read bytes."""

    def __init__(self, payload, n_read):
        self.payload = payload
        self.n_read = n_read

    def ReadProcessMemory(self, handle, addr, buf, size, nread):
        # ctypes may pass args as raw CArgObjects when prototypes are not
        # installed; cast to the pointer types the real kernel32 expects.
        nptr = ctypes.cast(nread, ctypes.POINTER(ctypes.c_size_t))
        bptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_char * size))
        nptr[0] = self.n_read
        if self.n_read:
            bptr[0][: self.n_read] = self.payload[: self.n_read]
        return self.n_read == size  # Win32: returns nonzero on full success


def _backend_with(n_read):
    be = WindowsMemoryBackend()
    be._handle = 1
    be._k32 = _FakeK32(b"\xAA" * 16, n_read)
    return be


def test_read_partial_is_error_not_truncation():
    """16-byte request, kernel32 returns only 8 -> must raise, not return 8 bytes."""
    be = _backend_with(n_read=8)
    with pytest.raises(ReadFailedError):
        be.read(0x1000, 16)


def test_read_zero_bytes_is_error():
    be = _backend_with(n_read=0)
    with pytest.raises(ReadFailedError):
        be.read(0x1000, 16)


def test_read_full_success_returns_all_bytes():
    be = _backend_with(n_read=16)
    data = be.read(0x1000, 16)
    assert data == b"\xAA" * 16


def test_read_raises_when_not_attached():
    be = WindowsMemoryBackend()
    with pytest.raises(ReadFailedError):
        be.read(0x1000, 4)

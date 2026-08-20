"""UE structure introspection: probe GObjects/FNamePool layouts, enumerate actors, decode FNames.

All read-only. Every result carries confidence (0.0-0.95) + evidence.

* :func:`introspect` validates a candidate ``TUObjectArray`` / ``FNamePool``
  address pair (item stride, chunk table, name-pool entry dialect) instead of
  trusting dumper offsets; failures degrade to ``verdict="failed"``.
* :func:`enumerate_actors` walks the confirmed GObjects array with batched
  reads + three caches and aggregates actors by class.
* :func:`read_fname` / :func:`decode_fname` / :func:`compare_fname` handle the
  FName lifecycle (raw handle -> decoded string -> index-based comparison).
"""

from __future__ import annotations

from .actors import enumerate_actors
from .fname import compare_fname, decode_fname, read_fname
from .layout import introspect

__all__ = [
    "introspect",
    "enumerate_actors",
    "read_fname",
    "decode_fname",
    "compare_fname",
]

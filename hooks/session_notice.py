#!/usr/bin/env python
"""SessionStart hook: print a one-time single-player-only reminder as context."""

import json
import sys

NOTICE = (
    "game-modifier is loaded. Reminder: use it ONLY on single-player / offline games "
    "you own. It refuses to attach when anti-cheat is detected. Memory writes are "
    "dry-run until --confirm, and originals are auto-backed-up."
)


def main() -> int:
    out = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": NOTICE}}
    try:
        json.dump(out, sys.stdout)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

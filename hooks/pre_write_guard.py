#!/usr/bin/env python
"""PreToolUse hook: require confirmation for applied game-modifier writes.

Claude Code pipes the tool call as JSON on stdin. When the Bash command is a
game-modifier write that will actually apply (contains ``--confirm``), we return
``permissionDecision: ask`` so the user explicitly approves the memory write.
All other commands pass through untouched. Any error fails open (allow), so the
hook never blocks unrelated work.
"""

import json
import sys


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # fail open

    if payload.get("tool_name") != "Bash":
        return 0
    command = (payload.get("tool_input") or {}).get("command", "") or ""

    if "game-modifier" not in command:
        return 0

    applies_write = "--confirm" in command
    is_write_cmd = any(tok in command for tok in (" modify", " nl", " template apply", " batch", " freeze run", " backup restore"))

    if applies_write and is_write_cmd:
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": (
                    "game-modifier is about to write to another process's memory. "
                    "Confirm this is a single-player/offline game you own. Originals are auto-backed-up."
                ),
            }
        }
        json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())

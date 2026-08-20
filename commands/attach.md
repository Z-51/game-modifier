---
description: Attach to a running single-player game process and start a reusable session
argument-hint: "--process <name.exe> | --pid <n> | --exe <path>"
allowed-tools: Bash(game-modifier:*)
---

Attach to the target game process. Running:

!`game-modifier attach $ARGUMENTS`

From the JSON result:
- Report the `session_id` (reuse it in every later game-modifier command).
- Report the detected `engine` and whether `anti_cheat.detected` is true.
- If `anti_cheat.detected` is true, STOP immediately and warn the user: this tool is for single-player/offline games only.

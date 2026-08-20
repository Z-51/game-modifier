---
description: Scan or refine a memory value search (Cheat-Engine style)
argument-hint: "--session <id> --type int32 --value N   (then: scan-next --value M)"
allowed-tools: Bash(game-modifier:*)
---

Locate a value in memory by narrowing candidates.

First scan:
!`game-modifier scan $ARGUMENTS`

Guidance:
- Report `data.count` and the sample `addresses_hex`.
- If many candidates remain, have the user change the value in-game, then run `game-modifier scan-next --session <id> --value <new>` to refine.
- When one candidate remains, save it with `game-modifier name set <name> --session <id> --base 0x<addr> --type <type>`.

---
description: List, show, or apply predefined genre modification templates
argument-hint: "list | show <name> | apply --session <id> --template rpg --option infinite_health [--param k=v] [--confirm]"
allowed-tools: Bash(game-modifier:*)
---

Use a predefined template (rpg/action/strategy). Running:

!`game-modifier template $ARGUMENTS`

Guidance:
- `list` shows templates + options; `show <name>` shows an option's targets.
- `apply` maps each target symbol; if `missing_symbols` is non-empty, scan those values and `name set` them, then re-apply.
- Writes require `--confirm`. Freeze-strategy options register freezes (run `freeze run` to enforce).

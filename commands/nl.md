---
description: Natural-language game edit in Chinese/English, e.g. 将金币设为9999
argument-hint: "--session <id> \"将金币设为9999\" [--confirm]"
allowed-tools: Bash(game-modifier:*)
---

Apply a natural-language modification. Running:

!`game-modifier nl $ARGUMENTS`

Guidance:
- The tool parses the phrase into an intent (action + field + value) and applies it via the session symbol table.
- Supported fields include 金币/生命/法力/移速/弹药/等级/经验; actions include 设为/增加/无限(freeze)/获取.
- Without `--confirm` it dry-runs. With `--confirm` it writes.
- On `E_NEEDS_SCAN`, read `error.details.next` for exactly what to scan, then `name set` the field, then retry the same phrase.

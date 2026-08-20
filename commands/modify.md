---
description: Write a game value by symbol or address (dry-run unless --confirm)
argument-hint: "--session <id> (--symbol NAME | --address 0x..) --type T --value V [--confirm] [--freeze]"
allowed-tools: Bash(game-modifier:*)
---

Modify a value. Running:

!`game-modifier modify $ARGUMENTS`

Guidance:
- Without `--confirm` this is a dry-run: report `old_value` -> `new_value` and ask the user to confirm.
- With `--confirm` it writes and auto-creates a backup (`backup_id`); report `verified_value`.
- Add `--freeze` to keep the value constant (then run `game-modifier freeze run --session <id>`).
- On `E_SYMBOL_NOT_FOUND`, scan for the value and `name set` it first.

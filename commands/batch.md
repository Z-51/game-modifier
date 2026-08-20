---
description: Run a batch file of many game-modifier operations in one call
argument-hint: "run --session <id> path/to/batch.yaml [--confirm] [--continue-on-error]"
allowed-tools: Bash(game-modifier:*)
---

Execute a batch of operations (one tool call, many edits - saves tokens). Running:

!`game-modifier batch $ARGUMENTS`

Guidance:
- The YAML lists `operations:` where each item is one of `nl` / `modify` / `template` / `scan` / `scan_next` / `read` / `resolve` / `name` / `backup`.
- `confirm: true` inside the file (or `--confirm`) applies writes; otherwise it dry-runs.
- Report `ok_count` / `error_count`; if `stopped_early`, inspect the failing step's `error.code`.

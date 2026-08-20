---
description: Detect the game engine and reverse-engineering toolchain for a session/target
argument-hint: "--session <id> [--deep]  (or --target <path>)"
allowed-tools: Bash(game-modifier:*)
---

Analyze the target to plan the modification approach. Running:

!`game-modifier analyze $ARGUMENTS`

From the JSON `data`:
- State the detected `engine` (unity-il2cpp / unity-mono / unreal / unknown) and its `artifacts`.
- List available RE tools from `toolchain.available`.
- Follow `next_steps` to decide whether to dump (Il2Cpp/UE) or scan.

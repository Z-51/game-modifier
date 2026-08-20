---
description: Detect installed reverse-engineering tools (radare2/x64dbg/WinDbg/Il2CppDumper/UE4SS/...)
argument-hint: "detect"
allowed-tools: Bash(game-modifier:*)
---

Detect the available reverse-engineering toolchain. Running:

!`game-modifier toolchain detect`

Report `data.available`. For any tool the user needs but that is missing, share the `hint` (install location) and note it can be set explicitly under `[tools]` in the config file.

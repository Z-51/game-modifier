---
description: Unreal Engine structure introspection (GObjects/FNamePool probe, actor enumeration, FName decode) — read-only
argument-hint: "introspect|actors|fname --session <id> [...]"
allowed-tools: Bash(game-modifier:*)
---

Probe and use UE runtime structures. All three subcommands are **read-only** (no `--confirm` needed).

## Command cheatsheet

```
game-modifier ue introspect --session <id> [--gobjects "Game.exe+0x.."] [--gnames "Game.exe+0x.."] [--gobjects-pattern "AOB"] [--gnames-pattern "AOB"] [--force]
game-modifier ue actors     --session <id> [--gobjects "Game.exe+0x.."] [--limit N] [--filter SUB] [--class SUB] [--list]
game-modifier ue fname      --session <id> [--address 0x..] [--index N] [--compare-index M]
```

- `introspect`: validate GObjects/FNamePool offsets (from a UE dumper). A `confirmed` verdict is cached in the session (`data.cached=true` on later calls; `--force` re-probes). Patterns only produce candidates — never auto-adopted.
- `actors`: enumerate Actor instances over the cached layout. Default output is the aggregate by-class view (token-cheap); add `--class`/`--filter` to narrow, then `--list` for per-actor details.
- `fname`: read an 8-byte FName handle (`--address`, decoded too when a GNames layout is cached), decode a name-pool index (`--index`), or compare two indices (`--index` + `--compare-index`).

## Typical UE workflow

```
1. attach -> session_id
2. ue introspect --session <id> --gobjects "Game.exe+0x1D2E500" --gnames "Game.exe+0x1C9A380"
   -> check data.verdict == "confirmed" (layout now cached)
3. ue actors --session <id> --limit 100               # aggregate by-class view first
   ue actors --session <id> --class Player --list     # details only once narrowed
4. (optional) ue fname --session <id> --address 0x..  # verify field names
5. name set <symbol> --session <id> --base 0x<actor or field addr> --type <type>
6. modify / freeze on the symbol as usual (dry-run first, then --confirm)
```

## Common errors

- `E_LAYOUT_UNSUPPORTED` from `ue actors` / `ue fname --index`: no confirmed layout in the session — run `ue introspect` first (or pass `--gobjects` explicitly to `ue actors`); do not fall back to blind scanning.
- `E_INVALID_ARGS` from `ue fname`: needs `--address` or `--index` (at least one).
- `E_SCAN_TIMEOUT`: probing/enumeration exceeded `[analysis] scan_timeout` — narrow the filters (`--class`/`--filter`, smaller `--limit`) or raise the budget.

Run the requested subcommand:

!`game-modifier ue $ARGUMENTS`

From the JSON `data`: report the `verdict` / cached status (introspect), the `by_class` counts or actor list (actors), or the decoded FName (fname), then follow the workflow above.

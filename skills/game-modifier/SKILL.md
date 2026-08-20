---
name: game-modifier
description: Modify single-player game memory efficiently. Use when the user wants to change game values (gold/health/ammo/speed), apply trainer-style cheats (infinite health/ammo, unlock), or analyze a game's engine/memory. Provides a CLI + MCP with Chinese natural-language edits, genre templates, batch ops, value scanning, and RE-toolchain integration. Single-player / offline only.
---

# game-modifier

Token-efficient toolkit for modifying a single-player game's memory. Prefer these commands over writing memory-manipulation code yourself: they return compact JSON, keep an attached session, and map Chinese phrases to concrete edits.

## Scope and safety (read first)
- Single-player / offline games the user owns. The tool refuses to attach when a known anti-cheat (EasyAntiCheat/BattlEye/Vanguard/...) is detected. Never use it on online/multiplayer titles.
- Writes are dry-run by default. Add `--confirm` (CLI) or `confirm=true` (MCP) to actually write. Originals are auto-backed-up.
- On Windows, attaching may require running the terminal as Administrator.

## Core workflow (minimal tokens)
1. Attach once, reuse the `session_id` in every later call:
   `game-modifier attach --process game.exe`
   (multi-process games, e.g. NW.js/RPG Maker with generic `nw.exe`/`Game.exe` names: `game-modifier attach --title "WindowTitle.*"`)
   If the result contains `save_edit.required=true`, skip memory scanning and jump to the save-edit workflow below.
2. Analyze to learn the engine + available tools + next steps:
   `game-modifier analyze --session <id> [--deep]`
3. Find the address of a value (Cheat-Engine style narrowing):
   - `game-modifier scan --session <id> --type int32 --value 100`
   - play so the value changes, then `game-modifier scan-next --session <id> --value 80`
   - repeat until 1 candidate remains.
4. Name it so you never handle raw addresses again:
   `game-modifier name set player.health --session <id> --base 0x<addr> --type int32`
5. Modify by symbol or natural language:
   - `game-modifier nl --session <id> "将金币设为9999" --confirm`
   - `game-modifier modify --session <id> --symbol player.health --value 100 --confirm --freeze`

## Save-edit workflow (save-file based games: RPG Maker / Ren'Py)
These engines keep player state in save files; memory edits get overwritten. When `attach` flags `save_edit.required=true` (or any command fails with `E_SAVE_EDIT_REQUIRED`):
1. `game-modifier save-edit detect --session <id>` -> `saves[]` (path, format, size, editable, reason)
2. `game-modifier save-edit modify --session <id> --path <save file> --field gold --value 99999` (dry-run: check old_value)
3. re-run with `--confirm` -> `applied:true` + `backup` (a `.bak` copy written before the edit)
`--field` supports dotted paths (e.g. `party.gold`). Edit while the game is at the title screen or closed, then verify by loading the save.

## Command cheatsheet
- `attach --pid N | --process name.exe | --exe path | --title "pattern"` -> session_id + engine + anti-cheat report + `save_edit` flag (`--title` matches the window title, case-insensitive regex or substring)
- `analyze --session <id> [--deep]` -> engine (unity-il2cpp / unity-mono / unreal / nwjs / rpg-maker / renpy / webview), toolchain, next_steps
- `scan` / `scan-next` -> candidate addresses (comparators: exact/gt/gte/lt/lte/between/changed/unchanged/increased/decreased; string/bytes values use contains/regex; first scan runs `[scan] workers` (default 4) threads in parallel, add `--progress` for per-region progress on stderr)
- `scan-aob --session <id> --pattern "48 8B ?? ?? 05" [--max-results N]` -> AOB signature scan across readable regions (`??`/`?`/`xx` wildcards; MCP tool `scan_aob`)
- `scan-candidates --session <id> [--offset N] [--limit M] [--min-addr 0x..] [--max-addr 0x..]` -> page/browse the current scan's persisted candidate set without re-scanning (read-only, O(limit); MCP tool `scan_candidates`)
- MCP-only scan knobs (no CLI flags): `scan` `encoding=utf8|utf16le` (string scans only — `utf16le` maps onto the `string_utf16` type); `scan_next` `retain_stale=true` keeps refining the old candidate set after a region-layout change (reply flagged `retained_stale=true` + staleness hint; default still raises `E_SCAN_CACHE_STALE`); `[scan] fingerprint_mode = strict|lenient` config controls how strictly the candidate cache fingerprints the region layout
- `read --session <id> --symbol NAME | --address 0x.. --type T`
- `modify --session <id> (--symbol NAME | --address 0x..) --type T --value V [--confirm] [--freeze]` -> dry-run returns `status:"dry_run_preview"` + `risk` (target region grading), confirmed writes return `status:"applied"`; judge the outcome by `status`, not just `ok`
- `resolve --session <id> --pointer "Module.dll+0x1234,0x10,0x20"` (or `--base`/`--offsets`) -> final address (pointer chains). Offset semantics via `--mode`: `pointer_chain` (default, deref+offset, CE-style pointer paths), `field_chain` (offset+deref - nested struct field chains like `gem.__data.MainPowerData.mPowerType`; add `--no-deref-last` to stop at a value-typed field's own address instead of dereferencing it), `relative` (plain addition). MCP `resolve`: `mode` + optional `deref_last` (default true)
- `layout --session <id> --what vtables|rtti|class|heap [--address 0x..] [--module Name.dll]` -> memory-layout analysis with per-result `confidence` (MCP tool `layout_analyze` / `heap_scan`)
- `pointer-scan --session <id> --address 0x.. [--max-depth N] [--max-paths N]` -> reverse pointer paths to a target address (MCP tool `pointer_scan`; add `--rescan` / `rescan=true` to re-validate previously saved paths from the `sessions/<id>/pointer_paths.bin` sidecar instead of a fresh scan; add `--async [--timeout N]` / `async_run=true` to run it as a background job: returns `job_id` immediately, no 30s hard timeout, poll with `job status` / `job_status`)
- `job status <job_id> [--session <id>]` / `job list [--session <id>]` / `job cancel <job_id>` -> poll/list/cancel background jobs (progress: `depth` / `paths_found`; results persisted to `sessions/<id>/jobs/<job_id>.json` even when failed/cancelled; MCP tools `job_status` / `job_list` read-only, `job_cancel` writable)
- `dissect --session <id> (--address 0x.. | --addresses 0xA,0xB,0xC) [--size 256]` -> Cheat-Engine style structure dissection: heuristic field types (vtable/ptr/int/float/bool) with per-field `confidence`; multiple same-class instances raise confidence (read-only; MCP tool `dissect`)
- `disasm --session <id> --address 0x..|symbol|Module+0x.. [--size 256] [--arch x86|x64] [--blocks]` -> capstone disassembly of live code, read-only (needs `pip install .[disasm]`; missing -> `E_DEPENDENCY_MISSING`; MCP tool `disasm`)
- `watch run --session <id> --address 0x.. [--type T] [--interval 0.1] [--iterations 100]` / `watch start|stop|report --session <id>` -> poll an address and log every value change (when + old/new; background worker logs to `sessions/<id>/watch.jsonl`; MCP tools `watch_run`/`watch_report` read-only, `watch_start`/`watch_stop` writable)
- `find-writers --session <id> --address 0x.. [--size 1|2|4|8] [--duration 5] [--max-hits 20]` -> hardware write breakpoint (DR0-3): captures the RIP of the instruction writing the address in real time; briefly suspends target threads, needs an Administrator terminal (`E_ACCESS_DENIED` otherwise), refused on anti-cheat sessions (`E_ANTI_CHEAT`); workflow: watch (when) -> find-writers (which instruction) -> disasm (the code) (MCP tool `find_writers`, writable profile only)
- `xrefs --session <id> --address 0x.. [--direction to|from] [--binary PATH]` -> cross-reference query, read-only; `to` = who references it (find the writer), runtime addresses auto-converted to RVA. Primary backend is radare2 (`data.backend="radare2"`); when radare2 is missing it silently falls back to a pure-Python live-memory aligned-pointer scan (`data.backend="python"` — check this field to tell which ran, it never raises `E_TOOL_NOT_FOUND` for a missing radare2). MCP tool `xrefs` adds `aligned` (default true: 4/8-byte alignment filter suppresses false positives; `aligned=false` scans every byte offset; no CLI flag)
- `ue introspect --session <id> [--gobjects "Game.exe+0x.."] [--gnames "Game.exe+0x.."] [--force]` -> probe UE GObjects/FNamePool layouts, cache confirmed verdict in the session (read-only; MCP tool `ue_introspect`)
- `ue actors --session <id> [--limit N] [--filter SUB] [--class SUB] [--list]` -> enumerate UE Actors over the cached layout; default output is the aggregate by-class view, `--list` for details (MCP tool `ue_actors`, params `name_filter` / `class_filter` / `list_results`)
- `ue fname --session <id> (--address 0x.. | --index N [--compare-index M])` -> read/decode/compare a UE FName (read-only; MCP tool `ue_fname`)
- `il2cpp string --session <id> --address 0x.. [--max-chars 4096]` -> decode an Il2CppString in one call (UTF-16, length@0x10 + chars@0x14; no manual byte-splicing; read-only; MCP tool `il2cpp_string`)
- `il2cpp list --session <id> --address 0x.. [--elem-type ptr|int32|float|...] [--limit 100]` -> read a List<T> (`ptr` elements can be fed back into `il2cpp string`; read-only; MCP tool `il2cpp_list`)
- `il2cpp dict --session <id> --address 0x.. [--limit 100]` -> read a Dictionary<K,V> (24-byte entries, free slots skipped; returns key_ptr/value_ptr; read-only; MCP tool `il2cpp_dict`)
- `il2cpp lookup --session <id> --rva 0x..|"RIP-base" [--script-json PATH] [--tolerance 0x100] [--force-index]` -> RVA -> IL2CPP method name over the dump's script.json (lazy index + gzip sidecar cache; `tolerance` matches function-body RVAs to the nearest function start, see `matched`; read-only; MCP tool `il2cpp_lookup`)
- `il2cpp dump --session <id> [--out-dir DIR] [--timeout 120]` -> run Il2CppDumper (auto-selected by metadata version) and associate script.json/dump.cs with the session, so `il2cpp lookup` needs no extra args afterwards (writable profile only; MCP tool `il2cpp_dump`; no dumper installed -> `E_TOOL_NOT_FOUND`)
- `il analyze --session <id> [--assembly PATH] [--type-filter SUB] [--member-filter SUB]` -> enumerate types/methods/fields of a managed assembly via il-tool (Mono games; assembly defaults to the session's Assembly-CSharp.dll; oversized output spills to `sessions/<id>/il/` as `out_file` unless `--member-filter` keeps it inline; read-only; MCP tool `il_analyze`)
- `il dump --session <id> --method NAME [--type T] [--assembly PATH]` -> render one method body's IL instruction stream (full listing spills to `out_file`; feed the opcodes into `il verify --expect` after a patch; read-only; MCP tool `il_dump`)
- `il callers --session <id> [--method SUB] [--type SUB] [--max-results N]` -> scan the assembly for call/callvirt/ldftn references to a target (caller list spills to `out_file`; read-only; MCP tool `il_callers`)
- `il patch --session <id> --op replace_body|mul_before_ret|insert_before_ret|insert_after_call --method NAME [--value V] [--target T] [--assembly PATH] [--out-assembly PATH] [--confirm]` -> rewrite a method's IL (dry-run unless `--confirm`; confirmed patches take an automatic file backup first — `backup_id` in the reply, restorable via `il restore`; `--value` = e.g. the mul_before_ret multiplier, `--target` = called method for insert_after_call; writes in place unless `--out-assembly`; verify with `il verify`; needs the .NET 8 runtime; MCP tool `il_patch`, writable profile only)
- `il verify --session <id> --method NAME --expect "mul,ret" [--type T] [--assembly PATH]` -> read back a method's IL and compare the opcode sequence against an expected pattern (contiguous subsequence match, or JSON `{"expected":[...],"exact":bool}`); the post-patch gate for `il patch` — mismatch returns `ok:false` (`E_IL_VERIFY_FAILED`) with expected/actual in details (read-only; MCP tool `il_verify`, `expect` param)
- `il backup --session <id> [--assembly PATH] [--label TEXT]` / `il restore <backup_id> --session <id> [--confirm]` -> file-level managed-assembly backup/restore (sha256 recorded + audited; `il patch` already backs up before every confirmed patch; restore is dry-run unless `--confirm`, a still-running game needs a restart to pick the restored image up; MCP tools `il_backup`/`il_restore`, writable profile only)
- `mono dump --session <id> [--assembly PATH] [--force] [--timeout 120]` -> build the full type/method index of a managed assembly (fingerprint-cached sidecar: size/mtime/head-hash, reused across calls with `reused=true` while fresh, `--force` rebuilds; the index is associated with the session so `mono symbol` needs no extra args — the il2cpp_dump counterpart for Mono games; MCP tool `mono_dump`, writable profile only but only writes the cached sidecar)
- `mono symbol --session <id> "substring|0xRVA" [--assembly PATH] [--limit N]` -> resolve a name substring (case-insensitive) or an exact `0x..` RVA against the dump index (the `il2cpp lookup` counterpart for Mono games; requires `mono dump` first; read-only; MCP tool `mono_symbol`)
- `mono string --session <id> --address 0x.. [--max-chars 4096] [--arch x86|x64]` -> decode a Mono System.String in one call (arch-aware layout: x86 length@0x8/chars@0xC, x64 0x10/0x14; `--arch` overrides the attached process arch; read-only; MCP tool `mono_string`)
- `mono list --session <id> --address 0x.. [--elem-type ptr|int32|...] [--limit 100]` / `mono dict --session <id> --address 0x.. [--limit 100]` -> read a Mono List<T> / Dictionary<K,V> (same managed layout as the il2cpp decoders; dict entries carry key_ptr/value_ptr — decode with `mono string`; read-only; MCP tools `mono_list`/`mono_dict`)
- `mono static --session <id> [--arch x86|x64] [--max-results 200] [--min-addr 0x..] [--max-addr 0x..]` -> locate static fields by scanning Mono JIT code for ldsfld artifacts (each hit carries code_addr/field_addr/opcode + confidence; read-only; MCP tool `mono_static`)
- `mono heap-scan --session <id> [--vtable-addr 0x..] [--max-results 500]` -> find live Mono objects on the heap, optionally filtered by a Mono class vtable (e.g. from `dissect`/`layout`; read-only; MCP tool `mono_heap_scan`)
- `nl --session <id> "中文指令" [--confirm]` -> parse + apply (金币/生命/移速/弹药/等级...; 设为/无限/增加...)
- `name set <NAME> --session <id> --base <expr> [--offsets ..] [--mode relative|pointer_chain|field_chain] [--temp]` / `name get` -> symbolic address table (`--temp` marks a transient symbol removable via `clear-temp`; the stored mode is reused by later read/modify)
- `name chain <NAME> --session <id> --base "Game.exe+0x1A4" --offsets "0x10,0x28,0x0" [--persist] [--mode pointer_chain|field_chain]` -> walk a multi-level pointer chain and register every intermediate as `<NAME>.step0..N` symbols (temp by default; broken chains keep the resolved intermediates so you can resume at the break; `--persist` keeps them; `--mode field_chain` walks offset+deref struct-field chains; MCP tool `name_chain`, `temp=false` = persist)
- `name clear-temp --session <id>` -> remove all temp symbols (persistent symbols kept; MCP tool `name_clear_temp`)
- `macro define <name> --session <id> (--file macro.yaml | --inline "<YAML>")` / `macro list|show|delete` / `macro run <name> --session <id> --params k=v,k=v [--confirm]` -> reusable parameterized op sequences: define once with `params` (name -> {required, default}) + `operations` (batch syntax, `${param}` placeholders, built-in `${i}` = op index), run many times with different params; runs through the batch pipeline (results persisted to `results_file`); missing required param / unresolved placeholder -> `E_INVALID_ARGS` with `details.missing` (MCP tools `macro_list`/`macro_show` read-only, `macro_define`/`macro_run`/`macro_delete` writable)
- `session snapshot <name> --session <id>` / `session snapshots` / `session restore <name>` -> named snapshots of session state (symbols, scan summary, engine verdict) at `sessions/<id>/snapshots/<name>.json`; restore auto-archives the current state as `<name>.pre-restore.json` first; unknown name -> `E_INVALID_ARGS` with `details.known` (MCP tools `session_snapshots` read-only, `session_snapshot`/`session_restore` writable)
- MCP `session_notes` (`action=get|set|delete`, `key`/`value`) -> per-session key/value notes stored as append-only `sessions/<id>/notes.jsonl` (outside the session JSON); `get` reads one key or all (read-only everywhere), `set` overwrites, `delete` on a missing key returns `not_found=true` instead of an error; `set`/`delete` are writes (refused on the readonly profile with `E_PROFILE_RESTRICTED`); no CLI counterpart
- `template list|show <name>|apply --template rpg --option infinite_health [--param amount=9999] [--confirm]`
- `batch run --session <id> file.yaml [--confirm] [--confirm-code] [--offset N] [--limit M]` -> many edits in one call; full results always persisted to `sessions/<id>/batch_results/<ts>.json` (`results_file` / `results_total` in the reply), `--offset`/`--limit` (MCP `offset`/`limit`) page the inline window — read the file or paginate instead of relying on truncated output. Write-risk grading: previews report per-item `risk` + a summary `risk_breakdown` ({"high": N, "normal": M}); `--confirm` only applies `risk=normal` writes, high-risk targets (executable/read-only/unknown regions) are skipped with `skipped_reason:"high_risk_requires_confirm_code"` unless `--confirm-code` (MCP/YAML top-level `confirm_code: true`) releases them
- MCP `batch_preview` (`file` or inline `yaml`) -> read-only pre-flight before `batch run`: parse + validate + per-op write-risk grading (high/normal/none) + `estimated_write_bytes` total, nothing executed; available in every profile (including readonly). MCP `batch_run` accepts an inline `yaml` parameter as an alternative to `file` (CLI `batch run` still takes a file path)
- `freeze list|clear|run|start|stop --session <id>` (`start`/`stop` = background enforcement; `run` = foreground loop, Ctrl-C to stop)
- `backup create|list|restore <backup_id> --session <id>`
- `file snapshot <path> --session <id> [--label TEXT]` / `file restore <backup_id> --session <id> [--confirm]` -> snapshot/restore any game file with sha256 + audit (copy lands in `sessions/<id>/file_backups/<backup_id>/`; restore is dry-run unless `--confirm` and refused while the game process is still running; a changed source file since the snapshot yields a non-blocking stale warning; MCP tools `file_snapshot`/`file_restore`, writable profile only)
- `save-edit detect --session <id>` / `save-edit modify --session <id> --path <file> --field <name> --value <val> [--confirm]` (MCP tools: `save_edit_detect` / `save_edit_modify`, file param is `file`)
- `toolchain detect` -> which RE tools are installed
- `safety level [--set dry_run_only|normal]` -> show/switch the runtime safety level (process-scoped, not persisted); `dry_run_only` refuses every confirmed modify/nl/batch/macro write with `E_PROFILE_RESTRICTED`, previews keep working (MCP tools `safety_get_level` read-only, all profiles / `safety_set_level`, default profile only)
- `game-modifier-mcp --groups core,scan,modify[,ue|il2cpp|il|mono|analysis|jobs|macros|safety]` -> register only the needed tool groups instead of everything, cutting per-call schema/context cost; `tools_catalog` is always registered and lists every group with its current members/counts (query it instead of hard-coding numbers); `--groups` stacks with `--profile`
- `--profile` safety tiers: `default` (everything) / `readonly` (no writes) / `dry-run` (write tools registered but confirm=true refused server-side with E_PROFILE_RESTRICTED, previews pass) / `symbols` (readonly + name_set/name_chain/name_clear_temp/session snapshots/macro define+delete) / `limited` (readonly + modify/nl single-op writes, no batch/freeze/template). Exact per-profile tool membership: query `tools_catalog` at runtime

## Reading results
Every command prints `{"ok": bool, "command": ..., "data": {...}}` or `{"ok": false, "error": {"code": "E_...", "message", "hint", "details"}}`. Branch on `error.code`:
- `E_NEEDS_SCAN` / `E_SYMBOL_NOT_FOUND`: the value is not mapped yet -> scan for it, then `name set`. The `details.next` field tells you exactly what to scan.
- `E_ANTI_CHEAT`: stop; do not proceed.
- `E_PROCESS_EXITED`: the game closed; re-attach.
- `E_SAVE_EDIT_REQUIRED`: memory edits are ineffective for this game -> switch to `save-edit detect` / `save-edit modify`.
- `E_SAVE_FORMAT_UNSUPPORTED`: this save file cannot be edited yet (unknown extension, compressed, or Ren'Py pickle; `details.known` lists supported extensions) -> do not retry; tell the user.
- `E_PATTERN_NOT_FOUND`: AOB pattern matched nothing -> verify the signature against the current build (patterns drift between game versions), retry with relaxed wildcards.
- `E_LAYOUT_UNSUPPORTED`: the chosen `layout --what` mode is not applicable here (e.g. no RTTI in the module, address not in a heap region) -> pick another mode or address; `details` explains why.
- `E_SCAN_TIMEOUT`: pointer-scan/layout analysis exceeded the time budget (`[analysis] scan_timeout`) -> retry with smaller `--max-depth`/`--max-paths` or a narrower region; for long pointer scans prefer `pointer-scan --async` (MCP `async_run=true`) instead — no hard timeout, partial results persisted. Job terminal states: `failed` -> read its `error`, fix the input before resubmitting; `cancelled` -> partial results are in `results_file`, usable as-is.
- `E_SCAN_CACHE_STALE`: a cached candidate list no longer matches the current scan state (game changed values / process restarted) -> re-run the full `scan` instead of `scan-next`.
- `E_PROFILE_RESTRICTED`: the active `--profile` (dry-run) or runtime safety level (`dry_run_only`) blocks confirmed writes -> do not retry; use confirm=false previews, or restart with a higher profile / `safety level --set normal` (needs the matching permissions).
- Write results carry `status`: `"dry_run_preview"` = nothing was written, `"applied"` = written and verified. Never report a preview as a completed write.

## Engines
- Unity Il2Cpp: run `analyze --deep`, then `il2cpp dump` (runs Il2CppDumper, associates script.json with the session) -> `il2cpp lookup` (RVA -> method name, e.g. interpret `find-writers` RIPs) -> `il2cpp string` / `il2cpp list` / `il2cpp dict` to decode runtime .NET objects; use dump.cs field offsets to build `GameAssembly.dll+RVA` symbols instead of blind scanning.
- Unreal: use a UE dumper for GObjects/GNames offsets, validate them with `ue introspect`, enumerate instances with `ue actors`, then `name set` + `resolve`/`modify` (see the `ue` commands above).
- Unknown/native: use `scan`/`scan-next`.
- NW.js / RPG Maker / Ren'Py / WebView: detected by web-runtime markers (`nw.dll`, `rmmz_core.js`, `renpy/` dir, ...); their `.pak` files no longer cause an Unreal misdetection. RPG Maker / Ren'Py are flagged `save_edit` -> use the save-edit workflow (RPG Maker `.rmmzsave`/`.rpgsave`/`.json` saves are editable; Ren'Py `.save` is detect-only).

## Templates
Genre templates (`rpg`, `action`, `strategy`) standardize what to change (e.g. `action/infinite_ammo` freezes `weapon.ammo`). They reference symbolic names, so map those symbols first (scan + `name set`); `template apply` reports any missing symbols.

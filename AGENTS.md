# game-modifier — agent integration guide

Token-efficient single-player game memory modifier. This file tells a coding
agent (Codex CLI, Claude Code, etc.) how to use it. **Single-player / offline
games only.** The tool refuses to attach when anti-cheat is detected.

> Headline project metrics (source/test counts, MCP tool count, error codes)
> are maintained by `scripts/refresh_metrics.py` — never hard-code them here;
> re-run the script and paste its output when updating docs.

## Install
```
pip install -e .            # from this repo (adds `game-modifier` + `game-modifier-mcp`)
pip install -e .[all]       # + psutil, r2pipe, mcp, capstone, pytest
pip install -e .[disasm]    # capstone only (needed by the `disasm` command)
```
Windows is the supported target this release. Attaching may require an
Administrator terminal.

## Two ways to call it

### 1. CLI (works in any agent that can run shell commands)
Every command prints one JSON line: `{"ok": bool, "command": ..., "data"|"error": ...}`.
```
game-modifier attach --process game.exe
game-modifier attach --title "WindowTitle.*"       # match by window title (NW.js multi-process games)
game-modifier analyze --session <id> --deep
game-modifier scan --session <id> --type int32 --value 100 [--progress]   # --progress prints per-region progress to stderr
game-modifier scan-next --session <id> --value 80
game-modifier scan-aob --session <id> --pattern "48 8B ?? ?? 05"   # AOB pattern scan (? wildcards)
game-modifier layout --session <id> --what vtables     # also rtti / class / heap
game-modifier pointer-scan --session <id> --address 0x<addr>   # discover pointer chains
game-modifier pointer-scan --session <id> --address 0x<addr> --rescan   # re-validate saved paths (pointer_paths.bin sidecar)
game-modifier pointer-scan --session <id> --address 0x<addr> --async [--timeout N]   # background job: returns job_id immediately, no 30s hard timeout
game-modifier job status <job_id> [--session <id>]   # poll progress (depth/paths_found); results persisted to sessions/<id>/jobs/<job_id>.json
game-modifier job list [--session <id>]              # list background jobs
game-modifier job cancel <job_id>                    # cooperative cancel; partial results are kept
game-modifier dissect --session <id> --address 0x<addr> [--addresses a,b,c] [--size 256]   # auto-dissect object fields (read-only)
game-modifier find-writers --session <id> --address 0x<addr> [--size 1|2|4|8] [--duration 5] [--max-hits 20]   # hardware write watchpoint (DR0-3; admin required)
game-modifier disasm --session <id> --address 0x<addr> [--size 256] [--arch x64] [--blocks]   # capstone disassembly (read-only)
game-modifier watch run --session <id> --address 0x<addr> [--type int32] [--interval 0.1] [--iterations 100]   # foreground value-change monitor
game-modifier watch start --session <id> --address 0x<addr>   # background watch (logs to sessions/<id>/watch.jsonl; watch stop / watch report)
game-modifier xrefs --session <id> --address 0x<addr> [--direction to|from] [--binary path]   # radare2 cross-references (read-only; silent pure-Python fallback when radare2 is absent - check data.backend)
game-modifier ue introspect --session <id> --gobjects "Game.exe+0x1D2E500" --gnames "Game.exe+0x1C9A380"   # probe GObjects/FNamePool (read-only)
game-modifier ue actors --session <id> --limit 100             # enumerate actors (aggregate view; --list for details)
game-modifier ue fname --session <id> --address 0x<addr>       # read/decode/compare FName (--index / --compare-index)
game-modifier il2cpp string --session <id> --address 0x<addr> [--max-chars 4096]   # decode Il2CppString (UTF-16, read-only)
game-modifier il2cpp list --session <id> --address 0x<addr> [--elem-type ptr|int32|float|...] [--limit 100]   # List<T> (read-only)
game-modifier il2cpp dict --session <id> --address 0x<addr> [--limit 100]   # Dictionary<K,V> (read-only)
game-modifier il2cpp lookup --session <id> --rva 0x... [--script-json path] [--tolerance 0x100] [--force-index]   # RVA -> method name over script.json (read-only)
game-modifier il2cpp dump --session <id> [--out-dir path] [--timeout 120]   # run Il2CppDumper, associate script.json/dump.cs with the session
game-modifier name set player.gold --session <id> --base 0x<addr> --type int32   # --temp marks it transient
game-modifier name chain mgr --session <id> --base "Game.exe+0x1A4" --offsets 0x10,0x28,0x0   # registers mgr.step0..stepN intermediates (temp by default; --persist to keep)
game-modifier name clear-temp --session <id>   # remove all temp symbols (persistent symbols kept)
game-modifier session snapshot <name> --session <id>   # save a snapshot of the session state (sessions/<id>/snapshots/<name>.json)
game-modifier session snapshots --session <id>         # list snapshots
game-modifier session restore <name> --session <id>    # restore a snapshot (current state auto-archived as <name>.pre-restore.json)
game-modifier nl --session <id> "将金币设为9999" --confirm
game-modifier read --session <id> --address "0x1b0c00276c5-0x8" --type int32   # address arithmetic (only +/-) also works for modify --address and resolve --base
game-modifier modify --session <id> --symbol player.health --value 100 --confirm --freeze   # high-risk (code) targets: add --confirm-code
game-modifier results-read --session <id> --path sessions/<id>/batch_results/<ts>.json [--offset N --limit M]   # page back spilled artifacts (session dir only)
game-modifier freeze start --session <id>     # background enforcement (freeze stop to end)
game-modifier template apply --session <id> --template action --option infinite_ammo --confirm
game-modifier batch run --session <id> ops.yaml --confirm [--offset N --limit M]   # full results always persisted to sessions/<id>/batch_results/*.json (results_file); offset/limit page the inline window
game-modifier scan-candidates --session <id> [--offset N] [--limit M] [--min-addr 0x..] [--max-addr 0x..]   # page/browse the current scan's candidate set (read-only)
game-modifier il analyze --session <id> [--assembly GameAssembly.dll] [--type-filter Sub] [--member-filter Sub]   # .NET assembly metadata via the il-tool subprocess (read-only; needs the .NET 8 runtime)
game-modifier il dump --session <id> --method "Namespace.Type::Method" [--type T] [--assembly path]   # dump one method's IL body (read-only)
game-modifier il callers --session <id> --method Sub [--type Sub] [--max-results N]   # who calls this method (read-only)
game-modifier il patch --session <id> --op replace_body|mul_before_ret|insert_before_ret|insert_after_call --method M [--value V] [--target T] [--out-assembly path] --confirm   # rewrite IL (auto file-backup first; writes a new image unless --out-assembly)
game-modifier il verify --session <id> --method M --expect "mul,ret"   # assert a method's IL opcodes after patching (read-only)
game-modifier il backup --session <id> [--assembly path] [--label note]   # FileBackupManager snapshot (sha256 + manifest)
game-modifier il restore --session <id> <backup_id> --confirm   # restore an il backup
game-modifier mono dump --session <id> [--assembly Assembly-CSharp.dll] [--force]   # dump Mono runtime types (fingerprint-cached sidecar, reused across calls)
game-modifier mono symbol --session <id> "substring|0xRVA" [--limit N]   # resolve name/RVA against the dump index (read-only)
game-modifier mono string --session <id> --address 0x.. [--max-chars 4096] [--arch x86|x64]   # decode a Mono string (arch-aware layout, read-only)
game-modifier mono list --session <id> --address 0x.. [--elem-type ptr|int32|...] [--limit 100]   # read a Mono List<T> (read-only)
game-modifier mono dict --session <id> --address 0x.. [--limit 100]   # read a Mono Dictionary<K,V> (read-only)
game-modifier mono static --session <id> [--max-results 200] [--min-addr 0x..] [--max-addr 0x..]   # scan JIT code for static-field loads (read-only)
game-modifier mono heap-scan --session <id> [--vtable-addr 0x..] [--max-results 500]   # find live Mono objects by vtable (read-only)
game-modifier file snapshot --session <id> saves/file.dat [--label "before edit"]   # snapshot any external file into sessions/<id>/file_backups/ (sha256 + audit)
game-modifier file restore --session <id> <backup_id> --confirm   # restore a file backup (refused while the game process is running)
game-modifier save-edit detect --session <id>       # save-file based games (RPG Maker / Ren'Py)
game-modifier save-edit modify --session <id> --path saves/file1.rmmzsave --field gold --value 99999 --confirm
```

### 2. MCP server (recommended for structured tool calls)
For **Codex CLI**, add to `~/.codex/config.toml`:
```toml
[mcp_servers.game-modifier]
command = "game-modifier-mcp"
args = []
```
For **Claude Code**, this repo already ships `.mcp.json` and the plugin manifest.

Tools exposed (default profile — the authoritative, always-current list and
count come from the `tools_catalog` MCP tool at runtime; do not hard-code
numbers here). The default profile registers every group: `attach, analyze,
scan, scan_next, scan_aob, scan_candidates, read, modify, resolve, nl,
name_set, name_get, name_chain, name_clear_temp, template_list,
template_show, template_apply, batch_run, batch_preview, freeze_list,
freeze_start, freeze_stop, backup_create, backup_list, backup_restore,
file_snapshot, file_restore, save_edit_detect, save_edit_modify,
toolchain_detect, sessions, session_info, session_survey,
session_snapshot, session_snapshots, session_restore, session_notes,
audit_tail, results_read, value_convert, layout_analyze, heap_scan, pointer_scan,
job_status, job_list, job_cancel,
macro_list, macro_show, macro_define, macro_run, macro_delete,
ue_introspect, ue_actors, ue_fname, il2cpp_string, il2cpp_list, il2cpp_dict,
il2cpp_lookup, il2cpp_dump, il_analyze, il_dump, il_callers, il_patch,
il_verify, il_backup, il_restore, mono_dump, mono_symbol, mono_string,
mono_list, mono_dict, mono_static, mono_heap_scan,
disasm, watch_run, watch_start,
watch_stop, watch_report, find_writers, xrefs, dissect, detach,
safety_get_level, safety_set_level, tools_catalog`.
(`pointer_scan` accepts an optional `rescan=true` to re-validate previously
saved paths, and `async_run=true` [+ optional `timeout` seconds] to run as a
background job polled via `job_status` / `job_list` and stopped via
`job_cancel`. `batch_run` accepts `offset` / `limit` to page the inline
results window, and an inline `yaml` parameter as an alternative to `file`.
`batch_preview` is a read-only pre-check of a batch (per-item risk grading +
`estimated_write_bytes`) available in every profile. `scan` / `scan_aob`
accept `offset`/`limit` pagination and `scan_aob` region filters
(`min_addr`/`max_addr`/`region_types`-style bounds, `stop_on_limit`); both
persist the full candidate set and return `results_file` + a
`region_summary`. `scan_candidates` pages through that persisted candidate
set without re-scanning. `session_notes` keeps key/value notes per session
(`get` is read-only everywhere; `set`/`delete` need a non-readonly profile).
`results_read` pages back any artifact under `sessions/<id>/` (spilled il
dumps, batch results, scan sidecars) with `offset`/`limit` - it is confined
to the session directory (`E_PATH_NOT_ALLOWED` on escape) and exists in every
profile including readonly.
`xrefs` adds an `aligned` flag (default true) and a pure-Python fallback
when radare2 is missing — check `data.backend` for `radare2` vs `python`.)

Tools are organised into groups (`core, scan, modify, analysis, ue, il2cpp,
il, mono, jobs, macros, safety`); start the server with `--groups core,scan`
to register only those groups and cut per-call context cost (default
registers everything; `tools_catalog` lists the groups and their current
members/counts and is always registered). The readonly profile still applies
on top of `--groups`.

Start the server with `--profile readonly` to register only the read-only
tools (every write tool — modify/nl/name writes/template_apply/batch_run/
freeze_*/watch_start/watch_stop/find_writers/backup_*/file_snapshot/
file_restore/save_edit_modify/il2cpp_dump/il_patch/il_backup/il_restore/
mono_dump/detach/job_cancel/macro writes/session writes/safety_set_level —
is excluded) for safe deployments.
Finer-grained profiles exist too: `--profile dry-run` (write tools registered
but confirm=true refused server-side with E_PROFILE_RESTRICTED),
`--profile symbols` (read-only + name_set/name_chain/name_clear_temp/
session_snapshot/session_restore/macro_define/macro_delete) and
`--profile limited` (read-only + modify/nl + symbol management; batch/freeze/
template bulk writes excluded). See `tools_catalog` for the exact current
membership of each profile. Independently of the profile, the runtime
safety level can be inspected with `safety_get_level` (read-only) and
switched with `safety_set_level` / CLI `safety level [--set dry_run_only|normal]`
(process-scoped; `dry_run_only` refuses every confirmed modify/nl/batch write).
Write tools are additionally risk-graded: high-risk targets (executable /
read-only / unknown regions) need an explicit `confirm_code=true` on top of
`confirm=true` (modify/nl/batch/macro); ordinary writes only need `confirm`.
File-touching tools (`file_snapshot`/`file_restore`/`save_edit_modify`/
`batch_run file=`) only accept paths inside an allow-list (game dir, sessions
dir, common save locations; extend via `[safety] allowed_paths`) - a path
outside it fails with `E_PATH_NOT_ALLOWED`, and the OS system directory is a
hard deny. Session-mutating ops are serialized per session (in-process lock +
cross-process lockfile), so a concurrent CLI and MCP writer can no longer
clobber each other's session state; contention surfaces as `E_SESSION_BUSY`
(retry after the running scan/batch finishes).
The UE introspection tools (`ue_introspect` / `ue_actors` / `ue_fname`),
the Unity il2cpp decoders (`il2cpp_string` / `il2cpp_list` / `il2cpp_dict` /
`il2cpp_lookup`; `il2cpp_dump` runs an external dumper and is writable-only),
the `il` group (static .NET IL inspection via the bundled `il-tool`
subprocess — `il_analyze`/`il_dump`/`il_callers`/`il_verify` are read-only,
`il_patch`/`il_backup`/`il_restore` are writes; needs the .NET 8 runtime),
the `mono` runtime tools (`mono_string`/`mono_list`/`mono_dict`/`mono_static`/
`mono_heap_scan`/`mono_symbol` are read-only in every profile; `mono_dump`
is writable-only but only writes a cached sidecar file),
`disasm`, `xrefs`, `dissect`, `watch_run` and `watch_report` are read-only and included
in both profiles. `disasm` needs capstone (`pip install game-modifier[disasm]`,
otherwise `E_DEPENDENCY_MISSING`); `xrefs` prefers radare2/r2pipe and falls
back to a pure-Python aligned-pointer scan when absent (`data.backend` tells
you which ran).
Oversized replies are throttled: anything above ~50 000 chars is truncated to a
preview (`data.totals` holds the original counts). `batch_run` is the
exception: its oversized reply becomes a summary + the first 10 results plus
`results_file` — the full result set is always persisted at
`sessions/<id>/batch_results/<ts>.json`, so read that file (or re-call with
`offset`/`limit`) instead of relying on the preview.

## Why this saves tokens
- Attach once; reuse `session_id` (no re-sending process/module maps).
- Deterministic Chinese NLP: pass one phrase, no reasoning or code needed.
- Symbolic address table: reference `player.gold`, never raw pointer chains.
- Built-in address arithmetic: `read`/`modify`/`resolve` accept `0x...+/-0x...` expressions (decimal/hex mix, negative result refused), and `value_convert` evaluates them too (`expression`/`evaluated` fields) - never compute addresses by hand. Module syntax `game.exe+0x1A4` is unaffected.
- Templates and batch files: many edits in a single call. Full batch results
  are always persisted to `results_file`; use `offset`/`limit` (or read the
  file) for large result sets.
- Long-running analysis as background jobs: `pointer-scan --async` (MCP
  `pointer_scan` with `async_run=true`) returns a `job_id` immediately with no
  30s hard timeout; poll `job status` / `job_status` for progress
  (depth/paths_found) and get results from `sessions/<id>/jobs/<job_id>.json`.
  Partial results survive cancellation and failure.
- Compact JSON with stable `error.code`s: branch without parsing prose.

## Safety contract
- Writes are dry-run unless `--confirm` / `confirm=true`; originals auto-backed-up (`backup restore` to revert; `save-edit modify` writes a `.bak` next to the save file).
- A single write is capped by `safety.max_write_bytes` (default 4096 bytes); larger spans are refused. Every confirmed write is appended to the per-session audit trail at `sessions/<id>/audit.jsonl` (read it back with the `audit_tail` MCP tool).
- UE structure introspection (`ue introspect` / `ue actors` / `ue fname`) and `dissect` are strictly read-only: they never write memory and need no `--confirm`. A confirmed layout is cached in the session (`introspect` field) and served directly on later calls unless `--force` re-probes.
- `find-writers` uses hardware debug registers (DR0-3): it briefly suspends target threads while sampling (capped by `--duration`), restores all debug-register state and detaches on every exit path, and requires an Administrator terminal (`E_ACCESS_DENIED` otherwise). It is refused outright on sessions where anti-cheat was detected (`E_ANTI_CHEAT`).
- Background jobs (`pointer-scan --async`) are read-only analysis: they never write game memory, persist their results to `sessions/<id>/jobs/<job_id>.json` before flipping to done/cancelled, so partial work is never lost to a timeout; use them instead of synchronous scans when the scan may exceed the 30s budget. For large `batch run` output, always take the full data from `results_file` (or `--offset`/`--limit`), never from a truncated preview.
- On `error.code == E_ANTI_CHEAT`: stop. On `E_NEEDS_SCAN` / `E_SYMBOL_NOT_FOUND`: scan then `name set`. On `E_PROCESS_EXITED`: re-attach.
- On `E_SAVE_EDIT_REQUIRED` (or `attach` returns `save_edit.required=true`): skip memory scanning, use `save-edit detect` → `save-edit modify`. On `E_SAVE_FORMAT_UNSUPPORTED`: the save format cannot be edited yet (compressed / Ren'Py pickle) — do not retry.
- On `E_PATTERN_NOT_FOUND`: the AOB signature matched nothing — broaden/recheck the pattern. On `E_LAYOUT_UNSUPPORTED`: layout analysis can't run here — fall back to plain `scan`; when it comes from `ue actors` / `ue fname`, run `ue introspect` first (or pass `--gobjects` explicitly). On `E_SCAN_TIMEOUT`: a scan hit its time budget — narrow the range or raise `[analysis] scan_timeout`. On `E_SCAN_CACHE_STALE`: the region layout changed since the last scan — re-run a fresh `scan` instead of `scan-next`.
- `xrefs` when radare2 is missing: it does NOT raise `E_TOOL_NOT_FOUND` — it silently switches to the pure-Python live-memory fallback; tell the backends apart via `data.backend` (`radare2` vs `python`). The fallback opt-out (`fallback=false`) exists only at the service level and is deliberately not exposed through MCP/CLI — a reviewed decision to keep the `test_surface_lock.py` golden schemas unchanged.
- `E_PROCESS_EXITED` from `xrefs` can come from the Python fallback scan (its live-memory reads hit a dying process), not necessarily from a stale attach — re-attach once; if it persists while the game is provably alive, the fallback scan itself raced, just retry.
- On `E_PATH_NOT_ALLOWED`: the file path is outside the allow-list — move the file under the game dir / a save location, or add the root to `[safety] allowed_paths` in `~/.game-modifier/config.toml`; the OS system directory can never be unlocked. On `E_SESSION_BUSY`: another op (scan/batch) holds the session — wait and retry, or `job list` / `job cancel` first.

## Engine detection
`attach` / `analyze` report the engine: `unity-il2cpp`, `unity-mono`, `unreal`,
`nwjs`, `rpg-maker`, `renpy`, `webview`, or `unknown`. NW.js-family games also
ship `.pak` files; detection excludes them so they are no longer misread as
Unreal. RPG Maker / Ren'Py results set `save_edit.required=true` — use the
`save-edit` commands instead of memory scanning. These games are often
multi-process with generic exe names (`nw.exe` / `Game.exe`); prefer
`attach --title` there.

For `unity-il2cpp` games the recommended workflow is:
`analyze` → `il2cpp dump` (run Il2CppDumper, associate `script.json` with the
session) → `il2cpp lookup` (RVA → method name, e.g. to interpret RIPs from
`find-writers`) → `il2cpp string` / `il2cpp list` / `il2cpp dict` to decode
runtime .NET objects directly (no manual UTF-16 splicing).

## Reverse-engineering toolchain
`game-modifier toolchain detect` reports installed tools. Optional, auto-detected,
degrade gracefully if absent:
- radare2 / rizin (static analysis; `analyze --deep`, `xrefs`)
- x64dbg (script generation), WinDbg/cdb (inspection)
- Il2CppDumper / il2cpp-dumper-rs / Il2CppInspector (Unity Il2Cpp field offsets + method RVAs)
- UE4 Dumper / UE4SS (Unreal GObjects/GNames)
Set explicit paths under `[tools]` in `~/.game-modifier/config.toml` if not on PATH.

## AI-assisted toolchain installation
When a required tool is missing, **prefer proposing an AI-driven install over
giving up or silently degrading**. Triggers:
- `toolchain detect` reports a tool with `found: false` + an install `hint`;
- a command returns `E_TOOL_NOT_FOUND` / `E_DEPENDENCY_MISSING` (the `hint`
  field already carries the install guidance);
- `analyze` detects the engine but its dump artifacts are missing (no
  `script.json` for il2cpp, no GObjects/GNames offsets for UE);
- an `il2cpp dump` / UE analysis flow starts and finds its dumper missing.

Standard flow: tell the user which tool is missing and why it matters → give
the exact install command (below) → after the user confirms, run the install
(or let the user install manually) → verify with `toolchain detect`
(`found: true`) → retry the original command. Only fall back to degradation
(no `--deep`, plain `scan`) when the user declines or the environment cannot
install.

Engine → tool quick reference:

| Situation | Recommended install | How |
| --- | --- | --- |
| `engine=unity-il2cpp`, no dump artifacts | **il2cpp-dumper-rs** (preferred: fast Rust build, metadata v16-v39) or Il2CppDumper (metadata ≤ 31 / Unity < 2022.2 only) | GitHub release binary (or `cargo install il2cpp_dumper`); set `tools.il2cppdumper_rs` (or `tools.il2cppdumper`) if not on PATH |
| `engine=unreal`, no GObjects/GNames offsets | **UE4SS** (preferred: runtime injection + SDK dump) or UE4 Dumper / Dumper-7 | UE4SS release into the game directory; set `tools.ue4ss` (or `tools.ue4dumper`) |
| `analyze --deep` → `E_TOOL_NOT_FOUND` (radare2 missing; `xrefs` does NOT raise — it silently falls back to the pure-Python scanner, `data.backend=python`) | radare2 + r2pipe | `winget install radare2` (or official download on PATH), then `pip install ".[radare2]"` |
| `disasm` → `E_DEPENDENCY_MISSING` | capstone | `pip install ".[disasm]"` |

Non-PATH tools are configured in `~/.game-modifier/config.toml` (keys are the
`[tools]` config names probed by `toolchain/registry.py`):

```toml
[tools]
il2cppdumper_rs = "C:/Tools/il2cpp-dumper-rs/il2cpp_dumper.exe"
il2cppdumper = "C:/Tools/Il2CppDumper/Il2CppDumper.exe"
ue4ss = "D:/Games/MyGame/UE4SS.dll"
radare2 = "C:/Tools/radare2/bin/radare2.exe"

[tools.search_dirs]
extra = ["C:/Tools"]   # additional auto-detect directories
```

Full key list: `radare2`, `rizin`, `x64dbg`, `x32dbg`, `cdb`, `windbg`,
`binaryninja`, `il2cppdumper`, `il2cppdumper_rs`, `il2cppinspector`,
`ue4dumper`, `ue4ss`, `il_tool`.

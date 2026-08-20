"""Command-line interface for game-modifier.

Thin argparse layer over :class:`game_modifier.service.ModifierService`. Every
command prints one JSON envelope (see :mod:`game_modifier.output`) and returns a
process exit code (0 ok / 1 error). JSON is the default because it is the
token-efficient contract for agents; ``--format human`` is available for people.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

import yaml

from . import __version__
from .config import load_config
from .errors import GameModifierError, InvalidArgsError
from .output import Result, emit
from .service import ModifierService


# --------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="game-modifier",
        description="Token-efficient single-player game memory modifier (Claude Code / Codex plugin).",
    )
    p.add_argument("--config", help="path to a TOML config file")
    p.add_argument("--format", choices=["json", "json-pretty", "human"], help="output format (default: config/json)")
    p.add_argument("--json", action="store_true", help="shorthand for --format json (the default)")
    p.add_argument("--version", action="store_true", help="print version and exit")

    sub = p.add_subparsers(dest="command")

    # attach
    sp = sub.add_parser("attach", help="attach to a running game process")
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--pid", type=int)
    g.add_argument("--process", help="process name, e.g. game.exe")
    g.add_argument("--exe", help="full path to the game executable")
    g.add_argument("--title", help="window title pattern (regex or substring, for multi-process games)")
    sp.add_argument("--allow-anti-cheat", action="store_true", help="override the anti-cheat refusal (not recommended)")

    # analyze
    sp = sub.add_parser("analyze", help="detect engine + toolchain, optionally static analysis")
    sp.add_argument("--session")
    sp.add_argument("--target", help="path to game exe/dir (when no session)")
    sp.add_argument("--deep", action="store_true", help="run radare2 static analysis if available")

    # scan / scan-next
    sp = sub.add_parser("scan", help="first value scan across readable memory")
    sp.add_argument("--session", required=True)
    sp.add_argument("--type", default="int32")
    sp.add_argument("--value")
    sp.add_argument("--comparator", default="exact")
    sp.add_argument("--value2", help="second bound for 'between'")
    sp.add_argument("--progress", action="store_true",
                    help="print per-region scan progress to stderr")

    sp = sub.add_parser("scan-next", help="refine the previous scan")
    sp.add_argument("--session", required=True)
    sp.add_argument("--comparator", default="exact")
    sp.add_argument("--value")
    sp.add_argument("--value2")

    sp = sub.add_parser("scan-aob", help="AOB pattern scan with ?? wildcards")
    sp.add_argument("--session", required=True)
    sp.add_argument("--pattern", required=True, help="e.g. '48 8B ?? ?? 05'")
    sp.add_argument("--max-results", type=int, default=1000)

    sp = sub.add_parser("scan-candidates", help="page the current scan candidate set (read-only)")
    sp.add_argument("--session", required=True)
    sp.add_argument("--offset", type=int, default=0)
    sp.add_argument("--limit", type=int, default=100)
    sp.add_argument("--min-addr", help="hex/decimal lower address bound (inclusive)")
    sp.add_argument("--max-addr", help="hex/decimal upper address bound (inclusive)")

    # read
    sp = sub.add_parser("read", help="read a value by symbol or address")
    sp.add_argument("--session", required=True)
    sp.add_argument("--symbol")
    sp.add_argument("--address")
    sp.add_argument("--type")
    sp.add_argument("--offsets", help="pointer offsets, e.g. '0x10,0x20'")
    sp.add_argument("--mode", choices=["relative", "pointer_chain", "field_chain"],
                    help="offset semantics: 'relative' (default for bare addresses, plain addition), "
                         "'pointer_chain' (dereference then add offset, CE-style pointer paths) "
                         "or 'field_chain' (add offset then dereference, nested struct fields)")

    # modify
    sp = sub.add_parser("modify", help="write a value (dry-run unless --confirm)")
    sp.add_argument("--session", required=True)
    sp.add_argument("--symbol")
    sp.add_argument("--address")
    sp.add_argument("--type")
    sp.add_argument("--value")
    sp.add_argument("--offsets")
    sp.add_argument("--mode", choices=["relative", "pointer_chain", "field_chain"],
                    help="offset semantics (see 'read --mode')")
    sp.add_argument("--confirm", action="store_true", help="actually apply the write")
    sp.add_argument("--confirm-code", action="store_true",
                    help="release high-risk writes (executable/read-only/unknown regions); "
                         "requires --confirm")
    sp.add_argument("--freeze", action="store_true", help="register a freeze on this target")

    # resolve
    sp = sub.add_parser("resolve", help="resolve a pointer path to an address")
    sp.add_argument("--session", required=True)
    sp.add_argument("--base", help="base expr, e.g. 'GameAssembly.dll+0x1234'")
    sp.add_argument("--pointer", help="full path 'Module.dll+0x1234,0x10,0x20' (base then offsets)")
    sp.add_argument("--offsets")
    sp.add_argument("--mode", choices=["relative", "pointer_chain", "field_chain"], default="pointer_chain",
                    help="offset semantics (default pointer_chain for module forms; "
                         "field_chain walks nested struct fields: addr = read(addr + offset))")
    sp.add_argument("--deref-last", action=argparse.BooleanOptionalAction, default=True,
                    help="field_chain only: dereference the final offset step (default true); "
                         "--no-deref-last stops at the value-typed field's own address")

    # nl
    sp = sub.add_parser("nl", help="natural-language modify (Chinese/English)")
    sp.add_argument("--session", required=True)
    sp.add_argument("text", help="e.g. '将金币设为9999'")
    sp.add_argument("--confirm", action="store_true")
    sp.add_argument("--confirm-code", action="store_true",
                    help="release high-risk writes (executable/read-only/unknown regions); "
                         "requires --confirm")

    # name
    sp = sub.add_parser("name", help="manage the session symbol table")
    nsub = sp.add_subparsers(dest="name_action", required=True)
    ns = nsub.add_parser("set")
    ns.add_argument("--session", required=True)
    ns.add_argument("name")
    ns.add_argument("--base", required=True)
    ns.add_argument("--offsets")
    ns.add_argument("--mode", choices=["relative", "pointer_chain", "field_chain"],
                    help="offset semantics (default auto: bare address=relative, module=pointer_chain; "
                         "field_chain for nested struct field paths)")
    ns.add_argument("--type", default="int32")
    ns.add_argument("--description", default="")
    ns.add_argument("--temp", action="store_true",
                    help="mark as a transient symbol (removable via 'name clear-temp')")
    ng = nsub.add_parser("get")
    ng.add_argument("--session", required=True)
    ng.add_argument("name", nargs="?")
    ng.add_argument("--include-temp", action=argparse.BooleanOptionalAction, default=True,
                    help="include temp symbols in the listing (default: all, marked with temp=true)")
    nc = nsub.add_parser("chain", help="walk a pointer chain and register each intermediate as <name>.stepN")
    nc.add_argument("--session", required=True)
    nc.add_argument("name")
    nc.add_argument("--base", required=True, help="base expr, e.g. 'Game.exe+0x1A4'")
    nc.add_argument("--offsets", help="chain offsets, e.g. '0x10,0x28,0x0'")
    nc.add_argument("--type", default="uint64")
    nc.add_argument("--mode", choices=["pointer_chain", "field_chain"], default=None,
                    help="offset semantics: pointer_chain (default, deref+offset) or "
                         "field_chain (offset+deref, nested struct fields)")
    nc.add_argument("--persist", action="store_true",
                    help="persist the chain symbols instead of marking them temp")
    nct = nsub.add_parser("clear-temp", help="remove all temp symbols (persistent symbols are kept)")
    nct.add_argument("--session", required=True)

    # template
    sp = sub.add_parser("template", help="predefined genre modification templates")
    tsub = sp.add_subparsers(dest="template_action", required=True)
    tsub.add_parser("list")
    tshow = tsub.add_parser("show")
    tshow.add_argument("name")
    tapply = tsub.add_parser("apply")
    tapply.add_argument("--session", required=True)
    tapply.add_argument("--template", required=True)
    tapply.add_argument("--option", required=True)
    tapply.add_argument("--param", action="append", default=[], help="key=value (repeatable)")
    tapply.add_argument("--confirm", action="store_true")

    # batch
    sp = sub.add_parser("batch", help="run a batch file of operations")
    bsub = sp.add_subparsers(dest="batch_action", required=True)
    brun = bsub.add_parser("run")
    brun.add_argument("--session", required=True)
    brun.add_argument("file")
    brun.add_argument("--confirm", action="store_true")
    brun.add_argument("--confirm-code", action="store_true",
                      help="also release high-risk writes (executable/read-only regions); without it confirm only applies risk=normal writes")
    brun.add_argument("--continue-on-error", action="store_true")
    brun.add_argument("--offset", type=int, default=0, help="first result index to return inline (pagination)")
    brun.add_argument("--limit", type=int, default=0, help="max inline results (0 = all; full set is persisted to results_file)")

    # macro (reusable parameterized operation sequences)
    sp = sub.add_parser("macro", help="reusable parameterized operation sequences")
    msub = sp.add_subparsers(dest="macro_action", required=True)
    mdef = msub.add_parser("define", help="define a macro from a YAML file or inline string")
    mdef.add_argument("name")
    mdef.add_argument("--session", required=True)
    mg = mdef.add_mutually_exclusive_group(required=True)
    mg.add_argument("--file", help="path to a macro YAML file")
    mg.add_argument("--inline", help="macro definition as an inline YAML string")
    mdef.add_argument("--description", default="")
    mlist = msub.add_parser("list", help="list macros stored for a session")
    mlist.add_argument("--session", required=True)
    mshow = msub.add_parser("show", help="show one macro definition")
    mshow.add_argument("name")
    mshow.add_argument("--session", required=True)
    mrun = msub.add_parser("run", help="run a macro with parameter substitution")
    mrun.add_argument("name")
    mrun.add_argument("--session", required=True)
    mrun.add_argument("--params", default="", help="key=value,key=value (values parsed as YAML scalars)")
    mrun.add_argument("--confirm", action="store_true")
    mrun.add_argument("--stop-on-error", action=argparse.BooleanOptionalAction, default=True,
                      help="stop at the first failed operation (default; --no-stop-on-error to continue)")
    mdel = msub.add_parser("delete", help="delete a stored macro")
    mdel.add_argument("name")
    mdel.add_argument("--session", required=True)

    # freeze
    sp = sub.add_parser("freeze", help="manage/run value freezes")
    fsub = sp.add_subparsers(dest="freeze_action", required=True)
    fl = fsub.add_parser("list"); fl.add_argument("--session", required=True)
    fc = fsub.add_parser("clear"); fc.add_argument("--session", required=True)
    fr = fsub.add_parser("run")
    fr.add_argument("--session", required=True)
    fr.add_argument("--interval", type=float, default=0.05)
    fr.add_argument("--iterations", type=int, default=0, help="0 = until Ctrl-C")
    fstart = fsub.add_parser("start", help="enforce freezes in a background process")
    fstart.add_argument("--session", required=True)
    fstart.add_argument("--interval", type=float, default=0.05)
    fstop = fsub.add_parser("stop", help="stop the background freeze process")
    fstop.add_argument("--session", required=True)

    # watch (polling-based value change monitor)
    sp = sub.add_parser("watch", help="poll an address and record value changes")
    wsub = sp.add_subparsers(dest="watch_action", required=True)
    wr = wsub.add_parser("run", help="foreground polling watch")
    wr.add_argument("--session", required=True)
    wr.add_argument("--address", required=True)
    wr.add_argument("--type", default="int32")
    wr.add_argument("--interval", type=float, default=0.1)
    wr.add_argument("--iterations", type=int, default=100, help="0 = until Ctrl-C")
    wr.add_argument("--log", help="append change records to this JSONL file (background worker mode)")
    wstart = wsub.add_parser("start", help="watch in a background process")
    wstart.add_argument("--session", required=True)
    wstart.add_argument("--address", required=True)
    wstart.add_argument("--type", default="int32")
    wstart.add_argument("--interval", type=float, default=0.1)
    wstop = wsub.add_parser("stop", help="stop the background watch process")
    wstop.add_argument("--session", required=True)
    wrep = wsub.add_parser("report", help="show the recorded value changes")
    wrep.add_argument("--session", required=True)
    wrep.add_argument("--limit", type=int, default=50)

    # find-writers (hardware breakpoint write watchpoint, phase 2.1)
    sp = sub.add_parser("find-writers", help="hardware breakpoint: find code writing to address")
    sp.add_argument("--session", required=True)
    sp.add_argument("--address", required=True)
    sp.add_argument("--size", type=int, default=4, choices=[1, 2, 4, 8])
    sp.add_argument("--duration", type=float, default=5.0)
    sp.add_argument("--max-hits", type=int, default=20)

    # save-edit
    sp = sub.add_parser("save-edit", help="edit game save files (RPG Maker, Ren'Py, etc.)")
    sesub = sp.add_subparsers(dest="save_action", required=True)
    sp_d = sesub.add_parser("detect", help="find editable save files")
    sp_d.add_argument("--session", required=True)
    sp_m = sesub.add_parser("modify", help="modify a save file value")
    sp_m.add_argument("--session", required=True)
    sp_m.add_argument("--path", required=True, help="save file path")
    sp_m.add_argument("--field", required=True, help="field to modify, e.g. gold")
    sp_m.add_argument("--value", required=True)
    sp_m.add_argument("--key", help="decryption key for Unity encrypted saves (Base64(DES-CBC(JSON))); never persisted")
    sp_m.add_argument("--iv", help="DES-CBC IV for Unity encrypted saves (defaults to the key)")
    sp_m.add_argument("--confirm", action="store_true")

    # layout (memory layout analysis, phase 3)
    sp = sub.add_parser("layout", help="memory layout analysis (vtables/RTTI/heap)")
    sp.add_argument("--session", required=True)
    sp.add_argument("--what", choices=["vtables", "rtti", "class", "heap"], default="vtables")
    sp.add_argument("--address", help="target address for class layout / heap filter")
    sp.add_argument("--module", help="restrict vtable candidates to this module")

    # pointer-scan (reverse pointer chain discovery, phase 3)
    sp = sub.add_parser("pointer-scan", help="automatic pointer chain discovery")
    sp.add_argument("--session", required=True)
    sp.add_argument("--address", required=True)
    sp.add_argument("--max-depth", type=int)
    sp.add_argument("--max-paths", type=int)
    sp.add_argument("--rescan", action="store_true",
                    help="re-validate previously saved pointer paths against --address instead of a fresh scan")
    sp.add_argument("--async", dest="async_run", action="store_true",
                    help="run as a background job (returns job_id immediately; no 30s hard timeout; "
                         "poll with `job status <job_id>`)")
    sp.add_argument("--timeout", type=float,
                    help="optional wall-clock cap in seconds for --async runs (default: unlimited)")

    # job (background job management for long-running read-only analysis)
    sp = sub.add_parser("job", help="background job status/cancel/list")
    jsub = sp.add_subparsers(dest="job_action", required=True)
    js = jsub.add_parser("status", help="show one job's status/progress/results")
    js.add_argument("job_id")
    js.add_argument("--session", help="session owning the job (lets a restarted server find persisted results)")
    jl = jsub.add_parser("list", help="list jobs")
    jl.add_argument("--session", help="filter by session")
    jc = jsub.add_parser("cancel", help="request cancellation of a running job")
    jc.add_argument("job_id")

    # results-read (read back a persisted session result file, read-only)
    sp = sub.add_parser("results-read",
                        help="read a persisted result file inside the session directory (read-only)")
    sp.add_argument("--session", required=True)
    sp.add_argument("--path", required=True,
                    help="out_file / results_file path (absolute or relative to sessions/<id>/)")
    sp.add_argument("--offset", type=int, default=0, help="line offset (default 0)")
    sp.add_argument("--limit", type=int, default=400, help="max lines (default 400; 0 = all)")

    # dissect (Cheat Engine-style structure dissection, read-only)
    sp = sub.add_parser("dissect", help="auto-dissect object structure fields")
    sp.add_argument("--session", required=True)
    sp.add_argument("--address", help="single instance address")
    sp.add_argument("--addresses", help="comma-separated instance addresses for multi-instance analysis")
    sp.add_argument("--size", type=int, default=256)

    # ue (Unreal Engine structure introspection, read-only)
    sp = sub.add_parser("ue", help="Unreal Engine structure introspection (read-only)")
    uesub = sp.add_subparsers(dest="ue_action", required=True)
    sp_i = uesub.add_parser("introspect", help="probe GObjects/FNamePool layouts")
    sp_i.add_argument("--session", required=True)
    sp_i.add_argument("--gobjects", help="GObjects offset, e.g. 'Game.exe+0x1D2E500' or '0x7ff...'")
    sp_i.add_argument("--gnames", help="GName offset")
    sp_i.add_argument("--gobjects-pattern", help="AOB pattern to locate GObjects (assist only)")
    sp_i.add_argument("--gnames-pattern")
    sp_i.add_argument("--force", action="store_true", help="re-probe even if cached layout exists")
    sp_a = uesub.add_parser("actors", help="enumerate actors with class names")
    sp_a.add_argument("--session", required=True)
    sp_a.add_argument("--gobjects", help="explicit GObjects offset (skips cached layout)")
    sp_a.add_argument("--limit", type=int, default=100)
    sp_a.add_argument("--filter", dest="name_filter", help="object name substring filter")
    sp_a.add_argument("--class", dest="class_filter", help="class name substring filter")
    sp_a.add_argument("--list", dest="list_results", action="store_true",
                      help="output detail list instead of aggregate")
    sp_f = uesub.add_parser("fname", help="read/decode/compare FName")
    sp_f.add_argument("--session", required=True)
    sp_f.add_argument("--address", help="address of FName struct (8 bytes)")
    sp_f.add_argument("--index", type=int, help="FName comparison index to decode")
    sp_f.add_argument("--compare-index", type=int, help="compare with another index")

    # disasm (runtime disassembly via capstone, read-only)
    sp = sub.add_parser("disasm", help="disassemble code at address (requires capstone)")
    sp.add_argument("--session", required=True)
    sp.add_argument("--address", required=True)
    sp.add_argument("--size", type=int, default=256)
    sp.add_argument("--arch", choices=["x86", "x64"], default=None)
    sp.add_argument("--blocks", action="store_true", help="split into basic blocks")

    # xrefs (cross-reference query via radare2, read-only)
    sp = sub.add_parser("xrefs", help="cross-reference query via radare2")
    sp.add_argument("--session", required=True)
    sp.add_argument("--address", required=True)
    sp.add_argument("--direction", choices=["to", "from"], default="to")
    sp.add_argument("--binary", help="binary path (default: session exe)")

    # il2cpp (Unity il2cpp runtime type decoders, read-only)
    sp = sub.add_parser("il2cpp", help="Unity il2cpp runtime type decoders")
    isub = sp.add_subparsers(dest="il2cpp_action", required=True)
    sp_s = isub.add_parser("string", help="decode an Il2CppString (UTF-16)")
    sp_s.add_argument("--session", required=True)
    sp_s.add_argument("--address", required=True)
    sp_s.add_argument("--max-chars", type=int, default=4096)
    sp_l = isub.add_parser("list", help="read a System.Collections.Generic.List<T>")
    sp_l.add_argument("--session", required=True)
    sp_l.add_argument("--address", required=True)
    sp_l.add_argument("--elem-type",
                      choices=["ptr", "int8", "uint8", "int16", "uint16", "int32",
                               "uint32", "int64", "uint64", "float", "double"],
                      default="ptr")
    sp_l.add_argument("--limit", type=int, default=100)
    sp_d = isub.add_parser("dict", help="read a System.Collections.Generic.Dictionary<K,V>")
    sp_d.add_argument("--session", required=True)
    sp_d.add_argument("--address", required=True)
    sp_d.add_argument("--limit", type=int, default=100)

    # il2cpp lookup/dump (RVA reverse-lookup + dumper session integration).
    # Idempotent: reuse the existing "il2cpp" group/subparsers when present,
    # only create them when missing, and never re-add existing subcommands.
    il2cpp_p = sub.choices.get("il2cpp")
    if il2cpp_p is None:
        il2cpp_p = sub.add_parser("il2cpp", help="Unity il2cpp tooling")
    il2sub = next((a for a in il2cpp_p._actions if isinstance(a, argparse._SubParsersAction)), None)
    if il2sub is None:
        il2sub = il2cpp_p.add_subparsers(dest="il2cpp_action", required=True)
    if "lookup" not in il2sub.choices:
        sp_lk = il2sub.add_parser("lookup", help="RVA -> method name reverse-lookup over script.json")
        sp_lk.add_argument("--session", required=True)
        sp_lk.add_argument("--rva", required=True, help="RVA hex/decimal or +/- address expression")
        sp_lk.add_argument("--script-json", help="script.json path (default: session-associated dump)")
        sp_lk.add_argument("--tolerance", default="0", help="nearest-function-start tolerance, e.g. 0x100")
        sp_lk.add_argument("--force-index", action="store_true", help="rebuild the RVA index even if cached")
        sp_lk.add_argument("--force", action="store_true", help="skip the dump-freshness (binary fingerprint) check")
    if "dump" not in il2sub.choices:
        sp_dm = il2sub.add_parser("dump", help="run Il2CppDumper and associate outputs with the session")
        sp_dm.add_argument("--session", required=True)
        sp_dm.add_argument("--out-dir", help="output directory (default: sessions/<id>/il2cpp_dump)")
        sp_dm.add_argument("--timeout", type=float, default=120.0)
        sp_dm.add_argument("--force", action="store_true", help="re-dump even when the existing dump fingerprint is still fresh")

    # il (Mono IL tool family via the il-tool subprocess)
    sp = sub.add_parser("il", help="Mono assembly IL analysis/patching via il-tool")
    ilsub = sp.add_subparsers(dest="il_action", required=True)
    sp_a = ilsub.add_parser("analyze", help="enumerate types/methods/fields")
    sp_a.add_argument("--session", required=True)
    sp_a.add_argument("--assembly", help="managed assembly path (default: session Assembly-CSharp.dll)")
    sp_a.add_argument("--type-filter", help="type full-name substring filter")
    sp_a.add_argument("--member-filter", help="method/field name substring filter (keeps the result inline)")
    sp_d = ilsub.add_parser("dump", help="render one method body's IL instruction stream")
    sp_d.add_argument("--session", required=True)
    sp_d.add_argument("--method", required=True)
    sp_d.add_argument("--type", help="declaring type (narrows overloads)")
    sp_d.add_argument("--assembly")
    sp_c = ilsub.add_parser("callers", help="scan call/callvirt/ldftn references to a target")
    sp_c.add_argument("--session", required=True)
    sp_c.add_argument("--method", help="target method name substring")
    sp_c.add_argument("--type", help="target type name substring (used when --method is absent)")
    sp_c.add_argument("--assembly")
    sp_c.add_argument("--max-results", type=int, default=0)
    sp_p = ilsub.add_parser("patch", help="patch one method body (dry-run unless --confirm)")
    sp_p.add_argument("--session", required=True)
    sp_p.add_argument("--op", required=True,
                      choices=["replace_body", "mul_before_ret", "insert_before_ret", "insert_after_call"])
    sp_p.add_argument("--method", required=True)
    sp_p.add_argument("--type")
    sp_p.add_argument("--value", help="op parameter, e.g. the mul_before_ret multiplier (YAML scalar)")
    sp_p.add_argument("--target", help="insert_after_call: called method name")
    sp_p.add_argument("--assembly")
    sp_p.add_argument("--out-assembly", help="write the patched image elsewhere instead of in place")
    sp_p.add_argument("--confirm", action="store_true", help="actually apply the patch (auto file-backup first)")
    sp_v = ilsub.add_parser("verify", help="read back IL and compare against an expected opcode pattern")
    sp_v.add_argument("--session", required=True)
    sp_v.add_argument("--method", required=True)
    sp_v.add_argument("--type")
    sp_v.add_argument("--assembly")
    sp_v.add_argument("--expect", required=True,
                      help='opcode list ("mul,ret") or JSON ({"expected":["mul"],"exact":false})')
    sp_b = ilsub.add_parser("backup", help="file-level backup of a managed assembly (sha256, audited)")
    sp_b.add_argument("--session", required=True)
    sp_b.add_argument("--assembly")
    sp_b.add_argument("--label", default="")
    sp_r = ilsub.add_parser("restore", help="restore an il backup by backup_id (dry-run unless --confirm)")
    sp_r.add_argument("--session", required=True)
    sp_r.add_argument("backup_id")
    sp_r.add_argument("--confirm", action="store_true")

    # mono (Mono index build + symbol lookup)
    sp = sub.add_parser("mono", help="Mono assembly index (mono_dump) + symbol lookup")
    monosub = sp.add_subparsers(dest="mono_action", required=True)
    sp_md = monosub.add_parser("dump", help="build the type/method index (fingerprint-cached)")
    sp_md.add_argument("--session", required=True)
    sp_md.add_argument("--assembly", help="managed assembly path (default: session Assembly-CSharp.dll)")
    sp_md.add_argument("--timeout", type=float, default=120.0)
    sp_md.add_argument("--force", action="store_true", help="rebuild even when the fingerprint is still fresh")
    sp_ms = monosub.add_parser("symbol", help="look up types/methods by name or RVA in the index")
    sp_ms.add_argument("--session", required=True)
    sp_ms.add_argument("query", help="name substring or '0x...' RVA")
    sp_ms.add_argument("--assembly", help="pick the index of another assembly for this session")
    sp_ms.add_argument("--limit", type=int, default=50)
    sp_mstr = monosub.add_parser("string", help="decode a Mono System.String (arch-aware layout)")
    sp_mstr.add_argument("--session", required=True)
    sp_mstr.add_argument("--address", required=True)
    sp_mstr.add_argument("--max-chars", type=int, default=4096)
    sp_mstr.add_argument("--arch", choices=["x86", "x64"], help="override the process architecture")
    sp_mlst = monosub.add_parser("list", help="read a Mono List<T> (same managed layout as IL2CPP)")
    sp_mlst.add_argument("--session", required=True)
    sp_mlst.add_argument("--address", required=True)
    sp_mlst.add_argument("--elem-type", default="ptr")
    sp_mlst.add_argument("--limit", type=int, default=100)
    sp_mdict = monosub.add_parser("dict", help="read a Mono Dictionary<K,V>")
    sp_mdict.add_argument("--session", required=True)
    sp_mdict.add_argument("--address", required=True)
    sp_mdict.add_argument("--limit", type=int, default=100)
    sp_mstat = monosub.add_parser("static", help="scan JIT code for ldsfld artifacts (static field locators)")
    sp_mstat.add_argument("--session", required=True)
    sp_mstat.add_argument("--arch", choices=["x86", "x64"], help="override the process architecture")
    sp_mstat.add_argument("--max-results", type=int, default=200)
    sp_mstat.add_argument("--min-addr", type=lambda x: int(x, 0), default=None)
    sp_mstat.add_argument("--max-addr", type=lambda x: int(x, 0), default=None)
    sp_mheap = monosub.add_parser("heap-scan", help="heap object candidates with optional Mono vtable filter")
    sp_mheap.add_argument("--session", required=True)
    sp_mheap.add_argument("--vtable-addr", default=None)
    sp_mheap.add_argument("--max-results", type=int, default=500)

    # file (generic game-file snapshot / restore)
    sp = sub.add_parser("file", help="game file snapshot/restore (sha256 + audit)")
    fsub = sp.add_subparsers(dest="file_action", required=True)
    fsn = fsub.add_parser("snapshot", help="snapshot a game file into the session backup store")
    fsn.add_argument("--session", required=True)
    fsn.add_argument("path", help="file to snapshot")
    fsn.add_argument("--label", default="")
    frs = fsub.add_parser("restore", help="restore a snapshot by backup_id (dry-run unless --confirm)")
    frs.add_argument("--session", required=True)
    frs.add_argument("backup_id")
    frs.add_argument("--confirm", action="store_true")

    # backup
    sp = sub.add_parser("backup", help="backup/restore original bytes")
    ksub = sp.add_subparsers(dest="backup_action", required=True)
    kc = ksub.add_parser("create")
    kc.add_argument("--session", required=True)
    kc.add_argument("--symbol")
    kc.add_argument("--address")
    kc.add_argument("--type")
    kc.add_argument("--offsets")
    kc.add_argument("--mode", choices=["relative", "pointer_chain", "field_chain"],
                    help="offset semantics (default auto: bare address=relative, module=pointer_chain)")
    kc.add_argument("--size", type=int, help="byte length when using --address without a fixed type")
    kc.add_argument("--label", default="")
    kl = ksub.add_parser("list"); kl.add_argument("--session", required=True)
    kr = ksub.add_parser("restore"); kr.add_argument("--session", required=True); kr.add_argument("backup_id")

    # toolchain
    sp = sub.add_parser("toolchain", help="detect reverse-engineering tools")
    tcs = sp.add_subparsers(dest="toolchain_action", required=True)
    tcs.add_parser("detect")

    # safety (runtime safety level: process-scoped write gear)
    sp = sub.add_parser("safety", help="runtime safety level (dry_run_only forces every confirmed write into a refusal)")
    sftysub = sp.add_subparsers(dest="safety_action", required=True)
    slvl = sftysub.add_parser("level", help="show or switch the runtime safety level")
    slvl.add_argument("--set", dest="set_level", choices=["normal", "dry_run_only"],
                      help="switch the level (omitting shows the current one)")

    # sessions
    sp = sub.add_parser("sessions", help="list sessions")
    sp = sub.add_parser("session", help="show one session / manage session snapshots")
    ssub = sp.add_subparsers(dest="session_action")
    sinfo = ssub.add_parser("info", help="show one session (implicit for a bare session_id)")
    sinfo.add_argument("session_id")
    ssnap = ssub.add_parser("snapshot", help="save a named snapshot of the current session state")
    ssnap.add_argument("name", help="snapshot name (letters, digits, '_', '-', '.')")
    ssnap.add_argument("--session", required=True)
    ssl = ssub.add_parser("snapshots", help="list snapshots stored for a session")
    ssl.add_argument("--session", required=True)
    srest = ssub.add_parser("restore", help="restore a snapshot (current state auto-archived as .pre-restore)")
    srest.add_argument("name")
    srest.add_argument("--session", required=True)
    sp = sub.add_parser("detach", help="delete a session")
    sp.add_argument("session_id")

    return p


_SESSION_SUBCOMMANDS = {"info", "snapshot", "snapshots", "restore"}


def _normalize_session_argv(argv: list[str]) -> list[str]:
    """Keep ``session <session_id>`` working after the subparser rework.

    When the ``session`` command is followed by a bare session id (anything
    that is not a snapshot subcommand), an implicit ``info`` subcommand is
    inserted so argparse sees ``session info <session_id>``.
    """

    argv = list(argv)
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("--config", "--format"):
            i += 2  # these global options consume the following value
            continue
        if tok.startswith("-"):
            i += 1
            continue
        if tok == "session" and (i + 1 >= len(argv) or argv[i + 1] not in _SESSION_SUBCOMMANDS):
            argv.insert(i + 1, "info")
        return argv
    return argv


def _parse_params(pairs: list[str]) -> dict:
    out: dict[str, str] = {}
    for item in pairs or []:
        if "=" in item:
            k, v = item.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _parse_macro_params(text: str) -> dict:
    """Parse ``key=value,key=value``; values go through YAML scalar parsing so
    numbers/booleans arrive typed and anything else stays a string."""

    out: dict = {}
    for item in (text or "").split(","):
        item = item.strip()
        if not item or "=" not in item:
            continue
        k, v = item.split("=", 1)
        k, v = k.strip(), v.strip()
        try:
            parsed = yaml.safe_load(v)
        except Exception:
            parsed = v
        # empty/unparseable-to-None keeps the original string form
        out[k] = v if parsed is None else parsed
    return out


# ------------------------------------------------------------------- dispatch
def dispatch(service: ModifierService, args: argparse.Namespace) -> Result:
    cmd = args.command

    if cmd == "attach":
        data = service.attach(pid=args.pid, name=args.process, exe=args.exe, title=args.title, allow_anti_cheat=args.allow_anti_cheat)
        return Result.success("attach", data)

    if cmd == "analyze":
        return Result.success("analyze", service.analyze(session_id=args.session, target=args.target, deep=args.deep))

    if cmd == "scan":
        extra: dict = {}
        if getattr(args, "progress", False):
            def progress_cb(p: dict) -> None:
                print(
                    f"scan progress: {p['regions_done']}/{p['regions_total']} regions, "
                    f"{p['bytes_scanned']} bytes scanned, {p['hits']} hits",
                    file=sys.stderr, flush=True,
                )
            extra["progress_cb"] = progress_cb
        return Result.success("scan", service.scan(session_id=args.session, type=args.type, value=args.value, comparator=args.comparator, value2=args.value2, **extra))

    if cmd == "scan-next":
        return Result.success("scan-next", service.scan_next(session_id=args.session, comparator=args.comparator, value=args.value, value2=args.value2))

    if cmd == "scan-aob":
        return Result.success("scan-aob", service.scan_aob(session_id=args.session, pattern=args.pattern, max_results=args.max_results))

    if cmd == "scan-candidates":
        def _addr_opt(v):
            if v is None:
                return None
            s = str(v).strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        return Result.success("scan-candidates", service.scan_candidates(
            session_id=args.session, offset=args.offset, limit=args.limit,
            min_addr=_addr_opt(args.min_addr), max_addr=_addr_opt(args.max_addr)))

    if cmd == "read":
        return Result.success("read", service.read(session_id=args.session, symbol=args.symbol, address=args.address, type=args.type, offsets=args.offsets, mode=args.mode))

    if cmd == "modify":
        res = service.modify(session_id=args.session, symbol=args.symbol, address=args.address, type=args.type,
                             value=args.value, offsets=args.offsets, mode=args.mode, confirm=args.confirm,
                             freeze=args.freeze, confirm_code=args.confirm_code)
        return Result.success("modify", res)

    if cmd == "resolve":
        base = args.base
        offsets = args.offsets
        if args.pointer:
            parts = [p.strip() for p in args.pointer.split(",") if p.strip()]
            base = parts[0]
            if len(parts) > 1:
                offsets = ",".join(parts[1:])
        if not base:
            return Result.failure("resolve", "E_INVALID_ARGS", "provide --base or --pointer")
        return Result.success("resolve", service.resolve(session_id=args.session, base_expr=base, offsets=offsets,
                                                         mode=args.mode, deref_last=args.deref_last))

    if cmd == "nl":
        return Result.success("nl", service.nl(session_id=args.session, text=args.text,
                                               confirm=args.confirm, confirm_code=args.confirm_code))

    if cmd == "name":
        if args.name_action == "set":
            return Result.success("name.set", service.name_set(session_id=args.session, name=args.name, base_expr=args.base, offsets=args.offsets, mode=args.mode, type=args.type, description=args.description, temp=args.temp))
        if args.name_action == "chain":
            return Result.success("name.chain", service.name_chain(args.session, name=args.name, base=args.base, offsets=args.offsets, type=args.type, temp=not args.persist, mode=args.mode))
        if args.name_action == "clear-temp":
            return Result.success("name.clear_temp", service.name_clear_temp(session_id=args.session))
        return Result.success("name.get", service.name_get(session_id=args.session, name=args.name, include_temp=args.include_temp))

    if cmd == "template":
        if args.template_action == "list":
            return Result.success("template.list", service.template_list())
        if args.template_action == "show":
            return Result.success("template.show", service.template_show(name=args.name))
        params = _parse_params(args.param)
        return Result.success("template.apply", service.template_apply(session_id=args.session, name=args.template, option=args.option, params=params, confirm=args.confirm))

    if cmd == "batch":
        bkwargs: dict = {}
        if getattr(args, "offset", 0) or getattr(args, "limit", 0):
            bkwargs["offset"] = args.offset
            bkwargs["limit"] = args.limit
        return Result.success("batch.run", service.batch_run(session_id=args.session, path=args.file, confirm=args.confirm, confirm_code=getattr(args, "confirm_code", False), stop_on_error=not args.continue_on_error, **bkwargs))

    if cmd == "macro":
        if args.macro_action == "list":
            return Result.success("macro.list", service.macro_list(session_id=args.session))
        if args.macro_action == "show":
            return Result.success("macro.show", service.macro_show(session_id=args.session, name=args.name))
        if args.macro_action == "define":
            if args.file:
                mpath = Path(args.file)
                if not mpath.exists():
                    raise InvalidArgsError(f"macro file not found: {args.file}", details={"path": args.file})
                definition = mpath.read_text(encoding="utf-8")
            else:
                definition = args.inline
            return Result.success("macro.define", service.macro_define(
                session_id=args.session, name=args.name, definition=definition, description=args.description))
        if args.macro_action == "delete":
            return Result.success("macro.delete", service.macro_delete(session_id=args.session, name=args.name))
        return Result.success("macro.run", service.macro_run(
            session_id=args.session, name=args.name, params=_parse_macro_params(args.params),
            confirm=args.confirm, stop_on_error=args.stop_on_error))

    if cmd == "freeze":
        if args.freeze_action == "list":
            return Result.success("freeze.list", service.freeze_list(session_id=args.session))
        if args.freeze_action == "clear":
            return Result.success("freeze.clear", service.freeze_clear(session_id=args.session))
        if args.freeze_action == "start":
            return Result.success("freeze.start", service.freeze_start(session_id=args.session, interval=args.interval))
        if args.freeze_action == "stop":
            return Result.success("freeze.stop", service.freeze_stop(session_id=args.session))
        return Result.success("freeze.run", service.freeze_run(session_id=args.session, interval=args.interval, iterations=args.iterations))

    if cmd == "watch":
        if args.watch_action == "start":
            return Result.success("watch.start", service.watch_start(session_id=args.session, address=args.address, type=args.type, interval=args.interval))
        if args.watch_action == "stop":
            return Result.success("watch.stop", service.watch_stop(session_id=args.session))
        if args.watch_action == "report":
            return Result.success("watch.report", service.watch_report(session_id=args.session, limit=args.limit))
        return Result.success("watch.run", service.watch_run(session_id=args.session, address=args.address, type=args.type,
                                                              interval=args.interval, iterations=args.iterations, jsonl_path=args.log))

    if cmd == "find-writers":
        return Result.success("find-writers", service.find_writers(session_id=args.session, address=args.address,
                                                                   size=args.size, duration=args.duration, max_hits=args.max_hits))

    if cmd == "save-edit":
        if args.save_action == "detect":
            return Result.success("save-edit.detect", service.save_edit_detect(session_id=args.session))
        return Result.success("save-edit.modify", service.save_edit_modify(session_id=args.session, path=args.path, field=args.field, value=args.value, confirm=args.confirm, key=args.key, iv=args.iv))

    if cmd == "layout":
        if args.what == "heap":
            data = service.heap_scan(session_id=args.session, vtable_addr=args.address)
        else:
            data = service.layout_analyze(session_id=args.session, module=args.module, what=args.what, address=args.address)
        return Result.success("layout", data)

    if cmd == "pointer-scan":
        if args.rescan:
            return Result.success("pointer-scan", service.pointer_rescan(session_id=args.session, address=args.address))
        if getattr(args, "async_run", False):
            return Result.success("pointer-scan", service.pointer_scan_async(
                session_id=args.session, address=args.address, max_depth=args.max_depth,
                max_paths=args.max_paths, timeout=args.timeout))
        return Result.success("pointer-scan", service.pointer_scan(session_id=args.session, address=args.address, max_depth=args.max_depth, max_paths=args.max_paths))

    if cmd == "job":
        if args.job_action == "status":
            return Result.success("job.status", service.job_status(args.job_id, session_id=args.session))
        if args.job_action == "list":
            return Result.success("job.list", service.job_list(session_id=args.session))
        return Result.success("job.cancel", service.job_cancel(args.job_id))

    if cmd == "results-read":
        return Result.success("results_read", service.results_read(
            session_id=args.session, path=args.path, offset=args.offset, limit=args.limit))

    if cmd == "dissect":
        return Result.success("dissect", service.dissect(session_id=args.session, address=args.address,
                                                         addresses=args.addresses, size=args.size))

    if cmd == "ue":
        if args.ue_action == "introspect":
            return Result.success("ue.introspect", service.ue_introspect(
                session_id=args.session, gobjects=args.gobjects, gnames=args.gnames,
                gobjects_pattern=args.gobjects_pattern, gnames_pattern=args.gnames_pattern,
                force=args.force))
        if args.ue_action == "actors":
            return Result.success("ue.actors", service.ue_actors(
                session_id=args.session, gobjects=args.gobjects, limit=args.limit,
                name_filter=args.name_filter, class_filter=args.class_filter,
                list_results=args.list_results))
        return Result.success("ue.fname", service.ue_fname(
            session_id=args.session, address=args.address, index=args.index,
            compare_index=args.compare_index))

    if cmd == "disasm":
        return Result.success("disasm", service.disasm(
            session_id=args.session, address=args.address, size=args.size,
            arch=args.arch, blocks=args.blocks))

    if cmd == "xrefs":
        return Result.success("xrefs", service.xrefs(
            session_id=args.session, address=args.address,
            direction=args.direction, binary=args.binary))

    if cmd == "il2cpp":
        if args.il2cpp_action == "string":
            return Result.success("il2cpp.string", service.il2cpp_string(
                session_id=args.session, address=args.address, max_chars=args.max_chars))
        if args.il2cpp_action == "list":
            return Result.success("il2cpp.list", service.il2cpp_list(
                session_id=args.session, address=args.address,
                elem_type=args.elem_type, limit=args.limit))
        if args.il2cpp_action == "lookup":
            return Result.success("il2cpp.lookup", service.il2cpp_lookup(
                session_id=args.session, rva=args.rva, script_json=args.script_json,
                tolerance=args.tolerance, force_index=args.force_index,
                force=getattr(args, "force", False)))
        if args.il2cpp_action == "dump":
            return Result.success("il2cpp.dump", service.il2cpp_dump(
                session_id=args.session, out_dir=args.out_dir, timeout=args.timeout,
                force=getattr(args, "force", False)))
        return Result.success("il2cpp.dict", service.il2cpp_dict(
            session_id=args.session, address=args.address, limit=args.limit))

    if cmd == "il":
        if args.il_action == "analyze":
            return Result.success("il.analyze", service.il_analyze(
                args.session, assembly=args.assembly, type_filter=args.type_filter,
                member_filter=args.member_filter))
        if args.il_action == "dump":
            return Result.success("il.dump", service.il_dump(
                args.session, method=args.method, type=args.type, assembly=args.assembly))
        if args.il_action == "callers":
            return Result.success("il.callers", service.il_callers(
                args.session, assembly=args.assembly, type=args.type, method=args.method,
                max_results=args.max_results))
        if args.il_action == "patch":
            value = None
            if args.value is not None:
                try:
                    value = yaml.safe_load(args.value)
                except Exception:
                    value = args.value
            return Result.success("il.patch", service.il_patch(
                args.session, op=args.op, method=args.method, type=args.type, value=value,
                target=args.target, assembly=args.assembly, out_assembly=args.out_assembly,
                confirm=args.confirm))
        if args.il_action == "verify":
            try:
                expect = json.loads(args.expect)
            except Exception:
                expect = [x.strip() for x in args.expect.split(",") if x.strip()]
            return Result.success("il.verify", service.il_verify(
                args.session, method=args.method, expect=expect, type=args.type,
                assembly=args.assembly))
        if args.il_action == "backup":
            return Result.success("il.backup", service.il_backup(
                args.session, assembly=args.assembly, label=args.label))
        return Result.success("il.restore", service.il_restore(
            args.session, backup_id=args.backup_id, confirm=args.confirm))

    if cmd == "mono":
        if args.mono_action == "dump":
            return Result.success("mono.dump", service.mono_dump(
                args.session, assembly=args.assembly, force=args.force, timeout=args.timeout))
        if args.mono_action == "string":
            return Result.success("mono.string", service.mono_string(
                args.session, address=args.address, max_chars=args.max_chars, arch=args.arch))
        if args.mono_action == "list":
            return Result.success("mono.list", service.mono_list(
                args.session, address=args.address, elem_type=args.elem_type, limit=args.limit))
        if args.mono_action == "dict":
            return Result.success("mono.dict", service.mono_dict(
                args.session, address=args.address, limit=args.limit))
        if args.mono_action == "static":
            return Result.success("mono.static", service.mono_static(
                args.session, arch=args.arch, max_results=args.max_results,
                min_addr=args.min_addr, max_addr=args.max_addr))
        if args.mono_action == "heap-scan":
            return Result.success("mono.heap-scan", service.mono_heap_scan(
                args.session, vtable_addr=args.vtable_addr, max_results=args.max_results))
        return Result.success("mono.symbol", service.mono_symbol(
            args.session, query=args.query, assembly=args.assembly, limit=args.limit))

    if cmd == "file":
        if args.file_action == "snapshot":
            return Result.success("file.snapshot", service.file_snapshot(
                args.session, path=args.path, label=args.label))
        return Result.success("file.restore", service.file_restore(
            args.session, backup_id=args.backup_id, confirm=args.confirm))

    if cmd == "backup":
        if args.backup_action == "create":
            target: dict = {}
            if args.symbol:
                target["symbol"] = args.symbol
            if args.address:
                target["address"] = args.address
            if args.type:
                target["type"] = args.type
            if args.offsets:
                target["offsets"] = args.offsets
            if getattr(args, "mode", None):
                target["mode"] = args.mode
            if args.size:
                target["size"] = args.size
            return Result.success("backup.create", service.backup_create(session_id=args.session, targets=[target], label=args.label))
        if args.backup_action == "list":
            return Result.success("backup.list", service.backup_list(session_id=args.session))
        return Result.success("backup.restore", service.backup_restore(session_id=args.session, backup_id=args.backup_id))

    if cmd == "toolchain":
        return Result.success("toolchain.detect", service.toolchain_detect())

    if cmd == "safety":
        if getattr(args, "set_level", None):
            return Result.success("safety.set_level", service.safety_set_level(level=args.set_level))
        return Result.success("safety.get_level", service.safety_get_level())

    if cmd == "sessions":
        return Result.success("sessions", service.list_sessions())
    if cmd == "session":
        action = getattr(args, "session_action", None) or "info"
        if action == "snapshot":
            return Result.success("session.snapshot", service.session_snapshot(args.session, name=args.name))
        if action == "snapshots":
            return Result.success("session.snapshots", service.session_snapshots(args.session))
        if action == "restore":
            return Result.success("session.restore", service.session_restore(args.session, name=args.name))
        return Result.success("session", service.session_info(session_id=args.session_id))
    if cmd == "detach":
        return Result.success("detach", service.detach(session_id=args.session_id))

    return Result.failure("unknown", "E_INVALID_ARGS", f"unknown command: {cmd!r}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    raw = sys.argv[1:] if argv is None else list(argv)
    args = parser.parse_args(_normalize_session_argv(raw))

    if args.version:
        emit(Result.success("version", {"version": __version__}), fmt=("json" if args.json else (args.format or "json")))
        return 0
    if not args.command:
        parser.print_help(sys.stderr)
        return 2

    try:
        config = load_config(args.config)
    except Exception as exc:  # config errors should still be structured
        return emit(Result.failure(args.command, "E_INVALID_ARGS", f"config error: {exc}"), fmt=args.format or "json")

    fmt = "json" if args.json else (args.format or config.output_format)
    service = ModifierService(config)

    try:
        result = dispatch(service, args)
    except GameModifierError as exc:
        result = Result.from_exception(args.command, exc)
    except KeyboardInterrupt:  # e.g. freeze run
        result = Result.success(args.command, {"interrupted": True})
    except Exception as exc:  # pragma: no cover - defensive
        result = Result.failure(args.command, "E_INTERNAL", f"{type(exc).__name__}: {exc}")

    return emit(result, fmt=fmt)


if __name__ == "__main__":
    raise SystemExit(main())

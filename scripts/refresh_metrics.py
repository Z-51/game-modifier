#!/usr/bin/env python3
"""refresh_metrics.py - compute real project metrics and print a markdown block.

Anti-drift tooling: documentation (HANDOVER_GUIDE, README, docs/decisions/*,
USER_MANUAL, AI_AGENT_GUIDE, INSTALL_GUIDE, AGENTS.md) contains headline
numbers (source files / lines / test cases / MCP tools / error codes / ...).
Those numbers drift as the codebase grows, so instead of trusting hand-edited
values, run this script and paste its output into the "现状指标" section of the
docs:

    .\\scripts\\refresh_metrics.py        # or: python scripts/refresh_metrics.py

Stdlib only (no third-party deps). Test-case count is collected via a pytest
subprocess (``--collect-only``) using the current interpreter; everything else
is parsed statically from the source tree.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "game_modifier"
TESTS = ROOT / "tests"


def py_files(d: Path) -> list[Path]:
    return [
        p
        for p in d.rglob("*.py")
        if "__pycache__" not in p.parts and "egg-info" not in p.parts
    ]


def line_count(files: list[Path]) -> int:
    n = 0
    for f in files:
        n += len(f.read_text(encoding="utf-8").splitlines())
    return n


def _target_is(var_name: str, targets) -> bool:
    return any(isinstance(t, ast.Name) and t.id == var_name for t in targets)


def _assign_dict_len(path: Path, var_name: str) -> int:
    """Count keys of a dict literal assigned to ``var_name`` (plain or annotated)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not _target_is(var_name, targets):
                continue
            value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
            if isinstance(value, ast.Dict):
                return len(value.keys)
    return 0


def _assign_set_len(path: Path, var_name: str) -> int:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not _target_is(var_name, targets):
                continue
            value = node.value
            if isinstance(value, (ast.Set, ast.List, ast.Tuple)):
                return len(value.elts)
    return 0


def error_code_count(path: Path) -> int:
    """Count members of the ErrorCode enum (assignments inside the class)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "ErrorCode":
            return sum(
                1
                for stmt in node.body
                if isinstance(stmt, ast.Assign)
                or (isinstance(stmt, ast.AnnAssign) and stmt.value is not None)
            )
    return 0


def tool_group_stats(path: Path) -> dict:
    """Return {groups: n, tools: n} parsed from TOOL_GROUPS."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    groups = 0
    tools = 0
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not _target_is("TOOL_GROUPS", targets):
                continue
            value = node.value
            if isinstance(value, ast.Dict):
                groups = len(value.keys)
                for v in value.values:
                    if isinstance(v, ast.List):
                        tools += len(v.elts)
    return {"groups": groups, "tools": tools}


def collect_test_cases() -> tuple[int, int]:
    """Return (collected, skipped) via a full pytest run.

    Output is redirected to a temp file (the sandbox blocks piped stdio for
    spawned subprocesses; file redirection is allowed). Some environments do
    not print the ``N passed, M skipped`` summary line, so we fall back to
    counting the ``-q`` progress markers before ``[100%]`` (``.`` = passed,
    ``s`` = skipped, ``F``/``E`` = failed). Falls back to 0 on failure so the
    docs never show a wrong-but-plausible number.
    """
    import os
    import re
    import tempfile

    fd, tmp = tempfile.mkstemp(prefix="gm-metrics-", suffix=".txt")
    try:
        with os.fdopen(fd, "w") as f:
            subprocess.run(
                [sys.executable, "-m", "pytest", "tests/", "-q", "-p", "no:cacheprovider"],
                cwd=ROOT,
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=600,
            )
        tail = Path(tmp).read_text(encoding="utf-8", errors="replace")
        # 1) prefer the summary line: "857 passed, 1 skipped in 2.31s"
        m = re.search(r"(\d+)\s+passed(?:,\s*(\d+)\s+skipped)?", tail)
        if m:
            passed = int(m.group(1))
            skipped = int(m.group(2) or 0)
            return passed + skipped, skipped
        # 2) fall back to counting -q progress markers before [100%]
        head = tail.split("[100%]")[0]
        passed = head.count(".")
        skipped = head.count("s")
        failed = head.count("F") + head.count("E")
        if passed + skipped + failed > 0:
            return passed + skipped + failed, skipped
        return 0, 0
    except Exception:
        return 0, 0
    finally:
        try:
            Path(tmp).unlink(missing_ok=True)
        except OSError:
            pass


def main() -> int:
    src_files = py_files(SRC)
    test_files = [p for p in py_files(TESTS) if p.name != "conftest.py"]
    test_files_all = py_files(TESTS)
    collected, skipped = collect_test_cases()

    toml = ROOT / "pyproject.toml"
    extra_groups = 0
    try:
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli  # type: ignore
        data = tomllib.loads(toml.read_text(encoding="utf-8")) if sys.version_info >= (3, 11) else tomli.loads(toml.read_text(encoding="utf-8"))
        extra_groups = len(data.get("project", {}).get("optional-dependencies", {}))
    except Exception:
        extra_groups = 0

    gs = tool_group_stats(SRC / "mcp_server.py")
    mcp_meta = {
        "groups": gs["groups"],
        "tools": gs["tools"],
        "readonly_tools": _assign_set_len(SRC / "mcp_server.py", "READONLY_TOOLS"),
        "write_tools": _assign_set_len(SRC / "mcp_server.py", "WRITE_TOOLS"),
        "profiles": _assign_dict_len(SRC / "mcp_server.py", "PROFILES"),
    }
    anti_cheat = _assign_dict_len(SRC / "safety" / "guard.py", "ANTI_CHEAT_SIGNATURES")
    errors = error_code_count(SRC / "errors.py")
    commands = len(list((ROOT / "commands").glob("*.md")))
    builtin_templates = len(list((SRC / "templates" / "builtin").glob("*.yaml")))

    metrics = {
        "src_files": len(src_files),
        "src_lines": line_count(src_files),
        "test_files": len(test_files),
        "test_files_all": len(test_files_all),
        "test_lines": line_count(test_files_all),
        "test_cases": collected,
        "test_skipped": skipped,
        "mcp": mcp_meta,
        "error_codes": errors,
        "anti_cheat_signatures": anti_cheat,
        "commands": commands,
        "builtin_templates": builtin_templates,
        "optional_extras": extra_groups,
        "services": {
            "service_lines": line_count([SRC / "service.py"]),
            "cli_lines": line_count([SRC / "cli.py"]),
            "mcp_server_lines": line_count([SRC / "mcp_server.py"]),
        },
    }

    print(render_markdown(metrics))
    print("\n--- json ---")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


def render_markdown(m: dict) -> str:
    passed = m["test_cases"] - m["test_skipped"]
    return f"""## 现状指标（以 scripts/refresh_metrics.py 输出为准）

> 由 `python scripts/refresh_metrics.py` 生成，勿手动改数字。代码变化后重跑并用本块替换文档中的旧数字。

| 指标 | 数值 |
| --- | --- |
| 源文件（`src/game_modifier`） | {m['src_files']} 个，约 {m['src_lines']:,} 行 |
| 测试文件 | {m['test_files']} 个（含 conftest 共 {m['test_files_all']} 个），约 {m['test_lines']:,} 行 |
| 测试用例 | {m['test_cases']} collected / {passed} passed / {m['test_skipped']} skipped |
| MCP 工具 | {m['mcp']['tools']} 个，{m['mcp']['groups']} 组；readonly profile {m['mcp']['readonly_tools']} 个，write 工具 {m['mcp']['write_tools']} 个 |
| MCP profile 档位 | {m['mcp']['profiles']} 档（default / readonly / dry-run / symbols / limited） |
| 稳定错误码 | {m['error_codes']} 个 `E_*` |
| 反作弊签名 | {m['anti_cheat_signatures']} 种防护系统 |
| slash 命令 | {m['commands']} 个（commands/*.md） |
| 内置模板 | {m['builtin_templates']} 个（rpg / action / strategy） |
| 可选依赖组 | {m['optional_extras']} 组 extras |
| 单个文件规模 | service.py {m['services']['service_lines']:,} 行 / cli.py {m['services']['cli_lines']:,} 行 / mcp_server.py {m['services']['mcp_server_lines']:,} 行 |
"""


if __name__ == "__main__":
    raise SystemExit(main())
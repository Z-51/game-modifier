"""MCP tool-group on-demand registration (build_server(groups=...) + tools_catalog + --groups).

Regression anchor: the default build_server() call must keep registering every
tool (groups=None == full catalog), so existing deployments are untouched.
"""

from __future__ import annotations

import pytest

# the mcp package is optional; skip this whole module when absent
pytest.importorskip("mcp")

from game_modifier import mcp_server  # noqa: E402


@pytest.fixture
def mcp_config_path(tmp_path):
    cfg = tmp_path / "mcp.toml"
    cfg.write_text(f'[paths]\nhome = "{(tmp_path / "home").as_posix()}"\n', encoding="utf-8")
    return str(cfg)


def _tool_names(server) -> set[str]:
    tm = getattr(server, "_tool_manager", None)
    if tm is not None and hasattr(tm, "_tools"):
        return set(tm._tools.keys())
    import asyncio

    return {t.name for t in asyncio.run(server.list_tools())}


ALL_GROUP_TOOLS = {t for tools in mcp_server.TOOL_GROUPS.values() for t in tools}


def test_groups_filter(mcp_config_path):
    names = _tool_names(mcp_server.build_server(mcp_config_path, groups=["core"]))
    expected = set(mcp_server.TOOL_GROUPS["core"]) | {"tools_catalog"}
    assert names == expected
    # tools from other groups are absent
    assert "scan" not in names and "modify" not in names and "ue_actors" not in names


def test_groups_multi(mcp_config_path):
    names = _tool_names(mcp_server.build_server(mcp_config_path, groups=["core", "scan", "ue"]))
    expected = {"tools_catalog"}
    for g in ("core", "scan", "ue"):
        expected |= set(mcp_server.TOOL_GROUPS[g])
    assert names == expected
    # modify/analysis groups stay excluded
    assert "modify" not in names and "dissect" not in names and "macro_run" not in names
    assert "scan" in names and "pointer_scan" in names and "ue_actors" in names


def test_groups_default_full(mcp_config_path):
    """groups=None keeps the historical full registration (backward compat)."""
    names = _tool_names(mcp_server.build_server(mcp_config_path))
    assert names == ALL_GROUP_TOOLS | {"tools_catalog"}


def test_groups_invalid(mcp_config_path):
    with pytest.raises(ValueError) as ei:
        mcp_server.build_server(mcp_config_path, groups=["core", "bogus"])
    msg = str(ei.value)
    assert "bogus" in msg
    for g in mcp_server.TOOL_GROUPS:
        assert g in msg  # valid groups are listed in the error

    with pytest.raises(ValueError):
        mcp_server.build_server(mcp_config_path, groups=[])


def test_groups_with_readonly(mcp_config_path):
    """readonly + groups: filter by group first, then by writability."""
    names = _tool_names(
        mcp_server.build_server(mcp_config_path, profile="readonly", groups=["core", "modify"]))
    # read-only members of both groups survive
    assert {"attach", "session_info", "session_snapshots", "name_get",
            "template_list", "backup_list", "save_edit_detect"} <= names
    # writable members are still gated by the profile
    assert not ({"modify", "nl", "name_set", "batch_run", "template_apply",
                 "detach", "session_snapshot", "session_restore"} & names)
    # unselected groups are gone entirely
    assert "scan" not in names and "ue_introspect" not in names
    assert "tools_catalog" in names


def test_tools_catalog(mcp_config_path):
    """Catalog completeness: groups cover every registered tool, no leaks/dupes."""
    server = mcp_server.build_server(mcp_config_path)
    names = _tool_names(server)
    assert names == ALL_GROUP_TOOLS | {"tools_catalog"}

    # no tool belongs to two groups
    seen: set[str] = set()
    for tools in mcp_server.TOOL_GROUPS.values():
        for t in tools:
            assert t not in seen, f"{t} listed in multiple groups"
            seen.add(t)

    # the catalog tool itself reports the same data
    tm = getattr(server, "_tool_manager", None)
    tool = tm._tools.get("tools_catalog") if tm is not None else None
    assert tool is not None
    data = tool.fn() if hasattr(tool, "fn") else None
    if data is not None:
        assert data["groups"] == mcp_server.TOOL_GROUPS
        assert data["total_tools"] == len(ALL_GROUP_TOOLS)
        assert "tip" in data

    # tools_catalog stays registered even on a lean server
    lean = _tool_names(mcp_server.build_server(mcp_config_path, groups=["ue"]))
    assert "tools_catalog" in lean


def test_mcp_main_groups_arg(monkeypatch, mcp_config_path):
    """main() parses --groups and forwards it; invalid groups exit non-zero."""
    spy_calls = {}

    orig_build = mcp_server.build_server

    def spy(config_path=None, profile="default", groups=None):
        server = orig_build(config_path, profile=profile, groups=groups)
        server.run = lambda *a, **k: None  # never start the stdio loop in tests
        spy_calls["profile"] = profile
        spy_calls["groups"] = groups
        return server

    monkeypatch.setattr(mcp_server, "build_server", spy)
    rc = mcp_server.main(["--config", mcp_config_path, "--groups", "core,ue,scan"])
    assert rc == 0
    assert spy_calls["profile"] == "default"
    assert spy_calls["groups"] == ["core", "ue", "scan"]

    # no --groups -> full registration (groups=None)
    rc = mcp_server.main(["--config", mcp_config_path])
    assert rc == 0
    assert spy_calls["groups"] is None

    # invalid group name -> error exit with the valid list, no server run
    rc = mcp_server.main(["--config", mcp_config_path, "--groups", "bogus"])
    assert rc != 0

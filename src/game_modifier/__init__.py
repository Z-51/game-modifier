"""game_modifier - token-efficient single-player game memory modifier.

A CLI + MCP toolkit designed for Claude Code / Codex agents. It exposes
structured, JSON-first commands so an agent can analyze and modify a
single-player game's memory with minimal tokens: deterministic Chinese
natural-language mapping, predefined templates, batch execution, session
reuse and a symbolic address table.

Only intended for single-player / offline games that the user legally owns.
The tool refuses to operate on processes protected by known anti-cheat
systems.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]

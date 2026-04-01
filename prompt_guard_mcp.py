"""
MCP (Model Context Protocol) server exposing prompt-guard as tools over stdio.

Used by Cursor, Claude Desktop, and other MCP clients. Install with::

    pip install -e ".[mcp]"

Run via the ``prompt-guard-mcp`` console script or ``python -m prompt_guard_mcp``.
"""

from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("prompt-guard")


def _config_for_mcp():
    """
    Optional env-driven config for quieter MCP runs.

    - ``PROMPT_GUARD_NO_LOG=1``: disable file/console logging from the library.
    - ``PROMPT_GUARD_SQLITE``: override DB path (default when no_log: memory).
    """
    from prompt_guard.config import PromptGuardConfig

    no_log = os.environ.get("PROMPT_GUARD_NO_LOG", "").lower() in ("1", "true", "yes")
    sqlite = os.environ.get("PROMPT_GUARD_SQLITE", "").strip()
    if not no_log and not sqlite:
        return None
    if no_log and not sqlite:
        sqlite = ":memory:"
    elif not sqlite:
        sqlite = "prompt_guard_analytics.db"
    return PromptGuardConfig(
        logging_enabled=not no_log,
        sqlite_path=sqlite,
    )


@mcp.tool()
def analyze_prompt(prompt: str) -> str:
    """
    Analyze prompt text for sensitive data (PII, secrets, profanity, org patterns).

    Returns JSON with: original, masked, findings (nested by domain), findings_flat,
    matches (with confidence), risk_score, stats_snapshot. Does not block execution;
    use the masked text or risk_score in the client to warn users.
    """
    from prompt_guard.api.service import analyze_prompt as run_analyze

    cfg = _config_for_mcp()
    result = run_analyze(prompt, config=cfg) if cfg is not None else run_analyze(prompt)
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
def prompt_guard_stats() -> str:
    """
    Return aggregate analytics (JSON) from the default tracker (SQLite or :memory:).
    """
    from prompt_guard import get_stats

    return json.dumps(get_stats(), ensure_ascii=False, indent=2)


def main() -> None:
    """Start the MCP server on stdio (required by Cursor / Claude Desktop)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

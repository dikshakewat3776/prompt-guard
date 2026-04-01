"""
prompt_guard — pluggable analysis engine for prompts sent to AI coding tools.

Analyze, mask, score risk, and persist lightweight analytics without blocking
downstream AI calls. Intended for IDE extensions and proxies that surface
warnings to the user.

Example::

    from prompt_guard import analyze_prompt

    result = analyze_prompt("My email is test@example.com and API key is sk-1234567890abcdef")
    print(result["risk_score"], result["masked"])
    print(result.get("findings", {}).get("global", {}).get("email"), result.get("matches"))
"""

from __future__ import annotations

from prompt_guard.analytics.tracker import get_stats
from prompt_guard.api.service import analyze_prompt
from prompt_guard.config import PromptGuardConfig, RegexRuleSpec

__version__ = "0.1.0"

__all__ = [
    "PromptGuardConfig",
    "RegexRuleSpec",
    "__version__",
    "analyze_prompt",
    "get_stats",
]

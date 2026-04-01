"""
Configuration objects for :mod:`prompt_guard`.

``PromptGuardConfig`` centralizes user overrides: custom regex rules, word lists,
and logging/analytics paths.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prompt_guard.config.default_rules import (
    DEFAULT_PROFANITY_WORDS,
    get_default_pattern_specs,
)
from prompt_guard.config.sensitive_data_map import (
    CUSTOM_FLAGGED_WORDS,
    ORG_RISK_WEIGHTS,
    ORG_SENSITIVE_MAP,
    SENSITIVE_DATA_MAP,
    SENSITIVITY_BUCKETS,
    TOXIC_WORDS,
)


@dataclass
class RegexRuleSpec:
    """
    Specification for a user-defined or built-in regex detection rule.

    Attributes:
        name: Logical category key (e.g. ``internal_id``).
        pattern: Regex pattern string.
        flags: Optional :mod:`re` flags (default 0).
    """

    name: str
    pattern: str
    flags: int = 0


@dataclass
class PromptGuardConfig:
    """
    Runtime configuration for :func:`prompt_guard.api.service.analyze_prompt`.

    Attributes:
        custom_regex_rules: Additional :class:`RegexRuleSpec` entries merged with
            built-in sensitive patterns.
        custom_flagged_keywords: Extra keywords/phrases to flag (case-insensitive).
        extra_profanity_words: Words merged with :data:`DEFAULT_PROFANITY_WORDS`.
        disabled_builtin_categories: Built-in regex category names to skip
            (e.g. ``{"phone"}``).
        logging_enabled: Master switch for package logging.
        debug: Enable DEBUG log level and verbose diagnostics.
        log_file: Path for rotating log file (default: ``prompt_guard.log`` in CWD).
        log_max_bytes: Rotation size threshold.
        log_backup_count: Number of rotated files to keep.
        sqlite_path: Path to SQLite DB for analytics (default in-memory).
        analytics_enabled: If False, skips SQLite writes (still returns in-memory
            snapshot if tracker is used).
    """

    custom_regex_rules: list[RegexRuleSpec] = field(default_factory=list)
    custom_flagged_keywords: list[str] = field(default_factory=list)
    extra_profanity_words: list[str] = field(default_factory=list)
    disabled_builtin_categories: frozenset[str] = field(
        default_factory=frozenset
    )
    logging_enabled: bool = True
    debug: bool = False
    log_file: Path | str | None = None
    log_max_bytes: int = 5 * 1024 * 1024
    log_backup_count: int = 5
    sqlite_path: str | Path = "prompt_guard_analytics.db"
    analytics_enabled: bool = True

    def merged_profanity_words(self) -> frozenset[str]:
        """
        Return the union of default and user-supplied profanity words.

        Returns:
            Normalized lowercase word set.
        """
        extra = {w.strip().lower() for w in self.extra_profanity_words if w.strip()}
        return DEFAULT_PROFANITY_WORDS | extra

    def merged_custom_keywords(self) -> frozenset[str]:
        """
        Return normalized custom flagged keywords.

        Returns:
            Lowercase keyword set.
        """
        return {w.strip().lower() for w in self.custom_flagged_keywords if w.strip()}

    def build_pattern_list(self) -> list[tuple[str, re.Pattern[str]]]:
        """
        Merge default and custom regex rules into compiled patterns.

        Returns:
            List of ``(category_name, compiled_regex)`` pairs.
        """
        specs: list[tuple[str, str, int]] = []
        for name, pat, flags in get_default_pattern_specs():
            if name in self.disabled_builtin_categories:
                continue
            specs.append((name, pat, flags))
        for rule in self.custom_regex_rules:
            specs.append((rule.name, rule.pattern, rule.flags))

        result: list[tuple[str, re.Pattern[str]]] = []
        for name, pat, flags in specs:
            result.append((name, re.compile(pat, flags)))
        return result

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize non-secret options for logging (patterns not expanded).

        Returns:
            JSON-serializable summary.
        """
        return {
            "custom_regex_rule_count": len(self.custom_regex_rules),
            "custom_keyword_count": len(self.custom_flagged_keywords),
            "extra_profanity_count": len(self.extra_profanity_words),
            "disabled_builtin_categories": sorted(self.disabled_builtin_categories),
            "logging_enabled": self.logging_enabled,
            "debug": self.debug,
            "sqlite_path": str(self.sqlite_path),
            "analytics_enabled": self.analytics_enabled,
        }


__all__ = [
    "CUSTOM_FLAGGED_WORDS",
    "ORG_RISK_WEIGHTS",
    "ORG_SENSITIVE_MAP",
    "PromptGuardConfig",
    "RegexRuleSpec",
    "SENSITIVE_DATA_MAP",
    "SENSITIVITY_BUCKETS",
    "TOXIC_WORDS",
]

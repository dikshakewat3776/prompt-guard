"""
Default rules bridge: re-exports :mod:`prompt_guard.config.sensitive_data_map` and
pattern-row helpers for :class:`~prompt_guard.config.PromptGuardConfig`.
"""

from __future__ import annotations

import re
from typing import Final

from .sensitive_data_map import (
    CATEGORY_SEVERITY,
    MASK_MAP,
    RISK_WEIGHTS,
    SENSITIVE_DATA_MAP,
    TOXIC_WORDS,
    flatten_sensitive_data_map,
)

# Back-compat alias used by older imports.
MASK_PLACEHOLDERS: Final[dict[str, str]] = MASK_MAP

# Merge legacy word list with :data:`TOXIC_WORDS` from the sensitivity map.
_DEFAULT_LEGACY_PROFANITY: frozenset[str] = frozenset(
    {
        "damn",
        "hell",
        "crap",
        "bastard",
        "bitch",
        "asshole",
        "shit",
        "fuck",
        "fucking",
        "dick",
        "piss",
        "slut",
        "whore",
    }
)

DEFAULT_PROFANITY_WORDS: Final[frozenset[str]] = _DEFAULT_LEGACY_PROFANITY | TOXIC_WORDS


def get_default_pattern_rows() -> list[tuple[str, str, str, int]]:
    """
    Return built-in rules as ``(domain, leaf_key, pattern, flags)`` rows.

    Returns:
        Rows suitable for :class:`~prompt_guard.detector.sensitive_detector.SensitiveDetector`.
    """
    return flatten_sensitive_data_map(SENSITIVE_DATA_MAP)


def get_default_pattern_specs() -> list[tuple[str, str, re.RegexFlag]]:
    """
    Return ``(leaf_key, pattern, flags)`` for config compilation (unique leaf names).

    Returns:
        List of tuples for :meth:`PromptGuardConfig.build_pattern_list`.
    """
    seen: set[str] = set()
    out: list[tuple[str, str, re.RegexFlag]] = []
    for domain, leaf, pat, flags in get_default_pattern_rows():
        if leaf in seen:
            continue
        seen.add(leaf)
        out.append((leaf, pat, flags))
    return out

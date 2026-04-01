"""
Shared helper utilities for hashing, normalization, and small pure functions.
"""

from __future__ import annotations

import hashlib


def hash_text(text: str, algorithm: str = "sha256") -> str:
    """
    Compute a hex digest of ``text`` for logging without storing raw secrets.

    Args:
        text: Input string (typically a user prompt).
        algorithm: Hash name supported by :mod:`hashlib` (default ``sha256``).

    Returns:
        Lowercase hexadecimal digest string.
    """
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8", errors="replace"))
    return h.hexdigest()


def clamp_int(value: int, low: int, high: int) -> int:
    """
    Clamp an integer to the inclusive range ``[low, high]``.

    Args:
        value: Value to clamp.
        low: Minimum allowed value.
        high: Maximum allowed value.

    Returns:
        Clamped integer.
    """
    return max(low, min(high, value))


def normalize_for_match(word: str) -> str:
    """
    Lowercase and strip surrounding whitespace for dictionary comparisons.

    Args:
        word: Raw word or phrase from configuration.

    Returns:
        Normalized string.
    """
    return word.strip().lower()

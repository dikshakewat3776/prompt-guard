"""
Checksum and heuristic validators to reduce false positives (Aadhaar, cards, length).
"""

from __future__ import annotations

import re
from typing import Final, Tuple

# Verhoeff multiplication table (d[i][j]).
_VERHOEFF_D: Final[Tuple[Tuple[int, ...], ...]] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

# Verhoeff permutation table (p[i][j]) — eight permutations for digit positions.
_VERHOEFF_P: Final[Tuple[Tuple[int, ...], ...]] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def digits_only(value: str) -> str:
    """
    Strip non-digit characters from ``value``.

    Args:
        value: Arbitrary string (e.g. spaced Aadhaar).

    Returns:
        Contiguous digit string.
    """
    return re.sub(r"\D", "", value)


def verhoeff_valid(number: str) -> bool:
    """
    Return True if ``number`` (digits only) passes the Verhoeff checksum.

    Used for Indian Aadhaar (12 digits including check digit).

    Args:
        number: Digit string (typically 12 digits for Aadhaar).

    Returns:
        True if the checksum validates.
    """
    digits = digits_only(number)
    if not digits:
        return False
    c = 0
    le = len(digits)
    for i in range(le):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(digits[le - i - 1])]]
    return c == 0


def luhn_valid(number: str) -> bool:
    """
    Return True if ``number`` passes the Luhn algorithm (card numbers).

    Args:
        number: Digit string (13–19 digits typical for cards).

    Returns:
        True if valid per Luhn.
    """
    digits = digits_only(number)
    if len(digits) < 13:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def normalize_card_candidate(raw: str) -> str:
    """
    Extract digits from a credit-card-like match (spaces/dashes allowed).

    Args:
        raw: Substring from regex.

    Returns:
        Digit-only string.
    """
    return digits_only(raw)


def is_plausible_credit_card(raw: str) -> bool:
    """
    Return True if ``raw`` has 13–16 contiguous digits (after cleanup) and passes Luhn.

    Args:
        raw: Matched text from detector.

    Returns:
        True if length and Luhn are satisfied.
    """
    d = digits_only(raw)
    if len(d) < 13 or len(d) > 19:
        return False
    return luhn_valid(d)


def is_plausible_aadhaar(raw: str) -> bool:
    """
    Return True if ``raw`` is 12 digits and passes Verhoeff.

    Args:
        raw: Matched Aadhaar substring.

    Returns:
        True if format and checksum validate.
    """
    d = digits_only(raw)
    if len(d) != 12:
        return False
    return verhoeff_valid(d)


def min_length_ok(raw: str, min_chars: int = 6) -> bool:
    """
    Return True if stripped ``raw`` meets minimum length (reduces noise).

    Args:
        raw: Candidate token.
        min_chars: Minimum inclusive length.

    Returns:
        True if ``len(raw.strip()) >= min_chars``.
    """
    return len(raw.strip()) >= min_chars

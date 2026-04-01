"""
Replace detected spans with stable placeholder tokens without structural leaks.
"""

from __future__ import annotations

from prompt_guard.config.default_rules import MASK_PLACEHOLDERS
from prompt_guard.detector.sensitive_detector import SpanMatch


class PromptMasker:
    """
    Applies category-specific placeholders from right to left to preserve indices.

    Unknown categories fall back to ``[MASKED]``.
    """

    def __init__(self) -> None:
        self._labels = dict(MASK_PLACEHOLDERS)

    def mask_with_spans(self, text: str, spans: list[SpanMatch]) -> tuple[str, int]:
        """
        Replace each span in ``text`` with its placeholder.

        Spans should be non-overlapping and sorted by ``start`` ascending.

        Args:
            text: Original prompt.
            spans: Winning detection spans (sensitive + profanity merged upstream).

        Returns:
            Tuple of ``(masked_text, number_of_replacements)``.
        """
        if not spans:
            return text, 0

        ordered = sorted(spans, key=lambda s: s.start, reverse=True)
        out = text
        count = 0
        for span in ordered:
            placeholder = self._labels.get(span.category, "[MASKED]")
            before = out[: span.start]
            after = out[span.end :]
            out = before + placeholder + after
            count += 1
        return out, count

    def placeholder_for(self, category: str) -> str:
        """
        Resolve the mask string for a logical category.

        Args:
            category: Detector category name.

        Returns:
            Placeholder string.
        """
        return self._labels.get(category, "[MASKED]")

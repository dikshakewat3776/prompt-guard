"""
Word-list based profanity detection with whole-word boundaries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from prompt_guard.config import PromptGuardConfig
from prompt_guard.config.sensitive_data_map import CATEGORY_SEVERITY
from prompt_guard.detector.sensitive_detector import SpanMatch, _resolve_overlaps


@dataclass
class ProfanityFindings:
    """
    Profanity matches and merged span list for masking.

    Attributes:
        spans: Non-overlapping profanity spans (category ``profanity``).
        words: Raw matched words/phrases in order of appearance.
    """

    spans: list[SpanMatch] = field(default_factory=list)
    words: list[str] = field(default_factory=list)

    def to_list(self) -> list[str]:
        """
        Return matched profanity strings for API ``findings['profanity']``.

        Returns:
            List of detected tokens.
        """
        return list(self.words)


class ProfanityDetector:
    """
    Scans text for profanity using a configurable word set.

    Matching uses word boundaries via regex to reduce substring false positives.

    Args:
        config: Optional :class:`~prompt_guard.config.PromptGuardConfig` with
            ``extra_profanity_words`` merged into defaults.
    """

    def __init__(self, config: PromptGuardConfig | None = None) -> None:
        self._config = config or PromptGuardConfig()
        self._words = sorted(
            self._config.merged_profanity_words(),
            key=len,
            reverse=True,
        )

    def detect(self, text: str) -> ProfanityFindings:
        """
        Find profanity tokens in ``text``.

        Args:
            text: User prompt.

        Returns:
            :class:`ProfanityFindings` with spans suitable for the masker.
        """
        if not self._words or not text:
            return ProfanityFindings()

        spans: list[SpanMatch] = []
        for word in self._words:
            if not word:
                continue
            pattern = re.compile(
                r"(?<!\w)" + re.escape(word) + r"(?!\w)",
                re.IGNORECASE | re.UNICODE,
            )
            for m in pattern.finditer(text):
                spans.append(
                    SpanMatch(
                        category="profanity",
                        value=m.group(0),
                        start=m.start(),
                        end=m.end(),
                        domain="toxicity",
                        severity=CATEGORY_SEVERITY["profanity"],
                        confidence=0.85,
                    )
                )

        resolved = _resolve_overlaps(spans)
        words = [s.value for s in resolved]
        return ProfanityFindings(spans=resolved, words=words)

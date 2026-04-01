"""
Dataclasses for analytics snapshots and internal event representation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class AnalyticsSnapshot:
    """
    Point-in-time aggregate statistics returned to API callers.

    Attributes:
        total_prompts: Total number of prompts processed since tracker init.
        total_sensitive_items: Sum of all detected sensitive/tagged items.
        masked_token_count: Total number of replacement spans applied.
        counts_by_category: Per-category detection counts (lifetime).
        last_updated: UTC timestamp of the last stats update.
    """

    total_prompts: int = 0
    total_sensitive_items: int = 0
    masked_token_count: int = 0
    counts_by_category: dict[str, int] = field(default_factory=dict)
    last_updated: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the snapshot to a JSON-friendly dictionary.

        Returns:
            Dict suitable for embedding in API responses.
        """
        return {
            "total_prompts": self.total_prompts,
            "total_sensitive_items": self.total_sensitive_items,
            "masked_token_count": self.masked_token_count,
            "counts_by_category": dict(self.counts_by_category),
            "last_updated": (
                self.last_updated.isoformat() if self.last_updated else None
            ),
        }


@dataclass
class PromptAnalyticsEvent:
    """
    Internal record for a single analyze operation (optional persistence hook).

    Attributes:
        prompt_hash: Optional hash of the prompt for deduplication/audit.
        risk_score: Computed risk score for the prompt.
        category_counts: Counts for this prompt only.
        masked_spans: Number of masked regions.
    """

    prompt_hash: str
    risk_score: int
    category_counts: dict[str, int]
    masked_spans: int

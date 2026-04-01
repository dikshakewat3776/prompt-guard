"""
Main service API: orchestrates detection, masking, risk scoring, logging, analytics.
"""

from __future__ import annotations

import json
from typing import Any

from prompt_guard.analytics.tracker import AnalyticsTracker, get_default_tracker
from prompt_guard.config import PromptGuardConfig
from prompt_guard.config.sensitive_data_map import RISK_WEIGHTS
from prompt_guard.detector.profanity_detector import ProfanityDetector
from prompt_guard.detector.sensitive_detector import SensitiveDetector, SpanMatch
from prompt_guard.detector.sensitive_detector import _resolve_overlaps as merge_spans
from prompt_guard.logger.logger import get_logger, setup_logging
from prompt_guard.masker.masker import PromptMasker
from prompt_guard.utils.helpers import clamp_int, hash_text

_log = get_logger("service")


def _compute_risk_score(category_counts: dict[str, int]) -> int:
    """
    Map per-category counts to a bounded 0-100 risk score.

    Weights favor secrets (API keys, JWT) over contact info and profanity.

    Args:
        category_counts: Counts per detector leaf key (e.g. ``api_key_generic``).

    Returns:
        Integer score from 0 to 100 inclusive.
    """
    raw = 0
    for cat, n in category_counts.items():
        w = RISK_WEIGHTS.get(cat, 5)
        for i in range(n):
            raw += max(1, w - i * 2)
    return clamp_int(raw, 0, 100)


def _nested_from_spans(spans: list[SpanMatch]) -> dict[str, dict[str, list[str]]]:
    """
    Build the nested ``domain -> leaf -> [values]`` map from winning spans.

    Args:
        spans: Overlap-resolved spans (already merged across detectors).

    Returns:
        Nested findings dict aligned with :data:`SENSITIVE_DATA_MAP` domains.
    """
    nested: dict[str, dict[str, list[str]]] = {}
    for sp in spans:
        nested.setdefault(sp.domain, {}).setdefault(sp.category, []).append(sp.value)
    return nested


def _matches_from_spans(spans: list[SpanMatch]) -> list[dict[str, Any]]:
    """
    Serialize spans to confidence-aware match rows for UIs.

    Args:
        spans: Overlap-resolved spans.

    Returns:
        Sorted list of ``{value, type, domain, confidence, start, end}``.
    """
    rows: list[dict[str, Any]] = [
        {
            "value": sp.value,
            "type": sp.category,
            "domain": sp.domain,
            "confidence": round(sp.confidence, 4),
            "start": sp.start,
            "end": sp.end,
        }
        for sp in spans
    ]
    rows.sort(key=lambda r: (r["start"], r["end"]))
    return rows


def _flatten_findings(nested: dict[str, dict[str, list[str]]]) -> dict[str, list[str]]:
    """
    Produce a flat ``leaf_key -> matches`` view for analytics / legacy consumers.

    Args:
        nested: Output of :func:`_merge_nested`.

    Returns:
        Flattened map (leaf keys may include ``profanity``).
    """
    flat: dict[str, list[str]] = {}
    for _domain, inner in nested.items():
        for leaf, vals in inner.items():
            flat.setdefault(leaf, []).extend(vals)
    return flat


def analyze_prompt(
    prompt: str,
    config: PromptGuardConfig | None = None,
    tracker: AnalyticsTracker | None = None,
) -> dict[str, Any]:
    """
    Analyze ``prompt`` for sensitive data and profanity; mask and score risk.

    This function never raises for typical user input: detectors are regex/word
    based. Optional SQLite or logging failures are caught where they could break
    callers; prefer fixing permissions for production deployments.

    Args:
        prompt: Raw user text before sending to an AI tool.
        config: Optional :class:`~prompt_guard.config.PromptGuardConfig`.
        tracker: Optional :class:`~prompt_guard.analytics.tracker.AnalyticsTracker`;
            if ``None``, the process default tracker is used.

    Returns:
        Dictionary with keys:

        - ``original``: Original prompt text.
        - ``masked``: Text after placeholder substitution.
        - ``findings``: Nested map ``domain -> leaf_key -> [matched strings]`` (see
          :data:`~prompt_guard.config.sensitive_data_map.SENSITIVE_DATA_MAP`).
        - ``findings_flat``: Flattened ``leaf_key -> [strings]`` for simple analytics.
        - ``matches``: List of ``{value, type, domain, confidence, start, end}``.
        - ``risk_score``: Integer 0-100.
        - ``stats_snapshot``: Aggregate stats from the analytics tracker.
    """
    cfg = config or PromptGuardConfig()

    setup_logging(
        enabled=cfg.logging_enabled,
        debug=cfg.debug,
        log_file=cfg.log_file,
        max_bytes=cfg.log_max_bytes,
        backup_count=cfg.log_backup_count,
    )

    sensitive_det = SensitiveDetector(cfg)
    profanity_det = ProfanityDetector(cfg)
    masker = PromptMasker()

    sens = sensitive_det.detect(prompt)
    prof = profanity_det.detect(prompt)

    all_spans: list[SpanMatch] = list(sens.spans) + list(prof.spans)
    merged = merge_spans(all_spans)
    masked_text, masked_count = masker.mask_with_spans(prompt, merged)

    nested = _nested_from_spans(merged)
    findings_flat = _flatten_findings(nested)
    matches = _matches_from_spans(merged)

    category_counts = {k: len(v) for k, v in findings_flat.items() if v}
    risk = _compute_risk_score(category_counts)
    phash = hash_text(prompt)

    tr = tracker or get_default_tracker(cfg)
    try:
        tr.record_prompt(
            prompt_hash=phash,
            risk_score=risk,
            category_counts=category_counts,
            masked_spans=masked_count,
        )
    except Exception as exc:  # noqa: BLE001 — keep API resilient
        _log.warning("Analytics record failed: %s", exc)

    stats_snapshot = tr.get_stats().to_dict()

    _log.info(
        "analyze_prompt | hash=%s | risk=%s | findings_nested=%s",
        phash,
        risk,
        json.dumps(nested, ensure_ascii=False),
    )
    _log.info("original_prompt=%s", prompt)
    _log.info("masked_prompt=%s", masked_text)

    return {
        "original": prompt,
        "masked": masked_text,
        "findings": nested,
        "findings_flat": findings_flat,
        "matches": matches,
        "risk_score": risk,
        "stats_snapshot": stats_snapshot,
    }

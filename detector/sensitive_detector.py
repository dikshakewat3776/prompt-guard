"""
Regex-based detection using :data:`~prompt_guard.config.sensitive_data_map.SENSITIVE_DATA_MAP`,
validators, and confidence scores.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from prompt_guard.config import PromptGuardConfig
from prompt_guard.config.default_rules import get_default_pattern_rows
from prompt_guard.config.sensitive_data_map import CATEGORY_SEVERITY, SENSITIVE_DATA_MAP
from prompt_guard.utils import validation as V


@dataclass
class SpanMatch:
    """
    A single detected substring with domain, leaf type, confidence, and bounds.

    Attributes:
        category: Leaf detector key (e.g. ``aadhaar``, ``api_key_generic``).
        domain: Top-level bucket from :data:`SENSITIVE_DATA_MAP` (e.g. ``india``).
        value: Raw matched text from the prompt.
        start: Start index in the original string (inclusive).
        end: End index (exclusive).
        severity: Priority for overlap resolution (higher wins).
        confidence: Heuristic 0.0–1.0 (checksums / context / pattern strength).
    """

    category: str
    value: str
    start: int
    end: int
    domain: str = "global"
    severity: int = 0
    confidence: float = 0.5

    def __post_init__(self) -> None:
        """Populate ``severity`` from :data:`CATEGORY_SEVERITY` when unset (0)."""
        if self.severity == 0:
            self.severity = CATEGORY_SEVERITY.get(self.category, 30)


@dataclass
class SensitiveFindings:
    """
    Detector output: spans, flat buckets, nested map, and detailed match records.

    Attributes:
        spans: Non-overlapping winning spans after resolution.
        raw_by_category: ``leaf_key -> [values]`` for risk scoring.
        nested: ``domain -> leaf_key -> [values]`` aligned with ``SENSITIVE_DATA_MAP``.
        matches_detail: Structured rows for UI / analytics (confidence per hit).
    """

    spans: list[SpanMatch] = field(default_factory=list)
    raw_by_category: dict[str, list[str]] = field(default_factory=dict)
    nested: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    matches_detail: list[dict[str, Any]] = field(default_factory=list)

    def to_findings_dict(self) -> dict[str, list[str]]:
        """
        Flatten ``raw_by_category`` (legacy helper).

        Returns:
            Mapping of leaf key to matched strings.
        """
        return {k: list(v) for k, v in self.raw_by_category.items()}


def _overlaps(a: SpanMatch, b: SpanMatch) -> bool:
    """Return True if ``[a.start, a.end)`` intersects ``[b.start, b.end)``."""
    return a.start < b.end and b.start < a.end


def _resolve_overlaps(spans: list[SpanMatch]) -> list[SpanMatch]:
    """
    Keep non-overlapping spans by processing highest severity (then longest) first.

    Args:
        spans: Detected spans (may overlap).

    Returns:
        Non-overlapping spans sorted left-to-right.
    """
    if not spans:
        return []
    ordered = sorted(
        spans,
        key=lambda s: (-s.severity, -(s.end - s.start), s.start),
    )
    accepted: list[SpanMatch] = []
    for span in ordered:
        if any(_overlaps(span, ex) for ex in accepted):
            continue
        accepted.append(span)
    accepted.sort(key=lambda s: s.start)
    return accepted


# Keywords near a candidate bank-account number (±window chars).
_BANK_CTX: frozenset[str] = frozenset(
    ("account", "acct", "a/c", "bank", "savings", "current", "ifsc", "iban", "neft", "rtgs")
)


def _has_bank_context(text: str, start: int, end: int, window: int = 96) -> bool:
    """Return True if a bank-related keyword appears near ``[start, end)``."""
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    chunk = text[lo:hi].lower()
    return any(k in chunk for k in _BANK_CTX)


def _is_indian_mobile_digits(value: str) -> bool:
    """Return True if digits form a 10-digit Indian mobile (starts 6–9)."""
    d = V.digits_only(value)
    return len(d) == 10 and d[0] in "6789"


# Domains from :data:`~prompt_guard.config.sensitive_data_map.ORG_SENSITIVE_MAP`.
_ENTERPRISE_DOMAINS: frozenset[str] = frozenset(
    {
        "client_data",
        "financial_data",
        "credentials",
        "internal_documents",
        "legal_compliance",
        "strategy_ip",
        "infrastructure",
    }
)


def _confidence_for_leaf(
    domain: str,
    leaf: str,
    value: str,
    text: str,
    start: int,
    end: int,
) -> tuple[float, bool]:
    """
    Compute confidence and whether the span should be kept.

    Returns:
        ``(confidence, keep)``. ``keep`` False drops the candidate.
    """
    # Broad / noisy patterns: short tokens ignored (except fixed-length IDs).
    if leaf in ("passport_generic", "address"):
        if not V.min_length_ok(value, 6):
            return (0.0, False)
        base = 0.22 if leaf == "address" else 0.25
        return (base, True)

    if leaf == "credit_card":
        if V.is_plausible_credit_card(value):
            return (0.92, True)
        return (0.0, False)

    if leaf == "aadhaar":
        if V.is_plausible_aadhaar(value):
            return (0.94, True)
        # Regex-only Aadhaar shape — keep with low confidence (Verhoeff may fail on typos).
        if len(V.digits_only(value)) == 12:
            return (0.38, True)
        return (0.0, False)

    if leaf == "bank_account":
        if _is_indian_mobile_digits(value):
            # Prefer ``indian_phone`` for typical mobile numbers.
            return (0.0, False)
        if not _has_bank_context(text, start, end):
            return (0.0, False)
        return (0.78, True)

    if leaf == "pan":
        return (0.92, True)

    if leaf == "ifsc":
        return (0.9, True)

    if leaf in ("api_key_generic", "jwt_token", "aws_access_key", "github_token"):
        return (0.88, True)

    if leaf == "private_key":
        return (0.98, True)

    if leaf in ("db_connection_string", "slack_token", "firebase_key"):
        return (0.9, True)

    if leaf == "internal_url":
        return (0.65, True)

    if leaf in ("email", "upi_id"):
        return (0.82, True)

    if leaf in ("indian_phone", "phone"):
        return (0.8, True)

    if leaf == "ssn_us":
        return (0.9, True)

    if leaf == "passport_india":
        return (0.42, True)

    if leaf == "pincode_india":
        return (0.35, True)

    if leaf == "dob":
        return (0.55, True)

    if leaf == "ip_address":
        return (0.62, True)

    if domain in _ENTERPRISE_DOMAINS:
        if leaf == "internal_password":
            return (0.93, True)
        if leaf == "credential_api_assignment":
            return (0.91, True)
        if leaf in ("client_id", "portfolio_id", "transaction_id", "deal_code"):
            return (0.88, True)
        if leaf == "amounts":
            return (0.68, True)
        if leaf == "investment_details":
            return (0.75, True)
        if leaf in ("vpn_config", "meeting_notes"):
            return (0.52, True)
        if leaf in ("confidential_tag", "audit_report", "mna_keywords"):
            return (0.72, True)
        if leaf in ("pricing_strategy", "forecast"):
            return (0.7, True)
        if leaf in ("case_id", "regulatory_ref", "nda_reference"):
            return (0.82, True)
        if leaf == "internal_ip":
            return (0.88, True)
        if leaf == "s3_bucket":
            return (0.82, True)
        if leaf == "server_names":
            return (0.72, True)
        if leaf == "employee_id":
            return (0.85, True)
        return (0.65, True)

    if domain == "custom":
        return (0.55, True)

    return (0.55, True)


class SensitiveDetector:
    """
    Applies :data:`SENSITIVE_DATA_MAP` rules, validation heuristics, and keyword scans.

    Args:
        config: Optional :class:`~prompt_guard.config.PromptGuardConfig` for
            extensions and disabled categories.
    """

    def __init__(self, config: PromptGuardConfig | None = None) -> None:
        self._config = config or PromptGuardConfig()
        self._patterns = self._config.build_pattern_list()

    def detect(self, text: str) -> SensitiveFindings:
        """
        Run all configured regex rules and custom keyword matching on ``text``.

        Args:
            text: User prompt content.

        Returns:
            :class:`SensitiveFindings` with nested and flat projections.
        """
        spans: list[SpanMatch] = []

        for domain, leaf_key, pattern, flags in self._iter_rule_rows():
            if leaf_key in self._config.disabled_builtin_categories:
                continue
            rx = re.compile(pattern, flags)
            for m in rx.finditer(text):
                conf, keep = _confidence_for_leaf(
                    domain, leaf_key, m.group(0), text, m.start(), m.end()
                )
                if not keep:
                    continue
                spans.append(
                    SpanMatch(
                        category=leaf_key,
                        value=m.group(0),
                        start=m.start(),
                        end=m.end(),
                        domain=domain,
                        confidence=conf,
                    )
                )

        keywords = self._config.merged_custom_keywords()
        if keywords:
            spans.extend(self._find_keyword_spans(text, keywords))

        resolved = _resolve_overlaps(spans)
        raw_by_category: dict[str, list[str]] = {}
        nested: dict[str, dict[str, list[str]]] = {}
        matches_detail: list[dict[str, Any]] = []

        for sp in resolved:
            raw_by_category.setdefault(sp.category, []).append(sp.value)
            nested.setdefault(sp.domain, {}).setdefault(sp.category, []).append(sp.value)
            matches_detail.append(
                {
                    "value": sp.value,
                    "type": sp.category,
                    "domain": sp.domain,
                    "confidence": round(sp.confidence, 4),
                    "start": sp.start,
                    "end": sp.end,
                }
            )

        return SensitiveFindings(
            spans=resolved,
            raw_by_category=raw_by_category,
            nested=nested,
            matches_detail=matches_detail,
        )

    def _iter_rule_rows(self) -> list[tuple[str, str, str, int]]:
        """
        Merge built-in flattened map with user :class:`RegexRuleSpec` entries.

        Returns:
            Rows ``(domain, leaf_key, pattern, flags)``.
        """
        rows = list(get_default_pattern_rows())
        for rule in self._config.custom_regex_rules:
            rows.append(("custom", rule.name, rule.pattern, rule.flags))
        return rows

    def _find_keyword_spans(self, text: str, keywords: frozenset[str]) -> list[SpanMatch]:
        """
        Find whole-word occurrences of configured keywords (case-insensitive).

        Args:
            text: Full prompt.
            keywords: Normalized lowercase keywords.

        Returns:
            Span list for category ``custom_keyword`` in domain ``custom``.
        """
        lower = text.lower()
        spans: list[SpanMatch] = []
        for kw in keywords:
            if not kw:
                continue
            start = 0
            while True:
                idx = lower.find(kw, start)
                if idx == -1:
                    break
                before = lower[idx - 1] if idx > 0 else " "
                after = lower[idx + len(kw)] if idx + len(kw) < len(lower) else " "
                if before.isalnum() or after.isalnum():
                    start = idx + 1
                    continue
                spans.append(
                    SpanMatch(
                        category="custom_keyword",
                        value=text[idx : idx + len(kw)],
                        start=idx,
                        end=idx + len(kw),
                        domain="custom",
                        confidence=0.75,
                    )
                )
                start = idx + len(kw)
        return spans

    @staticmethod
    def findings_to_public_dict(findings: SensitiveFindings) -> dict[str, Any]:
        """
        Serialize findings for API consumers (nested + detail).

        Args:
            findings: Detector output.

        Returns:
            Dict with ``nested`` and ``matches_detail`` keys.
        """
        return {
            "nested": findings.nested,
            "matches_detail": findings.matches_detail,
            "flat": findings.to_findings_dict(),
        }


def detect_all(
    text: str,
    patterns_map: dict[str, dict[str, str]] | None = None,
) -> dict[str, dict[str, list[str]]]:
    """
    Illustrative nested regex sweep (no validators). Prefer :class:`SensitiveDetector`.

    Args:
        text: Input text.
        patterns_map: Defaults to :data:`~prompt_guard.config.sensitive_data_map.SENSITIVE_DATA_MAP`.

    Returns:
        ``findings[domain][leaf] = [matches]`` (regex :func:`re.findall` semantics).
    """
    from prompt_guard.config.sensitive_data_map import detect_all as _detect_all_map

    return _detect_all_map(text, patterns_map or SENSITIVE_DATA_MAP)

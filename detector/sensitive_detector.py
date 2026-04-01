"""
Regex-based detection using :data:`~prompt_guard.config.sensitive_data_map.SENSITIVE_DATA_MAP`,
validators, and confidence scores.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from config import PromptGuardConfig
from config.default_rules import get_default_pattern_rows
from config.sensitive_data_map import CATEGORY_SEVERITY, SENSITIVE_DATA_MAP
from utils import validation as V


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


def _merge_leaf_confidence(*groups: tuple[frozenset[str], float]) -> dict[str, float]:
    """Build a leaf -> confidence map; each key appears once (last group wins if duplicated)."""
    out: dict[str, float] = {}
    for keys, conf in groups:
        for k in keys:
            out[k] = conf
    return out


# Optimized lookup: non-enterprise leaves with fixed confidence (evaluated before enterprise fallback).
# Used to set the confidence for the leaves that are not enterprise-domain leaves.
# The confidence is a float between 0.0 and 1.0.
# The higher the confidence, the more confident the detector is that the leaf is sensitive.
# The lower the confidence, the less confident the detector is that the leaf is sensitive.
# The confidence is used to determine if the leaf should be masked or not.
# The confidence is used to determine if the leaf should be masked or not.
_DEFAULT_LEAF_CONFIDENCE: dict[str, float] = _merge_leaf_confidence(
    (frozenset({"pan"}), 0.92),
    (frozenset({"ifsc"}), 0.9),
    (
        frozenset({"api_key_generic", "jwt_token", "aws_access_key", "github_token"}),
        0.88,
    ),
    (frozenset({"private_key"}), 0.98),
    (frozenset({"db_connection_string", "slack_token", "firebase_key"}), 0.9),
    (frozenset({"internal_url"}), 0.65),
    (frozenset({"email", "upi_id"}), 0.82),
    (frozenset({"indian_phone", "phone"}), 0.8),
    (frozenset({"ssn_us"}), 0.9),
    (frozenset({"passport_india"}), 0.42),
    (frozenset({"pincode_india"}), 0.35),
    (frozenset({"dob"}), 0.55),
    (frozenset({"ip_address"}), 0.62),
)

# O(1) lookup: enterprise-domain leaves (unknown leaf -> 0.65).
_ENTERPRISE_LEAF_CONFIDENCE: dict[str, float] = _merge_leaf_confidence(
    (frozenset({"internal_password"}), 0.93),
    (frozenset({"credential_api_assignment"}), 0.91),
    (
        frozenset({"client_id", "portfolio_id", "transaction_id", "deal_code"}),
        0.88,
    ),
    (frozenset({"amounts"}), 0.68),
    (frozenset({"investment_details"}), 0.75),
    (frozenset({"vpn_config", "meeting_notes"}), 0.52),
    (frozenset({"confidential_tag", "audit_report", "mna_keywords"}), 0.72),
    (frozenset({"pricing_strategy", "forecast"}), 0.7),
    (frozenset({"case_id", "regulatory_ref", "nda_reference"}), 0.82),
    (frozenset({"internal_ip"}), 0.88),
    (frozenset({"s3_bucket"}), 0.82),
    (frozenset({"server_names"}), 0.72),
    (frozenset({"employee_id"}), 0.85),
)


def _conf_address(value: str, _t: str, _s: int, _e: int) -> tuple[float, bool]:
    if not V.min_length_ok(value, 6):
        return (0.0, False)
    return (0.22, True)


def _conf_passport_generic(value: str, _t: str, _s: int, _e: int) -> tuple[float, bool]:
    if not V.min_length_ok(value, 6):
        return (0.0, False)
    return (0.25, True)


def _conf_credit_card(value: str, _t: str, _s: int, _e: int) -> tuple[float, bool]:
    if V.is_plausible_credit_card(value):
        return (0.92, True)
    return (0.0, False)


def _conf_aadhaar(value: str, _t: str, _s: int, _e: int) -> tuple[float, bool]:
    if V.is_plausible_aadhaar(value):
        return (0.94, True)
    if len(V.digits_only(value)) == 12:
        return (0.38, True)
    return (0.0, False)


def _conf_bank_account(value: str, text: str, start: int, end: int) -> tuple[float, bool]:
    if _is_indian_mobile_digits(value):
        return (0.0, False)
    if not _has_bank_context(text, start, end):
        return (0.0, False)
    return (0.78, True)


# Value- or context-dependent leaves: O(1) dispatch by leaf name.
_SPECIAL_LEAF_HANDLERS: dict[str, Callable[[str, str, int, int], tuple[float, bool]]] = {
    "address": _conf_address,
    "passport_generic": _conf_passport_generic,
    "credit_card": _conf_credit_card,
    "aadhaar": _conf_aadhaar,
    "bank_account": _conf_bank_account,
}


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

    Uses O(1) dict lookups for fixed-confidence leaves; special validators dispatch
    by ``leaf`` name. Order matches the previous implementation: global defaults
    before enterprise-domain rules.

    Returns:
        ``(confidence, keep)``. ``keep`` False drops the candidate.
    """
    special = _SPECIAL_LEAF_HANDLERS.get(leaf)
    if special is not None:
        # Call the special leaf handler
        # The special leaf handler is a function that takes the value, text, start, and end
        # The value is the matched text
        # The text is the user prompt content
        # The start is the start index of the matched text
        # The end is the end index of the matched text
        # The special leaf handler returns a tuple with the confidence and whether the span should be kept
        return special(value, text, start, end)

    conf = _DEFAULT_LEAF_CONFIDENCE.get(leaf)
    if conf is not None:
        return (conf, True)

    if domain in _ENTERPRISE_DOMAINS:
        return (_ENTERPRISE_LEAF_CONFIDENCE.get(leaf, 0.65), True)

    if domain == "custom":
        return (0.55, True)
    # If the leaf is not in the default leaf confidence or enterprise leaf confidence, return a confidence of 0.55
    return (0.55, True)


class SensitiveDetector:
    """
    Applies :data:`SENSITIVE_DATA_MAP` rules, validation heuristics, and keyword scans.

    Args:
        config: Optional :class:`~prompt_guard.config.PromptGuardConfig` for
            extensions and disabled categories.
    """

    # Initialize the SensitiveDetector with the config
    # The config is an optional PromptGuardConfig object
    # If no config is provided, use the default PromptGuardConfig
    def __init__(self, config: PromptGuardConfig | None = None) -> None:
        self._config = config or PromptGuardConfig()
        self._patterns = self._config.build_pattern_list()

    # Detect the sensitive data in the text
    # The text is the user prompt content
    # The detect method returns a SensitiveFindings object
    # The SensitiveFindings object contains the spans, raw_by_category, nested, and matches_detail
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
                # Compute the confidence for the leaf
                # The confidence is a float between 0.0 and 1.0
                conf, keep = _confidence_for_leaf(domain, leaf_key, m.group(0), text, m.start(), m.end())
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


def detect_all(text: str,patterns_map: dict[str, dict[str, str]] | None = None,) -> dict[str, dict[str, list[str]]]:
    """
    Illustrative nested regex sweep (no validators). Prefer :class:`SensitiveDetector`.

    Args:
        text: Input text.
        patterns_map: Defaults to :data:`~prompt_guard.config.sensitive_data_map.SENSITIVE_DATA_MAP`.

    Returns:
        ``findings[domain][leaf] = [matches]`` (regex :func:`re.findall` semantics).
    """
    # Import the detect_all function from the sensitive_data_map module
    from config.sensitive_data_map import detect_all as _detect_all_map
    # Call the detect_all function with the text and patterns_map
    # 1. If patterns_map is not provided, use the SENSITIVE_DATA_MAP
    # 2. The SENSITIVE_DATA_MAP is a dictionary that maps the domain to the patterns
    # 3. The patterns are a dictionary that maps the leaf to the pattern
    # 4. The pattern is a string that is the regex pattern
    # 5. The leaf is a string that is the leaf key
    # 6. The domain is a string that is the domain
    # 7. The detect_all function returns a dictionary that maps the domain to the leaves and the matches
    return _detect_all_map(text, patterns_map or SENSITIVE_DATA_MAP)

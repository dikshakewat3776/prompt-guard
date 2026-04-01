"""
Structured sensitive-data taxonomy: India, global, auth, org/dev secrets, demographics,
and enterprise organizational risk (client, financial, credentials, legal, strategy, infra).

This module defines :data:`SENSITIVE_DATA_MAP`, :data:`ORG_SENSITIVE_MAP`, mask labels,
severity, and risk weights used by detectors and the service layer.
"""

from __future__ import annotations

import re
from typing import Final

# ---------------------------------------------------------------------------
# India-specific (high priority for compliance-style detection)
# ---------------------------------------------------------------------------
INDIA_SENSITIVE_PATTERNS: Final[dict[str, str]] = {
    "aadhaar": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
    "pan": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "ifsc": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "bank_account": r"\b\d{9,18}\b",
    "upi_id": r"\b[\w.-]+@[\w]+\b",
    "indian_phone": r"\b[6-9]\d{9}\b",
    "passport_india": r"\b[A-Z][0-9]{7}\b",
}

# ---------------------------------------------------------------------------
# Global personal / financial identifiers
# ---------------------------------------------------------------------------
GLOBAL_PATTERNS: Final[dict[str, str]] = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "ssn_us": r"\b\d{3}-\d{2}-\d{4}\b",
    "passport_generic": r"\b[A-Z0-9]{6,9}\b",
    # International phone (e.g. US-style); complements ``indian_phone``.
    "phone": (
        r"(?:\+?1[-.\s]?)?"
        r"(?:\(\d{3}\)|\d{3})"
        r"[-.\s]?"
        r"\d{3}"
        r"[-.\s]?"
        r"\d{4}\b"
    ),
}

# ---------------------------------------------------------------------------
# Authentication & secrets (critical)
# ---------------------------------------------------------------------------
AUTH_PATTERNS: Final[dict[str, str]] = {
    "api_key_generic": r"\b(?:sk|pk|api|key)[-_]?[A-Za-z0-9]{16,}\b",
    "jwt_token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "aws_access_key": r"\bAKIA[0-9A-Z]{16}\b",
    "private_key": r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----",
    "github_token": r"\bghp_[A-Za-z0-9]{36}\b",
}

# ---------------------------------------------------------------------------
# Organizational / developer secrets
# ---------------------------------------------------------------------------
ORG_PATTERNS: Final[dict[str, str]] = {
    "db_connection_string": r"(?:mongodb|postgres|mysql):\/\/[^\s]+",
    "internal_url": r"https?:\/\/(?:internal|dev|staging)\.[^\s]+",
    "slack_token": r"xox[baprs]-[A-Za-z0-9-]+",
    "firebase_key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
}

# ---------------------------------------------------------------------------
# Demographics & network (broad patterns — lower default confidence)
# ---------------------------------------------------------------------------
DEMOGRAPHIC_PATTERNS: Final[dict[str, str]] = {
    "address": r"\d{1,5}\s[\w\s,.-]{10,}",
    "pincode_india": r"\b\d{6}\b",
    "dob": r"\b\d{2}[/-]\d{2}[/-]\d{4}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

# ---------------------------------------------------------------------------
# Enterprise / organizational (high-risk business context)
# ---------------------------------------------------------------------------
CLIENT_DATA_PATTERNS: Final[dict[str, str]] = {
    "client_id": r"\b(?:CLIENT|CUST)[-_]?\d{4,}\b",
    "portfolio_id": r"\bPORTFOLIO[-_]?\d+\b",
    "investment_details": r"(?i)(equity|bond|derivative).{0,30}?(position|holding)",
}

FINANCIAL_PATTERNS: Final[dict[str, str]] = {
    "transaction_id": r"\bTXN[-_]?\d{6,}\b",
    "deal_code": r"\bDEAL[-_]?\d+\b",
    "amounts": r"\b(?:USD|INR|\$)\s?\d+(?:,\d{3})*(?:\.\d+)?\b",
}

CREDENTIAL_PATTERNS: Final[dict[str, str]] = {
    "employee_id": r"\bEMP\d{4,}\b",
    "vpn_config": r"(?i)(vpn|openvpn|ipsec).{0,50}",
    "internal_password": r"(?i)password\s*[:=]\s*\S+",
    # Inline assignment lines (distinct from ``api_key_generic`` token patterns).
    "credential_api_assignment": r"(?i)\b(?:api[_-]?key|token)\s*[:=]\s*\S+",
}

INTERNAL_DOC_PATTERNS: Final[dict[str, str]] = {
    "confidential_tag": r"(?i)\b(confidential|internal use only|do not share)\b",
    "meeting_notes": r"(?i)(minutes of meeting|MoM).{0,50}",
    "audit_report": r"(?i)(audit findings|risk assessment).{0,50}",
}

LEGAL_PATTERNS: Final[dict[str, str]] = {
    "case_id": r"\bCASE[-_]?\d+\b",
    "regulatory_ref": r"\b(?:SEBI|SEC|FCA)[-_]?\d+\b",
    "nda_reference": r"\bNDA[-_]?\d+\b",
}

STRATEGY_PATTERNS: Final[dict[str, str]] = {
    # Keyword-first (avoid greedy ``.{0,30}`` spans that swallow unrelated tokens).
    "mna_keywords": r"(?i)\b(?:merger|acquisition|buyout)\b",
    "pricing_strategy": r"(?i)\b(?:pricing model|discount strategy)\b",
    "forecast": r"(?i)\b(?:revenue forecast|projection)\b",
}

INFRA_PATTERNS: Final[dict[str, str]] = {
    "internal_ip": r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "server_names": r"\b(?:prod|dev|staging)-[a-z0-9-]+\b",
    "s3_bucket": r"\b[a-z0-9.-]+\.s3\.amazonaws\.com\b",
}

# Top-level enterprise classification (maps to detector ``domain`` strings).
ORG_SENSITIVE_MAP: Final[dict[str, dict[str, str]]] = {
    "client_data": dict(CLIENT_DATA_PATTERNS),
    "financial_data": dict(FINANCIAL_PATTERNS),
    "credentials": dict(CREDENTIAL_PATTERNS),
    "internal_documents": dict(INTERNAL_DOC_PATTERNS),
    "legal_compliance": dict(LEGAL_PATTERNS),
    "strategy_ip": dict(STRATEGY_PATTERNS),
    "infrastructure": dict(INFRA_PATTERNS),
}

# ---------------------------------------------------------------------------
# Unified map (canonical internal structure)
# ---------------------------------------------------------------------------
SENSITIVE_DATA_MAP: Final[dict[str, dict[str, str]]] = {
    "india": dict(INDIA_SENSITIVE_PATTERNS),
    "global": dict(GLOBAL_PATTERNS),
    "auth": dict(AUTH_PATTERNS),
    "organization": dict(ORG_PATTERNS),
    "demographics": dict(DEMOGRAPHIC_PATTERNS),
} | {k: dict(v) for k, v in ORG_SENSITIVE_MAP.items()}

# High-level design buckets (documentation / future UI grouping).
SENSITIVITY_BUCKETS: Final[dict[str, tuple[str, ...]]] = {
    "financial": ("credit_card", "bank_account", "ifsc", "upi_id"),
    "personal_identifiers": (
        "aadhaar",
        "pan",
        "passport_india",
        "passport_generic",
        "ssn_us",
        "dob",
    ),
    "authentication": (
        "api_key_generic",
        "jwt_token",
        "aws_access_key",
        "private_key",
        "github_token",
    ),
    "contact_info": ("email", "phone", "indian_phone", "address", "pincode_india"),
    "organization_secrets": (
        "db_connection_string",
        "internal_url",
        "slack_token",
        "firebase_key",
    ),
    "enterprise_client": ("client_id", "portfolio_id", "investment_details"),
    "enterprise_financial": ("transaction_id", "deal_code", "amounts"),
    "enterprise_credentials": (
        "employee_id",
        "vpn_config",
        "internal_password",
        "credential_api_assignment",
    ),
    "enterprise_internal_docs": ("confidential_tag", "meeting_notes", "audit_report"),
    "enterprise_legal": ("case_id", "regulatory_ref", "nda_reference"),
    "enterprise_strategy": ("mna_keywords", "pricing_strategy", "forecast"),
    "enterprise_infrastructure": ("internal_ip", "server_names", "s3_bucket"),
    "toxicity": ("profanity",),
}

# ---------------------------------------------------------------------------
# Masking (extend freely; masker falls back to ``[MASKED]`` for unknown keys)
# ---------------------------------------------------------------------------
MASK_MAP: Final[dict[str, str]] = {
    "aadhaar": "[MASKED_AADHAAR]",
    "pan": "[MASKED_PAN]",
    "ifsc": "[MASKED_IFSC]",
    "bank_account": "[MASKED_BANK_ACCOUNT]",
    "upi_id": "[MASKED_UPI]",
    "indian_phone": "[MASKED_INDIAN_PHONE]",
    "passport_india": "[MASKED_PASSPORT_IN]",
    "email": "[MASKED_EMAIL]",
    "credit_card": "[MASKED_CARD]",
    "ssn_us": "[MASKED_SSN]",
    "passport_generic": "[MASKED_PASSPORT]",
    "phone": "[MASKED_PHONE]",
    "api_key_generic": "[MASKED_API_KEY]",
    "jwt_token": "[MASKED_JWT]",
    "aws_access_key": "[MASKED_AWS_KEY]",
    "private_key": "[MASKED_PRIVATE_KEY]",
    "github_token": "[MASKED_GITHUB_TOKEN]",
    "db_connection_string": "[MASKED_DB_URI]",
    "internal_url": "[MASKED_INTERNAL_URL]",
    "slack_token": "[MASKED_SLACK_TOKEN]",
    "firebase_key": "[MASKED_FIREBASE_KEY]",
    "address": "[MASKED_ADDRESS]",
    "pincode_india": "[MASKED_PINCODE]",
    "dob": "[MASKED_DOB]",
    "ip_address": "[MASKED_IP]",
    "client_id": "[MASKED_CLIENT_ID]",
    "portfolio_id": "[MASKED_PORTFOLIO_ID]",
    "investment_details": "[MASKED_INVESTMENT]",
    "transaction_id": "[MASKED_TXN_ID]",
    "deal_code": "[MASKED_DEAL_CODE]",
    "amounts": "[MASKED_AMOUNT]",
    "employee_id": "[MASKED_EMPLOYEE_ID]",
    "vpn_config": "[MASKED_VPN]",
    "internal_password": "[MASKED_PASSWORD_LINE]",
    "credential_api_assignment": "[MASKED_API_ASSIGNMENT]",
    "confidential_tag": "[MASKED_CONFIDENTIAL]",
    "meeting_notes": "[MASKED_MEETING_NOTES]",
    "audit_report": "[MASKED_AUDIT]",
    "case_id": "[MASKED_CASE_ID]",
    "regulatory_ref": "[MASKED_REG_REF]",
    "nda_reference": "[MASKED_NDA]",
    "mna_keywords": "[MASKED_MNA]",
    "pricing_strategy": "[MASKED_PRICING]",
    "forecast": "[MASKED_FORECAST]",
    "internal_ip": "[MASKED_INTERNAL_IP]",
    "server_names": "[MASKED_SERVER]",
    "s3_bucket": "[MASKED_S3_BUCKET]",
    "custom_keyword": "[MASKED_KEYWORD]",
    "profanity": "[MASKED_PROFANITY]",
}

# ---------------------------------------------------------------------------
# Risk weights (per detector leaf key; used by service risk scorer)
# ---------------------------------------------------------------------------
RISK_WEIGHTS: Final[dict[str, int]] = {
    "api_key_generic": 10,
    "jwt_token": 10,
    "aws_access_key": 10,
    "private_key": 10,
    "github_token": 10,
    "aadhaar": 9,
    "credit_card": 9,
    "pan": 8,
    "bank_account": 8,
    "ifsc": 8,
    "ssn_us": 9,
    "firebase_key": 9,
    "slack_token": 8,
    "db_connection_string": 9,
    "email": 4,
    "phone": 4,
    "indian_phone": 4,
    "upi_id": 5,
    "passport_india": 5,
    "passport_generic": 4,
    "internal_url": 5,
    "address": 3,
    "pincode_india": 2,
    "dob": 4,
    "ip_address": 3,
    "profanity": 2,
    "custom_keyword": 5,
    # Enterprise org (see :data:`ORG_RISK_WEIGHTS` for bucket-level reference).
    "client_id": 10,
    "portfolio_id": 10,
    "investment_details": 9,
    "transaction_id": 9,
    "deal_code": 9,
    "amounts": 9,
    "employee_id": 9,
    "vpn_config": 7,
    "internal_password": 10,
    "credential_api_assignment": 10,
    "confidential_tag": 7,
    "meeting_notes": 6,
    "audit_report": 8,
    "case_id": 8,
    "regulatory_ref": 8,
    "nda_reference": 7,
    "mna_keywords": 9,
    "pricing_strategy": 8,
    "forecast": 8,
    "internal_ip": 7,
    "server_names": 7,
    "s3_bucket": 8,
}

# Enterprise-level bucket weights (documentation; leaf weights in :data:`RISK_WEIGHTS`).
ORG_RISK_WEIGHTS: Final[dict[str, int]] = {
    "api_keys": 10,  # use leaf ``credential_api_assignment``
    "internal_password": 10,
    "mna_keywords": 9,
    "financial_data": 9,  # ``transaction_id``, ``deal_code``, ``amounts``
    "client_data": 10,  # ``client_id``, ``portfolio_id``, ``investment_details``
    "audit_report": 8,
    "internal_ip": 7,
}

# Severity for overlap resolution (higher = wins). Align with sensitivity.
CATEGORY_SEVERITY: Final[dict[str, int]] = {
    "private_key": 100,
    "api_key_generic": 99,
    "jwt_token": 98,
    "aws_access_key": 98,
    "github_token": 97,
    "firebase_key": 96,
    "db_connection_string": 95,
    "slack_token": 94,
    "aadhaar": 93,
    "credit_card": 92,
    "ssn_us": 91,
    "pan": 88,
    "bank_account": 86,
    "ifsc": 85,
    "email": 55,
    "phone": 52,
    "indian_phone": 52,
    "upi_id": 54,
    "passport_india": 45,
    "passport_generic": 38,
    "internal_url": 60,
    "address": 28,
    "pincode_india": 25,
    "dob": 40,
    "ip_address": 35,
    "custom_keyword": 50,
    "profanity": 25,
    "client_id": 96,
    "portfolio_id": 95,
    "investment_details": 90,
    "transaction_id": 91,
    "deal_code": 90,
    "amounts": 88,
    "employee_id": 93,
    "vpn_config": 78,
    "internal_password": 99,
    "credential_api_assignment": 98,
    "confidential_tag": 82,
    "meeting_notes": 75,
    "audit_report": 87,
    "case_id": 86,
    "regulatory_ref": 89,
    "nda_reference": 84,
    "mna_keywords": 92,
    "pricing_strategy": 88,
    "forecast": 86,
    "internal_ip": 84,
    "server_names": 80,
    "s3_bucket": 83,
}

# Words merged with config ``extra_profanity_words``.
TOXIC_WORDS: Final[frozenset[str]] = frozenset(
    {
        "fuck",
        "shit",
        "bitch",
        "asshole",
        "idiot",
        "stupid",
    }
)

# User-supplied additions (empty; use :class:`PromptGuardConfig` at runtime).
CUSTOM_FLAGGED_WORDS: Final[list[str]] = []

# Regex flags per domain (multiline for PEM blocks). Use 0 where case must be strict.
_PATTERN_FLAGS: dict[tuple[str, str], int] = {
    ("auth", "private_key"): re.DOTALL | re.IGNORECASE,
    # PAN / passport IDs are defined with explicit A–Z; IGNORECASE would match common words.
    ("india", "pan"): 0,
    ("india", "passport_india"): 0,
    ("global", "passport_generic"): 0,
    # Long enterprise spans may include newlines in pasted blocks.
    ("internal_documents", "meeting_notes"): re.DOTALL | re.IGNORECASE,
    ("internal_documents", "audit_report"): re.DOTALL | re.IGNORECASE,
    ("credentials", "vpn_config"): re.DOTALL | re.IGNORECASE,
}


def get_pattern_flags(domain: str, leaf_key: str) -> int:
    """
    Return ``re`` flags for a ``(domain, leaf_key)`` pattern.

    Args:
        domain: Top-level key in :data:`SENSITIVE_DATA_MAP`.
        leaf_key: Detector leaf name (e.g. ``private_key``).

    Returns:
        Integer flags for :func:`re.compile`.
    """
    return _PATTERN_FLAGS.get((domain, leaf_key), re.IGNORECASE)


def flatten_sensitive_data_map(
    data_map: dict[str, dict[str, str]] | None = None,
) -> list[tuple[str, str, str, int]]:
    """
    Flatten :data:`SENSITIVE_DATA_MAP` into rows ``(domain, leaf_key, pattern, flags)``.

    Args:
        data_map: Map to flatten; default :data:`SENSITIVE_DATA_MAP`.

    Returns:
        List of tuples for compilation in the detector.
    """
    m = data_map if data_map is not None else SENSITIVE_DATA_MAP
    rows: list[tuple[str, str, str, int]] = []
    for domain, inner in m.items():
        for leaf_key, pattern in inner.items():
            rows.append((domain, leaf_key, pattern, get_pattern_flags(domain, leaf_key)))
    return rows


def detect_all(
    text: str,
    patterns_map: dict[str, dict[str, str]],
) -> dict[str, dict[str, list[str]]]:
    """
    Run simple non-overlapping regex discovery (illustrative / debugging helper).

    Does not apply validators, masking, or confidence — use
    :class:`~prompt_guard.detector.sensitive_detector.SensitiveDetector` for production.

    Args:
        text: Input string.
        patterns_map: Nested map ``domain -> { leaf_key -> pattern }``.

    Returns:
        ``findings[domain][leaf_key] = [matches...]`` (full span matches, may overlap).
    """
    findings: dict[str, dict[str, list[str]]] = {}
    for domain, patterns in patterns_map.items():
        for key, pattern in patterns.items():
            try:
                rx = re.compile(pattern, get_pattern_flags(domain, key))
            except re.error:
                continue
            found: list[str] = []
            for m in rx.finditer(text):
                found.append(m.group(0))
            if found:
                findings.setdefault(domain, {})[key] = found
    return findings

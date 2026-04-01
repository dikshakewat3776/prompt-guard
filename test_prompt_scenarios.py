"""
Run all canned prompts through ``analyze_prompt`` and print DB-shaped output.

Matches SQLite tables ``aggregates`` and ``request_log`` (same schema as
:class:`~prompt_guard.analytics.tracker.AnalyticsTracker`).

Usage::

    python tests/test_prompt_scenarios.py          # print DB tables + run tests
    pytest tests/test_prompt_scenarios.py -v       # pytest only (builds its own DB)
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from api.service import analyze_prompt
from analytics.tracker import AnalyticsTracker
from config import PromptGuardConfig

# Populated when running as ``python tests/test_prompt_scenarios.py`` (print + test).
_AUDIT_FIXTURE: tuple[Path, list[tuple], list[tuple]] | None = None


# (scenario_id, prompt_text, expected_risk_score)
SCENARIOS: list[tuple[str, str, int]] = [
    (
        "1_clean_code_review",
        "Can you review this pull request and suggest improvements for error handling in the payment retry logic?",
        0,
    ),
    (
        "2_clean_product_discussion",
        "We need to design a better onboarding flow that reduces drop-offs during the signup process.",
        0,
    ),
    (
        "3_email_in_sentence",
        "Hey, if you need clarification on the API contract, just drop a mail to vivek.menon@company.in and he’ll help you out.",
        4,
    ),
    (
        "4_phone_in_support_context",
        "The delivery agent couldn’t reach me, please call me on +91 9823456789 to coordinate the package drop.",
        4,
    ),
    (
        "5_email_phone_realistic",
        "You can contact our regional manager at neha@retailco.in or call her directly at +91-9123456780 for urgent approvals.",
        8,
    ),
    (
        "6_pan_customer_support",
        "Hi, I’m submitting my PAN (ABCDE1234F) for verification, please update my account status once it’s validated.",
        8,
    ),
    (
        "7_aadhaar_kyc_flow",
        "For completing KYC, I’ve uploaded my Aadhaar number 5678 1234 9876 along with the required documents.",
        9,
    ),
    (
        "8_pan_aadhaar_financial",
        "My PAN is AAAPL1234C and Aadhaar is 4321 8765 2109, both are linked to my bank account for tax filing purposes.",
        17,
    ),
    (
        "9_bank_transfer_request",
        "Please process the refund to my account number 123456789876 with IFSC ICIC0004321 by end of day.",
        17,
    ),
    (
        "10_credit_card_checkout",
        "You can charge the amount to my card 4111111111111111 exp 10/28, let me know once the payment goes through.",
        9,
    ),
    (
        "11_credit_card_full_details",
        "Use my corporate card 5555444433331111 exp 09/27 CVV 456 for booking the flight tickets.",
        12,
    ),
    (
        "12_api_key_shared_in_chat",
        "For testing in staging, you can temporarily use this API key: sk-test-1234567890abcdef123456.",
        0,
    ),
    (
        "13_jwt_in_debugging",
        "I’m attaching the bearer token here: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz.abc so you can debug the auth issue.",
        10,
    ),
    (
        "14_password_shared",
        "You can log into the admin panel using username admin and password Admin@123 until we reset access.",
        5,
    ),
    (
        "15_enterprise_sensitive_deal",
        "This is confidential: CLIENT-5566 acquisition deal details, internal case CASE-77, password is Merge@2026, do not share outside leadership.",
        44,
    ),
    (
        "16_internal_project_leak",
        "The FalconX project is still under stealth, please don’t mention 'falconx-internal-beta' outside this channel.",
        0,
    ),
    (
        "17_invoice_payment_realistic",
        "Kindly release INR 1,25,000 to vendor account 998877665544 with IFSC HDFC0001122 against invoice INV-9087.",
        26,
    ),
    (
        "18_mixed_sensitive_real_world",
        "Please contact me at arjun@gmail.com, my Aadhaar is 2345 6789 0123 and you can use API key sk-abc123456789 for testing.",
        13,
    ),
    (
        "19_profanity_dev_context",
        "This deployment is completely broken and the API responses are slow as hell, we need to fix this urgently.",
        2,
    ),
    (
        "20_profanity_with_pressure",
        "The client is pissed because the dashboard is still not loading, can someone fix this damn issue today?",
        2,
    ),
]


def _dump_db_tables(conn: sqlite3.Connection) -> tuple[list[tuple[str, int]], list[tuple]]:
    """Return ``aggregates`` and ``request_log`` rows."""
    agg = conn.execute("SELECT key, value FROM aggregates ORDER BY key").fetchall()
    req = conn.execute(
        "SELECT id, created_at, prompt_hash, risk_score, masked_spans, findings_json "
        "FROM request_log ORDER BY id"
    ).fetchall()
    return agg, req


def run_audit_to_temp_db() -> tuple[Path, list[tuple[str, int]], list[tuple]]:
    """
    Process all scenarios with one tracker and return path + table snapshots.

    Returns:
        ``(db_path, aggregates_rows, request_log_rows)``
    """
    fd, path_str = tempfile.mkstemp(prefix="prompt_guard_audit_", suffix=".db")
    os.close(fd)
    path = Path(path_str)
    cfg = PromptGuardConfig(
        logging_enabled=False,
        sqlite_path=path,
        analytics_enabled=True,
    )
    tracker = AnalyticsTracker(config=cfg)

    for _sid, prompt, _ in SCENARIOS:
        analyze_prompt(prompt, config=cfg, tracker=tracker)

    conn = sqlite3.connect(str(path))
    try:
        agg, req = _dump_db_tables(conn)
    finally:
        conn.close()
    return path, agg, req


def print_db_report(agg: list[tuple], req: list[tuple]) -> None:
    """Print ``aggregates`` and ``request_log`` like a SQL browser."""
    print("\n=== table: aggregates (key, value) ===")
    for k, v in agg:
        print(f"{k}\t{v}")

    print("\n=== table: request_log ===")
    print("id | prompt_hash (trunc) | risk_score | masked_spans | findings_json")
    for row in req:
        rid, _created, ph, risk, masked, fj = row
        ph_short = (ph[:18] + "…") if ph and len(ph) > 18 else ph
        print(f"{rid} | {ph_short} | {risk} | {masked} | {fj}")


class PromptScenarioAuditTests(unittest.TestCase):
    """Assert risk scores and JSON category counts per ``request_log`` row."""

    @classmethod
    def setUpClass(cls) -> None:
        global _AUDIT_FIXTURE
        if _AUDIT_FIXTURE is not None:
            cls._path, cls._agg, cls._req = _AUDIT_FIXTURE
        else:
            cls._path, cls._agg, cls._req = run_audit_to_temp_db()

    @classmethod
    def tearDownClass(cls) -> None:
        p = getattr(cls, "_path", None)
        if p is not None and Path(p).exists() and _AUDIT_FIXTURE is None:
            Path(p).unlink(missing_ok=True)

    def test_row_count(self) -> None:
        self.assertEqual(len(SCENARIOS), len(self._req))

    def test_risk_scores_match_expected(self) -> None:
        # Report every mismatch in one failure (unittest would otherwise stop at the first row).
        mismatches: list[str] = []
        for i, (sid, _prompt, expected_risk) in enumerate(SCENARIOS):
            risk = self._req[i][3]
            if risk != expected_risk:
                mismatches.append(f"{sid}: expected {expected_risk}, got {risk}")
        self.assertFalse(
            mismatches,
            "risk_score mismatches:\n" + "\n".join(mismatches),
        )

    def test_findings_json_maps_categories_to_counts(self) -> None:
        for row in self._req:
            data = json.loads(row[5])
            self.assertIsInstance(data, dict)
            for _k, v in data.items():
                self.assertIsInstance(v, int)


if __name__ == "__main__":
    import sys

    _AUDIT_FIXTURE = run_audit_to_temp_db()
    print(f"SQLite file: {_AUDIT_FIXTURE[0]}", flush=True)
    print_db_report(_AUDIT_FIXTURE[1], _AUDIT_FIXTURE[2])
    print("\n=== unittest (assert risk + DB JSON shape) ===", flush=True)
    try:
        unittest.main(argv=[sys.argv[0]], verbosity=2, exit=False)
    finally:
        p = _AUDIT_FIXTURE[0]
        _AUDIT_FIXTURE = None
        p.unlink(missing_ok=True)

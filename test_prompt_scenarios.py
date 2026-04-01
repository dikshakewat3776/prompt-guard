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

from prompt_guard.api.service import analyze_prompt
from prompt_guard.analytics.tracker import AnalyticsTracker
from prompt_guard.config import PromptGuardConfig

# Populated when running as ``python tests/test_prompt_scenarios.py`` (print + test).
_AUDIT_FIXTURE: tuple[Path, list[tuple], list[tuple]] | None = None


# (scenario_id, prompt_text, expected_risk_score)
SCENARIOS: list[tuple[str, str, int]] = [
    (
        "1_clean",
        "Refactor the login handler to use async/await and add unit tests.",
        0,
    ),
    (
        "2_email",
        "Contact me at jane.doe@company.com for the API review.",
        4,
    ),
    (
        "3_email_phone",
        "Reach me at +1 (415) 555-0199 or sarah@acme.io.",
        8,
    ),
    (
        "4_india_pan_ifsc",
        "PAN ABCDE1234F bank IFSC HDFC0001234 for the refund.",
        16,
    ),
    (
        "5_api_key",
        "Use this key in dev only: sk-1234567890123456789012345678",
        10,
    ),
    (
        "6_jwt",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XggTsoPtgdQ0Qf_obqQ3k",
        10,
    ),
    (
        "7_profanity",
        "This bug is shit and blocking the release.",
        2,
    ),
    (
        "8_enterprise",
        "CLIENT-9001 TXN-123456789 password: SuperSecret99 merger acquisition CASE-42",
        53,
    ),
    (
        "9_credit_card",
        "Charge 4242424242424242 exp 12/28 for the invoice USD 1,250.00",
        18,
    ),
    (
        "10_mixed",
        "Email a@b.com Aadhaar 2345 2345 2342 sk-1234567890123456789012345678",
        23,
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
        for i, (sid, _prompt, expected_risk) in enumerate(SCENARIOS):
            risk = self._req[i][3]
            self.assertEqual(
                expected_risk,
                risk,
                msg=f"{sid}: expected risk {expected_risk}, got {risk}",
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

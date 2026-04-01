"""
SQLite-backed analytics with thread-safe updates and aggregate queries.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from prompt_guard.analytics.models import AnalyticsSnapshot
from prompt_guard.config import PromptGuardConfig


def _utc_now() -> datetime:
    """Return current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


class AnalyticsTracker:
    """
    Persists rolling counters and optional per-request audit rows.

    All public methods are synchronized with an internal :class:`threading.RLock`
    for safe concurrent use from multiple worker threads.

    Args:
        config: Configuration controlling DB path and whether writes occur.
        connection: Optional existing SQLite connection (mainly for tests).
    """

    def __init__(
        self,
        config: PromptGuardConfig | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        self._config = config or PromptGuardConfig()
        self._lock = threading.RLock()
        self._conn = connection
        self._owns_connection = connection is None

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            path = self._config.sqlite_path
            self._conn = sqlite3.connect(
                str(path) if path != ":memory:" else ":memory:",
                check_same_thread=False,
            )
            # WAL improves concurrent readers; not used for :memory: databases.
            if str(path) != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL;")
            self._init_schema()
        return self._conn

    def _init_schema(self) -> None:
        conn = self._get_connection()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS aggregates (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                prompt_hash TEXT,
                risk_score INTEGER NOT NULL,
                masked_spans INTEGER NOT NULL,
                findings_json TEXT NOT NULL
            );
            """
        )
        conn.commit()

    def record_prompt(
        self,
        *,
        prompt_hash: str,
        risk_score: int,
        category_counts: dict[str, int],
        masked_spans: int,
    ) -> None:
        """
        Increment global counters and optionally append an audit row.

        Args:
            prompt_hash: Hash of original prompt (not raw text).
            risk_score: Computed risk score for this request.
            category_counts: Per-category hit counts for this prompt.
            masked_spans: Number of masked regions.
        """
        if not self._config.analytics_enabled:
            return

        with self._lock:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO aggregates(key, value) VALUES('total_prompts', 1) "
                "ON CONFLICT(key) DO UPDATE SET value = value + 1"
            )
            total_sensitive = sum(category_counts.values())
            cur.execute(
                "INSERT INTO aggregates(key, value) VALUES('total_sensitive_items', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = value + ?",
                (total_sensitive, total_sensitive),
            )
            cur.execute(
                "INSERT INTO aggregates(key, value) VALUES('masked_token_count', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = value + ?",
                (masked_spans, masked_spans),
            )
            for cat, n in category_counts.items():
                key = f"category:{cat}"
                cur.execute(
                    "INSERT INTO aggregates(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = value + ?",
                    (key, n, n),
                )
            cur.execute(
                """
                INSERT INTO request_log(created_at, prompt_hash, risk_score, masked_spans, findings_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    _utc_now().isoformat(),
                    prompt_hash,
                    risk_score,
                    masked_spans,
                    json.dumps(category_counts),
                ),
            )
            conn.commit()

    def get_stats(self) -> AnalyticsSnapshot:
        """
        Load current aggregate statistics from SQLite.

        Returns:
            :class:`AnalyticsSnapshot` with lifetime counters.
        """
        with self._lock:
            conn = self._get_connection()
            cur = conn.execute("SELECT key, value FROM aggregates")
            rows = dict(cur.fetchall())
            total_prompts = int(rows.get("total_prompts", 0))
            total_sensitive = int(rows.get("total_sensitive_items", 0))
            masked = int(rows.get("masked_token_count", 0))
            counts_by_category: dict[str, int] = {}
            for k, v in rows.items():
                if k.startswith("cat:"):
                    counts_by_category[k[4:]] = int(v)
            snap = AnalyticsSnapshot(
                total_prompts=total_prompts,
                total_sensitive_items=total_sensitive,
                masked_token_count=masked,
                counts_by_category=counts_by_category,
                last_updated=_utc_now(),
            )
            return snap

    def close(self) -> None:
        """
        Close the underlying SQLite connection if owned by this tracker.
        """
        with self._lock:
            if self._owns_connection and self._conn is not None:
                self._conn.close()
                self._conn = None


# Module-level default tracker for simple ``analyze_prompt`` usage.
_default_tracker: AnalyticsTracker | None = None
_default_tracker_lock = threading.Lock()


def get_default_tracker(config: PromptGuardConfig | None = None) -> AnalyticsTracker:
    """
    Return a process-wide :class:`AnalyticsTracker`, creating it on first use.

    Args:
        config: Used only when the tracker has not yet been created.

    Returns:
        Shared tracker instance.
    """
    global _default_tracker
    with _default_tracker_lock:
        if _default_tracker is None:
            _default_tracker = AnalyticsTracker(config=config)
        return _default_tracker


def get_stats() -> dict[str, object]:
    """
    Return aggregate statistics from the process-wide default tracker.

    This is a convenience wrapper around :meth:`AnalyticsTracker.get_stats`
    returning a JSON-friendly dictionary.

    Returns:
        Same structure as :meth:`prompt_guard.analytics.models.AnalyticsSnapshot.to_dict`.
    """
    return get_default_tracker().get_stats().to_dict()

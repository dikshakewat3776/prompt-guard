"""
Logging setup with optional file output, rotation, and debug verbosity.

This module configures the ``prompt_guard`` named logger used across the package.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import Lock
from typing import Final

_CONFIGURE_LOCK: Final[Lock] = Lock()
_CONFIGURED: bool = False

DEFAULT_LOG_FILENAME: Final[str] = "prompt_guard.log"
DEFAULT_MAX_BYTES: Final[int] = 5 * 1024 * 1024  # 5 MiB
DEFAULT_BACKUP_COUNT: Final[int] = 5


def setup_logging(
    *,
    enabled: bool = True,
    debug: bool = False,
    log_file: str | Path | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
    force_reconfigure: bool = False,
) -> logging.Logger:
    """
    Configure the ``prompt_guard`` logger with console and optional rotating file.

    Thread-safe: concurrent calls serialize on a module lock. Idempotent unless
    ``force_reconfigure`` is True.

    Args:
        enabled: If False, sets level to CRITICAL and removes handlers (quiet).
        debug: If True, uses DEBUG level; otherwise INFO.
        log_file: Path for rotating file handler. Defaults to ``prompt_guard.log``
            in the current working directory if None and ``enabled`` is True.
        max_bytes: Maximum size of each log file before rotation.
        backup_count: Number of rotated backups to retain.
        force_reconfigure: Drop existing handlers and re-apply settings.

    Returns:
        The configured :class:`logging.Logger` instance.
    """
    global _CONFIGURED

    with _CONFIGURE_LOCK:
        logger = logging.getLogger("prompt_guard")
        logger.propagate = False

        if force_reconfigure:
            for h in list(logger.handlers):
                logger.removeHandler(h)
                h.close()
            _CONFIGURED = False

        # Quiet mode: drop handlers so a later ``enabled=True`` call can reattach.
        if not enabled:
            for h in list(logger.handlers):
                logger.removeHandler(h)
                h.close()
            logger.setLevel(logging.CRITICAL)
            _CONFIGURED = False
            return logger

        if _CONFIGURED and not force_reconfigure:
            return logger

        level = logging.DEBUG if debug else logging.INFO
        logger.setLevel(level)

        fmt = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Console: stderr so stdout stays clean for CLI piping.
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(level)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

        path = Path(log_file) if log_file else Path.cwd() / DEFAULT_LOG_FILENAME
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fh = RotatingFileHandler(
                path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            fh.setLevel(level)
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except OSError as exc:
            logger.warning("Could not attach file handler to %s: %s", path, exc)

        _CONFIGURED = True
        return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Return a child logger under the ``prompt_guard`` namespace.

    Args:
        name: Optional suffix (e.g. ``prompt_guard.api``).

    Returns:
        Configured :class:`logging.Logger`.
    """
    base = "prompt_guard"
    full = f"{base}.{name}" if name else base
    return logging.getLogger(full)

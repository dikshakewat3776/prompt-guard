"""
Command-line interface for quick local checks.

Usage::

    prompt-guard "My email is user@example.com"
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from prompt_guard.api.service import analyze_prompt
from prompt_guard.config import PromptGuardConfig


def _build_parser() -> argparse.ArgumentParser:
    """
    Construct the CLI argument parser.

    Returns:
        Configured :class:`argparse.ArgumentParser`.
    """
    p = argparse.ArgumentParser(
        prog="prompt-guard",
        description="Analyze a prompt for sensitive data and profanity (non-blocking).",
    )
    p.add_argument(
        "text",
        nargs="?",
        default=None,
        help="Prompt text to analyze (or read from stdin if omitted).",
    )
    p.add_argument(
        "--no-log",
        action="store_true",
        help="Disable package logging side effects.",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    p.add_argument(
        "--sqlite",
        default=None,
        help="Path to SQLite analytics database (overrides default file).",
    )
    p.add_argument(
        "--compact",
        action="store_true",
        help="Print minified JSON on one line.",
    )
    return p


def main(argv: Sequence[str] | None = None) -> int:
    """
    CLI entry point: run analysis and print JSON to stdout.

    Args:
        argv: Argument list (defaults to :data:`sys.argv`).

    Returns:
        Process exit code (0 on success).
    """
    args = _build_parser().parse_args(list(argv) if argv is not None else None)

    text = args.text
    if text is None:
        text = sys.stdin.read()

    kwargs: dict[str, Any] = {
        "logging_enabled": not args.no_log,
        "debug": args.debug,
    }
    if args.sqlite is not None:
        kwargs["sqlite_path"] = args.sqlite
    cfg = PromptGuardConfig(**kwargs)

    result: dict[str, Any] = analyze_prompt(text, config=cfg)
    indent = None if args.compact else 2
    print(json.dumps(result, ensure_ascii=False, indent=indent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

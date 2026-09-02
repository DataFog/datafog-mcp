"""
CLI entry point for the datafog-mcp.
"""

from __future__ import annotations

import argparse
import os
import subprocess

from . import __version__
from .paths import (
    ALLOWED_ROOTS_VAR,
    DENIED_DIR_NAMES,
    ROOTS_FILE,
    ROOTS_TEMPLATE,
    policy,
)


def _build_parser() -> argparse.ArgumentParser:
    """
    Construct the argument parser.

    Returns:
      A parser carrying the serve and roots subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="datafog-mcp",
        description="Local PII detection and redaction for MCP clients",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="Run the tool server (default)")

    roots = sub.add_parser("roots", help="Show the directories datafog may read and write")
    roots.add_argument("--edit", action="store_true", help="Open the roots file in $EDITOR")

    return parser


def _show_roots() -> None:
    """
    Print the roots in force, their source, and what is always refused.
    """
    current = policy()

    print(f"Allowed roots (from {current.source}):")
    for root in current.roots:
        print(f"  {root}")
    print()

    print(f"Config file: {ROOTS_FILE}")
    if not ROOTS_FILE.is_file():
        print("  not created yet - run: datafog-mcp roots --edit")
    if os.environ.get(ALLOWED_ROOTS_VAR, "").strip():
        print(f"  overridden by ${ALLOWED_ROOTS_VAR}; edits have no effect")
    print()

    print("Always refused, even inside a root: " + ", ".join(sorted(DENIED_DIR_NAMES)))


def _edit_roots() -> None:
    """
    Open the roots file in the user's editor, creating it if absent.
    """
    if not ROOTS_FILE.is_file():
        ROOTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        ROOTS_FILE.write_text(ROOTS_TEMPLATE, encoding="utf-8")

    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano"
    subprocess.run([editor, str(ROOTS_FILE)], check=False)


def main() -> None:
    """
    Console entry point: `datafog-mcp`.
    """
    args = _build_parser().parse_args()

    if args.command == "roots":
        if args.edit:
            _edit_roots()
        else:
            _show_roots()
        return

    from .server import run_server

    run_server()


if __name__ == "__main__":
    main()

"""
CLI entry point for the datafog-mcp.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess

from . import __version__
from .paths import (
    ALLOWED_ROOTS_VAR,
    DENIED_DIR_NAMES,
    ROOTS_FILE,
    ROOTS_TEMPLATE,
    PolicyError,
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

    keys = sub.add_parser("keys", help="Manage local pseudonymization keys")
    key_commands = keys.add_subparsers(dest="key_command", required=True)
    create_key = key_commands.add_parser("create", help="Generate a key for a configured scope")
    create_key.add_argument("scope", help="Scope name from policy.toml")

    return parser


def _show_roots() -> None:
    """
    Print the roots in force, their source, and what is always refused.
    """
    try:
        current = policy()
    except PolicyError as exc:
        raise SystemExit(f"datafog-mcp: {exc}") from None

    print(f"Allowed roots (from {current.source}):")
    for root in current.roots:
        print(f"  {root}")
    if not current.roots:
        print("  none - every path is refused")
    print()

    print(f"Config file: {ROOTS_FILE}")
    if not ROOTS_FILE.is_file():
        print("  not created yet - run: datafog-mcp roots --edit")
    if os.environ.get(ALLOWED_ROOTS_VAR) is not None:
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
    command = [*shlex.split(editor), str(ROOTS_FILE)]

    try:
        subprocess.run(command, check=False)
    except FileNotFoundError:
        raise SystemExit(f"datafog-mcp: editor not found: {command[0]}") from None


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

    if args.command == "keys":
        from .keys import KeyStorageError, generate_scope_key
        from .policy import PolicyError as LocalPolicyError
        from .policy import load_policy

        try:
            current_policy = load_policy()
            scope = current_policy.pseudonymization_scopes.get(args.scope)
            if scope is None:
                raise KeyStorageError("Scope is not configured in the local policy.")
            generate_scope_key(scope)
        except (KeyStorageError, LocalPolicyError) as exc:
            raise SystemExit(f"datafog-mcp: {exc}") from None
        print("Pseudonymization key created. Preserve it to keep future outputs joinable.")
        return

    from .server import run_server

    run_server()


if __name__ == "__main__":
    main()

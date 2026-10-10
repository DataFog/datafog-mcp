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
from .policy import POLICY_FILE, POLICY_TEMPLATE, OutputPolicyError, load_output_policy


def _build_parser() -> argparse.ArgumentParser:
    """
    Construct the argument parser.

    Returns:
      A parser carrying the serve, roots, and policy subcommands.
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

    copies = sub.add_parser("policy", help="Show owner scanning, copy, and workflow settings")
    copies.add_argument("--edit", action="store_true", help="Open policy.toml in $EDITOR")

    keys = sub.add_parser("keys", help="Explicit local pseudonymization key setup")
    commands = keys.add_subparsers(dest="key_command", required=True)
    create = commands.add_parser(
        "create", help="Create a configured scope key without replacing it"
    )
    create.add_argument("scope", help="Scope name configured in policy.toml")

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

    if args.command == "keys":
        from .keys import KeyStorageError, generate_scope_key

        try:
            current = load_output_policy()
            scope = current.pseudonym_scopes.get(args.scope)
            if scope is None:
                raise KeyStorageError("Pseudonymization scope is not configured.")
            generate_scope_key(scope)
        except (OutputPolicyError, KeyStorageError) as exc:
            raise SystemExit(f"datafog-mcp: {exc}") from None
        print("Pseudonymization key created. Preserve it to keep future outputs joinable.")
        return

    if args.command == "policy":
        if args.edit:
            _edit_policy()
        else:
            try:
                current = load_output_policy()
            except OutputPolicyError as exc:
                raise SystemExit(f"datafog-mcp: {exc}") from None
            print(f"Config file: {POLICY_FILE}")
            print(f"Copy destination: {current.directory or 'beside the input'}")
            print("Files to scan before reading (within allowed roots):")
            for folder in current.scope_folders:
                status = " (missing; inactive)" if folder in current.missing_scope_folders else ""
                print(f"  {folder}{status}")
            if not current.scope_folders:
                print("  all allowed directories")
            for warning in current.warnings:
                print(f"Warning: {warning}")
            print("Extensions: " + (", ".join(current.scope_extensions) or "all"))
            print(f"On findings: {current.on_findings} (advisory)")
            print(f"Suggested transformation: {current.transform_strategy}")
            print("Pseudonymization scopes: " + (", ".join(current.pseudonym_scopes) or "none"))
            if current.pseudonym_scope:
                print(f"Suggested pseudonym scope: {current.pseudonym_scope}")
            print(
                "Exact allowlist counts: "
                + ", ".join(f"{kind}={len(values)}" for kind, values in current.allow_exact.items())
            )
        return

    if args.command == "roots":
        if args.edit:
            _edit_roots()
        else:
            _show_roots()
        return

    from .server import run_server

    run_server()


def _edit_policy() -> None:
    """Create a private policy template if absent, then open the owner's editor."""
    if os.path.lexists(POLICY_FILE):
        if not POLICY_FILE.is_file():
            raise SystemExit("datafog-mcp: output policy is not a regular file")
    else:
        POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(POLICY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(POLICY_TEMPLATE)
        except OSError:
            raise SystemExit("datafog-mcp: cannot create output policy") from None
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano"
    command = [*shlex.split(editor), str(POLICY_FILE)]
    try:
        subprocess.run(command, check=False)
    except FileNotFoundError:
        raise SystemExit(f"datafog-mcp: editor not found: {command[0]}") from None


if __name__ == "__main__":
    main()

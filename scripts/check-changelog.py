"""Require a changelog addition or explicit exemption across a complete PR."""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE)


def exempt(event_path: str) -> bool:
    event = json.loads(Path(event_path).read_text())
    pr = event["pull_request"]
    if not any(label["name"] == "no-changelog" for label in pr["labels"]):
        return False
    reason = re.search(r"^Changelog exemption:[ \t]*([^\r\n]+)", pr.get("body") or "", re.MULTILINE)
    if reason is None or not reason.group(1).strip():
        raise ValueError(
            "The no-changelog label requires 'Changelog exemption: <reason>' in the PR body."
        )
    print(f"Changelog exemption: {reason.group(1).strip()}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=os.environ.get("CHANGELOG_BASE", "origin/main"))
    parser.add_argument(
        "--event", help="GitHub pull_request event JSON; enables labeled exemptions"
    )
    args = parser.parse_args()
    try:
        base = git("merge-base", args.base, "HEAD").strip()
        comparison = [base, "HEAD"]
        if not git("diff", "--name-only", *comparison).strip():
            print("No changes to check.")
            return 0
        if args.event and exempt(args.event):
            return 0
        patch = git("diff", "--no-ext-diff", "--unified=0", *comparison, "--", "CHANGELOG.md")
        additions = [
            line[1:].strip()
            for line in patch.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        if any(line and not line.startswith("#") and line != "-" for line in additions):
            print("Changelog addition found.")
            return 0
        print(
            "Add a substantive entry to CHANGELOG.md for this PR. For changes with no user-facing "
            "effect, see CONTRIBUTING.md for the explicit exemption process.",
            file=sys.stderr,
        )
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Cannot validate changelog: {error}", file=sys.stderr)
        print("Fetch the PR base, or set CHANGELOG_BASE to its local ref.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

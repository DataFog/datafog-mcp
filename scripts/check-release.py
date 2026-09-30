"""
Refuse to release when the tag, the version, and the changelog disagree.

Run by the release workflow before anything is built. On a tag push, the tag
must be v<version> and CHANGELOG.md must hold a dated entry for that version,
so release notes are written before the release rather than after. Any other
run, such as a TestPyPI rehearsal, needs only an entry for the version, which
may not be dated yet.

Needs Python 3.11 or later for tomllib; the workflow runs it on the runner's
system Python.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    """
    Check the release ref and notes, exiting non-zero on any mismatch.
    """
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    tagged = os.environ.get("GITHUB_REF_TYPE") == "tag"

    if tagged:
        expected = f"v{version}"
        actual = os.environ.get("GITHUB_REF_NAME")
        if actual != expected:
            sys.exit(
                f"tag {actual!r} does not match the pyproject.toml version; expected {expected!r}"
            )

    entry = rf"^## \[{re.escape(version)}\]"
    if tagged:
        entry += r" - \d{4}-\d{2}-\d{2}$"
    if not re.search(entry, changelog, re.MULTILINE):
        kind = "dated entry" if tagged else "entry"
        sys.exit(f"CHANGELOG.md has no {kind} for {version}; add '## [{version}] - YYYY-MM-DD'")

    print(f"release {version}: tag, version, and changelog agree")


if __name__ == "__main__":
    main()

"""
Refuse to release when the tag, the version, and the changelog disagree.

Run by the release workflow before anything is built. On a tag push, the tag
must be v<version> and CHANGELOG.md must hold a dated entry for that version,
so release notes are written before the release rather than after. Any other
run, such as a TestPyPI rehearsal, needs only an entry for the version, which
may not be dated yet.

When run in GitHub Actions, it also writes the version to $GITHUB_OUTPUT, so
later jobs test exactly the version checked here without reading
pyproject.toml themselves.

Needs Python 3.11 or later for tomllib. The workflow runs it with uv on 3.12
rather than whichever python3 is on PATH.
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

    # Written to $GITHUB_OUTPUT below, where a newline could inject outputs
    if not re.fullmatch(r"[0-9A-Za-z.+!_-]+", version):
        sys.exit(f"pyproject.toml version {version!r} is not a plain version string")

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

    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"version={version}\n")

    print(f"release {version}: tag, version, and changelog agree")


if __name__ == "__main__":
    main()

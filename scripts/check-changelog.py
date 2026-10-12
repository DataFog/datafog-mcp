"""Require a changelog addition or explicit exemption across a complete PR."""

import argparse
import copy
import importlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

BOT_AUTHORS = frozenset({"dependabot[bot]", "renovate[bot]", "pre-commit-ci[bot]"})
DEV_TOOLS = frozenset({"ruff", "mypy", "pyright", "pytest", "coverage"})


def toml(text: str) -> dict[str, Any]:
    module = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")
    return module.loads(text)


def runtime_project(project: dict[str, Any]) -> dict[str, Any]:
    """Remove only known contributor settings from the comparison."""
    result = copy.deepcopy(project)
    groups = result.get("dependency-groups", {})
    for group in ("dev", "ci"):
        groups.pop(group, None)
    if not groups:
        result.pop("dependency-groups", None)
    settings = result.get("tool", {})
    for name in DEV_TOOLS:
        settings.pop(name, None)
    if not settings:
        result.pop("tool", None)
    return result


def runtime_lock(lock: dict[str, Any], project: dict[str, Any]) -> dict[str, Any]:
    """Compare every resolved runtime dependency, including transitive/optional ones."""

    def canonical(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    root = canonical(project["project"]["name"])
    packages = lock["package"]
    pending = [root]
    selected: dict[str, list[dict[str, Any]]] = {}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        records = [copy.deepcopy(p) for p in packages if canonical(p["name"]) == name]
        if not records:
            raise ValueError(f"Missing runtime package in uv.lock: {name}")
        for record in records:
            if name == root:
                record.pop("dev-dependencies", None)
                record.get("metadata", {}).pop("requires-dev", None)
            dependencies = list(record.get("dependencies", []))
            for optional in record.get("optional-dependencies", {}).values():
                dependencies.extend(optional)
            pending.extend(canonical(d["name"]) for d in dependencies)
        selected[name] = sorted(records, key=lambda p: json.dumps(p, sort_keys=True))
    return {
        "settings": {k: v for k, v in lock.items() if k != "package"},
        "packages": selected,
    }


def bot_exempt(pr: dict[str, Any], base: str, paths: list[str]) -> bool:
    try:
        return _bot_exempt(pr, base, paths)
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError, TypeError):
        # Unclassifiable bot changes still have the ordinary entry/exemption path.
        return False


def _bot_exempt(pr: dict[str, Any], base: str, paths: list[str]) -> bool:
    """Exempt recognized bot updates only when the runtime is unchanged."""
    author = pr.get("user", {})
    if author.get("type") != "Bot" or author.get("login") not in BOT_AUTHORS:
        return False
    for path in paths:
        workflow = path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))
        if path not in {"pyproject.toml", "uv.lock", ".pre-commit-config.yaml"} and not workflow:
            return False
        before = git("show", f"{base}:{path}")
        after = git("show", f"HEAD:{path}")
        if path == "pyproject.toml":
            if runtime_project(toml(before)) != runtime_project(toml(after)):
                return False
        elif path == "uv.lock":
            old_project = toml(git("show", f"{base}:pyproject.toml"))
            new_project = toml(git("show", "HEAD:pyproject.toml"))
            if runtime_lock(toml(before), old_project) != runtime_lock(toml(after), new_project):
                return False
        elif workflow:
            # Only action ref changes qualify, not arbitrary workflow behavior changes.
            pattern = (
                r"(?m)^(\s*(?:-\s*)?uses:\s*[\"\x27]?[^\s@]+@)[^\s\"\x27]+[\"\x27]?[ \t]*(?:#.*)?$"
            )
            if re.sub(pattern, r"\1<ref>", before) != re.sub(pattern, r"\1<ref>", after):
                return False
        elif path == ".pre-commit-config.yaml":
            pattern = r"(?m)^(\s*rev:\s*).+$"
            if re.sub(pattern, r"\1<ref>", before) != re.sub(pattern, r"\1<ref>", after):
                return False
    print("Automatic changelog exemption: recognized bot updates contributor tooling only.")
    return True


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE)


def exempt(event_path: str, base: str, paths: list[str]) -> bool:
    event = json.loads(Path(event_path).read_text())
    pr = event["pull_request"]
    if not any(label["name"] == "no-changelog" for label in pr["labels"]):
        return bot_exempt(pr, base, paths)
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
        paths = git("diff", "--name-only", "-z", *comparison).strip("\0").split("\0")
        if paths == [""]:
            print("No changes to check.")
            return 0
        if args.event and exempt(args.event, base, paths):
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
    except (
        subprocess.CalledProcessError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        ImportError,
    ) as error:
        print(f"Cannot validate changelog: {error}", file=sys.stderr)
        print("Fetch the PR base, or set CHANGELOG_BASE to its local ref.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

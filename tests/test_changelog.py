"""Exercise the contributor policy against real branch and index changes."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

CHECKER = Path(__file__).resolve().parents[1] / "scripts" / "check-changelog.py"


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-b", "main")
    git(tmp_path, "config", "user.email", "test@example.com")
    git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n\nExisting entry.\n")
    (tmp_path / "behavior.txt").write_text("original\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-m", "base")
    git(tmp_path, "switch", "-c", "feature")
    return tmp_path


def check(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--base", "main", *args],
        cwd=repo,
        capture_output=True,
        text=True,
    )


def stage_behavior(repo: Path) -> None:
    (repo / "behavior.txt").write_text("changed\n")
    git(repo, "add", "behavior.txt")


def test_unstaged_entry_does_not_cover_staged_behavior(repo: Path) -> None:
    stage_behavior(repo)
    (repo / "CHANGELOG.md").write_text("# Changelog\n\nChanged output behavior.\n")
    assert check(repo, "--staged").returncode == 1
    git(repo, "add", "CHANGELOG.md")
    assert check(repo, "--staged").returncode == 0
    # CI sees only committed files.
    git(repo, "commit", "-m", "behavior with entry")
    assert check(repo).returncode == 0


def test_previous_commit_entry_covers_later_commits(repo: Path) -> None:
    (repo / "CHANGELOG.md").write_text("# Changelog\n\nChanged output behavior.\n")
    git(repo, "add", "CHANGELOG.md")
    git(repo, "commit", "-m", "entry")
    stage_behavior(repo)
    assert check(repo, "--staged").returncode == 0
    git(repo, "commit", "-m", "implementation")
    assert check(repo).returncode == 0


@pytest.mark.parametrize("entry", ["", "# Changelog\n", "# Changelog\n\nExisting entry.\n\n"])
def test_deletion_heading_and_blank_additions_do_not_count(repo: Path, entry: str) -> None:
    stage_behavior(repo)
    (repo / "CHANGELOG.md").write_text(entry)
    git(repo, "add", "CHANGELOG.md")
    assert check(repo, "--staged").returncode == 1


def test_renaming_changelog_does_not_count(repo: Path) -> None:
    git(repo, "mv", "CHANGELOG.md", "history.md")
    assert check(repo, "--staged").returncode == 1


@pytest.mark.parametrize(
    ("labels", "body", "expected"),
    [
        ([], "Changelog exemption: Tests only.", 1),
        ([{"name": "no-changelog"}], "", 1),
        ([{"name": "no-changelog"}], "Changelog exemption:   \nOther text", 1),
        ([{"name": "no-changelog"}], "Changelog exemption: Regression tests only.", 0),
    ],
)
def test_ci_exemption_requires_label_and_reason(
    repo: Path,
    tmp_path: Path,
    labels: list[dict[str, str]],
    body: str,
    expected: int,
) -> None:
    stage_behavior(repo)
    git(repo, "commit", "-m", "change without entry")
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"labels": labels, "body": body}}))
    assert check(repo, "--event", str(event)).returncode == expected


def test_missing_base_and_malformed_event_fail_closed(repo: Path) -> None:
    assert check(repo, "--base", "missing").returncode == 1
    stage_behavior(repo)
    git(repo, "commit", "-m", "change")
    event = repo / "event.json"
    event.write_text("invalid json")
    assert check(repo, "--event", str(event)).returncode == 1


def test_base_only_changelog_entry_does_not_cover_feature(repo: Path) -> None:
    git(repo, "switch", "main")
    (repo / "CHANGELOG.md").write_text("# Changelog\n\nUnrelated base change.\n")
    git(repo, "add", "CHANGELOG.md")
    git(repo, "commit", "-m", "base entry")
    git(repo, "switch", "feature")
    stage_behavior(repo)
    git(repo, "commit", "-m", "feature behavior")
    assert check(repo).returncode == 1


def test_no_changes_pass(repo: Path) -> None:
    assert check(repo).returncode == 0

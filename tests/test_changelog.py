"""Exercise the CI contributor policy against real PR branch changes."""

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


def test_uncommitted_entry_does_not_cover_committed_behavior(repo: Path) -> None:
    stage_behavior(repo)
    git(repo, "commit", "-m", "behavior without entry")
    (repo / "CHANGELOG.md").write_text("# Changelog\n\nChanged output behavior.\n")
    assert check(repo).returncode == 1
    git(repo, "add", "CHANGELOG.md")
    assert check(repo).returncode == 1
    git(repo, "commit", "-m", "entry")
    assert check(repo).returncode == 0


def test_previous_commit_entry_covers_later_commits(repo: Path) -> None:
    (repo / "CHANGELOG.md").write_text("# Changelog\n\nChanged output behavior.\n")
    git(repo, "add", "CHANGELOG.md")
    git(repo, "commit", "-m", "entry")
    stage_behavior(repo)
    git(repo, "commit", "-m", "implementation")
    assert check(repo).returncode == 0


@pytest.mark.parametrize("entry", ["", "# Changelog\n", "# Changelog\n\nExisting entry.\n\n"])
def test_deletion_heading_and_blank_additions_do_not_count(repo: Path, entry: str) -> None:
    stage_behavior(repo)
    (repo / "CHANGELOG.md").write_text(entry)
    git(repo, "add", "CHANGELOG.md")
    git(repo, "commit", "-m", "change without substantive entry")
    assert check(repo).returncode == 1


def test_renaming_changelog_does_not_count(repo: Path) -> None:
    git(repo, "mv", "CHANGELOG.md", "history.md")
    git(repo, "commit", "-m", "rename changelog")
    assert check(repo).returncode == 1


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


@pytest.fixture
def bot_repo(repo: Path) -> Path:
    """A project with separate runtime and development dependency graphs."""
    git(repo, "switch", "main")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "app"\nversion = "1.0"\ndependencies = ["runtime>=1"]\n'
        '[dependency-groups]\ndev = ["linter>=1"]\n'
    )
    (repo / "uv.lock").write_text(
        'version = 1\nrequires-python = ">=3.10"\n'
        '[[package]]\nname = "app"\nversion = "1.0"\n'
        'dependencies = [{name = "runtime"}]\n'
        '[package.dev-dependencies]\ndev = [{name = "linter"}]\n'
        '[package.optional-dependencies]\nfeature = [{name = "optional-runtime"}]\n'
        '[[package]]\nname = "runtime"\nversion = "1"\n'
        'dependencies = [{name = "shared"}]\n'
        '[[package]]\nname = "shared"\nversion = "1"\n'
        '[[package]]\nname = "optional-runtime"\nversion = "1"\n'
        '[[package]]\nname = "linter"\nversion = "1"\n'
    )
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n")
    (repo / ".pre-commit-config.yaml").write_text("repos:\n  - repo: example\n    rev: v1\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "project dependency graph")
    git(repo, "switch", "feature")
    git(repo, "merge", "--ff-only", "main")
    return repo


def replace(repo: Path, path: str, old: str, new: str) -> None:
    file = repo / path
    file.write_text(file.read_text().replace(old, new))


def bot_check(
    repo: Path, login: str = "dependabot[bot]", account_type: str = "Bot"
) -> subprocess.CompletedProcess[str]:
    git(repo, "add", ".")
    git(repo, "commit", "-m", "bot update")
    event = repo / "event.json"
    event.write_text(
        json.dumps(
            {
                "sender": {"login": "human-triggering-label-event", "type": "User"},
                "pull_request": {
                    "user": {"login": login, "type": account_type},
                    "labels": [],
                    "body": "",
                },
            }
        )
    )
    return check(repo, "--event", str(event))


@pytest.mark.parametrize("login", ["dependabot[bot]", "renovate[bot]", "pre-commit-ci[bot]"])
def test_bot_development_update_is_exempt(bot_repo: Path, login: str) -> None:
    replace(bot_repo, "pyproject.toml", "linter>=1", "linter>=2")
    replace(bot_repo, "uv.lock", 'name = "linter"\nversion = "1"', 'name = "linter"\nversion = "2"')
    assert bot_check(bot_repo, login).returncode == 0


@pytest.mark.parametrize(
    "file,old,new",
    [
        (".github/workflows/ci.yml", "checkout@v4", "checkout@v5 # v5.0.0"),
        (".pre-commit-config.yaml", "rev: v1", "rev: v2"),
    ],
)
def test_bot_tool_refs_are_exempt(bot_repo: Path, file: str, old: str, new: str) -> None:
    replace(bot_repo, file, old, new)
    assert bot_check(bot_repo).returncode == 0


@pytest.mark.parametrize(
    "login,account_type",
    [
        ("sidmohan0", "User"),
        ("unrecognized[bot]", "Bot"),
        ("dependabot[bot]", "User"),
    ],
)
def test_author_identity_is_required(bot_repo: Path, login: str, account_type: str) -> None:
    replace(bot_repo, ".github/workflows/ci.yml", "checkout@v4", "checkout@v5")
    assert bot_check(bot_repo, login, account_type).returncode == 1


@pytest.mark.parametrize(
    "file,old,new",
    [
        ("pyproject.toml", "runtime>=1", "runtime>=2"),
        ("pyproject.toml", 'version = "1.0"', 'version = "2.0"'),
        ("uv.lock", 'name = "runtime"\nversion = "1"', 'name = "runtime"\nversion = "2"'),
        ("uv.lock", 'name = "shared"\nversion = "1"', 'name = "shared"\nversion = "2"'),
        (".github/workflows/ci.yml", "checkout@v4", "other/action@v4"),
        (".github/workflows/ci.yml", "steps:", "if: false\n    steps:"),
        (".pre-commit-config.yaml", "repo: example", "repo: other"),
    ],
)
def test_bot_runtime_and_behavior_changes_are_not_exempt(
    bot_repo: Path, file: str, old: str, new: str
) -> None:
    replace(bot_repo, file, old, new)
    assert bot_check(bot_repo).returncode == 1


def test_mixed_bot_update_is_not_exempt(bot_repo: Path) -> None:
    replace(bot_repo, ".github/workflows/ci.yml", "checkout@v4", "checkout@v5")
    stage_behavior(bot_repo)
    assert bot_check(bot_repo).returncode == 1


def test_bot_runtime_update_can_still_supply_changelog(bot_repo: Path) -> None:
    replace(bot_repo, "pyproject.toml", "runtime>=1", "runtime>=2")
    (bot_repo / "CHANGELOG.md").write_text("# Changelog\n\nRuntime fixes email matching.\n")
    assert bot_check(bot_repo).returncode == 0


def test_new_workflow_needs_explicit_entry(bot_repo: Path) -> None:
    (bot_repo / ".github/workflows/new.yml").write_text("jobs: {}\n")
    assert bot_check(bot_repo).returncode == 1


def test_unclassifiable_bot_change_can_supply_entry(bot_repo: Path) -> None:
    (bot_repo / "uv.lock").write_text("invalid TOML !")
    (bot_repo / "CHANGELOG.md").write_text("# Changelog\n\nMaintenance update.\n")
    assert bot_check(bot_repo).returncode == 0


def test_optional_runtime_update_is_not_exempt(bot_repo: Path) -> None:
    replace(
        bot_repo,
        "uv.lock",
        'name = "optional-runtime"\nversion = "1"',
        'name = "optional-runtime"\nversion = "2"',
    )
    assert bot_check(bot_repo).returncode == 1


def test_bot_runtime_update_can_use_explicit_exemption(bot_repo: Path) -> None:
    replace(bot_repo, "pyproject.toml", "runtime>=1", "runtime>=2")
    assert bot_check(bot_repo).returncode == 1
    event = bot_repo / "event.json"
    data = json.loads(event.read_text())
    data["pull_request"]["labels"] = [{"name": "no-changelog"}]
    data["pull_request"]["body"] = "Changelog exemption: Reviewed update has no user-facing effect."
    event.write_text(json.dumps(data))
    assert check(bot_repo, "--event", str(event)).returncode == 0

# Contributing

Install the development dependencies and hooks before making changes:

```sh
uv sync --frozen --group dev
uv run pre-commit install
```

## Changelog policy

Every PR that changes user-facing behavior must add a concise entry to the
unreleased version in `CHANGELOG.md`. This includes tool behavior, defaults,
configuration, security, installation, and supported file formats. Describe what
users will experience; do not copy commit messages or claim unfinished features.

For example, a change to output permissions belongs under `Security`, while a new
file format belongs under `Added`. Keep the release marked `Unreleased` until the
release is ready. The existing release workflow separately checks the version and
dated release heading when publishing a tag.

Changelog enforcement runs only in CI after you push. CI checks the complete PR
against its actual target branch, including when PRs are stacked on other branches.
An entry committed earlier in the PR counts; later commits do not need duplicate
entries. The local pre-commit hooks still run their existing quality checks.

The changelog checker detects a text addition, not whether that text accurately
describes the change; reviewers must
check its substance. Missing base refs fail the check instead of silently passing.

## Changes with no user-facing effect

Tests, internal refactoring, and documentation cleanup can be exempted when they
do not change user-facing behavior. Add the `no-changelog` PR label and a line in
the PR description explaining why:

```text
Changelog exemption: Adds regression tests without changing runtime behavior.
```

Both the label and a nonempty reason are required. Reviewers should confirm the
reason; the label alone is insufficient. CI reruns when the PR description or
labels change. Repository administrators should require the `Changelog policy`
status check in branch protection so failed checks prevent merging.

## Automatic bot exemptions

PRs authored by `dependabot[bot]`, `renovate[bot]`, or `pre-commit-ci[bot]`
(with GitHub account type `Bot`) can omit a changelog entry and exemption reason
when their complete diff changes only contributor tooling:

- Existing GitHub Actions workflow files: action `uses:` refs only.
- Existing pre-commit configuration: hook `rev:` refs only.
- `pyproject.toml`: the `dev`/`ci` dependency groups or Ruff, mypy, Pyright,
  pytest, and coverage settings only.
- `uv.lock`: runtime dependencies, including transitive dependencies and
  optional dependencies, must remain unchanged.

Runtime dependency updates, package/build metadata changes, other files, and
mixed changes still need an entry or the explicit `no-changelog` exemption.
New or deleted files and changes the checker cannot classify fail closed.
Human-authored tooling PRs use the explicit exemption. The author is taken from
the PR, so a human editing its description or labels does not change the bot's
eligibility. The bot exemption concerns release notes only; all other checks
and review requirements still apply.

Run the regular quality checks before opening a PR:

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pyright
uv run pytest
```

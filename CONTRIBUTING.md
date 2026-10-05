# Contributing

Install the development dependencies and hooks before making changes:

```sh
uv sync --frozen --group dev
uv run pre-commit install
git fetch origin main
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

The hook checks the branch's changes from its merge base with `origin/main`,
including staged changes and excluding unstaged edits. An entry committed earlier
on the same branch counts; later commits do not need duplicate entries. Stage the
entry before committing. For a different PR base, fetch it and run:

```sh
CHANGELOG_BASE=origin/other-branch uv run pre-commit run changelog --all-files
```

CI checks the complete PR against its actual base. The checker detects a text
addition, not whether that text accurately describes the change; reviewers must
check its substance. Missing base refs fail the check instead of silently passing.

## Changes with no user-facing effect

Tests, internal refactoring, and documentation cleanup can be exempted when they
do not change user-facing behavior. Add the `no-changelog` PR label and a line in
the PR description explaining why:

```text
Changelog exemption: Adds regression tests without changing runtime behavior.
```

Both the label and a nonempty reason are required. Reviewers should confirm the
reason; the label alone is insufficient. If these changes cannot pass the local
hook, bypass only that hook for the commit:

```sh
SKIP=changelog git commit
```

This local bypass does not exempt the PR in CI. CI reruns when the PR description
or labels change. Repository administrators should require the `Changelog policy`
status check in branch protection so failed checks prevent merging.

Run the regular quality checks before opening a PR:

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pyright
uv run pytest
```

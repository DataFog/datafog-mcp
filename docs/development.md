# Development setup

## Prerequisites

Install [uv](https://docs.astral.sh/uv/) and ensure Python 3.10+ is available.

## Bootstrap

```bash
uv sync --group dev --group docs
uv run pre-commit install
```

## Useful commands

```bash
uv run ruff check .
uv run ruff format .
uv run mypy
uv run pyright
uv run pytest
uv run mkdocs build
```

## Commit hygiene

Pre-commit hooks enforce formatting, linting, and type checks before each commit.

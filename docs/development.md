# Development

See [CONTRIBUTING.md](https://github.com/DataFog/datafog-mcp/blob/main/CONTRIBUTING.md) for the changelog policy and exemption process.

Bare `datafog-mcp` runs the server over stdio; `datafog-mcp serve` is equivalent.

To install from a checkout instead of PyPI, run `uv tool install .` from the repository root.

MCP passes its default or explicit `entity_types` to Core before scanning, including decoded CSV/TSV cells. Only selected detectors run. This installation requires datafog-core 1.7.x (`>=1.7.0,<1.8`). The server accepts one Core minor line at a time, because each Core minor can change what a scan finds; `tests/test_core_1_7.py` fails when a different minor is installed. Under the `<1.8` cap an installation stays on Core 1.7.x: a fresh install or `uv tool upgrade datafog-mcp` picks up Core 1.7 patch releases without a new server release, and nothing moves it to Core 1.8 or later until a datafog-mcp release changes the accepted line.

```bash
uv sync --group dev
uv run pre-commit install
```

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pyright && uv run pytest
```

Runtime dependencies are audited for known advisories weekly, on every push to `main`, and on any pull request that changes them. To run the same audit of the locked dependencies locally:

```bash
uv export --frozen --no-dev --no-emit-project -o locked.txt && uvx pip-audit --disable-pip -r locked.txt
```

[Back to the README](../README.md)

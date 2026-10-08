"""Tests for the synthetic files the size benchmark generates."""

from __future__ import annotations

import asyncio
import csv
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fastmcp import Client

from datafog_mcp.server import mcp

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_sizes.py"
SIZE = 20_000


def _load() -> ModuleType:
    """
    Import the benchmark script as a module.

    Returns:
      The loaded module.
    """
    spec = importlib.util.spec_from_file_location("benchmark_sizes", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclasses look their module up by name while the class is built
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bench = _load()


def _scan(path: Path) -> dict[str, Any]:
    """
    Scan a file with the default types through an in-memory client.

    Parameters:
      path: The file to scan.
    Returns:
      The tool's structured result.
    """

    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool("datafog_scan", {"path": str(path)})
            return result.structured_content or {}

    return asyncio.run(run())


@pytest.mark.parametrize("fmt", bench.FORMATS)
@pytest.mark.parametrize("density", [0.0, 1000.0, None])
def test_files_are_exact_size_and_well_formed(
    tmp_path: Path, fmt: str, density: float | None
) -> None:
    """
    Every format parses and lands on exactly the requested byte count.

    Parameters:
      tmp_path: Where the file is written.
      fmt: The format under test.
      density: Entities per MB, or None for max.
    """
    path = tmp_path / f"sample{bench.LAYOUTS[fmt].suffix}"
    bench.generate(path, fmt, SIZE, density)
    text = path.read_text(encoding="utf-8")

    assert path.stat().st_size == SIZE
    if fmt == "json":
        json.loads(text)
    elif fmt.startswith("csv"):
        widths = {len(row) for row in csv.reader(text.splitlines())}
        assert widths == {bench.LAYOUTS[fmt].slots + 2}
    elif fmt == "sql":
        assert text.endswith(";\n")


def test_generation_is_deterministic(tmp_path: Path) -> None:
    """
    The same arguments always produce the same bytes.

    Parameters:
      tmp_path: Where the files are written.
    """
    first, second = tmp_path / "a.csv", tmp_path / "b.csv"
    bench.generate(first, "csv-narrow", SIZE, 1000.0)
    bench.generate(second, "csv-narrow", SIZE, 1000.0)

    assert first.read_bytes() == second.read_bytes()


@pytest.mark.parametrize("fmt", bench.FORMATS)
@pytest.mark.parametrize("density", [0.0, None])
def test_scan_finds_exactly_the_planted_entities(
    tmp_path: Path, fmt: str, density: float | None
) -> None:
    """
    A default scan finds every planted value and nothing in the filler.

    Benchmark results are only comparable if density means what it says, so
    the control must be clean and every planted value must be detected.

    Parameters:
      tmp_path: Where the file is written.
      fmt: The format under test.
      density: Entities per MB, or None for max.
    """
    path = tmp_path / f"sample{bench.LAYOUTS[fmt].suffix}"
    meta = bench.generate(path, fmt, SIZE, density)

    assert _scan(path)["counts"] == meta["expected"]

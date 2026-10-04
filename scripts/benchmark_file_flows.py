#!/usr/bin/env python3
"""Optional synthetic size qualification; never part of ordinary PR CI.

Run each format in a fresh process so peak RSS is attributable to that run:
  uv run python scripts/benchmark_file_flows.py --format csv --bytes 100000000
No model is enabled. Inputs, policy, and copies are temporary and deleted.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import os
import resource
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from fastmcp import Client

from datafog_mcp.server import mcp

MARKER = b"synthetic-person@example.com"


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1_048_576):
            result.update(block)
    return result.hexdigest()


def generate(path: Path, size: int, fmt: str, row_bytes: int) -> tuple[int, int]:
    header = b"kind,value\n" if fmt == "csv" else b""
    prefix = b"filler," if fmt == "csv" else b""
    row = prefix + b"a" * (row_bytes - 1 - len(prefix)) + b"\n"
    full_rows = (size - len(header) - 128) // len(row)
    remaining = size - len(header) - full_rows * len(row)
    tail_prefix = b"tail," if fmt == "csv" else b""
    tail = tail_prefix + b" " * (remaining - len(tail_prefix) - len(MARKER) - 1) + MARKER + b"\n"
    with path.open("wb") as handle:
        handle.write(header)
        for _ in range(full_rows):
            handle.write(row)
        handle.write(tail)
    assert path.stat().st_size == size
    return size - len(MARKER) - 1, full_rows + 1


async def benchmark(fmt: str, size: int, row_bytes: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="datafog-size-") as directory:
        root = Path(directory).resolve()
        os.environ["DATAFOG_MCP_ALLOWED_ROOTS"] = str(root)
        os.environ["DATAFOG_POLICY_PATH"] = str(root / "absent-policy.toml")
        source = root / ("synthetic.csv" if fmt == "csv" else "synthetic.txt")
        expected_start, records = generate(source, size, fmt, row_bytes)
        original_digest = digest(source)
        timings = {}
        async with Client(mcp) as client:
            start = time.perf_counter()
            scanned = await client.call_tool("datafog_scan", {"path": str(source)})
            timings["scan_seconds"] = round(time.perf_counter() - start, 3)
            data = scanned.structured_content
            assert data is not None and data["counts"] == {"EMAIL": 1}
            assert data["complete"] is True
            assert data["findings"][0]["start"] == expected_start
            assert data["findings"][0]["end"] == expected_start + len(MARKER)
            if fmt == "csv":
                assert data["findings"][0]["record"] == records
                assert data["findings"][0]["column"] == 2
            start = time.perf_counter()
            transformed = await client.call_tool("datafog_redact", {"path": str(source)})
            timings["redact_seconds"] = round(time.perf_counter() - start, 3)
            assert transformed.structured_content is not None
            assert transformed.structured_content["counts"] == {"EMAIL": 1}
            output = Path(transformed.structured_content["output_path"])
        assert digest(source) == original_digest
        if fmt == "csv":
            with source.open(newline="") as original, output.open(newline="") as modified:
                before, after = csv.reader(original), csv.reader(modified)
                assert next(before) == next(after) == ["kind", "value"]
                for _record_number in range(1, records + 1):
                    a, b = next(before), next(after)
                    assert len(a) == len(b) == 2
                    assert b == [a[0], a[1].replace(MARKER.decode(), "[EMAIL]")]
                assert next(before, None) is None and next(after, None) is None
        else:
            with source.open("rb") as original, output.open("rb") as modified:
                # Unchanged prefix equality without loading the whole file again.
                remaining = expected_start
                while remaining:
                    n = min(remaining, 1_048_576)
                    assert original.read(n) == modified.read(n)
                    remaining -= n
                assert modified.read() == b"[EMAIL]\n"
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_bytes = peak if sys.platform == "darwin" else peak * 1024
        return {
            "format": fmt,
            "input_bytes": size,
            "records": records,
            "row_bytes": row_bytes,
            "model_enabled": False,
            **timings,
            "peak_rss_bytes": rss_bytes,
            "near_eof_detected": True,
            "original_preserved": True,
            "transformation_verified": True,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=["text", "csv"], required=True)
    parser.add_argument("--bytes", type=int, default=100_000_000)
    parser.add_argument("--row-bytes", type=int, default=65536)
    args = parser.parse_args()
    if not 128 <= args.row_bytes <= 65536:
        parser.error("--row-bytes must be between 128 and 65536")
    if not 1024 <= args.bytes <= 100_000_000:
        parser.error("--bytes must be between 1024 and 100000000")
    print(json.dumps(asyncio.run(benchmark(args.format, args.bytes, args.row_bytes)), indent=2))


if __name__ == "__main__":
    main()

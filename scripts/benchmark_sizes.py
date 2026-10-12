"""
Benchmark the tools across file size, file format, and entity density.

The results decide the file size limit, so each run measures what a client
experiences: wall time per tool call, the server's peak memory, and how large
the response is once it reaches the agent's context.

Three subcommands do the work:

  generate   Write one synthetic file of an exact byte size and density, with a
             sidecar listing how many entities of each type it holds.
  matrix     Generate every file in a matrix and time each tool on it, one fresh
             process per run so peak memory belongs to that run alone.
  summarize  Reduce a results file to a table checked against the budgets.

Sizes are decimal megabytes (1 MB = 1,000,000 bytes). Density is entities per
MB, or "max" for an entity in every field. Everything is generated at run time
from a fixed seed, so no fixture is committed and runs are reproducible.

The server's 1 MiB limit is lifted inside the measuring process only, by
wrapping its file reader. Nothing about the installed server changes.

Usage:
  uv run python scripts/benchmark_sizes.py matrix --out results.jsonl
  uv run python scripts/benchmark_sizes.py summarize results.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import platform
import random
import resource
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Any

MB = 1_000_000
SEED = 20261007

# Budgets proposed for the limit decision; see the measurements doc.
BUDGET_SECONDS = 30.0
BUDGET_RSS_BYTES = 1 << 30
BUDGET_TOKENS_WARN = 10_000
BUDGET_TOKENS_MAX = 25_000

# JSON full of digits and punctuation tokenizes densely. Three characters per
# token overestimates slightly, which is the safe direction for a budget.
CHARS_PER_TOKEN = 3

FORMATS = ("text", "csv-narrow", "csv-wide", "json", "sql")
TOOLS = {
    "scan": "datafog_scan",
    "redact": "datafog_redact",
    "mask": "datafog_mask",
    "remove": "datafog_remove",
}

# Default-on types only, so a default request should find every one. Weights
# roughly follow how often each turns up in an export.
ENTITY_WEIGHTS = {
    "EMAIL": 35,
    "SSN": 20,
    "CREDIT_CARD": 20,
    "NPI": 10,
    "API_KEY": 10,
    "JWT": 5,
}

# Filler resembles real exports but matches no default-on detector. Numbers
# avoid 9 digits (SSN) and 13 or more (cards); 10-digit IDs, dates, and
# 5-digit codes match only the opt-in PHONE, DATE, and ZIP_CODE detectors.
WORDS = (
    "shipped",
    "pending",
    "refund",
    "invoice",
    "warehouse",
    "north",
    "south",
    "pallet",
    "batch",
    "retry",
    "timeout",
    "cache",
    "Zoë",
    "Müller",
    "Ångström",
    "naïve",
    "café",
    "山田",
    "東京",
    "order",
    "status",
    "region",
    "priority",
)


@dataclass(frozen=True)
class Layout:
    """
    How rows of one format are framed and how many fields each row holds.

    Attributes:
      suffix: File extension, which also selects the server's parsing rules.
      slots: Fields per row that may hold an entity.
      header: Text before the first row.
      footer: Text after the last row.
      separator: Text between rows.
    """

    suffix: str
    slots: int
    header: str
    footer: str
    separator: str


LAYOUTS = {
    "text": Layout(".log", 6, "", "", ""),
    "csv-narrow": Layout(".csv", 6, "id,ts,a,b,c,d,e,f\n", "", ""),
    "csv-wide": Layout(".csv", 40, "id,ts," + ",".join(f"c{i}" for i in range(40)) + "\n", "", ""),
    "json": Layout(".json", 6, "[\n", "\n]\n", ",\n"),
    "sql": Layout(
        ".sql", 6, "INSERT INTO records (id, ts, a, b, c, d, e, f) VALUES\n", ";\n", ",\n"
    ),
}


def _b64url(raw: bytes) -> str:
    """
    Encode bytes as unpadded Base64URL.

    Parameters:
      raw: The bytes to encode.
    Returns:
      The encoded text.
    """
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _luhn_card(rng: random.Random) -> str:
    """
    Make a 16-digit card number that passes the Luhn check.

    Parameters:
      rng: The seeded generator.
    Returns:
      The card number.
    """
    payload = [4] + [rng.randrange(10) for _ in range(14)]
    total = 0
    for index, digit in enumerate(reversed(payload)):
        doubled = digit * 2 if index % 2 == 0 else digit
        total += doubled - 9 if doubled > 9 else doubled
    return "".join(map(str, payload)) + str((10 - total % 10) % 10)


def _entity(kind: str, rng: random.Random, serial: int) -> str:
    """
    Make one synthetic value of a type.

    Parameters:
      kind: The entity type.
      rng: The seeded generator.
      serial: A running number that keeps values distinct.
    Returns:
      The value.
    """
    alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    if kind == "EMAIL":
        return f"user{serial}.{rng.choice(WORDS[:12])}@example{serial % 97}.com"
    if kind == "SSN":
        area = rng.randrange(100, 666)
        return f"{area:03d}-{rng.randrange(1, 100):02d}-{rng.randrange(1, 10000):04d}"
    if kind == "CREDIT_CARD":
        return _luhn_card(rng)
    if kind == "NPI":
        return f"NPI: {rng.randrange(10**9, 10**10)}"
    if kind == "API_KEY":
        return "ghp_" + "".join(rng.choice(alphanumeric) for _ in range(36))
    header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    claims = _b64url(json.dumps({"sub": str(serial)}).encode())
    return f"{header}.{claims}.{_b64url(rng.randbytes(32))}"


def _filler(rng: random.Random) -> str:
    """
    Make one field of realistic text that no default detector matches.

    Parameters:
      rng: The seeded generator.
    Returns:
      The field.
    """
    pick = rng.randrange(6)
    if pick == 0:
        return f"{rng.choice(WORDS)}-{rng.choice(WORDS)}"
    if pick == 1:
        return str(rng.randrange(1, 10**8))
    if pick == 2:
        return f"{rng.randrange(10**9, 10**10)}"
    if pick == 3:
        return f"2026-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}"
    if pick == 4:
        return f"v{rng.randrange(10)}.{rng.randrange(20)}.{rng.randrange(50)}"
    return f"{rng.randrange(10000, 100000)}"


def _row(fmt: str, number: int, fields: list[str]) -> str:
    """
    Frame one record in a format.

    Parameters:
      fmt: The format name.
      number: The record number.
      fields: The field values, entities and filler alike.
    Returns:
      The record, without the separator between rows.
    """
    stamp = f"2026-09-14T08:{number // 60 % 60:02d}:{number % 60:02d}Z"
    if fmt == "text":
        # Space-separated digit runs read as card numbers, so fields are
        # delimited the way many structured logs delimit them
        return f"{stamp} INFO req={number:08x} | {' | '.join(fields)}\n"
    if fmt.startswith("csv"):
        return f"{number},{stamp},{','.join(fields)}\n"
    if fmt == "json":
        values = ", ".join(json.dumps(field, ensure_ascii=False) for field in fields)
        return f'{{"id": {number}, "ts": "{stamp}", "fields": [{values}]}}'
    quoted = ", ".join("'" + field.replace("'", "''") + "'" for field in fields)
    return f"({number}, '{stamp}', {quoted})"


def _rows(fmt: str, size: int, density: float | None, rng: random.Random) -> Iterator[str]:
    """
    Yield the text of a file, piece by piece, at an exact byte size.

    Entities are spread evenly: before each row, enough are placed to keep the
    running total at the target density for the bytes written so far.

    Parameters:
      fmt: The format name.
      size: Total size in bytes.
      density: Entities per MB, or None for an entity in every field.
      rng: The seeded generator.
    Returns:
      Pieces of the file, ending with a counts dict as the final item.
    """
    layout = LAYOUTS[fmt]
    kinds = list(ENTITY_WEIGHTS)
    weights = list(ENTITY_WEIGHTS.values())
    counts: Counter[str] = Counter()
    footer = len(layout.footer.encode())
    written = len(layout.header.encode())
    yield layout.header

    def framed(number: int, fields: list[str]) -> str:
        """
        Frame a row with the separator that precedes it.

        Parameters:
          number: The record number.
          fields: The field values.
        Returns:
          The framed row.
        """
        return (layout.separator if number > 1 else "") + _row(fmt, number, fields)

    def padding_row(number: int, width: int) -> str:
        """
        Make a row of filler whose first field is a given width.

        Parameters:
          number: The record number.
          width: Characters in the first field.
        Returns:
          The framed row, with every other field a dash.
        """
        return framed(number, ["x" * width] + ["-"] * (layout.slots - 1))

    number = 0
    while True:
        number += 1
        if density is None:
            wanted = layout.slots
        else:
            target = density * (written + 120) / MB
            wanted = max(0, min(layout.slots, int(target) - sum(counts.values())))
        positions = set(rng.sample(range(layout.slots), wanted))
        placed: list[str] = []
        fields = []
        for slot in range(layout.slots):
            if slot in positions:
                kind = rng.choices(kinds, weights)[0]
                placed.append(kind)
                fields.append(_entity(kind, rng, sum(counts.values()) + len(placed)))
            else:
                fields.append(_filler(rng))
        piece = framed(number, fields).encode()

        # Keep room for one padded row so the file ends at exactly size bytes
        room = len(padding_row(number + 1, 1).encode())
        if written + len(piece) + room + footer > size:
            break
        counts.update(placed)
        written += len(piece)
        yield piece.decode()

    blank = len(padding_row(number, 1).encode())
    yield padding_row(number, size - written - footer - blank + 1)
    yield layout.footer
    yield json.dumps(dict(counts))


def generate(path: Path, fmt: str, size: int, density: float | None) -> dict[str, Any]:
    """
    Write one synthetic file and its sidecar of expected entity counts.

    Parameters:
      path: Where to write the file.
      fmt: The format name.
      size: Total size in bytes.
      density: Entities per MB, or None for an entity in every field.
    Returns:
      The sidecar contents.
    """
    rng = random.Random(f"{SEED}:{fmt}:{size}:{density}")
    pieces = _rows(fmt, size, density, rng)
    with path.open("w", encoding="utf-8", newline="") as handle:
        previous = next(pieces)
        for piece in pieces:
            handle.write(previous)
            previous = piece
    counts = json.loads(previous)
    actual = path.stat().st_size
    if actual != size:
        raise RuntimeError(f"generated {actual} bytes, wanted {size}")
    meta = {
        "format": fmt,
        "size_bytes": size,
        "density_target": "max" if density is None else density,
        "density_actual": round(sum(counts.values()) / (size / MB), 1),
        "expected": counts,
    }
    path.with_name(path.name + ".meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return meta


def _peak_rss() -> int:
    """
    Report this process's peak resident memory so far.

    Returns:
      Bytes. Linux reports kilobytes and macOS bytes, so both are normalized.
    """
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024


def measure(tool: str, path: Path, entity_types: list[str] | None) -> dict[str, Any]:
    """
    Call one tool once through an in-memory MCP client and record its cost.

    Runs in a fresh process, so the peak memory reported is this call's own,
    plus the fixed cost of importing the server.

    Parameters:
      tool: A key of TOOLS.
      path: The file to process.
      entity_types: Types to request, or None for the defaults.
    Returns:
      The measurements, and the error message if the call failed.
    """
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    from datafog_mcp import server

    # Lift the size limit for this process only
    reader = server.read_text_file

    def unlimited(target: str, *_args: Any, **_kwargs: Any) -> Any:
        """
        Read a file with the limit raised to its own size.

        The reader allocates its limit up front, so an arbitrarily large limit
        would fail with MemoryError rather than lift the cap.

        Parameters:
          target: The path to read.
        Returns:
          What the server's reader returns.
        """
        return reader(target, max(1, os.path.getsize(target)))

    server.read_text_file = unlimited  # type: ignore[assignment]

    arguments: dict[str, Any] = {"path": str(path)}
    if entity_types:
        arguments["entity_types"] = entity_types

    async def call() -> Any:
        """
        Make the tool call.

        Returns:
          The client's result.
        """
        async with Client(server.mcp) as client:
            return await client.call_tool(TOOLS[tool], arguments)

    baseline = _peak_rss()
    start = time.perf_counter()
    try:
        result = asyncio.run(call())
    except ToolError as exc:
        return {"status": "error", "error": str(exc), "seconds": time.perf_counter() - start}
    seconds = time.perf_counter() - start

    text = "".join(getattr(item, "text", "") for item in result.content)
    data = result.structured_content or {}
    return {
        "status": "ok",
        "seconds": round(seconds, 3),
        "peak_rss_bytes": _peak_rss(),
        "import_rss_bytes": baseline,
        "response_chars": len(text),
        "response_tokens_approx": len(text) // CHARS_PER_TOKEN,
        "counts": data.get("counts", {}),
        "output_path": data.get("output_path"),
    }


def _machine() -> dict[str, Any]:
    """
    Describe the machine and code being measured.

    Returns:
      Platform, CPU, Python, engine version, and the checked-out commit.
    """
    commit = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    return {
        "kind": "machine",
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpus": os.cpu_count(),
        "python": platform.python_version(),
        "datafog_core": version("datafog-core"),
        "commit": commit or None,
    }


def _isolated_env(workdir: Path, policy: Path | None) -> dict[str, str]:
    """
    Build an environment that confines the server to the scratch directory.

    HOME moves too, so no personal roots, policy, or keys are read.

    Parameters:
      workdir: The scratch directory.
      policy: An optional policy file, such as one enabling the model.
    Returns:
      The environment for each measuring process.
    """
    home = workdir / "home"
    (home / ".config" / "datafog").mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "HOME": str(home),
        "DATAFOG_MCP_ALLOWED_ROOTS": str(workdir),
        "DATAFOG_POLICY_PATH": str(workdir / "absent-policy.toml"),
    }
    if policy is not None:
        copy = home / ".config" / "datafog" / "policy.toml"
        copy.write_text(policy.read_text(encoding="utf-8"), encoding="utf-8")
        env["DATAFOG_POLICY_PATH"] = str(copy)
    return env


def _cells(args: argparse.Namespace) -> Iterator[tuple[str, int, float | None]]:
    """
    List the format, size, and density combinations to run.

    At 100 MB only the control, realistic-dense, and max densities run unless
    --full is given, since those runs are slow and the smaller sizes show the
    shape of the curve.

    Parameters:
      args: The parsed matrix arguments.
    Returns:
      Each combination in turn.
    """
    for size_mb in args.sizes:
        for fmt in args.formats:
            for density in args.densities:
                if size_mb >= 100 and not args.full and density not in (0.0, 30000.0, None):
                    continue
                yield fmt, int(size_mb * MB), density


def matrix(args: argparse.Namespace) -> None:
    """
    Generate each file, measure every tool on it, and append the results.

    Parameters:
      args: The parsed matrix arguments.
    """
    workdir = Path(args.workdir or tempfile.mkdtemp(prefix="datafog-bench-")).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    env = _isolated_env(workdir, args.policy)
    out = Path(args.out)

    with out.open("a", encoding="utf-8") as results:
        results.write(json.dumps(_machine()) + "\n")
        for fmt, size, density in _cells(args):
            label = "max" if density is None else f"{density:g}"
            path = workdir / f"{fmt}-{size}-{label}{LAYOUTS[fmt].suffix}"
            meta = generate(path, fmt, size, density)
            print(f"{path.name}: {meta['density_actual']} entities/MB", file=sys.stderr)

            for tool in args.tools:
                for repeat in range(args.repeats):
                    record = _run_once(tool, path, args, env)
                    record.update(
                        kind="run",
                        tool=tool,
                        repeat=repeat,
                        format=fmt,
                        size_bytes=size,
                        density_target=meta["density_target"],
                        density_actual=meta["density_actual"],
                        expected=meta["expected"],
                    )
                    results.write(json.dumps(record) + "\n")
                    results.flush()
                    print(
                        f"  {tool} #{repeat}: {record['status']} {record.get('seconds')}s",
                        file=sys.stderr,
                    )

            if not args.keep:
                path.unlink()
                path.with_name(path.name + ".meta.json").unlink()


def _run_once(
    tool: str, path: Path, args: argparse.Namespace, env: dict[str, str]
) -> dict[str, Any]:
    """
    Measure one call in a fresh process and remove any copy it wrote.

    Parameters:
      tool: A key of TOOLS.
      path: The file to process.
      args: The parsed matrix arguments.
      env: The isolated environment.
    Returns:
      The measurements, or a timeout or crash record.
    """
    command = [sys.executable, __file__, "measure", "--tool", tool, "--path", str(path)]
    if args.entity_types:
        command += ["--entity-types", args.entity_types]
    try:
        done = subprocess.run(
            command, env=env, capture_output=True, text=True, timeout=args.timeout
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "seconds": args.timeout}
    if done.returncode != 0:
        return {"status": "crash", "error": done.stderr.strip().splitlines()[-1:]}

    record: dict[str, Any] = json.loads(done.stdout)
    output = record.pop("output_path", None)
    if output:
        Path(output).unlink(missing_ok=True)
    return record


def summarize(path: Path) -> None:
    """
    Print one table row per cell, checked against the budgets.

    Parameters:
      path: A results file written by matrix.
    """
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record.get("kind") == "machine":
            print(f"<!-- {record} -->")
            continue
        key = (
            record["format"],
            record["size_bytes"] // MB,
            record["density_target"],
            record["tool"],
        )
        groups.setdefault(key, []).append(record)

    print(
        "| Format | MB | Density | Tool | Runs | Median s | Max s | Peak RSS MB "
        "| Tokens | Found/expected | Within budget |"
    )
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for (fmt, size_mb, density, tool), runs in groups.items():
        ok = [run for run in runs if run["status"] == "ok"]
        failures = len(runs) - len(ok)
        if not ok:
            statuses = ", ".join(sorted({run["status"] for run in runs}))
            print(
                f"| {fmt} | {size_mb} | {density} | {tool} | {len(runs)} "
                f"| | | | | | no ({statuses}) |"
            )
            continue
        times = [run["seconds"] for run in ok]
        rss = max(run["peak_rss_bytes"] for run in ok)
        tokens = max(run["response_tokens_approx"] for run in ok)
        found = sum(ok[0]["counts"].values())
        expected = sum(ok[0]["expected"].values())
        within = (
            failures == 0
            and max(times) <= BUDGET_SECONDS
            and rss <= BUDGET_RSS_BYTES
            and tokens <= BUDGET_TOKENS_MAX
        )
        verdict = "yes" if within else "no"
        if within and tokens > BUDGET_TOKENS_WARN:
            verdict = "yes (token warning)"
        print(
            f"| {fmt} | {size_mb} | {density} | {tool} | {len(runs)} "
            f"| {statistics.median(times):.2f} | {max(times):.2f} | {rss / MB:.0f} "
            f"| {tokens:,} | {found}/{expected} | {verdict} |"
        )


def _density(raw: str) -> float | None:
    """
    Parse a density argument.

    Parameters:
      raw: A number of entities per MB, or "max".
    Returns:
      The density, or None for max.
    """
    return None if raw == "max" else float(raw)


def _csv(convert: Callable[[str], Any]) -> Callable[[str], list[Any]]:
    """
    Make an argument parser for comma-separated lists.

    Parameters:
      convert: Applied to each item.
    Returns:
      A function argparse can use as a type.
    """
    return lambda raw: [convert(item) for item in raw.split(",")]


def main() -> None:
    """
    Dispatch to a subcommand.
    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1])
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="write one synthetic file")
    gen.add_argument("--format", choices=FORMATS, required=True)
    gen.add_argument("--mb", type=float, required=True)
    gen.add_argument("--density", type=_density, required=True)
    gen.add_argument("--out", type=Path, required=True)

    run = sub.add_parser("measure", help="measure one call (used by matrix)")
    run.add_argument("--tool", choices=TOOLS, required=True)
    run.add_argument("--path", type=Path, required=True)
    run.add_argument("--entity-types")

    grid = sub.add_parser("matrix", help="generate and measure a full matrix")
    grid.add_argument("--out", required=True)
    grid.add_argument("--sizes", type=_csv(float), default=[1.0, 10.0, 100.0])
    grid.add_argument("--formats", type=_csv(str), default=list(FORMATS))
    grid.add_argument(
        "--densities", type=_csv(_density), default=[0.0, 10.0, 1000.0, 30000.0, None]
    )
    grid.add_argument("--tools", type=_csv(str), default=["scan", "redact"])
    grid.add_argument("--repeats", type=int, default=5)
    grid.add_argument("--timeout", type=float, default=300.0)
    grid.add_argument("--entity-types", help="comma-separated; omit for defaults")
    grid.add_argument("--policy", type=Path, help="policy file, such as one enabling the model")
    grid.add_argument("--workdir", help="scratch directory; a temporary one by default")
    grid.add_argument("--full", action="store_true", help="every density at 100 MB too")
    grid.add_argument("--keep", action="store_true", help="keep generated files")

    summary = sub.add_parser("summarize", help="tabulate a results file")
    summary.add_argument("results", type=Path)

    args = parser.parse_args()
    if args.command == "generate":
        print(json.dumps(generate(args.out, args.format, int(args.mb * MB), args.density)))
    elif args.command == "measure":
        types = args.entity_types.split(",") if args.entity_types else None
        print(json.dumps(measure(args.tool, args.path, types)))
    elif args.command == "matrix":
        matrix(args)
    else:
        summarize(args.results)


if __name__ == "__main__":
    main()

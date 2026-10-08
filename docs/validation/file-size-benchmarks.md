# File size benchmarks

Measurements to decide the file size limit, currently 1 MiB. Produced by [`scripts/benchmark_sizes.py`](../../scripts/benchmark_sizes.py).

## Budgets

A limit is acceptable when every tool call on a file at that size, at realistic density, stays within all three budgets.

| Budget | Value | Why |
|---|---|---|
| Time per call | 30 s, worst of the runs | The hard ceiling is 60 s: Codex's default `tool_timeout_sec`, and the Claude Desktop app reportedly cancels stdio tool calls at about 60 s. The Claude Code CLI waits far longer. Half the ceiling leaves room for slower machines. |
| Peak memory | 1 GB for the server process | The server runs beside an IDE and an agent on 8 to 16 GB machines. |
| Response size | 25,000 tokens; aim for 10,000 | Claude Code warns at 10,000 tokens of MCP output and truncates at 25,000 (`MAX_MCP_OUTPUT_TOKENS`). |

These are proposals and haven't been agreed yet.

## Method

- **Files** are generated at run time from a fixed seed, at exact sizes of 1, 10, and 100 MB (decimal).
- **Formats**:
  - A structured log.
  - Narrow CSV (6 fields per row).
  - Wide CSV (40 fields per row).
  - A JSON array.
  - A SQL `INSERT` dump.
- **Filler** looks like real exports: words (including accented and Japanese), IDs, dates, versions, and 5- and 10-digit numbers. It matches no default-on detector.
- **Entities** come from the default-on types, weighted toward the common ones: email, SSN, card, labeled NPI, GitHub token, and JWT.
- **Density** is entities per MB:
  - 0, the control.
  - 10.
  - 1,000.
  - 30,000, a dense customer export.
  - max, an entity in every field.

  JSON and SQL saturate near 25,000 to 28,000, so their dense and max rows are nearly the same file.
- **Each call runs in a fresh process.** Peak memory therefore belongs to that call. It includes about 95 MB for importing the server.
- **Calls go through an MCP client**, so the measured response is what reaches the agent. Tokens are estimated at three characters each, which slightly overestimates.
- **The 1 MiB limit is lifted** inside the measuring process only.
- **Every run checks that the scan found exactly the planted entities.** All runs below did.

Machine: Linux x86_64, 16 CPUs, Python 3.12.11, datafog-core 0.4.2. One run per cell. Times are far enough from the budget that repeats wouldn't change a conclusion, and memory doesn't vary between runs.

## Results

Ranges cover every format and both scan and redact.

### Text path (`main` at `a42981b`)

All five formats take this path on `main`.

| MB | Density | Call time (s) | Peak memory (MB) | Scan response (tokens) |
|---|---|---|---|---|
| 1 | 0 | 0.06–0.07 | 100–111 | 62–64 |
| 1 | 10 | 0.06–0.08 | 100–110 | 208–220 |
| 1 | 1,000 | 0.06–0.07 | 99–111 | 15,197–15,249 |
| 1 | 30,000 | 0.09–0.16 | 137–156 | 382,731–454,517 |
| 1 | max | 0.09–0.17 | 138–166 | 383,334–540,384 |
| 10 | 0 | 0.33–0.46 | 239–335 | 62–65 |
| 10 | 10 | 0.34–0.48 | 238–334 | 1,647–1,678 |
| 10 | 1,000 | 0.36–0.49 | 240–334 | 158,159–158,315 |
| 10 | 30,000 | 0.69–1.25 | 574–725 | 3,931,586–4,746,909 |
| 10 | max | 0.66–1.34 | 565–810 | 3,934,738–5,557,423 |
| 100 | 0 | 2.90–4.28 | 1,392–2,458 | 64–66 |
| 100 | 30,000 | 6.44–12.16 | 4,772–6,336 | 40,407,420–49,475,324 |
| 100 | max | 6.48–12.88 | 4,773–7,202 | 40,419,007–57,029,068 |

### CSV cell path (#41 at `de6966e`)

CSV files only. The branch predates the opt-in defaults, so `main`'s default types were requested explicitly.

| MB | Density | Call time (s) | Peak memory (MB) | Scan response (tokens) |
|---|---|---|---|---|
| 1 | 0 | 0.46–0.49 | 90–91 | 64–65 |
| 1 | 1,000 | 0.47–0.50 | 94–95 | 23,575–23,670 |
| 1 | 30,000 | 0.37–0.44 | 103–131 | 702,462–702,495 |
| 1 | max | 0.36–0.44 | 101–137 | 740,479–833,865 |
| 10 | 0 | 4.29–4.63 | 116–118 | 65 |
| 10 | 1,000 | 4.44–4.67 | 150–158 | 245,052–245,967 |
| 10 | 30,000 | 3.54–4.34 | 246–553 | 7,326,914–7,328,228 |
| 10 | max | 3.36–4.21 | 238–598 | 7,555,366–8,565,911 |
| 100 | 0 | 42.06–45.18 | 383–386 | 65–66 |
| 100 | 30,000 | 36.70–45.43 | 1,648–4,467 | 76,257,993–76,266,941 |

## Findings

1. **Response size fails first, at every file size.**
   - Findings aren't paginated, and each costs about 15 tokens, so a response exceeds 25,000 tokens past roughly 1,600 findings.
   - That happens at 1,000 entities per MB in a 1 MB file, which is under today's limit.
   - Raising the byte limit changes nothing for dense files until findings are paginated or summarized.
   - Responses from the write tools stay under 160 tokens at every size.
2. **Memory fails next, at 100 MB.**
   - The text path peaks at 1.4 to 2.5 GB with no entities, and 4.8 to 7.2 GB when dense.
   - At 10 MB, every format and density stays under 1 GB, at 810 MB or less.
3. **Most memory at the control density goes to types nobody asked for.**
   - Core's text `scan` has no way to select entity types. It detects every type, including the opt-in DATE, ZIP_CODE, and PHONE, and the server discards them afterward.
   - On the 100 MB control file, Core returned 2,714,934 such findings. They took memory from about 300 MB to 1.4 GB before being thrown away.
   - Letting Core's text scan take a type selection, as its structured scan already takes `exclude`, would remove most of that cost.
4. **The CSV cell path trades time for memory.**
   - It scans one cell at a time, so control memory stays near 380 MB even at 100 MB.
   - It runs about 10 times slower: 42 to 45 s at 100 MB. That's over the 30 s budget and close to the 60 s ceiling.
5. **Time isn't the limiting factor on the text path.** Its slowest call was 13 s at 100 MB dense. That's on a 16-CPU desktop; the reference runner is still to be measured.

## Recommendation

- **Raise the limit to 10 MB (10,000,000 bytes).**
  - Every format and density measured stays within the time and memory budgets: at most 1.34 s and 810 MB on the text path, and 4.67 s and 598 MB on the CSV path.
  - This holds once response size is handled.
- **Bound scan responses before or alongside the raise.**
  - Paginate findings, or return counts without locations above a threshold.
  - Without this, dense files fail at any limit, including today's.
- **Don't support 100 MB yet.**
  - Memory reaches 7 GB on the text path.
  - The CSV path takes about 45 s.
  - It needs Core changes first: type selection for text scans, and chunked or streaming scans.

## Still to measure

- The reference runner. Run the manual **Size benchmark** workflow and compare.
- The name and address model (#51), which needs its own runs.
- Mask and remove. These share redact's path; spot-check them.

## Reproducing

```bash
uv run python scripts/benchmark_sizes.py matrix --out results.jsonl --repeats 1
uv run python scripts/benchmark_sizes.py summarize results.jsonl
```

Only control, dense, and max run at 100 MB unless `--full` is given. To measure another branch, copy the script into that checkout; it drives the tools through an MCP client, so it doesn't depend on server internals beyond the file reader it wraps.

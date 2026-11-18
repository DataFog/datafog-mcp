# File size benchmarks

Measurements behind the 10 MB file size limit, which replaced the earlier 1 MiB limit. Produced by [`scripts/benchmark_sizes.py`](../../scripts/benchmark_sizes.py).

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
- **The file size limit is lifted** inside the measuring process only.
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

## Response-listing validation after CSV and type selection

PR #60 caps location listings at **700 findings** for every input format. At
701 or more, scans return complete counts and an empty list with
`findings_listed: false`. Redact, mask, and remove still transform every finding.
The earlier 1,200 proposal was sized for plain-text findings; CSV/TSV also
include record and column coordinates.

Local macOS ARM64, Python 3.12, published Core 0.4.3: in-memory MCP scans with
700 labeled US routing numbers after 950,000 padding characters returned:

| Format | MCP text characters | Estimated tokens (characters / 3) |
|---|---:|---:|
| Text | about 40,120 | about 13,373 |
| CSV | about 56,813 | about 18,937 |
| TSV | about 56,813 | about 18,937 |

Temporary path length can vary these sizes slightly. A separate regression
uses seven-digit offsets, records, and columns, a long path, and the longest
currently supported type name. Its conservative JSON serialization stays below
75,000 characters at 700 findings. The equivalent 1,200-finding response exceeds
120,000 characters.

Tests check actual MCP text output as well as structured results, the listing
boundary for both table delimiters, omission of matched values, and complete
transformations above the cutoff. These are response-size checks, not a rerun
of the timing/memory matrix above. Token figures use the existing benchmark
estimate, not an exact tokenizer or a guarantee for every client's context
budget. Rerun the size/format/density matrix on the combined code before the
10 MB limit change (#61).

## Rerun on datafog-core 1.5.0

The matrix above was rerun after the server moved to datafog-core 1.5.0, on the change that raised the requirement to 1.5.0 (with fastmcp 3.4.7, before the locked dependencies were updated to 3.4.11). The numbers predate the move to datafog-core 1.8.0, which the server now requires; they were not rerun on it. Since the original runs, CSV files take the cell path, the server passes its entity selection to Core (finding 3), and scan responses stop listing locations above 700 findings (finding 1).

**These numbers come from a different machine and are not comparable run for run with the tables above.** They were measured on a shared Linux aarch64 virtual machine with 4 CPUs and 3.9 GB of memory, no swap, Python 3.12.15, datafog-core 1.5.0. The original tables came from a 16-CPU x86_64 desktop. The virtual machine is noisy: other work on the host changes timings between runs. Use this section to check the budgets on current code and a small machine, not to measure a speedup or slowdown against the earlier hardware. The reference runner is still to be measured.

Method as above, with these differences:

- Three runs per cell at 1 and 10 MB; ranges cover every run, every format on the path, and both scan and redact. One run per cell at 100 MB.
- The matrix was run in several invocations of `matrix`, one or two formats at a time, because of a time limit on each command in this environment. Each tool call still ran in its own fresh process.
- At 100 MB, calls ran under a 3.3 GB address-space limit (`ulimit -v`) so a failed allocation could not take the machine down.
- Every completed run found exactly the planted entities. Importing the server accounts for about 79 MB of each peak.

### Text path (plain text, JSON, SQL)

| MB | Density | Call time (s) | Peak memory (MB) | Scan response (tokens) |
|---|---|---|---|---|
| 1 | 0 | 0.04–0.05 | 97 | 74 |
| 1 | 10 | 0.05–0.06 | 97 | 218–230 |
| 1 | 1,000 | 0.05–0.07 | 97 | 98–99 |
| 1 | 30,000 | 0.10–0.13 | 138–145 | 102 |
| 1 | max | 0.10–0.12 | 138–143 | 101–102 |
| 10 | 0 | 0.27–0.34 | 131–161 | 74–75 |
| 10 | 10 | 0.29–0.37 | 132–161 | 1,658–1,670 |
| 10 | 1,000 | 0.31–0.44 | 147–176 | 101 |
| 10 | 30,000 | 0.83–1.15 | 525–560 | 104–105 |
| 10 | max | 0.81–1.03 | 515–560 | 104 |
| 100 | 0 | 2.46–3.92 | 486–785 | 74–75 |
| 100 | 30,000 | not measured | not measured | not measured |
| 100 | max | not measured | not measured | not measured |

The dense and max cells at 100 MB were attempted for plain text only, and both scan and redact failed with an allocation error under the 3.3 GB limit. This machine cannot hold them, so they say nothing new beyond confirming that dense 100 MB files need more than about 3 GB. JSON and SQL were run at 100 MB for the control density only.

### CSV cell path (narrow and wide CSV)

| MB | Density | Call time (s) | Peak memory (MB) | Scan response (tokens) |
|---|---|---|---|---|
| 1 | 0 | 0.52–0.58 | 94 | 75–76 |
| 1 | 10 | 0.52–0.59 | 94–95 | 305 |
| 1 | 1,000 | 0.52–0.60 | 94 | 100 |
| 1 | 30,000 | 0.38–0.41 | 104–105 | 104 |
| 1 | max | 0.35–0.38 | 103–105 | 103–104 |
| 10 | 0 | 5.09–5.55 | 112–122 | 76 |
| 10 | 10 | 5.11–5.72 | 147–157 | 2,532–2,560 |
| 10 | 1,000 | 5.08–5.57 | 149–159 | 103 |
| 10 | 30,000 | 3.55–3.95 | 247–248 | 106–107 |
| 10 | max | 3.35–3.65 | 235–250 | 106 |
| 100 | 0 | 50.61–54.39 | 376–386 | 76–77 |

Dense and max were not attempted at 100 MB on this path.

### What the rerun shows

- **The 10 MB limit holds within all three budgets on this machine.** The slowest call at 10 MB took 5.72 s (CSV) against the 30 s budget, the highest peak was 560 MB (dense text) against 1 GB, and the largest scan response was 2,560 tokens against 25,000. Write-tool responses stayed under 95 tokens.
- **Response size no longer fails.** Above 700 findings a scan returns counts without locations, so the largest responses now come from sparse files whose findings are all listed, not from dense ones.
- **Control-density memory on the text path is much lower than in the original runs** (131–161 MB at 10 MB, 486–785 MB at 100 MB, against 239–335 MB and 1,392–2,458 MB). This is the direction finding 3 predicted once Core accepted a type selection. The machines differ, so treat the size of the drop as indicative only.
- **100 MB is still not supportable.** The CSV path takes 51 to 54 s at the control density here, over the 30 s budget and close to the 60 s ceiling, and dense text files exceed the memory this machine has.

The raw results were produced with the commands under [Reproducing](#reproducing), with `--sizes`, `--formats`, and `--densities` narrowing each invocation and `--repeats 3`.

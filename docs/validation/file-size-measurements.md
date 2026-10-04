# File-size measurements

Local development measurements on 2026-10-04, macOS 26.6.2 arm64, Python 3.12.13, locked Core 0.4.1. These are single runs on this machine, not service-level guarantees. Each run starts a fresh process and uses the real MCP interface in memory, with temporary allowed roots and an absent temporary policy. No model is configured.

Run separately for independent peak-RSS measurements:

```bash
uv run python scripts/benchmark_file_flows.py --format text --bytes 100000000
uv run python scripts/benchmark_file_flows.py --format csv --bytes 100000000
uv run python scripts/benchmark_file_flows.py --format csv --bytes 100000000 --row-bytes 128
```

The script generates exact-size synthetic files, checks scan counts and the original offset of an email near EOF, creates a redacted copy, checks the original checksum, and validates output content. For CSV it compares every parsed record and cell: headers, record/column counts, unchanged cells, and the intended replacement. It deletes all generated files when finished. It never downloads artifacts or reads personal policy/keys.

## Measured results

| Input | Size (bytes) | Data records | Scan seconds | Redact seconds | Peak RSS (bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Plain text, 64 KiB lines | 100,000,000 | 1,526 | 0.757 | 0.708 | 506,068,992 |
| CSV, 64 KiB records | 100,000,000 | 1,526 | 5.147 | 4.979 | 387,792,896 |
| CSV, 128-byte records, optimized worker | 1,000,000 | 7,812 | 0.124 | 0.109 | 89,882,624 |
| CSV, 128-byte records, optimized worker | 100,000,000 | 781,249 | 11.248 | 11.374 | 386,957,312 |

The deterministic CSV processing loop now runs in one worker thread, avoiding two threadpool dispatches per cell. Before this optimization, narrow-row 1 MB cost 1.008s/1.004s for scan/redact and 10 MB cost 10.350s/10.066s. These earlier measurements motivated the change; they are not the current performance baseline. The wide-row and plain-text measurements above predate this dispatch optimization.

All listed runs passed full-input EOF and transformation invariants. Timings include the tool call but exclude fixture generation and post-call validation. Peak RSS is the process lifetime high-water mark, including startup, generation, scanning, transformation, and validation. No claim about throughput on other machines follows from these numbers.

## Limits of this qualification

- Files contain one synthetic email near EOF, with otherwise repetitive filler. They do not measure dense findings, overlap-heavy detection, or real customer-data distributions.
- Wide CSV records deliberately test large source size with relatively few callbacks. The actual 100 MB narrow-row run additionally exercises 781,249 two-column records. It remains slower than the wide-row case, but completed both operations and all content assertions after the worker-dispatch optimization.
- Model-enabled performance is not measured here. This script intentionally isolates deterministic parsing/detection. Native model qualification and window-boundary tests remain separate release work.
- Findings pagination bounds response size, but the scanner still materializes transformations and repeats scanning for each continuation. Large-file acceptance is not a bounded-memory streaming guarantee.
- Only scan and redact are benchmarked. Other strategy correctness belongs in deterministic tests; pseudonymization and model-enabled resource costs need separate measurement.

The current 100 MB byte limit is therefore exercised end to end for plain text, wide-row CSV, and narrow-row CSV. Dense findings, larger column counts, and enabled model inference remain separate performance qualification items. Keep this script optional rather than adding machine-dependent timing thresholds to ordinary PR CI.

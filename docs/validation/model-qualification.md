# Experimental local name/address model qualification

This branch integrates the existing September 25, 2026 research model through
an **opt-in standalone Rust subprocess adapter**. It does not add a native model
API to the published DataFog Core package. Portable Core release integration and
broader model qualification remain outstanding. Names/address detection is not
available in an ordinary installation without a configured bundle.

## Artifact and provenance

The evaluated artifact is the 65.2M-parameter DistilBERT token classifier described
in DataFog Core's `docs/research/local-pii-model.mdx` and
`docs/research/local-pii-methodology.mdx`. The existing local research workspace
contains `artifacts/bundle/`; it was reused without downloading another model,
retraining, or altering the frozen weights/threshold.

- Bundle: approximately 300 MB including the native executable and ONNX Runtime.
- Platform actually exercised: macOS Apple arm64 only. This artifact contains
  `libonnxruntime.dylib`; Linux and Windows releases have not been qualified.
- All 16 recorded SHA-256 checksums passed before evaluation.
- `model.onnx` SHA-256:
  `04889c1ea2e9029d9b89cd5f35697224634bb06d9777abfa6ea575810b9a3eb2`.
- `config.json` SHA-256:
  `446e6d4beb141b894ee2bd1c51a0755bac9a214b3db09fbe86dfe9137f037f1b`.
- `calibration.json` SHA-256:
  `75a946908fdc07549d81c7b72a2c1774da39e0755b88f7083a2492c70a8f1f53`.
- Pretrained backbone revision: `6ea81172465e8b0ad3fddeed32b986cdcdcffcf0`.
- Nemotron-PII dataset revision: `b70ffaf5ff39e079776134c5bf4381f00a9fd1ed`.

The research threshold is experimental. Original research results are synthetic
and must not be represented as general customer-file accuracy. That work's
separate hand-authored support examples recovered only 14 of 18 entities.

## Integration contract

A user explicitly configures `[model].bundle_directory` in policy TOML. MCP
launches its `datafog-pii` executable without a shell and exchanges JSONL locally.
No model download or network inference occurs. `first_name` and `last_name` map
to separate `PERSON` findings; `street_address` maps to `STREET_ADDRESS`. Other
model categories are ignored in favor of the existing Core detectors.

The adapter validates half-open UTF-8 byte boundaries, converts them into Core
`Finding` objects, and uses Core for the selected transformation and allowlist
behavior. It never exposes the runtime's returned redacted text. Missing bundles,
malformed responses, and timeouts fail explicitly; there is no silent fallback.
The runtime is reused under a lock and restarted when bundle file stat identities
change. The signature supports cache invalidation, not tamper-proof provenance.

CSV inference receives one complete decoded, header-labeled record. Only spans
wholly contained in cell-value ranges are transformed; headers and delimiters
remain untouched. This context matters: bare-cell inference missed `10 Example
Road` and `Musterstrasse 5` in the existing fixture, while complete-record context
recovered both. No heuristic substitutes for model detection.

Large plain text is processed in 16,384-character segments with 1,024-character
overlap, while the runtime retains its own 512-token internal windows. Midpoint
ownership avoids duplicate overlap findings and offsets are restored globally.
An owned finding touching a nonfinal segment's end is refused as unsupported.
Finite overlap is not a guarantee for arbitrary-length entities or every possible
boundary prediction. The adapter's timeout includes queueing and all segments
in one invocation. MCP shares one model-inference deadline across all records
in a CSV operation; each record receives only the remaining budget. A timeout
fails the operation before any output copy is written. A deterministic mocked
clock/runtime test proves that two records consuming the budget prevent a third
inference and leave both the original and destination state unchanged.

## Diagnostic evidence, October 4, 2026

These are small synthetic integration fixtures, not a held-out accuracy benchmark
or evidence of production reliability. Fixture outcomes informed integration
changes, so they must not be described as an independent model acceptance set.

| Case | Result |
| --- | --- |
| Five original customer records with row context | All 15 planted first-name, last-name, and street-address spans recovered |
| One prose example and one emoji/accented Unicode example | All 6 planted target spans recovered, exact boundaries |
| One clean operational sentence | No target findings |
| Entire original raw customer CSV | All 15 target spans recovered |
| Native adapter outer-segment boundary | Names at characters 16370–16378 and address at 16388–16404 recovered exactly once |
| Configured MCP CSV scan | 10 PERSON and 5 STREET_ADDRESS findings; values absent from response |
| Configured MCP redact, mask, and remove | All target values changed; headers, unrelated cells, record/column counts, and original bytes preserved |

Observed individual warm row requests took approximately 14–18 ms; the complete
CSV took 60 ms; first initialization plus the first prose request took 340 ms.
These are single observations on the development Mac, not latency percentiles.

## Tests and reproduction

Ordinary CI tests transport failures, Unicode offsets, concurrency, timeouts,
segmentation ownership, model-change invalidation, and CSV mapping without
requiring weights or platform-specific binaries. Real model adapter and MCP
integration tests are **opt-in**, skipped when the bundle is absent:

```sh
DATAFOG_TEST_MODEL_BUNDLE=/absolute/path/to/artifacts/bundle \
  uv run pytest tests/test_model_runtime.py tests/test_csv_processing.py --no-cov
```

No weights or runtime binary are committed. To reproduce model tests, obtain the
original research bundle with the recorded model/config/calibration checksums.
There is no public portable release URL in this implementation.

## Resource measurement

One 100,000,000-byte synthetic plain-text file contained operational sentences
and a final name/address/email sentence. A real in-memory MCP client invoked
`datafog_scan`; process maximum RSS was measured with `resource.getrusage` on
macOS (bytes). This is a single throughput observation, not a service target.

- EMAIL-only Core scan: **2.486 seconds**, parent maximum RSS **405,716,992 bytes**
  (approximately 387 MiB). The planted near-EOF email was reported exactly at
  character offsets **99,999,982–99,999,998** with a complete response.
- EMAIL + PERSON + STREET_ADDRESS with the configured model and a 120-second
  inference timeout: **explicit timeout after 121.056 seconds end-to-end**.
  Parent maximum RSS **284,508,160 bytes** (approximately 271 MiB); native child
  maximum RSS **516,079,616 bytes** (approximately 492 MiB). These are separate
  process high-water marks, not a simultaneous total. No partial or clean scan
  response was returned; near-EOF model coverage was **not established**.

Consequently, this model does **not** meet the 100 MB complete-scan target under
this tested deadline. Keep it experimental; improve throughput/overall resource
control or evaluate another small model before claiming that target is met.

The 100 MB file admission limit is not a claim that every detector/file format
has acceptable throughput at that size. In particular, many-row CSV model scans
have per-record overhead and can exhaust the shared operation deadline.

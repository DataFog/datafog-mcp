# GLiNER fixture comparison in GitHub Actions

A separate CI job runs GLiNER directly on a GitHub-hosted CPU runner against four
committed synthetic examples and the original customer CSV and clean notes fixtures. It needs no Cloudflare service, external inference
endpoint, API token, or GitHub secrets. Model inference runs within the CI job;
public model files are downloaded during preparation.

This is a comparison with an independent detector. It does not establish that MCP
or Core find the same entities, and does not add GLiNER to the shipped package or
change local-only product behavior. Existing offline MCP CI remains separate.

## Reproducible model preparation

The job creates an isolated `.gliner-venv` using the CPU dependencies in
`scripts/gliner_fixture_runtime/requirements.txt`. The preparation helper downloads
`urchade/gliner_small-v2.1` at revision
`4e091416cf7c3481db542c2a3d26156916f3a47f`, prepares its pinned backbone, and records
provenance. The evaluator requires that exact model ID and revision. Inference
loads only the prepared directory with Hub and Transformers offline mode enabled.
Model-download or inference failures fail the job rather than producing a clean
result or silently skipping evaluation.

The workflow runs on relevant pull requests, relevant pushes to `main`, and manual
dispatch. It has read-only repository permissions, does not persist checkout
credentials, and has a 20-minute job timeout. Fork pull requests can run without
access to account credentials, subject to GitHub's normal approval rules. This
adds a separate CI check; making it a required branch-protection check is an
independent repository setting.

## What is measured

The evaluator reads the original committed `tests/data/user_flows/customers.csv`
and `notes_clean.txt`. Each of the five customer rows is presented as header-labeled
text, preserving every field as context. Expected `person` and `address` spans
are the exact `full_name` and `street_address` values. City is a separate labeled
field, so it is not part of the expected street-address span. The original notes
must produce no findings. No arbitrary input file path is accepted.

Four additional built-in diagnostics in `scripts/check_gliner_fixtures.py` cover:

- A prose name and address.
- A CSV containing a name and address.
- A name following Unicode characters, including an emoji.
- A clean negative.

The labels are `person` and `address`, with a fixed confidence threshold of 0.5.
Offsets must be zero-based Unicode codepoints with an exclusive end. Expected
spans are explicit and exact: missing entities, extra findings, or different span
boundaries make the exact-span comparison unsuccessful. Returned spans and scores are validated before
scoring, including duplicate and out-of-range rejection.

The added CSV diagnostic sends a complete small CSV string to GLiNER. It does not test MCP's
CSV parser, column locations, transformations, or output integrity; the offline
MCP suite covers those behaviors. These examples are a smoke comparison,
not a representative accuracy benchmark, a 100 MB performance test, or a release
gate for the local model. Changes to the MCP fixture directory trigger the job,
and the evaluator reads the customer CSV and clean notes on every run. The other
original files remain covered by offline MCP tests rather than this person/address
comparison.

Output contains the pinned model ID/revision and per-case expected, matched,
missed, and unexpected counts. It does not print source text or matched values.
The evaluator exits `0` when all exact spans match, `1` for a completed comparison
with quality mismatches, and `2` for runtime, schema, provenance, or fixture errors.
The workflow treats only exit `1` as a **nonblocking diagnostic**: it emits a visible
**NOT QUALIFIED** warning and summary, and uploads the metrics JSON as an artifact.
Exit `2` and other unexpected failures fail the job. There is no blanket
`continue-on-error`. No production quality thresholds have been agreed, so a green
workflow with a warning means the comparison executed, not that the model is
qualified. Even exact agreement on this small corpus is not product qualification.

The `missed` count means an expected exact labeled span was not returned. It does
not necessarily mean all or any sensitive characters went undetected: a shorter,
longer, or split entity can produce a miss and unexpected spans together. Additional
findings are likewise candidates for review, not automatically proven false positives.
The metrics artifact contains no source text or model-returned strings.

A mismatch is evidence to investigate model behavior or the span policy. Do not
weaken expected findings merely to make an observed run green.

## Run locally

Use a compatible CPU environment and the same isolated dependency setup:

```sh
uv venv --python 3.12 .gliner-venv
uv pip install --python .gliner-venv/bin/python --extra-index-url https://download.pytorch.org/whl/cpu -r scripts/gliner_fixture_runtime/requirements.txt
.gliner-venv/bin/python scripts/gliner_fixture_runtime/prepare_model.py --output /tmp/gliner-fixture-model
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 .gliner-venv/bin/python scripts/check_gliner_fixtures.py --model-directory /tmp/gliner-fixture-model
```

The dependency file targets the Linux CPU CI environment; platform-specific
PyTorch wheel availability can differ on a developer machine.

Offline evaluator tests use injected predictions and require no model download:

```sh
uv run pytest tests/test_gliner_fixtures.py --no-cov
```

Those tests check grading, Unicode offset semantics, schema validation, and
failure behavior. They do not substitute for the real model run in CI.

## Initial local observation (October 4, 2026)

The pinned model recovered all ten expected name/street-address spans across the
five original customer rows. Three rows also had extra findings (2, 1, and 1).
The two added prose/CSV address diagnostics each had one exact-span mismatch and
two extra findings. Across all ten cases, 13 of 15 expected spans matched exactly,
with eight unexpected spans. Both clean negatives and the Unicode name check passed.
These are fixture observations, not general accuracy estimates. The expected
spans and threshold were not changed to fit the model output. The quality result
is NOT QUALIFIED under exact agreement; consult each CI artifact for that run.

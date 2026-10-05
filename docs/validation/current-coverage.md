# Current validation coverage

The original gap inventory mixed current contracts, known detector limitations, and future features. Required CI checks now assert observable supported behavior and reject unexpected failures. An error is never counted as a clean scan or a successful access refusal.

## Required deterministic checks

| Area | Fixture/test | Contract |
| --- | --- | --- |
| Defaults and detector overlap | `test_server.py`, Garmin export | Email/phone present, DATE/ZIP opt-in; selected overlapping types resolved consistently |
| Email source boundaries | `test_email_context.py` | Real MCP-client scans and redact/mask/remove copies for `.env`, `.env.*`, and SQL, exact Unicode source offsets, legitimate local parts and SQL escapes, explicit format overrides, stale-pagination refusal, unchanged originals and CSV/plain-text behavior |
| CSV structure | `test_csv_processing.py`, `test_user_flows.py` | Quoted commas/quotes, multiline fields, empty values, Unicode, BOM/CRLF, headerless modes, original offsets, record/field locations, unchanged headers and cells |
| Policy | `test_policy.py`, `test_user_flows.py` | Strict schema, snapshots/reload, exact case-sensitive allowlists, invalid configuration rejection, advisory scope/action |
| File transformations | `test_transform.py`, `test_user_flows.py` | Original preserved, meaningful output, scan/write counts agree, permissions preserved, no overwrite |
| Output directories | `test_paths.py`, `test_user_flows.py` | Explicit/configured/sibling precedence, root confinement, credential/configuration exclusions |
| Direct text | `test_user_flows.py` | Metadata-only responses, Unicode locations, byte limits, shared allowlists |
| Batch and pages | `test_user_flows.py` | Explicit per-file outcomes, opt-in recursion, no writes, full counts, bounded pages, stale-input/config rejection |
| Activity | `test_user_flows.py` | Disabled by default; enabled records contain counts/status but no paths or values |
| Serving | `test_offline.py` | Real stdio startup, policy discovery, scan, redact/mask/remove, collision refusal, original bytes, no DNS/connect egress |
| Error privacy | `test_error_privacy.py` and injected engine failure | Failure cannot masquerade as clean; sensitive exception details excluded |

Small fixtures stay in source control. Generate large inputs in temporary directories rather than committing them. Existing synthetic user-flow fixtures remain in `tests/data/user_flows/`; they are discovery and model-evaluation inputs, not a claim of universal detection coverage.

Pseudonymization is covered in `test_keys.py` and `test_pseudonym_workflow.py`: paired CSV/text exports verify same-key consistency, fresh Core managers verify persistent keys, and distinct keys separate results. Tests use temporary file/fake credential backends. Never inspect a developer's personal credential store in ordinary CI.

See [file-size measurements](file-size-measurements.md) for reproducible optional benchmarks and their workload limits.

## Separate release qualification

- Pin and hash model artifacts; evaluate names and addresses against independently labeled examples, including negative and window-boundary cases. Document misses and excessive redaction. A model adapter or successful download is not qualification.
- Measure 100 MB runtime, resident memory, and response size separately for deterministic and model-enabled processing. Include detections near EOF and window boundaries. Pagination limits response size but each continuation currently repeats scanning.
- Exercise supported desktop credential stores manually or in dedicated platform jobs. Missing/locked storage must fail without replacement keys or fallback.
- Keep detector-quality corpus deltas separate from MCP contract regressions. Exact-span scores differ from sensitive bytes left exposed and structural damage.

## Agent workflow evaluations

Record the client/model versions and the policy used. Exercise default ask, configured transform/proceed/stop, scope discovery before first read, project-local data, and outbound drafts. Observe all content-producing operations (including shell reads), not just a tool named Read. Record bypasses as limitations of advisory integration; do not imply host enforcement exists.

The [historical runbook](original-runbook.md) preserves the initial discovery scenarios but is not a release checklist. Its old size limits, pseudonym-label expectations, and capability heuristics must not be used to grade the new implementation.

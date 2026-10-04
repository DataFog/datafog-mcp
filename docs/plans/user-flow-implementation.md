# DataFog MCP user flow implementation plan

Agreed direction as of October 4, 2026. This plan turns the fourteen product-gap decisions into implementation slices with concrete fixture coverage. The implementation snapshot and remaining release gates are recorded in [implementation status](../validation/implementation-status.md). This document preserves the agreed sequencing and acceptance requirements.

The sequencing principle is **fixtures just ahead of the behavior they specify**. Preserve the original examples now, establish trustworthy CI assertions, then add each feature's fixtures and implementation together. Do not create one large failing suite for the entire roadmap, and do not redefine expected results merely to make an implementation pass.

## Branch and starting point

- Implementation branch: `feat/mcp-user-flows` in `/Users/sid/projects/datafog/datafog-mcp`.
- Base: `origin/main`, commit `99ed333`.
- Existing reference worktree: `/Users/sid/projects/datafog/datafog-mcp/.claude/worktrees/datafog-mcp-user-flows-d5b340`. Its `validation/` directory is untracked and must be explicitly copied when importing it; branch switching alone will not preserve it in Git.
- Leave that worktree intact until its useful fixtures and runbook have been migrated and verified. Do not delete it as part of this plan.
- Current MCP dependency is locked to `datafog-core` 0.4.1. Check release and PR status again when implementation starts. Reconcile corpus PR #29 and documentation PR #30 rather than copying competing versions of their work.
- Core changes, including model integration if needed, belong on a separate focused Core branch. MCP adopts a tested release afterward.

## Agreed product requirements

| Gap | Decision |
| --- | --- |
| 1 Names and street addresses | Evaluate DataFog's September DistilBERT checkpoint first. Use a different lightweight model if it fails the acceptance criteria. Retain existing Core detectors alongside it. |
| 2 DATE and ZIP defaults | Make both opt-in, retaining explicit selection. |
| 3 Published accuracy | Require clear coverage, limitations, and examples. Keep corpus results for regression testing; defer a polished public accuracy report. |
| 4 Finding locations | CSV record number and field name or column index; line and character column for other text; retain exact offsets. |
| 5 Allowlists | Versioned `~/.config/datafog/policy.toml`; exact, case-sensitive values by entity type, applied across tools. Missing file means no allowlist; malformed policy fails; reload on the next call. Defer custom detection patterns. |
| 6 Pseudonymization | Expose Core's keyed pseudonymization through MCP. Named scopes persist across related files. OS credential storage by default, explicitly selected local-file storage for headless use. Fail on missing keys; defer cloud storage. |
| 7 File sizes | Target 100 MB files, with measured memory and runtime and a configurable upper limit. No silent truncation. |
| 8 CSV integrity | Preserve records, columns, headers, and valid quoting. Only matched content within cells changes; empty cells are valid. |
| 9 Batch scans | Selected files or folders, per-file outcomes, continued processing after individual failures, opt-in recursion. Defer batch transformation. |
| 10 Output copies | Explicit output path overrides policy directory, which overrides sibling output. Directory must exist and be within allowed roots. Never overwrite. No automatic deletion. |
| 11 Workflow policy | Ask by default after findings; configurable transform, proceed, or stop. Advisory until host enforcement exists. |
| 12 Activity logs | Opt-in, local, recording time, operation, outcome, and entity counts. Exclude content, matched values, and paths by default. |
| 13 Outbound text | Add scan-only `datafog_check_text`, reusing detection and policy. Return metadata, never echo input. Define an input-size limit. Host tool-argument retention remains outside DataFog's control. |
| 14 Scan scope | Configurable folders and optional file types. No automatic exemption for project-local or Git-tracked files. Make rules available before the agent's first read; scope is advisory and separate from allowed roots. |

## Ownership and implementation boundaries

Core owns detection, exact allowlist matching, overlap resolution, and cryptographic transformations. Core 0.4.1 already supports exact allowlists and provider-backed HMAC-SHA-256 pseudonymization. Regex allowlists are exclusions, not custom detectors.

MCP owns local policy loading, filesystem access, CSV interpretation, tool schemas and responses, key-provider integration, and logging. It should share scanning and policy application across file and text tools, rather than duplicate detection logic.

The model is a separate research artifact, not automatically included by installing Core 0.4.1. Locate and verify the frozen checkpoint and native inference bundle before deciding how Core will load it. Preserve byte/code-point offset semantics and the no-network-during-serving contract.

## Fixture sequencing policy

For each slice:

1. Define the observable contract and expected result independently of implementation.
2. Add the smallest fixture that exercises it; demonstrate that the assertion fails for the intended reason on the old behavior when feasible.
3. Implement the behavior and make the targeted tests pass.
4. Run related existing tests and required quality checks; review output and fixture changes.
5. Land the feature and its passing tests together. Add the next slice afterward.

Known detector limitations belong in a versioned quality corpus or explicitly documented follow-ups. Missing roadmap features are not global CI failures. Unexpected tool errors always fail contract tests. Expected refusals must identify the intended cause and verify relevant files are unchanged.

## Phase 1 Preserve fixtures and establish reliable acceptance tests

Import the five original synthetic fixtures and a revised runbook from the old worktree into the new branch. Keep one canonical copy of each fixture; reuse the PR #29 corpus conventions where appropriate. Keep generated files and reports outside tracked fixture data.

Replace gap-report heuristics with assertions only for existing product promises. Reuse existing tests in `test_server.py`, `test_transform.py`, `test_paths.py`, and `test_error_privacy.py`; do not duplicate them under a second runner. Keep roadmap inventory informational.

Fix these weak checks before relying on them:

- A failed scan must not count as a clean scan, low false positives, or absence of filename disclosure.
- The no-overwrite check must establish first-call success, assert the destination-exists refusal, and verify existing output bytes.
- Names in a schema, a `text` parameter, or the disappearance of a docstring phrase do not establish working features.
- Credential coverage must match individual labeled values and spans, not aggregate non-email finding counts.
- Preserve logs during tests so errors and unintended disclosure can be asserted rather than globally suppressed.

Use per-test temporary paths and explicit environment configuration. Do not inspect or modify personal Claude settings, policy files, or keychains during ordinary CI. Remove PyPI availability from required PR checks.

Exit condition: current supported contracts pass; a deliberately failed tool call fails the appropriate test instead of being classified as success.

## Phase 2 Define policy and ship the first small behavior changes

Introduce a versioned TOML loader. Reserve one documented schema for allowlists, output preference, workflow preference, scope, logging, limits, and pseudonymization references. The agreed location and `version = 1` are fixed; field names beyond agreed examples should be finalized in this slice. On Python 3.10, use a compatible TOML parser since standard-library `tomllib` is not available there.

Read and validate a policy snapshot at the start of each operation, before reading sensitive input. Apply fresh snapshots on subsequent calls. For a batch, use one snapshot for the entire operation. This snapshot behavior is a proposed implementation detail to document.

Add tiny policies and fixtures proving missing-file defaults, malformed/unknown configuration handling, exact case-sensitive matching, and next-call reload. Avoid echoing policy values through parse errors.

Remove DATE and ZIP_CODE from defaults. Use `app.log` to prove those types are excluded while its synthetic credential remains detectable; use explicit selection to prove DATE/ZIP remain available. Do not call this log wholly insensitive: it contains a credential.

Pass exact allowlists through Core's transformation configuration for both scan reporting and writes. Use one allowed email, one disallowed email, and a case variant. Preserve agreement between reported actionable findings and replacements. Indicate policy application without disclosing allowlisted values.

Exit condition: policy reload and refusal behavior, defaults, and allowlists are covered consistently across current tools.

## Phase 3 Run model evaluation early and integrate only after qualification

Start this evaluation after Phase 1, independently of policy and CSV implementation. Do not delay finding out whether the checkpoint is suitable until the end of the project.

Locate the frozen September model, tokenizer, calibration settings, artifact hashes, and Rust runtime. Test local loading without serving-time downloads. Evaluate labeled names and addresses from the existing customer fixture plus separate support prose, Unicode names, negative examples, and entities near window boundaries. Use fixtures not involved in training or threshold tuning for the final acceptance decision.

Before scoring, record the acceptance thresholds for per-type recall, excessive redaction, startup cost, memory, and latency. Those numeric thresholds have not been agreed yet; synthetic research scores alone cannot substitute for them. If the model fails, evaluate a small alternative on the same protocol, preserving a held-out acceptance set.

Implement shared native model integration in Core if the runtime is not already available there. Retain deterministic detectors and define overlap precedence. Missing or invalid model artifacts must produce an explicit degraded-mode status or failure under a documented policy, never silent claims of full coverage. The choice between opt-in degraded mode and mandatory failure remains to be finalized.

Add actual positive/negative detection and offset assertions, not checks for advertised entity names. Verify all MCP transformation paths use the same accepted detections. Adopt the tested Core release in both the minimum dependency and lockfile where necessary.

Exit condition: recorded model qualification, offline inference, and fixture-level behavior. The model requirement is not complete merely because weights have downloaded.

## Phase 4 CSV interpretation and useful finding locations

Define location conventions before implementation. Proposed: one-based data-record numbers excluding the header, one-based column indices always present, optional header names; one-based line/character columns for other text. Retain existing zero-based, end-exclusive code-point offsets into the original file. Explicitly document BOM and CRLF handling.

Add a compact CSV edge-case fixture with quoted commas, escaped quotes, embedded newlines, empty fields, Unicode, and duplicate headers; add separate headerless and malformed examples. Decide supported dialect/header configuration explicitly rather than guessing silently.

Scan decoded cell values and map findings back to original source locations. Escaped quotes mean this mapping cannot be a simple constant offset. Preserve field context where detectors need it, and test label-sensitive NPIs/routing numbers so cell scanning does not silently regress coverage.

Transform cells and serialize valid CSV while preserving record/column counts, headers, and untouched cell values. Preserve existing BOM guarantees. Byte-for-byte identical quoting is not required by the current product decision, but unchanged data and valid structure are. Malformed or ambiguous input must receive an explicit outcome under the chosen parser policy.

Use original offsets for source reporting and decoded-cell spans for cell transformation. Keep scan results and write-tool counts consistent. Track Core issue #31 separately; parsing does not justify claiming all generic-text boundary problems are solved.

Exit condition: meaningful locations and structural guarantees tested across redact, mask, and remove, extended to pseudonymization when introduced.

## Phase 5 Keys and pseudonymization

Expose a dedicated pseudonymization tool backed by Core's asynchronous `PrivacyManager`. Map explicit named scopes to stable key references and versions. Generate keys only during explicit setup; never place raw keys in TOML, MCP arguments, responses, or logs. Missing/unavailable keys fail without automatic regeneration or backend fallback.

Implement OS credential storage for desktop use and an explicitly selected owner-readable file backend for headless use. Document platform support, unlock behavior, backup/transfer, and rotation. Test real platform storage separately from ordinary CI; contract tests use a temporary provider or temporary file backend. No test should alter a developer's real credential store.

Add paired exports with repeated values, distinct values, and an identity column whose meaning is explicitly defined. Assert same-value/same-key consistency within and across files and restarts, separation across scope keys, exact-case behavior, and failures for unavailable keys. Do not assert numbered placeholders: Core emits Base64 HMAC output. Distinct-person counting is not identity resolution.

Use the complete customer fixture for realism, but not as proof that redaction prevents identity linkage: names and addresses may provide other clues. Verify no-values and file-integrity guarantees for the new tool.

Exit condition: persistence and cross-file consistency work with documented key lifecycle behavior.

## Phase 6 Output locations and direct text checks

Allow explicit output paths within allowed roots, then configured existing output directories, then sibling defaults. Add temporary destination fixtures for precedence, absent directories, outside-root destinations, symlink/path escape cases, collisions, and restrictive permissions. Preserve no-overwrite, no-original-modification, and partial-write cleanup guarantees when directories differ.

Add `datafog_check_text` using the shared scan/policy helper. Add clean and sensitive synthetic drafts, exact offsets, Unicode, input-limit boundaries, and failure privacy checks. It does not send messages or guarantee that a host excludes arguments from its logs. Keep the text-input limit independently configurable from the large-file limit.

Exit condition: all output choices obey access rules; outbound checks are scan-only and do not echo input.

## Phase 7 Large files and batch scanning

Agree whether the 100 MB target means 100,000,000 bytes or 100 MiB and document the exact limit before writing boundary expectations. Generate exact below/at/above-limit inputs at runtime; do not commit huge fixtures. The former 1.4 MB refusal case becomes an ordinary supported input once the new limit is enabled.

Measure runtime, resident memory, and response size with regex and model enabled. Chunk as necessary using record-aware CSV processing and tested model windows. Include an entity at a chunk boundary and another near EOF to detect silent truncation, duplication, and offset drift. CSV records may themselves exceed a chunk, and multiline cells must not be split as independent records.

A 100 MB scan can produce an impractically large findings response. Define bounded summaries plus explicit pagination or continuation before release; never silently omit findings. No numeric latency budget or response cap has been agreed yet.

Add a generated mixed folder containing supported, clean, oversized, unsupported, and nested inputs. Verify selected-file and folder modes, opt-in recursion, deterministic per-file reporting, continued processing after individual errors, and no output-copy creation. Define symlink traversal, duplicate paths, file-count limits, and bounded concurrency. Never widen allowed roots.

Exit condition: full-input coverage, bounded resources, transparent result completeness, and per-file batch outcomes. Batch transformation remains out of scope.

## Phase 8 Workflow guidance and activity logging

Expose configured scan scope before the first read through a documented client-visible mechanism, such as server instructions plus an explicit policy-discovery tool. Verify actual client support; merely returning policy after a scan does not meet this requirement. Define how updates become visible during long-running sessions.

Return advisory post-finding actions consistently. Default to ask; support proceed, stop, and transform. Specify which transformation and scope apply when transform is selected. Policy scope does not grant filesystem access or automatically exempt Git-tracked/project-local files.

Add opt-in local logging with time, operation, outcome, and entity counts. Default off; omit content, matched values, and paths. Test success, refusal, engine errors, and batch operations with synthetic sentinels. Define retention, log permissions, and behavior on log-write failures before shipping. Logs attest only to DataFog operations, not all agent reads.

Update manual/evaluated agent flows for default ask, configured actions, early scope visibility, outbound drafts, and explicit bypass. Record client/model versions and inspect all content-producing tools, including shell commands. These evaluations do not create host enforcement and are not initially required PR gates.

Exit condition: deterministic policy/logging tests pass, and documented client evaluations show what the advisory workflow does and does not achieve.

## CI and release sequencing

Keep the existing Python 3.10–3.12 quality matrix. Add required assertions to pytest as each slice lands; retain lint, formatting, mypy, and pyright checks. Add one small subprocess workflow using the existing stdio transport pattern to cover startup, serialization, lifecycle, and representative scan/write behavior.

Keep ordinary PR checks offline after dependency installation. Provision pinned model artifacts explicitly before model tests; verify serving performs no network access. Run model acceptance tests on changes to detector integration or pinned artifacts, with a broader scheduled run. Use a documented release gate for 100 MB model performance and platform credential-store smoke tests. Test exact size-boundary behavior independently of unstable wall-clock thresholds on shared runners.

Use PR #29's versioned corpus for detection changes. Review baseline deltas intentionally; never conflate exact-span errors with sensitive bytes left behind. Preserve core failure-privacy and no-network tests.

Before release, update README and tool descriptions with defaults, coverage, known misses, supported formats, policy and key setup, limits, CSV location semantics, and advisory-policy limitations. No polished public accuracy report is required. Unsupported formats, custom detectors, batch transformation, cloud key storage, and host/proxy enforcement remain deferred.

## Suggested landing order

1. Fixture preservation and reliable current-contract assertions.
2. Policy schema, DATE/ZIP defaults, and exact allowlists.
3. CSV locations and safe cell transformations.
4. Pseudonymization and key lifecycle.
5. Output directories and direct text checks.
6. Large-file support, bounded findings responses, and batch scans.
7. Workflow guidance and opt-in logging.
8. Final model integration, if not ready earlier, followed by combined acceptance and release documentation.

Model qualification starts immediately after the first slice and can proceed independently; integration may land earlier when qualified. Large-file acceptance must be repeated with the selected model. Each slice carries its own fixtures, implementation, documentation, and passing checks. Do not merge a placeholder implementation just to satisfy a schema-based capability check.

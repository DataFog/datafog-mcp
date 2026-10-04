# datafog-mcp

Local file checks and transformations for MCP clients, powered by [datafog-core](https://github.com/DataFog/datafog-core). Agents can inspect entity counts and locations without receiving matched values, then create a transformed copy before analysis or sharing.

This branch locks Core **0.4.1** (`>=0.4.1,<0.5`). The optional local name/address model is a separate experimental artifact; installing Core does not install or enable that model.

## Install and connect

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/). From this checkout:

```bash
uv tool install .
claude mcp add --scope user datafog -- ~/.local/bin/datafog-mcp
```

Register the executable with another MCP client using its stdio-server configuration. `datafog-mcp` and `datafog-mcp serve` both start the server. Installing dependencies downloads packages; serving does not download models or check for updates.

## Start with the policy

The intended agent flow is:

1. Call `datafog_get_policy` before a new file workflow to learn scan scope and preferences.
2. Scan applicable files before reading them into model context.
3. Follow the advisory action when findings are present, as defined below.
4. If using a transformed copy, open that copy separately for analysis.

- **ask:** pause for user permission before reading originals or sending sensitive content.
- **transform:** use the configured strategy and pseudonymization scope to create a copy; read or share only the successfully created copy.
- **stop:** stop the affected workflow and explain findings using metadata only.
- **proceed:** continue under policy and existing user authorization. This does not independently authorize sending or publishing.

If scanning or transformation fails—including a timeout or unsupported format—report the limitation. Do not open the original with another tool to investigate or bypass the failure. Apply this rule individually to failed files in a batch.

Before sending an already-composed draft, use `datafog_check_text` and follow the same findings policy. It does not transform or send text: if transformation is required, revise and recheck the draft, or create a transformed source-file copy using the configured strategy. Do not read an unscanned file into context just to pass its contents to this tool. The host may retain its arguments.

These instructions are advisory. DataFog cannot intercept or block a shell command, another MCP server, or a direct file read. A refusal means the file was not checked. A clean result means the selected detectors found nothing actionable, not that no sensitive data exists.

## Tools

| Tool | Behavior |
|---|---|
| `datafog_get_policy` | Exposes advisory scope, workflow preferences, limits, and available pseudonymization scopes, without allowlist values or keys |
| `datafog_scan` | Scans one file; reports counts and paginated findings with source locations |
| `datafog_scan_batch` | Scans selected files/folders, with per-file success/error and counts; subfolders require `recursive=true` |
| `datafog_check_text` | Checks an outbound draft already in context; returns metadata, does not send or transform text |
| `datafog_redact` | Writes type labels such as `[EMAIL]` |
| `datafog_mask` | Covers matched characters; CSV quoting can change serialized file length |
| `datafog_remove` | Deletes matched values, retaining empty CSV cells |
| `datafog_pseudonymize` | Writes consistent opaque HMAC pseudonyms using a required named scope |

All write tools preserve the original and refuse existing destinations. Output precedence is explicit `output_path`, `[output].directory`, then a sibling named with `_redacted`, `_masked`, `_removed`, or `_pseudonymized`. The destination directory must exist within allowed roots. Copies retain source permissions minus execute bits; partial writes are cleaned up. Copies are not deleted automatically.

Batch scans are sequential, deduplicate resolved paths, do not follow directory symlinks, and create no copies. File symlinks still undergo allowed-root validation. A per-file failure does not make other files disappear from the result. Exceeding the configured batch count refuses the whole selection before scanning.

### Coverage and known limits

Default deterministic types: `EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `US_ROUTING_NUMBER`, `NPI`, `API_KEY`, `BEARER_TOKEN`, `JWT`, `CREDENTIAL_URI`, and `PRIVATE_KEY`.

`DATE`, `ZIP_CODE`, and `IP_ADDRESS` are **opt-in**. Pass `entity_types` to select them; an empty list is invalid. For example, `entity_types=["EMAIL", "DATE"]` selects just those types.

- Core's API-key coverage is GitHub/Stripe formats, not arbitrary credentials such as every AWS key.
- Credential URIs cover password-bearing PostgreSQL formats, not every URI scheme.
- NPIs and routing numbers require recognizable labels. CSV headers supply context; an arbitrary identifier column is not automatically understood.
- Dates can be operational timestamps, and five-digit IDs can look like ZIP codes. This is why those types are not default selections.
- Names and street addresses require the separately configured model below. Its first-/last-name spans map to `PERSON`, not necessarily one combined full-name span.
- Plain-text email boundaries can include surrounding syntax such as an assignment prefix or SQL quote. CSV parsing protects cell boundaries but does not repair every Core detector limitation. Track [issue #31](https://github.com/DataFog/datafog-mcp/issues/31).
- Redaction labels do not preserve distinct identities. Pseudonyms preserve exact-value equality, not person identity; two addresses for one person remain different values.

We test named fixtures and regression behavior; these are not general accuracy guarantees. Review outputs for your data format and use case.

## Files, CSVs, and finding pages

UTF-8 text files are accepted up to **100,000,000 bytes (100 MB, decimal)** by default. Text tool arguments default to 1,048,576 bytes independently. Files are fully checked; results are paginated instead of silently truncated. Large-file model latency and memory are separate release qualifications, not guaranteed by accepting a size limit.

XLSX, PDF, DOCX, images, archives, and non-UTF-8 encodings are refused. Export or convert them outside DataFog first. A UTF-8 BOM is retained.

`.csv` and `.tsv` use explicit comma/tab parsing, with double quotes and doubled-quote escaping. The first record is a header by default; use `has_header=false` for headerless inputs. `input_format="text"` explicitly treats an irregular export as plain text. There is no silent fallback after a CSV error.

CSV transformations preserve headers, record/column counts, and untouched cell values. Quoted commas, embedded newlines, escaped quotes, Unicode, empty cells, duplicate headers, and CRLF are supported. Malformed quoting, inconsistent column counts, and blank physical records are refused. Other dialects are not guessed.

Findings use zero-based, end-exclusive Unicode code-point offsets into the **original input**, including BOM and CRLF. Text locations also include one-based `line` and `character_column`. CSV findings add one-based `record` (excluding header), `column`, and optional `field_name`. Duplicate or empty headers are disambiguated by column index. Headers themselves are preserved and not selected for transformation.

For `datafog_scan` and `datafog_check_text`, inspect `complete`. If false, repeat with `offset=next_offset` and the previous `content_digest`, retaining the same input/options. Counts describe the whole input, while `findings` contains one page. Changed content or detection settings invalidate continuation. Each continuation rescans the input; pagination bounds response size, not total scan memory or work.

## Local configuration

The optional `~/.config/datafog/policy.toml` reloads at the next tool call. A batch uses one policy snapshot. `DATAFOG_POLICY_PATH` can select another absolute file path. Missing policy means defaults; malformed or unknown settings fail clearly without echoing policy contents.

Example (create the output directory separately and ensure it is allowed):

```toml
version = 1

[allow.exact]
EMAIL = ["test@example.com"] # Exact and case-sensitive; applies to every tool

[output]
directory = "~/Documents/datafog-output"

[workflow]
on_findings = "ask" # ask | transform | proceed | stop
transform_strategy = "redact" # redact | mask | remove | pseudonymize

[scope]
folders = ["~/Downloads", "~/Documents/customer-data"]
extensions = [".csv", ".txt", ".log"]

[logging]
enabled = false

[limits]
max_file_bytes = 100000000
max_text_bytes = 1048576
max_findings = 1000
max_batch_files = 1000
```

Omitted/empty scope filters mean all data files, with no automatic Git or project exemption. Scope defines advisory scan-before-read behavior; an explicit scan outside that scope still runs if access is permitted. Allowlisted matches remain in output copies and are excluded from actionable counts. Responses indicate policy and allowlist application without listing allowed values.

For `on_findings="transform"`, the agent is told to use the configured strategy. Pseudonymization additionally requires `scope="customer_analysis"` in `[workflow]` and a matching scope definition below. The server returns guidance; it does not automatically read, send, or transform a file after a scan.

### Filesystem access

Allowed roots remain separate from workflow policy:

```bash
datafog-mcp roots
datafog-mcp roots --edit
```

`~/.config/datafog/allowed_roots` contains one absolute path per line, with `~` expanded. Without this file or an override, the root is the user's home. `DATAFOG_MCP_ALLOWED_ROOTS` (platform path-separator separated) overrides it. Empty configuration refuses all paths; malformed configuration fails without falling back. Roots-file edits take effect on subsequent operations.

Both reads and writes enforce roots and resolve symlinks. Credential directories `.ssh`, `.gnupg`, `.aws`, `.kube`, and `gcloud` remain blocked. DataFog configuration/key/activity files and configured model assets cannot be treated as ordinary data inputs or outputs. Selecting an output directory never grants access to it.

### Pseudonymization keys

Add a named scope to the policy:

```toml
[pseudonymization.scopes.customer_analysis]
key_ref = "customer-analysis"
key_version = "1"
backend = "keyring" # Default: OS credential store
```

Then explicitly create its key:

```bash
datafog-mcp keys create customer_analysis
```

Call `datafog_pseudonymize` with `path` and `scope="customer_analysis"`. Core 0.4.1 uses HMAC-SHA-256; identical exact values and the same secret produce consistent opaque pseudonyms across files and server restarts. Changing case, spacing, detection boundaries, or the key changes the result. This is one-way, not decryptable tokenization.

Desktop storage uses supported macOS/Windows/Linux credential-store backends via `keyring`; a locked/unavailable store fails explicitly. There is no automatic plaintext fallback. For POSIX headless environments choose `backend="file"` and an absolute `key_file` path in that scope. Create its parent directory first. Key files must be owner-controlled, mode 0600, without symlinks or hardlinks. The file backend is not supported on Windows.

Keys never belong in TOML or tool arguments. Setup does not replace existing keys, and tool calls never generate missing ones. Back up and transfer keys securely if joins must survive machine changes. Copying policy alone is insufficient. For explicit rotation, use a new reference/version (and a different file path for file storage), retain old keys if needed, and expect new outputs to stop joining old outputs. Unrelated scopes should have separate keys; scope names alone do not alter HMAC behavior.

### Optional experimental name/address model

A compatible local native bundle can be selected with:

```toml
[model]
bundle_directory = "/absolute/path/to/native-bundle"
timeout_seconds = 30
```

The bundle and runtime must be installed separately before serving. This enables `PERSON` and `STREET_ADDRESS` alongside the deterministic detectors. Without it, explicit model-type requests fail rather than falsely reporting clean results. Configured inference failures also fail explicitly; there is no silent downgrade. Model weights are not automatically fetched, and this configuration is not a claim that the checkpoint passed release acceptance. See [validation coverage](docs/validation/current-coverage.md) for qualification boundaries.

### Activity logging and privacy

Set `[logging].enabled=true` to write a local JSONL log (default `~/.local/state/datafog/activity.jsonl`; optional absolute `path`). Records contain time, operation, outcome, and entity counts, never paths, input contents, or matched values. The log is created with private permissions. At 10 MB or on an unavailable/unsafe destination, logging stops and successful tool responses report `activity_log="unavailable"`; operations do not overwrite/rotate the log. Users manage retention locally. A log establishes which DataFog operations ran, not whether every agent read was checked.

Tool responses include paths, entity metadata, and CSV header names. Those can themselves be identifying; CSV headers are source metadata, not guaranteed nonsensitive text. Direct text-check arguments are already in agent context and may be retained by the host. DataFog cannot control host logs or external telemetry exporters a user separately installs. Unexpected exception details are withheld from tool responses and server error logs.

## Development and validation

```bash
uv sync --group dev
uv run pre-commit install
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pyright
uv run pytest
```

CI runs these checks on Python 3.10–3.12, including deterministic product contracts and a real offline stdio session. Ordinary tests isolate policy files and use temporary credentials; they must not touch personal keychains or model downloads. A separate [GLiNER fixture comparison](docs/validation/gliner-fixtures.md) downloads pinned public weights in an isolated GitHub Actions job; its diagnostic metrics do not qualify the shipped local detector. See [current validation coverage](docs/validation/current-coverage.md) and the [implementation plan](docs/plans/user-flow-implementation.md).

## Uninstall

Remove the MCP registration before uninstalling the executable:

```bash
claude mcp remove datafog --scope user
uv tool uninstall datafog-mcp
```

For another client, remove its server configuration. Policy, roots, optional logs, keys, model artifacts, and transformed copies are retained for deliberate user cleanup. Do not delete keys needed to reproduce pseudonyms or join future exports. Remove environment overrides from shell/client configuration if no longer needed.

## License

MIT

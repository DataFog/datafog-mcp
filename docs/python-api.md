# Python interface

`datafog_mcp.api` gives another program the rules the MCP server applies: allowed roots, the owner's `policy.toml`, file reading, and the scan pipeline. It is meant for short-lived processes that run beside the server, such as a hook that checks each tool call.

```python
from datafog_mcp import api
```

> **Provisional.** This interface is new in this release. Names and signatures may change in the next minor version; pin the package version if you depend on it.

Importing it does not import `fastmcp` or `mcp` and starts nothing. Measured with `python -X importtime`, the import is roughly 20 times faster than importing `datafog_mcp.server`. Absolute timings are machine-dependent, so measure on your own hardware if a hook has a time budget. The package ships a `py.typed` marker, so type checkers use its annotations. Only the names listed here belong to the interface; other modules in the package can change without notice.

## Example

```python
from datafog_mcp import api


def check(path: str) -> dict[str, int]:
    current = api.load_policy()  # one snapshot per request
    content = api.read_text_file(path, api.DEFAULT_MAX_BYTES)  # enforces allowed roots
    if not current.in_scope(content.path):
        return {}
    result = api.process_text(content.text, policy=current, source=content.path)
    return api.counts_by_type(result.transformations)
```

Report failures by exception type unless the exception is one of those listed under [What is and is not returned](#what-is-and-is-not-returned).

## Owner policy

| Name | Signature | Purpose |
| --- | --- | --- |
| `load_policy` | `() -> Policy` | Read and validate `policy.toml`. An absent file gives the defaults; an unusable one raises `PolicyFileError`, including one whose copy directory or scope folder is the vault or inside it. |
| `Policy.is_allowlisted` | `(entity_type: str, value: str) -> bool` | Whether the owner approved exactly this value for this type. |
| `Policy.allowlist_counts` | `dict[str, int]` | Approved values per entity type, as counts. |
| `Policy.in_scope` | `(path: Path) -> bool` | Whether a resolved path is in the routine scanning scope. Check roots first. |
| `Policy.scope_folders`, `available_scope_folders`, `missing_scope_folders` | `tuple[Path, ...]` | Configured, usable, and missing scope folders. |
| `Policy.scope_extensions` | `tuple[str, ...]` | Lower-cased extensions in scope; empty means all. |
| `Policy.on_findings` | `"ask" \| "transform" \| "stop"` (`Action`) | Advisory workflow action. |
| `Policy.transform_strategy` | `"redact" \| "mask" \| "remove"` (`Strategy`) | Suggested strategy for `transform`. |
| `Policy.directory` | `Path \| None` | Owner-chosen copy destination. |
| `Policy.warnings` | `list[str]` | Content-free warnings, such as missing scope folders. |

A loaded policy is an immutable snapshot. Load one per request and pass it through. `PolicyFileError` is raised for an unusable `policy.toml`.

`Policy`, `load_policy`, `PolicyFileError`, and `RootPolicyError` are this interface's names for what the package's own modules call `OutputPolicy`, `load_output_policy`, `OutputPolicyError`, and `PolicyError`. They are the same objects, so a traceback shows the older class names. The older names remain importable from `datafog_mcp.policy` and `datafog_mcp.paths` but are not part of this interface.

## Allowed roots and reading

| Name | Signature | Purpose |
| --- | --- | --- |
| `allowed_roots` | `() -> tuple[Path, ...]` | The roots in force. |
| `root_policy` | `() -> RootPolicy` | The roots and where they were configured (`.roots`, `.source`). |
| `resolve_input` | `(path: str) -> Path` | Resolve a path, following symlinks, and check it against roots and credential directories. Raises `PathNotAllowed`. |
| `read_text_file` | `(path: str, max_bytes: int) -> FileContent` | Check the path, then read UTF-8 text up to the limit. Raises `PathNotAllowed` or a `ReadError` (`PathNotFound`, `NotARegularFile`, `FileTooLarge`, `NotText`). |
| `ALLOWED_ROOTS_VAR`, `DENIED_DIR_NAMES`, `DEFAULT_MAX_BYTES` | constants | The roots variable name, the always-refused directory names, and the 10 MB limit. |

`RootPolicyError` is the `PathNotAllowed` raised when the roots configuration, or the vault setting, is itself unusable. It is not raised by `load_policy`; that raises `PolicyFileError`.

`resolve_input` and `read_text_file` refuse every path inside the configured vault directory, after following symlinks, exactly as the server's tools do.

## Scanning

| Name | Signature | Purpose |
| --- | --- | --- |
| `process_text` | `(text: str, *, policy: Policy, source: str \| Path = "", config: ScanConfig \| None = None, strategy: Strategy = "redact", input_format: InputFormat = "auto", has_header: bool = True) -> CellResult` | Run the server's pipeline on text already in memory. |
| `ScanConfig` | `(entities: tuple[str, ...] = DEFAULT_ENTITIES, max_bytes: int = DEFAULT_MAX_BYTES)` | The entity types to detect. Unsupported or empty selections raise `ValueError`. |
| `DEFAULT_ENTITIES`, `SUPPORTED_ENTITIES` | `tuple[str, ...]`, `frozenset[str]` | The default and selectable entity types. |
| `counts_by_type` | `(items: Sequence[Located]) -> dict[str, int]` | Tally results per entity type. |
| `process_csv` | `(text: str, process_cell: CellProcessor, *, has_header: bool = True, delimiter: str = ",") -> CsvResult` | The table walker on its own, for a caller supplying its own per-cell function. |

`process_text` uses `source` only for its filename, to choose a format when `input_format` is `auto`: `.csv` and `.tsv` are scanned cell by cell with header context, ENV and SQL filenames select their email boundaries, and anything else is plain text. Exact allowlists from the policy apply before overlaps are resolved. It does not check roots or read the disk; use `read_text_file` for that.

The result has two parts:

- `transformations`: one item per detection, with `entity_type` and `source_codepoint_range` (`start`, `end`) in the original text. Table results are `CsvFinding` objects that add one-based `record` and `column`.
- `text`: the input with each detection replaced according to `strategy`.

It raises `CsvError` for a malformed table and `OverlapConflict` when detections of different types partly overlap. An `input_format` or `strategy` that is not one of the allowed values raises `ValueError`; the message lists the allowed values (`input_format must be one of: auto, text, csv, tsv, env, sql` or `strategy must be one of: mask, redact, remove`) and does not repeat the argument. Values are case-sensitive.

## Vault location

| Name | Signature | Purpose |
| --- | --- | --- |
| `vault_dir` | `() -> Path \| None` | The validated `DATAFOG_VAULT_DIR`, or `None` when unset. Raises `VaultConfigError`. |
| `vault_configured` | `() -> bool` | Whether a usable location is set. Raises `VaultConfigError`. |
| `VAULT_DIR_VAR` | constant | The variable's name. |

See [application vault location](policy.md#application-vault-location) for the rules. These functions validate the location only; nothing here reads or writes the vault. Leave the variable out of the environment when there is no vault: an empty value is an error.

## What is and is not returned

- **Matched values are not returned.** Results carry entity types, counts, and positions. `text` is the transformed input, so it still holds everything that was not detected; discard it if you only need to know what was found. Table header text is not returned.
- **Approved allowlist values never appear in results, reprs, or errors, but the policy holds them.** `is_allowlisted` answers yes or no for a value you already hold, and `allowlist_counts` gives counts. The values do not appear in scan results, in `repr()` or `str()` of the policy or of its allowlist mapping, or in any error message. `Policy.allow_exact` does hold them in memory in order to match, and reading that attribute gives you the values. Do not serialize, log, or return `allow_exact` or its contents, for example through `dataclasses.asdict`, `vars`, JSON, or pickle.
- **These errors are written to be shown:** `PolicyFileError`, `CsvError`, `OverlapConflict`, and `VaultConfigError`, and the `ValueError` that `process_text` raises for an unknown `input_format` or `strategy`. Their messages hold no file content, no allowlist value, no policy path, and no vault location.
- **Path errors name paths.** `PathNotAllowed`, `RootPolicyError`, and `ReadError` messages include the path involved and the allowed roots, as the server's tool errors do. A filename can identify a person on its own. A path refused for being inside the vault is the exception: that message names no path.
- **`vault_dir` returns the location** to your program. The MCP server reports only whether one is configured.
- **Any other exception may quote the text.** An unexpected engine failure can carry input in its message. Report its type, as the server does, not its message.

[Back to the README](../README.md)

# Python interface

`datafog_mcp.api` gives another program the rules the MCP server applies: allowed roots, the owner's `policy.toml`, file reading, and the scan pipeline. It is meant for short-lived processes that run beside the server, such as a hook that checks each tool call.

```python
from datafog_mcp import api
```

Importing it does not import `fastmcp` or `mcp` and starts nothing. Measured with `python -X importtime` on a Linux arm64 test machine with Python 3.12, the import takes roughly 15 to 20 ms, against roughly 300 to 450 ms for `datafog_mcp.server`. Only the names listed here are supported; other modules in the package can change without notice.

## Example

```python
from datafog_mcp import api


def check(path: str) -> dict[str, int]:
    current = api.load_output_policy()  # one snapshot per request
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
| `load_output_policy` | `() -> OutputPolicy` | Read and validate `policy.toml`. An absent file gives the defaults; an unusable one raises `OutputPolicyError`. |
| `OutputPolicy.is_allowlisted` | `(entity_type: str, value: str) -> bool` | Whether the owner approved exactly this value for this type. |
| `OutputPolicy.allowlist_counts` | `dict[str, int]` | Approved values per entity type, as counts. |
| `OutputPolicy.in_scope` | `(path: Path) -> bool` | Whether a resolved path is in the routine scanning scope. Check roots first. |
| `OutputPolicy.scope_folders`, `available_scope_folders`, `missing_scope_folders` | `tuple[Path, ...]` | Configured, usable, and missing scope folders. |
| `OutputPolicy.scope_extensions` | `tuple[str, ...]` | Lower-cased extensions in scope; empty means all. |
| `OutputPolicy.on_findings` | `"ask" \| "transform" \| "stop"` (`Action`) | Advisory workflow action. |
| `OutputPolicy.transform_strategy` | `"redact" \| "mask" \| "remove"` (`Strategy`) | Suggested strategy for `transform`. |
| `OutputPolicy.directory` | `Path \| None` | Owner-chosen copy destination. |
| `OutputPolicy.warnings` | `list[str]` | Content-free warnings, such as missing scope folders. |

A loaded policy is an immutable snapshot. Load one per request and pass it through.

## Allowed roots and reading

| Name | Signature | Purpose |
| --- | --- | --- |
| `allowed_roots` | `() -> tuple[Path, ...]` | The roots in force. |
| `root_policy` | `() -> RootPolicy` | The roots and where they were configured (`.roots`, `.source`). |
| `resolve_input` | `(path: str) -> Path` | Resolve a path, following symlinks, and check it against roots and credential directories. Raises `PathNotAllowed`. |
| `read_text_file` | `(path: str, max_bytes: int) -> FileContent` | Check the path, then read UTF-8 text up to the limit. Raises `PathNotAllowed` or a `ReadError` (`PathNotFound`, `NotARegularFile`, `FileTooLarge`, `NotText`). |
| `ALLOWED_ROOTS_VAR`, `DENIED_DIR_NAMES`, `DEFAULT_MAX_BYTES` | constants | The roots variable name, the always-refused directory names, and the 10 MB limit. |

`PolicyError` is the `PathNotAllowed` raised when the roots configuration itself is unusable.

## Scanning

| Name | Signature | Purpose |
| --- | --- | --- |
| `process_text` | `(text: str, *, policy: OutputPolicy, source: str \| Path = "", config: ScanConfig \| None = None, strategy: Strategy = "redact", input_format: InputFormat = "auto", has_header: bool = True) -> CellResult` | Run the server's pipeline on text already in memory. |
| `ScanConfig` | `(entities: tuple[str, ...] = DEFAULT_ENTITIES, max_bytes: int = DEFAULT_MAX_BYTES)` | The entity types to detect. Unsupported or empty selections raise `ValueError`. |
| `DEFAULT_ENTITIES`, `SUPPORTED_ENTITIES` | `tuple[str, ...]`, `frozenset[str]` | The default and selectable entity types. |
| `counts_by_type` | `(items: Sequence[Located]) -> dict[str, int]` | Tally results per entity type. |
| `process_csv` | `(text: str, process_cell: CellProcessor, *, has_header: bool = True, delimiter: str = ",") -> CsvResult` | The table walker on its own, for a caller supplying its own per-cell function. |

`process_text` uses `source` only for its filename, to choose a format when `input_format` is `auto`: `.csv` and `.tsv` are scanned cell by cell with header context, ENV and SQL filenames select their email boundaries, and anything else is plain text. Exact allowlists from the policy apply before overlaps are resolved. It does not check roots or read the disk; use `read_text_file` for that.

The result has two parts:

- `transformations`: one item per detection, with `entity_type` and `source_codepoint_range` (`start`, `end`) in the original text. Table results are `CsvFinding` objects that add one-based `record` and `column`.
- `text`: the input with each detection replaced according to `strategy`.

It raises `CsvError` for a malformed table and `OverlapConflict` when detections of different types partly overlap.

## Vault location

| Name | Signature | Purpose |
| --- | --- | --- |
| `vault_dir` | `() -> Path \| None` | The validated `DATAFOG_VAULT_DIR`, or `None` when unset. Raises `VaultConfigError`. |
| `vault_configured` | `() -> bool` | Whether a usable location is set. Raises `VaultConfigError`. |
| `VAULT_DIR_VAR` | constant | The variable's name. |

See [application vault location](policy.md#application-vault-location) for the rules. These functions validate the location only; nothing here reads or writes the vault.

## What is and is not returned

- **Matched values are not returned.** Results carry entity types, counts, and positions. `text` is the transformed input, so it still holds everything that was not detected; discard it if you only need to know what was found. Table header text is not returned.
- **Approved allowlist values are not returned.** `is_allowlisted` answers yes or no for a value you already hold, and `allowlist_counts` gives counts. The values do not appear in `repr()` or `str()` of the policy or of its allowlist mapping, or in any error message. The policy object holds them in memory in order to match, so do not serialize its attributes yourself.
- **These errors are written to be shown:** `OutputPolicyError`, `CsvError`, `OverlapConflict`, and `VaultConfigError`. Their messages hold no file content, no allowlist value, and no vault location.
- **Path errors name paths.** `PathNotAllowed`, `PolicyError`, and `ReadError` messages include the path involved and the allowed roots, as the server's tool errors do. A filename can identify a person on its own.
- **`vault_dir` returns the location** to your program. The MCP server reports only whether one is configured.
- **Any other exception may quote the text.** An unexpected engine failure can carry input in its message. Report its type, as the server does, not its message.

[Back to the README](../README.md)

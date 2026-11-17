"""
The supported Python interface to DataFog's owner policy and scanning.

For programs that run beside the MCP server, such as a hook that checks each
tool call, and need the same answers the server gives: which directories are
allowed, what the owner's policy.toml says, and what a file or a piece of text
contains. Importing this module does not import fastmcp or mcp and starts
nothing.

Every name in __all__ is supported; anything else in the package may change.

What this interface returns, and what it does not:

- Scan results carry entity types, counts, and positions, plus the transformed
  text. They never carry a matched value or a table's header text.
- Approved allowlist values are never returned. OutputPolicy.is_allowlisted
  answers yes or no for a value the caller already holds, and
  OutputPolicy.allowlist_counts gives a count per entity type. The values are
  absent from the policy's repr() and str() and from every error message.
- Policy, table, overlap, and vault errors (OutputPolicyError, CsvError,
  OverlapConflict, VaultConfigError) have messages written to be shown: they
  hold no file content, no allowlist value, and no vault location.
- Path and read errors (PathNotAllowed, PolicyError, ReadError) name the
  path involved and the allowed roots, as the server's tool errors do. A
  filename can identify a person on its own.
- vault_dir returns the configured location to the calling program. The MCP
  server reports only whether one is configured.
- Any other exception raised while scanning may quote the text in its
  message. Report its type, not its message.

Each call reads the configuration afresh, so edits to the roots file,
policy.toml, or the environment take effect on the next call. Load one
OutputPolicy per request and pass it through, so every step of that request
sees the same settings.
"""

from __future__ import annotations

from .config import (
    DEFAULT_ENTITIES,
    DEFAULT_MAX_BYTES,
    SUPPORTED_ENTITIES,
    ScanConfig,
    Strategy,
)
from .csv_processing import CellProcessor, CellResult, CsvError, CsvResult, process_csv
from .findings import CsvFinding, Located, counts_by_type
from .paths import (
    ALLOWED_ROOTS_VAR,
    DENIED_DIR_NAMES,
    PathNotAllowed,
    PolicyError,
    RootPolicy,
    allowed_roots,
    resolve_input,
)
from .paths import policy as root_policy
from .policy import Action, OutputPolicy, OutputPolicyError, load_output_policy
from .reader import (
    FileContent,
    FileTooLarge,
    NotARegularFile,
    NotText,
    PathNotFound,
    ReadError,
    read_text_file,
)
from .scanning import InputFormat, OverlapConflict, process_text
from .vault import VAULT_DIR_VAR, VaultConfigError, vault_configured, vault_dir

__all__ = [
    "ALLOWED_ROOTS_VAR",
    "DEFAULT_ENTITIES",
    "DEFAULT_MAX_BYTES",
    "DENIED_DIR_NAMES",
    "SUPPORTED_ENTITIES",
    "VAULT_DIR_VAR",
    "Action",
    "CellProcessor",
    "CellResult",
    "CsvError",
    "CsvFinding",
    "CsvResult",
    "FileContent",
    "FileTooLarge",
    "InputFormat",
    "Located",
    "NotARegularFile",
    "NotText",
    "OutputPolicy",
    "OutputPolicyError",
    "OverlapConflict",
    "PathNotAllowed",
    "PathNotFound",
    "PolicyError",
    "ReadError",
    "RootPolicy",
    "ScanConfig",
    "Strategy",
    "VaultConfigError",
    "allowed_roots",
    "counts_by_type",
    "load_output_policy",
    "process_csv",
    "process_text",
    "read_text_file",
    "resolve_input",
    "root_policy",
    "vault_configured",
    "vault_dir",
]

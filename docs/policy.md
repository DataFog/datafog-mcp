# Allowed roots and owner policy

Every read and write is checked against a set of allowed root directories. With no roots file and no override, the allowed root is your home directory.

```bash
datafog-mcp roots          # show the roots in force and where they came from
datafog-mcp roots --edit   # open the roots file in $EDITOR
```

The file is `~/.config/datafog/allowed_roots`, one absolute path per line, with `~` expanded. Edits take effect immediately, so there's no need to restart or re-register. `roots --edit` creates the file starting from `~`, so creating it changes nothing until you narrow it.

`DATAFOG_MCP_ALLOWED_ROOTS` (colon-separated) overrides the file whenever it is set, for installs that shouldn't be widened by editing a file.

A configured policy never falls back to the default:

- **An empty policy refuses every path.** A file that lists no directories, or a variable set to an empty value, locks the server down rather than reverting to your home directory. Delete the file or unset the variable to return to the default.
- **A malformed policy refuses every path and says why.** A relative path, an unreadable file, or something other than a regular file at the file's location is an error, not an absence. Relative paths are refused because they would resolve against whichever directory your MCP client launched the server from.

Always refused, even inside a root: `.ssh`, `.gnupg`, `.aws`, `.kube`, `gcloud`.

A refused path returns a tool error naming the roots in force, or why the policy can't be used.

## Choose where copies go

During setup, create the directory where you want cleaned copies and include both the input directory and output directory in your allowed roots. Then edit the copy policy:

```bash
datafog-mcp policy --edit  # create a private template and open it in $EDITOR
datafog-mcp policy        # show the configured copy destination
```

The file is `~/.config/datafog/policy.toml`:

```toml
version = 1

[output]
directory = "~/Documents/datafog-copies"
```

The directory must already exist and be an absolute path or start with `~`. The server creates files directly inside it, retaining the usual `_redacted`, `_masked`, or `_removed` names. It never creates directories automatically. Setting this destination grants no additional access: allowed roots, credential-directory denials, and the configuration-directory write refusal still apply. If two inputs produce the same output name, use an explicit destination path inside the configured directory; existing copies are never overwritten.

Edits take effect on the next request. A missing policy file uses sibling copies. A valid file containing just `version = 1` also explicitly selects sibling copies. An empty, malformed, unreadable, or unsupported policy refuses scans and writes rather than falling back.

## Files to scan before reading and workflow guidance

Allowed roots are the permission boundary. Scanning scope selects files **within that boundary** for routine checks before reading; it never grants access. Explicit scans and writes remain available for files outside the routine scope when roots permit them.

Extend the same `policy.toml` with optional sections:

```toml
version = 1

[allow.exact]
EMAIL = ["public-support@example.com"]

[scope]
folders = ["~/Downloads/customer-exports"]
extensions = [".csv", ".tsv"]

[workflow]
on_findings = "ask"
transform_strategy = "redact"
```

Scanning folders must resolve inside allowed roots. Missing folders are reported as inactive rather than blocking scans or writes. Validation expands `~`, follows symlinks, and refuses credential directories. Narrowing roots or retargeting a symlink takes effect on the next request; outside-root or credential-directory settings, permission errors, and non-directory entries still cause a configuration error. Missing folders are rechecked on every request and become active again if recreated within the allowed roots. An omitted/empty folder list means all allowed directories, and an omitted/empty extension list means all extensions. A configured folder list whose entries are all missing matches no routine files; it never expands to all allowed directories. When both are provided, both must match. Extensions are dot-prefixed and matched without regard to case. These settings describe routine checks; existing advice about avoiding unnecessary scans of project source/configuration still applies.

Exact allowlists suppress a complete detected value only for its configured entity type, with no case folding, whitespace normalization, substring matching, or regex rules. They apply before overlap resolution in scans and all write tools, including decoded CSV/TSV cell values. Header labels supply detector context and are not part of the value matched against an allowlist. A value that also matches another detector can still be reported or transformed under that other type. Approved values remain in copies, so configure only values you intentionally permit to remain. Allowlist values are never included in tool responses or error messages.

The agent can call `datafog_policy` to discover scope, workflow settings, copy destination, and allowlist counts. With an optional `path`, it checks roots and reports `scan_before_read`; it does not read or scan the file. Its scope metadata distinguishes configured, available, and missing folders. Missing-folder warnings also appear in file-tool responses and the owner CLI. A scope match is a scheduling instruction, never evidence that a file is clean.

Completed scans return advisory `policy.action`: `ask` (default), `transform`, or `stop` when non-allowlisted findings remain; `proceed` when none remain under the selected detectors and allowlists. `transform` includes the suggested strategy (`redact`, `mask`, or `remove`). Scans never automatically write a copy. Explicit write tools retain the strategy requested by the caller. These actions guide the agent; the server cannot prevent access through another tool. Failed scans or invalid policies never authorize a fallback read of the original.

## Application vault location

An application that launches the server, such as a plugin, can tell it where that application keeps its vault by setting `DATAFOG_VAULT_DIR` in the server's environment. This only records the location: the server does not create the directory, read from it, or write to it.

The environment variable is the only source. There is no `policy.toml` setting and no default location, so a server started without the variable has no vault, and nothing in a configuration file can add or change one.

The value must be an absolute path or start with `~`. Symlinks are followed, and a location inside a credential directory (`.ssh`, `.gnupg`, `.aws`, `.kube`, `gcloud`) is refused. The directory does not have to exist yet, but anything already at the path must be a directory. It may sit inside or outside the allowed roots.

**The file tools never touch the vault.** `datafog_scan`, `datafog_redact`, `datafog_mask`, `datafog_remove`, and the path check in `datafog_policy` refuse any path that is the vault directory or inside it, as they refuse credential directories. This applies to input paths, `output_path`, and an owner-configured output directory, and it is checked after symlinks are followed, so a link into the vault is refused too. The error says the path is inside the application vault directory and names neither the path nor the vault.

**An unusable value stops the server from starting.** A variable that is set but unusable, including one set to an empty value, is an error rather than an absent setting. The server exits at startup with a message on stderr naming the variable and the problem, never the value. `datafog-mcp policy` fails the same way; `datafog-mcp roots` is unaffected. A launcher with no vault must leave the variable out of the server's environment rather than set it to an empty string.

`datafog_policy` returns `vault_configured`, `true` or `false`. The location is never included in a tool response or error message. `datafog-mcp policy` prints the same yes or no.

`datafog-mcp policy` shows the same settings to the owner, including counts instead of exact allowlist values. The parser rejects unknown sections/settings so configuration mistakes cannot silently disable a safeguard. Each request uses one immutable policy snapshot; edits apply to subsequent requests.

[Back to the README](../README.md)

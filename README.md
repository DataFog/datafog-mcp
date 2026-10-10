# datafog-mcp

An MCP server that lets an AI agent check a file for personally identifiable information (PII), and produce a cleaned copy, without the file's contents ever appearing in the tool's response.

Detection runs locally on the [datafog-core](https://github.com/DataFog/datafog-core) engine.

**What stays on the machine.** File contents are read and processed locally, and the server makes no network requests while running. FastMCP's update check is switched off, and its OpenTelemetry hooks do nothing unless you install an OpenTelemetry SDK and configure an exporter yourself. Tool responses are a different matter: they go into the agent's context, and the agent sends its context to its model provider. That is why responses carry no file contents or matched values. Installing the server downloads packages, which is separate from running it.

**What this does and does not protect.** No tool response contains file contents or matched values, so "is this file sensitive" can be answered without the answer carrying the sensitive parts. That is the whole of the guarantee. Note that the agent can still open the file directly, and sometimes will.

The guarantee holds when a tool fails, too. An unexpected error returns only its type, such as `datafog failed with RuntimeError`, and its details are kept out of both the response and the server's log.

These checks are advisory and reduce exposure; they do not de-identify data or enforce an agent's file access. They complement enterprise data-loss-prevention (DLP) and endpoint controls rather than replace them. Plain-text names and street addresses are not detected by this installation.

What responses do carry:

- **Paths.** Every response names the files it read and wrote, and errors name the path they refused. A filename like `jane_doe_lab_results.csv` identifies a person on its own.
- **Metadata.** Entity types, per-type counts, and character offsets, plus numeric record/column locations for tables. These reveal that a file holds, say, two email addresses at known positions, without revealing addresses, cell values, or header text.
- **Allowed roots.** A refused path returns the configured roots, which name directories on your machine.

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/)

## Install

Not yet on PyPI. From a checkout:

```bash
uv tool install .
```

That puts `datafog-mcp` on your `PATH`. Register it with your MCP client.
For Claude Code:

```bash
claude mcp add --scope user datafog -- ~/.local/bin/datafog-mcp
```

Bare `datafog-mcp` runs the server over stdio; `datafog-mcp serve` is the same thing spelled out.

The client must be able to launch this executable and access files on this machine. A cloud-hosted agent cannot reach this local stdio server directly. The Claude Code instructions above do not establish support for other clients; those need separate integration testing.

## Tools

File tools take a path and return scan metadata or a copy path. `datafog_policy` discovers owner settings and can check a path's routine scanning scope. None returns file contents or matched values.

| Tool | What it does | Output |
|---|---|---|
| `datafog_policy` | Reports owner settings and an optional path's routine scanning scope | Metadata only |
| `datafog_scan` | Reports entity types, counts, and character offsets (offsets for up to 700 findings) | — |
| `datafog_redact` | Replaces each value with a label naming its kind, `[EMAIL]` | `name_redacted.ext` |
| `datafog_mask` | Covers each value character for character, preserving decoded value length | `name_masked.ext` |
| `datafog_remove` | Deletes each value outright, leaving no marker | `name_removed.ext` |
| `datafog_pseudonymize` | Replaces values consistently using an explicitly configured scope key | `name_pseudonymized.ext` |

A scan lists the offsets of at most 700 findings, to bound response size, including CSV/TSV record and column locations. Above that, `findings` is empty and `findings_listed` is `false`, while `entity_count` and `counts` remain complete. To see where values are in a dense file, scan again with fewer `entity_types`.

The write tools never modify the original. By default they create a sibling of the input. You can choose a fixed output directory in `policy.toml` during setup (see below). An existing file at the destination is never overwritten. `output_path` can choose a filename within that directory, but cannot select another allowed root or a subdirectory. Output filenames beginning with `.` are refused, including missing shell startup files such as `.profile`. Hidden inputs remain scannable; default copies strip leading dots from the input stem (for example, `.env` becomes `env_redacted`).

A copy gets the input's permissions, minus any execute bits, so a file only you can read produces a copy only you can read. A copy can still hold values the detectors missed, so it is never made more readable than its source. If a write fails partway, the incomplete copy is deleted.

Before creating a copy, the server checks the destination filesystem has space for the transformed UTF-8 output. Insufficient space, or an unavailable free-space check, refuses the write. This checks available capacity at that moment; it does not reserve space or account for disk quotas. A later write failure still removes the incomplete copy.

Detected by default:

- **Personal data** — `EMAIL`, `SSN`, `CREDIT_CARD`
- **Financial and health identifiers** — `US_ROUTING_NUMBER`, `NPI`
- **Credentials** — `API_KEY`, `BEARER_TOKEN`, `JWT`, `CREDENTIAL_URI`, `PRIVATE_KEY`

`DATE`, `ZIP_CODE`, `PHONE`, and `IP_ADDRESS` are available but off by default. Dates, ZIP codes, and phone numbers can match operational timestamps or numeric IDs, so enable them when that coverage is needed. A default scan does not check these types, and a default write leaves their values unchanged unless another selected detector also matches them.

Pass `entity_types` to choose the types to check or transform, or omit it for the defaults. An explicit list **replaces** the defaults; it does not add to them. For example, `{"path": "/absolute/path/export.csv", "entity_types": ["EMAIL", "PHONE", "DATE", "ZIP_CODE"]}` checks only those four types. Include every default type you still want when opting into another type. Unsupported types and an empty list are refused.

Some types are narrower than their names suggest:

- **`US_ROUTING_NUMBER` and `NPI`** are found only after a label, such as `Routing number:` or `NPI:`. Table headers supply this label context; bare values in plain text can be missed or reported as another type.
- **`API_KEY`** covers GitHub tokens and Stripe secret and restricted keys. Keys from other providers, such as AWS, are not detected.
- **`BEARER_TOKEN`** is the token in an `Authorization: Bearer` header.
- **`CREDENTIAL_URI`** covers PostgreSQL connection strings that include a password (`postgres://` or `postgresql://`). Other schemes, such as MySQL, Redis, or MongoDB, are not detected.
- **`PRIVATE_KEY`** is a complete PEM private-key block. Public keys and certificates are not reported.

Credential detection is not a substitute for a dedicated secret scanner. A clean result means none of the selected detectors matched; it is not proof a file holds no sensitive data or secrets.

## Supported files

UTF-8 text, up to 10 MB (10,000,000 bytes): CSV, TSV, JSON, logs, SQL dumps, plain text, and similar. CSV/TSV files are scanned as decoded cells; ENV/SQL files use their email boundary rules, and other files use plain-text matching.

### CSV and TSV

All five file tools accept `input_format`: `auto` (default) selects comma-separated CSV for `.csv` and tab-separated TSV for `.tsv`, ignoring extension case; ENV/SQL filenames select their email boundary rules as described below; other extensions use plain text. Choose `csv`, `tsv`, `env`, or `sql` explicitly for another filename, or `text` to force flat scanning.

The first record is a header by default (`has_header=true`). It supplies context for label-sensitive detectors such as NPI and routing numbers, and is preserved without scanning or transforming its contents. Set `has_header=false` for headerless files, or when the first record may itself contain sensitive values that need processing. Header presence is never guessed.

Scan findings add numeric `record` and `column` fields, both one-based; record 1 is the first data record after the header. A quoted multiline cell is part of one record. `start`/`end` remain character offsets into the original raw file, including its BOM, line endings, and doubled quote escapes. Header strings are never returned, because they can contain sensitive data too.

Writes preserve the delimiter, record/column structure, headers, BOM, line endings, and untouched cell syntax. Changed cells are quoted and embedded double quotes escaped; removing the sole value in a one-column record writes `""` rather than a blank line. Masking preserves decoded value length, but added CSV quotes can change the serialized file length.

This supports comma/tab delimiters and double-quote escaping, including quoted multiline values and duplicate or empty headers. Trailing blank lines, ragged rows, and literal quotes inside unquoted fields are accepted and preserved. Missing cells are not filled in; extra cells are scanned without header context. Quoted tabs and multiline cells remain supported in TSV. Unterminated quoted fields, trailing text after a closing quote, and interior blank records are refused with a content-free error naming the record and column (error records include the header). The error suggests an explicit plain-text scan, whose transformed copies do not guarantee table structure. Empty and header-only files are valid. Other delimiters and backslash escaping require conversion or an explicit plain-text scan; plain-text transformation does not guarantee table structure.

Email matching uses format-specific boundaries in ENV and SQL files. With the default `input_format="auto"`, `.env`, `.env.*`, and `*.env` filenames select ENV boundaries; `*.sql` selects SQL boundaries, ignoring filename case. CSV and TSV use plain-text email boundaries within each decoded cell. Other files use plain-text boundaries. All five file tools accept an explicit `input_format` of `env`, `sql`, or `text` to override the filename.

For example, an ENV copy preserves `EMAIL=` and surrounding quotes while transforming the address; a SQL copy preserves the quotes surrounding a string value. Scan offsets refer to the email's span in the original file, including doubled SQL quotes within the address, using Unicode character positions. This is not a full ENV or SQL parser: SQL backslash escapes, dollar quoting, and encoded email characters are not interpreted.

Refused with an error, never scanned:

- **Other encodings.** UTF-16, UTF-32, Latin-1, and so on. Convert to UTF-8 first. A UTF-8 byte-order mark, as Excel writes, is fine and is kept in the copy.
- **Binary files.** XLSX, PDF, DOCX, images, and archives such as ZIP are not parsed. Export to CSV or text first.
- **Anything over 10 MB.**

A refusal is not a clean result. It means the file was not checked.

## Where it may look

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

### Choose where copies go

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

The directory must already exist and be an absolute path or start with `~`. The server creates files directly inside it, retaining the usual `_redacted`, `_masked`, `_removed`, or `_pseudonymized` names. It never creates directories automatically. Setting this destination grants no additional access: allowed roots, credential-directory denials, and the configuration-directory write refusal still apply. If two inputs produce the same output name, use an explicit destination path inside the configured directory; existing copies are never overwritten.

Edits take effect on the next request. A missing policy file uses sibling copies. A valid file containing just `version = 1` also explicitly selects sibling copies. An empty, malformed, unreadable, or unsupported policy refuses scans and writes rather than falling back.

### Files to scan before reading and workflow guidance

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

Completed scans return advisory `policy.action`: `ask` (default), `transform`, or `stop` when non-allowlisted findings remain; `proceed` when none remain under the selected detectors and allowlists. `transform` includes the suggested strategy (`redact`, `mask`, `remove`, or `pseudonymize`). With `pseudonymize`, it also includes the configured `pseudonym_scope`. Scans never automatically write a copy. Explicit write tools retain the strategy requested by the caller. These actions guide the agent; the server cannot prevent access through another tool. Failed scans or invalid policies never authorize a fallback read of the original.

`datafog-mcp policy` shows the same settings to the owner, including counts instead of exact allowlist values. The parser rejects unknown sections/settings so configuration mistakes cannot silently disable a safeguard. Each request uses one immutable policy snapshot; edits apply to subsequent requests.

### Consistent pseudonyms and local key setup

Use `datafog_pseudonymize(path, scope)` when analysis needs to link repeated values across files. Core creates deterministic keyed pseudonyms: the same exact value and entity type, with the same key, produces the same replacement. Separate keys separate linkage; different scope names alone do not. Changes in case, formatting, or detector boundaries may affect matches. Pseudonymization preserves linkage and does **not** make data anonymous.

The same `input_format` and `has_header` options apply as for the other file tools. CSV/TSV pseudonyms use decoded values, preserving headers, table structure, and untouched cell syntax; exact allowlists still apply. Missing scanning folders return the same warnings without blocking explicit pseudonymization or widening routine scope.

Configure a scope in `~/.config/datafog/policy.toml`. Keys never belong in the policy, tool arguments, or environment variables:

```toml
version = 1

[pseudonymization.scopes.customers]
key_ref = "customer-analysis"
key_version = "1"
backend = "keyring"
```

Then explicitly create its key locally:

```bash
datafog-mcp keys create customers
```

The default backend accepts only OS credential stores supported by `keyring`: macOS Keychain, Windows Credential Manager, Linux Secret Service/libsecret, or KWallet. The OS store must be configured and unlocked. Plaintext, fallback, and chained backends are refused; explicitly select a supported OS backend if your keyring setup normally uses a chain. An unavailable or locked store fails instead of switching to a file. Setup never intentionally replaces an existing key and prints no key material. Concurrent OS-store setup commands use a local `.key-setup.lock` directory beside the policy; a stale lock must be inspected and removed locally before retrying.

For a headless **POSIX** system, explicitly select file storage instead:

```toml
[pseudonymization.scopes.customers]
key_ref = "customer-analysis"
key_version = "1"
backend = "file"
key_file = "/home/service/.config/datafog/keys/customers.key"
```

Create the private parent directory yourself (`mkdir -p` and `chmod 700`), then run the same `keys create customers` command. The path must be absolute (or start with `~`), without `..` or symlinks in any component. Use the actual canonical path if a directory such as `/tmp` is a symlink on your OS. Setup exclusively creates an owner-only `0600` file containing a base64-encoded 256-bit random key; this backend is protected by filesystem permissions, not encryption at rest. Retrieval requires a regular file owned by the current user, exactly `0600`, with one hard link. Symlinks, hard links, malformed keys, and unavailable storage are refused. File storage is not supported on Windows.

Missing keys fail even when the input has no findings. MCP tools never create keys, rotate them, or choose a different backend. Each request resolves one key snapshot. Configured key files and their symbolic/hard-link aliases are refused as data inputs and copy destinations. Copies retain the existing roots, fixed-directory, no-overwrite, permission, and disk-space safeguards; exact allowlists still apply. Tool responses expose paths and counts, never keys, matched values, pseudonyms, or content digests.

To recommend this strategy after a scan, add:

```toml
[workflow]
on_findings = "transform"
transform_strategy = "pseudonymize"
pseudonym_scope = "customers"
```

`datafog_policy` and `datafog-mcp policy` expose configured scope names without retrieving keys. A workflow naming an absent scope is invalid. Preserve the key, reference/version, and policy securely if future outputs must remain joinable. Deleting or replacing a key breaks linkage with earlier outputs; no key export, recovery, or rotation command is provided in this release.

## Uninstall

Remove the registration first. If the program goes first, Claude Code fails to start `datafog` in every session (`ENOENT`) until the registration is removed too.

```bash
claude mcp remove datafog --scope user
uv tool uninstall datafog-mcp
```

Then remove the configuration, if you created it with `datafog-mcp roots --edit`:

```bash
rm ~/.config/datafog/allowed_roots
```

The optional `~/.config/datafog/policy.toml` stores your copy destination, exact allowlists, routine scanning scope, and workflow guidance. Keep it for reinstalling, or remove it separately if you want to discard those settings. Removing it does not delete any copies or pseudonymization keys.

If you remove both configuration files, `rmdir ~/.config/datafog` removes the now-empty directory.

If you set `DATAFOG_MCP_ALLOWED_ROOTS` in your shell profile, remove it there.

The server keeps no cache, log, or data directory of its own.

These remain, on purpose:

- **Copies the tools wrote.** These are your files, saved beside their originals or in your configured output directory with `_redacted`, `_masked`, `_removed`, or `_pseudonymized` in the name, and they may still hold values the detectors missed. Uninstalling doesn't touch them. To find them, review the results before deleting anything:

  ```bash
  find ~ \( -name '*_redacted.*' -o -name '*_masked.*' -o -name '*_removed.*' -o -name '*_pseudonymized.*' \) -type f
  ```

- **Pseudonymization keys.** Uninstalling does not delete keys from the OS credential store or your explicitly configured private files. Preserve them for future joins, or delete them manually only when you intend to lose that linkage. A key file in the configuration directory will also prevent `rmdir` from removing it.

- **Claude Code's logs about the server.** Claude Code records its connections to each MCP server and keeps those records after the server is gone. They're under `~/.cache/claude-cli-nodejs/*/mcp-logs-datafog/` on Linux and `~/Library/Caches/claude-cli-nodejs/*/mcp-logs-datafog/` on macOS, and you can delete them.

For another MCP client, remove the `datafog` entry from that client's MCP configuration in place of the `claude mcp remove` step.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the changelog policy and exemption process.

MCP passes its default or explicit `entity_types` to Core before scanning, including decoded CSV/TSV cells. Only selected detectors run. This requires datafog-core 0.4.3 or later.

```bash
uv sync --group dev
uv run pre-commit install
```

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pyright && uv run pytest
```

Runtime dependencies are audited for known advisories weekly, on every push to `main`, and on any pull request that changes them. To run the same audit of the locked dependencies locally:

```bash
uv export --frozen --no-dev --no-emit-project -o locked.txt && uvx pip-audit --disable-pip -r locked.txt
```

## License

MIT

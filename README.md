# datafog-mcp

An MCP server that lets an AI agent check a file for personally identifiable information (PII), and produce a cleaned copy, without the file's contents ever appearing in the tool's response.

Detection runs locally on the [datafog-core](https://github.com/DataFog/datafog-core) engine.

**What stays on the machine.** File contents are read and processed locally, and the server makes no network requests while running. FastMCP's update check is switched off, and its OpenTelemetry hooks do nothing unless you install an OpenTelemetry SDK and configure an exporter yourself. Tool responses are a different matter: they go into the agent's context, and the agent sends its context to its model provider. That is why responses carry no file contents or matched values. Installing the server downloads packages, which is separate from running it.

**What this does and does not protect.** No tool response contains file contents or matched values, so "is this file sensitive" can be answered without the answer carrying the sensitive parts. That is the whole of the guarantee. Note that the agent can still open the file directly, and sometimes will.

The guarantee holds when a tool fails, too. An unexpected error returns only its type, such as `datafog failed with RuntimeError`, and its details are kept out of both the response and the server's log.

These checks are advisory and reduce exposure; they do not de-identify data or enforce an agent's file access. They complement enterprise data-loss-prevention (DLP) and endpoint controls rather than replace them. Plain-text names and street addresses are not detected by this installation.

What responses do carry:

- **Paths.** Every response names the files it read and wrote, and errors name the path they refused. A filename like `jane_doe_lab_results.csv` identifies a person on its own.
- **Metadata.** Entity types, per-type counts, and character offsets. These reveal that a file holds, say, two email addresses at known positions, without revealing the addresses.
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

Every tool takes a path and returns a path. None returns file contents or matched values.

| Tool | What it does | Output |
|---|---|---|
| `datafog_scan` | Reports entity types, counts, and character offsets | — |
| `datafog_redact` | Replaces each value with a label naming its kind, `[EMAIL]` | `name_redacted.ext` |
| `datafog_mask` | Covers each value character for character, preserving length | `name_masked.ext` |
| `datafog_remove` | Deletes each value outright, leaving no marker | `name_removed.ext` |

The write tools never modify the original. By default they create a sibling of the input. You can choose a fixed output directory in `policy.toml` during setup (see below). An existing file at the destination is never overwritten. `output_path` can choose a filename within that directory, but cannot select another allowed root or a subdirectory.

A copy gets the input's permissions, minus any execute bits, so a file only you can read produces a copy only you can read. A copy can still hold values the detectors missed, so it is never made more readable than its source. If a write fails partway, the incomplete copy is deleted.

Before creating a copy, the server checks the destination filesystem has space for the transformed UTF-8 output. Insufficient space, or an unavailable free-space check, refuses the write. This checks available capacity at that moment; it does not reserve space or account for disk quotas. A later write failure still removes the incomplete copy.

Detected by default:

- **Personal data** — `EMAIL`, `SSN`, `CREDIT_CARD`
- **Financial and health identifiers** — `US_ROUTING_NUMBER`, `NPI`
- **Credentials** — `API_KEY`, `BEARER_TOKEN`, `JWT`, `CREDENTIAL_URI`, `PRIVATE_KEY`

`DATE`, `ZIP_CODE`, `PHONE`, and `IP_ADDRESS` are available but off by default. Dates, ZIP codes, and phone numbers can match operational timestamps or numeric IDs, so enable them when that coverage is needed. A default scan does not check these types, and a default write leaves their values unchanged unless another selected detector also matches them.

Pass `entity_types` to choose the types to check or transform, or omit it for the defaults. An explicit list **replaces** the defaults; it does not add to them. For example, `{"path": "/absolute/path/export.csv", "entity_types": ["EMAIL", "PHONE", "DATE", "ZIP_CODE"]}` checks only those four types. Include every default type you still want when opting into another type. Unsupported types and an empty list are refused.

Some types are narrower than their names suggest:

- **`US_ROUTING_NUMBER` and `NPI`** are found only after a label, such as `Routing number:` or `NPI:`. A bare value, such as one in a CSV column named `npi`, can be missed or reported as another type.
- **`API_KEY`** covers GitHub tokens and Stripe secret and restricted keys. Keys from other providers, such as AWS, are not detected.
- **`BEARER_TOKEN`** is the token in an `Authorization: Bearer` header.
- **`CREDENTIAL_URI`** covers PostgreSQL connection strings that include a password (`postgres://` or `postgresql://`). Other schemes, such as MySQL, Redis, or MongoDB, are not detected.
- **`PRIVATE_KEY`** is a complete PEM private-key block. Public keys and certificates are not reported.

Credential detection is not a substitute for a dedicated secret scanner. A clean result means none of the selected detectors matched; it is not proof a file holds no sensitive data or secrets.

## Supported files

UTF-8 text, up to 1 MiB (1,048,576 bytes): CSV, TSV, JSON, logs, SQL dumps, plain text, and similar. Detection reads the file as flat text, so it finds values anywhere in it but has no notion of columns or fields.

Email matching uses format-specific boundaries in ENV and SQL files. With the default `input_format="auto"`, `.env`, `.env.*`, and `*.env` filenames select ENV boundaries; `*.sql` selects SQL boundaries, ignoring filename case. Other files, including CSV and TSV, use plain-text boundaries. All four tools accept an explicit `input_format` of `env`, `sql`, or `text` to override the filename.

For example, an ENV copy preserves `EMAIL=` and surrounding quotes while transforming the address; a SQL copy preserves the quotes surrounding a string value. Scan offsets refer to the email's span in the original file, including doubled SQL quotes within the address, using Unicode character positions. This is not a full ENV or SQL parser: SQL backslash escapes, dollar quoting, and encoded email characters are not interpreted.

Refused with an error, never scanned:

- **Other encodings.** UTF-16, UTF-32, Latin-1, and so on. Convert to UTF-8 first. A UTF-8 byte-order mark, as Excel writes, is fine and is kept in the copy.
- **Binary files.** XLSX, PDF, DOCX, images, and archives such as ZIP are not parsed. Export to CSV or text first.
- **Anything over 1 MiB.**

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

The directory must already exist and be an absolute path or start with `~`. The server creates files directly inside it, retaining the usual `_redacted`, `_masked`, or `_removed` names. It never creates directories automatically. Setting this destination grants no additional access: allowed roots, credential-directory denials, and the configuration-directory write refusal still apply. If two inputs produce the same output name, use an explicit destination path inside the configured directory; existing copies are never overwritten.

Edits take effect on the next write request. A missing policy file uses sibling copies. A valid file containing just `version = 1` also explicitly selects sibling copies. An empty, malformed, unreadable, or unsupported policy refuses writes rather than falling back. This version supports only `version` and `[output].directory`; broader workflow settings will be added separately. Scans do not depend on the copy policy.

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

The optional `~/.config/datafog/policy.toml` stores your copy destination. Keep it for reinstalling, or remove it separately if you want to discard that setting. Removing it does not delete any copies.

If you remove both configuration files, `rmdir ~/.config/datafog` removes the now-empty directory.

If you set `DATAFOG_MCP_ALLOWED_ROOTS` in your shell profile, remove it there.

The server keeps no cache, log, or data directory of its own.

Two things remain, on purpose:

- **Copies the tools wrote.** These are your files, saved beside their originals or in your configured output directory with `_redacted`, `_masked`, or `_removed` in the name, and they may still hold values the detectors missed. Uninstalling doesn't touch them. To find them, review the results before deleting anything:

  ```bash
  find ~ \( -name '*_redacted.*' -o -name '*_masked.*' -o -name '*_removed.*' \) -type f
  ```

- **Claude Code's logs about the server.** Claude Code records its connections to each MCP server and keeps those records after the server is gone. They're under `~/.cache/claude-cli-nodejs/*/mcp-logs-datafog/` on Linux and `~/Library/Caches/claude-cli-nodejs/*/mcp-logs-datafog/` on macOS, and you can delete them.

For another MCP client, remove the `datafog` entry from that client's MCP configuration in place of the `claude mcp remove` step.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the changelog policy and exemption process.

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

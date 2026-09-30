# datafog-mcp

An MCP server that lets an AI agent check a file for personally identifiable information (PII), and produce a cleaned copy, without the file's contents ever appearing in the tool's response.

Detection runs locally on the [datafog-core](https://github.com/DataFog/datafog-core) engine.

**What stays on the machine.** File contents are read and processed locally, and the server makes no network requests while running. FastMCP's update check is switched off, and its OpenTelemetry hooks do nothing unless you install an OpenTelemetry SDK and configure an exporter yourself. Tool responses are a different matter: they go into the agent's context, and the agent sends its context to its model provider. That is why responses carry no file contents or matched values. Installing the server downloads packages, which is separate from running it.

**What this does and does not protect.** No tool response contains file contents or matched values, so "is this file sensitive" can be answered without the answer carrying the sensitive parts. That is the whole of the guarantee. Note that the agent can still open the file directly, and sometimes will.

The guarantee holds when a tool fails, too. An unexpected error returns only its type, such as `datafog failed with RuntimeError`, and its details are kept out of both the response and the server's log.

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

## Tools

Every tool takes a path and returns a path. None returns file contents or matched values.

| Tool | What it does | Output |
|---|---|---|
| `datafog_scan` | Reports entity types, counts, and character offsets | — |
| `datafog_redact` | Replaces each value with a label naming its kind, `[EMAIL]` | `name_redacted.ext` |
| `datafog_mask` | Covers each value character for character, preserving length | `name_masked.ext` |
| `datafog_remove` | Deletes each value outright, leaving no marker | `name_removed.ext` |

The write tools create a sibling of the input and never modify the original. An existing file at the destination is never overwritten. `output_path` can name the file but not move it to another directory.

A copy gets the input's permissions, minus any execute bits, so a file only you can read produces a copy only you can read. A copy can still hold values the detectors missed, so it is never made more readable than its source. If a write fails partway, the incomplete copy is deleted.

Detected by default:

- **Personal data** — `EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `DATE`, `ZIP_CODE`
- **Financial and health identifiers** — `US_ROUTING_NUMBER`, `NPI`
- **Credentials** — `API_KEY`, `BEARER_TOKEN`, `JWT`, `CREDENTIAL_URI`, `PRIVATE_KEY`

`IP_ADDRESS` is available but off by default. Pass `entity_types` to narrow or widen the set.

Credential detection covers common formats. It is not a substitute for a dedicated secret scanner, and a clean result is not proof a file holds no secrets.

## Supported files

UTF-8 text, up to 1 MiB (1,048,576 bytes): CSV, TSV, JSON, logs, SQL dumps, plain text, and similar. Detection reads the file as flat text, so it finds values anywhere in it but has no notion of columns or fields.

Refused with an error, never scanned:

- **Other encodings.** UTF-16, UTF-32, Latin-1, and so on. Convert to UTF-8 first. A UTF-8 byte-order mark, as Excel writes, is fine and is kept in the copy.
- **Binary files.** XLSX, PDF, DOCX, images, and archives such as ZIP are not parsed. Export to CSV or text first.
- **Anything over 1 MiB.**

A refusal is not a clean result. It means the file was not checked.

## Where it may look

Every read and write is checked against a set of allowed root directories. The default allowed root is the home directory.

```bash
datafog-mcp roots          # show the roots in force and where they came from
datafog-mcp roots --edit   # open the roots file in $EDITOR
```

The file is `~/.config/datafog/allowed_roots`, one path per line. Edits take effect immediately so there's no need to restart or re-register. `DATAFOG_MCP_ALLOWED_ROOTS` (colon-separated) overrides the file when set, for installs that shouldn't be widened by editing a file.

Always refused, even inside a root: `.ssh`, `.gnupg`, `.aws`, `.kube`, `gcloud`.

A refused path returns a tool error naming the roots in force.

## Development

```bash
uv sync --group dev
uv run pre-commit install
```

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pyright && uv run pytest
```

## License

MIT

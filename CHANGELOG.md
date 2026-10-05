# Changelog

Notable changes to datafog-mcp. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

First release: an MCP server that checks a file for personal data and credentials, and writes a cleaned copy, without file contents or matched values ever appearing in a tool response.

### Added

- `datafog_scan` reports the entity types, per-type counts, and character offsets found in a file. A value two detectors both match is reported once, as the type the write tools would replace it with.
- `datafog_redact`, `datafog_mask`, and `datafog_remove` write a transformed copy beside the original, which is never modified.
- Detection by the [datafog-core](https://github.com/DataFog/datafog-core) engine, on this machine: email addresses, phone numbers, SSNs, credit card numbers, dates, ZIP codes, US routing numbers, NPIs, API keys, bearer tokens, JWTs, credentials embedded in URIs, and PEM private keys. IP addresses on request.
- Allowed roots confine every read and write to configured directories. `datafog-mcp roots` shows and edits them. Credential directories such as `.ssh` are always refused.
- CSV/TSV scans use decoded cell values with header context and report numeric record/column locations alongside original-source offsets. Writes preserve table structure and untouched syntax, with explicit headerless/plain-text options and safe refusals for malformed tables. Responses contain no header text or cell values.

### Security

- No tool response or server log carries file contents or matched values, including when a tool fails.
- The server makes no network requests while running.
- A copy is never more readable than its source, and a failed write leaves no partial copy.
- An empty or malformed roots policy refuses every path rather than falling back to the default.

### Known limitations

- Reads UTF-8 text files up to 1 MiB. Other encodings, binary formats such as XLSX and PDF, and larger files are refused.
- Detection is pattern-based. It reduces exposure but does not de-identify, names are not detected in plain text, and a clean result is not proof a file holds no sensitive data.
- An agent can still open a file directly instead of using these tools.

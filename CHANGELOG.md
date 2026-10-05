# Changelog

Notable changes to datafog-mcp. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

First release: an MCP server that checks a file for personal data and credentials, and writes a cleaned copy, without file contents or matched values ever appearing in a tool response.

### Added

- `datafog_check_text` checks already-composed outbound drafts using existing detector/model selection, exact allowlists, and overlap handling. It returns counts, character spans, and advisory findings guidance without echoing, transforming, saving, or sending the draft. Drafts are bounded to 1 MiB of UTF-8 bytes; malformed arguments and processing failures withhold draft values. A clean result never grants permission to send, and transformed drafts must be revised and rechecked separately.

- Explicit `datafog-mcp model install` setup downloads the pinned DataFog PII EN 65M native release, verifies archive/manifest/file integrity and MCP/Core/platform compatibility, and supports offline installation without overwriting existing bundles. Owner-configured model inference adds PERSON and STREET_ADDRESS across scans and all copy tools with local-only transport, inference deadlines, allowlists, and content-free responses. Missing or failed requested model support refuses the operation with setup guidance; no tool performs downloads or silently falls back to Core-only results.

- `datafog_pseudonymize` writes consistently keyed copies for cross-file linkage using owner-configured scopes. Explicit `datafog-mcp keys create SCOPE` setup supports OS credential storage and an explicitly selected owner-only POSIX file backend. Missing/unavailable keys refuse the operation without generation, replacement, or backend fallback; configured key files and aliases are refused as data. Policy discovery and workflow guidance expose scope names without key material. Pseudonymization does not make data anonymous.

- `datafog_scan` reports the entity types, per-type counts, and character offsets found in a file. A value two detectors both match is reported once, as the type the write tools would replace it with.
- `datafog_redact`, `datafog_mask`, and `datafog_remove` write a transformed copy beside the original by default, or in an owner-configured output directory. The original is never modified.
- Detection by the [datafog-core](https://github.com/DataFog/datafog-core) engine, on this machine: email addresses, phone numbers, SSNs, credit card numbers, dates, ZIP codes, US routing numbers, NPIs, API keys, bearer tokens, JWTs, credentials embedded in URIs, and PEM private keys. IP addresses on request.
- Allowed roots confine every read and write to configured directories. `datafog-mcp roots` shows and edits them. Credential directories such as `.ssh` are always refused.
- Owners can choose one copy destination in `policy.toml` using `datafog-mcp policy --edit`. Tool-selected filenames stay within that directory, subject to allowed roots and directory denials; absent policy keeps sibling copies. Invalid copy policy or insufficient destination disk space refuses writes.
- The same policy supports exact per-entity allowlists, routine scanning folders/extensions constrained by allowed roots, and advisory ask/transform/stop guidance. `datafog_policy` exposes settings without exact allowlist values; each scan/write validates a fresh immutable snapshot, and invalid policy refuses access.

### Security

- No tool response or server log carries file contents or matched values, including when a tool fails.
- The server makes no network requests while running.
- A copy is never more readable than its source, and a failed write leaves no partial copy.
- An empty or malformed roots policy refuses every path rather than falling back to the default.

### Known limitations

- Reads UTF-8 text files up to 1 MiB. Other encodings, binary formats such as XLSX and PDF, and larger files are refused.
- Core detection is pattern-based. Detection reduces exposure but does not de-identify; names require the separately installed optional model, and a clean result is not proof a file holds no sensitive data.
- An agent can still open a file directly instead of using these tools.

# Changelog

Notable changes to datafog-mcp. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

First release: an MCP server that checks a file for personal data and credentials, and writes a cleaned copy, without file contents or matched values ever appearing in a tool response.

### Added

- Pass default or explicit entity selections to Core before detection for text, ENV/SQL, and CSV/TSV cell scans. Unselected detectors do not run; findings and copy behavior retain their existing selection rules. Requires datafog-core 0.4.3 or later.

- `datafog_scan` reports the entity types, per-type counts, and character offsets found in a file. A value two detectors both match is reported once, as the type the write tools would replace it with.
- `datafog_redact`, `datafog_mask`, and `datafog_remove` write a transformed copy beside the original by default, or in an owner-configured output directory. The original is never modified.
- Detection by the [datafog-core](https://github.com/DataFog/datafog-core) engine, on this machine: email addresses, SSNs, credit card numbers, labeled US routing numbers and NPIs, GitHub and Stripe API keys, bearer tokens in Authorization headers, JWTs, PostgreSQL connection strings with a password, and complete PEM private-key blocks. Dates, ZIP codes, phone numbers, and IP addresses on request.
- Allowed roots confine every read and write to configured directories. `datafog-mcp roots` shows and edits them. Credential directories such as `.ssh` are always refused.
- CSV/TSV scans use decoded cell values with header context and report numeric record/column locations alongside original-source offsets. Writes preserve table structure and untouched syntax, with explicit headerless/plain-text options. Ragged rows, trailing blank lines, and literal quotes in unquoted fields are preserved; ambiguous tables are refused with record/column locations and plain-text scan guidance. Responses contain no header text or cell values.
- Email scans and transformed copies preserve ENV assignment syntax and surrounding SQL string quotes using datafog-core 0.4.2. All four tools infer these email boundaries from common ENV/SQL filenames and accept an `input_format` override; other files retain plain-text matching.

- `DATE`, `ZIP_CODE`, and `PHONE` are opt-in for scans and all write tools, reducing matches on operational timestamps and numeric IDs. Select them explicitly through `entity_types`; an explicit list replaces the defaults. Detection coverage and advisory-use limitations are documented more precisely.
- Owners can choose one copy destination in `policy.toml` using `datafog-mcp policy --edit`. Tool-selected filenames stay within that directory, subject to allowed roots and directory denials; absent policy keeps sibling copies. Invalid copy policy or insufficient destination disk space refuses writes. Output filenames beginning with `.` are refused; hidden inputs remain readable and receive visible default copy names.



### Security

- No tool response or server log carries file contents or matched values, including when a tool fails.
- The server makes no network requests while running.
- A copy is never more readable than its source, and a failed write leaves no partial copy.
- An empty or malformed roots policy refuses every path rather than falling back to the default.

### Known limitations

- Reads UTF-8 text files up to 1 MiB. Other encodings, binary formats such as XLSX and PDF, and larger files are refused.
- Detection is pattern-based. It reduces exposure but does not de-identify, names are not detected in plain text, and a clean result is not proof a file holds no sensitive data.
- An agent can still open a file directly instead of using these tools.

# Changelog

Notable changes to datafog-mcp. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `ACCOUNT_NUMBER` and `STREET_ADDRESS` can be selected through `entity_types` in all four file tools, and used as `[allow.exact]` keys in `policy.toml`. Both match only after a label, such as `Account number:` or `Street address:`, and both are off by default.

### Changed

- Require datafog-core 1.5.0 or later, below 2. The default entity types are unchanged: the server keeps its own list and does not follow Core's wider default scan, so `DATE`, `ZIP_CODE`, `PHONE`, `IP_ADDRESS`, `ACCOUNT_NUMBER`, and `STREET_ADDRESS` remain opt-in.
- The same file can produce different findings than under datafog-core 0.4.4:
  - In plain text and in CSV/TSV cells, an email address is reported without label syntax in front of it: one leading `name=` prefix and an opening double quote are no longer part of the match, so `email=alice@example.com` is found as `alice@example.com` and the copy keeps `email=`. A single quote directly after the label is still part of the match: `email='alice@example.com'` is found as `'alice@example.com`, opening quote included, and redacts to `email=[EMAIL]'`. A later `=` stays in the address, so `EMAIL=customer=tag@example.com` is found as `customer=tag@example.com`. A prefix ending in `&`, `?`, or `|` is trimmed the same way. Previously the whole string was matched and replaced. ENV and SQL formats keep their existing boundaries.
  - Because the label is no longer part of the match, an `[allow.exact]` entry now applies to a labeled address in plain text: with `support@example.com` approved, `email=support@example.com` matches the entry, is not reported, and stays in copies. Under datafog-core 0.4.4 the detected value was the whole `email=support@example.com`, which did not match the entry, so it was reported and replaced. Review `[allow.exact]` entries with this in mind.
  - An email address whose local part begins with a ZIP- or SSN-shaped number and a separator, such as `12345.name@example.com`, is reported from after the separator, in every format. The leading digits and separator stay in copies unless another selected type matches them.
  - A credit card number followed by a space or hyphen and more digits is now found; it was missed before. A card match no longer extends into digits that follow it, digits spanning a phone number and a date are no longer reported as a card, and more card formats are recognized, including 14-digit numbers.
  - A GitHub or Stripe key directly after `/` is now found.
  - A PostgreSQL connection string no longer absorbs the start of a card number that follows a hyphen.
  - With opt-in types selected: `DATE` now matches the date in an ISO timestamp such as `2026-10-01T10:00:00Z`. A ZIP code, phone number, or IPv6 address joined to a neighboring number by `.`, `,`, or `-` can be reported differently or not at all; for example, a ZIP code directly before a hyphen and a date is now found, while one directly after a hyphenated number is not.
- Scans and writes now refuse a file in which two detections of different types partly overlap, naming the entity types and suggesting a narrower `entity_types` selection. Previously one detection was kept and the rest of the other value could stay in the copy. An example is a PostgreSQL connection string followed by `;` and a card number. One detection wholly inside another is still resolved as before.

### Security

- Locked runtime dependencies updated past published advisories: authlib 1.9.3, certifi 2026.10.23, dnspython 2.9.1 (Python 3.11+), fastmcp 3.4.11, joserfc 1.7.7 (Python 3.10) and 1.8.0, and opentelemetry-api 1.45.2.

- Locked dnspython updated to 2.9.2 on Python 3.11 and later, past CVE-2026-128089 (excessive memory and CPU use when parsing a crafted WKS record from zone-file text). Python 3.10 stays on dnspython 2.8.0, the newest release that supports it; this server does not parse zone files.

## [1.0.0] - 2026-10-12

First release: an MCP server that checks a file for personal data and credentials, and writes a cleaned copy, without file contents or matched values ever appearing in a tool response.

### Added

- `datafog_scan` reports the entity types, per-type counts, and character offsets found in a file. A value two detectors both match is reported once, as the type the write tools would replace it with.
- `datafog_scan` lists offsets for up to 700 findings. Above that it returns complete counts without offsets, to bound response size for plain text and CSV/TSV.
- `datafog_redact`, `datafog_mask`, and `datafog_remove` write a transformed copy beside the original by default, or in an owner-configured output directory. The original is never modified.
- Detection by the [datafog-core](https://github.com/DataFog/datafog-core) engine, on this machine: email addresses, SSNs, credit card numbers, labeled US routing numbers and NPIs, GitHub and Stripe API keys, bearer tokens in Authorization headers, JWTs, PostgreSQL connection strings with a password, and complete PEM private-key blocks. Dates, ZIP codes, phone numbers, and IP addresses on request.
- Allowed roots confine every read and write to configured directories. `datafog-mcp roots` shows and edits them. Credential directories such as `.ssh` are always refused.
- CSV/TSV scans use decoded cell values with header context and report numeric record/column locations alongside original-source offsets. Writes preserve table structure and untouched syntax, with explicit headerless/plain-text options. Ragged rows, trailing blank lines, and literal quotes in unquoted fields are preserved; ambiguous tables are refused with record/column locations and plain-text scan guidance. Responses contain no header text or cell values.
- Email scans and transformed copies preserve ENV assignment syntax and surrounding SQL string quotes using datafog-core 0.4.2. All four tools infer these email boundaries from common ENV/SQL filenames and accept an `input_format` override; other files retain plain-text matching.
- `DATE`, `ZIP_CODE`, and `PHONE` are opt-in for scans and all write tools, reducing matches on operational timestamps and numeric IDs. Select them explicitly through `entity_types`; an explicit list replaces the defaults. Detection coverage and advisory-use limitations are documented more precisely.
- Only the selected entity types are detected: scans and writes pass the default or explicit `entity_types` to Core, so unselected detectors don't run. Requires datafog-core 0.4.3 or later.
- Owners can choose one copy destination in `policy.toml` using `datafog-mcp policy --edit`. Tool-selected filenames stay within that directory, subject to allowed roots and directory denials; absent policy keeps sibling copies. Invalid copy policy or insufficient destination disk space refuses writes. Output filenames beginning with `.` are refused; hidden inputs remain readable and receive visible default copy names.
- The same policy supports exact per-entity allowlists, routine scanning folders/extensions constrained by allowed roots, and advisory ask/transform/stop guidance. `datafog_policy` exposes settings without exact allowlist values; each scan/write validates a fresh immutable snapshot, and invalid policy refuses access. Missing scope folders are reported as inactive with warnings, without blocking explicit scans/writes or widening routine scope.

### Changed

- Require datafog-core 0.4.4 or later, reducing phone matches on Unix timestamps and credit-card matches inside decimal numbers.

### Security

- No tool response or server log carries file contents or matched values, including when a tool fails.
- The server makes no network requests while running.
- A copy is never more readable than its source, and a failed write leaves no partial copy.
- An empty or malformed roots policy refuses every path rather than falling back to the default.

### Known limitations

- Reads UTF-8 text files up to 10 MB (10,000,000 bytes). Other encodings, binary formats such as XLSX and PDF, and larger files are refused.
- Detection is pattern-based. It reduces exposure but does not de-identify, names are not detected in plain text, and a clean result is not proof a file holds no sensitive data.
- An agent can still open a file directly instead of using these tools.

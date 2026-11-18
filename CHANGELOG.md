# Changelog

Notable changes to datafog-mcp. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `ACCOUNT_NUMBER` and `STREET_ADDRESS` can be selected through `entity_types` in all four file tools, and used as `[allow.exact]` keys in `policy.toml`. Both match only after a label, such as `Account number:` or `Street address:`, and both are off by default.

### Changed

- Require datafog-core 1.7.x (`>=1.7.0,<1.8`). The server accepts one Core minor line at a time, because each Core minor can change what a scan finds. datafog-core 1.5.0 and 1.6.0 are excluded because they miss values: an email address directly after closing punctuation or dots, such as `"ok".alice@example.com` or `me...alice@example.com`, and a phone number directly after a number and a comma, or at the end of a line when the next line starts with a digit. With 1.7 these are found, as they were under 0.4.4. The default entity types are unchanged: the server keeps its own list and does not follow Core's wider default scan, so `DATE`, `ZIP_CODE`, `PHONE`, `IP_ADDRESS`, `ACCOUNT_NUMBER`, and `STREET_ADDRESS` remain opt-in. datafog-core 1.7.0 no longer ships a prebuilt package for Intel Macs, so installing on an Intel Mac builds Core from source and needs a Rust toolchain; Apple Silicon, Linux and Windows are unaffected.
- The same file can produce different findings than under datafog-core 0.4.4:
  - In plain text and in CSV/TSV cells, an email address is reported without label syntax in front of it: one leading `name=` prefix is no longer part of the match, so `email=alice@example.com` is found as `alice@example.com` and the copy keeps `email=`. A later `=` stays in the address, so `EMAIL=customer=tag@example.com` is found as `customer=tag@example.com`. A prefix ending in `&`, `?`, or `|` is trimmed the same way, as is a leading `*`, `/`, or `{`. Previously the whole string was matched and replaced. This reaches further than a label. In a query string or a pipe-delimited record, 1.0.0 removed the text joined to the front of the address along with it; now only the address is replaced, and what stands before it stays in the copy unless its own detector matches. `user=alice&pass=hunter2&email=alice@example.com` redacted to `[EMAIL]` and now redacts to `user=alice&pass=hunter2&email=[EMAIL]`, and `1|Alice|Smith|alice@example.com` redacted to `[EMAIL]` and now redacts to `1|Alice|Smith|[EMAIL]`. A password, token, or name before an address is therefore no longer removed as a side effect. A JWT directly after `=`, as in a URL ending `?id_token=<JWT>&email=alice@example.com`, is not detected on its own by either version, so it was removed with the address before and now stays in clear. Review copies of URLs, query strings, and delimited records with this in mind. A double quote was never part of the match and still is not. A single quote that opens a quoted address is no longer part of it: `'alice@example.com'` redacts to `'[EMAIL]'`, where it was `[EMAIL]'` before. Directly after a label it still is: `email='alice@example.com'` is found as `'alice@example.com`, opening quote included, and redacts to `email=[EMAIL]'`. ENV and SQL formats keep their existing boundaries.
  - Because the prefix is no longer part of the match, an `[allow.exact]` entry now applies to a labeled address in plain text: with `support@example.com` approved, `email=support@example.com` matches the entry, is not reported, and stays in copies. Under datafog-core 0.4.4 the detected value was the whole `email=support@example.com`, which did not match the entry, so it was reported and replaced. The same holds for the other trimmed prefixes. Review `[allow.exact]` entries with this in mind.
  - An email address whose local part begins with a value shaped like another entity type, followed by a separator, is reported from after the separator, in every format. Before, the whole string was one address. The shapes are a ZIP code (`12345`, `12345-6789`), an SSN, a credit card number, a phone number (`2025550143`, `+12025550143`, `202-555-0143`, `202.555.0143`), an IP address (`192.0.2.1`), and a date (`2026-10-01`, `10/01/2026`). The separators are `.`, `-`, `_`, `+`, `'`, `#`, `/`, `=`, `?`, `|`, and `&`, except that a five-digit number followed by `-` stays in the address. The split-off value and separator stay in copies unless a selected type matches them. `SSN` and `CREDIT_CARD` are default types, so `123-45-6789.alice@example.com` redacts to `[SSN].[EMAIL]`. `PHONE`, `IP_ADDRESS`, `DATE`, and `ZIP_CODE` are opt-in, so by default a phone number, IP address, date, or ZIP code in front of an address is now left visible: `2025550143.alice@example.com` redacts to `2025550143.[EMAIL]`, `192.0.2.1-alice@example.com` to `192.0.2.1-[EMAIL]`, `2026-10-01_alice@example.com` to `2026-10-01_[EMAIL]`, and `12345.alice@example.com` to `12345.[EMAIL]`, where each was `[EMAIL]` before. Select those types to replace the prefix as well. Other digit runs are not split and remain part of the address: `1234.alice@example.com`, `123456.alice@example.com`, and `20261001.alice@example.com` each redact to `[EMAIL]`, as does an all-digit local part such as `2025550143@example.com`.
  - A credit card number followed by a space or hyphen and more digits is now found, as the card number alone: `4111 1111 1111 1111 22` redacts to `[CREDIT_CARD] 22`. It was missed before. One case is unchanged: of two card numbers separated by a single space or hyphen in plain text, only one is found, as is one of two unspaced 16-digit numbers separated by a comma. Digits spanning a hyphenated phone number and a date, such as `555-0143 2026-10-01`, are no longer reported as a card; digit groups separated only by spaces still can be. More card formats are recognized, including 14-digit numbers.
  - A GitHub or Stripe key directly after `/` is now found.
  - A PostgreSQL connection string no longer absorbs the start of a card number that follows a hyphen or a slash.
  - With opt-in types selected:
    - `DATE` now matches the date in an ISO timestamp such as `2026-10-01T10:00:00Z`.
    - `ZIP_CODE` is no longer reported directly after `.`, `-`, or `$` (`v.12345`, `AB-12345`, `$12345`), or directly before a period and a digit (`12345.5`). A ZIP code directly before a hyphen and a date is now reported as the five-digit code; before, `12345-2026` was reported as one ZIP+4 code.
    - `IP_ADDRESS` no longer reports an IPv6 address directly followed by a period and a digit (`2001:db8::1.5`). An IPv6 address that ends in an IPv4 address, such as `2001:db8::192.0.2.1`, is now reported whole.
    - `PHONE` is matched within one line. Digit groups on different lines are no longer joined into one number, and a number that starts with `+` at the end of a line no longer takes in a digit that starts the next line, which previously removed the line break and that digit from the copy. A ten- or eleven-digit number at the start of a line is now found when the line before ends in three or more digits.
    - `PHONE` directly after a digit and a period is reported only when the number has a `+`, parentheses, or a space or hyphen between its groups: `7.202-555-0143` is found, while `7.2025550143` and `7.202.555.0143` are not. Directly after a digit and a comma, an unsigned number with a single period, such as `6,306.2723362`, is no longer reported. Other numbers after a digit and a comma are reported as before, including each number in `2025550143,2025550144`; so, as before, a ten-digit run after a comma can be a decimal fraction or an ID rather than a phone number.
- Scans and writes now refuse a file in which two detections of different types partly overlap, naming the entity types and suggesting a narrower `entity_types` selection. Previously one detection was kept and the rest of the other value could stay in the copy. An example is a PostgreSQL connection string followed by `;` and a card number. One detection wholly inside another is still resolved as before.

### Security

- Locked runtime dependencies updated past published advisories: authlib 1.9.3, certifi 2026.10.23, dnspython 2.9.2 (Python 3.11 and later), fastmcp 3.4.11, joserfc 1.7.7 (Python 3.10) and 1.8.0, and opentelemetry-api 1.45.2. dnspython 2.9.2 is past CVE-2026-128089 (excessive memory and CPU use when parsing a crafted WKS record from zone-file text). Python 3.10 stays on dnspython 2.8.0, the newest release that supports it; this server does not parse zone files.

### Known issues

- A non-ASCII letter directly touching an email address is treated as part of the address ([datafog-core#272](https://github.com/DataFog/datafog-core/issues/272)). This affects letters such as `é`, `à`, `ü`, `и`, `和`, `と`, and `와`, and combining accents. It does not affect punctuation and spacing such as `、`, `。`, `：`, `（`, a no-break space, or a zero-width space, nor emoji. The consequences, in every format:
  - When two addresses are joined by such a letter, one match is reported and the second address's domain stays in the copy: `alice@example.comとbob@example.net` redacts to `[EMAIL]@example.net`. Version 1.0.0 redacted both, to `[EMAIL]と[EMAIL]`.
  - Text written without spaces around an address can be replaced whole, and another value inside it is then not reported under its own type: `SSNは123-45-6789でメールはalice@example.comです` redacts to `[EMAIL]`, with one `EMAIL` and no `SSN` reported. The SSN is removed from the copy, but the scan does not count it. Version 1.0.0 wrote `SSNは[SSN]でメールは[EMAIL]です`.
  - A card number written with spaces, followed by such text and an address, makes scans and writes refuse the file with the partial-overlap error: `カードは4111 1111 1111 1111でメールはalice@example.comです` is refused, naming `CREDIT_CARD` and `EMAIL`.

  The same change is why addresses with non-ASCII letters are now found at all: `josé@example.com`, `名前@example.com`, and `alice@bücher.example` are each reported and redacted, where 1.0.0 missed them. Until the Core fix, check copies of text in which addresses touch non-ASCII letters, and separate values with a space or punctuation where you control the input.

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

# Supported files

UTF-8 text, up to 10 MB (10,000,000 bytes): CSV, TSV, JSON, logs, SQL dumps, plain text, and similar. CSV/TSV files are scanned as decoded cells; ENV/SQL files use their email boundary rules, and other files use plain-text matching.

## CSV and TSV

All four tools accept `input_format`: `auto` (default) selects comma-separated CSV for `.csv` and tab-separated TSV for `.tsv`, ignoring extension case; ENV/SQL filenames select their email boundary rules as described below; other extensions use plain text. Choose `csv`, `tsv`, `env`, or `sql` explicitly for another filename, or `text` to force flat scanning.

The first record is a header by default (`has_header=true`). It supplies context for label-sensitive detectors such as NPI and routing numbers, and is preserved without scanning or transforming its contents. Set `has_header=false` for headerless files, or when the first record may itself contain sensitive values that need processing. Header presence is never guessed.

Scan findings add numeric `record` and `column` fields, both one-based; record 1 is the first data record after the header. A quoted multiline cell is part of one record. `start`/`end` remain character offsets into the original raw file, including its BOM, line endings, and doubled quote escapes. Header strings are never returned, because they can contain sensitive data too.

Writes preserve the delimiter, record/column structure, headers, BOM, line endings, and untouched cell syntax. Changed cells are quoted and embedded double quotes escaped; removing the sole value in a one-column record writes `""` rather than a blank line. Masking preserves decoded value length, but added CSV quotes can change the serialized file length.

This supports comma/tab delimiters and double-quote escaping, including quoted multiline values and duplicate or empty headers. Trailing blank lines, ragged rows, and literal quotes inside unquoted fields are accepted and preserved. Missing cells are not filled in; extra cells are scanned without header context. Quoted tabs and multiline cells remain supported in TSV. Unterminated quoted fields, trailing text after a closing quote, and interior blank records are refused with a content-free error naming the record and column (error records include the header). The error suggests an explicit plain-text scan, whose transformed copies do not guarantee table structure. Empty and header-only files are valid. Other delimiters and backslash escaping require conversion or an explicit plain-text scan; plain-text transformation does not guarantee table structure.

Email matching uses format-specific boundaries in ENV and SQL files. With the default `input_format="auto"`, `.env`, `.env.*`, and `*.env` filenames select ENV boundaries; `*.sql` selects SQL boundaries, ignoring filename case. CSV and TSV use plain-text email boundaries within each decoded cell. Other files use plain-text boundaries. All four tools accept an explicit `input_format` of `env`, `sql`, or `text` to override the filename.

For example, an ENV copy preserves `EMAIL=` and surrounding quotes while transforming the address; a SQL copy preserves the quotes surrounding a string value. Scan offsets refer to the email's span in the original file, including doubled SQL quotes within the address, using Unicode character positions. This is not a full ENV or SQL parser: SQL backslash escapes, dollar quoting, and encoded email characters are not interpreted.

Refused with an error, never scanned:

- **Other encodings.** UTF-16, UTF-32, Latin-1, and so on. Convert to UTF-8 first. A UTF-8 byte-order mark, as Excel writes, is fine and is kept in the copy.
- **Binary files.** XLSX, PDF, DOCX, images, and archives such as ZIP are not parsed. Export to CSV or text first.
- **Anything over 10 MB.**

A refusal is not a clean result. It means the file was not checked.

[Back to the README](../README.md)

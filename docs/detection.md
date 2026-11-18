# Detection and copy behavior

A scan lists the offsets of at most 700 findings, to bound response size, including CSV/TSV record and column locations. Above that, `findings` is empty and `findings_listed` is `false`, while `entity_count` and `counts` remain complete. To see where values are in a dense file, scan again with fewer `entity_types`.

The write tools never modify the original. By default they create a sibling of the input. You can choose a fixed output directory in `policy.toml` during setup (see [owner policy](policy.md)). An existing file at the destination is never overwritten. `output_path` can choose a filename within that directory, but cannot select another allowed root or a subdirectory. Output filenames beginning with `.` are refused, including missing shell startup files such as `.profile`. Hidden inputs remain scannable; default copies strip leading dots from the input stem (for example, `.env` becomes `env_redacted`).

A copy gets the input's permissions, minus any execute bits, so a file only you can read produces a copy only you can read. A copy can still hold values the detectors missed, so it is never made more readable than its source. If a write fails partway, the incomplete copy is deleted.

Before creating a copy, the server checks the destination filesystem has space for the transformed UTF-8 output. Insufficient space, or an unavailable free-space check, refuses the write. This checks available capacity at that moment; it does not reserve space or account for disk quotas. A later write failure still removes the incomplete copy.

Detected by default:

- **Personal data** — `EMAIL`, `SSN`, `CREDIT_CARD`
- **Financial and health identifiers** — `US_ROUTING_NUMBER`, `NPI`
- **Credentials** — `API_KEY`, `BEARER_TOKEN`, `JWT`, `CREDENTIAL_URI`, `PRIVATE_KEY`

`DATE`, `ZIP_CODE`, `PHONE`, `IP_ADDRESS`, `ACCOUNT_NUMBER`, and `STREET_ADDRESS` are available but off by default. Dates, ZIP codes, and phone numbers can match operational timestamps or numeric IDs, so enable them when that coverage is needed. A default scan does not check these types, and a default write leaves their values unchanged unless another selected detector also matches them.

Pass `entity_types` to choose the types to check or transform, or omit it for the defaults. An explicit list **replaces** the defaults; it does not add to them. For example, `{"path": "/absolute/path/export.csv", "entity_types": ["EMAIL", "PHONE", "DATE", "ZIP_CODE"]}` checks only those four types. Include every default type you still want when opting into another type. Unsupported types and an empty list are refused.

Some types are narrower than their names suggest:

- **`US_ROUTING_NUMBER` and `NPI`** are found only after a label, such as `Routing number:` or `NPI:`. Table headers supply this label context; bare values in plain text can be missed or reported as another type.
- **`ACCOUNT_NUMBER` and `STREET_ADDRESS`** are found only after a label, such as `Account number:` or `Street address:`. Unlabeled account numbers and street addresses are not detected.
- **`API_KEY`** covers GitHub tokens and Stripe secret and restricted keys. Keys from other providers, such as AWS, are not detected.
- **`BEARER_TOKEN`** is the token in an `Authorization: Bearer` header.
- **`CREDENTIAL_URI`** covers PostgreSQL connection strings that include a password (`postgres://` or `postgresql://`). Other schemes, such as MySQL, Redis, or MongoDB, are not detected.
- **`PRIVATE_KEY`** is a complete PEM private-key block. Public keys and certificates are not reported.

An email address is replaced on its own; text joined to its front is not part of it. In plain text and CSV/TSV cells, `user=alice&pass=hunter2&email=alice@example.com` redacts to `user=alice&pass=hunter2&email=[EMAIL]`, and `1|Alice|Smith|alice@example.com` redacts to `1|Alice|Smith|[EMAIL]`. Version 1.0.0 wrote `[EMAIL]` for each of these. A password, token, or name before an address in a query string, URL, or delimited record therefore stays in the copy unless its own detector matches it. A JWT directly after `=`, as in `?id_token=<JWT>&email=alice@example.com`, is not detected and stays in clear. ENV and SQL formats keep their own boundaries: in an ENV file, `URL=user=alice&pass=hunter2&email=alice@example.com` still redacts to `URL=[EMAIL]`.

In every format, a local part that begins with a value shaped like another entity type and a separator is split there: the address is reported from after the separator. The shapes are a ZIP code, an SSN, a credit card number, a phone number, an IP address, and a date; the separators are `.`, `-`, `_`, `+`, `'`, `#`, `/`, `=`, `?`, `|`, and `&`, except that a five-digit number followed by `-` stays in the address. The value in front is replaced only when its type is selected. `123-45-6789.alice@example.com` redacts to `[SSN].[EMAIL]` by default, while `2025550143.alice@example.com` redacts to `2025550143.[EMAIL]`, `192.0.2.1-alice@example.com` to `192.0.2.1-[EMAIL]`, and `2026-10-01_alice@example.com` to `2026-10-01_[EMAIL]`, because `PHONE`, `IP_ADDRESS`, `DATE`, and `ZIP_CODE` are off by default. Other digit runs, such as `1234.alice@example.com` or `20261001.alice@example.com`, and all-digit local parts such as `2025550143@example.com`, are one address.

When two detections of different types partly overlap and neither contains the other, replacing either one would leave part of the other value in the copy. Scans and writes refuse such a file with an error naming the entity types involved; nothing is written. Run the tool again with a narrower `entity_types` selection. One detection wholly inside another, such as the address-shaped part of a connection string, is resolved normally. A future release may instead replace the whole overlapping span with a single marker rather than refuse the file; until then the refusal is the intended behavior.

Credential detection is not a substitute for a dedicated secret scanner. A clean result means none of the selected detectors matched; it is not proof a file holds no sensitive data or secrets.

## Known issue: email addresses touching non-ASCII letters

A non-ASCII letter directly touching an email address is treated as part of the address. This is tracked as [datafog-core#272](https://github.com/DataFog/datafog-core/issues/272) and applies in every format.

- **Affected:** letters such as `é`, `à`, `ü`, `и`, `和`, `と`, and `와`, and combining accents.
- **Not affected:** punctuation and spacing such as `、`, `。`, `：`, `（`, a no-break space, or a zero-width space, and emoji. Two addresses separated by one of these are each found.

What this means for copies and scans:

- Two addresses joined by such a letter are reported as one match, and the second address's domain stays in the copy: `alice@example.comとbob@example.net` redacts to `[EMAIL]@example.net`. Version 1.0.0 redacted both.
- Text written without spaces around an address can be replaced whole: `メールはalice@example.comです` redacts to `[EMAIL]`. Another value inside that text is then not reported under its own type: `SSNは123-45-6789でメールはalice@example.comです` redacts to `[EMAIL]` and the scan reports one `EMAIL` and no `SSN`.
- A card number written with spaces, followed by such text and an address, is refused with the partial-overlap error described above: `カードは4111 1111 1111 1111でメールはalice@example.comです`.

The same matching is what finds addresses that contain non-ASCII letters, which version 1.0.0 missed: `josé@example.com`, `名前@example.com`, and `alice@bücher.example` are each reported and redacted.

Until this is fixed in Core, check copies of text in which addresses touch non-ASCII letters. Where you control the input, a space or punctuation mark between values avoids it.

[Back to the README](../README.md)

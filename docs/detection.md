# Detection and copy behavior

A scan lists the offsets of at most 700 findings, to bound response size, including CSV/TSV record and column locations. Above that, `findings` is empty and `findings_listed` is `false`, while `entity_count` and `counts` remain complete. To see where values are in a dense file, scan again with fewer `entity_types`.

The write tools never modify the original. By default they create a sibling of the input. You can choose a fixed output directory in `policy.toml` during setup (see [owner policy](policy.md)). An existing file at the destination is never overwritten. `output_path` can choose a filename within that directory, but cannot select another allowed root or a subdirectory. Output filenames beginning with `.` are refused, including missing shell startup files such as `.profile`. Hidden inputs remain scannable; default copies strip leading dots from the input stem (for example, `.env` becomes `env_redacted`).

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

[Back to the README](../README.md)

# Detection corpus

Labeled documents that measure what `datafog_scan` finds, run by [`tests/test_corpus.py`](../../test_corpus.py).

Each `.in` file is a document in a format users scan: a CRM export, an API dump, an application log, a SQL dump, an environment file, a support ticket, and a file of look-alikes that should come back clean. Between them they include overlapping values, non-ASCII text before and around values, and a CSV written as Excel writes it, with a byte-order mark and CRLF line endings.

## Labels

`[[TYPE|value]]` marks a value the scan should find. The markup is stripped before scanning, and the label's position becomes the expected span. A finding is correct only when its type and span both match.

`{{name}}` is filled in from `SECRETS` in the test. Credential-shaped values are assembled there so no scannable literal is committed. None is usable.

What gets a label:

- **Label what a reader would expect to be found, not what the engine is documented to find.** A routing number in a `routing_number` column is labeled even though the engine needs the word "routing" beside it. That way recall measures what a user gets.
- **DATE marks dates about a person**, such as a birth date or an appointment. Timestamps on records and log lines are not labeled, so a DATE found there counts against precision.
- **Where values overlap, label the more specific type.** A labeled NPI is NPI, not PHONE, and a PostgreSQL URI is CREDENTIAL_URI, not EMAIL.
- **Names are not labeled.** The engine detects PERSON only in structured input, which the server never passes.

## Results

[`baseline.json`](baseline.json) records the engine version, per-type precision and recall, and every miss and false alarm by line. The test fails when a scan departs from it. If the change is intended, such as after an engine upgrade or a corpus edit, regenerate the baseline and review the diff:

```bash
DATAFOG_UPDATE_CORPUS=1 uv run pytest tests/test_corpus.py
```

The baseline records how detection behaves now. It does not set an acceptable level. Thresholds have yet to be agreed.

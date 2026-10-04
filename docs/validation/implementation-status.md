# User-flow implementation status

Implementation branch: `feat/mcp-user-flows`, based on `99ed333`. The previous reference worktree remains intact. This is an implementation and validation record, not a production release announcement.

## Implemented MCP behavior

- Versioned, reloadable TOML policy; DATE/ZIP opt-in; exact allowlists shared across scans and transformations.
- CSV/TSV cell transformations with preserved headers, records, fields, quoting validity, BOM/CRLF, and original-source finding locations. Malformed tables fail explicitly.
- Named pseudonymization scopes using Core 0.4.1 HMAC, explicit key provisioning, OS credential storage by default, and explicit private-file storage for POSIX headless use. Missing keys fail.
- Configurable 100 MB file cap, bounded finding pages with stale-continuation rejection, and batch scanning with explicit per-selection errors and opt-in recursion.
- Output-directory precedence, no overwrites, unchanged originals, and preserved restrictive source permissions.
- Advisory workflow/scope discovery, opt-in metadata activity logs, and scan-only `datafog_check_text`.
- Original synthetic fixtures preserved; observable behavior checked through the MCP interface and offline stdio in CI.

The model adapter runs the existing native Rust executable locally and supplies its findings to Core for overlap resolution and transformations. It does not reimplement the detector in Python. Row context is retained for model inference; transformations are restricted to cell values.

## Remaining release gates and limits

**Names/addresses remain experimental.** The trained bundle passed small local diagnostic examples and actual MCP CSV transformations. This is not an independently held-out accuracy evaluation. The available executable is macOS ARM64; a portable, versioned Core integration and agreed model acceptance thresholds remain outstanding. Default CI tests adapter contracts; actual-bundle checks are opt-in. No Core release or dependency upgrade was fabricated to hide that gap.

**A size cap is not a performance guarantee.** See the separate measurement reports for workload, elapsed time, memory, and explicit model timeout behavior. Full input and findings are held in memory; response pagination is not streaming. Dense detections and narrow, numerous CSV records can cost substantially more than sparse examples. Model failure is an error, never a silent regex-only result.

**Agent policy is advisory.** MCP cannot enforce that a host calls it before another tool reads or transmits data. Tool arguments, paths, and CSV field names can already disclose information in host context.

**Existing Core boundary bugs remain.** CSV handling preserves table structure, but arbitrary text syntax inside cells or ordinary text can still be damaged by overly broad Core spans (see issue #31). There is no claim to have fixed Core detection here.

**Credentials and filesystem limits.** OS credential APIs are covered with fake backends; actual desktop stores still require platform qualification. Data paths resolve and check allowed roots, including known secret aliases. The existing path-check/open sequence is not a sandbox against concurrent filesystem mutation by a hostile local process. Activity logs are bounded, best-effort local records, not tamper-proof audits.

## Validation

Final local checks on Python 3.12.13: Ruff lint/format, mypy, and Pyright passed (zero typing errors or warnings). The ordinary suite passed **248 tests**, with **3 opt-in checks skipped**, and measured **94% coverage**. The separate real-bundle model/CSV run passed **30 tests**. These are local results. Consult the pull request checks for remote CI results.

The reproducible 100 MB narrow-row CSV benchmark passed scan, redact, every-cell invariants, and original preservation: approximately **11.25 seconds scan**, **11.37 seconds redact**, **387 MB process peak RSS**. See [file-size measurements](file-size-measurements.md) and [model qualification](model-qualification.md) for methodology and limits.

Run the commands in the README for required lint, formatting, typing, and pytest checks. Real-model tests and large-file measurements are separate opt-in checks, documented alongside their results. Ordinary tests do not touch personal keychains or download weights.

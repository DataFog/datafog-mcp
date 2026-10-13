# Security policy

datafog-mcp checks files for personal data and credentials on behalf of AI agents, so a flaw in what it reveals or where it reads and writes is a security issue.

## Reporting a vulnerability

Report it privately through GitHub using [Report a vulnerability](https://github.com/DataFog/datafog-mcp/security/advisories/new). If that isn't available to you, email hi@datafog.ai.

Please don't open a public issue or pull request for a vulnerability, and don't include real personal data in a report. A synthetic example is enough.

## In scope

- File contents, matched values, or allowlist values appearing in a tool response, error message, or server log.
- Reading or writing outside the allowed roots, or inside a refused credential directory such as `.ssh`.
- Writing a copy outside the configured destination, overwriting an existing file, or making a copy more readable than its source.
- Network requests while the server is running.

## Out of scope

- Values the detectors miss, or match wrongly. Detection is pattern-based and not exhaustive; report these as regular issues.
- An agent reading a file directly with its own tools. The server can’t prevent that.

## Supported versions

Security fixes go into the latest release.

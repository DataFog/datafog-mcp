# Changelog

## 0.2.0

- Added proxy error-path redaction hardening and optional redaction logging.
- Added `--log-redactions/--no-log-redactions` across serve/proxy modes with
  environment fallback (`DATAFOG_LOG_REDACTIONS`).
- Added `DATAFOG_NO_TELEMETRY` propagation in runtime codepaths and CLI controls.
- Added serve-mode end-to-end runtime smoke validation using subprocess MCP transport.
- Added package build step to CI and initial GitHub release workflow.

## 0.1.0

- Initial MCP tool and proxy implementation scaffolding.
- Added UV/ruff/pytest-based developer workflow.

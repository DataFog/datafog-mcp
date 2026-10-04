"""Optional bounded local audit records containing metadata only."""

from __future__ import annotations

import json
import os
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from datafog_mcp.paths import ROOTS_FILE
from datafog_mcp.policy import Policy

_LOCK = threading.Lock()
_MAX_LOG_BYTES = 10_000_000


def record(policy: Policy, operation: str, outcome: str, counts: dict[str, int]) -> str:
    """Return logging status without turning a completed write into a reported failure."""
    if not policy.logging_enabled:
        return "disabled"
    payload: dict[str, Any] = {
        "time": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "outcome": outcome,
        "counts": counts,
    }
    try:
        with _LOCK:
            path = policy.log_path
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            protected: list[Path | None] = [policy.source_path, ROOTS_FILE]
            protected.extend(scope.key_file for scope in policy.pseudonymization_scopes.values())
            resolved = path.resolve()
            if any(
                candidate is not None and resolved == candidate.resolve() for candidate in protected
            ):
                return "unavailable"
            if policy.model_bundle_directory is not None:
                bundle = policy.model_bundle_directory.resolve()
                if resolved == bundle or bundle in resolved.parents:
                    return "unavailable"
            flags = (
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                info = os.fstat(handle.fileno())
                encoded = json.dumps(payload, separators=(",", ":")) + "\n"
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_size + len(encoded.encode("utf-8")) > _MAX_LOG_BYTES
                ):
                    return "unavailable"
                if os.name == "posix" and (info.st_mode & 0o077 or info.st_uid != os.getuid()):
                    return "unavailable"
                for candidate in protected:
                    if candidate is None:
                        continue
                    try:
                        protected_info = candidate.stat()
                    except FileNotFoundError:
                        continue
                    if (info.st_dev, info.st_ino) == (protected_info.st_dev, protected_info.st_ino):
                        return "unavailable"
                handle.write(encoded)
        return "recorded"
    except (OSError, ValueError):
        return "unavailable"

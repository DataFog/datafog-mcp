"""Explicit private, bounded, best-effort local activity metadata. Never input payloads."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult
from mcp.types import CallToolRequestParams, TextContent

from . import policy
from .config import SUPPORTED_ENTITIES
from .policy import OutputPolicy, OutputPolicyError

MAX_LOG_BYTES = 10 * 1024 * 1024
WARNING = "Activity logging is unavailable; this operation's outcome is unchanged."
OPERATIONS = frozenset(
    {
        "datafog_policy",
        "datafog_scan",
        "datafog_redact",
        "datafog_mask",
        "datafog_remove",
        "datafog_pseudonymize",
        "datafog_check_text",
    }
)
CURRENT_POLICY: ContextVar[OutputPolicy | None] = ContextVar(
    "datafog_activity_policy", default=None
)


class ActivityStorageError(ValueError):
    """A fixed, content-free local setup/storage error."""


@contextmanager
def _parent_fd(path: Path) -> Iterator[int]:
    if os.name != "posix" or not path.is_absolute() or ".." in path.parts:
        raise ActivityStorageError("Private activity storage currently requires POSIX.")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ActivityStorageError("Activity storage needs an owner-controlled 0700 directory.")
        yield descriptor
    finally:
        os.close(descriptor)


def _check_file(descriptor: int) -> None:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise ActivityStorageError("Activity file must be an owner-controlled 0600 regular file.")


def _check_destination(current: OutputPolicy) -> Path:
    from .paths import ROOTS_FILE

    path = current.activity.path
    if path is None:
        raise ActivityStorageError("An explicit activity path is required.")
    resolved = path.resolve()
    # Reserve a dedicated directory; never append to configuration/key/model assets.
    protected = [policy.POLICY_FILE, ROOTS_FILE]
    protected.extend(
        scope.key_file for scope in current.pseudonym_scopes.values() if scope.key_file
    )
    for candidate in protected:
        if candidate.resolve() == resolved or path.parent.resolve() == candidate.parent.resolve():
            raise ActivityStorageError("Activity storage needs a separate private directory.")
        try:
            if path.parent.samefile(candidate.parent):
                raise ActivityStorageError("Activity storage needs a separate private directory.")
            if path.samefile(candidate):
                raise ActivityStorageError("Activity storage cannot modify private configuration.")
        except (FileNotFoundError, NotADirectoryError):
            pass
    if current.model is not None:
        bundle = current.model.bundle_directory.resolve()
        if resolved == bundle or bundle in resolved.parents or resolved in bundle.parents:
            raise ActivityStorageError("Activity storage cannot modify model assets.")
    return path


def initialize(current: OutputPolicy) -> None:
    """Exclusively create a fresh log after explicit owner setup; never replace files."""
    try:
        path = _check_destination(current)
        with _parent_fd(path) as parent:
            descriptor = os.open(
                path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            try:
                os.fchmod(descriptor, 0o600)
                _check_file(descriptor)
            finally:
                os.close(descriptor)
    except FileExistsError:
        raise ActivityStorageError("Activity file already exists; refusing replacement.") from None
    except ActivityStorageError:
        raise
    except Exception:
        raise ActivityStorageError(
            "Cannot initialize activity storage; create its private parent directory first."
        ) from None


def verify(current: OutputPolicy) -> None:
    """Inspect permissions/capacity without reading, appending, or creating records."""
    try:
        path = _check_destination(current)
        with _parent_fd(path) as parent:
            descriptor = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
            )
            try:
                _check_file(descriptor)
                if os.fstat(descriptor).st_size >= MAX_LOG_BYTES:
                    raise ActivityStorageError("Activity file reached its 10 MiB cap.")
            finally:
                os.close(descriptor)
    except ActivityStorageError:
        raise
    except Exception:
        raise ActivityStorageError(
            "Activity storage is unavailable; inspect setup locally."
        ) from None


def record(current: OutputPolicy, operation: str, outcome: str, counts: object) -> bool:
    """Append only whitelisted metadata; failure never changes a tool's outcome."""
    try:
        if (
            not current.activity.enabled
            or operation not in OPERATIONS
            or outcome not in {"success", "error"}
        ):
            return False
        safe_counts = (
            {
                kind: value
                for kind, value in counts.items()
                if kind in SUPPORTED_ENTITIES and type(value) is int and value >= 0
            }
            if isinstance(counts, dict) and outcome == "success"
            else {}
        )
        payload = {
            "schema": 1,
            "time": datetime.now(timezone.utc).isoformat(),
            "operation": operation,
            "outcome": outcome,
            "counts": safe_counts,
        }
        encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        path = _check_destination(current)
        with _parent_fd(path) as parent:
            descriptor = os.open(
                path.name,
                os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=parent,
            )
            try:
                # Advisory lock is bounded/nonblocking and serializes cooperating processes.
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                _check_file(descriptor)
                before = os.fstat(descriptor).st_size
                if before + len(encoded) > MAX_LOG_BYTES:
                    return False
                try:
                    if os.write(descriptor, encoded) != len(encoded):
                        raise OSError("Incomplete activity append")
                    os.fsync(descriptor)
                except OSError:
                    os.ftruncate(descriptor, before)
                    return False
                return True
            finally:
                os.close(descriptor)
    except Exception:
        return False


class ActivityLoggingMiddleware(Middleware):
    """Keep one owner policy snapshot and add a visible, content-free logging status."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        name = context.message.name
        if name not in OPERATIONS:
            return await call_next(context)
        try:
            current = policy.load_output_policy()
        except OutputPolicyError as exc:
            raise ToolError(str(exc)) from None
        token = CURRENT_POLICY.set(current)
        try:
            if not current.activity.enabled:
                return await call_next(context)
            try:
                result = await call_next(context)
            except Exception as exc:
                recorded = await asyncio.to_thread(record, current, name, "error", {})
                if recorded:
                    raise
                message = (
                    str(exc)
                    if isinstance(exc, ToolError)
                    else "Operation failed; details are withheld."
                )
                raise ToolError(message + " " + WARNING) from None
            data = result.structured_content
            recorded = await asyncio.to_thread(
                record,
                current,
                name,
                "error" if result.is_error else "success",
                data.get("counts", {}) if data else {},
            )
            status = {"status": "recorded" if recorded else "unavailable"}
            if not recorded:
                status["warning"] = WARNING
            if data is not None:
                data = {**data, "activity_log": status}
                return ToolResult(
                    content=data,
                    structured_content=data,
                    meta=result.meta,
                    is_error=result.is_error,
                )
            content = list(result.content)
            if not recorded:
                content.append(TextContent(type="text", text=WARNING))
            return ToolResult(content=content, meta=result.meta, is_error=result.is_error)
        finally:
            CURRENT_POLICY.reset(token)

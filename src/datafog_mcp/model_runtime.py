"""Opt-in adapter for the experimental, locally installed native PII bundle.

The runtime owns tokenization/windowing. This adapter never downloads models,
returns runtime text, or falls back to a different detector after a failure.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import math
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, cast

from datafog_core import Finding, TextRange

MODEL_WINDOW_CHARS = 16_384
MODEL_OVERLAP_CHARS = 1_024

_LABELS = {"first_name": "PERSON", "last_name": "PERSON", "street_address": "STREET_ADDRESS"}


class ModelRuntimeError(ValueError):
    """A sanitized model failure safe for tool responses."""


def _convert(text: str, response: Any) -> list[Finding]:
    if not isinstance(response, dict) or "error" in response:
        raise ModelRuntimeError("Local model inference failed.")
    raw = cast(dict[str, Any], response).get("findings")
    if not isinstance(raw, list):
        raise ModelRuntimeError("Local model returned an invalid response.")
    entries: list[Any] = raw
    encoded = text.encode("utf-8")
    # Decode each interval once; store only finding endpoints, not one mapping
    # entry per character (which would consume gigabytes on a large input).
    boundaries = {0}
    for finding in entries:
        if not isinstance(finding, dict):
            raise ModelRuntimeError("Local model returned an invalid finding.")
        finding = cast(dict[str, Any], finding)
        label = finding.get("label")
        if isinstance(label, str) and label in _LABELS:
            for key in ("start", "end"):
                value = finding.get(key)
                if type(value) is not int or not 0 <= value <= len(encoded):
                    raise ModelRuntimeError("Local model returned invalid finding boundaries.")
                boundaries.add(value)
    offsets = {0: 0}
    previous = 0
    count = 0
    try:
        for boundary in sorted(boundaries):
            count += len(encoded[previous:boundary].decode("utf-8"))
            offsets[boundary] = count
            previous = boundary
    except UnicodeDecodeError:
        raise ModelRuntimeError("Local model returned invalid UTF-8 boundaries.") from None
    result: list[Finding] = []
    for finding in entries:
        if not isinstance(finding, dict):
            raise ModelRuntimeError("Local model returned an invalid finding.")
        finding = cast(dict[str, Any], finding)
        label = finding.get("label")
        if not isinstance(label, str) or label not in _LABELS:
            continue
        start, end = finding.get("start"), finding.get("end")
        score = finding.get("confidence")
        if (
            type(start) is not int
            or type(end) is not int
            or start not in offsets
            or end not in offsets
            or start >= end
            or (
                score is not None
                and (
                    type(score) not in (int, float)
                    or not math.isfinite(score)
                    or not 0 <= score <= 1
                )
            )
        ):
            raise ModelRuntimeError(
                "Local model returned invalid finding boundaries or confidence."
            )
        result.append(
            Finding(
                _LABELS[label],
                encoded[start:end].decode("utf-8"),
                TextRange(start, end),
                TextRange(offsets[start], offsets[end]),
                "datafog-local-pii",
                score,
            )
        )
    return result


class _Runtime:
    def __init__(self, bundle: Path, signature: str) -> None:
        self.bundle = bundle
        self.signature = signature
        self.lock = threading.Lock()
        self.process: subprocess.Popen[bytes] | None = None

    def close(self) -> None:
        process, self.process = self.process, None
        if process is None:
            return
        if process.poll() is None:
            process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()

    def scan(self, text: str, timeout: float) -> list[Finding]:
        deadline = time.monotonic() + timeout
        if not self.lock.acquire(timeout=timeout):
            raise ModelRuntimeError("Local model inference timed out waiting for another request.")
        try:
            if self.process is None or self.process.poll() is not None:
                self.close()
                try:
                    self.process = subprocess.Popen(
                        [str(self.bundle / "datafog-pii"), str(self.bundle)],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                    )
                except OSError:
                    raise ModelRuntimeError("Local model bundle could not be started.") from None
            process = self.process
            response: queue.Queue[bytes | None] = queue.Queue(maxsize=1)
            payload = (json.dumps({"text": text}, ensure_ascii=False) + "\n").encode()
            # The prototype also returns redacted text. Bound transport allocation
            # and discard that field; it must never reach an MCP response or log.
            limit = max(1_048_576, len(payload) * 32)

            def exchange() -> None:
                try:
                    assert process.stdin is not None and process.stdout is not None
                    process.stdin.write(payload)
                    process.stdin.flush()
                    data = process.stdout.readline(limit + 1)
                    response.put(data if data.endswith(b"\n") and len(data) <= limit else None)
                except (OSError, ValueError):
                    response.put(None)

            worker = threading.Thread(target=exchange, daemon=True)
            worker.start()
            try:
                data = response.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty:
                self.close()
                worker.join(timeout=1)
                raise ModelRuntimeError("Local model inference timed out.") from None
            if data is None:
                self.close()
                raise ModelRuntimeError("Local model returned an incomplete response.")
            try:
                return _convert(text, json.loads(data))
            except (ValueError, TypeError, OverflowError):
                self.close()
                raise ModelRuntimeError("Local model returned an invalid response.") from None
        finally:
            self.lock.release()


_runtimes: dict[Path, _Runtime] = {}
_registry_lock = threading.Lock()


def model_signature(bundle_directory: str | Path) -> str:
    """Stat identity of installed bundle inputs for process/cache invalidation.

    This is change detection, not a cryptographic model provenance check.
    Include nested calibration/runtime files without assuming platform suffixes.
    """
    bundle = Path(bundle_directory).expanduser().resolve()
    try:
        entries: list[tuple[str, int, int, int, int]] = []
        for path in sorted(bundle.rglob("*")):
            if path.is_file():
                stat = path.stat()
                entries.append(
                    (
                        str(path.relative_to(bundle)),
                        stat.st_dev,
                        stat.st_ino,
                        stat.st_size,
                        stat.st_mtime_ns,
                    )
                )
        if not entries:
            raise ModelRuntimeError("Local model bundle is missing required files.")
        return hashlib.sha256(json.dumps(entries).encode()).hexdigest()
    except OSError:
        raise ModelRuntimeError("Local model bundle could not be inspected.") from None


def model_findings(
    text: str, bundle_directory: str | Path, timeout_seconds: float = 30
) -> list[Finding]:
    """Detect PERSON/STREET_ADDRESS using a persistent, serialized native process."""
    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ModelRuntimeError(
            "Local model timeout must be greater than 0 and at most 300 seconds."
        )
    bundle = Path(bundle_directory).expanduser().resolve()
    required = ("datafog-pii", "model.onnx", "tokenizer.json", "config.json")
    if not all((bundle / name).is_file() for name in required):
        raise ModelRuntimeError("Local model bundle is missing required files.")
    signature = model_signature(bundle)
    with _registry_lock:
        runtime = _runtimes.get(bundle)
        if runtime is None or runtime.signature != signature:
            if runtime is not None:
                with runtime.lock:
                    runtime.close()
            runtime = _Runtime(bundle, signature)
            _runtimes[bundle] = runtime
    if len(text) <= MODEL_WINDOW_CHARS:
        return runtime.scan(text, timeout_seconds)
    # Bound prototype tokenization/window allocations. Ownership cuts halfway
    # through overlaps; entities touching a physical segment edge are unsafe
    # when their start belongs to that segment and must fail explicitly.
    # This is finite overlap protection, not arbitrary-length entity support.
    deadline = time.monotonic() + timeout_seconds
    result: list[Finding] = []
    start = byte_start = 0
    step = MODEL_WINDOW_CHARS - MODEL_OVERLAP_CHARS
    while start < len(text):
        end = min(start + MODEL_WINDOW_CHARS, len(text))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ModelRuntimeError("Local model inference timed out.")
        local = runtime.scan(text[start:end], remaining)
        lower = MODEL_OVERLAP_CHARS // 2 if start else 0
        upper = end - start - MODEL_OVERLAP_CHARS // 2 if end < len(text) else end - start
        for finding in local:
            a, b = finding.codepoint_range.start, finding.codepoint_range.end
            if not lower <= a < upper:
                continue
            if (start and a == 0) or (end < len(text) and b == end - start):
                raise ModelRuntimeError("Local model entity exceeds supported segment boundaries.")
            result.append(
                Finding(
                    finding.entity_type,
                    finding.matched_text,
                    TextRange(
                        byte_start + finding.byte_range.start, byte_start + finding.byte_range.end
                    ),
                    TextRange(start + a, start + b),
                    finding.detector_name,
                    finding.confidence,
                    finding.detector_version,
                )
            )
        if end == len(text):
            break
        byte_start += len(text[start : start + step].encode("utf-8"))
        start += step
    return result


def close_model_runtimes() -> None:
    """Release native processes, including when an MCP server exits."""
    with _registry_lock:
        for runtime in _runtimes.values():
            with runtime.lock:
                runtime.close()
        _runtimes.clear()


atexit.register(close_model_runtimes)

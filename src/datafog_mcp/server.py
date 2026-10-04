from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal, cast

import fastmcp
from datafog_core import Finding, TextRange, scan, transform
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from datafog_mcp import __version__
from datafog_mcp import paths as path_policy
from datafog_mcp.activity import record
from datafog_mcp.config import DEFAULT_ENTITIES, SUPPORTED_ENTITIES
from datafog_mcp.csv_processing import CsvError
from datafog_mcp.findings import Mode
from datafog_mcp.keys import KeyStorageError
from datafog_mcp.model_runtime import ModelRuntimeError, model_signature
from datafog_mcp.paths import PathNotAllowed, resolve_input, resolve_output
from datafog_mcp.policy import Policy, PolicyError, load_policy
from datafog_mcp.reader import ReadError, WriteError, read_text_file, write_text_file

MODEL_ENTITIES = frozenset({"PERSON", "STREET_ADDRESS"})
if TYPE_CHECKING:
    from datafog_core import _TransformationConfig

    EntityType = str
else:
    EntityType = Literal[tuple(sorted(SUPPORTED_ENTITIES | MODEL_ENTITIES))]
EntitySelection = Annotated[list[EntityType], Field(min_length=1)] | None
InputFormat = Literal["auto", "text", "csv", "tsv"]
PageOffset = Annotated[int, Field(ge=0)]
PageSize = Annotated[int, Field(ge=1, le=100_000)]

mcp = FastMCP(
    name="datafog",
    version=__version__,
    mask_error_details=True,
    instructions=(
        "Local sensitive-data checks and transformations. Before each new file or outbound "
        "workflow, call datafog_get_policy to refresh scan scope and post-finding preferences. "
        "Within that advisory scope, scan files by path before reading contents into context, "
        "including project-local and Git-tracked data.\n\n"
        "When findings are present, follow the returned advisory action. "
        "ask: pause and obtain the user's permission before reading originals or sending "
        "sensitive content. transform: create a copy using the configured strategy and, for "
        "pseudonymization, the configured scope; use only the successfully created copy for "
        "subsequent reading or sharing. stop: stop the affected workflow and explain the "
        "findings using metadata only. proceed: continue under the configured policy, subject "
        "to the user's existing authorization; this is not permission to send or publish.\n\n"
        "A failed scan, timeout, unsupported format, or failed transformation leaves the "
        "affected input unchecked or untransformed. Report the limitation; do not open the "
        "original with another tool to investigate or bypass the failure. In batches, handle "
        "each file's outcome separately.\n\n"
        "Before sending an already-composed outbound draft, use datafog_check_text and follow "
        "the same findings policy. This tool only checks text; it does not transform or send "
        "it. If transformation is required, revise the draft and recheck before sending, or "
        "create a transformed source-file copy using the configured strategy. Never read an "
        "unscanned file into context just to pass its contents to datafog_check_text. "
        "The host may retain text-check arguments.\n\n"
        "DataFog cannot block other tools. Responses contain paths and metadata, including "
        "CSV field names, but no matched values. A clean scan means the selected detectors "
        "found no actionable matches, not proof that no sensitive data exists."
    ),
)
_SUFFIXES = {
    "redact": "redacted",
    "mask": "masked",
    "remove": "removed",
    "pseudonymize": "pseudonymized",
}


@contextmanager
def _contained() -> Iterator[None]:
    try:
        yield
    except ToolError:
        raise
    except (
        PolicyError,
        ReadError,
        WriteError,
        PathNotAllowed,
        CsvError,
        KeyStorageError,
        ModelRuntimeError,
    ) as exc:
        raise ToolError(str(exc)) from None
    except Exception as exc:
        raise ToolError(
            f"datafog failed with {type(exc).__name__}; details are withheld "
            "because they may contain file content"
        ) from None


def _selection(policy: Policy, requested: list[str] | None) -> set[str]:
    defaults = set(DEFAULT_ENTITIES)
    if policy.model_bundle_directory is not None:
        defaults |= MODEL_ENTITIES
    selected = defaults if requested is None else set(requested)
    if not selected or not selected <= SUPPORTED_ENTITIES | MODEL_ENTITIES:
        raise ToolError("entity_types must select supported nonempty types")
    if selected & MODEL_ENTITIES and policy.model_bundle_directory is None:
        raise ToolError("PERSON and STREET_ADDRESS require a configured local model bundle")
    return selected


def _protect(path: Path, policy: Policy) -> None:
    """Data operations cannot expose or overwrite policy, keys, logs, or model assets."""
    resolved = path.resolve()
    protected: list[Path | None] = [policy.source_path, policy.log_path, path_policy.ROOTS_FILE]
    protected.extend(s.key_file for s in policy.pseudonymization_scopes.values())

    def same_file(candidate: Path | None) -> bool:
        if candidate is None:
            return False
        if resolved == candidate.resolve():
            return True
        try:
            return resolved.samefile(candidate)
        except (FileNotFoundError, NotADirectoryError):
            return False

    if any(same_file(p) for p in protected):
        raise ToolError(
            "DataFog configuration, key, and activity files are not data inputs or outputs"
        )
    if policy.model_bundle_directory is not None:
        bundle = policy.model_bundle_directory.resolve()
        if resolved == bundle or bundle in resolved.parents:
            raise ToolError("Model assets are not data inputs or outputs")


def _scope_applies(path: Path, policy: Policy) -> bool:
    resolved = path.resolve()
    folder_match = not policy.scope_folders or any(
        resolved == p.resolve() or p.resolve() in resolved.parents for p in policy.scope_folders
    )
    return folder_match and (
        not policy.scope_extensions or path.suffix.lower() in policy.scope_extensions
    )


def _policy_metadata(policy: Policy, count: int, path: Path | None = None) -> dict[str, Any]:
    action = policy.on_findings if count else "no_findings"
    return {
        "policy_applied": policy.loaded,
        "allowlist_applied": bool(policy.allow_exact),
        "advisory_action": action,
        "advisory_only": True,
        "transform_strategy": policy.transform_strategy if action == "transform" else None,
        "transform_scope": policy.transform_scope if action == "transform" else None,
        "within_scan_scope": _scope_applies(path, policy) if path else None,
    }


async def _operation(
    name: str, body: Callable[[Policy], Awaitable[dict[str, Any]]]
) -> dict[str, Any]:
    with _contained():
        policy = load_policy()
        try:
            result = await body(policy)
        except Exception:
            record(policy, name, "error", {})
            raise
        outcome = "partial" if result.get("error_count") else "success"
        result["activity_log"] = record(policy, name, outcome, result.get("counts", {}))
        return result


def _digest(text: str, policy: Policy, selected: set[str], fmt: str, header: bool) -> str:
    h = hashlib.sha256(text.encode("utf-8"))
    h.update(
        json.dumps(
            {
                "entities": sorted(selected),
                "allow": dict(policy.allow_exact),
                "format": fmt,
                "header": header,
                "model": (
                    model_signature(policy.model_bundle_directory)
                    if policy.model_bundle_directory is not None and selected & MODEL_ENTITIES
                    else None
                ),
            },
            sort_keys=True,
        ).encode()
    )
    return h.hexdigest()


async def _process(
    text: str,
    policy: Policy,
    selected: set[str],
    strategy: str,
    fmt: str,
    has_header: bool,
    scope: str | None = None,
) -> Any:
    config: dict[str, Any] = {
        "default": {"strategy": strategy},
        "allow": {"exact": {k: v for k, v in policy.allow_exact.items() if v}},
    }
    manager: Any = None
    if strategy == "pseudonymize":
        from datafog_core import PrivacyManager

        from datafog_mcp.keys import LocalKeyProvider

        if scope is None or scope not in policy.pseudonymization_scopes:
            raise ToolError("Choose a configured pseudonymization scope")
        key = policy.pseudonymization_scopes[scope]
        provider = LocalKeyProvider(key)
        await provider.resolve_key(key.key_ref, key.key_version)
        manager = PrivacyManager(provider=provider)
        config["default"].update(key_ref=key.key_ref, key_version=key.key_version)

    deadline = time.monotonic() + policy.model_timeout_seconds

    def remaining_model_time() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ModelRuntimeError("Local model inference timed out.")
        return remaining

    csv_without_model = fmt in ("csv", "tsv") and not selected & MODEL_ENTITIES

    async def process_cell(value: str, value_start: int = 0) -> Any:
        # The entire deterministic CSV loop runs in one worker below. Dispatching
        # two thread-pool jobs per tiny cell dominates large narrow-row exports.
        found = scan(value) if csv_without_model else await asyncio.to_thread(scan, value)
        if selected & MODEL_ENTITIES:
            from datafog_mcp.model_runtime import model_findings

            assert policy.model_bundle_directory is not None
            found.extend(
                await asyncio.to_thread(
                    model_findings,
                    value,
                    policy.model_bundle_directory,
                    remaining_model_time(),
                )
            )
        kept = [
            f
            for f in found
            if f.entity_type in selected
            and f.codepoint_range.start >= value_start
            and f.codepoint_range.end <= len(value)
        ]
        if manager is not None:
            return await manager.transform(value, kept, config)
        if csv_without_model:
            return transform(value, kept, cast("_TransformationConfig", config))
        return await asyncio.to_thread(
            transform, value, kept, cast("_TransformationConfig", config)
        )

    async def process_record(context: str, ranges: list[TextRange]) -> list[Any]:
        from datafog_mcp.model_runtime import model_findings

        assert policy.model_bundle_directory is not None
        found = await asyncio.to_thread(scan, context)
        found.extend(
            await asyncio.to_thread(
                model_findings, context, policy.model_bundle_directory, remaining_model_time()
            )
        )
        results: list[Any] = []
        for cell_range in ranges:
            value = context[cell_range.start : cell_range.end]
            kept: list[Finding] = []
            for finding in found:
                span = finding.codepoint_range
                if (
                    finding.entity_type not in selected
                    or span.start < cell_range.start
                    or span.end > cell_range.end
                ):
                    continue
                start, end = span.start - cell_range.start, span.end - cell_range.start
                kept.append(
                    Finding(
                        entity_type=finding.entity_type,
                        matched_text=value[start:end],
                        codepoint_range=TextRange(start=start, end=end),
                        byte_range=TextRange(
                            start=len(value[:start].encode()), end=len(value[:end].encode())
                        ),
                        detector_name=finding.detector_name,
                        confidence=finding.confidence,
                        detector_version=finding.detector_version,
                    )
                )
            if manager is not None:
                results.append(await manager.transform(value, kept, config))
            else:
                results.append(
                    await asyncio.to_thread(
                        transform, value, kept, cast("_TransformationConfig", config)
                    )
                )
        return results

    if fmt in ("csv", "tsv"):
        from datafog_mcp.csv_processing import process_csv

        async def run_csv() -> Any:
            return await process_csv(
                text,
                process_cell,
                has_header=has_header,
                delimiter="\t" if fmt == "tsv" else ",",
                process_record=process_record if selected & MODEL_ENTITIES else None,
            )

        if csv_without_model:
            return await asyncio.to_thread(lambda: asyncio.run(run_csv()))
        return await run_csv()

    return await process_cell(text)


def _format(path: Path, fmt: InputFormat) -> str:
    if fmt != "auto":
        return fmt
    return {".csv": "csv", ".tsv": "tsv"}.get(path.suffix.lower(), "text")


def _page(
    text: str,
    result: Any,
    policy: Policy,
    offset: int,
    limit: int,
    digest: str,
    expected_digest: str | None,
) -> dict[str, Any]:
    if offset and expected_digest is None:
        raise ToolError("Pagination requires the previous content_digest")
    if expected_digest is not None and expected_digest != digest:
        raise ToolError("Input or scanning configuration changed; restart pagination at offset 0")
    items = result.transformations
    counts = dict(Counter(item.entity_type for item in items))
    if offset > len(items):
        raise ToolError("offset exceeds the finding count")
    size = min(limit, policy.max_findings)
    page_items = items[offset : offset + size]
    locations: dict[int, tuple[int, int]] = {}
    previous, line = 0, 1
    for start in sorted({item.source_codepoint_range.start for item in page_items}):
        line += text.count("\n", previous, start)
        locations[start] = (line, start - text.rfind("\n", 0, start))
        previous = start
    findings: list[dict[str, Any]] = []
    for item in page_items:
        start, end = item.source_codepoint_range.start, item.source_codepoint_range.end
        line, column = locations[start]
        finding: dict[str, Any] = {
            "type": item.entity_type,
            "start": start,
            "end": end,
            "line": line,
            "character_column": column,
        }
        for attr in ("record", "column", "field_name"):
            value = getattr(item, attr, None)
            if value is not None:
                finding[attr] = value
        findings.append(finding)
    next_offset = offset + len(findings)
    return {
        "mode": "findings",
        "entity_count": len(items),
        "counts": counts,
        "findings": findings,
        "content_digest": digest,
        "offset": offset,
        "next_offset": next_offset if next_offset < len(items) else None,
        "complete": next_offset >= len(items),
    }


async def _scan_file(
    path: str,
    mode: Mode,
    entity_types: list[str] | None,
    policy: Policy,
    input_format: InputFormat = "auto",
    has_header: bool = True,
    offset: int = 0,
    limit: int = 1000,
    content_digest: str | None = None,
) -> dict[str, Any]:
    selected = _selection(policy, entity_types)
    _protect(Path(path).expanduser(), policy)
    content = read_text_file(path, policy.max_file_bytes)
    fmt = _format(content.path, input_format)
    digest = _digest(content.text, policy, selected, fmt, has_header)
    if content_digest is not None and content_digest != digest:
        raise ToolError("Input or scanning configuration changed; restart pagination at offset 0")
    result = await _process(content.text, policy, selected, "redact", fmt, has_header)
    response = _page(content.text, result, policy, offset, limit, digest, content_digest)
    response.update(
        path=str(content.path), **_policy_metadata(policy, response["entity_count"], content.path)
    )
    return response


@mcp.tool
async def datafog_get_policy() -> dict[str, Any]:
    """Read advisory scope and workflow preferences BEFORE reading any data file.

    Refresh at the start of each file workflow. This returns configuration metadata,
    never allowlist values or secret keys. Scope is advisory; roots still govern access.
    """
    with _contained():
        p = load_policy()
        return {
            "version": p.version,
            "configured": p.loaded,
            "advisory_only": True,
            "scope": {
                "folders": [str(x) for x in p.scope_folders],
                "extensions": list(p.scope_extensions),
                "empty_scope_means": "all data files; no Git or project exemption",
            },
            "on_findings": p.on_findings,
            "transform_strategy": p.transform_strategy,
            "transform_scope": p.transform_scope,
            "output_directory": str(p.output_directory) if p.output_directory else None,
            "allowlist_applied": bool(p.allow_exact),
            "pseudonymization_scopes": sorted(p.pseudonymization_scopes),
            "model_enabled": p.model_bundle_directory is not None,
            "default_entities": sorted(_selection(p, None)),
            "limits": {
                "file_bytes": p.max_file_bytes,
                "text_bytes": p.max_text_bytes,
                "findings_per_page": p.max_findings,
                "batch_files": p.max_batch_files,
            },
            "activity_logging": p.logging_enabled,
        }


@mcp.tool
async def datafog_scan(
    path: str,
    mode: Mode = "findings",
    entity_types: EntitySelection = None,
    input_format: InputFormat = "auto",
    has_header: bool = True,
    offset: PageOffset = 0,
    limit: PageSize = 1000,
    content_digest: str | None = None,
) -> dict[str, Any]:
    """Check a UTF-8 file before reading contents. Consult datafog_get_policy first.

    Returns actionable types/counts/locations, never matched values. DATE, ZIP_CODE and IP_ADDRESS
    are opt-in. PERSON/STREET_ADDRESS require a configured local model. Credential coverage is
    GitHub/Stripe keys, Authorization bearer tokens, JWTs, password-bearing PostgreSQL URIs and
    PEM private keys; not arbitrary AWS keys or URI schemes. Routing numbers/NPIs need labels.
    CSV/TSV scan cells and preserve headers; set has_header=False for headerless files, or
    input_format=text for a text export that happens to have a CSV extension. CSV record/column
    numbers are one-based (record excludes header); offsets are original Unicode code points.
    A refusal is not clean. After findings follow advisory_action before reading the original.
    Findings are paginated; repeat using next_offset and content_digest until complete.
    """
    return await _operation(
        "scan",
        lambda p: _scan_file(
            path, mode, entity_types, p, input_format, has_header, offset, limit, content_digest
        ),
    )


@mcp.tool
async def datafog_check_text(
    text: str,
    entity_types: EntitySelection = None,
    offset: PageOffset = 0,
    limit: PageSize = 1000,
    content_digest: str | None = None,
) -> dict[str, Any]:
    """Check an outbound draft already in context, without sending it or echoing its values.

    Use before sending an already-composed draft and follow the returned findings policy.
    Never read an unscanned file into context just to supply this argument; scan its path first.
    This tool does not transform or send text. Revise and recheck if transformation is required.
    The host may retain tool arguments. Same detectors/allowlists as files; no file is written.
    Default input limit is 1 MiB, independently configurable. Follow pagination if incomplete.
    """

    async def run(p: Policy) -> dict[str, Any]:
        selected = _selection(p, entity_types)
        if len(text.encode("utf-8")) > p.max_text_bytes:
            raise ToolError("Text exceeds the configured byte limit")
        result = await _process(text, p, selected, "redact", "text", False)
        response = _page(
            text,
            result,
            p,
            offset,
            limit,
            _digest(text, p, selected, "text", False),
            content_digest,
        )
        response.update(_policy_metadata(p, response["entity_count"]))
        return response

    return await _operation("check_text", run)


async def _transform_to_file(
    path: str,
    output_path: str | None,
    entity_types: list[str] | None,
    strategy: str,
    p: Policy,
    input_format: InputFormat = "auto",
    has_header: bool = True,
    scope: str | None = None,
) -> dict[str, Any]:
    selected = _selection(p, entity_types)
    _protect(Path(path).expanduser(), p)
    content = read_text_file(path, p.max_file_bytes)
    source = content.path
    directory = p.output_directory or source.parent
    destination = (
        Path(output_path).expanduser()
        if output_path
        else directory / f"{source.stem}_{_SUFFIXES[strategy]}{source.suffix}"
    )
    _protect(destination, p)
    resolve_output(str(destination), source)
    result = await _process(
        content.text, p, selected, strategy, _format(source, input_format), has_header, scope
    )
    written = write_text_file(destination, result.text, beside=source)
    counts = dict(Counter(item.entity_type for item in result.transformations))
    return {
        "input_path": str(source),
        "output_path": str(written),
        "strategy": strategy,
        "entity_count": len(result.transformations),
        "counts": counts,
        **_policy_metadata(p, len(result.transformations), source),
    }


@mcp.tool
async def datafog_redact(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
    input_format: InputFormat = "auto",
    has_header: bool = True,
) -> dict[str, Any]:
    """Write a copy with matched values replaced by type labels such as [EMAIL].

    Equal labels do not preserve identity. Original remains unchanged; never overwrites.
    Destination: explicit output_path, policy output directory, then sibling. Directory must
    exist inside allowed roots. CSV/TSV preserve headers, records, columns and valid quoting.
    """
    return await _operation(
        "redact",
        lambda p: _transform_to_file(
            path, output_path, entity_types, "redact", p, input_format, has_header
        ),
    )


@mcp.tool
async def datafog_mask(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
    input_format: InputFormat = "auto",
    has_header: bool = True,
) -> dict[str, Any]:
    """Write a copy covering matched values character for character. CSV syntax may be re-escaped.

    Same policy and destination rules as datafog_redact; does not modify the original.
    """
    return await _operation(
        "mask",
        lambda p: _transform_to_file(
            path, output_path, entity_types, "mask", p, input_format, has_header
        ),
    )


@mcp.tool
async def datafog_remove(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
    input_format: InputFormat = "auto",
    has_header: bool = True,
) -> dict[str, Any]:
    """Write a copy deleting matched values. Empty CSV cells are preserved as cells.

    Same policy and destination rules as datafog_redact; does not modify the original.
    """
    return await _operation(
        "remove",
        lambda p: _transform_to_file(
            path, output_path, entity_types, "remove", p, input_format, has_header
        ),
    )


@mcp.tool
async def datafog_pseudonymize(
    path: str,
    scope: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
    input_format: InputFormat = "auto",
    has_header: bool = True,
) -> dict[str, Any]:
    """Write a copy with Core HMAC pseudonyms using an explicitly configured named scope.

    Same exact value and secret key yield the same opaque value across files/restarts.
    Keys are locally provisioned via CLI; never send a key in a tool call. Missing keys fail.
    Different capitalization/spacing or detected boundaries change pseudonyms. One-way,
    not reversible tokenization, and not automatic person identification.
    """
    return await _operation(
        "pseudonymize",
        lambda p: _transform_to_file(
            path, output_path, entity_types, "pseudonymize", p, input_format, has_header, scope
        ),
    )


def _batch_paths(inputs: list[str], recursive: bool, p: Policy) -> list[Path]:
    found: dict[str, Path] = {}

    def add(path: Path) -> None:
        key = str(path.resolve())
        found.setdefault(key, path)
        if len(found) > p.max_batch_files:
            raise ToolError("Batch exceeds configured file count; choose a smaller selection")

    for raw in inputs:
        path = Path(raw).expanduser()
        try:
            resolved = resolve_input(str(path))
            _protect(resolved, p)
        except (PathNotAllowed, ToolError):
            add(path)
            continue
        if not resolved.is_dir():
            add(resolved)
            continue

        def enumeration_error(error: OSError, folder: Path = resolved) -> None:
            # A directory refusal becomes an explicit per-selection error, not an empty scan.
            add(Path(error.filename) if error.filename else folder)

        for directory, dirs, files in os.walk(
            resolved, followlinks=False, onerror=enumeration_error
        ):
            permitted: list[str] = []
            for name in sorted(dirs):
                child = Path(directory) / name
                if child.is_symlink():
                    continue
                try:
                    resolve_input(str(child))
                    _protect(child, p)
                except (PathNotAllowed, ToolError):
                    if recursive:
                        add(child)
                    continue
                permitted.append(name)
            dirs[:] = permitted
            for name in sorted(files):
                add(Path(directory) / name)
            if not recursive:
                break
    return list(found.values())


@mcp.tool
async def datafog_scan_batch(
    paths: Annotated[list[str], Field(min_length=1, max_length=1000)],
    recursive: bool = False,
    entity_types: EntitySelection = None,
    input_format: InputFormat = "auto",
    has_header: bool = True,
) -> dict[str, Any]:
    """Scan selected files or folders sequentially, without creating transformed copies.

    Recursion is opt-in; directory symlinks are not followed. Each file has a success/error
    outcome and counts; failures do not stop other files. Request detailed locations with
    datafog_scan. Exceeding the batch file limit refuses the batch before scanning.
    """

    async def run(p: Policy) -> dict[str, Any]:
        _selection(p, entity_types)
        selected_paths = _batch_paths(paths, recursive, p)
        results: list[dict[str, Any]] = []
        counts: Counter[str] = Counter()
        for path in selected_paths:
            try:
                with _contained():
                    item = await _scan_file(
                        str(path), "findings", entity_types, p, input_format, has_header, limit=1
                    )
                counts.update(item["counts"])
                results.append(
                    {
                        "path": item["path"],
                        "status": "success",
                        "entity_count": item["entity_count"],
                        "counts": item["counts"],
                        "advisory_action": item["advisory_action"],
                    }
                )
            except ToolError as exc:
                results.append({"path": str(path), "status": "error", "error": str(exc)})
        return {
            "files": results,
            "file_count": len(results),
            "counts": dict(counts),
            "error_count": sum(r["status"] == "error" for r in results),
            "complete": True,
            "advisory_only": True,
        }

    return await _operation("scan_batch", run)


def run_server() -> None:
    """Serve locally without FastMCP update checks or a network-checking banner."""
    fastmcp.settings.check_for_updates = "off"
    mcp.run(transport="stdio", show_banner=False)

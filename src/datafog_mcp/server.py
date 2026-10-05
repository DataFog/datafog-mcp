from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal

import fastmcp
from datafog_core import Finding, PrivacyManager, scan, transform
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from datafog_mcp import __version__
from datafog_mcp.config import (
    DEFAULT_ENTITIES,
    MODEL_ENTITIES,
    SUPPORTED_ENTITIES,
    ScanConfig,
    transform_config,
)
from datafog_mcp.drafts import DraftValidationMiddleware, validate_draft
from datafog_mcp.findings import (
    Mode,
    counts_by_type,
    finding_to_dict,
    render,
    render_transformation,
)
from datafog_mcp.keys import KeyStorageError, LocalKeyProvider
from datafog_mcp.model_runtime import ModelRuntimeError, model_findings
from datafog_mcp.paths import PathNotAllowed, allowed_roots, resolve_input, resolve_output
from datafog_mcp.policy import OutputPolicy, OutputPolicyError, WriteStrategy, load_output_policy
from datafog_mcp.reader import (
    ReadError,
    WriteError,
    read_text_file,
    write_text_file,
)

if TYPE_CHECKING:
    EntityType = str
else:
    # Built from the engine's own list, so the schema cannot drift from what a
    # scan can report. Type checkers see str; FastMCP publishes the enum.
    EntityType = Literal[tuple(sorted(SUPPORTED_ENTITIES))]

# Omit for the default set. An empty list asks for nothing, so the schema
# declares it invalid rather than reading it as the default.
EntitySelection = Annotated[list[EntityType], Field(min_length=1)] | None

mcp = FastMCP(
    name="datafog",
    version=__version__,
    mask_error_details=True,
    middleware=[DraftValidationMiddleware()],
    instructions=(
        "Local PII and credential detection and transformation. Scans "
        "files on disk for emails, phone numbers, SSNs, credit card "
        "numbers, dates, ZIP codes, bank routing numbers, NPIs, API "
        "keys, tokens, and private keys. An explicitly installed optional model "
        "adds PERSON and STREET_ADDRESS detection. Missing model support refuses "
        "those requests with local setup guidance. The server can write a transformed "
        "copy. File contents are processed on this machine and never "
        "included in tool responses. Use datafog_policy to discover owner "
        "settings and whether a path should be scanned before reading. "
        "Scanning scope guides routine checks within allowed roots; explicit "
        "scans outside that scope are still permitted within roots. Follow "
        "the scan response's advisory policy action: ask the user, transform "
        "a copy using its suggested strategy, or stop. A refused or failed "
        "scan is never permission to read the original through another tool. "
        "Before sending an already-composed outbound draft, call datafog_check_text. "
        "It reports findings and advisory policy only; it does not rewrite or send text. "
        "For transform guidance, revise the draft and recheck it before sending. "
        "A clean check does not grant permission to send. The client may retain tool "
        "arguments. Never read an unscanned file into context to supply draft text."
    ),
)

_OUTPUT_SUFFIXES: dict[WriteStrategy, str] = {
    "redact": "redacted",
    "mask": "masked",
    "remove": "removed",
    "pseudonymize": "pseudonymized",
}


@contextmanager
def _contained() -> Iterator[None]:
    """
    Replace any unexpected failure with an error that carries no content.

    FastMCP logs any exception other than ToolError with its message and
    traceback, and masking only changes what the client sees. Engine and I/O
    messages may quote the file being processed, so an unexpected exception is
    replaced with one naming only its type. `from None` drops the original
    from the chain, so no traceback can reach it either.

    Deliberate ToolErrors pass through untouched, since their messages are
    written to be shown.

    Returns:
      A context manager guarding the enclosed block.
    """
    try:
        yield
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(
            f"datafog failed with {type(exc).__name__}; details are withheld "
            "because they may contain file content"
        ) from None


def _config_from(entity_types: list[str] | None, current: OutputPolicy) -> ScanConfig:
    """
    Build detection settings from optional tool arguments.

    Parameters:
      entity_types: The types to keep, or None for the default set.
    Returns:
      A validated ScanConfig.
    """
    try:
        entities = tuple(entity_types) if entity_types is not None else DEFAULT_ENTITIES
        if entity_types is None and current.model is not None:
            entities += tuple(sorted(MODEL_ENTITIES))
        config = ScanConfig(entities=entities)
        if MODEL_ENTITIES.intersection(config.entities) and current.model is None:
            raise ToolError(
                "PERSON/STREET_ADDRESS require an installed model. Run `datafog-mcp model install` "
                "locally and configure [model].bundle_directory in policy.toml."
            )
        return config
    except ValueError as exc:
        raise ToolError(str(exc)) from exc


def _request_policy() -> OutputPolicy:
    """Load and validate the owner's settings before accessing file contents."""
    try:
        return load_output_policy()
    except OutputPolicyError as exc:
        raise ToolError(str(exc)) from None


def _protect_private_resources(path: Path, current: OutputPolicy) -> None:
    """Refuse configured model bundles and key files (including key aliases)."""
    if current.model is not None:
        resolved = path.resolve()
        bundle = current.model.bundle_directory
        if resolved == bundle or bundle in resolved.parents:
            raise ToolError("Configured model bundles cannot be processed as data.")
    for scope in current.pseudonym_scopes.values():
        if scope.key_file is None:
            continue
        try:
            if path.resolve() == scope.key_file.resolve() or path.samefile(scope.key_file):
                raise ToolError(
                    "Configured pseudonymization key files cannot be processed as data."
                )
        except (FileNotFoundError, NotADirectoryError):
            continue


def _checked_input(path: str, current: OutputPolicy) -> str:
    try:
        resolved = resolve_input(path)
    except PathNotAllowed as exc:
        raise ToolError(str(exc)) from None
    _protect_private_resources(resolved, current)
    return str(resolved)


@mcp.tool
async def datafog_policy(path: str | None = None) -> dict[str, Any]:
    """Discover owner policy without returning exact allowlist values or scanning a file.

    Scanning scope means files to check routinely before reading, within allowed
    roots. Explicit scans remain permitted elsewhere within roots. Folder and
    extension restrictions combine; empty lists impose no additional restriction.
    Workflow actions are advisory: this server cannot control other read tools.

    Parameters:
      path: Optional path to check against roots and advisory scanning scope.
    Returns:
      Scope, copy destination, allowlist counts by type, and workflow guidance.
      An optional scope match is configuration guidance, never a clean scan.
    """
    with _contained():
        current = _request_policy()
        try:
            roots = allowed_roots()
            resolved = resolve_input(path) if path is not None else None
        except PathNotAllowed as exc:
            raise ToolError(str(exc)) from None
        result: dict[str, Any] = {
            "advisory": True,
            "allowed_roots": [str(root) for root in roots],
            "scope": {
                "folders": [str(folder) for folder in current.scope_folders],
                "extensions": list(current.scope_extensions),
            },
            "output_directory": str(current.directory) if current.directory else None,
            "allowlist_counts": {kind: len(values) for kind, values in current.allow_exact.items()},
            "workflow": {
                "on_findings": current.on_findings,
                "transform_strategy": current.transform_strategy,
            },
        }
        result["model"] = {
            "configured": current.model is not None,
            "entity_types": sorted(MODEL_ENTITIES),
            "verified": False,
            "setup_command": "datafog-mcp model install",
        }
        result["pseudonymization_scopes"] = list(current.pseudonym_scopes)
        if current.pseudonym_scope is not None:
            result["workflow"]["pseudonym_scope"] = current.pseudonym_scope
        if resolved is not None:
            _protect_private_resources(resolved, current)
            result["scan_before_read"] = current.in_scope(resolved)
        return result


@mcp.tool
async def datafog_scan(
    path: str,
    mode: Mode = "findings",
    entity_types: EntitySelection = None,
) -> dict[str, Any]:
    """
    Detect personal and sensitive data in a file, without reading it into
    context.

    WHEN TO CALL THIS: before the first read of any file that might contain
    personal data - CSV and other text exports, downloads, logs, SQL dumps, or
    anything the user obtained from a third-party service. Use the owner's
    scanning scope for routine checks (datafog_policy can check a path).
    Within that scope, a request to analyze, summarize, convert, or upload a
    file is as much a trigger as a request to check it for PII. Explicit scans
    remain available outside the routine scope, within allowed roots.

    CALL THIS FIRST, BEFORE Read. This tool opens and scans the file itself. If
    you read the file first and then call this tool, the contents are already in
    the conversation and the check is pointless - the exposure you were checking
    for has already happened. Reading afterward is fine; reading before is not.

    WHEN NOT TO CALL IT: source code, configuration tracked in the project's
    repository, lockfiles, or build output.

    INPUTS: UTF-8 text files up to 1 MiB, such as CSV, TSV, JSON, logs, and
    plain text. Other encodings, binary files, and larger files are refused
    with an error rather than scanned. XLSX, PDF, DOCX, images, and archives
    are binary and are not parsed. A refusal is not a clean result: the file
    was not checked.

    It also detects common credentials - API keys, bearer tokens, JWTs,
    credentials embedded in URIs, and PEM private keys - but is not a
    substitute for a dedicated secret scanner. A clean result means none of
    these detectors matched, not that the file holds no secrets.

    Owner-configured exact allowlists apply to this scan and every write tool.
    The response includes advisory policy guidance for the remaining findings.
    Scanning scope guides routine checks; explicit scans elsewhere within
    allowed roots remain permitted. Call datafog_policy to inspect the settings.

    Parameters:
      path: The path of the file to scan.
      mode: What to return. Only "findings" is available: the type and
      offsets of each detected entity.
      entity_types: The types to look for. Defaults to API_KEY, BEARER_TOKEN,
      CREDENTIAL_URI, CREDIT_CARD, DATE, EMAIL, JWT, NPI, PHONE, PRIVATE_KEY,
      SSN, US_ROUTING_NUMBER, and ZIP_CODE. IP_ADDRESS is available on
      request. Omit for the defaults; an empty list is refused.
    Returns:
      A dict with the scanned path, an entity count, a tally per type, and the
      detected entities.
    """
    with _contained():
        return await _scan_file(path, mode, entity_types)


async def _scan_file(
    path: str,
    mode: Mode,
    entity_types: list[str] | None,
) -> dict[str, Any]:
    """
    Scan a file and build the response.

    Parameters:
      path: The file to scan.
      mode: What to return.
      entity_types: The types to keep, or None for the default.
    Returns:
      The tool response describing what was found.
    """
    # Config before the read, so bad input never touches the filesystem
    current = _request_policy()
    config = _config_from(entity_types, current)

    try:
        content = read_text_file(_checked_input(path, current), config.max_bytes)
    except (ReadError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    kept = await _selected_findings(content.text, config, current)

    # The engine reports every detector's match, so one value can appear
    # twice: an NPI is also a valid phone number. Transforming resolves those
    # overlaps, so the scan reports exactly the spans the write tools replace.
    # The transformed text is discarded.
    resolved = await asyncio.to_thread(transform, content.text, kept, transform_config("redact"))

    response = render(
        mode=mode,
        findings=resolved.transformations,
        path=str(content.path),
    )
    response["policy"] = _findings_policy(current, bool(resolved.transformations))
    response["policy"]["scan_before_read"] = current.in_scope(content.path)
    return response


def _findings_policy(current: OutputPolicy, has_findings: bool) -> dict[str, Any]:
    """Use the same advisory findings decision for files and outbound drafts."""
    guidance: dict[str, Any] = {
        "advisory": True,
        "action": current.on_findings if has_findings else "proceed",
    }
    if has_findings and current.on_findings == "transform":
        guidance["transform_strategy"] = current.transform_strategy
        if current.pseudonym_scope is not None:
            guidance["pseudonym_scope"] = current.pseudonym_scope
    return guidance


@mcp.tool
async def datafog_check_text(
    text: str,
    entity_types: EntitySelection = None,
) -> dict[str, Any]:
    """Check an outbound draft already in context before sending or publishing it.

    Use for already-composed email, chat messages, or other outbound text. Never
    read an unscanned file into context to supply this argument: scan its path first.
    The client/model provider may retain tool arguments; this cannot undo exposure
    that happened when composing the draft or putting it into context.

    Returns counts, types, Unicode character offsets, and the owner's advisory
    findings action. It never echoes text, matched values, hashes, or transformed
    drafts, reads source files, writes copies, or sends anything. Existing detectors,
    exact allowlists, overlap handling, and explicitly configured model apply.

    Follow ask/transform/stop guidance. For transform, revise the draft and recheck
    the final version before sending; pseudonymize guidance requires the separate
    file workflow with its configured scope and key. A clean result means only that
    selected detectors found no non-allowlisted matches. It is neither proof the
    draft contains no sensitive data nor authorization to send or publish it.
    Failed checks leave the draft unchecked, never approved to send.

    Parameters:
      text: An already-composed UTF-8 draft, up to 1 MiB in encoded bytes.
      entity_types: Omit for the configured defaults; a nonempty supported list
        selects only those categories. Model categories need explicit model setup.
    Returns:
      Entity count, per-type counts, character spans, and advisory workflow policy.
    """
    with _contained():
        validate_draft({"text": text, "entity_types": entity_types})
        current = _request_policy()
        config = _config_from(entity_types, current)
        kept = await _selected_findings(text, config, current)
        # Resolve exactly the same overlaps as file scans; discard rewritten text.
        resolved = await asyncio.to_thread(transform, text, kept, transform_config("redact"))
        guidance = _findings_policy(current, bool(resolved.transformations))
        guidance["check_before_send"] = True
        return {
            "entity_count": len(resolved.transformations),
            "counts": counts_by_type(resolved.transformations),
            "findings": [finding_to_dict(item) for item in resolved.transformations],
            "policy": guidance,
        }


async def _selected_findings(text: str, config: ScanConfig, current: OutputPolicy) -> list[Finding]:
    """Share detector selection and typed exact allowlists across every check/write."""
    found = await _detections(text, config, current)
    return [
        item
        for item in found
        if config.keeps(item.entity_type)
        and not current.is_allowlisted(
            item.entity_type, text[item.codepoint_range.start : item.codepoint_range.end]
        )
    ]


async def _detections(text: str, config: ScanConfig, current: OutputPolicy) -> list[Finding]:
    """Combine Core findings with explicitly requested, installed model categories."""
    found = await asyncio.to_thread(scan, text)
    if MODEL_ENTITIES.intersection(config.entities):
        assert current.model is not None
        try:
            found += await asyncio.to_thread(
                model_findings, text, current.model.bundle_directory, current.model.timeout_seconds
            )
        except ModelRuntimeError as exc:
            raise ToolError(str(exc)) from None
    return found


async def _transform_to_file(
    path: str,
    output_path: str | None,
    entity_types: list[str] | None,
    strategy: WriteStrategy,
    scope: str | None = None,
) -> dict[str, Any]:
    """
    Write a copy of a file with detected values transformed.

    Parameters:
      path: The file to read.
      output_path: Destination path within the policy's directory, or None for the default name.
      entity_types: The types to transform, or None for the default.
      strategy: Redact, mask, remove, or keyed pseudonymize.
      scope: Required configured scope name for pseudonymize.
    Returns:
      The tool response describing what was replaced.
    """
    copy_policy = _request_policy()
    config = _config_from(entity_types, copy_policy)
    selected = copy_policy.pseudonym_scopes.get(scope) if scope is not None else None
    provider = None
    if strategy == "pseudonymize":
        if selected is None:
            raise ToolError("Pseudonymization scope is not configured.")
        provider = LocalKeyProvider(selected)
        try:
            # Resolve even for clean inputs, then reuse this snapshot for Core.
            await provider.resolve_key(selected.key_ref, selected.key_version)
        except KeyStorageError as exc:
            raise ToolError(str(exc)) from None

    try:
        content = read_text_file(_checked_input(path, copy_policy), config.max_bytes)
    except (ReadError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    source = content.path
    suffix = _OUTPUT_SUFFIXES[strategy]
    destination = (
        Path(output_path)
        if output_path
        else (copy_policy.directory or source.parent) / f"{source.stem}_{suffix}{source.suffix}"
    )

    try:
        destination = resolve_output(str(destination), source, copy_policy)
        _protect_private_resources(destination, copy_policy)
    except PathNotAllowed as exc:
        raise ToolError(str(exc)) from None

    kept = await _selected_findings(content.text, config, copy_policy)

    if strategy == "pseudonymize":
        assert selected is not None and provider is not None
        result = await PrivacyManager(provider=provider).transform(
            content.text,
            kept,
            {
                "default": {
                    "strategy": "pseudonymize",
                    "key_ref": selected.key_ref,
                    "key_version": selected.key_version,
                }
            },
        )
    else:
        result = await asyncio.to_thread(transform, content.text, kept, transform_config(strategy))

    try:
        written = write_text_file(destination, result.text, beside=source, copy_policy=copy_policy)
    except (WriteError, PathNotAllowed) as exc:
        raise ToolError(str(exc)) from exc

    return render_transformation(
        transformations=result.transformations,
        input_path=str(source),
        output_path=str(written),
        strategy=strategy,
    )


@mcp.tool
async def datafog_redact(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
) -> dict[str, Any]:
    """
    Write a copy of a file with personal data replaced by labels.

    Each detected value becomes an unnumbered placeholder naming its kind, such
    as [EMAIL]. The value is destroyed but the reader can still tell what sort
    of thing was there. Every value of the same kind gets the same placeholder,
    so two different emails are not distinguishable in the copy.

    Use datafog_mask to hide the kind as well, or datafog_remove to leave no
    trace that anything was there.

    The original file is not modified. This tool never returns the values it
    replaced, so read the copy to see the result.

    Parameters:
      path: The file to read. UTF-8 text up to 1 MiB, as for datafog_scan.
      output_path: Destination path within the owner-configured output directory,
      or beside the input if none is configured. Defaults to name_redacted.ext.
      entity_types: The types to replace. Defaults to the same types as
      datafog_scan; an empty list is refused.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    with _contained():
        return await _transform_to_file(
            path,
            output_path,
            entity_types,
            strategy="redact",
        )


@mcp.tool
async def datafog_mask(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
) -> dict[str, Any]:
    """
    Write a copy of a file with personal data covered over.

    Each detected value is replaced character for character, so the copy keeps
    the original length and column alignment but reveals neither the value nor
    what kind of value it was.

    Use datafog_redact when the reader should still know what kind of thing was
    removed.

    The original file is not modified. This tool never returns the values it
    replaced, so read the copy to see the result.

    Parameters:
      path: The file to read. UTF-8 text up to 1 MiB, as for datafog_scan.
      output_path: Destination path within the owner-configured output directory,
      or beside the input if none is configured. Defaults to name_masked.ext.
      entity_types: The types to replace. Defaults to the same types as
      datafog_scan; an empty list is refused.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    with _contained():
        return await _transform_to_file(
            path,
            output_path,
            entity_types,
            strategy="mask",
        )


@mcp.tool
async def datafog_remove(
    path: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
) -> dict[str, Any]:
    """
    Write a copy of a file with personal data deleted outright.

    Each detected value is cut from the text. Nothing marks where it was, so the
    copy reads as though the data was never present and positions shift. This is
    the only operation whose output cannot later be inspected to see what was
    taken - the tool response is the only record.

    Use datafog_mask to keep length and alignment, or datafog_redact to leave a
    visible marker naming what was removed.

    The original file is not modified. This tool never returns the values it
    deleted.

    Parameters:
      path: The file to read. UTF-8 text up to 1 MiB, as for datafog_scan.
      output_path: Destination path within the owner-configured output directory,
      or beside the input if none is configured. Defaults to name_removed.ext.
      entity_types: The types to delete. Defaults to the same types as
      datafog_scan; an empty list is refused.
    Returns:
      A dict with both paths, an entity count, and a tally per type.
    """
    with _contained():
        return await _transform_to_file(
            path,
            output_path,
            entity_types,
            strategy="remove",
        )


@mcp.tool
async def datafog_pseudonymize(
    path: str,
    scope: str,
    output_path: str | None = None,
    entity_types: EntitySelection = None,
) -> dict[str, Any]:
    """Write a copy with deterministic pseudonyms using an explicitly configured scope.

    Use when analysis needs consistent linkage across files. Matching exact values
    of the same entity type with the same key yields the same pseudonym. Different
    scope names do not separate outputs if they reference the same key. Changes
    in case, spacing, or detector boundaries may change linkage. Pseudonymization
    does not make data anonymous; other fields and repeated values may identify people.

    The owner must configure a scope and run `datafog-mcp keys create SCOPE`
    locally first. Missing or unavailable keys refuse the operation, even on a
    clean input: keys are never generated, replaced, or stored through MCP tools.
    File contents, matched values, keys, and content digests are never returned.
    Exact allowlists and copy-directory restrictions apply; existing copies and
    the source are never overwritten. Read the resulting copy, not the original.

    Parameters:
      path: UTF-8 input file within allowed roots, up to the configured size limit.
      scope: Owner-configured pseudonymization scope name; never a raw key.
      output_path: Optional new filename within the owner's copy directory.
      entity_types: Entity types to transform, or None for the default set.
    Returns:
      Input/output paths, strategy, entity count, and per-type counts.
    """
    with _contained():
        return await _transform_to_file(path, output_path, entity_types, "pseudonymize", scope)


def run_server() -> None:
    """
    Run the MCP server over stdio, without touching the network.

    FastMCP's startup banner checks PyPI for a newer release, which is the
    server's only outbound request. The banner is suppressed, and the check is
    switched off as well so nothing else in FastMCP can trigger it.
    """
    fastmcp.settings.check_for_updates = "off"
    mcp.run(transport="stdio", show_banner=False)

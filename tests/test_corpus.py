"""
Detection quality on a labeled corpus, measured through datafog_scan.

Each document under tests/data/corpus marks every value a reader would
expect to be found, as [[TYPE|value]]. The markup is stripped before the scan,
so the server sees ordinary text and the labels give exact spans. A finding
counts as correct only when its type and span both match a label.

Results are recorded in baseline.json beside the documents: per-type
precision and recall, and every miss and false alarm. The test fails when a
scan departs from the recorded results, so a change in detection, whether
from the server or an engine upgrade, has to be accepted deliberately. To
accept one, rerun with DATAFOG_UPDATE_CORPUS=1 and review the diff.
"""

from __future__ import annotations

import asyncio
import base64
import difflib
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Any

from fastmcp import Client

from datafog_mcp.config import SUPPORTED_ENTITIES
from datafog_mcp.server import mcp

CORPUS = Path(__file__).parent / "data" / "corpus"
BASELINE = CORPUS / "baseline.json"
UPDATE_VAR = "DATAFOG_UPDATE_CORPUS"

LABEL = re.compile(r"\[\[([A-Z_]+)\|(.*?)\]\]", re.DOTALL)
PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")

# Rendered as Excel writes CSV: a UTF-8 byte-order mark and CRLF line endings
EXCEL_STYLE = {"crm_export.csv"}


def _b64url(claims: Mapping[str, Any]) -> str:
    """
    Encode a JSON object as an unpadded Base64URL segment.

    Parameters:
      claims: The object to encode.
    Returns:
      The segment.
    """
    raw = json.dumps(claims, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _pem(label: str, body: bytes) -> str:
    """
    Wrap bytes in a PEM block.

    Parameters:
      label: The block label, such as PRIVATE KEY.
      body: The bytes to encode.
    Returns:
      The block, with 64-character lines.
    """
    encoded = base64.b64encode(body).decode()
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    return "\n".join(["-----BEGIN " + label + "-----", *lines, "-----END " + label + "-----"])


# Credential-shaped values are assembled here rather than written into the
# documents, so no scannable literal lands in the repository. None is usable.
SECRETS = {
    "github_token": "ghp_" + "Zq7Lm2Xc9Vb4Nn1Kp8Tr5Ws3Yd6Fh0Gj2Aa9",
    "stripe_key": "sk_" + "test_" + "51Hx" + "Qe7Rt2Yu9Io4Pa1Sd8Fg5Hj3Kl",
    "stripe_publishable": "pk_" + "test_" + "51Hx" + "Mn6Bv3Cx0Za7Lk4Jh1Gf8Ds2",
    "aws_key_id": "AKIA" + "Q3EXAMPLE7N4ZP2W",
    "jwt": ".".join(
        [
            _b64url({"alg": "HS256", "typ": "JWT"}),
            _b64url({"sub": "8f2c", "exp": 0}),
            "c2lnbmF0dXJl",
        ]
    ),
    "private_key": _pem("PRIVATE" + " KEY", b"datafog synthetic test key, not usable " * 4),
}


@dataclass(frozen=True)
class Label:
    """
    A value the scan should find.

    Attributes:
      kind: The expected entity type.
      start: Start offset in the rendered text, in code points.
      end: End offset in the rendered text, in code points.
      shown: The value as written in the document, before any placeholder is
        filled, so the baseline never records a credential.
    """

    kind: str
    start: int
    end: int
    shown: str


@dataclass(frozen=True)
class Document:
    """
    A corpus document ready to scan.

    Attributes:
      name: The file name to scan it under.
      text: The rendered text, with labels stripped.
      labels: What the scan should find.
    """

    name: str
    text: str
    labels: tuple[Label, ...]


def _fill(raw: str, crlf: bool) -> str:
    """
    Fill placeholders and set line endings in a piece of a document.

    Parameters:
      raw: Text from the document template.
      crlf: Whether to use CRLF line endings.
    Returns:
      The text as it will be scanned.
    """
    text = PLACEHOLDER.sub(lambda match: SECRETS[match[1]], raw)
    return text.replace("\n", "\r\n") if crlf else text


def load(template: Path) -> Document:
    """
    Render a corpus template into scannable text and its labels.

    Parameters:
      template: A .in file under the corpus directory.
    Returns:
      The rendered document.
    """
    name = template.name.removesuffix(".in")
    excel = name in EXCEL_STYLE
    source = template.read_text(encoding="utf-8")

    text = "﻿" if excel else ""
    labels: list[Label] = []
    position = 0
    for match in LABEL.finditer(source):
        text += _fill(source[position : match.start()], excel)
        value = _fill(match[2], excel)
        labels.append(Label(match[1], len(text), len(text) + len(value), match[2]))
        text += value
        position = match.end()
    text += _fill(source[position:], excel)

    return Document(name=name, text=text, labels=tuple(labels))


def corpus() -> list[Document]:
    """
    Load every corpus document.

    Returns:
      The documents, sorted by name.
    """
    return [load(template) for template in sorted(CORPUS.glob("*.in"))]


def _scan_all(documents: Iterable[Document], workdir: Path) -> dict[str, list[dict[str, Any]]]:
    """
    Write each document to disk and scan it through the MCP server.

    Every supported type is requested, so types off by default are measured
    too.

    Parameters:
      documents: The documents to scan.
      workdir: Where to write them.
    Returns:
      Each document's findings, keyed by name.
    """

    async def run() -> dict[str, list[dict[str, Any]]]:
        results: dict[str, list[dict[str, Any]]] = {}
        async with Client(mcp) as client:
            for document in documents:
                path = workdir / document.name
                path.write_text(document.text, encoding="utf-8", newline="")
                arguments = {"path": str(path), "entity_types": sorted(SUPPORTED_ENTITIES)}
                result = await client.call_tool("datafog_scan", arguments)
                results[document.name] = (result.structured_content or {})["findings"]
        return results

    return asyncio.run(run())


def _describe(text: str, kind: str, start: int, shown: str) -> str:
    """
    Describe a miss or false alarm for the baseline.

    Parameters:
      text: The rendered document.
      kind: The entity type.
      start: Where the span starts.
      shown: The value to show.
    Returns:
      A line such as "line 3: PHONE 4815162342".
    """
    line = text.count("\n", 0, start) + 1
    return f"line {line}: {kind} {json.dumps(shown, ensure_ascii=False)}"


def score(document: Document, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Compare one document's findings with its labels.

    Parameters:
      document: The labeled document.
      findings: What the scan reported.
    Returns:
      Per-type counts, and descriptions of each miss and false alarm.
    """
    expected = {(label.kind, label.start, label.end): label for label in document.labels}
    found = {(item["type"], item["start"], item["end"]) for item in findings}

    missed = [
        _describe(document.text, label.kind, label.start, label.shown)
        for key, label in expected.items()
        if key not in found
    ]
    false_alarms = [
        _describe(document.text, kind, start, document.text[start:end])
        for kind, start, end in sorted(found - expected.keys(), key=lambda span: span[1])
    ]

    counts: dict[str, dict[str, int]] = {}
    for kind, *_ in expected:
        counts.setdefault(kind, {"labeled": 0, "found": 0, "correct": 0})["labeled"] += 1
    for kind, *_ in found:
        counts.setdefault(kind, {"labeled": 0, "found": 0, "correct": 0})["found"] += 1
    for kind, *_ in found & expected.keys():
        counts[kind]["correct"] += 1

    return {"counts": counts, "missed": missed, "false_alarms": false_alarms}


def _ratio(numerator: int, denominator: int) -> float | None:
    """
    Divide, rounding for the record.

    Parameters:
      numerator: Correct findings.
      denominator: Findings or labels.
    Returns:
      The ratio to three places, or None when there is nothing to divide by.
    """
    return round(numerator / denominator, 3) if denominator else None


def summarize(scored: Mapping[str, dict[str, Any]]) -> dict[str, Any]:
    """
    Build the baseline record from every document's score.

    Parameters:
      scored: Each document's score, keyed by name.
    Returns:
      Per-type totals with precision and recall, and per-document details.
    """
    totals: dict[str, dict[str, int]] = {}
    for result in scored.values():
        for kind, counts in result["counts"].items():
            tally = totals.setdefault(kind, {"labeled": 0, "found": 0, "correct": 0})
            for field, value in counts.items():
                tally[field] += value

    return {
        "engine": f"datafog-core {version('datafog-core')}",
        "totals": {
            kind: {
                **tally,
                "precision": _ratio(tally["correct"], tally["found"]),
                "recall": _ratio(tally["correct"], tally["labeled"]),
            }
            for kind, tally in sorted(totals.items())
        },
        "documents": {
            name: {"missed": result["missed"], "false_alarms": result["false_alarms"]}
            for name, result in sorted(scored.items())
        },
    }


def test_every_supported_type_is_labeled() -> None:
    """
    The corpus measures every type the server advertises.

    A type added to the engine fails this until the corpus covers it.
    """
    labeled = {label.kind for document in corpus() for label in document.labels}

    assert labeled >= SUPPORTED_ENTITIES, sorted(SUPPORTED_ENTITIES - labeled)


def test_labels_are_supported_types() -> None:
    """A label naming a type the server cannot report is a typo."""
    labeled = {label.kind for document in corpus() for label in document.labels}

    assert labeled <= SUPPORTED_ENTITIES, sorted(labeled - SUPPORTED_ENTITIES)


def test_scan_matches_the_recorded_baseline(tmp_path: Path) -> None:
    """
    Detection on the corpus is exactly what baseline.json records.

    Parameters:
      tmp_path: Where the rendered documents are written.
    """
    documents = corpus()
    findings = _scan_all(documents, tmp_path)
    measured = summarize({doc.name: score(doc, findings[doc.name]) for doc in documents})

    current = json.dumps(measured, indent=2, ensure_ascii=False) + "\n"
    if os.environ.get(UPDATE_VAR):
        BASELINE.write_text(current, encoding="utf-8")

    recorded = BASELINE.read_text(encoding="utf-8")
    diff = difflib.unified_diff(
        recorded.splitlines(), current.splitlines(), "baseline.json", "measured", lineterm=""
    )
    changes = "\n".join(diff)
    assert not changes, f"detection changed; rerun with {UPDATE_VAR}=1 to accept\n{changes}"

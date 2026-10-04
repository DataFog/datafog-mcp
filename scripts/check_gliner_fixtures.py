"""Evaluate a CI-only GLiNER detector on built-in synthetic fixtures, never user-supplied files."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from collections.abc import Callable
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EXPECTED_MODEL = ("urchade/gliner_small-v2.1", "4e091416cf7c3481db542c2a3d26156916f3a47f")


class EvaluationError(Exception):
    """Only fixed, non-sensitive messages may cross the command-line boundary."""


@dataclass(frozen=True)
class Fixture:
    name: str
    text: str
    expected: tuple[tuple[str, str], ...]


FIXTURES = (
    Fixture(
        "prose",
        "Patient name: Jane Doe. Home address: 123 Main Street, Springfield.",
        (("person", "Jane Doe"), ("address", "123 Main Street, Springfield")),
    ),
    Fixture(
        "csv",
        'customer_name,street_address\nJane Doe,"123 Main Street, Springfield"\n',
        (("person", "Jane Doe"), ("address", "123 Main Street, Springfield")),
    ),
    Fixture("unicode_offsets", "Résumé 🧪 — Patient name: Jane Doe.", (("person", "Jane Doe"),)),
    Fixture("clean", "The build completed successfully. All unit tests passed.", ()),
)


def evaluation_fixtures() -> tuple[Fixture, ...]:
    """Read only the original committed CSV and clean notes, alongside diagnostics."""
    directory = Path(__file__).resolve().parents[1] / "tests" / "data" / "user_flows"
    originals = []
    try:
        with (directory / "customers.csv").open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames is None or not {"full_name", "street_address"}.issubset(
                reader.fieldnames
            ):
                raise EvaluationError("Original customer fixture lacks required columns.")
            for record, row in enumerate(reader, start=1):
                if None in row or any(value is None for value in row.values()):
                    raise EvaluationError("Original customer fixture has an invalid row.")
                if not row["full_name"] or not row["street_address"]:
                    raise EvaluationError("Original customer fixture lacks expected values.")
                # Separate headers retain context without turning the city into the street span.
                text = "\n".join(f"{key}: {value}" for key, value in row.items())
                originals.append(
                    Fixture(
                        f"original_customers_record_{record}",
                        text,
                        (("person", row["full_name"]), ("address", row["street_address"])),
                    )
                )
        if not originals:
            raise EvaluationError("Original customer fixture is empty.")
        originals.append(
            Fixture(
                "original_clean_notes",
                (directory / "notes_clean.txt").read_text(encoding="utf-8"),
                (),
            )
        )
    except (OSError, UnicodeError, csv.Error):
        raise EvaluationError("Cannot read the committed original fixtures.") from None
    return (*FIXTURES, *originals)


def load_predictor(model_directory: Path) -> Callable[[str], object]:
    """Load only prepared local weights; inference must not download a floating revision."""
    try:
        provenance = json.loads((model_directory / "provenance.json").read_text())
        if (provenance["id"], provenance["revision"]) != EXPECTED_MODEL:
            raise EvaluationError("Prepared model does not match the pinned evaluation model.")
    except (OSError, ValueError, KeyError, TypeError):
        raise EvaluationError("Prepared model provenance is missing or invalid.") from None

    from gliner import GLiNER

    model = GLiNER.from_pretrained(str(model_directory), local_files_only=True)
    model.eval()

    def predict(text: str) -> object:
        # Check the model's actual splitter too; whitespace alone undercounts punctuation.
        if len(list(model.data_processor.words_splitter(text))) > 256:
            raise EvaluationError("Fixture exceeds the model token budget; refusing truncation.")
        findings = model.predict_entities(text, ["person", "address"], threshold=0.5)
        return {
            "model": {"id": EXPECTED_MODEL[0], "revision": EXPECTED_MODEL[1]},
            "findings": [
                {key: finding[key] for key in ("label", "start", "end", "score")}
                for finding in findings
            ],
        }

    return predict


def validate(payload: object, text: str) -> tuple[tuple[str, str], set[tuple[str, int, int]]]:
    if not isinstance(payload, dict) or set(payload) != {"model", "findings"}:
        raise EvaluationError("Model output has an invalid schema.")
    model = payload["model"]
    if (
        not isinstance(model, dict)
        or set(model) != {"id", "revision"}
        or any(not isinstance(model.get(key), str) or not model[key] for key in ("id", "revision"))
    ):
        raise EvaluationError("Model output lacks model provenance.")
    if (model["id"], model["revision"]) != EXPECTED_MODEL:
        raise EvaluationError("Model does not match the pinned evaluation model.")
    findings = payload["findings"]
    if not isinstance(findings, list) or len(findings) > 100:
        raise EvaluationError("Model output has invalid findings.")
    spans: set[tuple[str, int, int]] = set()
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != {"label", "start", "end", "score"}:
            raise EvaluationError("Model output has an invalid finding schema.")
        label, start, end, score = (finding[key] for key in ("label", "start", "end", "score"))
        if (
            label not in ("person", "address")
            or type(start) is not int
            or type(end) is not int
            or not 0 <= start < end <= len(text)
            or type(score) not in (int, float)
            or not math.isfinite(score)
            or not 0.5 <= score <= 1
        ):
            raise EvaluationError("Model output has invalid spans or confidence.")
        span = (label, start, end)
        if span in spans:
            raise EvaluationError("Model output has duplicate findings.")
        spans.add(span)
    return (model["id"], model["revision"]), spans


def evaluate(predict: Callable[[str], object]) -> dict[str, Any]:
    provenance: tuple[str, str] | None = None
    results = []
    for fixture in evaluation_fixtures():
        if len(fixture.text) > 4096 or len(re.findall(r"\w+|[^\w\s]", fixture.text)) > 256:
            raise EvaluationError("Fixture exceeds the text or token budget; refusing truncation.")
        model, actual = validate(predict(fixture.text), fixture.text)
        if provenance is not None and model != provenance:
            raise EvaluationError("Model changed during evaluation; rerun against one revision.")
        provenance = model
        expected = {
            (label, fixture.text.index(value), fixture.text.index(value) + len(value))
            for label, value in fixture.expected
        }
        results.append(
            {
                "case": fixture.name,
                "expected": len(expected),
                "matched": len(actual & expected),
                "missed": len(expected - actual),
                "unexpected": len(actual - expected),
                "passed": actual == expected,
            }
        )
    # Emit only metrics and fixed case names, never full source text or returned entities.
    return {
        "model": {"id": EXPECTED_MODEL[0], "revision": EXPECTED_MODEL[1]},
        "cases": results,
        "passed": all(result["passed"] for result in results),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        # Keep third-party loader chatter out of the machine-readable metrics report.
        with redirect_stdout(sys.stderr):
            result = evaluate(load_predictor(args.model_directory))
    except EvaluationError as error:
        print(f"GLiNER fixture evaluation failed: {error}", file=sys.stderr)
        return 2
    except Exception:
        print("GLiNER fixture evaluation failed unexpectedly.", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

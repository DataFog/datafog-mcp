"""Offline tests of the optional CI-only model evaluator; no model download needed."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "check_gliner_fixtures",
    Path(__file__).resolve().parents[1] / "scripts/check_gliner_fixtures.py",
)
assert _spec is not None and _spec.loader is not None
runner = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = runner
_spec.loader.exec_module(runner)


def payload(findings=None):
    return {
        "model": {"id": runner.EXPECTED_MODEL[0], "revision": runner.EXPECTED_MODEL[1]},
        "findings": findings or [],
    }


def finding(label="person", start=0, end=4, score=0.9):
    return {"label": label, "start": start, "end": end, "score": score}


def perfect_predict(text: str):
    fixture = next(case for case in runner.evaluation_fixtures() if case.text == text)
    return payload(
        [
            finding(label, text.index(value), text.index(value) + len(value))
            for label, value in fixture.expected
        ]
    )


def test_exact_fixture_contract_and_metrics_only():
    result = runner.evaluate(perfect_predict)
    assert result["passed"]
    assert len(result["cases"]) == len(runner.evaluation_fixtures())
    assert "Jane Doe" not in json.dumps(result)


def test_missed_and_unexpected_findings_fail():
    result = runner.evaluate(lambda text: payload())
    assert not result["passed"]
    assert result["cases"][0]["missed"] == 2
    assert result["cases"][-1]["passed"]
    result = runner.evaluate(lambda text: payload([finding()]))
    assert not result["passed"]
    assert result["cases"][-1]["unexpected"] == 1


def test_unicode_byte_offsets_cannot_pass_as_codepoint_offsets():
    def wrong_byte_predict(text: str):
        result = perfect_predict(text)
        for entity in result["findings"]:
            entity["start"] = len(text[: entity["start"]].encode())
            entity["end"] = len(text[: entity["end"]].encode())
        return result

    with pytest.raises(runner.EvaluationError, match="spans"):
        runner.evaluate(wrong_byte_predict)


@pytest.mark.parametrize(
    "bad",
    [
        finding(start=True),
        finding(end=100),
        finding(start=-1),
        finding(end=0),
        finding(score=float("nan")),
        finding(score=0.49),
        finding(score=True),
        finding(score=1.01),
        finding(label="email"),
        {"label": "person", "start": 0, "end": 4},
        {**finding(), "text": "leaky"},
    ],
)
def test_rejects_invalid_findings(bad):
    with pytest.raises(runner.EvaluationError):
        runner.validate(payload([bad]), "Jane Doe")


def test_rejects_duplicates_and_unpinned_model():
    with pytest.raises(runner.EvaluationError, match="duplicate"):
        runner.validate(payload([finding(), finding()]), "Jane Doe")
    response = payload()
    response["model"]["revision"] = "other"
    with pytest.raises(runner.EvaluationError, match="pinned"):
        runner.validate(response, "Jane Doe")


def test_command_reports_metrics_and_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(runner, "load_predictor", lambda path: perfect_predict)
    assert runner.main(["--model-directory", "/synthetic/model"]) == 0
    assert json.loads(capsys.readouterr().out)["passed"]
    monkeypatch.setattr(runner, "load_predictor", lambda path: lambda text: payload())
    assert runner.main(["--model-directory", "/synthetic/model"]) == 1
    assert not json.loads(capsys.readouterr().out)["passed"]


def test_model_loading_errors_fail_explicitly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    def fail(path):
        raise RuntimeError("failed to load")

    monkeypatch.setattr(runner, "load_predictor", fail)
    assert runner.main(["--model-directory", "/synthetic/model"]) == 2
    assert "failed unexpectedly" in capsys.readouterr().err


@pytest.mark.parametrize("text", ["x" * 4097, "word " * 257])
def test_oversized_fixture_fails_before_inference(monkeypatch: pytest.MonkeyPatch, text: str):
    monkeypatch.setattr(runner, "FIXTURES", (runner.Fixture("oversized", text, ()),))

    def no_inference(text):
        pytest.fail("oversized text reached inference")

    with pytest.raises(runner.EvaluationError, match="budget"):
        runner.evaluate(no_inference)


def test_prepared_model_provenance_required(tmp_path: Path):
    with pytest.raises(runner.EvaluationError, match="provenance"):
        runner.load_predictor(tmp_path)
    (tmp_path / "provenance.json").write_text(json.dumps({"id": "other", "revision": "floating"}))
    with pytest.raises(runner.EvaluationError, match="pinned"):
        runner.load_predictor(tmp_path)


def test_original_csv_rows_and_clean_notes_are_included():
    fixtures = runner.evaluation_fixtures()
    originals = [case for case in fixtures if case.name.startswith("original_customers_record_")]
    assert len(originals) == 5
    assert sum(len(case.expected) for case in originals) == 10
    assert "full_name: Jane Doe" in originals[0].text
    assert "street_address: 1600 Fake Street\ncity: San Francisco" in originals[0].text
    assert originals[-1].expected == (("person", "Wei Chen"), ("address", "Musterstrasse 5"))
    notes = next(case for case in fixtures if case.name == "original_clean_notes")
    assert "Quarterly planning notes" in notes.text
    assert notes.expected == ()


def test_schema_failure_is_not_a_quality_mismatch(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(runner, "load_predictor", lambda path: lambda text: {"invalid": True})
    assert runner.main(["--model-directory", "/synthetic/model"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "schema" in captured.err


def test_model_stdout_cannot_corrupt_json_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    def load(path):
        print("model loader progress")
        return perfect_predict

    monkeypatch.setattr(runner, "load_predictor", load)
    assert runner.main(["--model-directory", "/synthetic/model"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["passed"]
    assert "model loader progress" in captured.err

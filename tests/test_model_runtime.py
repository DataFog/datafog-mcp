"""Native transport contract tests; deterministic peers require no model download."""

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from datafog_mcp.model_runtime import (
    ModelRuntimeError,
    _convert,
    close_model_runtimes,
    model_findings,
)


@pytest.fixture(autouse=True)
def cleanup(monkeypatch):
    # Windows does not execute shebang scripts. Only generated test peers are
    # launched with Python; real PE executables use the production argv intact.
    if sys.platform == "win32":
        import datafog_mcp.model_runtime as module

        original = module.subprocess.Popen

        def popen(args, *positional, **kwargs):
            executable = Path(args[0])
            with executable.open("rb") as stream:
                is_script = stream.read(2) == b"#!"
            if is_script:
                args = [sys.executable, *args]
            return original(args, *positional, **kwargs)

        monkeypatch.setattr(module.subprocess, "Popen", popen)
    yield
    close_model_runtimes()


def bundle(tmp_path: Path, body: str) -> Path:
    for name in ("model.onnx", "tokenizer.json", "config.json"):
        (tmp_path / name).touch()
    executable = tmp_path / ("datafog-pii.exe" if sys.platform == "win32" else "datafog-pii")
    executable.write_text(f"#!{sys.executable}\nimport sys,json,time\n{body}\n")
    executable.chmod(0o700)
    return tmp_path


def test_unicode_offsets_and_label_filter():
    result = _convert(
        "🙂 José",
        {
            "redacted": "discard this",
            "findings": [
                {"label": "first_name", "start": 5, "end": 10, "confidence": 0.9},
                {"label": "email", "start": 0, "end": 1},
            ],
        },
    )
    assert len(result) == 1
    assert result[0].entity_type == "PERSON"
    assert result[0].matched_text == "José"
    assert (result[0].codepoint_range.start, result[0].codepoint_range.end) == (2, 6)
    assert (result[0].byte_range.start, result[0].byte_range.end) == (5, 10)


@pytest.mark.parametrize(
    "start,end,confidence", [(1, 4, 1), (0, 3, 1), (0, 4, 2), (0, 4, float("nan"))]
)
def test_invalid_spans_fail_closed(start, end, confidence):
    with pytest.raises(ModelRuntimeError):
        _convert(
            "🙂",
            {
                "findings": [
                    {"label": "first_name", "start": start, "end": end, "confidence": confidence}
                ]
            },
        )


def test_missing_bundle_is_explicit(tmp_path):
    with pytest.raises(ModelRuntimeError, match="missing"):
        model_findings("Jane", tmp_path)


def test_native_process_reused_serialized(tmp_path):
    path = bundle(
        tmp_path,
        """
count=0
for line in sys.stdin:
    count+=1
    text=json.loads(line)['text']
    print(json.dumps({'findings':[{'label':'first_name','start':0,'end':len(text.encode()),
        'confidence':count/100}]}), flush=True)
""",
    )
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: model_findings("Jane", path), range(4)))
    scores: list[float] = []
    for result in results:
        score = result[0].confidence
        assert score is not None
        scores.append(round(score, 2))
    assert sorted(scores) == [0.01, 0.02, 0.03, 0.04]


def test_timeout_terminates_and_can_retry(tmp_path):
    path = bundle(tmp_path, "for line in sys.stdin: time.sleep(10)")
    with pytest.raises(ModelRuntimeError, match="timed out"):
        model_findings("Jane", path, 0.05)
    bundle(tmp_path, "for line in sys.stdin: print(json.dumps({'findings':[]}), flush=True)")
    assert model_findings("Jane", path) == []


@pytest.mark.parametrize("response", ['{"error":"secret jane@example.com"}', "not-json", "{}"])
def test_bad_responses_never_echo_text(tmp_path, response):
    path = bundle(tmp_path, f"for line in sys.stdin: print({response!r}, flush=True)")
    with pytest.raises(ModelRuntimeError) as error:
        model_findings("jane@example.com", path)
    assert "jane@example.com" not in str(error.value)


def test_real_bundle_opt_in():
    path = os.environ.get("DATAFOG_TEST_MODEL_BUNDLE")
    if not path:
        pytest.skip("Local experimental model bundle not configured")
    text = "🙂 Customer José García lives at 42 Sample Avenue."
    findings = model_findings(text, path)
    assert [(f.entity_type, f.matched_text) for f in findings] == [
        ("PERSON", "José"),
        ("PERSON", "García"),
        ("STREET_ADDRESS", "42 Sample Avenue"),
    ]
    assert model_findings("The report completed successfully.", path) == []


def test_segment_offsets_ownership_and_unicode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import datafog_mcp.model_runtime as module

    monkeypatch.setattr(module, "MODEL_WINDOW_CHARS", 64)
    monkeypatch.setattr(module, "MODEL_OVERLAP_CHARS", 24)
    path = bundle(
        tmp_path,
        """
for line in sys.stdin:
    text=json.loads(line)['text']
    findings=[]
    start=0
    while (start:=text.find('Jane Doe',start))>=0:
        findings.append({'label':'first_name','start':len(text[:start].encode()),
            'end':len(text[:start+8].encode()),'confidence':1})
        start+=8
    print(json.dumps({'findings':findings}),flush=True)
""",
    )
    text = "🙂" + "x " * 20 + "Jane Doe" + "x " * 20 + "Jane Doe" + "x " * 20
    results = model_findings(text, path)
    assert len(results) == 2
    assert [f.codepoint_range.start for f in results] == [41, 89]
    assert [f.byte_range.start for f in results] == [44, 92]


def test_owned_segment_edge_entity_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import datafog_mcp.model_runtime as module

    monkeypatch.setattr(module, "MODEL_WINDOW_CHARS", 64)
    monkeypatch.setattr(module, "MODEL_OVERLAP_CHARS", 24)
    path = bundle(
        tmp_path,
        """
for line in sys.stdin:
    print(json.dumps({'findings':[{'label':'first_name','start':20,'end':64}]}),flush=True)
""",
    )
    with pytest.raises(ModelRuntimeError, match="segment boundaries"):
        model_findings("x" * 100, path)


def test_real_csv_mcp_scan_and_transform(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import asyncio
    import csv
    import io

    from fastmcp import Client

    from datafog_mcp.server import mcp

    path = os.environ.get("DATAFOG_TEST_MODEL_BUNDLE")
    if not path:
        pytest.skip("Local experimental model bundle not configured")
    policy = tmp_path / "policy.toml"
    policy.write_text(f"version = 1\n[model]\nbundle_directory = {json.dumps(path)}\n")
    monkeypatch.setenv("DATAFOG_POLICY_PATH", str(policy))
    source = tmp_path / "customers.csv"
    original = (Path(__file__).parent / "data/user_flows/customers.csv").read_bytes()
    source.write_bytes(original)

    async def run():
        async with Client(mcp) as client:
            scan_result = (
                await client.call_tool(
                    "datafog_scan",
                    {"path": str(source), "entity_types": ["PERSON", "STREET_ADDRESS"]},
                )
            ).structured_content
            assert scan_result is not None
            assert scan_result["counts"] == {"PERSON": 10, "STREET_ADDRESS": 5}
            assert "Jane" not in json.dumps(scan_result)
            assert "Musterstrasse" not in json.dumps(scan_result)
            for tool, suffix in [
                ("datafog_redact", "redact"),
                ("datafog_mask", "mask"),
                ("datafog_remove", "remove"),
            ]:
                dest = tmp_path / f"{suffix}.csv"
                result = (
                    await client.call_tool(
                        tool,
                        {
                            "path": str(source),
                            "output_path": str(dest),
                            "entity_types": ["PERSON", "STREET_ADDRESS"],
                        },
                    )
                ).structured_content
                assert result is not None
                assert result["counts"] == {"PERSON": 10, "STREET_ADDRESS": 5}
                changed = list(csv.reader(io.StringIO(dest.read_text())))
                before = list(csv.reader(io.StringIO(original.decode())))
                assert len(changed) == len(before)
                assert changed[0] == before[0]
                for old, new in zip(before[1:], changed[1:], strict=True):
                    assert len(new) == len(old)
                    for index in range(len(old)):
                        if index not in (1, 4):
                            assert new[index] == old[index]
                    assert old[1] not in new[1]
                    assert old[4] not in new[4]
            assert source.read_bytes() == original

    asyncio.run(run())


def test_changed_bundle_restarts_process(tmp_path: Path):
    from datafog_mcp.model_runtime import model_signature

    path = bundle(
        tmp_path,
        """
count=0
for line in sys.stdin:
    count+=1
    print(json.dumps({'findings':[{'label':'first_name','start':0,'end':4,
                                  'confidence':count/100}]}),flush=True)
""",
    )
    original = model_signature(path)
    assert model_findings("Jane", path)[0].confidence == pytest.approx(0.01)
    assert model_findings("Jane", path)[0].confidence == pytest.approx(0.02)
    (path / "calibration.json").write_text('{"threshold":0.8}')
    assert model_signature(path) != original
    assert model_findings("Jane", path)[0].confidence == pytest.approx(0.01)


def test_csv_model_deadline_is_shared_and_writes_no_partial_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import asyncio
    from types import SimpleNamespace

    from datafog_core import Finding, TextRange
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    import datafog_mcp.model_runtime as runtime
    import datafog_mcp.server as server

    clock = [100.0]
    budgets: list[float] = []

    def fake_model(text: str, bundle_directory: object, timeout_seconds: float):
        budgets.append(timeout_seconds)
        clock[0] += 6
        start = text.index("Jane")
        return [
            Finding(
                "PERSON",
                "Jane",
                TextRange(start, start + 4),
                TextRange(start, start + 4),
                "test-model",
            )
        ]

    monkeypatch.setattr(server, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(runtime, "model_findings", fake_model)
    policy = tmp_path / "policy.toml"
    policy.write_text(
        'version=1\n[model]\nbundle_directory="/unused-test-bundle"\ntimeout_seconds=10\n'
    )
    monkeypatch.setenv("DATAFOG_POLICY_PATH", str(policy))
    source, destination = tmp_path / "source.csv", tmp_path / "redacted.csv"
    original = "name\nJane\nJane\nJane\n"
    source.write_text(original)

    async def run():
        async with Client(server.mcp) as client:
            with pytest.raises(ToolError, match="timed out"):
                await client.call_tool(
                    "datafog_redact",
                    {
                        "path": str(source),
                        "output_path": str(destination),
                        "entity_types": ["PERSON"],
                    },
                )

    asyncio.run(run())
    assert budgets == [10, 4]
    assert not destination.exists()
    assert source.read_text() == original


@pytest.mark.parametrize(
    "platform_name,expected",
    [("win32", "datafog-pii.exe"), ("linux", "datafog-pii"), ("darwin", "datafog-pii")],
)
def test_executable_name_matches_platform(monkeypatch, platform_name, expected):
    import datafog_mcp.model_runtime as module

    monkeypatch.setattr(module, "sys", SimpleNamespace(platform=platform_name))
    assert module._executable_name() == expected

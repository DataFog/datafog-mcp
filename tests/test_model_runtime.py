"""Native transport contract tests; deterministic peers require no model download."""

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from datafog_mcp.model_runtime import (
    ModelRuntimeError,
    _convert,
    close_model_runtimes,
    model_findings,
)


@pytest.fixture(autouse=True)
def cleanup(monkeypatch: pytest.MonkeyPatch):
    import datafog_mcp.model_runtime as module

    # Transport unit tests isolate the peer protocol; installer tests verify integrity.
    monkeypatch.setattr(module, "verify_bundle", lambda path: None)
    # Windows does not execute shebang scripts. Only generated test peers are
    # launched with Python; real PE executables use the production argv intact.
    if sys.platform == "win32":
        import datafog_mcp.model_runtime as module

        class ScriptPeerPopen(subprocess.Popen[bytes]):
            def __init__(self, args: list[str], *positional: Any, **kwargs: Any):
                executable = Path(args[0])
                with executable.open("rb") as stream:
                    is_script = stream.read(2) == b"#!"
                if is_script:
                    args = [sys.executable, *args]
                super().__init__(args, *positional, **kwargs)

        # Confine the shim to the adapter. MCP's Windows utilities must retain
        # the real, subscriptable subprocess.Popen class at import time.
        monkeypatch.setattr(
            module,
            "subprocess",
            SimpleNamespace(
                Popen=ScriptPeerPopen, PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL
            ),
        )
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
                {"label": "email", "start": 5, "end": 10},
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


@pytest.mark.parametrize(
    "platform_name,expected",
    [("win32", "datafog-pii.exe"), ("linux", "datafog-pii"), ("darwin", "datafog-pii")],
)
def test_executable_name_matches_platform(
    monkeypatch: pytest.MonkeyPatch, platform_name: str, expected: str
):
    import datafog_mcp.model_runtime as module

    monkeypatch.setattr(module, "sys", SimpleNamespace(platform=platform_name))
    assert module._executable_name() == expected


def test_unknown_native_label_is_refused():
    with pytest.raises(ModelRuntimeError, match="label"):
        _convert("Jane", {"findings": [{"label": "PERSON", "start": 0, "end": 4}]})


def test_deadline_includes_runtime_setup_wait(tmp_path: Path):
    import datafog_mcp.model_runtime as module

    path = bundle(tmp_path, "for line in sys.stdin: print('{}', flush=True)")
    with module._registry_lock, pytest.raises(ModelRuntimeError, match="runtime setup"):
        model_findings("Jane", path, 0.01)


def test_verification_cannot_reset_inference_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import datafog_mcp.model_runtime as module

    path = bundle(tmp_path, "for line in sys.stdin: print('{}', flush=True)")
    clock = [100.0]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))

    def verify(path: Path) -> None:
        clock[0] += 11

    monkeypatch.setattr(module, "verify_bundle", verify)
    with pytest.raises(ModelRuntimeError, match="timed out"):
        model_findings("Jane", path, 10)

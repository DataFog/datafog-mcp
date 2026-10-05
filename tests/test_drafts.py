"""Outbound draft checks share file policy without echoing, rewriting, or sending text."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import policy, server
from datafog_mcp.config import DEFAULT_MAX_BYTES
from datafog_mcp.paths import ALLOWED_ROOTS_VAR
from test_model_install import release as release
from test_model_workflow import installed_model as installed_model

DRAFT = "🙂 Private message for private-person@example.com. Keep DRAFT_SENTINEL here."
EMAIL = "private-person@example.com"


def call(**arguments: Any) -> Any:
    async def run() -> Any:
        async with Client(server.mcp) as client:
            return await client.call_tool("datafog_check_text", arguments)

    return asyncio.run(run())


def configure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    config = tmp_path / "policy.toml"
    config.write_text("version=1\n" + body, encoding="utf-8")
    monkeypatch.setattr(policy, "POLICY_FILE", config)


def test_draft_returns_only_findings_and_advisory_guidance() -> None:
    result = call(text=DRAFT, entity_types=["EMAIL"])
    data = result.structured_content
    assert data == {
        "entity_count": 1,
        "counts": {"EMAIL": 1},
        "findings": [
            {"type": "EMAIL", "start": DRAFT.index(EMAIL), "end": DRAFT.index(EMAIL) + len(EMAIL)}
        ],
        "policy": {"advisory": True, "action": "ask", "check_before_send": True},
    }
    payload = str(result.content) + json.dumps(data)
    for value in (EMAIL, "Private message", "DRAFT_SENTINEL", DRAFT):
        assert value not in payload


def test_draft_matches_file_counts_and_overlap_resolution(tmp_path: Path) -> None:
    text = "NPI: 1234567893; " + DRAFT
    source = tmp_path / "source.txt"
    source.write_text(text)

    async def compare() -> None:
        async with Client(server.mcp) as client:
            file = (
                await client.call_tool("datafog_scan", {"path": str(source)})
            ).structured_content
            draft = (
                await client.call_tool("datafog_check_text", {"text": text})
            ).structured_content
            assert file is not None and draft is not None
            for field in ("entity_count", "counts", "findings"):
                assert draft[field] == file[field]
            assert draft["counts"]["NPI"] == 1
            assert "PHONE" not in draft["counts"]

    asyncio.run(compare())
    assert source.read_text() == text
    assert list(tmp_path.iterdir()) == [source]


@pytest.mark.parametrize("action", ["ask", "stop", "transform"])
def test_draft_uses_owner_policy_and_requires_recheck_after_transform(
    action: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(
        tmp_path, monkeypatch, f'[workflow]\non_findings="{action}"\ntransform_strategy="mask"'
    )
    data = call(text=DRAFT).structured_content
    assert data["policy"]["action"] == action
    assert data["policy"]["advisory"] is True
    assert data["policy"]["check_before_send"] is True
    assert ("transform_strategy" in data["policy"]) == (action == "transform")
    if action == "transform":
        assert data["policy"]["transform_strategy"] == "mask"
    # Checking the revised, already-composed draft is a separate explicit call.
    revised = "Public message with no identifiers."
    assert call(text=revised).structured_content["policy"]["action"] == "proceed"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["policy.toml"]


def test_pseudonymize_guidance_names_scope_without_creating_or_reading_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(
        tmp_path,
        monkeypatch,
        '[workflow]\non_findings="transform"\ntransform_strategy="pseudonymize"\n'
        'pseudonym_scope="customers"\n[pseudonymization.scopes.customers]\n'
        'key_ref="customer-key"\n',
    )
    data = call(text=DRAFT).structured_content
    assert data["policy"]["transform_strategy"] == "pseudonymize"
    assert data["policy"]["pseudonym_scope"] == "customers"
    assert "customer-key" not in json.dumps(data)


def test_exact_allowlist_and_explicit_detector_selection_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch, f'[allow.exact]\nEMAIL=["{EMAIL}"]')
    text = f"{EMAIL}\nPRIVATE-PERSON@example.com\n127.0.0.1"
    data = call(text=text, entity_types=["EMAIL"]).structured_content
    assert data["counts"] == {"EMAIL": 1}
    assert (
        text[data["findings"][0]["start"] : data["findings"][0]["end"]]
        == "PRIVATE-PERSON@example.com"
    )
    assert call(text="127.0.0.1").structured_content["entity_count"] == 0
    assert call(text="127.0.0.1", entity_types=["IP_ADDRESS"]).structured_content["counts"] == {
        "IP_ADDRESS": 1
    }
    assert (
        call(text=EMAIL, entity_types=["EMAIL"]).structured_content["policy"]["action"] == "proceed"
    )


@pytest.mark.parametrize("text", ["", "Harmless draft."])
def test_no_matches_are_advisory_not_send_authorization(text: str) -> None:
    data = call(text=text).structured_content
    assert data["entity_count"] == 0
    assert data["counts"] == {} and data["findings"] == []
    assert data["policy"] == {"advisory": True, "action": "proceed", "check_before_send": True}
    assert set(data) == {"entity_count", "counts", "findings", "policy"}


def test_utf8_byte_limit_is_exact_and_not_a_character_limit() -> None:
    text = "🙂" * (DEFAULT_MAX_BYTES // 4)
    assert call(text=text, entity_types=["EMAIL"]).structured_content["entity_count"] == 0
    with pytest.raises(ToolError, match="1 MiB"):
        call(text=text + "a", entity_types=["EMAIL"])


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"text": None},
        {"text": {"secret": EMAIL}},
        {"text": [EMAIL]},
        {"text": DRAFT, "entity_types": []},
        {"text": DRAFT, "entity_types": EMAIL},
        {"text": DRAFT, "entity_types": [EMAIL]},
        {"text": DRAFT, "entity_types": [123]},
        {"text": DRAFT, "entity_types": ["EMAIL", None]},
        {"text": DRAFT, EMAIL: DRAFT},
        {"text": "DRAFT_SENTINEL\ud800"},
        {"text": "DRAFT_SENTINEL" + "a" * DEFAULT_MAX_BYTES},
    ],
)
def test_invalid_arguments_never_echo_draft_or_unknown_values(
    arguments: dict[str, Any], caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(ToolError) as caught:
        call(**arguments)
    output = capsys.readouterr()
    payload = str(caught.value) + caplog.text + output.out + output.err
    assert EMAIL not in payload and "DRAFT_SENTINEL" not in payload


@pytest.mark.parametrize("stage", ["scan", "transform", "model_findings"])
def test_engine_failure_is_sanitized_not_a_clean_result(
    stage: str,
    installed_model: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError(DRAFT)

    monkeypatch.setattr(server, stage, broken)
    with pytest.raises(ToolError, match="details are withheld") as caught:
        call(text=DRAFT)
    output = capsys.readouterr()
    payload = str(caught.value) + caplog.text + output.out + output.err
    assert EMAIL not in payload and "DRAFT_SENTINEL" not in payload


def test_failed_policy_refuses_draft_without_silent_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configure(tmp_path, monkeypatch, '[workflow]\non_findings="invalid"')
    with pytest.raises(ToolError, match="workflow action"):
        call(text=DRAFT)


def test_draft_never_reads_or_writes_source_files_or_fetches_models(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datafog_mcp import model_install

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Draft check attempted file I/O or a model download")

    monkeypatch.setattr(server, "read_text_file", forbidden)
    monkeypatch.setattr(server, "write_text_file", forbidden)
    monkeypatch.setattr(model_install.urllib.request, "urlopen", forbidden)
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, "")
    assert call(text=DRAFT, entity_types=["EMAIL"]).structured_content["counts"] == {"EMAIL": 1}


def test_missing_requested_model_is_refused() -> None:
    with pytest.raises(ToolError, match="model install"):
        call(text="Jane Doe", entity_types=["PERSON"])


def test_verified_model_adds_draft_names_and_addresses(installed_model: Path) -> None:
    text = "🙂 Jane Doe lives at 42 Sample Road; jane@example.com"
    data = call(text=text).structured_content
    assert data["counts"] == {"PERSON": 2, "STREET_ADDRESS": 1, "EMAIL": 1}
    assert "Jane" not in json.dumps(data) and "42 Sample Road" not in json.dumps(data)
    for finding in data["findings"]:
        assert text[finding["start"] : finding["end"]] in {
            "Jane",
            "Doe",
            "42 Sample Road",
            "jane@example.com",
        }


def test_model_failure_never_yields_core_only_draft_success(
    installed_model: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datafog_mcp.model_runtime import ModelRuntimeError

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise ModelRuntimeError("Local model inference timed out.")

    monkeypatch.setattr(server, "model_findings", broken)
    with pytest.raises(ToolError, match="timed out"):
        call(text=DRAFT)
    assert call(text=DRAFT, entity_types=["EMAIL"]).structured_content["counts"] == {"EMAIL": 1}


def test_real_native_draft_opt_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from datafog_mcp.model_runtime import close_model_runtimes

    bundle = os.environ.get("DATAFOG_TEST_MODEL_BUNDLE")
    if not bundle:
        pytest.skip("Pinned native model integration explicitly enabled")
    configure(tmp_path, monkeypatch, f"[model]\nbundle_directory={json.dumps(bundle)}")
    text = "Customer José García lives at 42 Sample Avenue; jane@example.com."
    try:
        result = call(text=text)
        data = result.structured_content
        assert data["counts"] == {"PERSON": 2, "STREET_ADDRESS": 1, "EMAIL": 1}
        for value in ("José", "García", "42 Sample Avenue", "jane@example.com"):
            assert value not in str(result.content) + json.dumps(data)
        people = [finding for finding in data["findings"] if finding["type"] == "PERSON"]
        assert [text[f["start"] : f["end"]] for f in people] == ["José", "García"]
    finally:
        close_model_runtimes()

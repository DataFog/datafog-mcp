"""MCP model onboarding, policy and response privacy with a verified synthetic bundle."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp import __main__, model_install, model_runtime, policy, server
from datafog_mcp.keys import generate_scope_key
from datafog_mcp.policy import PseudonymScope
from test_model_install import release as release


@pytest.fixture
def installed_model(
    tmp_path: Path, release: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    bundle = model_install.install_model(tmp_path / "model", release)
    config = tmp_path / "policy.toml"
    config.write_text(f"version=1\n[model]\nbundle_directory={json.dumps(str(bundle))}\n")
    monkeypatch.setattr(policy, "POLICY_FILE", config)
    yield bundle
    model_runtime.close_model_runtimes()


def call(tool: str, **args: Any) -> Any:
    async def run() -> Any:
        async with Client(server.mcp) as client:
            return await client.call_tool(tool, args)

    return asyncio.run(run())


@pytest.mark.parametrize(
    "tool",
    ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove", "datafog_pseudonymize"],
)
def test_all_tools_use_verified_model_and_keep_values_out_of_responses(
    installed_model: Path, tmp_path: Path, tool: str
) -> None:
    source = tmp_path / "contacts.txt"
    text = "🙂 Customer Jane Doe lives at 42 Sample Road; jane@example.com."
    source.write_text(text)
    args: dict[str, Any] = {"path": str(source)}
    if tool == "datafog_pseudonymize":
        key = tmp_path / "key"
        generate_scope_key(PseudonymScope("analysis", "file", key))
        with policy.POLICY_FILE.open("a") as handle:
            handle.write(
                '[pseudonymization.scopes.analysis]\nkey_ref="analysis"\n'
                f'backend="file"\nkey_file={json.dumps(str(key))}\n'
            )
        args["scope"] = "analysis"
    result = call(tool, **args)
    data = result.structured_content
    assert data is not None
    assert data["counts"] == {"PERSON": 2, "STREET_ADDRESS": 1, "EMAIL": 1}
    payload = str(result.content) + json.dumps(data)
    for private in ("Jane", "Doe", "42 Sample Road", "jane@example.com", "Customer"):
        assert private not in payload
    if tool == "datafog_scan":
        people = [f for f in data["findings"] if f["type"] == "PERSON"]
        assert [text[f["start"] : f["end"]] for f in people] == ["Jane", "Doe"]
    else:
        output = Path(data["output_path"]).read_text()
        assert "Jane" not in output and "42 Sample Road" not in output
    assert source.read_text() == text


@pytest.mark.parametrize("kind", ["PERSON", "STREET_ADDRESS"])
def test_missing_model_gives_setup_guidance_before_read(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Missing-model request read the source")

    monkeypatch.setattr(server, "read_text_file", unexpected)
    with pytest.raises(ToolError, match="model install"):
        call("datafog_scan", path="/missing.txt", entity_types=[kind])


def test_core_only_selection_does_not_launch_model(
    installed_model: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Explicit Core-only request invoked the optional model")

    monkeypatch.setattr(server, "model_findings", unexpected)
    source = tmp_path / "contacts.txt"
    source.write_text("Jane jane@example.com")
    assert call("datafog_scan", path=str(source), entity_types=["EMAIL"]).structured_content[
        "counts"
    ] == {"EMAIL": 1}


def test_allowlist_applies_to_model_entities(installed_model: Path, tmp_path: Path) -> None:
    with policy.POLICY_FILE.open("a") as handle:
        handle.write('[allow.exact]\nPERSON=["Jane"]\n')
    source = tmp_path / "contacts.txt"
    source.write_text("Jane Doe")
    data = call("datafog_redact", path=str(source)).structured_content
    assert data is not None and data["counts"] == {"PERSON": 1}
    assert Path(data["output_path"]).read_text() == "Jane [PERSON]"


def test_discovery_does_not_verify_or_execute_bundle(
    installed_model: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Discovery executed or verified the model")

    monkeypatch.setattr(model_runtime, "verify_bundle", unexpected)
    model = call("datafog_policy").structured_content["model"]
    assert model == {
        "configured": True,
        "verified": False,
        "entity_types": ["PERSON", "STREET_ADDRESS"],
        "setup_command": "datafog-mcp model install",
    }


@pytest.mark.parametrize("tool", ["datafog_scan", "datafog_redact", "datafog_policy"])
def test_bundle_cannot_be_processed_as_input(installed_model: Path, tool: str) -> None:
    with pytest.raises(ToolError, match="model bundles"):
        call(tool, path=str(installed_model / "config.json"))


def test_bundle_cannot_be_copy_destination(installed_model: Path, tmp_path: Path) -> None:
    source = tmp_path / "contacts.txt"
    source.write_text("Jane")
    with policy.POLICY_FILE.open("a") as handle:
        handle.write(f"[output]\ndirectory={json.dumps(str(installed_model))}\n")
    with pytest.raises(ToolError, match="model bundles"):
        call("datafog_redact", path=str(source))
    assert not (installed_model / "contacts_redacted.txt").exists()


@pytest.mark.parametrize("failure", ["tampered", "timeout", "malformed"])
def test_model_failure_never_falls_back_or_writes_a_copy(
    installed_model: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    source = tmp_path / "contacts.txt"
    source.write_text("Jane jane@example.com")
    if failure == "tampered":
        (installed_model / "model.onnx").write_text("PRIVATE_SENTINEL")
    else:

        def fail(*args: Any, **kwargs: Any) -> Any:
            if failure == "timeout":
                raise model_runtime.ModelRuntimeError("Local model inference timed out.")
            raise RuntimeError("PRIVATE_SENTINEL")

        monkeypatch.setattr(server, "model_findings", fail)
    with pytest.raises(ToolError) as error:
        call("datafog_redact", path=str(source))
    captured = capfd.readouterr()
    payload = str(error.value) + captured.out + captured.err + caplog.text
    assert "PRIVATE_SENTINEL" not in payload and "jane@example.com" not in payload
    assert not (tmp_path / "contacts_redacted.txt").exists()


def test_cli_offline_install_and_status(
    release: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = tmp_path / "cli-model"
    monkeypatch.setattr(
        sys,
        "argv",
        ["datafog-mcp", "model", "install", "--archive", str(release), "--directory", str(bundle)],
    )
    __main__.main()
    assert "installed and verified" in capsys.readouterr().out
    config = tmp_path / "policy.toml"
    config.write_text(f"version=1\n[model]\nbundle_directory={json.dumps(str(bundle))}\n")
    monkeypatch.setattr(policy, "POLICY_FILE", config)
    monkeypatch.setattr(sys, "argv", ["datafog-mcp", "model", "status"])
    __main__.main()
    assert "verified" in capsys.readouterr().out


def test_real_release_opt_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = os.environ.get("DATAFOG_TEST_MODEL_BUNDLE")
    if not path:
        pytest.skip("Pinned native model integration explicitly enabled")
    config = tmp_path / "policy.toml"
    config.write_text(f"version=1\n[model]\nbundle_directory={json.dumps(path)}\n")
    monkeypatch.setattr(policy, "POLICY_FILE", config)
    source = tmp_path / "sample.txt"
    source.write_text("Customer José García lives at 42 Sample Avenue; jane@example.com.")
    key = tmp_path / "key"
    generate_scope_key(PseudonymScope("analysis", "file", key))
    with config.open("a") as handle:
        handle.write(
            '[pseudonymization.scopes.analysis]\nkey_ref="analysis"\n'
            f'backend="file"\nkey_file={json.dumps(str(key))}\n'
        )
    try:
        for tool in (
            "datafog_scan",
            "datafog_redact",
            "datafog_mask",
            "datafog_remove",
            "datafog_pseudonymize",
        ):
            args = {"path": str(source)}
            if tool == "datafog_pseudonymize":
                args["scope"] = "analysis"
            data = call(tool, **args).structured_content
            assert data is not None
            assert data["counts"] == {"PERSON": 2, "STREET_ADDRESS": 1, "EMAIL": 1}
            assert "José" not in json.dumps(data) and "jane@example.com" not in json.dumps(data)
            if tool != "datafog_scan":
                text = Path(data["output_path"]).read_text()
                assert "José" not in text and "42 Sample Avenue" not in text
    finally:
        model_runtime.close_model_runtimes()


@pytest.mark.parametrize("timeout", ["0", "-1", "301", "true", "nan", "inf", '"30"'])
def test_model_policy_refuses_bad_timeouts(installed_model: Path, timeout: str) -> None:
    with policy.POLICY_FILE.open("a") as handle:
        handle.write(f"timeout_seconds={timeout}\n")
    with pytest.raises(policy.OutputPolicyError, match="timeout"):
        policy.load_output_policy()


def test_serving_with_model_never_downloads(
    installed_model: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("An MCP operation attempted to download")

    monkeypatch.setattr(model_install.urllib.request, "urlopen", unexpected)
    source = tmp_path / "contacts.txt"
    source.write_text("Jane Doe")
    assert call("datafog_scan", path=str(source)).structured_content["counts"] == {"PERSON": 2}
    call("datafog_redact", path=str(source))
    call("datafog_policy")

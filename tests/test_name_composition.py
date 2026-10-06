"""Composition preserves coordinates, cell boundaries and transformation freshness."""

import asyncio
import os
from pathlib import Path

import pytest

from datafog_mcp.model_runtime import _convert, join_person_findings
from datafog_mcp.policy import Policy, PolicyError, load_policy
from datafog_mcp.server import _digest


def names(text: str, words: tuple[str, ...]):
    return _convert(
        text,
        {
            "findings": [
                {
                    "label": "first_name",
                    "start": len(text[: text.index(word)].encode()),
                    "end": len(text[: text.index(word) + len(word)].encode()),
                    "confidence": 0.9,
                }
                for word in words
            ]
        },
    )


def test_unicode_composition_is_opt_in_and_does_not_invent_calibration():
    text = "🙂 José García"
    native = names(text, ("José", "García"))
    confidence = native[0].confidence
    assert join_person_findings(text, native, 0) is native
    joined = join_person_findings(text, native, 1)
    assert len(joined) == 1
    assert joined[0].matched_text == "José García"
    assert text[joined[0].codepoint_range.start : joined[0].codepoint_range.end] == "José García"
    assert (
        text.encode()[joined[0].byte_range.start : joined[0].byte_range.end].decode()
        == "José García"
    )
    assert joined[0].confidence is None
    assert native[0].confidence == confidence
    assert joined[0].detector_name == "datafog-local-pii-composed"


def test_composition_never_crosses_record_or_cell_boundaries():
    for text in ("Jane\nDoe", "Jane, Doe", "Jane    Doe"):
        native = names(text, ("Jane", "Doe"))
        assert len(join_person_findings(text, native, 3)) == 2
    text = "Jane\tDoe"
    native = names(text, ("Jane", "Doe"))
    assert len(join_person_findings(text, native, 1)) == 1
    assert len(join_person_findings(text, native, 1, (4, 5))) == 2


@pytest.mark.parametrize("value", [True, -1, 4, "1", 1.5])
def test_invalid_policy_gap_rejected(value):
    with pytest.raises(PolicyError):
        Policy(model_join_person_gap=value)


def test_policy_setting_changes_scan_digest(tmp_path: Path):
    path = tmp_path / "policy.toml"
    path.write_text("version = 1\n[model]\njoin_person_gap = 1\n")
    assert load_policy(path).model_join_person_gap == 1
    assert _digest("Jane Doe", Policy(), {"EMAIL"}, "text", False) != _digest(
        "Jane Doe", Policy(model_join_person_gap=1), {"EMAIL"}, "text", False
    )


def test_real_mcp_person_composition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from fastmcp import Client

    from datafog_mcp.model_runtime import close_model_runtimes
    from datafog_mcp.server import mcp

    bundle = os.environ.get("DATAFOG_TEST_MODEL_BUNDLE")
    if not bundle:
        pytest.skip("Local experimental model bundle not configured")
    policy = tmp_path / "policy.toml"
    policy.write_text(
        f'version = 1\n[model]\nbundle_directory = "{Path(bundle).as_posix()}"\n'
        "join_person_gap = 1\n"
    )
    monkeypatch.setenv("DATAFOG_POLICY_PATH", str(policy))
    monkeypatch.setenv("DATAFOG_MCP_ALLOWED_ROOTS", str(tmp_path))
    text = "🙂 Customer José García lives at 42 Sample Avenue."
    source = tmp_path / "customer.txt"
    source.write_text(text)

    async def run():
        async with Client(mcp) as client:
            result = await client.call_tool(
                "datafog_scan",
                {
                    "path": str(source),
                    "input_format": "text",
                    "entity_types": ["PERSON", "STREET_ADDRESS"],
                },
            )
            return result.structured_content

    try:
        result = asyncio.run(run())
        assert result is not None
        persons = [f for f in result["findings"] if f["type"] == "PERSON"]
        assert len(persons) == 1
        assert text[persons[0]["start"] : persons[0]["end"]] == "José García"
        assert any(f["type"] == "STREET_ADDRESS" for f in result["findings"])
    finally:
        close_model_runtimes()

"""Persistent pseudonyms through the MCP boundary, not just the Core API."""

import asyncio
import csv
import io
import json
import os
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from datafog_mcp.keys import generate_scope_key
from datafog_mcp.policy import load_policy
from datafog_mcp.server import mcp


def call(**arguments: Any) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        async with Client(mcp) as client:
            result = await client.call_tool("datafog_pseudonymize", arguments)
            assert result.structured_content is not None
            return result.structured_content

    return asyncio.run(run())


@pytest.mark.skipif(os.name != "posix", reason="file key backend requires POSIX permissions")
def test_persistent_scope_across_csv_and_text_and_missing_key(tmp_path: Path) -> None:
    config = Path(os.environ["DATAFOG_POLICY_PATH"])
    config.write_text(
        "version = 1\n[pseudonymization.scopes.customers]\n"
        'key_ref = "customers"\nbackend = "file"\n'
        f'key_file = "{tmp_path / "customers.key"}"\n'
    )
    text = tmp_path / "input.txt"
    table = tmp_path / "input.csv"
    text.write_text("jane@example.com")
    table.write_text('email,notes\njane@example.com,"a,b"\n')
    with pytest.raises(ToolError, match="key could not be retrieved"):
        call(path=str(text), scope="customers")
    assert not text.with_name("input_pseudonymized.txt").exists()
    generate_scope_key(load_policy().pseudonymization_scopes["customers"])
    first = call(path=str(text), scope="customers")
    second = call(path=str(table), scope="customers")
    pseudonym = Path(first["output_path"]).read_text()
    rows = list(csv.reader(io.StringIO(Path(second["output_path"]).read_text())))
    assert rows == [["email", "notes"], [pseudonym, "a,b"]]
    assert pseudonym != text.read_text() == "jane@example.com"
    assert table.read_text() == 'email,notes\njane@example.com,"a,b"\n'
    assert first["counts"] == second["counts"] == {"EMAIL": 1}
    assert "jane@example.com" not in json.dumps([first, second])
    assert (tmp_path / "customers.key").read_text().strip() not in json.dumps([first, second])

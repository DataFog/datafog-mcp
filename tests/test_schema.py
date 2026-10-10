"""
The published tool schemas advertise only what the server supports.

An agent reads the schema to decide what to send. A mode listed there but not
built, or an entity type the engine cannot report, invites a call that can
only fail, or worse, succeed with a result the agent misreads.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastmcp import Client

from datafog_mcp.config import SUPPORTED_ENTITIES
from datafog_mcp.server import mcp

TOOLS = ["datafog_scan", "datafog_redact", "datafog_mask", "datafog_remove", "datafog_pseudonymize"]


def _schemas() -> dict[str, dict[str, Any]]:
    """
    Fetch every tool's input schema as a client would see it.

    Returns:
      Each tool's input schema, keyed by tool name.
    """

    async def run() -> dict[str, dict[str, Any]]:
        async with Client(mcp) as client:
            return {tool.name: tool.inputSchema for tool in await client.list_tools()}

    return asyncio.run(run())


def test_scan_advertises_only_implemented_modes() -> None:
    """findings is the only mode built, so it is the only one offered."""
    mode = _schemas()["datafog_scan"]["properties"]["mode"]

    assert mode.get("const") == "findings" or mode.get("enum") == ["findings"]


@pytest.mark.parametrize("tool", TOOLS)
def test_entity_types_are_enumerated(tool: str) -> None:
    """
    Each tool lists exactly the types a scan can report, and no others.

    Parameters:
      tool: The tool whose schema is checked.
    """
    selection = _schemas()[tool]["properties"]["entity_types"]
    array = next(option for option in selection["anyOf"] if option.get("type") == "array")

    assert sorted(array["items"]["enum"]) == sorted(SUPPORTED_ENTITIES)


@pytest.mark.parametrize("tool", TOOLS)
def test_empty_selection_is_refused_by_the_schema(tool: str) -> None:
    """
    An empty list is declared invalid, not silently read as the default.

    Omitting entity_types selects the defaults. An empty list selects nothing,
    which is caller error.

    Parameters:
      tool: The tool whose schema is checked.
    """
    selection = _schemas()[tool]["properties"]["entity_types"]
    array = next(option for option in selection["anyOf"] if option.get("type") == "array")

    assert array["minItems"] == 1


def test_pseudonym_schema_requires_scope_and_has_no_key_management_tools() -> None:
    schemas = _schemas()
    schema = schemas["datafog_pseudonymize"]
    assert set(schema["required"]) == {"path", "scope"}
    assert set(schema["properties"]) == {
        "path",
        "scope",
        "output_path",
        "entity_types",
        "input_format",
        "has_header",
    }
    assert set(schemas) == set(TOOLS) | {"datafog_policy"}

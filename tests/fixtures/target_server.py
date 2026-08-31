"""
A fake MCP server returning PII, to test the proxy.
"""

from __future__ import annotations

from fastmcp import FastMCP

mcp = FastMCP(name="fixture-target")


@mcp.tool
def get_member(member_id: str) -> dict[str, str]:
    """
    Return a fake member record containing PII.

    Parameters:
      member_id: Identifier echoed back in the record.
    Returns:
      A record with contact details and a DOB.
    """
    return {
        "member_id": member_id,
        "email": "jack.smith@example.com",
        "phone": "415-555-0182",
        "DOB": "03/14/1987",
        "postal_code": "94117",
        "plan": "premium",
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")

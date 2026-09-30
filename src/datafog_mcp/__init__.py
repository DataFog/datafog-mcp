"""DataFog MCP server package."""

from importlib.metadata import PackageNotFoundError, version

# pyproject.toml is the only place the version is written; everything else
# reads it back from the installed package's metadata.
try:
    __version__ = version("datafog-mcp")
except PackageNotFoundError:
    # Imported from a source tree that was never installed, so there is no
    # metadata to read. Say so rather than report a version that may be wrong.
    __version__ = "0+unknown"

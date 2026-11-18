"""DataFog MCP server package.

The supported Python interface is :mod:`datafog_mcp.api`. Importing this
package, or that module, does not import the MCP server.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    __version__: str


def __getattr__(name: str) -> str:
    """
    Resolve ``__version__`` on first use rather than at import.

    pyproject.toml is the only place the version is written; everything else
    reads it back from the installed package's metadata. That lookup imports
    importlib.metadata, which costs more than the rest of the policy modules
    together, so a short-lived process that only needs the policy never pays
    for it. The value is not cached: the lookup is rare, and a cache would
    outlive a reinstall in a reloaded module.

    Parameters:
      name: The attribute being looked up.
    Returns:
      The installed version, or "0+unknown" for a source tree that was never
      installed.
    """
    if name != "__version__":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib.metadata

    try:
        return importlib.metadata.version("datafog-mcp")
    except importlib.metadata.PackageNotFoundError:
        # Imported from a source tree that was never installed, so there is no
        # metadata to read. Say so rather than report a version that may be wrong.
        return "0+unknown"

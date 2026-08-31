"""
Move the client's MCP servers behind the datafog proxy.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

CLAUDE_CONFIG = Path.home() / ".claude.json"
DEFAULT_PROXY_CONFIG = Path.home() / ".config" / "datafog" / "servers.json"
PROXY_SERVER_NAME = "datafog-proxy"

# Wrapping our own servers would make the proxy spawn itself.
RESERVED_NAMES: frozenset[str] = frozenset(
    {PROXY_SERVER_NAME, "datafog-scan"}
)


class AdoptError(RuntimeError):
    """Adoption could not complete."""


def read_client_servers(path: Path = CLAUDE_CONFIG) -> dict[str, Any]:
    """
    Read the user-scope MCP servers registered with the client.

    Parameters:
      path: The client's configuration file.
    Returns:
      The mcpServers mapping, empty if the client has none.
    """
    if not path.is_file():
        raise AdoptError(f"no client config at {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AdoptError(f"{path} is not valid JSON: {exc}") from exc

    servers = data.get("mcpServers")
    return servers if isinstance(servers, dict) else {}


def partition(
    servers: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """
    Split registered servers into what the proxy can wrap and what it cannot.

    Parameters:
      servers: The client's mcpServers mapping.
    Returns:
      The adoptable servers, and the names skipped for being remote.
    """
    taking: dict[str, Any] = {}
    skipping: list[str] = []

    for name, config in servers.items():
        if name in RESERVED_NAMES:
            continue
        transport = config.get("type") or config.get("transport") or "stdio"
        if transport != "stdio":
            skipping.append(name)
            continue
        taking[name] = config

    return taking, skipping


def merge_proxy_config(
    servers: dict[str, Any],
    path: Path = DEFAULT_PROXY_CONFIG,
) -> list[str]:
    """
    Add servers to the proxy's config, keeping any already there.

    The file ends up holding every wrapped server's credentials, so it is 
    written owner-only.

    Parameters:
      servers: The servers to add.
      path: The proxy's configuration file.
    Returns:
      The names that were not already present.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    existing: dict[str, Any] = {}
    if path.is_file():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        existing = loaded.get("mcpServers") or {}

    added = [name for name in servers if name not in existing]
    existing.update(servers)

    path.write_text(
        json.dumps({"mcpServers": existing}, indent=2) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return added


def _claude(*args: str, check: bool = True) -> None:
    """
    Run one claude mcp subcommand.

    Parameters:
      args: Arguments following "claude mcp".
      check: Raise when the command fails.
    Returns:
      None.
    """
    result = subprocess.run(
        ["claude", "mcp", *args], capture_output=True, text=True
    )
    if check and result.returncode != 0:
        raise AdoptError(
            f"claude mcp {' '.join(args)} failed: {result.stderr.strip()}"
        )


def _register_proxy(
    proxy_config: Path,
    executable: str,
    strategy: str,
    skip_keys: str,
) -> None:
    """
    Point the client at the proxy, replacing any earlier registration.

    Parameters:
      proxy_config: The proxy's configuration file.
      executable: Absolute path to the datafog-mcp entry point.
      strategy: How the middleware replaces detections.
      skip_keys: Comma-separated keys left unscanned.
    Returns:
      None.
    """
    _claude("remove", PROXY_SERVER_NAME, "-s", "user", check=False)

    command = [
        executable,
        "proxy",
        "--config",
        str(proxy_config),
        "--strategy",
        strategy,
    ]
    if skip_keys:
        command += ["--skip-keys", skip_keys]

    _claude("add", "--scope", "user", PROXY_SERVER_NAME, "--", *command)


def adopt(
    proxy_config: Path = DEFAULT_PROXY_CONFIG,
    executable: str | None = None,
    strategy: str = "mask",
    skip_keys: str = "",
    dry_run: bool = False,
) -> None:
    """
    Wrap every stdio server the client knows about.

    Re-runnable: servers already behind the proxy are left alone, and servers 
    registered since the last run are picked up.

    Parameters:
      proxy_config: Where the proxy's server list lives.
      executable: Path to datafog-mcp; resolved from PATH if omitted.
      strategy: How the middleware replaces detections.
      skip_keys: Comma-separated keys left unscanned.
      dry_run: Report the plan without changing anything.
    Returns:
      None.
    """
    entry = executable or shutil.which("datafog-mcp")
    if entry is None:
        raise AdoptError("datafog-mcp is not on PATH; pass --executable")

    taking, skipping = partition(read_client_servers())

    for name in skipping:
        print(f"skipped {name}: not a stdio server")

    if not taking:
        print("nothing to adopt")
        return

    print("adopting:", ", ".join(sorted(taking)))
    if dry_run:
        return

    backup = CLAUDE_CONFIG.with_suffix(".json.datafog-backup")
    shutil.copy2(CLAUDE_CONFIG, backup)
    print(f"backed up client config to {backup}")

    merge_proxy_config(taking, proxy_config)

    for name in taking:
        _claude("remove", name, "-s", "user")

    _register_proxy(proxy_config, entry, strategy, skip_keys)
    print(f"{PROXY_SERVER_NAME} now fronts {len(taking)} server(s)")
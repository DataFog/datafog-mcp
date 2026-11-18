"""
Where the launching application keeps its vault, if it configured one.

Only the location is handled here: it is read from the environment and
validated. Nothing in this package reads from or writes to the directory.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

VAULT_DIR_VAR = "DATAFOG_VAULT_DIR"


class VaultConfigError(ValueError):
    """An unusable vault location; its message never includes the location."""


def vault_dir() -> Path | None:
    """
    Resolve the vault directory the launching application configured.

    The environment variable is the only source. There is no policy.toml
    setting and no default location, so a process started without the variable
    has no vault.

    A variable that is set but unusable is an error rather than an absent
    setting, so a mistake cannot silently turn the vault off. The directory
    may not exist yet; whatever exists at the path must be a directory.
    Symlinks are followed before the credential-directory check. The vault
    may sit inside or outside the allowed roots; either way the file tools
    refuse every path inside it.

    Returns:
      The resolved directory, or None when the variable is unset.
    """
    # Import here: the path access layer consults this module on every check.
    from .paths import DENIED_DIR_NAMES

    raw = os.environ.get(VAULT_DIR_VAR)
    if raw is None:
        return None
    if not raw.strip() or "\x00" in raw:
        raise VaultConfigError(f"${VAULT_DIR_VAR} is set but names no directory")
    try:
        expanded = Path(raw).expanduser()
        if not expanded.is_absolute():
            raise VaultConfigError(f"${VAULT_DIR_VAR} must be an absolute path or start with ~")
        resolved = expanded.resolve(strict=False)
    except (OSError, RuntimeError):
        raise VaultConfigError(f"${VAULT_DIR_VAR} cannot be resolved") from None
    if any(part.casefold() in DENIED_DIR_NAMES for part in resolved.parts):
        raise VaultConfigError(f"${VAULT_DIR_VAR} is in a refused credential directory")
    try:
        if not stat.S_ISDIR(resolved.stat().st_mode):
            raise VaultConfigError(f"${VAULT_DIR_VAR} must name a directory")
    except FileNotFoundError:
        pass
    except OSError:
        raise VaultConfigError(f"${VAULT_DIR_VAR} cannot be inspected") from None
    return resolved


def vault_configured() -> bool:
    """
    Report whether a usable vault location is configured.

    Returns:
      True when the variable names a usable directory, False when it is unset.
      An unusable value raises VaultConfigError.
    """
    return vault_dir() is not None

"""
Where the server is allowed to read and write.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .policy import OutputPolicy, OutputPolicyError, load_output_policy
from .vault import VAULT_DIR_VAR, VaultConfigError, vault_dir

ROOTS_FILE = Path.home() / ".config" / "datafog" / "allowed_roots"

ROOTS_TEMPLATE = """\
# Directories datafog may read from and write to.
# One absolute path per line; ~ is expanded. Blank lines and lines
# starting with # are ignored.
#
# This file starts out allowing your home directory, the same as having
# no file at all. Replace ~ with narrower directories, for example:
#
# ~/Downloads
# ~/Documents
#
# A file that lists no directories refuses every path. Delete the file
# to return to the default.

~
"""

ALLOWED_ROOTS_VAR = "DATAFOG_MCP_ALLOWED_ROOTS"

# Refused even inside an allowed root
DENIED_DIR_NAMES: frozenset[str] = frozenset({".aws", ".gnupg", ".kube", ".ssh", "gcloud"})


class PathNotAllowed(Exception):
    """
    The path lies outside the roots this server may touch.
    """


class PolicyError(PathNotAllowed):
    """
    The roots configuration exists but cannot be used.

    A broken policy permits nothing, so this subclasses PathNotAllowed: every
    request fails with the reason rather than the server guessing what was
    meant.
    """


@dataclass(frozen=True)
class RootPolicy:
    """
    The roots in force and where they were configured.
    """

    roots: tuple[Path, ...]
    source: str


def _parse(entries: Iterable[str], source: str) -> tuple[Path, ...]:
    """
    Turn raw entries into resolved roots.

    Only whole-line comments are honored, so a path containing a hash is not
    truncated. A relative entry is refused rather than resolved: the working
    directory is wherever the MCP client launched the server, so it could name
    any directory at all.

    Parameters:
      entries: Candidate path strings.
      source: Where the entries came from, for error messages.
    Returns:
      The resolved roots, skipping blanks and comments.
    """
    roots: list[Path] = []
    for entry in (raw.strip() for raw in entries):
        if not entry or entry.startswith("#"):
            continue
        expanded = Path(entry).expanduser()
        if not expanded.is_absolute():
            raise PolicyError(f"{source}: {entry!r} is not an absolute path")
        roots.append(expanded.resolve())
    return tuple(roots)


def _roots_from_env() -> tuple[Path, ...] | None:
    """
    Read roots from the environment.

    Returns:
      The configured roots, or None when the variable is unset. Set but naming
      no directory is a deliberate empty policy, not an absent one.
    """
    raw = os.environ.get(ALLOWED_ROOTS_VAR)
    if raw is None:
        return None
    return _parse(raw.split(os.pathsep), f"${ALLOWED_ROOTS_VAR}")


def _roots_from_file(path: Path) -> tuple[Path, ...] | None:
    """
    Read roots from the config file.

    Anything at the path counts as configuration, including a directory or a
    dangling symlink, so a broken file fails closed instead of reading as
    absent.

    Parameters:
      path: The roots file.
    Returns:
      The configured roots, or None when nothing exists at the path. A file
      listing no roots is a deliberate empty policy.
    """
    if not os.path.lexists(path):
        return None
    if not path.is_file():
        raise PolicyError(f"{path} is not a regular file")
    try:
        body = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc.strerror}") from None
    except UnicodeDecodeError:
        raise PolicyError(f"{path} is not valid UTF-8") from None
    return _parse(body.splitlines(), str(path))


def policy() -> RootPolicy:
    """
    Resolve the roots in force and where they came from.

    Precedence is the environment variable, then the config file, then the
    user's home directory. The variable wins so a locked-down install cannot be
    widened by editing a file.

    A source that is present takes effect even when it lists no roots, which
    refuses every path. Falling through to the home directory instead would
    mean clearing a policy widens it.

    Returns:
      The roots and a description of their source.
    """
    from_env = _roots_from_env()
    if from_env is not None:
        return RootPolicy(from_env, f"${ALLOWED_ROOTS_VAR}")

    from_file = _roots_from_file(ROOTS_FILE)
    if from_file is not None:
        return RootPolicy(from_file, str(ROOTS_FILE))

    return RootPolicy((Path.home().resolve(),), "default (home directory)")


def allowed_roots() -> tuple[Path, ...]:
    """
    Resolve the roots this server may read from and write to.

    Returns:
      The roots in force.
    """
    return policy().roots


def _is_denied(resolved: Path) -> bool:
    """
    Report whether a path crosses a credential directory.

    Components are casefolded before comparison to account for case-sensitive
    filesystems.

    Parameters:
      resolved: An already-resolved absolute path.
    Returns:
      True if any component names a denied directory.
    """
    return any(part.casefold() in DENIED_DIR_NAMES for part in resolved.parts)


def _in_vault(resolved: Path) -> bool:
    """
    Report whether a path is the application vault or lies inside it.

    The vault holds what the tools exist to keep out of context, so it is
    refused like a credential directory. Paths are compared after symlink
    resolution, and also by device and inode when the vault exists, so a
    differently-cased spelling on a case-insensitive filesystem still counts.
    An unusable vault setting refuses every path rather than protecting
    nothing.

    Parameters:
      resolved: An already-resolved absolute path.
    Returns:
      True if the path is inside the configured vault directory.
    """
    try:
        vault = vault_dir()
    except VaultConfigError as exc:
        raise PolicyError(str(exc)) from None
    if vault is None:
        return False
    candidates = (resolved, *resolved.parents)
    return vault in candidates or any(_same_directory(parent, vault) for parent in candidates)


def check_vault_against_roots() -> None:
    """
    Refuse a vault that is an allowed root or contains one.

    Every path under such a root is inside the vault, so every request would
    be refused, and the reported roots together with those refusals would show
    where the vault is. A roots configuration that cannot be read is left to
    the path checks, which refuse every path and say why.

    Raises:
      VaultConfigError: The vault covers an allowed root, or its setting is
      unusable. The message names the variable, never a location.
    """
    if vault_dir() is None:
        return
    try:
        roots = policy().roots
    except PolicyError:
        return
    if any(_in_vault(root) for root in roots):
        raise VaultConfigError(
            f"${VAULT_DIR_VAR} is an allowed root or contains one, so every path would be refused"
        )


def _check(resolved: Path) -> Path:
    """
    Apply the root policy to an already-resolved path.

    The policy is resolved once, so the check and the refusal message cannot
    disagree about which roots were in force.

    Parameters:
      resolved: An already-resolved absolute path.
    Returns:
      The same path, when policy permits it.
    """
    if _is_denied(resolved):
        raise PathNotAllowed(f"{resolved} is in a credential directory")
    if _in_vault(resolved):
        # No path in the message: after symlink resolution it would show
        # where the vault is, which tool responses never reveal.
        raise PathNotAllowed("the requested path is inside the application vault directory")

    current = policy()
    if not current.roots:
        raise PathNotAllowed(
            f"{resolved} is refused because {current.source} lists no allowed roots"
        )
    if not any(resolved == root or root in resolved.parents for root in current.roots):
        roots = ", ".join(str(root) for root in current.roots)
        raise PathNotAllowed(f"{resolved} is outside the allowed roots: {roots}")
    return resolved


def _same_directory(left: Path, right: Path) -> bool:
    """
    Report whether two paths name the same directory.

    Uses .samefile to compare by device and inode instead of just spelling.
    Therefore, a symlink and its target, or two case variants on a case-
    insensitive filesystem, count as the same directory.

    Parameters:
      left: A directory path.
      right: A directory path.
    Returns:
      True when both exist and are the same directory. Otherwise False.
    """
    try:
        return left.samefile(right)
    except OSError:
        return False


def resolve_input(path: str) -> Path:
    """
    Resolve a path the server may read.

    Symlinks are followed before the policy check, so a link inside an allowed
    root pointing outside it is refused.

    Parameters:
      path: The requested path.
    Returns:
      The resolved path, when policy permits it.
    """
    return _check(Path(path).expanduser().resolve())


def resolve_output(path: str, beside: Path, copy_policy: OutputPolicy | None = None) -> Path:
    """
    Resolve a path the server may write.

    Outputs are confined to the owner-configured directory, or the input's
    directory when none is configured. Configuration directories and output
    filenames beginning with a dot are refused.

    Parameters:
        path: The requested path.
        beside: The resolved input path whose directory bounds the output.
        copy_policy: A request's policy snapshot, or None to load it now.
    Returns:
        The resolved path, when policy permits it.
    """
    raw_path = Path(path).expanduser()
    if raw_path.name.startswith("."):
        raise PathNotAllowed("output filenames must not begin with a dot")
    destination = raw_path.parent.resolve() / raw_path.name
    resolved = _check(destination)

    if copy_policy is None:
        try:
            copy_policy = load_output_policy()
        except OutputPolicyError as exc:
            raise PolicyError(str(exc)) from None

    if _same_directory(resolved.parent, ROOTS_FILE.parent):
        raise PathNotAllowed(f"{resolved} is inside the server's configuration directory")
    expected = copy_policy.directory or beside.parent
    if not _same_directory(resolved.parent, expected):
        if copy_policy.directory is not None:
            raise PathNotAllowed("copy must be in the configured output directory")
        raise PathNotAllowed(f"{resolved} must be in the same directory as {beside}")

    return resolved

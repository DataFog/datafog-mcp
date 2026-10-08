"""Owner-configured output policy, reloaded for each write request."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

POLICY_FILE = Path.home() / ".config" / "datafog" / "policy.toml"
POLICY_TEMPLATE = """\
# Copy destinations. With no [output].directory, copies stay beside the input.
version = 1

# To choose one output directory, create it, allow it in your roots policy,
# and uncomment these lines with your directory:
# [output]
# directory = "~/Documents/datafog-copies"
"""


class OutputPolicyError(ValueError):
    """An unusable output policy; its message never includes policy values."""


@dataclass(frozen=True)
class OutputPolicy:
    """The fixed output directory, or None for copies beside the input."""

    directory: Path | None = None


def load_output_policy() -> OutputPolicy:
    """Load a strict version-1 policy; only an absent file uses the default."""
    if not os.path.lexists(POLICY_FILE):
        return OutputPolicy()
    if not POLICY_FILE.is_file():
        raise OutputPolicyError("output policy is not a regular file")
    try:
        with POLICY_FILE.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError):
        raise OutputPolicyError("cannot read output policy as valid UTF-8 TOML") from None
    if set(data) - {"version", "output"}:
        raise OutputPolicyError("output policy contains an unknown setting")
    if type(data.get("version")) is not int or data["version"] != 1:
        raise OutputPolicyError("output policy must declare version = 1")
    output = data.get("output", {})
    if not isinstance(output, dict) or set(output) - {"directory"}:
        raise OutputPolicyError("output policy requires an [output] table with only directory")
    if "directory" not in output:
        return OutputPolicy()
    raw = output["directory"]
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise OutputPolicyError("output directory must be a nonempty absolute path")
    try:
        directory = Path(raw).expanduser()
        if not directory.is_absolute():
            raise OutputPolicyError("output directory must be absolute or start with ~")
        directory = directory.resolve(strict=True)
        if not directory.is_dir():
            raise OutputPolicyError("output directory must already exist and be a directory")
    except (OSError, RuntimeError):
        raise OutputPolicyError("output directory cannot be resolved") from None
    return OutputPolicy(directory)

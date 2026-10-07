"""
Shared fixtures.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from datafog_mcp import policy
from datafog_mcp.paths import ALLOWED_ROOTS_VAR

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def allow_test_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """
    Let tests read and write where pytest puts their files.

    The default root is the user's home directory, but pytest writes
    under /tmp and the checked-in fixtures live in the repo, which in a
    devcontainer is outside home. Tests of the policy itself set their
    own roots, which override this.

    Parameters:
      monkeypatch: Sets the environment variable for one test.
      tmp_path_factory: Supplies pytest's temp root.
    """
    roots = os.pathsep.join([str(tmp_path_factory.getbasetemp().resolve()), str(REPO_ROOT)])
    monkeypatch.setenv(ALLOWED_ROOTS_VAR, roots)
    monkeypatch.setattr(policy, "POLICY_FILE", tmp_path_factory.getbasetemp() / "policy.toml")


@pytest.fixture
def umask_022() -> Iterator[None]:
    """
    Run a test under the common default umask of 022.

    The umask is process-wide, so the caller's value is restored afterward.

    Returns:
      Nothing. Yields once while the umask is in force.
    """
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)

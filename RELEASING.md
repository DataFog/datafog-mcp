# Releasing datafog-mcp

Releases are published to PyPI by [`.github/workflows/release.yml`](.github/workflows/release.yml) using PyPI Trusted Publishing. No API token exists anywhere: PyPI trusts this repository's release workflow directly, and every publish waits for the maintainer's approval.

## One-time setup (maintainer)

1. **PyPI.** Add a pending trusted publisher for the project `datafog-mcp`: owner `DataFog`, repository `datafog-mcp`, workflow `release.yml`, environment `pypi`. The name is claimed by the first successful publish, not by this step.
2. **TestPyPI.** Do the same on test.pypi.org, with environment `testpypi`.
3. **GitHub environments.** In the repository settings, create `pypi` and `testpypi`, each requiring the maintainer's approval. Limit `pypi` to tags matching `v*`.

## Cutting a release

1. **Prepare.** On a branch, set the version in `pyproject.toml`, which is the only place it is written. Date the changelog entry: `## [X.Y.Z] - YYYY-MM-DD`. Merge the pull request. The release workflow builds and smoke-tests the package on it.

2. **Rehearse.** This is required before the first release, and worth doing whenever the workflow changes. Run the Release workflow by hand on `main`, then approve the `testpypi` deployment. Check the published file, installing only it from TestPyPI and its dependencies from PyPI:

   ```bash
   uv venv /tmp/rehearsal
   uvx pip download --no-deps --index-url https://test.pypi.org/simple/ --dest /tmp/rehearsal/dist datafog-mcp==X.Y.Z
   uv pip install --python /tmp/rehearsal/bin/python /tmp/rehearsal/dist/*.whl
   /tmp/rehearsal/bin/python scripts/smoke_installed.py X.Y.Z
   ```

   Don't point an installer at TestPyPI with PyPI as a fallback. Anyone can publish to TestPyPI, so that lets it supply dependencies too.

   TestPyPI accepts each version only once. To rehearse again, use a pre-release version such as `X.Y.Zrc1`.

3. **Tag.**

   ```bash
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

   The workflow refuses a tag that doesn't match `pyproject.toml`, and a version without a dated changelog entry.

4. **Approve** the `pypi` deployment once the build and verify jobs pass.

## What the workflow checks before publishing

- The tag matches the version, and the changelog has a dated entry for it.
- The wheel is built from the sdist, so the sdist is known to be complete.
- On Python 3.10, 3.11, and 3.12, the wheel installs into a clean environment outside the checkout with freshly resolved dependencies. Its metadata reports the right version and license, `datafog-mcp --version` agrees, and a stdio session through the installed console script scans and redacts a file without returning the value or modifying the original.

## Verifying a release

The build job's summary lists each file's SHA-256. The hashes PyPI shows for each file must match it. PyPI also shows a provenance attestation for each file, linking it to this repository and the workflow run that built it.

## Rolling back

Never delete a release from PyPI. A version number can never be reused, so deleting frees nothing and breaks anyone who pinned it.

1. **Yank** the bad version on PyPI, giving a reason. Unpinned installs stop getting it, while `datafog-mcp==X.Y.Z` still installs for anyone who needs it.
2. **Fix forward.** Release `X.Y.(Z+1)` through the normal process, noting the yank in its changelog entry.

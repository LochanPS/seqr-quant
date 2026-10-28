# Releasing pqcmap

pqcmap is published to PyPI by the [`pqcmap` workflow](../.github/workflows/pqcmap.yml)
using **PyPI Trusted Publishing (OIDC)** — there is no stored PyPI token anywhere.

## Version + tag policy

- `pqcmap` follows semantic versioning; the version lives in
  [`pyproject.toml`](pyproject.toml) (`project.version`) and `pqcmap/__init__.py`
  (`__version__`). Keep the two in sync.
- Releases are cut from **annotated tags** namespaced `pqcmap-vX.Y.Z` (e.g.
  `pqcmap-v0.1.0`). The `pqcmap-` prefix keeps the SDK's tags distinct from the
  `seqr` CLI's tags in this monorepo.

## One-time setup (maintainer, on PyPI + TestPyPI)

Trusted publishing must be registered once per index before the first upload:

1. **PyPI** → *Publishing* → add a **pending** trusted publisher:
   - Owner: `LochanPS` · Repository: `SeQr-Labs` · Workflow: `pqcmap.yml`
     · Environment: `pypi`.
2. **TestPyPI** → same, with Environment: `testpypi`.
3. In GitHub repo settings, create Environments `pypi` and `testpypi`. Optionally add
   **required reviewers** to `pypi` for a manual approval gate on top of the tag.

## Cutting a release

1. Bump `version` in `pyproject.toml` and `__version__` in `pqcmap/__init__.py`; move
   the `CHANGELOG.md` *Unreleased* notes under the new version.
2. Merge to `main`; confirm the `test` matrix is green.
3. Tag and push:

   ```bash
   git tag -a pqcmap-v0.2.0 -m "pqcmap 0.2.0"
   git push origin pqcmap-v0.2.0
   ```

4. The workflow runs `test → build → TestPyPI dry-run → PyPI`. The PyPI job publishes
   only after the dry-run succeeds (and any environment approval you configured).

Nothing publishes without a `pqcmap-v*` tag — ordinary pushes and PRs only run tests.

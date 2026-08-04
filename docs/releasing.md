# Releasing RunbookProof

RunbookProof releases are built, verified, published to PyPI, and attached to a
GitHub release by `.github/workflows/release.yml`.

## One-time PyPI setup

Before publishing the first version:

1. Create or sign in to the PyPI account that will own `runbookproof`.
2. Configure a PyPI Trusted Publisher with:
   - Owner: `antonisloukis`
   - Repository: `runbookproof`
   - Workflow: `release.yml`
   - Environment: `pypi`
3. In the GitHub repository, create an environment named `pypi`.
4. Add environment protection rules before publishing production releases.

No PyPI API token is stored in the repository.

## Release checklist

1. Start from an up-to-date `main` branch.
2. Confirm the intended version in `pyproject.toml`.
3. Add the release notes to `CHANGELOG.md`.
4. Run the complete validation suite.
5. Build the wheel and source distribution.
6. Run the distribution-content checker.
7. Install and smoke-test the generated wheel.
8. Merge the release-preparation pull request.
9. Create and push an annotated version tag.
10. Confirm that the Release workflow succeeds.
11. Confirm the package appears on PyPI.
12. Confirm the GitHub release contains both distribution files.

## Local release validation

```bash
uv sync --frozen
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
git diff --check
```

Build fresh distributions:

```bash
rm -rf dist
uv build --no-sources
uv run python scripts/check_distribution.py
```

Smoke-test the built wheel in an isolated environment:

```bash
rm -rf .release-venv

uv venv --python 3.11 .release-venv

uv pip install   --python .release-venv/bin/python   dist/*.whl

.release-venv/bin/runbookproof --version
.release-venv/bin/runbookproof rules --format json
.release-venv/bin/runbookproof scan README.md

rm -rf .release-venv
```

## Creating a release

For version `0.1.0`:

```bash
git switch main
git pull origin main

git tag -a v0.1.0   -m "RunbookProof v0.1.0"

git push origin v0.1.0
```

The tag must exactly match the project version prefixed with `v`.

The release workflow will:

1. run formatting, linting, type checking, and tests
2. verify that the tag matches `pyproject.toml`
3. build the source distribution and wheel
4. inspect the distribution contents
5. install and smoke-test the wheel
6. publish the distributions through PyPI Trusted Publishing
7. create a GitHub release and attach the distributions

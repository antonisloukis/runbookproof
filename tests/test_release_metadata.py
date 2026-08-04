"""Tests for release metadata and automation."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import cast


def _project_version() -> str:
    """Return the current project version."""
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    project = cast(dict[str, object], data["project"])
    version = project.get("version")

    assert isinstance(version, str)

    return version


def test_changelog_contains_current_version() -> None:
    """The changelog should document the package version."""
    version = _project_version()
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

    assert f"## [{version}]" in changelog


def test_release_documentation_exists() -> None:
    """The repository should document the release process."""
    documentation = Path("docs/releasing.md").read_text(encoding="utf-8")

    assert "PyPI Trusted Publisher" in documentation
    assert "git tag -a" in documentation
    assert "uv build --no-sources" in documentation


def test_release_workflow_contains_required_checks() -> None:
    """The release workflow should validate before publishing."""
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

    required_fragments = (
        "environment: pypi",
        "uv run ruff format --check .",
        "uv run ruff check .",
        "uv run mypy",
        "uv run pytest",
        "uv build --no-sources",
        "scripts/check_distribution.py",
        "uv publish",
        "gh release create",
    )

    for fragment in required_fragments:
        assert fragment in workflow

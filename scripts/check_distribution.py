"""Validate RunbookProof wheel and source-distribution contents."""

from __future__ import annotations

import tarfile
import tomllib
import zipfile
from email.parser import Parser
from pathlib import Path
from typing import cast


def _project_identity() -> tuple[str, str]:
    """Return the configured project name and version."""
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    project = cast(dict[str, object], data["project"])

    name = project.get("name")
    version = project.get("version")

    if not isinstance(name, str):
        raise SystemExit("pyproject.toml project.name must be a string.")

    if not isinstance(version, str):
        raise SystemExit("pyproject.toml project.version must be a string.")

    return name, version


def _single_artifact(
    directory: Path,
    pattern: str,
) -> Path:
    """Return exactly one matching distribution artifact."""
    matches = sorted(directory.glob(pattern))

    if len(matches) != 1:
        raise SystemExit(
            f"Expected exactly one {pattern!r} artifact, found {len(matches)}."
        )

    return matches[0]


def _verify_wheel(
    wheel_path: Path,
    project_name: str,
    project_version: str,
) -> None:
    """Verify package files and wheel metadata."""
    with zipfile.ZipFile(wheel_path) as archive:
        names = set(archive.namelist())

        required_files = {
            "runbookproof/__init__.py",
            "runbookproof/__main__.py",
            "runbookproof/cli.py",
            "runbookproof/rules.py",
            "runbookproof/py.typed",
        }

        missing_files = sorted(required_files - names)

        if missing_files:
            raise SystemExit(
                "Wheel is missing package files: " + ", ".join(missing_files)
            )

        metadata_paths = [
            name for name in names if name.endswith(".dist-info/METADATA")
        ]
        entry_point_paths = [
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        ]

        if len(metadata_paths) != 1:
            raise SystemExit("Wheel must contain exactly one METADATA file.")

        if len(entry_point_paths) != 1:
            raise SystemExit("Wheel must contain exactly one entry_points.txt file.")

        metadata_text = archive.read(metadata_paths[0]).decode("utf-8")
        metadata = Parser().parsestr(metadata_text)

        if metadata["Name"] != project_name:
            raise SystemExit("Wheel project name does not match pyproject.toml.")

        if metadata["Version"] != project_version:
            raise SystemExit("Wheel version does not match pyproject.toml.")

        entry_points = archive.read(entry_point_paths[0]).decode("utf-8")

        expected_entry_point = "runbookproof = runbookproof.cli:main"

        if expected_entry_point not in entry_points:
            raise SystemExit("Wheel does not contain the RunbookProof CLI entry point.")


def _verify_source_distribution(
    source_path: Path,
) -> None:
    """Verify required source-distribution files."""
    with tarfile.open(source_path, "r:gz") as archive:
        names = {member.name for member in archive.getmembers()}

    required_suffixes = (
        "/pyproject.toml",
        "/README.md",
        "/LICENSE",
        "/src/runbookproof/__init__.py",
        "/src/runbookproof/__main__.py",
        "/src/runbookproof/cli.py",
        "/src/runbookproof/rules.py",
        "/src/runbookproof/py.typed",
    )

    missing_suffixes = [
        suffix
        for suffix in required_suffixes
        if not any(name.endswith(suffix) for name in names)
    ]

    if missing_suffixes:
        raise SystemExit(
            "Source distribution is missing files ending with: "
            + ", ".join(missing_suffixes)
        )


def main() -> None:
    """Validate the distributions in the dist directory."""
    project_name, project_version = _project_identity()
    dist_directory = Path("dist")

    if not dist_directory.is_dir():
        raise SystemExit("dist directory does not exist. Run uv build first.")

    wheel_path = _single_artifact(
        dist_directory,
        "*.whl",
    )
    source_path = _single_artifact(
        dist_directory,
        "*.tar.gz",
    )

    _verify_wheel(
        wheel_path,
        project_name,
        project_version,
    )
    _verify_source_distribution(source_path)

    print(f"Validated distributions: {wheel_path.name}, {source_path.name}")


if __name__ == "__main__":
    main()

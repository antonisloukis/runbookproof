"""Command-line interface for RunbookProof."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast

from runbookproof import __version__
from runbookproof.engine import (
    AnalysisReport,
    VerificationEngine,
    VerificationPack,
)
from runbookproof.packs import (
    AwsCliPack,
    AzureCliPack,
    BashPack,
    DockerPack,
    GitPack,
    KubectlPack,
    NodePackagePack,
    PythonPackagePack,
    TerraformPack,
    UniversalPack,
)


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="runbookproof",
        description=(
            "Continuously verify commands in documentation, "
            "runbooks, and AI-generated instructions."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a Markdown file or directory.",
        description=(
            "Analyze Markdown files without executing the commands they contain."
        ),
    )
    scan_parser.add_argument(
        "path",
        type=Path,
        help=("Path to a Markdown file or a directory containing Markdown files."),
    )

    return parser


def _built_in_packs() -> tuple[VerificationPack, ...]:
    """Return all built-in verification packs."""
    return (
        AwsCliPack(),
        AzureCliPack(),
        DockerPack(),
        GitPack(),
        KubectlPack(),
        NodePackagePack(),
        PythonPackagePack(),
        TerraformPack(),
        BashPack(),
        UniversalPack(),
    )


def _pluralized(count: int, noun: str) -> str:
    """Return a count with a correctly pluralized noun."""
    suffix = "" if count == 1 else "s"
    return f"{count} {noun}{suffix}"


def _print_findings(report: AnalysisReport) -> None:
    """Print the findings from one analysis report."""
    for finding in report.findings:
        severity = finding.severity.value.upper()

        print(f"{severity} {finding.rule_id} {finding.location}: {finding.message}")


def _report_summary(report: AnalysisReport) -> str:
    """Return the human-readable summary for one report."""
    return ", ".join(
        (
            _pluralized(report.command_count, "command"),
            _pluralized(report.error_count, "error"),
            _pluralized(report.warning_count, "warning"),
            f"{report.info_count} info",
        )
    )


def _print_report(report: AnalysisReport) -> None:
    """Print one human-readable analysis report."""
    _print_findings(report)
    print(f"Scanned {report.path}: {_report_summary(report)}")


def _read_markdown(path: Path) -> str | None:
    """Read one UTF-8 Markdown document."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        detail = error.strerror or str(error)

        print(
            f"runbookproof: error: cannot read {path}: {detail}",
            file=sys.stderr,
        )
    except UnicodeError:
        print(
            f"runbookproof: error: {path} is not valid UTF-8",
            file=sys.stderr,
        )

    return None


def _analyze_file(
    path: Path,
    engine: VerificationEngine,
) -> AnalysisReport | None:
    """Read and analyze one Markdown document."""
    markdown = _read_markdown(path)

    if markdown is None:
        return None

    return engine.analyze_markdown(
        markdown,
        path=str(path),
    )


def _markdown_files(directory: Path) -> tuple[Path, ...]:
    """Return Markdown files below a directory in stable order."""
    files = (
        path
        for path in directory.rglob("*")
        if path.is_file() and path.suffix.lower() == ".md"
    )

    return tuple(
        sorted(
            files,
            key=lambda path: path.as_posix(),
        )
    )


def _run_file_scan(
    path: Path,
    engine: VerificationEngine,
) -> int:
    """Scan one Markdown file."""
    report = _analyze_file(path, engine)

    if report is None:
        return 2

    _print_report(report)

    return report.exit_code


def _run_directory_scan(
    path: Path,
    engine: VerificationEngine,
) -> int:
    """Recursively scan Markdown files in one directory."""
    files = _markdown_files(path)

    command_count = 0
    error_count = 0
    warning_count = 0
    info_count = 0

    for markdown_path in files:
        report = _analyze_file(markdown_path, engine)

        if report is None:
            return 2

        _print_findings(report)

        command_count += report.command_count
        error_count += report.error_count
        warning_count += report.warning_count
        info_count += report.info_count

    summary = ", ".join(
        (
            _pluralized(len(files), "Markdown file"),
            _pluralized(command_count, "command"),
            _pluralized(error_count, "error"),
            _pluralized(warning_count, "warning"),
            f"{info_count} info",
        )
    )

    print(f"Scanned {path}: {summary}")

    if error_count > 0:
        return 1

    return 0


def _run_scan(path: Path) -> int:
    """Scan one Markdown file or directory."""
    engine = VerificationEngine(
        packs=_built_in_packs(),
    )

    if path.is_dir():
        return _run_directory_scan(path, engine)

    return _run_file_scan(path, engine)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the RunbookProof command-line interface."""
    parser = build_parser()
    arguments = parser.parse_args(argv)
    command = cast(
        str | None,
        getattr(arguments, "command", None),
    )

    if command is None:
        parser.print_help()
        return 0

    if command == "scan":
        path = cast(Path, arguments.path)
        return _run_scan(path)

    parser.error(f"unknown command: {command}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

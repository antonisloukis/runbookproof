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
        help="Scan a Markdown file for risky commands.",
        description=(
            "Analyze commands found in a Markdown document without executing them."
        ),
    )
    scan_parser.add_argument(
        "path",
        type=Path,
        help="Path to the Markdown file to scan.",
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


def _print_report(report: AnalysisReport) -> None:
    """Print one human-readable analysis report."""
    for finding in report.findings:
        severity = finding.severity.value.upper()

        print(f"{severity} {finding.rule_id} {finding.location}: {finding.message}")

    summary = ", ".join(
        (
            _pluralized(report.command_count, "command"),
            _pluralized(report.error_count, "error"),
            _pluralized(report.warning_count, "warning"),
            f"{report.info_count} info",
        )
    )

    print(f"Scanned {report.path}: {summary}")


def _run_scan(path: Path) -> int:
    """Scan one Markdown file and return its report exit code."""
    try:
        markdown = path.read_text(encoding="utf-8")
    except OSError as error:
        detail = error.strerror or str(error)

        print(
            f"runbookproof: error: cannot read {path}: {detail}",
            file=sys.stderr,
        )
        return 2
    except UnicodeError:
        print(
            f"runbookproof: error: {path} is not valid UTF-8",
            file=sys.stderr,
        )
        return 2

    report = VerificationEngine(
        packs=_built_in_packs(),
    ).analyze_markdown(
        markdown,
        path=str(path),
    )

    _print_report(report)

    return report.exit_code


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

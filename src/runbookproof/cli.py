"""Command-line interface for RunbookProof."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections.abc import Sequence
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Literal, cast

from runbookproof import __version__
from runbookproof.engine import (
    AnalysisReport,
    VerificationEngine,
    VerificationPack,
)
from runbookproof.models import Finding
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
from runbookproof.rules import RULES, RuleInfo

OutputFormat = Literal["text", "json", "sarif"]
RulesFormat = Literal["text", "json"]
SarifLevel = Literal["error", "warning", "note"]

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_PROJECT_URL = "https://github.com/antonisloukis/runbookproof"
_DEFAULT_CONFIG_PATH = Path(".runbookproof.toml")
_RULE_ID_PATTERN = re.compile(r"^RBP-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3}$")


def _rule_id(value: str) -> str:
    """Validate and normalize one ignored rule ID."""
    normalized = value.strip().upper()

    if not _RULE_ID_PATTERN.fullmatch(normalized):
        raise argparse.ArgumentTypeError("rule ID must follow the format RBP-PACK-001")

    return normalized


def _print_config_error(
    path: Path,
    message: str,
) -> None:
    """Print a configuration-file error."""
    print(
        f"runbookproof: error: {path}: {message}",
        file=sys.stderr,
    )


def _load_config_rule_ids(
    path: Path,
    *,
    required: bool,
) -> frozenset[str] | None:
    """Load ignored rule IDs from a TOML configuration file."""
    try:
        with path.open("rb") as config_file:
            config = tomllib.load(config_file)
    except FileNotFoundError:
        if required:
            _print_config_error(
                path,
                "file not found",
            )
            return None

        return frozenset()
    except tomllib.TOMLDecodeError as error:
        _print_config_error(
            path,
            f"invalid TOML: {error}",
        )
        return None
    except OSError as error:
        detail = error.strerror or str(error)

        _print_config_error(
            path,
            f"cannot read file: {detail}",
        )
        return None

    scan_value: object = config.get(
        "scan",
        {},
    )

    if not isinstance(scan_value, dict):
        _print_config_error(
            path,
            "scan must be a TOML table",
        )
        return None

    ignore_value: object = scan_value.get(
        "ignore_rules",
        [],
    )

    if not isinstance(ignore_value, list):
        _print_config_error(
            path,
            "scan.ignore_rules must be an array of rule IDs",
        )
        return None

    ignored_rule_ids: set[str] = set()

    for value in ignore_value:
        if not isinstance(value, str):
            _print_config_error(
                path,
                "scan.ignore_rules must contain only strings",
            )
            return None

        try:
            ignored_rule_ids.add(_rule_id(value))
        except argparse.ArgumentTypeError as error:
            _print_config_error(
                path,
                f"invalid rule ID {value!r}: {error}",
            )
            return None

    return frozenset(ignored_rule_ids)


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
    scan_parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        dest="output_format",
        help="Output format. Defaults to text.",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        dest="output_path",
        help="Write scan output to a UTF-8 file instead of standard output.",
    )
    scan_parser.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        type=_rule_id,
        dest="ignored_rule_ids",
        metavar="RULE_ID",
        help=("Ignore findings with this rule ID. May be supplied more than once."),
    )
    scan_parser.add_argument(
        "--config",
        type=Path,
        dest="config_path",
        metavar="PATH",
        help=(
            "Load configuration from PATH. Defaults to .runbookproof.toml when present."
        ),
    )

    rules_parser = subparsers.add_parser(
        "rules",
        help="List built-in static-analysis rules.",
        description=("Display the built-in RunbookProof rule catalogue."),
    )
    rules_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="Output format. Defaults to text.",
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


def _rule_to_dict(
    rule: RuleInfo,
) -> dict[str, object]:
    """Convert one catalogue rule into JSON data."""
    return {
        "rule_id": rule.rule_id,
        "pack": rule.pack_name,
        "messages": list(rule.messages),
    }


def _print_rule_catalog(
    output_format: RulesFormat,
) -> None:
    """Print the built-in rule catalogue."""
    if output_format == "json":
        _print_json(
            {
                "rule_count": len(RULES),
                "rules": [_rule_to_dict(rule) for rule in RULES],
            }
        )
        return

    rule_id_width = max(
        len("RULE ID"),
        *(len(rule.rule_id) for rule in RULES),
    )
    pack_width = max(
        len("PACK"),
        *(len(rule.pack_name) for rule in RULES),
    )

    print(f"{'RULE ID':<{rule_id_width}}  {'PACK':<{pack_width}}  DESCRIPTION")

    for rule in RULES:
        print(
            f"{rule.rule_id:<{rule_id_width}}  "
            f"{rule.pack_name:<{pack_width}}  "
            f"{rule.description}"
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
            _pluralized(
                report.warning_count,
                "warning",
            ),
            f"{report.info_count} info",
        )
    )


def _print_report(report: AnalysisReport) -> None:
    """Print one human-readable analysis report."""
    _print_findings(report)
    print(f"Scanned {report.path}: {_report_summary(report)}")


def _finding_to_dict(
    finding: Finding,
) -> dict[str, object]:
    """Convert one finding into JSON-compatible data."""
    command = finding.command
    source = command.source

    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "message": finding.message,
        "fingerprint": finding.fingerprint,
        "location": finding.location,
        "command": {
            "raw_text": command.raw_text,
            "language": command.language,
            "executable": command.executable,
            "arguments": list(command.arguments),
            "working_directory": (command.working_directory),
            "source": {
                "path": source.path,
                "start_line": source.start_line,
                "end_line": source.end_line,
            },
        },
        "evidence": [
            {
                "kind": evidence.kind.value,
                "message": evidence.message,
                "source": evidence.source,
            }
            for evidence in finding.evidence
        ],
    }


def _report_to_dict(
    report: AnalysisReport,
) -> dict[str, object]:
    """Convert one analysis report into JSON data."""
    return {
        "path": report.path,
        "command_count": report.command_count,
        "finding_count": report.finding_count,
        "error_count": report.error_count,
        "warning_count": report.warning_count,
        "info_count": report.info_count,
        "exit_code": report.exit_code,
        "pack_names": list(report.pack_names),
        "findings": [_finding_to_dict(finding) for finding in report.findings],
    }


def _sarif_level(finding: Finding) -> SarifLevel:
    """Map a RunbookProof severity to a SARIF level."""
    if finding.severity.value == "error":
        return "error"

    if finding.severity.value == "warning":
        return "warning"

    return "note"


def _finding_to_sarif_rule(
    finding: Finding,
) -> dict[str, object]:
    """Convert one finding into a SARIF rule."""
    return {
        "id": finding.rule_id,
        "shortDescription": {
            "text": finding.message,
        },
        "defaultConfiguration": {
            "level": _sarif_level(finding),
        },
    }


def _finding_to_sarif_result(
    finding: Finding,
) -> dict[str, object]:
    """Convert one finding into a SARIF result."""
    command = finding.command
    source = command.source

    return {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding),
        "message": {
            "text": finding.message,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": source.path.replace(
                            "\\",
                            "/",
                        ),
                    },
                    "region": {
                        "startLine": source.start_line,
                        "endLine": source.end_line,
                    },
                }
            }
        ],
        "partialFingerprints": {
            "runbookproofFingerprint": (finding.fingerprint),
        },
        "properties": {
            "severity": finding.severity.value,
            "command": command.raw_text,
            "language": command.language,
            "evidence": [evidence.message for evidence in finding.evidence],
        },
    }


def _sarif_payload(
    reports: Sequence[AnalysisReport],
) -> dict[str, object]:
    """Build a SARIF 2.1.0 document."""
    findings = tuple(finding for report in reports for finding in report.findings)

    rules_by_id: dict[str, Finding] = {}

    for finding in findings:
        rules_by_id.setdefault(
            finding.rule_id,
            finding,
        )

    rules = [
        _finding_to_sarif_rule(rules_by_id[rule_id]) for rule_id in sorted(rules_by_id)
    ]

    results = [_finding_to_sarif_result(finding) for finding in findings]

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RunbookProof",
                        "version": __version__,
                        "informationUri": _PROJECT_URL,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _print_json(payload: dict[str, object]) -> None:
    """Print deterministic, human-readable JSON."""
    print(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        )
    )


def _write_output(path: Path, content: str) -> bool:
    """Write rendered scan output as UTF-8."""
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as error:
        detail = error.strerror or str(error)

        print(
            f"runbookproof: error: cannot write {path}: {detail}",
            file=sys.stderr,
        )
        return False

    return True


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


def _markdown_files(
    directory: Path,
) -> tuple[Path, ...]:
    """Return Markdown files in stable order."""
    files = (
        path
        for path in directory.rglob("*")
        if (path.is_file() and path.suffix.lower() == ".md")
    )

    return tuple(
        sorted(
            files,
            key=lambda path: path.as_posix(),
        )
    )


def _filter_report(
    report: AnalysisReport,
    ignored_rule_ids: frozenset[str],
) -> AnalysisReport:
    """Return a report without findings from ignored rules."""
    if not ignored_rule_ids:
        return report

    return AnalysisReport(
        path=report.path,
        parse_results=report.parse_results,
        findings=tuple(
            finding
            for finding in report.findings
            if finding.rule_id not in ignored_rule_ids
        ),
        pack_names=report.pack_names,
    )


def _run_file_scan(
    path: Path,
    engine: VerificationEngine,
    output_format: OutputFormat,
    ignored_rule_ids: frozenset[str],
) -> int:
    """Scan one Markdown file."""
    report = _analyze_file(path, engine)

    if report is None:
        return 2

    report = _filter_report(
        report,
        ignored_rule_ids,
    )

    if output_format == "json":
        payload = _report_to_dict(report)
        payload["kind"] = "file"
        _print_json(payload)
    elif output_format == "sarif":
        _print_json(_sarif_payload((report,)))
    else:
        _print_report(report)

    return report.exit_code


def _run_directory_scan(
    path: Path,
    engine: VerificationEngine,
    output_format: OutputFormat,
    ignored_rule_ids: frozenset[str],
) -> int:
    """Recursively scan Markdown files."""
    files = _markdown_files(path)
    reports: list[AnalysisReport] = []

    for markdown_path in files:
        report = _analyze_file(
            markdown_path,
            engine,
        )

        if report is None:
            return 2

        reports.append(
            _filter_report(
                report,
                ignored_rule_ids,
            )
        )

    command_count = sum(report.command_count for report in reports)
    finding_count = sum(report.finding_count for report in reports)
    error_count = sum(report.error_count for report in reports)
    warning_count = sum(report.warning_count for report in reports)
    info_count = sum(report.info_count for report in reports)
    exit_code = 1 if error_count > 0 else 0

    if output_format == "json":
        _print_json(
            {
                "kind": "directory",
                "path": str(path),
                "markdown_file_count": len(files),
                "command_count": command_count,
                "finding_count": finding_count,
                "error_count": error_count,
                "warning_count": warning_count,
                "info_count": info_count,
                "exit_code": exit_code,
                "reports": [_report_to_dict(report) for report in reports],
            }
        )
    elif output_format == "sarif":
        _print_json(_sarif_payload(reports))
    else:
        for report in reports:
            _print_findings(report)

        summary = ", ".join(
            (
                _pluralized(
                    len(files),
                    "Markdown file",
                ),
                _pluralized(
                    command_count,
                    "command",
                ),
                _pluralized(
                    error_count,
                    "error",
                ),
                _pluralized(
                    warning_count,
                    "warning",
                ),
                f"{info_count} info",
            )
        )

        print(f"Scanned {path}: {summary}")

    return exit_code


def _run_scan(
    path: Path,
    output_format: OutputFormat,
    ignored_rule_ids: frozenset[str],
) -> int:
    """Scan one Markdown file or directory."""
    engine = VerificationEngine(
        packs=_built_in_packs(),
    )

    if path.is_dir():
        return _run_directory_scan(
            path,
            engine,
            output_format,
            ignored_rule_ids,
        )

    return _run_file_scan(
        path,
        engine,
        output_format,
        ignored_rule_ids,
    )


def _run_scan_with_output(
    path: Path,
    output_format: OutputFormat,
    output_path: Path | None,
    ignored_rule_ids: frozenset[str],
) -> int:
    """Run a scan and optionally write its output to a file."""
    if output_path is None:
        return _run_scan(
            path,
            output_format,
            ignored_rule_ids,
        )

    if path.is_file() and path.resolve() == output_path.resolve():
        print(
            f"runbookproof: error: output path matches input file: {path}",
            file=sys.stderr,
        )
        return 2

    output = StringIO()

    with redirect_stdout(output):
        exit_code = _run_scan(
            path,
            output_format,
            ignored_rule_ids,
        )

    if exit_code == 2:
        return exit_code

    if not _write_output(
        output_path,
        output.getvalue(),
    ):
        return 2

    return exit_code


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """Run the RunbookProof CLI."""
    parser = build_parser()
    arguments = parser.parse_args(argv)

    command = cast(
        str | None,
        getattr(
            arguments,
            "command",
            None,
        ),
    )

    if command is None:
        parser.print_help()
        return 0

    if command == "rules":
        rules_format = cast(
            RulesFormat,
            arguments.output_format,
        )
        _print_rule_catalog(rules_format)
        return 0

    if command == "scan":
        path = cast(
            Path,
            arguments.path,
        )
        output_format = cast(
            OutputFormat,
            arguments.output_format,
        )
        output_path = cast(
            Path | None,
            arguments.output_path,
        )
        cli_ignored_rule_ids = frozenset(
            cast(
                list[str],
                arguments.ignored_rule_ids,
            )
        )
        config_argument = cast(
            Path | None,
            arguments.config_path,
        )
        config_path = (
            config_argument if config_argument is not None else _DEFAULT_CONFIG_PATH
        )
        config_ignored_rule_ids = _load_config_rule_ids(
            config_path,
            required=config_argument is not None,
        )

        if config_ignored_rule_ids is None:
            return 2

        ignored_rule_ids = config_ignored_rule_ids | cli_ignored_rule_ids

        return _run_scan_with_output(
            path,
            output_format,
            output_path,
            ignored_rule_ids,
        )

    parser.error(f"unknown command: {command}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

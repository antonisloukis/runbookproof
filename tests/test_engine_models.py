"""Tests for verification-engine contracts and reports."""

from __future__ import annotations

from runbookproof.engine import AnalysisReport, PackExecutionError
from runbookproof.models import (
    CommandCandidate,
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    ShellParseResult,
    SourceSpan,
)


def make_parse_result(
    *,
    path: str = "docs/deployment.md",
    line: int = 4,
    raw_text: str = "terraform validate",
) -> ShellParseResult:
    """Create a parsed command for engine tests."""
    command = CommandCandidate(
        source=SourceSpan(
            path=path,
            start_line=line,
            end_line=line,
        ),
        raw_text=raw_text,
        language="bash",
        executable="terraform",
        arguments=("validate",),
    )

    return ShellParseResult(
        command=command,
        tokens=("terraform", "validate"),
    )


def make_finding(
    result: ShellParseResult,
    *,
    severity: Severity,
    rule_id: str,
) -> Finding:
    """Create an evidence-backed finding for engine tests."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message="Test verification finding",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message="Detected by the test verification pack",
                source="test pack",
            ),
        ),
    )


def test_empty_analysis_report() -> None:
    """A document containing no commands should produce an empty report."""
    report = AnalysisReport(
        path="README.md",
        parse_results=(),
        findings=(),
    )

    assert report.path == "README.md"
    assert report.commands == ()
    assert report.command_count == 0
    assert report.finding_count == 0
    assert report.exit_code == 0


def test_report_normalizes_path_and_pack_names() -> None:
    """Report paths and pack names should use normalized values."""
    result = make_parse_result(path="docs/deployment.md")

    report = AnalysisReport(
        path=r"docs\deployment.md",
        parse_results=(result,),
        findings=(),
        pack_names=(" universal ", " terraform "),
    )

    assert report.path == "docs/deployment.md"
    assert report.pack_names == ("universal", "terraform")


def test_report_exposes_parsed_commands() -> None:
    """The report should expose commands from its parsing results."""
    first = make_parse_result(line=4)
    second = make_parse_result(
        line=8,
        raw_text="terraform plan",
    )

    report = AnalysisReport(
        path="docs/deployment.md",
        parse_results=(first, second),
        findings=(),
    )

    assert report.commands == (
        first.command,
        second.command,
    )
    assert report.command_count == 2


def test_report_counts_findings_by_severity() -> None:
    """Reports should calculate deterministic severity totals."""
    result = make_parse_result()
    findings = (
        make_finding(
            result,
            severity=Severity.ERROR,
            rule_id="RBP-TEST-001",
        ),
        make_finding(
            result,
            severity=Severity.WARNING,
            rule_id="RBP-TEST-002",
        ),
        make_finding(
            result,
            severity=Severity.INFO,
            rule_id="RBP-TEST-003",
        ),
    )

    report = AnalysisReport(
        path="docs/deployment.md",
        parse_results=(result,),
        findings=findings,
    )

    assert report.finding_count == 3
    assert report.error_count == 1
    assert report.warning_count == 1
    assert report.info_count == 1
    assert report.has_errors
    assert report.exit_code == 1


def test_warning_only_report_exits_successfully() -> None:
    """Warnings should not fail the default command-line execution."""
    result = make_parse_result()
    finding = make_finding(
        result,
        severity=Severity.WARNING,
        rule_id="RBP-TEST-001",
    )

    report = AnalysisReport(
        path="docs/deployment.md",
        parse_results=(result,),
        findings=(finding,),
    )

    assert not report.has_errors
    assert report.exit_code == 0


def test_report_rejects_empty_path() -> None:
    """Every report must identify its analyzed document."""
    try:
        AnalysisReport(
            path=" ",
            parse_results=(),
            findings=(),
        )
    except ValueError as error:
        assert str(error) == "report path must not be empty"
    else:
        raise AssertionError("AnalysisReport did not reject empty path")


def test_report_rejects_duplicate_pack_names() -> None:
    """A verification pack should execute at most once per report."""
    try:
        AnalysisReport(
            path="README.md",
            parse_results=(),
            findings=(),
            pack_names=("terraform", "terraform"),
        )
    except ValueError as error:
        assert str(error) == "pack names must be unique"
    else:
        raise AssertionError("AnalysisReport did not reject duplicate pack names")


def test_report_rejects_finding_from_another_command() -> None:
    """A report cannot contain a finding for an unrelated command."""
    result = make_parse_result()
    other_result = make_parse_result(
        line=20,
        raw_text="terraform destroy",
    )
    finding = make_finding(
        other_result,
        severity=Severity.ERROR,
        rule_id="RBP-TEST-001",
    )

    try:
        AnalysisReport(
            path="docs/deployment.md",
            parse_results=(result,),
            findings=(finding,),
        )
    except ValueError as error:
        assert str(error) == ("all findings must belong to a parsed command")
    else:
        raise AssertionError("AnalysisReport accepted an unrelated finding")


def test_pack_execution_error_contains_context() -> None:
    """Pack failures should retain the failed pack and command identity."""
    error = PackExecutionError(
        pack_name="terraform",
        command_identifier="abc123",
    )

    assert error.pack_name == "terraform"
    assert error.command_identifier == "abc123"
    assert str(error) == ("verification pack 'terraform' failed for command abc123")

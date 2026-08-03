"""Tests for the universal verification pack."""

from __future__ import annotations

import pytest

from runbookproof.engine import VerificationEngine
from runbookproof.models import (
    CommandCandidate,
    EvidenceKind,
    Severity,
    ShellOperator,
    ShellParseResult,
    SourceSpan,
)
from runbookproof.packs import UniversalPack
from runbookproof.parsers import parse_shell_command


def make_result(raw_text: str) -> ShellParseResult:
    """Parse a shell command for universal-pack tests."""
    command = CommandCandidate(
        source=SourceSpan(
            path="README.md",
            start_line=4,
            end_line=4,
        ),
        raw_text=raw_text,
        language="bash",
    )

    return parse_shell_command(command)


def test_universal_pack_supports_every_command() -> None:
    """Universal verification should apply to every parsed command."""
    pack = UniversalPack()

    assert pack.supports(make_result("git status"))
    assert pack.supports(make_result('echo "unfinished'))


def test_simple_command_produces_no_findings() -> None:
    """An ordinary parsed command should pass universal verification."""
    findings = UniversalPack().verify(make_result("kubectl get pods"))

    assert findings == ()


def test_malformed_shell_syntax_produces_error() -> None:
    """A shell parsing error should become an evidence-backed finding."""
    findings = UniversalPack().verify(make_result('echo "unfinished'))

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "RBP-UNIVERSAL-001"
    assert finding.severity is Severity.ERROR
    assert finding.message == "Command contains invalid shell syntax"
    assert finding.evidence[0].kind is EvidenceKind.STATIC_ANALYSIS
    assert finding.evidence[0].message == (
        "Shell parser reported: No closing quotation."
    )
    assert finding.evidence[0].source == ("RunbookProof shell parser")
    assert finding.repair is None


def test_command_without_executable_produces_error() -> None:
    """An assignment-only command should report its missing executable."""
    findings = UniversalPack().verify(make_result("AWS_REGION=eu-west-1"))

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "RBP-UNIVERSAL-002"
    assert finding.severity is Severity.ERROR
    assert finding.message == "Command has no detectable executable"
    assert finding.evidence[0].message == (
        "Shell parsing found no executable after processing assignments and comments."
    )


@pytest.mark.parametrize(
    (
        "raw_text",
        "operator",
        "rule_id",
        "message",
    ),
    [
        (
            "git status | grep clean",
            ShellOperator.PIPE,
            "RBP-UNIVERSAL-010",
            "Command uses a shell pipeline",
        ),
        (
            "terraform fmt && terraform validate",
            ShellOperator.CHAIN,
            "RBP-UNIVERSAL-011",
            "Command uses conditional command chaining",
        ),
        (
            "echo first; echo second",
            ShellOperator.SEQUENCE,
            "RBP-UNIVERSAL-012",
            "Command contains sequential operations",
        ),
        (
            "docker compose up &",
            ShellOperator.BACKGROUND,
            "RBP-UNIVERSAL-013",
            "Command starts a background operation",
        ),
        (
            "terraform plan > plan.txt",
            ShellOperator.REDIRECTION,
            "RBP-UNIVERSAL-014",
            "Command redirects shell input or output",
        ),
        (
            "echo $(whoami)",
            ShellOperator.COMMAND_SUBSTITUTION,
            "RBP-UNIVERSAL-015",
            "Command performs command substitution",
        ),
        (
            "cat <(git diff)",
            ShellOperator.PROCESS_SUBSTITUTION,
            "RBP-UNIVERSAL-016",
            "Command performs process substitution",
        ),
        (
            "echo $((1 + 2))",
            ShellOperator.ARITHMETIC_EXPANSION,
            "RBP-UNIVERSAL-017",
            "Command performs arithmetic expansion",
        ),
    ],
)
def test_reports_complex_shell_operator(
    raw_text: str,
    operator: ShellOperator,
    rule_id: str,
    message: str,
) -> None:
    """Each complex shell construct should have a stable rule."""
    result = make_result(raw_text)
    findings = UniversalPack().verify(result)

    assert operator in result.operators
    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == rule_id
    assert finding.severity is Severity.WARNING
    assert finding.message == message
    assert finding.command is result.command
    assert finding.evidence[0].kind is EvidenceKind.STATIC_ANALYSIS
    assert finding.evidence[0].source == ("RunbookProof shell parser")
    assert finding.repair is None


def test_multiple_operators_use_deterministic_order() -> None:
    """Multiple findings should follow the pack's published rule order."""
    findings = UniversalPack().verify(
        make_result("terraform fmt && terraform validate > result.txt")
    )

    assert [finding.rule_id for finding in findings] == [
        "RBP-UNIVERSAL-011",
        "RBP-UNIVERSAL-014",
    ]


def test_operator_finding_contains_specific_evidence() -> None:
    """Operator findings should explain exactly what was detected."""
    findings = UniversalPack().verify(make_result("git status | grep clean"))

    assert findings[0].evidence[0].message == (
        "Detected an unquoted pipe operator (`|` or `|&`)."
    )


def test_universal_pack_integrates_with_engine() -> None:
    """The verification engine should run universal analysis end to end."""
    report = VerificationEngine(
        packs=(UniversalPack(),),
    ).analyze_markdown(
        "```bash\nterraform plan > plan.txt\n```\n",
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.warning_count == 1
    assert report.error_count == 0
    assert report.pack_names == ("universal",)
    assert report.findings[0].rule_id == "RBP-UNIVERSAL-014"

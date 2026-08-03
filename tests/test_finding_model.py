"""Tests for structured findings, evidence, and repairs."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from runbookproof.models import (
    CommandCandidate,
    Evidence,
    EvidenceKind,
    Finding,
    RepairConfidence,
    RepairSuggestion,
    Severity,
    SourceSpan,
)


def make_command(
    *,
    start_line: int = 8,
    end_line: int = 8,
) -> CommandCandidate:
    """Create a command candidate for finding tests."""
    return CommandCandidate(
        source=SourceSpan(
            path="docs/deployment.md",
            start_line=start_line,
            end_line=end_line,
        ),
        raw_text="terraform refresh",
        language="bash",
        executable="terraform",
        arguments=("refresh",),
    )


def make_evidence() -> Evidence:
    """Create deterministic evidence for finding tests."""
    return Evidence(
        kind=EvidenceKind.TOOL_HELP,
        message="terraform refresh is marked as deprecated",
        source="Terraform 1.13 help output",
    )


def test_evidence_normalizes_text() -> None:
    """Evidence text and sources should be stripped."""
    evidence = Evidence(
        kind=EvidenceKind.STATIC_ANALYSIS,
        message="  Output redirection detected  ",
        source="  shell parser  ",
    )

    assert evidence.message == "Output redirection detected"
    assert evidence.source == "shell parser"


def test_evidence_accepts_missing_source() -> None:
    """Evidence may omit an external source."""
    evidence = Evidence(
        kind=EvidenceKind.POLICY,
        message="Command requires manual review",
    )

    assert evidence.source is None


def test_evidence_rejects_empty_message() -> None:
    """Evidence must contain a meaningful fact."""
    with pytest.raises(
        ValueError,
        match="evidence message must not be empty",
    ):
        Evidence(
            kind=EvidenceKind.STATIC_ANALYSIS,
            message=" ",
        )


def test_evidence_rejects_empty_source() -> None:
    """An explicitly supplied source cannot be blank."""
    with pytest.raises(
        ValueError,
        match="evidence source must not be empty",
    ):
        Evidence(
            kind=EvidenceKind.STATIC_ANALYSIS,
            message="Output redirection detected",
            source=" ",
        )


def test_repair_suggestion_normalizes_text() -> None:
    """Repair text and rationale should be stripped."""
    repair = RepairSuggestion(
        replacement_text="  terraform plan -refresh-only  ",
        rationale="  Uses the supported replacement command.  ",
        confidence=RepairConfidence.HIGH,
        safe_to_apply=True,
    )

    assert repair.replacement_text == "terraform plan -refresh-only"
    assert repair.rationale == ("Uses the supported replacement command.")
    assert repair.safe_to_apply


def test_repair_rejects_empty_replacement() -> None:
    """A repair must include replacement text."""
    with pytest.raises(
        ValueError,
        match="replacement_text must not be empty",
    ):
        RepairSuggestion(
            replacement_text=" ",
            rationale="Use the supported command.",
            confidence=RepairConfidence.HIGH,
        )


def test_repair_rejects_empty_rationale() -> None:
    """A repair must explain why it is proposed."""
    with pytest.raises(
        ValueError,
        match="repair rationale must not be empty",
    ):
        RepairSuggestion(
            replacement_text="terraform plan -refresh-only",
            rationale=" ",
            confidence=RepairConfidence.HIGH,
        )


@pytest.mark.parametrize(
    "confidence",
    [
        RepairConfidence.LOW,
        RepairConfidence.MEDIUM,
    ],
)
def test_automatic_repair_requires_high_confidence(
    confidence: RepairConfidence,
) -> None:
    """Only high-confidence repairs may be applied automatically."""
    with pytest.raises(
        ValueError,
        match="safe_to_apply requires high repair confidence",
    ):
        RepairSuggestion(
            replacement_text="terraform plan -refresh-only",
            rationale="Potential replacement.",
            confidence=confidence,
            safe_to_apply=True,
        )


def test_finding_normalizes_rule_and_message() -> None:
    """Finding identifiers and messages should be normalized."""
    finding = Finding(
        rule_id="  rbp-terraform-001  ",
        severity=Severity.WARNING,
        message="  Deprecated Terraform command  ",
        command=make_command(),
        evidence=(make_evidence(),),
    )

    assert finding.rule_id == "RBP-TERRAFORM-001"
    assert finding.message == "Deprecated Terraform command"


@pytest.mark.parametrize(
    "rule_id",
    [
        "",
        "TERRAFORM-001",
        "RBP-TERRAFORM-1",
        "RBP-TERRAFORM-0001",
        "RBP--001",
    ],
)
def test_finding_rejects_invalid_rule_id(rule_id: str) -> None:
    """Rule identifiers must use the published format."""
    with pytest.raises(
        ValueError,
        match="rule_id must follow the format RBP-PACK-001",
    ):
        Finding(
            rule_id=rule_id,
            severity=Severity.WARNING,
            message="Deprecated command",
            command=make_command(),
            evidence=(make_evidence(),),
        )


def test_finding_rejects_empty_message() -> None:
    """A finding must contain a user-facing explanation."""
    with pytest.raises(
        ValueError,
        match="finding message must not be empty",
    ):
        Finding(
            rule_id="RBP-TERRAFORM-001",
            severity=Severity.WARNING,
            message=" ",
            command=make_command(),
            evidence=(make_evidence(),),
        )


def test_finding_requires_evidence() -> None:
    """Every verdict must be backed by deterministic evidence."""
    with pytest.raises(
        ValueError,
        match="finding must contain evidence",
    ):
        Finding(
            rule_id="RBP-TERRAFORM-001",
            severity=Severity.WARNING,
            message="Deprecated command",
            command=make_command(),
            evidence=(),
        )


def test_finding_accepts_repair_suggestion() -> None:
    """A finding may include an evidence-backed repair."""
    repair = RepairSuggestion(
        replacement_text="terraform plan -refresh-only",
        rationale="Uses the supported refresh-only workflow.",
        confidence=RepairConfidence.HIGH,
        safe_to_apply=True,
    )
    finding = Finding(
        rule_id="RBP-TERRAFORM-001",
        severity=Severity.WARNING,
        message="Deprecated Terraform command",
        command=make_command(),
        evidence=(make_evidence(),),
        repair=repair,
    )

    assert finding.repair is repair


def test_finding_fingerprint_is_stable() -> None:
    """Equivalent findings should receive the same fingerprint."""
    first = Finding(
        rule_id="RBP-TERRAFORM-001",
        severity=Severity.WARNING,
        message="Deprecated command",
        command=make_command(),
        evidence=(make_evidence(),),
    )
    second = Finding(
        rule_id="RBP-TERRAFORM-001",
        severity=Severity.ERROR,
        message="Different wording",
        command=make_command(),
        evidence=(make_evidence(),),
    )

    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 16


def test_fingerprint_changes_for_different_rule() -> None:
    """Different rules on the same command require separate identities."""
    first = Finding(
        rule_id="RBP-TERRAFORM-001",
        severity=Severity.WARNING,
        message="Deprecated command",
        command=make_command(),
        evidence=(make_evidence(),),
    )
    second = Finding(
        rule_id="RBP-TERRAFORM-002",
        severity=Severity.WARNING,
        message="Different rule",
        command=make_command(),
        evidence=(make_evidence(),),
    )

    assert first.fingerprint != second.fingerprint


def test_location_formats_single_line() -> None:
    """Single-line commands should use a compact source location."""
    finding = Finding(
        rule_id="RBP-TERRAFORM-001",
        severity=Severity.WARNING,
        message="Deprecated command",
        command=make_command(start_line=8, end_line=8),
        evidence=(make_evidence(),),
    )

    assert finding.location == "docs/deployment.md:8"


def test_location_formats_line_range() -> None:
    """Multiline commands should expose their complete source range."""
    finding = Finding(
        rule_id="RBP-TERRAFORM-001",
        severity=Severity.WARNING,
        message="Deprecated command",
        command=make_command(start_line=8, end_line=10),
        evidence=(make_evidence(),),
    )

    assert finding.location == "docs/deployment.md:8-10"


def test_finding_is_immutable() -> None:
    """Published findings should not be mutated after creation."""
    finding = Finding(
        rule_id="RBP-TERRAFORM-001",
        severity=Severity.WARNING,
        message="Deprecated command",
        command=make_command(),
        evidence=(make_evidence(),),
    )

    with pytest.raises(FrozenInstanceError):
        finding.message = "Changed"  # type: ignore[misc]

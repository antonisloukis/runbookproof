"""Tests for verification-engine orchestration."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

import pytest

from runbookproof.engine import (
    PackExecutionError,
    VerificationEngine,
    analyze_markdown,
)
from runbookproof.models import (
    CommandCandidate,
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    ShellParseResult,
    SourceSpan,
)


def make_finding(
    result: ShellParseResult,
    *,
    rule_id: str,
    severity: Severity,
    message: str,
    source: str,
) -> Finding:
    """Create a finding produced by a test verification pack."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message="Detected by a test verification pack",
                source=source,
            ),
        ),
    )


@dataclass(slots=True)
class RecordingPack:
    """Verification pack that records commands it verifies."""

    name: str
    executable: str
    rule_id: str
    severity: Severity = Severity.WARNING
    calls: list[str] = field(default_factory=list)

    def supports(self, result: ShellParseResult) -> bool:
        """Support commands matching the configured executable."""
        return result.command.executable == self.executable

    def verify(
        self,
        result: ShellParseResult,
    ) -> Iterable[Finding]:
        """Return one deterministic finding."""
        self.calls.append(result.command.identifier)

        return (
            make_finding(
                result,
                rule_id=self.rule_id,
                severity=self.severity,
                message=f"{self.name} finding",
                source=self.name,
            ),
        )


class UnorderedPack:
    """Return findings in a deliberately unstable-looking order."""

    name = "unordered"

    def supports(self, result: ShellParseResult) -> bool:
        """Support every parsed command."""
        return True

    def verify(
        self,
        result: ShellParseResult,
    ) -> Iterable[Finding]:
        """Return warning before error to test report sorting."""
        return (
            make_finding(
                result,
                rule_id="RBP-TEST-002",
                severity=Severity.WARNING,
                message="Warning finding",
                source=self.name,
            ),
            make_finding(
                result,
                rule_id="RBP-TEST-001",
                severity=Severity.ERROR,
                message="Error finding",
                source=self.name,
            ),
        )


class SupportsFailurePack:
    """Fail while deciding whether a command is supported."""

    name = "supports-failure"

    def supports(self, result: ShellParseResult) -> bool:
        """Simulate an unexpected support-check failure."""
        raise RuntimeError("support check failed")

    def verify(
        self,
        result: ShellParseResult,
    ) -> Iterable[Finding]:
        """This method should never be reached."""
        return ()


class VerifyFailurePack:
    """Fail while verifying a supported command."""

    name = "verify-failure"

    def supports(self, result: ShellParseResult) -> bool:
        """Support every command."""
        return True

    def verify(
        self,
        result: ShellParseResult,
    ) -> Iterable[Finding]:
        """Simulate an unexpected verification failure."""
        raise RuntimeError("verification failed")


class ForeignFindingPack:
    """Return an invalid finding for an unrelated command."""

    name = "foreign-finding"

    def supports(self, result: ShellParseResult) -> bool:
        """Support every command."""
        return True

    def verify(
        self,
        result: ShellParseResult,
    ) -> Iterable[Finding]:
        """Return a finding associated with another source location."""
        foreign_command = CommandCandidate(
            source=SourceSpan(
                path=result.command.source.path,
                start_line=999,
                end_line=999,
            ),
            raw_text=result.command.raw_text,
            language=result.command.language,
            executable=result.command.executable,
            arguments=result.command.arguments,
        )
        foreign_result = ShellParseResult(
            command=foreign_command,
            tokens=result.tokens,
        )

        return (
            make_finding(
                foreign_result,
                rule_id="RBP-TEST-001",
                severity=Severity.ERROR,
                message="Foreign command finding",
                source=self.name,
            ),
        )


def test_engine_analyzes_markdown_without_packs() -> None:
    """The engine should connect extraction and shell parsing."""
    markdown = "```bash\nterraform validate\n```\n"

    report = VerificationEngine().analyze_markdown(
        markdown,
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 0
    assert report.commands[0].executable == "terraform"
    assert report.commands[0].arguments == ("validate",)
    assert report.pack_names == ()


def test_engine_runs_only_supporting_packs() -> None:
    """Only packs supporting an executable should verify it."""
    git_pack = RecordingPack(
        name="git",
        executable="git",
        rule_id="RBP-GIT-001",
    )
    terraform_pack = RecordingPack(
        name="terraform",
        executable="terraform",
        rule_id="RBP-TERRAFORM-001",
    )

    report = VerificationEngine(
        packs=(git_pack, terraform_pack),
    ).analyze_markdown(
        "```bash\nterraform validate\n```\n",
        path="README.md",
    )

    assert git_pack.calls == []
    assert len(terraform_pack.calls) == 1
    assert report.finding_count == 1
    assert report.findings[0].rule_id == "RBP-TERRAFORM-001"
    assert report.pack_names == ("git", "terraform")


def test_engine_analyzes_multiple_commands() -> None:
    """Different packs should verify commands in the same document."""
    git_pack = RecordingPack(
        name="git",
        executable="git",
        rule_id="RBP-GIT-001",
    )
    terraform_pack = RecordingPack(
        name="terraform",
        executable="terraform",
        rule_id="RBP-TERRAFORM-001",
    )
    markdown = "```bash\ngit status\nterraform validate\n```\n"

    report = VerificationEngine(
        packs=(git_pack, terraform_pack),
    ).analyze_markdown(
        markdown,
        path="README.md",
    )

    assert report.command_count == 2
    assert report.finding_count == 2
    assert len(git_pack.calls) == 1
    assert len(terraform_pack.calls) == 1


def test_engine_deduplicates_finding_fingerprints() -> None:
    """The first identical rule-command finding should be retained."""
    first_pack = RecordingPack(
        name="first",
        executable="terraform",
        rule_id="RBP-TEST-001",
    )
    second_pack = RecordingPack(
        name="second",
        executable="terraform",
        rule_id="RBP-TEST-001",
    )

    report = VerificationEngine(
        packs=(first_pack, second_pack),
    ).analyze_markdown(
        "```bash\nterraform validate\n```\n",
        path="README.md",
    )

    assert report.finding_count == 1
    assert report.findings[0].message == "first finding"


def test_engine_sorts_findings_deterministically() -> None:
    """Errors should appear before warnings at the same location."""
    report = VerificationEngine(
        packs=(UnorderedPack(),),
    ).analyze_markdown(
        "```bash\nterraform validate\n```\n",
        path="README.md",
    )

    assert [finding.rule_id for finding in report.findings] == [
        "RBP-TEST-001",
        "RBP-TEST-002",
    ]


def test_engine_rejects_duplicate_pack_names() -> None:
    """Pack names must uniquely identify registered plugins."""
    first = RecordingPack(
        name="terraform",
        executable="terraform",
        rule_id="RBP-TEST-001",
    )
    second = RecordingPack(
        name="terraform",
        executable="terraform",
        rule_id="RBP-TEST-002",
    )

    with pytest.raises(
        ValueError,
        match="verification pack names must be unique",
    ):
        VerificationEngine(packs=(first, second))


def test_engine_rejects_empty_pack_name() -> None:
    """Every registered pack must have a meaningful name."""
    pack = RecordingPack(
        name=" ",
        executable="terraform",
        rule_id="RBP-TEST-001",
    )

    with pytest.raises(
        ValueError,
        match="verification pack names must not be empty",
    ):
        VerificationEngine(packs=(pack,))


def test_engine_wraps_support_check_failure() -> None:
    """Unexpected support-check failures should include pack context."""
    engine = VerificationEngine(
        packs=(SupportsFailurePack(),),
    )

    with pytest.raises(PackExecutionError) as captured:
        engine.analyze_markdown(
            "```bash\nterraform validate\n```\n",
            path="README.md",
        )

    assert captured.value.pack_name == "supports-failure"
    assert isinstance(captured.value.__cause__, RuntimeError)


def test_engine_wraps_verification_failure() -> None:
    """Unexpected verification failures should include pack context."""
    engine = VerificationEngine(
        packs=(VerifyFailurePack(),),
    )

    with pytest.raises(PackExecutionError) as captured:
        engine.analyze_markdown(
            "```bash\nterraform validate\n```\n",
            path="README.md",
        )

    assert captured.value.pack_name == "verify-failure"
    assert isinstance(captured.value.__cause__, RuntimeError)


def test_engine_rejects_finding_for_another_command() -> None:
    """Packs cannot attach findings to unrelated commands."""
    engine = VerificationEngine(
        packs=(ForeignFindingPack(),),
    )

    with pytest.raises(PackExecutionError) as captured:
        engine.analyze_markdown(
            "```bash\nterraform validate\n```\n",
            path="README.md",
        )

    assert captured.value.pack_name == "foreign-finding"
    assert isinstance(captured.value.__cause__, ValueError)


def test_analyze_markdown_convenience_function() -> None:
    """The module helper should construct and run an engine."""
    pack = RecordingPack(
        name="terraform",
        executable="terraform",
        rule_id="RBP-TERRAFORM-001",
    )

    report = analyze_markdown(
        "```bash\nterraform validate\n```\n",
        path="README.md",
        packs=(pack,),
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.pack_names == ("terraform",)

"""Tests for the Git verification pack."""

from __future__ import annotations

import pytest

from runbookproof.engine import VerificationEngine
from runbookproof.models import (
    CommandCandidate,
    RepairConfidence,
    Severity,
    ShellParseResult,
    SourceSpan,
)
from runbookproof.packs import GitPack
from runbookproof.parsers import parse_shell_command


def make_result(raw_text: str) -> ShellParseResult:
    """Parse a command for Git-pack tests."""
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


def test_git_pack_supports_git_commands() -> None:
    """The pack should support successfully parsed Git commands."""
    pack = GitPack()

    assert pack.supports(make_result("git status"))
    assert not pack.supports(make_result("terraform validate"))


def test_simple_git_command_produces_no_findings() -> None:
    """A read-only Git command should pass verification."""
    assert GitPack().verify(make_result("git status")) == ()


def test_detects_hard_reset() -> None:
    """Hard resets should be treated as destructive."""
    finding = GitPack().verify(make_result("git reset --hard HEAD~1"))[0]

    assert finding.rule_id == "RBP-GIT-001"
    assert finding.severity is Severity.ERROR


def test_supports_git_global_options() -> None:
    """Git global options should not hide the real subcommand."""
    finding = GitPack().verify(make_result("git -C repository reset --hard"))[0]

    assert finding.rule_id == "RBP-GIT-001"


def test_soft_reset_produces_no_finding() -> None:
    """A soft reset does not discard working-tree content."""
    assert GitPack().verify(make_result("git reset --soft HEAD~1")) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "git push --force origin main",
        "git push -f origin main",
        "git push -uf origin main",
    ],
)
def test_detects_unrestricted_force_push(raw_text: str) -> None:
    """Unrestricted forced pushes should be errors."""
    finding = GitPack().verify(make_result(raw_text))[0]

    assert finding.rule_id == "RBP-GIT-002"
    assert finding.severity is Severity.ERROR


def test_force_with_lease_has_separate_warning() -> None:
    """Force-with-lease should not be classified as raw force."""
    findings = GitPack().verify(make_result("git push --force-with-lease origin main"))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-GIT-003"
    assert findings[0].severity is Severity.WARNING


def test_forced_git_clean_produces_warning() -> None:
    """Forced removal of untracked files should require review."""
    finding = GitPack().verify(make_result("git clean -f"))[0]

    assert finding.rule_id == "RBP-GIT-004"
    assert finding.severity is Severity.WARNING


def test_broad_git_clean_produces_error() -> None:
    """Removing directories and ignored files is more destructive."""
    finding = GitPack().verify(make_result("git clean -fdx"))[0]

    assert finding.rule_id == "RBP-GIT-004"
    assert finding.severity is Severity.ERROR


def test_dry_run_git_clean_produces_no_finding() -> None:
    """A clean dry run does not remove anything."""
    assert GitPack().verify(make_result("git clean -n")) == ()


def test_forced_branch_deletion_produces_warning() -> None:
    """Forced deletion can remove an unmerged local branch."""
    finding = GitPack().verify(make_result("git branch -D old-feature"))[0]

    assert finding.rule_id == "RBP-GIT-005"


def test_normal_branch_deletion_produces_no_finding() -> None:
    """Safe branch deletion already checks merge status."""
    assert GitPack().verify(make_result("git branch -d old-feature")) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "git checkout -- configuration.yml",
        "git restore configuration.yml",
        "git restore --worktree configuration.yml",
    ],
)
def test_detects_discarded_working_tree_changes(
    raw_text: str,
) -> None:
    """Commands replacing working-tree content should be reported."""
    finding = GitPack().verify(make_result(raw_text))[0]

    assert finding.rule_id == "RBP-GIT-006"


def test_staged_restore_does_not_discard_worktree() -> None:
    """Restoring only the index should not trigger this rule."""
    assert GitPack().verify(make_result("git restore --staged configuration.yml")) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "git push origin --delete old-feature",
        "git push origin :old-feature",
    ],
)
def test_detects_remote_branch_deletion(raw_text: str) -> None:
    """Remote branch deletion should require explicit review."""
    finding = GitPack().verify(make_result(raw_text))[0]

    assert finding.rule_id == "RBP-GIT-007"


def test_normal_push_produces_no_finding() -> None:
    """An ordinary push should pass static verification."""
    assert GitPack().verify(make_result("git push origin main")) == ()


def test_pull_without_strategy_produces_warning() -> None:
    """Pull behavior should not depend on local configuration."""
    finding = GitPack().verify(make_result("git pull origin main"))[0]

    assert finding.rule_id == "RBP-GIT-008"
    assert finding.severity is Severity.WARNING


@pytest.mark.parametrize(
    "strategy",
    [
        "--ff-only",
        "--rebase",
        "--no-rebase",
    ],
)
def test_explicit_pull_strategy_produces_no_finding(
    strategy: str,
) -> None:
    """Explicit pull strategies should be deterministic."""
    assert GitPack().verify(make_result(f"git pull {strategy} origin main")) == ()


def test_legacy_checkout_branch_creation_has_repair() -> None:
    """Legacy branch creation should include a modern suggestion."""
    finding = GitPack().verify(make_result("git checkout -b feature/authentication"))[0]

    assert finding.rule_id == "RBP-GIT-009"
    assert finding.severity is Severity.INFO
    assert finding.repair is not None
    assert finding.repair.replacement_text == ("git switch -c feature/authentication")
    assert finding.repair.confidence is RepairConfidence.MEDIUM
    assert not finding.repair.safe_to_apply


@pytest.mark.parametrize(
    "operation",
    [
        "clear",
        "drop",
    ],
)
def test_detects_destructive_stash_operations(
    operation: str,
) -> None:
    """Stash deletion should require review."""
    finding = GitPack().verify(make_result(f"git stash {operation}"))[0]

    assert finding.rule_id == "RBP-GIT-010"


def test_help_command_produces_no_finding() -> None:
    """Help requests should not be treated as operational commands."""
    assert GitPack().verify(make_result("git pull --help")) == ()


def test_multiple_findings_have_deterministic_order() -> None:
    """Findings should follow their published rule order."""
    findings = GitPack().verify(
        make_result("git push --force origin --delete old-feature")
    )

    assert [finding.rule_id for finding in findings] == [
        "RBP-GIT-002",
        "RBP-GIT-007",
    ]


def test_git_pack_integrates_with_engine() -> None:
    """The verification engine should run the Git pack end to end."""
    report = VerificationEngine(
        packs=(GitPack(),),
    ).analyze_markdown(
        "```bash\ngit reset --hard HEAD~1\n```\n",
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.error_count == 1
    assert report.pack_names == ("git",)
    assert report.findings[0].rule_id == "RBP-GIT-001"

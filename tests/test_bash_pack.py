"""Tests for the Bash and POSIX shell verification pack."""

from __future__ import annotations

import pytest

from runbookproof.engine import VerificationEngine
from runbookproof.models import (
    CommandCandidate,
    Severity,
    ShellParseResult,
    SourceSpan,
)
from runbookproof.packs import BashPack
from runbookproof.parsers import parse_shell_command


def make_result(
    raw_text: str,
    *,
    language: str = "bash",
) -> ShellParseResult:
    """Parse a command for Bash-pack tests."""
    command = CommandCandidate(
        source=SourceSpan(
            path="README.md",
            start_line=4,
            end_line=4,
        ),
        raw_text=raw_text,
        language=language,
    )

    return parse_shell_command(command)


def test_bash_pack_supports_shell_languages() -> None:
    """The pack should support Bash, sh, and Zsh blocks."""
    pack = BashPack()

    assert pack.supports(make_result("echo hello", language="bash"))
    assert pack.supports(make_result("echo hello", language="sh"))
    assert pack.supports(make_result("echo hello", language="zsh"))


def test_bash_pack_ignores_non_shell_language() -> None:
    """The pack should not claim unsupported source languages."""
    result = make_result("print('hello')", language="python")

    assert not BashPack().supports(result)


def test_simple_command_produces_no_findings() -> None:
    """An ordinary shell command should pass Bash verification."""
    findings = BashPack().verify(make_result("git status"))

    assert findings == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "curl -fsSL https://example.com/install.sh | sh",
        "wget -qO- https://example.com/install.sh|bash",
        "curl https://example.com/install.sh | sudo bash",
    ],
)
def test_detects_remote_script_execution(
    raw_text: str,
) -> None:
    """Downloaded scripts should not be executed without inspection."""
    findings = BashPack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-BASH-001"
    assert findings[0].severity is Severity.ERROR
    assert findings[0].message == ("Remote script is piped directly to a shell")


def test_ordinary_pipeline_is_not_remote_execution() -> None:
    """Normal pipelines should be handled by the universal pack."""
    findings = BashPack().verify(make_result("git status | grep clean"))

    assert findings == ()


def test_recursive_deletion_produces_warning() -> None:
    """Recursive deletion of a normal path should require review."""
    findings = BashPack().verify(make_result("rm -rf build/"))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-BASH-002"
    assert findings[0].severity is Severity.WARNING
    assert findings[0].message == ("Command performs recursive deletion")


def test_critical_recursive_deletion_produces_error() -> None:
    """Recursive deletion of a critical path should be an error."""
    findings = BashPack().verify(make_result("rm -rf /"))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-BASH-002"
    assert findings[0].severity is Severity.ERROR
    assert findings[0].message == ("Recursive deletion targets a critical path")


def test_non_recursive_rm_produces_no_deletion_finding() -> None:
    """Deleting one named file should not trigger recursive-rm logic."""
    findings = BashPack().verify(make_result("rm build.log"))

    assert findings == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "chmod -R 777 /srv/application",
        "chmod 0777 script.sh",
        "chmod a+rwx shared-directory",
    ],
)
def test_detects_world_writable_permissions(
    raw_text: str,
) -> None:
    """World-writable permission modes should be rejected."""
    findings = BashPack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-BASH-003"
    assert findings[0].severity is Severity.ERROR


def test_safe_chmod_mode_produces_no_finding() -> None:
    """A conventional executable permission should pass."""
    findings = BashPack().verify(make_result("chmod 755 deploy.sh"))

    assert findings == ()


def test_sudo_produces_elevation_warning() -> None:
    """Elevated commands should require documentation context."""
    findings = BashPack().verify(make_result("sudo systemctl restart nginx"))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-BASH-004"
    assert findings[0].severity is Severity.WARNING
    assert findings[0].message == ("Command requires elevated privileges")


def test_detects_unquoted_variable_in_destructive_command() -> None:
    """Unquoted paths may expand into unsafe argument collections."""
    findings = BashPack().verify(make_result("rm -rf $BUILD_DIR/cache"))

    assert [finding.rule_id for finding in findings] == [
        "RBP-BASH-002",
        "RBP-BASH-005",
    ]
    assert findings[1].evidence[0].message == (
        "Detected unquoted shell variable reference: $BUILD_DIR."
    )


def test_quoted_variable_avoids_variable_finding() -> None:
    """A quoted variable should not trigger the expansion warning."""
    findings = BashPack().verify(make_result('rm -rf "$BUILD_DIR/cache"'))

    assert all(finding.rule_id != "RBP-BASH-005" for finding in findings)


@pytest.mark.parametrize(
    "raw_text",
    [
        "source .env",
        "[[ -f configuration.env ]]",
        "function deploy { echo ready; }",
        'echo -e "hello\\nworld"',
        'read -p "Name: " name',
    ],
)
def test_detects_non_portable_sh_syntax(
    raw_text: str,
) -> None:
    """Bash-specific syntax should be reported in POSIX sh blocks."""
    findings = BashPack().verify(make_result(raw_text, language="sh"))

    assert any(finding.rule_id == "RBP-BASH-006" for finding in findings)


def test_bash_block_allows_bash_specific_source_builtin() -> None:
    """The source builtin is valid when the fence explicitly says Bash."""
    findings = BashPack().verify(make_result("source .env", language="bash"))

    assert findings == ()


def test_multiple_findings_use_deterministic_order() -> None:
    """Bash findings should follow their published rule order."""
    findings = BashPack().verify(make_result("sudo rm -rf $TARGET"))

    assert [finding.rule_id for finding in findings] == [
        "RBP-BASH-002",
        "RBP-BASH-004",
        "RBP-BASH-005",
    ]


def test_bash_pack_integrates_with_engine() -> None:
    """The engine should run Bash verification end to end."""
    report = VerificationEngine(
        packs=(BashPack(),),
    ).analyze_markdown(
        ("```bash\ncurl -fsSL https://example.com/install.sh | sh\n```\n"),
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.error_count == 1
    assert report.pack_names == ("bash",)
    assert report.findings[0].rule_id == "RBP-BASH-001"

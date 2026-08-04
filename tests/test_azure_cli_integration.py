"""Integration tests for the Azure CLI verification pack."""

from __future__ import annotations

import pytest

from runbookproof.engine import VerificationEngine
from runbookproof.models import (
    CommandCandidate,
    Finding,
    Severity,
    ShellParseResult,
    SourceSpan,
)
from runbookproof.packs import AzureCliPack
from runbookproof.parsers import parse_shell_command


def make_result(raw_text: str) -> ShellParseResult:
    """Parse one command for Azure CLI pack tests."""
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


def findings(raw_text: str) -> tuple[Finding, ...]:
    """Return findings generated for one Azure CLI command."""
    return AzureCliPack().verify(make_result(raw_text))


def rule_ids(raw_text: str) -> tuple[str, ...]:
    """Return rule identifiers generated for one Azure command."""
    return tuple(finding.rule_id for finding in findings(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        "az group list",
        "az group delete --name production --yes",
        (
            "az role assignment create "
            "--assignee admin@example.com "
            "--role Owner "
            "--scope /subscriptions/example"
        ),
        (
            "az network nsg rule create "
            "--resource-group production "
            "--nsg-name web-nsg "
            "--name allow-public "
            "--priority 100 "
            "--direction Inbound "
            "--access Allow "
            "--source-address-prefixes 0.0.0.0/0"
        ),
        (
            "az storage container set-permission "
            "--name public-assets "
            "--account-name example "
            "--public-access container"
        ),
        "az --subscription example-subscription group list",
    ],
)
def test_supports_azure_cli_commands(raw_text: str) -> None:
    """The pack should support valid Azure CLI operations."""
    assert AzureCliPack().supports(make_result(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        "git status",
        "docker ps",
        "kubectl get pods",
        "terraform plan",
        "aws s3 ls",
        "az",
        "az group",
    ],
)
def test_ignores_unrelated_or_incomplete_commands(
    raw_text: str,
) -> None:
    """Unrelated and incomplete commands should not be claimed."""
    assert not AzureCliPack().supports(make_result(raw_text))


def test_malformed_command_is_not_supported() -> None:
    """Malformed Azure commands should not be verified."""
    result = make_result('az group delete --name "unfinished')

    assert not AzureCliPack().supports(result)
    assert AzureCliPack().verify(result) == ()


@pytest.mark.parametrize(
    ("raw_text", "expected_rule", "expected_severity"),
    [
        (
            "az group delete --name production --yes",
            "RBP-AZURE-001",
            Severity.ERROR,
        ),
        (
            "az role assignment create "
            "--assignee admin@example.com "
            "--role Owner "
            "--scope /subscriptions/example/resourceGroups/app",
            "RBP-AZURE-002",
            Severity.ERROR,
        ),
        (
            "az role assignment create "
            "--assignee developer@example.com "
            "--role Reader "
            "--scope /subscriptions/example",
            "RBP-AZURE-003",
            Severity.WARNING,
        ),
        (
            "az network nsg rule create "
            "--resource-group production "
            "--nsg-name web-nsg "
            "--name allow-public "
            "--priority 100 "
            "--direction Inbound "
            "--access Allow "
            "--source-address-prefixes 0.0.0.0/0",
            "RBP-AZURE-004",
            Severity.ERROR,
        ),
        (
            "az storage container set-permission "
            "--name public-assets "
            "--account-name example "
            "--public-access container",
            "RBP-AZURE-005",
            Severity.ERROR,
        ),
    ],
)
def test_returns_structured_azure_findings(
    raw_text: str,
    expected_rule: str,
    expected_severity: Severity,
) -> None:
    """Risky Azure commands should produce structured findings."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1

    finding = result_findings[0]

    assert finding.rule_id == expected_rule
    assert finding.severity is expected_severity
    assert finding.command.raw_text == raw_text
    assert len(finding.evidence) == 1
    assert finding.evidence[0].source == ("RunbookProof Azure CLI pack")


@pytest.mark.parametrize(
    "raw_text",
    [
        "az group list",
        "az account show",
        (
            "az role assignment create "
            "--assignee developer@example.com "
            "--role Reader "
            "--scope /subscriptions/example/"
            "resourceGroups/app/providers/"
            "Microsoft.Storage/storageAccounts/example"
        ),
        (
            "az network nsg rule create "
            "--resource-group production "
            "--nsg-name web-nsg "
            "--name allow-private "
            "--priority 100 "
            "--direction Inbound "
            "--access Allow "
            "--source-address-prefixes 10.0.0.0/8"
        ),
        (
            "az storage container set-permission "
            "--name private-assets "
            "--account-name example "
            "--public-access off"
        ),
    ],
)
def test_safe_azure_commands_produce_no_findings(
    raw_text: str,
) -> None:
    """Safe Azure commands should not create findings."""
    assert findings(raw_text) == ()


def test_azure_cli_pack_integrates_with_engine() -> None:
    """The verification engine should run the pack end to end."""
    report = VerificationEngine(
        packs=(AzureCliPack(),),
    ).analyze_markdown(
        ("```bash\naz group delete --name production --yes\n```\n"),
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.error_count == 1
    assert report.warning_count == 0
    assert report.pack_names == ("azure-cli",)
    assert report.findings[0].rule_id == "RBP-AZURE-001"

"""Tests for Terraform CLI command verification."""

from __future__ import annotations

import pytest

from runbookproof.engine import VerificationEngine
from runbookproof.models import (
    CommandCandidate,
    Finding,
    RepairConfidence,
    Severity,
    ShellParseResult,
    SourceSpan,
)
from runbookproof.packs import TerraformPack
from runbookproof.parsers import parse_shell_command


def make_result(raw_text: str) -> ShellParseResult:
    """Parse one command for Terraform-pack tests."""
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
    """Return findings generated for one Terraform command."""
    return TerraformPack().verify(make_result(raw_text))


def rule_ids(raw_text: str) -> tuple[str, ...]:
    """Return rule identifiers generated for one command."""
    return tuple(finding.rule_id for finding in findings(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform init",
        "terraform validate",
        "terraform plan",
        "terraform apply plan.tfplan",
        "terraform destroy",
        "terraform output",
        "terraform state list",
        "terraform state rm module.old",
        "terraform workspace select production",
        "terraform import aws_instance.web i-0123456789",
        "terraform -chdir=environments/production plan",
        "terraform -chdir environments/production plan",
    ],
)
def test_supports_terraform_commands(raw_text: str) -> None:
    """The pack should support valid Terraform commands."""
    assert TerraformPack().supports(make_result(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        "git status",
        "docker ps",
        "kubectl get pods",
        "tofu plan",
        "terragrunt plan",
        "terraform",
    ],
)
def test_ignores_unrelated_or_incomplete_commands(
    raw_text: str,
) -> None:
    """Unsupported or incomplete commands should not be claimed."""
    assert not TerraformPack().supports(make_result(raw_text))


def test_malformed_command_is_not_supported() -> None:
    """Malformed commands should remain a universal-pack concern."""
    result = make_result('terraform apply "unfinished')

    assert not TerraformPack().supports(result)
    assert TerraformPack().verify(result) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform help",
        "terraform version",
        "terraform plan -help",
        "terraform apply --help",
        "terraform state rm -help",
        "terraform workspace delete --help",
    ],
)
def test_help_and_version_commands_produce_no_findings(
    raw_text: str,
) -> None:
    """Informational commands should not generate findings."""
    assert findings(raw_text) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform apply -auto-approve",
        "terraform apply -auto-approve=true",
        "terraform destroy -auto-approve",
        "terraform destroy -auto-approve=true",
    ],
)
def test_detects_unreviewed_automatic_approval(
    raw_text: str,
) -> None:
    """Automatic approval without a saved plan should be an error."""
    result_findings = findings(raw_text)
    finding = next(
        item for item in result_findings if item.rule_id == "RBP-TERRAFORM-001"
    )

    assert finding.severity is Severity.ERROR


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform apply plan.tfplan -auto-approve",
        "terraform apply -auto-approve plan.tfplan",
        "terraform apply -auto-approve=false",
    ],
)
def test_reviewed_or_disabled_automatic_approval_passes(
    raw_text: str,
) -> None:
    """Saved plans and disabled auto-approval should pass this rule."""
    assert "RBP-TERRAFORM-001" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform destroy",
        "terraform destroy -auto-approve",
        "terraform plan -destroy",
        "terraform plan -destroy=true",
        "terraform apply -destroy",
        "terraform apply -destroy=true",
    ],
)
def test_detects_destroy_operations(raw_text: str) -> None:
    """Destroy planning and execution should be treated as errors."""
    result_findings = findings(raw_text)
    finding = next(
        item for item in result_findings if item.rule_id == "RBP-TERRAFORM-002"
    )

    assert finding.severity is Severity.ERROR


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform plan",
        "terraform apply plan.tfplan",
        "terraform apply -destroy=false plan.tfplan",
    ],
)
def test_normal_non_destroy_operations_pass(
    raw_text: str,
) -> None:
    """Normal planning and reviewed apply should not trigger destroy."""
    assert "RBP-TERRAFORM-002" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform apply",
        "terraform apply -input=false",
        "terraform apply -parallelism=4",
        "terraform apply -var region=eu-west-1",
        "terraform apply -var-file production.tfvars",
    ],
)
def test_detects_direct_apply_without_saved_plan(
    raw_text: str,
) -> None:
    """Direct apply should warn when no reviewed plan is supplied."""
    result_findings = findings(raw_text)
    finding = next(
        item for item in result_findings if item.rule_id == "RBP-TERRAFORM-003"
    )

    assert finding.severity is Severity.WARNING


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform apply plan.tfplan",
        "terraform apply ./plans/production.tfplan",
        ("terraform apply -input=false ./plans/production.tfplan"),
        ("terraform apply -var region=eu-west-1 production.tfplan"),
        "terraform apply -destroy",
    ],
)
def test_saved_plan_or_destroy_apply_passes_direct_apply_rule(
    raw_text: str,
) -> None:
    """Saved plans and destroy mode should not trigger direct apply."""
    assert "RBP-TERRAFORM-003" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        ("terraform plan -target=aws_instance.application"),
        ("terraform plan -target aws_instance.application"),
        ("terraform apply -replace=aws_instance.application"),
        ("terraform destroy -target module.legacy"),
        ("terraform plan -target=module.database -replace=aws_instance.application"),
    ],
)
def test_detects_selective_resource_scope(
    raw_text: str,
) -> None:
    """Target and replace options should require explicit review."""
    result_findings = findings(raw_text)
    finding = next(
        item for item in result_findings if item.rule_id == "RBP-TERRAFORM-004"
    )

    assert finding.severity is Severity.WARNING


def test_duplicate_target_is_reported_once() -> None:
    """Repeated identical targets should be deduplicated in evidence."""
    result_findings = findings(
        "terraform plan -target=aws_instance.web -target=aws_instance.web"
    )
    finding = next(
        item for item in result_findings if item.rule_id == "RBP-TERRAFORM-004"
    )

    assert finding.evidence[0].message.count("-target=aws_instance.web") == 1


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform validate",
        "terraform plan",
        "terraform apply plan.tfplan",
        "terraform import aws_instance.web i-123",
    ],
)
def test_operations_without_selective_scope_pass(
    raw_text: str,
) -> None:
    """Commands without target or replace should pass this rule."""
    assert "RBP-TERRAFORM-004" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform plan -lock=false",
        "terraform apply -lock=false",
        "terraform destroy -lock=0",
        "terraform plan -lock no",
        "terraform plan -lock false",
    ],
)
def test_detects_disabled_state_locking(
    raw_text: str,
) -> None:
    """Disabling state locking should be treated as an error."""
    result_findings = findings(raw_text)
    finding = next(
        item for item in result_findings if item.rule_id == "RBP-TERRAFORM-005"
    )

    assert finding.severity is Severity.ERROR


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform plan",
        "terraform plan -lock=true",
        "terraform apply -lock yes plan.tfplan",
        "terraform destroy -lock=1",
    ],
)
def test_enabled_or_default_state_locking_passes(
    raw_text: str,
) -> None:
    """Enabled and default locking should pass this rule."""
    assert "RBP-TERRAFORM-005" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform force-unlock LOCK-ID",
        "terraform force-unlock -force LOCK-ID",
    ],
)
def test_detects_forced_state_unlock(raw_text: str) -> None:
    """Force-unlock should always require manual review."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-TERRAFORM-006"
    assert result_findings[0].severity is Severity.ERROR


@pytest.mark.parametrize(
    ("raw_text", "severity"),
    [
        (
            "terraform state rm module.legacy",
            Severity.ERROR,
        ),
        (
            "terraform state push terraform.tfstate",
            Severity.ERROR,
        ),
        (
            "terraform state mv aws_instance.old aws_instance.new",
            Severity.WARNING,
        ),
        (
            (
                "terraform state replace-provider "
                "registry.terraform.io/hashicorp/aws "
                "example.com/custom/aws"
            ),
            Severity.WARNING,
        ),
    ],
)
def test_detects_manual_state_modification(
    raw_text: str,
    severity: Severity,
) -> None:
    """Manual state mutations should be reported."""
    result_findings = findings(raw_text)
    finding = next(
        item for item in result_findings if item.rule_id == "RBP-TERRAFORM-007"
    )

    assert finding.severity is severity


def test_state_rm_dry_run_passes_state_mutation_rule() -> None:
    """A state-rm dry run should not report actual state mutation."""
    assert "RBP-TERRAFORM-007" not in rule_ids(
        "terraform state rm -dry-run module.legacy"
    )


def test_disabled_state_rm_dry_run_still_warns() -> None:
    """An explicitly false state-rm dry run still mutates state."""
    assert "RBP-TERRAFORM-007" in rule_ids(
        "terraform state rm -dry-run=false module.legacy"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform state list",
        "terraform state show aws_instance.web",
        "terraform workspace show",
    ],
)
def test_read_only_state_operations_pass(
    raw_text: str,
) -> None:
    """Read-only state operations should not trigger mutation rules."""
    assert "RBP-TERRAFORM-007" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform state push -force terraform.tfstate",
        "terraform state push -force=true terraform.tfstate",
    ],
)
def test_detects_forced_state_push(raw_text: str) -> None:
    """Forced state push should bypass remote safety checks."""
    assert rule_ids(raw_text) == (
        "RBP-TERRAFORM-007",
        "RBP-TERRAFORM-008",
    )


def test_nonforced_state_push_has_no_force_finding() -> None:
    """A normal state push should not trigger the force-specific rule."""
    assert "RBP-TERRAFORM-008" not in rule_ids("terraform state push terraform.tfstate")


@pytest.mark.parametrize(
    "raw_text",
    [
        ("TF_VAR_DATABASE_PASSWORD=super-secret terraform plan"),
        ("terraform plan -var database_password=super-secret"),
        ("terraform plan -var=api_token=super-secret"),
        ("terraform init -backend-config access_key=super-secret"),
        ("terraform init -backend-config=client_secret=super-secret"),
    ],
)
def test_detects_literal_secret_values(
    raw_text: str,
) -> None:
    """Literal Terraform credentials should be rejected."""
    result_findings = findings(raw_text)
    finding = next(
        item for item in result_findings if item.rule_id == "RBP-TERRAFORM-009"
    )

    assert finding.severity is Severity.ERROR


@pytest.mark.parametrize(
    "value",
    [
        "$DATABASE_PASSWORD",
        "${DATABASE_PASSWORD}",
        "$(read-secret)",
        "se://production/database-password",
        "vault://production/database-password",
        "<database-password>",
        "changeme",
        "example",
        "placeholder",
        "your-secret-here",
    ],
)
def test_secret_references_and_placeholders_pass(
    value: str,
) -> None:
    """Secret references and placeholders are not literal values."""
    assert "RBP-TERRAFORM-009" not in rule_ids(
        f"terraform plan -var database_password='{value}'"
    )


def test_nonsensitive_literal_variable_passes() -> None:
    """Ordinary Terraform variables should not be treated as secrets."""
    assert "RBP-TERRAFORM-009" not in rule_ids(
        "terraform plan -var region=eu-west-1 -var environment=production"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform state pull",
        "terraform show -json",
        "terraform show -json plan.tfplan",
        "terraform output -json",
        "terraform output -raw database_password",
    ],
)
def test_detects_sensitive_state_or_output_exposure(
    raw_text: str,
) -> None:
    """Raw state, plan, and output rendering should require review."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-TERRAFORM-010"
    assert result_findings[0].severity is Severity.WARNING


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform state list",
        "terraform show",
        "terraform output",
        "terraform output application_url",
    ],
)
def test_normal_state_and_output_display_passes(
    raw_text: str,
) -> None:
    """Normal formatted output should pass the exposure rule."""
    assert "RBP-TERRAFORM-010" not in rule_ids(raw_text)


def test_detects_deprecated_refresh_command() -> None:
    """The deprecated refresh command should suggest a safer workflow."""
    result_findings = findings("terraform refresh")

    assert len(result_findings) == 1

    finding = result_findings[0]

    assert finding.rule_id == "RBP-TERRAFORM-011"
    assert finding.severity is Severity.WARNING
    assert finding.repair is not None
    assert finding.repair.confidence is RepairConfidence.LOW
    assert not finding.repair.safe_to_apply
    assert finding.repair.replacement_text == "terraform apply -refresh-only"


def test_refresh_repair_preserves_arguments() -> None:
    """Refresh-only replacement should preserve command arguments."""
    result_findings = findings("terraform refresh -target=module.database")
    finding = next(
        item for item in result_findings if item.rule_id == "RBP-TERRAFORM-011"
    )

    assert finding.repair is not None
    assert finding.repair.replacement_text == (
        "terraform apply -refresh-only -target=module.database"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform plan -refresh-only",
        "terraform apply -refresh-only plan.tfplan",
    ],
)
def test_refresh_only_operations_do_not_trigger_deprecated_rule(
    raw_text: str,
) -> None:
    """Modern refresh-only operations should not trigger the rule."""
    assert "RBP-TERRAFORM-011" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform init -upgrade",
        "terraform init -upgrade=true",
    ],
)
def test_detects_dependency_upgrade_during_init(
    raw_text: str,
) -> None:
    """Dependency upgrades during initialization should be visible."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-TERRAFORM-012"
    assert result_findings[0].severity is Severity.WARNING


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform init",
        "terraform init -upgrade=false",
    ],
)
def test_normal_init_passes_upgrade_rule(
    raw_text: str,
) -> None:
    """Normal initialization should not trigger dependency upgrade."""
    assert "RBP-TERRAFORM-012" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform workspace delete production",
        "terraform workspace delete -force production",
        "terraform workspace delete",
    ],
)
def test_detects_workspace_deletion(raw_text: str) -> None:
    """Workspace deletion should require explicit review."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-TERRAFORM-013"
    assert result_findings[0].severity is Severity.WARNING


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform workspace list",
        "terraform workspace show",
        "terraform workspace select production",
        "terraform workspace new staging",
    ],
)
def test_nondelete_workspace_commands_pass(
    raw_text: str,
) -> None:
    """Other workspace commands should not trigger deletion."""
    assert "RBP-TERRAFORM-013" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "terraform import aws_instance.web i-0123456789",
        (
            "terraform import "
            "module.database.aws_db_instance.primary "
            "production-database"
        ),
    ],
)
def test_detects_direct_resource_import(
    raw_text: str,
) -> None:
    """Terraform import should be reported as a state operation."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-TERRAFORM-014"
    assert result_findings[0].severity is Severity.WARNING


def test_global_chdir_option_does_not_hide_operation() -> None:
    """The global chdir option should preserve command analysis."""
    assert rule_ids("terraform -chdir=environments/production apply -auto-approve") == (
        "RBP-TERRAFORM-001",
        "RBP-TERRAFORM-003",
    )


def test_multiple_findings_have_deterministic_order() -> None:
    """Findings should follow the pack's published rule order."""
    result_ids = rule_ids(
        "terraform apply "
        "-destroy "
        "-auto-approve "
        "-target=aws_instance.application "
        "-lock=false "
        "-var database_password=super-secret"
    )

    assert result_ids == (
        "RBP-TERRAFORM-001",
        "RBP-TERRAFORM-002",
        "RBP-TERRAFORM-004",
        "RBP-TERRAFORM-005",
        "RBP-TERRAFORM-009",
    )


def test_terraform_pack_integrates_with_engine() -> None:
    """The verification engine should run this pack end to end."""
    report = VerificationEngine(
        packs=(TerraformPack(),),
    ).analyze_markdown(
        ("```bash\nterraform destroy\n```\n"),
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.error_count == 1
    assert report.warning_count == 0
    assert report.pack_names == ("terraform",)
    assert report.findings[0].rule_id == "RBP-TERRAFORM-002"

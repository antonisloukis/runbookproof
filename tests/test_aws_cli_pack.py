"""Tests for AWS CLI command verification."""

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
from runbookproof.packs import AwsCliPack
from runbookproof.parsers import parse_shell_command


def make_result(raw_text: str) -> ShellParseResult:
    """Parse one command for AWS CLI pack tests."""
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
    """Return findings generated for one AWS CLI command."""
    return AwsCliPack().verify(make_result(raw_text))


def rule_ids(raw_text: str) -> tuple[str, ...]:
    """Return rule identifiers generated for one command."""
    return tuple(finding.rule_id for finding in findings(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        "aws sts get-caller-identity",
        "aws s3 ls",
        "aws ec2 describe-instances",
        "aws ec2 terminate-instances --instance-ids i-123",
        "aws iam list-users",
        "aws secretsmanager get-secret-value --secret-id database",
        "aws --profile production ec2 describe-instances",
        "aws --region eu-west-1 s3api list-buckets",
        ("aws --endpoint-url https://example.com ec2 describe-instances"),
    ],
)
def test_supports_aws_cli_commands(raw_text: str) -> None:
    """The pack should support valid AWS CLI service operations."""
    assert AwsCliPack().supports(make_result(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        "git status",
        "docker ps",
        "kubectl get pods",
        "terraform plan",
        "aws",
        "aws ec2",
    ],
)
def test_ignores_unrelated_or_incomplete_commands(
    raw_text: str,
) -> None:
    """Unsupported and incomplete commands should not be claimed."""
    assert not AwsCliPack().supports(make_result(raw_text))


def test_malformed_command_is_not_supported() -> None:
    """Malformed commands should remain a universal-pack concern."""
    result = make_result('aws ec2 describe-instances "unfinished')

    assert not AwsCliPack().supports(result)
    assert AwsCliPack().verify(result) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "aws help version",
        "aws version help",
        "aws ec2 help",
        "aws ec2 describe-instances --help",
        "aws ec2 describe-instances -h",
        "aws ec2 describe-instances --version",
        ("aws ec2 run-instances --generate-cli-skeleton input"),
    ],
)
def test_informational_commands_produce_no_findings(
    raw_text: str,
) -> None:
    """Help, version, and skeleton commands should not be analysed."""
    assert findings(raw_text) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "aws --no-verify-ssl ec2 describe-instances",
        "aws ec2 describe-instances --no-verify-ssl",
    ],
)
def test_detects_disabled_tls_verification(
    raw_text: str,
) -> None:
    """AWS API certificate verification must remain enabled."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-AWS-001"
    assert result_findings[0].severity is Severity.ERROR


def test_normal_tls_verification_passes() -> None:
    """Normal AWS CLI requests should not trigger TLS findings."""
    assert "RBP-AWS-001" not in rule_ids("aws ec2 describe-instances")


@pytest.mark.parametrize(
    ("raw_text", "expected_name"),
    [
        (
            "AWS_ACCESS_KEY_ID=AKIAEXAMPLE aws sts get-caller-identity",
            "AWS_ACCESS_KEY_ID",
        ),
        (
            "AWS_SECRET_ACCESS_KEY=super-secret aws sts get-caller-identity",
            "AWS_SECRET_ACCESS_KEY",
        ),
        (
            "AWS_SESSION_TOKEN=super-secret aws sts get-caller-identity",
            "AWS_SESSION_TOKEN",
        ),
        (
            "aws rds create-db-instance --master-user-password super-secret",
            "--master-user-password",
        ),
        (
            "aws secretsmanager create-secret "
            "--name database "
            "--secret-string super-secret",
            "--secret-string",
        ),
        (
            "aws elasticache modify-replication-group --auth-token super-secret",
            "--auth-token",
        ),
        (
            "aws ssm put-parameter "
            "--name database-password "
            "--type SecureString "
            "--value super-secret",
            "--value",
        ),
    ],
)
def test_detects_literal_credentials(
    raw_text: str,
    expected_name: str,
) -> None:
    """Literal credentials should be rejected."""
    result_findings = findings(raw_text)
    finding = next(item for item in result_findings if item.rule_id == "RBP-AWS-002")

    assert finding.severity is Severity.ERROR
    assert expected_name in finding.evidence[0].message


@pytest.mark.parametrize(
    "value",
    [
        "$AWS_SECRET_ACCESS_KEY",
        "${AWS_SECRET_ACCESS_KEY}",
        "$(read-secret)",
        "se://production/aws-secret",
        "vault://production/aws-secret",
        "file://secret.json",
        "fileb://secret.bin",
        "<aws-secret>",
        "changeme",
        "example",
        "placeholder",
        "your-secret-here",
    ],
)
def test_credential_references_and_placeholders_pass(
    value: str,
) -> None:
    """References and placeholders should not count as literals."""
    assert "RBP-AWS-002" not in rule_ids(
        f"aws secretsmanager create-secret --name database --secret-string '{value}'"
    )


def test_nonsecure_ssm_parameter_value_passes() -> None:
    """Ordinary String parameters should not count as credentials."""
    assert "RBP-AWS-002" not in rule_ids(
        "aws ssm put-parameter --name environment --type String --value production"
    )


@pytest.mark.parametrize(
    ("raw_text", "severity"),
    [
        (
            "aws ec2 terminate-instances --instance-ids i-123",
            Severity.ERROR,
        ),
        (
            "aws cloudformation delete-stack --stack-name production",
            Severity.ERROR,
        ),
        (
            "aws rds delete-db-instance --db-instance-identifier primary",
            Severity.ERROR,
        ),
        (
            "aws iam delete-user --user-name old-user",
            Severity.ERROR,
        ),
        (
            "aws s3api delete-bucket --bucket application-data",
            Severity.ERROR,
        ),
        (
            "aws s3api delete-object --bucket data --key old.txt",
            Severity.WARNING,
        ),
        (
            "aws s3api delete-objects --bucket data --delete '{}'",
            Severity.ERROR,
        ),
        (
            "aws secretsmanager delete-secret --secret-id database",
            Severity.ERROR,
        ),
    ],
)
def test_detects_destructive_operations(
    raw_text: str,
    severity: Severity,
) -> None:
    """Destructive AWS operations should be reported."""
    result_findings = findings(raw_text)
    finding = next(item for item in result_findings if item.rule_id == "RBP-AWS-003")

    assert finding.severity is severity


@pytest.mark.parametrize(
    ("raw_text", "severity"),
    [
        (
            "aws s3 rm s3://application-data/old.txt",
            Severity.WARNING,
        ),
        (
            "aws s3 rm s3://application-data --recursive",
            Severity.ERROR,
        ),
        (
            "aws s3 rb s3://application-data",
            Severity.WARNING,
        ),
        (
            "aws s3 rb s3://application-data --force",
            Severity.ERROR,
        ),
    ],
)
def test_detects_high_level_s3_deletion(
    raw_text: str,
    severity: Severity,
) -> None:
    """High-level S3 deletion commands should be reported."""
    result_findings = findings(raw_text)
    finding = next(item for item in result_findings if item.rule_id == "RBP-AWS-003")

    assert finding.severity is severity


@pytest.mark.parametrize(
    "raw_text",
    [
        "aws ec2 describe-instances",
        "aws s3 ls",
        "aws iam list-users",
        "aws cloudformation describe-stacks",
    ],
)
def test_read_only_operations_pass_destructive_rule(
    raw_text: str,
) -> None:
    """Read-only AWS operations should not be destructive."""
    assert "RBP-AWS-003" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        ("aws ec2 terminate-instances --instance-ids i-123 --force"),
        ("aws ec2 terminate-instances --instance-ids i-123 --skip-os-shutdown"),
        (
            "aws rds delete-db-instance "
            "--db-instance-identifier production "
            "--skip-final-snapshot"
        ),
        (
            "aws rds delete-db-cluster "
            "--db-cluster-identifier production "
            "--skip-final-snapshot"
        ),
        (
            "aws redshift delete-cluster "
            "--cluster-identifier production "
            "--skip-final-snapshot"
        ),
        (
            "aws secretsmanager delete-secret "
            "--secret-id database "
            "--force-delete-without-recovery"
        ),
        (
            "aws s3api delete-object "
            "--bucket data "
            "--key protected.txt "
            "--bypass-governance-retention"
        ),
        ("aws ecr delete-repository --repository-name application --force"),
        (
            "aws cloudformation create-stack "
            "--stack-name application "
            "--template-body file://template.yaml "
            "--disable-rollback"
        ),
        (
            "aws cloudformation update-stack "
            "--stack-name application "
            "--template-body file://template.yaml "
            "--disable-rollback"
        ),
        (
            "aws rds modify-db-instance "
            "--db-instance-identifier production "
            "--no-deletion-protection"
        ),
        (
            "aws ec2 modify-instance-attribute "
            "--instance-id i-123 "
            "--no-disable-api-termination"
        ),
        (
            "aws cloudformation update-termination-protection "
            "--stack-name production "
            "--no-enable-termination-protection"
        ),
    ],
)
def test_detects_safety_control_bypass(
    raw_text: str,
) -> None:
    """Commands bypassing AWS safety controls should be errors."""
    assert "RBP-AWS-004" in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        (
            "aws rds delete-db-instance "
            "--db-instance-identifier production "
            "--final-db-snapshot-identifier production-final"
        ),
        (
            "aws secretsmanager delete-secret "
            "--secret-id database "
            "--recovery-window-in-days 30"
        ),
        (
            "aws cloudformation update-stack "
            "--stack-name production "
            "--template-body file://template.yaml"
        ),
    ],
)
def test_operations_preserving_safety_controls_pass(
    raw_text: str,
) -> None:
    """Normal safety controls should not trigger bypass findings."""
    assert "RBP-AWS-004" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        ("aws ec2 terminate-instances --instance-ids i-123"),
        ("aws ec2 stop-instances --instance-ids i-123"),
        ("aws ec2 start-instances --instance-ids i-123"),
        ("aws ec2 run-instances --image-id ami-123 --instance-type t3.micro"),
        (
            "aws ec2 authorize-security-group-ingress "
            "--group-id sg-123 "
            "--protocol tcp "
            "--port 443 "
            "--cidr 10.0.0.0/8"
        ),
        ("aws ec2 delete-security-group --group-id sg-123"),
    ],
)
def test_detects_missing_ec2_dry_run(
    raw_text: str,
) -> None:
    """Supported EC2 mutations should include dry-run checks."""
    result_findings = findings(raw_text)
    finding = next(item for item in result_findings if item.rule_id == "RBP-AWS-005")

    assert finding.severity is Severity.WARNING
    assert finding.repair is not None
    assert finding.repair.confidence is RepairConfidence.LOW
    assert not finding.repair.safe_to_apply
    assert "--dry-run" in finding.repair.replacement_text


@pytest.mark.parametrize(
    "raw_text",
    [
        ("aws ec2 terminate-instances --instance-ids i-123 --dry-run"),
        ("aws ec2 run-instances --image-id ami-123 --instance-type t3.micro --dry-run"),
        ("aws ec2 stop-instances --instance-ids i-123 --dry-run=true"),
    ],
)
def test_ec2_mutations_with_dry_run_pass(
    raw_text: str,
) -> None:
    """Enabled dry-run options should satisfy the preview rule."""
    assert "RBP-AWS-005" not in rule_ids(raw_text)


def test_explicitly_disabled_dry_run_still_warns() -> None:
    """An explicitly false dry-run option is not a preview."""
    assert "RBP-AWS-005" in rule_ids(
        "aws ec2 terminate-instances --instance-ids i-123 --dry-run=false"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        ("aws s3api put-bucket-acl --bucket application --acl public-read"),
        (
            "aws s3api put-object-acl "
            "--bucket application "
            "--key index.html "
            "--acl public-read-write"
        ),
        ("aws s3api create-bucket --bucket application --acl authenticated-read"),
        ("aws s3 cp index.html s3://application --acl public-read"),
        ("aws s3 sync . s3://application --acl public-read"),
        (
            "aws s3api put-bucket-acl "
            "--bucket application "
            "--grant-read "
            "uri=http://acs.amazonaws.com/groups/global/AllUsers"
        ),
        (
            "aws s3api put-bucket-acl "
            "--bucket application "
            "--grant-write "
            "uri=http://acs.amazonaws.com/groups/global/"
            "AuthenticatedUsers"
        ),
        ("aws s3api delete-public-access-block --bucket application"),
        ("aws s3control delete-public-access-block --account-id 123456789012"),
        (
            "aws s3api put-public-access-block "
            "--bucket application "
            "--public-access-block-configuration "
            "'BlockPublicAcls=false,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true'"
        ),
    ],
)
def test_detects_public_s3_access(
    raw_text: str,
) -> None:
    """Commands enabling public S3 access should be errors."""
    assert "RBP-AWS-006" in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        ("aws s3api put-bucket-acl --bucket application --acl private"),
        ("aws s3 cp index.html s3://application --acl bucket-owner-full-control"),
        (
            "aws s3api put-public-access-block "
            "--bucket application "
            "--public-access-block-configuration "
            "'BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true'"
        ),
    ],
)
def test_private_s3_configuration_passes(
    raw_text: str,
) -> None:
    """Private S3 access configuration should pass."""
    assert "RBP-AWS-006" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    ("raw_text", "expected_cidr"),
    [
        (
            "aws ec2 authorize-security-group-ingress "
            "--group-id sg-123 "
            "--protocol tcp "
            "--port 22 "
            "--cidr 0.0.0.0/0",
            "0.0.0.0/0",
        ),
        (
            "aws ec2 authorize-security-group-ingress "
            "--group-id sg-123 "
            "--ip-permissions "
            "'IpProtocol=tcp,FromPort=443,ToPort=443,"
            "Ipv6Ranges=[{CidrIpv6=::/0}]'",
            "::/0",
        ),
    ],
)
def test_detects_world_accessible_ingress(
    raw_text: str,
    expected_cidr: str,
) -> None:
    """World-accessible security groups should be errors."""
    result_findings = findings(raw_text)
    finding = next(item for item in result_findings if item.rule_id == "RBP-AWS-007")

    assert finding.severity is Severity.ERROR
    assert expected_cidr in finding.evidence[0].message


def test_private_security_group_ingress_passes() -> None:
    """Private CIDR ingress should not trigger public-access rules."""
    assert "RBP-AWS-007" not in rule_ids(
        "aws ec2 authorize-security-group-ingress "
        "--group-id sg-123 "
        "--protocol tcp "
        "--port 443 "
        "--cidr 10.0.0.0/8 "
        "--dry-run"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        (
            "aws iam attach-role-policy "
            "--role-name application "
            "--policy-arn "
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ),
        (
            "aws iam attach-user-policy "
            "--user-name operator "
            "--policy-arn "
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ),
        (
            "aws iam create-policy "
            "--policy-name admin "
            "--policy-document "
            '\'{"Statement":[{"Action":"*","Resource":"*"}]}\''
        ),
        (
            "aws iam put-role-policy "
            "--role-name application "
            "--policy-name broad "
            "--policy-document "
            '\'{"Statement":[{"Action":["*"],"Resource":["*"]}]}\''
        ),
        (
            "aws iam create-role "
            "--role-name public-role "
            "--assume-role-policy-document "
            '\'{"Statement":[{"Principal":"*"}]}\''
        ),
        (
            "aws iam update-assume-role-policy "
            "--role-name public-role "
            "--policy-document "
            '\'{"Statement":[{"Principal":{"AWS":"*"}}]}\''
        ),
    ],
)
def test_detects_broad_iam_permissions(
    raw_text: str,
) -> None:
    """Administrative permissions and wildcard trust should be errors."""
    assert "RBP-AWS-008" in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        (
            "aws iam attach-role-policy "
            "--role-name application "
            "--policy-arn "
            "arn:aws:iam::aws:policy/ReadOnlyAccess"
        ),
        (
            "aws iam create-policy "
            "--policy-name application "
            "--policy-document file://policy.json"
        ),
        (
            "aws iam create-role "
            "--role-name application "
            "--assume-role-policy-document file://trust.json"
        ),
        (
            "aws iam create-policy "
            "--policy-name application "
            "--policy-document "
            '\'{"Statement":[{"Action":"s3:GetObject",'
            '"Resource":"arn:aws:s3:::application/*"}]}\''
        ),
    ],
)
def test_scoped_iam_permissions_pass(
    raw_text: str,
) -> None:
    """Scoped and file-based IAM policies should pass this rule."""
    assert "RBP-AWS-008" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        ("aws secretsmanager get-secret-value --secret-id database"),
        "aws ecr get-login-password",
        "aws iam create-access-key --user-name deployment",
        (
            "aws rds generate-db-auth-token "
            "--hostname database.example.com "
            "--port 5432 "
            "--username application"
        ),
        ("aws ssm get-parameter --name database-password --with-decryption"),
        ("aws ssm get-parameters --names database-password --with-decryption"),
    ],
)
def test_detects_sensitive_output_operations(
    raw_text: str,
) -> None:
    """Commands returning credentials should require review."""
    result_findings = findings(raw_text)
    finding = next(item for item in result_findings if item.rule_id == "RBP-AWS-009")

    assert finding.severity is Severity.WARNING


@pytest.mark.parametrize(
    "raw_text",
    [
        "aws secretsmanager list-secrets",
        "aws iam list-access-keys --user-name deployment",
        "aws ssm get-parameter --name environment",
    ],
)
def test_nonsecret_output_operations_pass(
    raw_text: str,
) -> None:
    """Metadata-only operations should pass the secret-output rule."""
    assert "RBP-AWS-009" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    ("raw_text", "expected_value"),
    [
        (
            "aws --endpoint-url http://localhost:4566 s3api list-buckets",
            "http://localhost:4566",
        ),
        (
            "AWS_ENDPOINT_URL=http://localhost:4566 aws s3api list-buckets",
            "AWS_ENDPOINT_URL",
        ),
        (
            "AWS_ENDPOINT_URL_S3=http://localhost:4566 aws s3api list-buckets",
            "AWS_ENDPOINT_URL_S3",
        ),
        (
            "AWS_ENDPOINT_URL_STS=http://localhost:4566 aws sts get-caller-identity",
            "AWS_ENDPOINT_URL_STS",
        ),
    ],
)
def test_detects_unencrypted_custom_endpoint(
    raw_text: str,
    expected_value: str,
) -> None:
    """Custom AWS endpoints should use HTTPS."""
    result_findings = findings(raw_text)
    finding = next(item for item in result_findings if item.rule_id == "RBP-AWS-010")

    assert finding.severity is Severity.ERROR
    assert expected_value in finding.evidence[0].message


@pytest.mark.parametrize(
    "raw_text",
    [
        ("aws --endpoint-url https://localhost:4566 s3api list-buckets"),
        "aws s3api list-buckets",
    ],
)
def test_https_or_default_endpoint_passes(
    raw_text: str,
) -> None:
    """Default and HTTPS endpoints should pass."""
    assert "RBP-AWS-010" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "aws cloudtrail stop-logging --name organization-trail",
        "aws cloudtrail delete-trail --name organization-trail",
        (
            "aws configservice stop-configuration-recorder "
            "--configuration-recorder-name default"
        ),
        (
            "aws configservice delete-configuration-recorder "
            "--configuration-recorder-name default"
        ),
        "aws guardduty delete-detector --detector-id detector-123",
        "aws inspector2 disable --account-ids 123456789012",
        "aws macie2 disable-macie",
        "aws securityhub disable-security-hub",
    ],
)
def test_detects_disabled_security_monitoring(
    raw_text: str,
) -> None:
    """Disabling AWS security monitoring should be an error."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-AWS-011"
    assert result_findings[0].severity is Severity.ERROR


@pytest.mark.parametrize(
    "raw_text",
    [
        "aws cloudtrail describe-trails",
        "aws guardduty list-detectors",
        "aws securityhub describe-hub",
    ],
)
def test_read_only_monitoring_operations_pass(
    raw_text: str,
) -> None:
    """Read-only security service operations should pass."""
    assert "RBP-AWS-011" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        (
            "aws rds create-db-instance "
            "--db-instance-identifier database "
            "--engine postgres "
            "--publicly-accessible"
        ),
        (
            "aws rds modify-db-instance "
            "--db-instance-identifier database "
            "--publicly-accessible"
        ),
        (
            "aws redshift create-cluster "
            "--cluster-identifier analytics "
            "--node-type ra3.xlplus "
            "--publicly-accessible"
        ),
        (
            "aws redshift modify-cluster "
            "--cluster-identifier analytics "
            "--publicly-accessible=true"
        ),
    ],
)
def test_detects_public_database_resources(
    raw_text: str,
) -> None:
    """Public database resources should require review."""
    result_findings = findings(raw_text)
    finding = next(item for item in result_findings if item.rule_id == "RBP-AWS-012")

    assert finding.severity is Severity.WARNING


@pytest.mark.parametrize(
    "raw_text",
    [
        (
            "aws rds create-db-instance "
            "--db-instance-identifier database "
            "--engine postgres "
            "--no-publicly-accessible"
        ),
        (
            "aws rds modify-db-instance "
            "--db-instance-identifier database "
            "--publicly-accessible=false"
        ),
    ],
)
def test_private_database_resources_pass(
    raw_text: str,
) -> None:
    """Private database resources should pass this rule."""
    assert "RBP-AWS-012" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "aws --no-sign-request s3api list-buckets",
        "aws s3 cp s3://public-bucket/file.txt . --no-sign-request",
    ],
)
def test_detects_unsigned_aws_requests(
    raw_text: str,
) -> None:
    """Unsigned AWS requests should require review."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-AWS-013"
    assert result_findings[0].severity is Severity.WARNING


def test_normal_signed_request_passes() -> None:
    """Normal signed requests should not trigger."""
    assert "RBP-AWS-013" not in rule_ids("aws s3api list-buckets")


def test_global_options_before_service_are_supported() -> None:
    """Global options should not hide the AWS operation."""
    result_ids = rule_ids(
        "aws "
        "--profile production "
        "--region eu-west-1 "
        "ec2 terminate-instances "
        "--instance-ids i-123"
    )

    assert result_ids == (
        "RBP-AWS-003",
        "RBP-AWS-005",
    )


def test_global_options_between_service_and_operation_are_supported() -> None:
    """Global options between command components should be accepted."""
    assert AwsCliPack().supports(
        make_result("aws ec2 --region eu-west-1 describe-instances")
    )


def test_multiple_findings_have_deterministic_order() -> None:
    """Findings should follow the pack's published rule order."""
    result_ids = rule_ids(
        "AWS_SECRET_ACCESS_KEY=super-secret "
        "aws "
        "--no-verify-ssl "
        "--endpoint-url http://localhost:4566 "
        "--no-sign-request "
        "ec2 terminate-instances "
        "--instance-ids i-123 "
        "--force"
    )

    assert result_ids == (
        "RBP-AWS-001",
        "RBP-AWS-002",
        "RBP-AWS-003",
        "RBP-AWS-004",
        "RBP-AWS-005",
        "RBP-AWS-010",
        "RBP-AWS-013",
    )


def test_aws_cli_pack_integrates_with_engine() -> None:
    """The verification engine should run the pack end to end."""
    report = VerificationEngine(
        packs=(AwsCliPack(),),
    ).analyze_markdown(
        ("```bash\naws cloudformation delete-stack --stack-name production\n```\n"),
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.error_count == 1
    assert report.warning_count == 0
    assert report.pack_names == ("aws-cli",)
    assert report.findings[0].rule_id == "RBP-AWS-003"

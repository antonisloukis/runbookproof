"""Static verification for AWS CLI commands."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from runbookproof.models import (
    Evidence,
    EvidenceKind,
    Finding,
    RepairConfidence,
    RepairSuggestion,
    Severity,
    ShellParseResult,
)

_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--ca-bundle",
        "--cli-binary-format",
        "--cli-connect-timeout",
        "--cli-error-format",
        "--cli-read-timeout",
        "--color",
        "--endpoint-url",
        "--output",
        "--profile",
        "--query",
        "--region",
    }
)

_DESTRUCTIVE_OPERATIONS = frozenset(
    {
        ("accessanalyzer", "delete-analyzer"),
        ("acm", "delete-certificate"),
        ("autoscaling", "delete-auto-scaling-group"),
        ("cloudformation", "delete-stack"),
        ("cloudfront", "delete-distribution"),
        ("cloudwatch", "delete-alarms"),
        ("dynamodb", "delete-table"),
        ("ec2", "delete-key-pair"),
        ("ec2", "delete-network-interface"),
        ("ec2", "delete-security-group"),
        ("ec2", "delete-snapshot"),
        ("ec2", "delete-subnet"),
        ("ec2", "delete-volume"),
        ("ec2", "delete-vpc"),
        ("ec2", "deregister-image"),
        ("ec2", "terminate-instances"),
        ("ecr", "delete-repository"),
        ("ecs", "delete-cluster"),
        ("ecs", "delete-service"),
        ("eks", "delete-cluster"),
        ("elasticache", "delete-cache-cluster"),
        ("iam", "delete-access-key"),
        ("iam", "delete-group"),
        ("iam", "delete-policy"),
        ("iam", "delete-role"),
        ("iam", "delete-user"),
        ("kms", "schedule-key-deletion"),
        ("lambda", "delete-function"),
        ("logs", "delete-log-group"),
        ("rds", "delete-db-cluster"),
        ("rds", "delete-db-cluster-snapshot"),
        ("rds", "delete-db-instance"),
        ("rds", "delete-db-snapshot"),
        ("redshift", "delete-cluster"),
        ("route53", "delete-hosted-zone"),
        ("s3api", "delete-bucket"),
        ("s3api", "delete-object"),
        ("s3api", "delete-objects"),
        ("secretsmanager", "delete-secret"),
        ("sns", "delete-topic"),
        ("sqs", "delete-queue"),
        ("ssm", "delete-parameter"),
        ("ssm", "delete-parameters"),
    }
)

_DRY_RUN_OPERATIONS = frozenset(
    {
        ("ec2", "authorize-security-group-egress"),
        ("ec2", "authorize-security-group-ingress"),
        ("ec2", "create-security-group"),
        ("ec2", "delete-network-interface"),
        ("ec2", "delete-security-group"),
        ("ec2", "delete-snapshot"),
        ("ec2", "delete-subnet"),
        ("ec2", "delete-volume"),
        ("ec2", "delete-vpc"),
        ("ec2", "deregister-image"),
        ("ec2", "modify-instance-attribute"),
        ("ec2", "reboot-instances"),
        ("ec2", "revoke-security-group-egress"),
        ("ec2", "revoke-security-group-ingress"),
        ("ec2", "run-instances"),
        ("ec2", "start-instances"),
        ("ec2", "stop-instances"),
        ("ec2", "terminate-instances"),
    }
)

_SECURITY_MONITORING_OPERATIONS = frozenset(
    {
        ("cloudtrail", "delete-trail"),
        ("cloudtrail", "stop-logging"),
        ("configservice", "delete-configuration-recorder"),
        ("configservice", "stop-configuration-recorder"),
        ("guardduty", "delete-detector"),
        ("inspector2", "disable"),
        ("macie2", "disable-macie"),
        ("securityhub", "disable-security-hub"),
    }
)

_SECRET_OUTPUT_OPERATIONS = frozenset(
    {
        ("ecr", "get-login-password"),
        ("iam", "create-access-key"),
        ("rds", "generate-db-auth-token"),
        ("secretsmanager", "get-secret-value"),
    }
)

_IAM_POLICY_OPERATIONS = frozenset(
    {
        "create-policy",
        "create-policy-version",
        "put-group-policy",
        "put-role-policy",
        "put-user-policy",
    }
)

_IAM_ATTACH_OPERATIONS = frozenset(
    {
        "attach-group-policy",
        "attach-role-policy",
        "attach-user-policy",
    }
)

_PUBLIC_ACLS = frozenset(
    {
        "authenticated-read",
        "public-read",
        "public-read-write",
    }
)

_LITERAL_SECRET_OPTIONS = (
    "--auth-token",
    "--master-user-password",
    "--new-password",
    "--password",
    "--secret-access-key",
    "--secret-binary",
    "--secret-string",
    "--session-token",
    "--token",
)

_AWS_CREDENTIAL_VARIABLES = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SECURITY_TOKEN",
        "AWS_SESSION_TOKEN",
    }
)

_SECRET_NAME_PATTERN = re.compile(
    r"(?:^|_)"
    r"(?:"
    r"ACCESS_KEY|"
    r"API_KEY|"
    r"AUTH_TOKEN|"
    r"CLIENT_SECRET|"
    r"PASSWORD|"
    r"PASSWD|"
    r"PRIVATE_KEY|"
    r"SECRET|"
    r"SESSION_TOKEN|"
    r"TOKEN"
    r")"
    r"(?:$|_)",
    flags=re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _Invocation:
    """Describe one normalized AWS CLI invocation."""

    service: str
    operation: str
    arguments: tuple[str, ...]
    all_arguments: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Risk:
    """Describe one detected AWS CLI risk."""

    severity: Severity
    evidence: str


class AwsCliPack:
    """Detect dangerous and non-reviewable AWS CLI commands."""

    name = "aws-cli"

    def supports(self, result: ShellParseResult) -> bool:
        """Support successfully parsed AWS CLI service operations."""
        return (
            result.error is None
            and result.command.executable == "aws"
            and _parse_invocation(result) is not None
        )

    def verify(
        self,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Return deterministic findings for one AWS CLI command."""
        if result.error is not None:
            return ()

        invocation = _parse_invocation(result)

        if invocation is None or _is_informational(invocation):
            return ()

        findings: list[Finding] = []

        if _has_option(
            invocation.all_arguments,
            option="--no-verify-ssl",
        ):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-001",
                    severity=Severity.ERROR,
                    message="AWS CLI TLS certificate verification is disabled",
                    evidence="Detected the global `--no-verify-ssl` option.",
                )
            )

        credential_problem = _literal_credential_problem(
            result,
            invocation,
        )

        if credential_problem is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-002",
                    severity=Severity.ERROR,
                    message="AWS CLI command contains a literal credential",
                    evidence=credential_problem,
                )
            )

        destructive_risk = _destructive_risk(invocation)

        if destructive_risk is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-003",
                    severity=destructive_risk.severity,
                    message="AWS CLI command deletes or destroys resources",
                    evidence=destructive_risk.evidence,
                )
            )

        safety_bypass = _safety_bypass(invocation)

        if safety_bypass is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-004",
                    severity=Severity.ERROR,
                    message="AWS resource safety controls are bypassed",
                    evidence=safety_bypass,
                )
            )

        if _missing_dry_run(invocation):
            replacement = shlex.join((*result.tokens, "--dry-run"))
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-005",
                    severity=Severity.WARNING,
                    message="AWS EC2 mutation has no dry-run permission check",
                    evidence=(
                        "Detected an EC2 operation that supports `--dry-run` "
                        "without that option."
                    ),
                    repair=RepairSuggestion(
                        replacement_text=replacement,
                        rationale=(
                            "AWS EC2 dry-run checks whether the operation is "
                            "authorized without performing the request."
                        ),
                        confidence=RepairConfidence.LOW,
                    ),
                )
            )

        public_s3_problem = _public_s3_problem(invocation)

        if public_s3_problem is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-006",
                    severity=Severity.ERROR,
                    message="AWS CLI command enables public S3 access",
                    evidence=public_s3_problem,
                )
            )

        public_ingress = _public_ingress_problem(invocation)

        if public_ingress is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-007",
                    severity=Severity.ERROR,
                    message=("EC2 security-group ingress is open to the internet"),
                    evidence=public_ingress,
                )
            )

        iam_problem = _iam_policy_problem(invocation)

        if iam_problem is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-008",
                    severity=Severity.ERROR,
                    message="AWS IAM command grants broad administrative access",
                    evidence=iam_problem,
                )
            )

        secret_exposure = _secret_output_problem(invocation)

        if secret_exposure is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-009",
                    severity=Severity.WARNING,
                    message=("AWS CLI command returns sensitive credential material"),
                    evidence=secret_exposure,
                )
            )

        insecure_endpoint = _insecure_endpoint_problem(
            result,
            invocation,
        )

        if insecure_endpoint is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-010",
                    severity=Severity.ERROR,
                    message="AWS CLI command uses an unencrypted HTTP endpoint",
                    evidence=insecure_endpoint,
                )
            )

        monitoring_problem = _monitoring_problem(invocation)

        if monitoring_problem is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-011",
                    severity=Severity.ERROR,
                    message="AWS security monitoring is disabled or deleted",
                    evidence=monitoring_problem,
                )
            )

        public_resource = _public_resource_problem(invocation)

        if public_resource is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-012",
                    severity=Severity.WARNING,
                    message="AWS database resource is configured as public",
                    evidence=public_resource,
                )
            )

        unsigned_request = _unsigned_request_problem(invocation)

        if unsigned_request is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-AWS-013",
                    severity=Severity.WARNING,
                    message="AWS CLI request is sent without request signing",
                    evidence=unsigned_request,
                )
            )

        return tuple(findings)


def _finding(
    result: ShellParseResult,
    *,
    rule_id: str,
    severity: Severity,
    message: str,
    evidence: str,
    repair: RepairSuggestion | None = None,
) -> Finding:
    """Create one deterministic AWS CLI finding."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=evidence,
                source="RunbookProof AWS CLI pack",
            ),
        ),
        repair=repair,
    )


def _parse_invocation(
    result: ShellParseResult,
) -> _Invocation | None:
    """Normalize one AWS CLI service operation."""
    if result.command.executable != "aws":
        return None

    arguments = result.command.arguments
    service, remaining = _split_component(
        arguments,
        options_with_values=_GLOBAL_OPTIONS_WITH_VALUES,
    )

    if service is None:
        return None

    operation, operation_arguments = _split_component(
        remaining,
        options_with_values=_GLOBAL_OPTIONS_WITH_VALUES,
    )

    if operation is None:
        return None

    return _Invocation(
        service=service.lower(),
        operation=operation.lower(),
        arguments=operation_arguments,
        all_arguments=arguments,
    )


def _split_component(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> tuple[str | None, tuple[str, ...]]:
    """Separate leading options from an AWS command component."""
    index = 0

    while index < len(arguments):
        argument = arguments[index]

        if argument == "--":
            index += 1
            break

        if not argument.startswith("-"):
            return argument, arguments[index + 1 :]

        option = argument.split("=", maxsplit=1)[0]

        if option in options_with_values and "=" not in argument:
            index += 2
        else:
            index += 1

    if index < len(arguments):
        return arguments[index], arguments[index + 1 :]

    return None, ()


def _is_informational(invocation: _Invocation) -> bool:
    """Return whether the invocation does not perform an API operation."""
    if invocation.service in {
        "help",
        "version",
    }:
        return True

    if invocation.operation in {
        "help",
        "version",
    }:
        return True

    if any(
        argument
        in {
            "-h",
            "--help",
            "--version",
        }
        for argument in invocation.all_arguments
    ):
        return True

    return _has_option(
        invocation.all_arguments,
        option="--generate-cli-skeleton",
    )


def _literal_credential_problem(
    result: ShellParseResult,
    invocation: _Invocation,
) -> str | None:
    """Return evidence for literal AWS credential material."""
    for assignment in result.assignments:
        if "=" not in assignment:
            continue

        name, value = assignment.split("=", maxsplit=1)

        if name in _AWS_CREDENTIAL_VARIABLES and _is_literal_secret(value):
            return f"Detected literal AWS credential environment variable `{name}`."

    for option in _LITERAL_SECRET_OPTIONS:
        for value in _option_values(
            invocation.all_arguments,
            options=(option,),
        ):
            if _is_literal_secret(value):
                return f"Detected a literal value passed through `{option}`."

    if (
        invocation.service == "ssm"
        and invocation.operation == "put-parameter"
        and _option_value_equals(
            invocation.all_arguments,
            option="--type",
            expected="SecureString",
        )
    ):
        parameter_value = _first_option_value(
            invocation.all_arguments,
            options=("--value",),
        )

        if parameter_value is not None and _is_literal_secret(parameter_value):
            return "Detected a literal SecureString value passed through `--value`."

    return None


def _destructive_risk(
    invocation: _Invocation,
) -> _Risk | None:
    """Return risk details for destructive AWS operations."""
    operation = (
        invocation.service,
        invocation.operation,
    )

    if operation in _DESTRUCTIVE_OPERATIONS:
        severity = (
            Severity.WARNING
            if operation == ("s3api", "delete-object")
            else Severity.ERROR
        )
        return _Risk(
            severity=severity,
            evidence=(
                "Detected destructive AWS operation "
                f"`aws {invocation.service} {invocation.operation}`."
            ),
        )

    if invocation.service == "s3" and invocation.operation == "rm":
        recursive = _has_option(
            invocation.all_arguments,
            option="--recursive",
        )
        return _Risk(
            severity=(Severity.ERROR if recursive else Severity.WARNING),
            evidence=(
                "Detected recursive S3 deletion."
                if recursive
                else "Detected deletion of an S3 object."
            ),
        )

    if invocation.service == "s3" and invocation.operation == "rb":
        forced = _has_option(
            invocation.all_arguments,
            option="--force",
        )
        return _Risk(
            severity=(Severity.ERROR if forced else Severity.WARNING),
            evidence=(
                "Detected forced S3 bucket removal."
                if forced
                else "Detected S3 bucket removal."
            ),
        )

    return None


def _safety_bypass(invocation: _Invocation) -> str | None:
    """Return evidence for bypassed deletion or recovery controls."""
    operation = (
        invocation.service,
        invocation.operation,
    )

    if operation == ("ec2", "terminate-instances") and _has_option(
        invocation.all_arguments,
        option="--force",
    ):
        return "Detected forced EC2 instance termination."

    if operation == ("ec2", "terminate-instances") and _has_option(
        invocation.all_arguments,
        option="--skip-os-shutdown",
    ):
        return "Detected EC2 termination that skips operating-system shutdown."

    if operation in {
        ("rds", "delete-db-cluster"),
        ("rds", "delete-db-instance"),
        ("redshift", "delete-cluster"),
    } and _has_option(
        invocation.all_arguments,
        option="--skip-final-snapshot",
    ):
        return "Detected database deletion without a final snapshot."

    if operation == ("secretsmanager", "delete-secret") and _has_option(
        invocation.all_arguments,
        option="--force-delete-without-recovery",
    ):
        return "Detected immediate secret deletion without a recovery window."

    if (
        invocation.service == "s3api"
        and invocation.operation
        in {
            "delete-object",
            "delete-objects",
        }
        and _has_option(
            invocation.all_arguments,
            option="--bypass-governance-retention",
        )
    ):
        return "Detected bypass of S3 Object Lock governance retention."

    if operation == ("ecr", "delete-repository") and _has_option(
        invocation.all_arguments,
        option="--force",
    ):
        return "Detected forced deletion of a non-empty ECR repository."

    if (
        invocation.service == "cloudformation"
        and invocation.operation
        in {
            "create-stack",
            "update-stack",
        }
        and _has_option(
            invocation.all_arguments,
            option="--disable-rollback",
        )
    ):
        return "Detected disabled CloudFormation rollback protection."

    if (
        invocation.service == "rds"
        and invocation.operation
        in {
            "modify-db-cluster",
            "modify-db-instance",
        }
        and _has_option(
            invocation.all_arguments,
            option="--no-deletion-protection",
        )
    ):
        return "Detected disabled RDS deletion protection."

    if operation == ("ec2", "modify-instance-attribute") and _has_option(
        invocation.all_arguments,
        option="--no-disable-api-termination",
    ):
        return "Detected disabled EC2 termination protection."

    if operation == (
        "cloudformation",
        "update-termination-protection",
    ) and _has_option(
        invocation.all_arguments,
        option="--no-enable-termination-protection",
    ):
        return "Detected disabled CloudFormation termination protection."

    return None


def _missing_dry_run(invocation: _Invocation) -> bool:
    """Return whether a supported EC2 mutation lacks dry-run."""
    operation = (
        invocation.service,
        invocation.operation,
    )

    if operation not in _DRY_RUN_OPERATIONS:
        return False

    return not _flag_enabled(
        invocation.all_arguments,
        option="--dry-run",
    )


def _public_s3_problem(
    invocation: _Invocation,
) -> str | None:
    """Return evidence for public S3 access changes."""
    if invocation.service == "s3api" and invocation.operation in {
        "create-bucket",
        "put-bucket-acl",
        "put-object-acl",
    }:
        acl = _first_option_value(
            invocation.all_arguments,
            options=("--acl",),
        )

        if acl is not None and acl.lower() in _PUBLIC_ACLS:
            return f"Detected public S3 canned ACL `{acl}`."

        for option in (
            "--grant-full-control",
            "--grant-read",
            "--grant-read-acp",
            "--grant-write",
            "--grant-write-acp",
        ):
            values = _option_values(
                invocation.all_arguments,
                options=(option,),
            )

            if any(_contains_public_grantee(value) for value in values):
                return f"Detected a public S3 grantee through `{option}`."

    if invocation.service == "s3" and invocation.operation in {"cp", "sync"}:
        acl = _first_option_value(
            invocation.all_arguments,
            options=("--acl",),
        )

        if acl is not None and acl.lower() in _PUBLIC_ACLS:
            return f"Detected public S3 canned ACL `{acl}`."

    if (
        invocation.service
        in {
            "s3api",
            "s3control",
        }
        and invocation.operation == "delete-public-access-block"
    ):
        return "Detected deletion of an S3 public-access block."

    if (
        invocation.service
        in {
            "s3api",
            "s3control",
        }
        and invocation.operation == "put-public-access-block"
    ):
        configuration = _first_option_value(
            invocation.all_arguments,
            options=("--public-access-block-configuration",),
        )

        if configuration is not None and _disables_public_access_block(configuration):
            return "Detected disabled S3 public-access-block controls."

    return None


def _contains_public_grantee(value: str) -> bool:
    """Return whether an S3 grant targets a broad public group."""
    normalized = value.lower()

    return "allusers" in normalized or "authenticatedusers" in normalized


def _disables_public_access_block(value: str) -> bool:
    """Return whether S3 public-access protection is disabled."""
    normalized = re.sub(
        r"\s+",
        "",
        value.lower(),
    )

    controls = (
        "blockpublicacls",
        "ignorepublicacls",
        "blockpublicpolicy",
        "restrictpublicbuckets",
    )

    return any(
        f'"{control}":false' in normalized or f"{control}=false" in normalized
        for control in controls
    )


def _public_ingress_problem(
    invocation: _Invocation,
) -> str | None:
    """Return evidence for world-accessible security-group ingress."""
    if (
        invocation.service != "ec2"
        or invocation.operation != "authorize-security-group-ingress"
    ):
        return None

    joined = " ".join(invocation.arguments).lower()

    if "0.0.0.0/0" in joined:
        return "Detected IPv4 ingress from `0.0.0.0/0`."

    if "::/0" in joined:
        return "Detected IPv6 ingress from `::/0`."

    return None


def _iam_policy_problem(
    invocation: _Invocation,
) -> str | None:
    """Return evidence for broad IAM permissions or trust."""
    if invocation.service == "iam" and invocation.operation in _IAM_ATTACH_OPERATIONS:
        policy_arn = _first_option_value(
            invocation.all_arguments,
            options=("--policy-arn",),
        )

        if policy_arn is not None and policy_arn.endswith(
            ":policy/AdministratorAccess"
        ):
            return "Detected attachment of the AdministratorAccess policy."

    if invocation.service == "iam" and invocation.operation in _IAM_POLICY_OPERATIONS:
        policy_document = _first_option_value(
            invocation.all_arguments,
            options=("--policy-document",),
        )

        if policy_document is not None and _contains_policy_wildcard(policy_document):
            return "Detected wildcard action or resource in an IAM policy."

    if invocation.service == "iam" and invocation.operation in {
        "create-role",
        "update-assume-role-policy",
    }:
        trust_options = (
            ("--policy-document",)
            if invocation.operation == "update-assume-role-policy"
            else ("--assume-role-policy-document",)
        )
        trust_document = _first_option_value(
            invocation.all_arguments,
            options=trust_options,
        )

        if trust_document is not None and _contains_public_principal(trust_document):
            return "Detected a wildcard principal in an IAM trust policy."

    return None


def _contains_policy_wildcard(value: str) -> bool:
    """Return whether inline IAM JSON grants wildcard authority."""
    if value.startswith(
        (
            "file://",
            "fileb://",
        )
    ):
        return False

    normalized = re.sub(
        r"\s+",
        "",
        value.lower(),
    )

    return any(
        pattern in normalized
        for pattern in (
            '"action":"*"',
            '"action":["*"]',
            '"resource":"*"',
            '"resource":["*"]',
            "action=*",
            "resource=*",
        )
    )


def _contains_public_principal(value: str) -> bool:
    """Return whether inline trust JSON grants a wildcard principal."""
    if value.startswith(
        (
            "file://",
            "fileb://",
        )
    ):
        return False

    normalized = re.sub(
        r"\s+",
        "",
        value.lower(),
    )

    return any(
        pattern in normalized
        for pattern in (
            '"principal":"*"',
            '"aws":"*"',
            "principal=*",
        )
    )


def _secret_output_problem(
    invocation: _Invocation,
) -> str | None:
    """Return evidence for commands that print secret material."""
    operation = (
        invocation.service,
        invocation.operation,
    )

    if operation in _SECRET_OUTPUT_OPERATIONS:
        return (
            "Detected credential-returning operation "
            f"`aws {invocation.service} {invocation.operation}`."
        )

    if (
        invocation.service == "ssm"
        and invocation.operation
        in {
            "get-parameter",
            "get-parameters",
            "get-parameters-by-path",
        }
        and _has_option(
            invocation.all_arguments,
            option="--with-decryption",
        )
    ):
        return "Detected decrypted Systems Manager parameter output."

    return None


def _insecure_endpoint_problem(
    result: ShellParseResult,
    invocation: _Invocation,
) -> str | None:
    """Return evidence for unencrypted custom AWS endpoints."""
    endpoint = _first_option_value(
        invocation.all_arguments,
        options=("--endpoint-url",),
    )

    if endpoint is not None and endpoint.lower().startswith("http://"):
        return f"Detected unencrypted endpoint URL `{endpoint}`."

    for assignment in result.assignments:
        if "=" not in assignment:
            continue

        name, value = assignment.split("=", maxsplit=1)

        if name in {
            "AWS_ENDPOINT_URL",
            "AWS_ENDPOINT_URL_S3",
            "AWS_ENDPOINT_URL_STS",
        } and value.lower().startswith("http://"):
            return f"Detected unencrypted AWS endpoint environment variable `{name}`."

    return None


def _monitoring_problem(
    invocation: _Invocation,
) -> str | None:
    """Return evidence for disabling AWS security monitoring."""
    operation = (
        invocation.service,
        invocation.operation,
    )

    if operation not in _SECURITY_MONITORING_OPERATIONS:
        return None

    return (
        "Detected security-monitoring operation "
        f"`aws {invocation.service} {invocation.operation}`."
    )


def _public_resource_problem(
    invocation: _Invocation,
) -> str | None:
    """Return evidence for publicly accessible database resources."""
    public_operations = {
        ("rds", "create-db-instance"),
        ("rds", "modify-db-instance"),
        ("redshift", "create-cluster"),
        ("redshift", "modify-cluster"),
    }

    operation = (
        invocation.service,
        invocation.operation,
    )

    if operation not in public_operations:
        return None

    if not _flag_enabled(
        invocation.all_arguments,
        option="--publicly-accessible",
    ):
        return None

    return (
        "Detected enabled `--publicly-accessible` on "
        f"`aws {invocation.service} {invocation.operation}`."
    )


def _unsigned_request_problem(
    invocation: _Invocation,
) -> str | None:
    """Return evidence for unsigned AWS service requests."""
    if not _has_option(
        invocation.all_arguments,
        option="--no-sign-request",
    ):
        return None

    return "Detected the global `--no-sign-request` option."


def _is_literal_secret(value: str) -> bool:
    """Return whether a value appears to contain literal secret data."""
    normalized = value.strip()

    if not normalized:
        return False

    if normalized.startswith(
        (
            "$",
            "${",
            "$(",
            "arn:",
            "se://",
            "vault://",
        )
    ):
        return False

    if normalized.startswith(
        (
            "file://",
            "fileb://",
        )
    ):
        return False

    if normalized.startswith("<") and normalized.endswith(">"):
        return False

    return normalized.lower() not in {
        "changeme",
        "example",
        "placeholder",
        "your-secret-here",
    }


def _option_value_equals(
    arguments: tuple[str, ...],
    *,
    option: str,
    expected: str,
) -> bool:
    """Return whether an option has the expected value."""
    values = _option_values(
        arguments,
        options=(option,),
    )

    return any(value.lower() == expected.lower() for value in values)


def _first_option_value(
    arguments: tuple[str, ...],
    *,
    options: tuple[str, ...],
) -> str | None:
    """Return the first value assigned to selected options."""
    values = _option_values(
        arguments,
        options=options,
    )

    if values:
        return values[0]

    return None


def _option_values(
    arguments: tuple[str, ...],
    *,
    options: tuple[str, ...],
) -> tuple[str, ...]:
    """Return values assigned to selected AWS CLI options."""
    values: list[str] = []
    index = 0

    while index < len(arguments):
        argument = arguments[index]
        matched = False

        for option in options:
            if argument == option:
                next_index = index + 1

                if next_index < len(arguments):
                    values.append(arguments[next_index])

                index += 2
                matched = True
                break

            prefix = f"{option}="

            if argument.startswith(prefix):
                values.append(argument[len(prefix) :])
                index += 1
                matched = True
                break

        if not matched:
            index += 1

    return tuple(values)


def _flag_enabled(
    arguments: tuple[str, ...],
    *,
    option: str,
) -> bool:
    """Return whether one AWS CLI Boolean option is enabled."""
    enabled = False
    negative = f"--no-{option.removeprefix('--')}"

    for argument in arguments:
        if argument == negative:
            enabled = False
            continue

        if argument == option:
            enabled = True
            continue

        if argument.startswith(f"{option}="):
            value = argument.split("=", maxsplit=1)[1].lower()
            enabled = value not in {
                "0",
                "false",
                "no",
            }

    return enabled


def _has_option(
    arguments: tuple[str, ...],
    *,
    option: str,
) -> bool:
    """Return whether arguments contain one AWS CLI option."""
    return any(
        argument == option or argument.startswith(f"{option}=")
        for argument in arguments
    )

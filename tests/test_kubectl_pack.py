"""Tests for kubectl command verification."""

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
from runbookproof.packs import KubectlPack
from runbookproof.parsers import parse_shell_command

DIGEST = f"sha256:{'a' * 64}"
PINNED_IMAGE = f"nginx@{DIGEST}"


def make_result(raw_text: str) -> ShellParseResult:
    """Parse one command for kubectl-pack tests."""
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
    """Return findings generated for one kubectl command."""
    return KubectlPack().verify(make_result(raw_text))


def rule_ids(raw_text: str) -> tuple[str, ...]:
    """Return rule identifiers generated for one command."""
    return tuple(finding.rule_id for finding in findings(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        "kubectl get pods",
        "kubectl apply -f deployment.yaml",
        "kubectl delete pod application",
        "kubectl create deployment application --image nginx",
        "kubectl set image deployment/application web=nginx",
        "kubectl rollout restart deployment/application",
        "kubectl config current-context",
    ],
)
def test_supports_kubectl_commands(raw_text: str) -> None:
    """The pack should support valid kubectl commands."""
    assert KubectlPack().supports(make_result(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        "git status",
        "docker run alpine",
        "helm list",
        "terraform validate",
        "kubectl",
    ],
)
def test_ignores_unrelated_or_incomplete_commands(
    raw_text: str,
) -> None:
    """Unsupported or incomplete commands should not be claimed."""
    assert not KubectlPack().supports(make_result(raw_text))


def test_malformed_command_is_not_supported() -> None:
    """Malformed commands should remain a universal-pack concern."""
    result = make_result('kubectl apply -f "unfinished')

    assert not KubectlPack().supports(result)
    assert KubectlPack().verify(result) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "kubectl help",
        "kubectl options",
        "kubectl version",
        "kubectl get --help",
        "kubectl apply --help",
        "kubectl create deployment --help",
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
        "kubectl --insecure-skip-tls-verify get pods",
        "kubectl --insecure-skip-tls-verify=true get pods",
        ("kubectl get pods --insecure-skip-tls-verify=true"),
    ],
)
def test_detects_disabled_tls_verification(
    raw_text: str,
) -> None:
    """Kubernetes API certificate verification must remain enabled."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-KUBECTL-001"
    assert result_findings[0].severity is Severity.ERROR


def test_explicitly_enabled_tls_verification_passes() -> None:
    """An explicitly false insecure option should not trigger."""
    assert "RBP-KUBECTL-001" not in rule_ids(
        "kubectl --insecure-skip-tls-verify=false get pods"
    )


@pytest.mark.parametrize(
    ("raw_text", "option"),
    [
        (
            "kubectl --token super-secret get pods",
            "--token",
        ),
        (
            "kubectl --token=super-secret get pods",
            "--token",
        ),
        (
            "kubectl --password super-secret get pods",
            "--password",
        ),
        (
            "kubectl --password=super-secret get pods",
            "--password",
        ),
    ],
)
def test_detects_literal_cluster_credentials(
    raw_text: str,
    option: str,
) -> None:
    """Tokens and passwords should not appear literally."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-KUBECTL-002"
    assert result_findings[0].severity is Severity.ERROR
    assert option in result_findings[0].evidence[0].message


@pytest.mark.parametrize(
    "value",
    [
        "$KUBE_TOKEN",
        "${KUBE_TOKEN}",
        "$(get-token)",
        "se://production/kube-token",
        "<kube-token>",
        "changeme",
        "placeholder",
    ],
)
def test_credential_references_and_placeholders_pass(
    value: str,
) -> None:
    """References and placeholders should not count as literals."""
    assert "RBP-KUBECTL-002" not in rule_ids(f"kubectl --token '{value}' get pods")


@pytest.mark.parametrize(
    "raw_text",
    [
        "kubectl delete pods --all-namespaces",
        "kubectl delete pods -A",
        "kubectl label pods -A environment=production",
        "kubectl scale deployment -A --replicas 0",
    ],
)
def test_detects_mutations_across_all_namespaces(
    raw_text: str,
) -> None:
    """Cluster-wide mutations should require explicit review."""
    assert "RBP-KUBECTL-003" in rule_ids(raw_text)


def test_read_only_all_namespaces_command_passes() -> None:
    """Read-only listing across namespaces should not trigger."""
    assert "RBP-KUBECTL-003" not in rule_ids("kubectl get pods --all-namespaces")


@pytest.mark.parametrize(
    ("raw_text", "severity"),
    [
        (
            "kubectl delete pod application",
            Severity.WARNING,
        ),
        (
            "kubectl delete deployment application",
            Severity.WARNING,
        ),
        (
            "kubectl delete namespace production",
            Severity.ERROR,
        ),
        (
            "kubectl delete secret database-password",
            Severity.ERROR,
        ),
        (
            "kubectl delete node worker-01",
            Severity.ERROR,
        ),
        (
            "kubectl delete persistentvolume data-volume",
            Severity.ERROR,
        ),
        (
            "kubectl delete -f deployment.yaml",
            Severity.WARNING,
        ),
    ],
)
def test_detects_resource_deletion(
    raw_text: str,
    severity: Severity,
) -> None:
    """Resource deletion should be reported with risk severity."""
    result_findings = findings(raw_text)
    deletion = next(
        finding for finding in result_findings if finding.rule_id == "RBP-KUBECTL-004"
    )

    assert deletion.severity is severity


@pytest.mark.parametrize(
    "raw_text",
    [
        "kubectl delete pod application --force",
        "kubectl delete pod application --force=true",
        "kubectl delete pod application --now",
        "kubectl delete pod application --grace-period 0",
        "kubectl replace --force -f deployment.yaml",
    ],
)
def test_detects_forced_or_immediate_mutations(
    raw_text: str,
) -> None:
    """Forced replacement and deletion bypass safety controls."""
    assert "RBP-KUBECTL-005" in rule_ids(raw_text)


def test_normal_delete_has_no_force_finding() -> None:
    """Ordinary graceful deletion should not trigger force detection."""
    assert "RBP-KUBECTL-005" not in rule_ids("kubectl delete pod application")


@pytest.mark.parametrize(
    "raw_text",
    [
        "kubectl delete pods --all",
        "kubectl delete all --all",
        "kubectl label pods --all environment=production",
        "kubectl annotate all owner=platform",
    ],
)
def test_detects_mutations_selecting_all_resources(
    raw_text: str,
) -> None:
    """Broad mutation selectors should be treated as errors."""
    assert "RBP-KUBECTL-006" in rule_ids(raw_text)


def test_read_only_all_resource_query_passes() -> None:
    """Read-only queries against all resources should not trigger."""
    assert "RBP-KUBECTL-006" not in rule_ids("kubectl get all")


@pytest.mark.parametrize(
    "raw_text",
    [
        "kubectl apply -f deployment.yaml",
        "kubectl create -f service.yaml",
        "kubectl create deployment app --image nginx",
        "kubectl patch deployment app -p '{}'",
        "kubectl replace -f deployment.yaml",
        ("kubectl set image deployment/app web=nginx"),
        ("kubectl set env deployment/app LOG_LEVEL=info"),
    ],
)
def test_detects_mutations_without_dry_run(
    raw_text: str,
) -> None:
    """Reviewable mutations should include a dry-run preview."""
    result_findings = findings(raw_text)
    dry_run_finding = next(
        finding for finding in result_findings if finding.rule_id == "RBP-KUBECTL-007"
    )

    assert dry_run_finding.severity is Severity.WARNING
    assert dry_run_finding.repair is not None
    assert dry_run_finding.repair.confidence is RepairConfidence.LOW
    assert not dry_run_finding.repair.safe_to_apply
    assert "--dry-run=server" in (dry_run_finding.repair.replacement_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        ("kubectl apply -f deployment.yaml --dry-run=server"),
        ("kubectl create -f service.yaml --dry-run=client"),
        ("kubectl patch deployment app -p '{}' --dry-run=server"),
        (f"kubectl set image deployment/app web={PINNED_IMAGE} --dry-run=server"),
    ],
)
def test_dry_run_mutations_pass_preview_rule(
    raw_text: str,
) -> None:
    """Client and server dry runs should satisfy preview checks."""
    assert "RBP-KUBECTL-007" not in rule_ids(raw_text)


def test_false_dry_run_value_is_not_a_preview() -> None:
    """An explicitly false dry-run option should still trigger."""
    assert "RBP-KUBECTL-007" in rule_ids(
        "kubectl apply -f deployment.yaml --dry-run=false"
    )


def test_detects_forced_server_side_apply_conflicts() -> None:
    """Forced ownership conflicts should be treated as errors."""
    result_ids = rule_ids(
        "kubectl apply "
        "--server-side "
        "--force-conflicts "
        "--dry-run=server "
        "-f deployment.yaml"
    )

    assert result_ids == ("RBP-KUBECTL-008",)


def test_disabled_force_conflicts_passes() -> None:
    """An explicitly false force-conflicts option should pass."""
    assert "RBP-KUBECTL-008" not in rule_ids(
        "kubectl apply "
        "--server-side "
        "--force-conflicts=false "
        "--dry-run=server "
        "-f deployment.yaml"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        "kubectl exec -it pod/application -- sh",
        "kubectl exec --stdin pod/application -- sh",
        "kubectl exec --tty pod/application -- sh",
        "kubectl attach -it pod/application",
        (
            "kubectl run debug-shell "
            f"--image {PINNED_IMAGE} "
            "--stdin --tty --dry-run=server"
        ),
        "kubectl debug -it pod/application",
    ],
)
def test_detects_interactive_cluster_sessions(
    raw_text: str,
) -> None:
    """Interactive shell access should require explicit review."""
    assert "RBP-KUBECTL-009" in rule_ids(raw_text)


def test_noninteractive_exec_passes_interactive_rule() -> None:
    """A noninteractive exec command should not trigger."""
    assert "RBP-KUBECTL-009" not in rule_ids("kubectl exec pod/application -- env")


@pytest.mark.parametrize(
    "raw_text",
    [
        (
            "kubectl create secret generic database "
            "--from-literal=PASSWORD=super-secret "
            "--dry-run=server"
        ),
        (
            "kubectl create secret generic database "
            "--from-literal API_TOKEN=super-secret "
            "--dry-run=server"
        ),
        (
            "kubectl set env deployment/application "
            "API_KEY=super-secret --dry-run=server"
        ),
        (
            "kubectl run application "
            f"--image {PINNED_IMAGE} "
            "--env AUTH_TOKEN=super-secret "
            "--dry-run=server"
        ),
    ],
)
def test_detects_literal_secret_values(
    raw_text: str,
) -> None:
    """Literal Kubernetes secret material should be rejected."""
    assert "RBP-KUBECTL-010" in rule_ids(raw_text)


@pytest.mark.parametrize(
    "value",
    [
        "$PASSWORD",
        "${PASSWORD}",
        "$(read-secret)",
        "se://production/password",
        "<password>",
        "changeme",
        "placeholder",
        "your-secret-here",
    ],
)
def test_secret_references_and_placeholders_pass(
    value: str,
) -> None:
    """Secret references should not be reported as literals."""
    assert "RBP-KUBECTL-010" not in rule_ids(
        "kubectl create secret generic database "
        f"--from-literal PASSWORD='{value}' "
        "--dry-run=server"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        ("kubectl run application --image nginx:latest --dry-run=server"),
        ("kubectl create deployment application --image nginx:1.27 --dry-run=server"),
        ("kubectl set image deployment/application web=nginx:1.27 --dry-run=server"),
        ("kubectl debug pod/application --image busybox:1.36"),
    ],
)
def test_detects_mutable_workload_images(
    raw_text: str,
) -> None:
    """Image tags should not be treated as immutable."""
    assert "RBP-KUBECTL-011" in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        (f"kubectl run application --image {PINNED_IMAGE} --dry-run=server"),
        (
            "kubectl create deployment application "
            f"--image {PINNED_IMAGE} "
            "--dry-run=server"
        ),
        (
            "kubectl set image deployment/application "
            f"web={PINNED_IMAGE} "
            "--dry-run=server"
        ),
    ],
)
def test_digest_pinned_images_pass(
    raw_text: str,
) -> None:
    """Full SHA-256 image digests should pass."""
    assert "RBP-KUBECTL-011" not in rule_ids(raw_text)


def test_detects_privileged_debug_profile() -> None:
    """The sysadmin debug profile should be treated as privileged."""
    assert "RBP-KUBECTL-012" in rule_ids(
        "kubectl debug node/worker-01 --profile sysadmin"
    )


@pytest.mark.parametrize(
    "override",
    [
        '{"spec":{"hostNetwork":true}}',
        '{"spec":{"hostPID":true}}',
        '{"spec":{"hostIPC":true}}',
        ('{"spec":{"containers":[{"securityContext":{"privileged":true}}]}}'),
    ],
)
def test_detects_privileged_pod_overrides(
    override: str,
) -> None:
    """Privileged and host-namespace overrides should be errors."""
    assert "RBP-KUBECTL-012" in rule_ids(
        "kubectl run debug "
        f"--image {PINNED_IMAGE} "
        f"--overrides '{override}' "
        "--dry-run=server"
    )


def test_general_debug_profile_passes_privilege_rule() -> None:
    """A general debug profile should not trigger privilege detection."""
    assert "RBP-KUBECTL-012" not in rule_ids(
        "kubectl debug pod/application --profile general"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        ("kubectl apply -f deployment.yaml --validate=false --dry-run=server"),
        ("kubectl create -f deployment.yaml --validate=ignore --dry-run=server"),
    ],
)
def test_detects_disabled_schema_validation(
    raw_text: str,
) -> None:
    """Schema validation should remain enabled."""
    assert "RBP-KUBECTL-013" in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        ("kubectl apply -f deployment.yaml --validate=true --dry-run=server"),
        ("kubectl apply -f deployment.yaml --validate=strict --dry-run=server"),
    ],
)
def test_enabled_schema_validation_passes(
    raw_text: str,
) -> None:
    """Strict and true validation values should pass."""
    assert "RBP-KUBECTL-013" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "kubectl get --raw /api/v1/pods",
        "kubectl get --raw=/healthz",
    ],
)
def test_detects_raw_api_access(raw_text: str) -> None:
    """Direct Kubernetes API path access should require review."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-KUBECTL-014"
    assert result_findings[0].severity is Severity.WARNING


def test_normal_resource_query_has_no_raw_api_finding() -> None:
    """Normal kubectl resource commands should pass this rule."""
    assert "RBP-KUBECTL-014" not in rule_ids("kubectl get pods")


def test_global_options_before_command_are_supported() -> None:
    """Global kubectl options should not hide the operation."""
    result_ids = rule_ids(
        "kubectl --context production --namespace application apply -f deployment.yaml"
    )

    assert result_ids == ("RBP-KUBECTL-007",)


def test_multiple_findings_have_deterministic_order() -> None:
    """Findings should follow the pack's published rule order."""
    result_ids = rule_ids(
        "kubectl "
        "--insecure-skip-tls-verify "
        "--token super-secret "
        "run application "
        "--all-namespaces "
        "--image nginx:latest "
        "--stdin "
        "--env API_TOKEN=super-secret"
    )

    assert result_ids == (
        "RBP-KUBECTL-001",
        "RBP-KUBECTL-002",
        "RBP-KUBECTL-003",
        "RBP-KUBECTL-007",
        "RBP-KUBECTL-009",
        "RBP-KUBECTL-010",
        "RBP-KUBECTL-011",
    )


def test_kubectl_pack_integrates_with_engine() -> None:
    """The verification engine should run this pack end to end."""
    report = VerificationEngine(
        packs=(KubectlPack(),),
    ).analyze_markdown(
        ("```bash\nkubectl delete namespace production\n```\n"),
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.error_count == 1
    assert report.warning_count == 0
    assert report.pack_names == ("kubectl",)
    assert report.findings[0].rule_id == "RBP-KUBECTL-004"

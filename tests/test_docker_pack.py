"""Tests for Docker and Docker Compose verification."""

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
from runbookproof.packs import DockerPack
from runbookproof.parsers import parse_shell_command

DIGEST = f"sha256:{'a' * 64}"
PINNED_IMAGE = f"alpine@{DIGEST}"


def make_result(raw_text: str) -> ShellParseResult:
    """Parse a command for Docker-pack tests."""
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
    """Return findings produced for one Docker command."""
    return DockerPack().verify(make_result(raw_text))


def rule_ids(raw_text: str) -> tuple[str, ...]:
    """Return rule identifiers produced for one Docker command."""
    return tuple(finding.rule_id for finding in findings(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        f"docker run {PINNED_IMAGE}",
        f"docker container run {PINNED_IMAGE}",
        "docker compose up",
        "docker-compose up",
        "docker system prune",
        "docker image pull alpine:3.20",
    ],
)
def test_supports_docker_commands(raw_text: str) -> None:
    """The pack should support Docker and Compose commands."""
    assert DockerPack().supports(make_result(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        "git status",
        "kubectl get pods",
        "podman run alpine",
        "terraform validate",
        "docker",
        "docker compose",
    ],
)
def test_ignores_unrelated_or_incomplete_commands(
    raw_text: str,
) -> None:
    """Unsupported or incomplete commands should not be claimed."""
    assert not DockerPack().supports(make_result(raw_text))


def test_malformed_command_is_not_supported() -> None:
    """Malformed commands should remain a universal-pack concern."""
    result = make_result('docker run "unfinished')

    assert not DockerPack().supports(result)
    assert DockerPack().verify(result) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "docker --help",
        "docker version",
        "docker run --help",
        "docker compose version",
        "docker compose up --help",
        "docker-compose up --help",
        "docker-compose --version",
    ],
)
def test_help_and_version_commands_produce_no_findings(
    raw_text: str,
) -> None:
    """Informational commands should not produce findings."""
    assert DockerPack().verify(make_result(raw_text)) == ()


def test_safe_pinned_container_produces_no_findings() -> None:
    """A minimal digest-pinned container should pass."""
    assert findings(f"docker run --rm {PINNED_IMAGE} echo ready") == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "docker -H tcp://docker.example.com:2375 ps",
        "docker --host tcp://docker.example.com:2375 ps",
        "docker --host=tcp://docker.example.com:2375 ps",
        "DOCKER_HOST=tcp://docker.example.com:2375 docker ps",
        ("docker --host=tcp://docker.example.com:2376 --tlsverify=false ps"),
    ],
)
def test_detects_unverified_remote_daemon(
    raw_text: str,
) -> None:
    """Remote TCP daemon access should verify certificates."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-001"
    assert result_findings[0].severity is Severity.ERROR


@pytest.mark.parametrize(
    "raw_text",
    [
        ("docker --host=tcp://docker.example.com:2376 --tlsverify ps"),
        ("DOCKER_HOST=tcp://docker.example.com:2376 DOCKER_TLS_VERIFY=1 docker ps"),
        "docker -H unix:///var/run/docker.sock ps",
    ],
)
def test_verified_or_local_daemon_produces_no_transport_finding(
    raw_text: str,
) -> None:
    """Verified TCP and local Unix connections should pass."""
    assert "RBP-DOCKER-001" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        f"docker run --privileged {PINNED_IMAGE}",
        f"docker run --privileged=true {PINNED_IMAGE}",
        f"docker container run --privileged {PINNED_IMAGE}",
    ],
)
def test_detects_privileged_containers(raw_text: str) -> None:
    """Privileged containers should be treated as errors."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-002"
    assert result_findings[0].severity is Severity.ERROR


def test_explicitly_disabled_privileged_mode_passes() -> None:
    """An explicitly false privileged option should not trigger."""
    assert "RBP-DOCKER-002" not in rule_ids(
        f"docker run --privileged=false {PINNED_IMAGE}"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        f"docker run --network host {PINNED_IMAGE}",
        f"docker run --network=host {PINNED_IMAGE}",
        f"docker run --pid host {PINNED_IMAGE}",
        f"docker run --ipc=host {PINNED_IMAGE}",
        f"docker run --uts host {PINNED_IMAGE}",
    ],
)
def test_detects_host_namespace_sharing(
    raw_text: str,
) -> None:
    """Host namespaces should not be shared implicitly."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-003"
    assert result_findings[0].severity is Severity.ERROR


def test_combines_multiple_host_namespaces() -> None:
    """Multiple host namespaces should produce one finding."""
    result_findings = findings(
        f"docker run --network host --pid=host --ipc host --uts=host {PINNED_IMAGE}"
    )

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-003"

    evidence = result_findings[0].evidence[0].message

    assert "network" in evidence
    assert "PID" in evidence
    assert "IPC" in evidence
    assert "UTS" in evidence


@pytest.mark.parametrize(
    "raw_text",
    [
        (f"docker run -v /var/run/docker.sock:/var/run/docker.sock {PINNED_IMAGE}"),
        (f"docker run --volume=/run/docker.sock:/socket {PINNED_IMAGE}"),
        (
            "docker run "
            "--mount "
            "type=bind,source=/var/run/docker.sock,target=/socket "
            f"{PINNED_IMAGE}"
        ),
    ],
)
def test_detects_docker_socket_mounts(
    raw_text: str,
) -> None:
    """The Docker control socket should never be exposed silently."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-004"
    assert result_findings[0].severity is Severity.ERROR


@pytest.mark.parametrize(
    "source",
    [
        "/",
        "/etc",
        "/etc/ssh",
        "/root",
        "/proc",
        "/sys",
        "/var/lib/docker",
        "~/.aws",
        "~/.kube",
        "~/.ssh",
    ],
)
def test_detects_sensitive_host_mounts(source: str) -> None:
    """Sensitive host paths should require review."""
    result_findings = findings(f"docker run -v {source}:/host:ro {PINNED_IMAGE}")

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-005"
    assert result_findings[0].severity is Severity.WARNING


def test_named_volume_is_not_sensitive_host_path() -> None:
    """A named Docker volume is not a host bind mount."""
    assert "RBP-DOCKER-005" not in rule_ids(
        f"docker run -v application-data:/data {PINNED_IMAGE}"
    )


@pytest.mark.parametrize(
    "user",
    [
        "0",
        "0:0",
        "root",
        "root:root",
    ],
)
def test_detects_explicit_root_user(user: str) -> None:
    """Explicit root execution should be visible."""
    result_findings = findings(f"docker run --user {user} {PINNED_IMAGE}")

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-006"
    assert result_findings[0].severity is Severity.WARNING


def test_non_root_user_produces_no_root_finding() -> None:
    """A non-root numeric user should pass this rule."""
    assert "RBP-DOCKER-006" not in rule_ids(
        f"docker run --user 1000:1000 {PINNED_IMAGE}"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        "docker run alpine",
        "docker run alpine:3.20",
        "docker create nginx:1.27",
        "docker pull ubuntu:24.04",
        "docker image pull ubuntu:24.04",
    ],
)
def test_detects_images_not_pinned_by_digest(
    raw_text: str,
) -> None:
    """Tags are mutable and should not be treated as immutable."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-007"
    assert result_findings[0].severity is Severity.WARNING


@pytest.mark.parametrize(
    "raw_text",
    [
        f"docker run {PINNED_IMAGE}",
        f"docker pull {PINNED_IMAGE}",
        f"docker image pull {PINNED_IMAGE}",
    ],
)
def test_digest_pinned_images_pass(raw_text: str) -> None:
    """Full SHA-256 image digests should be immutable."""
    assert "RBP-DOCKER-007" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "security_option",
    [
        "seccomp=unconfined",
        "apparmor=unconfined",
        "label=disable",
        "no-new-privileges=false",
        "systempaths=unconfined",
    ],
)
def test_detects_disabled_container_security(
    security_option: str,
) -> None:
    """Docker confinement controls should remain enabled."""
    result_findings = findings(
        f"docker run --security-opt {security_option} {PINNED_IMAGE}"
    )

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-008"
    assert result_findings[0].severity is Severity.ERROR


@pytest.mark.parametrize(
    "capability",
    [
        "SYS_ADMIN",
        "ALL",
    ],
)
def test_detects_dangerous_capabilities(
    capability: str,
) -> None:
    """Dangerous Linux capabilities should be errors."""
    result_findings = findings(f"docker run --cap-add {capability} {PINNED_IMAGE}")

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-009"
    assert result_findings[0].severity is Severity.ERROR


def test_normal_capability_does_not_trigger_rule() -> None:
    """A capability outside the high-risk set should not trigger."""
    assert "RBP-DOCKER-009" not in rule_ids(
        f"docker run --cap-add NET_BIND_SERVICE {PINNED_IMAGE}"
    )


@pytest.mark.parametrize(
    ("raw_text", "severity"),
    [
        ("docker system prune", Severity.WARNING),
        ("docker system prune --force", Severity.ERROR),
        ("docker system prune -af", Severity.ERROR),
        ("docker image prune --all", Severity.ERROR),
        ("docker volume prune", Severity.ERROR),
        ("docker builder prune -f", Severity.ERROR),
        ("docker buildx prune --force", Severity.ERROR),
    ],
)
def test_detects_destructive_prune_commands(
    raw_text: str,
    severity: Severity,
) -> None:
    """Docker prune operations can permanently remove local data."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-010"
    assert result_findings[0].severity is severity


@pytest.mark.parametrize(
    "raw_text",
    [
        "docker compose down --volumes",
        "docker compose down -v",
        "docker-compose down --volumes",
        "docker-compose down -v",
    ],
)
def test_detects_compose_volume_deletion(
    raw_text: str,
) -> None:
    """Compose volume removal should be treated as destructive."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-010"
    assert result_findings[0].severity is Severity.ERROR


def test_detects_compose_image_deletion() -> None:
    """Removing all service images should require review."""
    result_findings = findings("docker compose down --rmi all")

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-010"
    assert result_findings[0].severity is Severity.WARNING


def test_normal_compose_down_produces_no_cleanup_finding() -> None:
    """Stopping a Compose project alone should not trigger cleanup."""
    assert "RBP-DOCKER-010" not in rule_ids("docker compose down")


@pytest.mark.parametrize(
    "raw_text",
    [
        ("docker login --password super-secret registry.example.com"),
        ("docker login -p super-secret registry.example.com"),
        (f"docker run -e API_KEY=super-secret {PINNED_IMAGE}"),
        ("docker compose run --env AUTH_TOKEN=super-secret application"),
        ("docker build --build-arg CLIENT_SECRET=super-secret ."),
        ("docker buildx build --build-arg PRIVATE_KEY=super-secret ."),
    ],
)
def test_detects_literal_secrets(raw_text: str) -> None:
    """Literal credentials should not appear in command arguments."""
    result_findings = findings(raw_text)

    assert len(result_findings) == 1
    assert result_findings[0].rule_id == "RBP-DOCKER-011"
    assert result_findings[0].severity is Severity.ERROR


@pytest.mark.parametrize(
    "value",
    [
        "$API_KEY",
        "${API_KEY}",
        "se://production/api-key",
        "<api-key>",
        "changeme",
        "placeholder",
        "your-secret-here",
    ],
)
def test_secret_references_and_placeholders_pass(
    value: str,
) -> None:
    """References and obvious placeholders are not literal secrets."""
    assert "RBP-DOCKER-011" not in rule_ids(
        f"docker run --env API_KEY={value} {PINNED_IMAGE}"
    )


def test_compose_run_supports_root_and_capability_rules() -> None:
    """Compose run should receive applicable runtime checks."""
    assert rule_ids(
        "docker compose run --user root --cap-add SYS_ADMIN application"
    ) == (
        "RBP-DOCKER-006",
        "RBP-DOCKER-009",
    )


def test_multiple_findings_have_deterministic_order() -> None:
    """Findings should follow the published rule order."""
    result_findings = findings(
        "docker run "
        "--privileged "
        "--network host "
        "-v /var/run/docker.sock:/socket "
        "--user root "
        "--security-opt seccomp=unconfined "
        "--cap-add SYS_ADMIN "
        "-e API_KEY=super-secret "
        "alpine:latest"
    )

    assert tuple(finding.rule_id for finding in result_findings) == (
        "RBP-DOCKER-002",
        "RBP-DOCKER-003",
        "RBP-DOCKER-004",
        "RBP-DOCKER-006",
        "RBP-DOCKER-007",
        "RBP-DOCKER-008",
        "RBP-DOCKER-009",
        "RBP-DOCKER-011",
    )


def test_docker_pack_integrates_with_engine() -> None:
    """The verification engine should run the Docker pack end to end."""
    report = VerificationEngine(
        packs=(DockerPack(),),
    ).analyze_markdown(
        (f"```bash\ndocker run --privileged {PINNED_IMAGE}\n```\n"),
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.error_count == 1
    assert report.warning_count == 0
    assert report.pack_names == ("docker",)
    assert report.findings[0].rule_id == "RBP-DOCKER-002"

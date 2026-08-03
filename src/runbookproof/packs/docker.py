"""Static verification for Docker and Docker Compose commands."""

from __future__ import annotations

import re
from dataclasses import dataclass

from runbookproof.models import (
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    ShellParseResult,
)

_SUPPORTED_EXECUTABLES = frozenset(
    {
        "docker",
        "docker-compose",
    }
)

_DOCKER_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--config",
        "--context",
        "--host",
        "--log-level",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
        "-H",
        "-c",
        "-l",
    }
)

_COMPOSE_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--ansi",
        "--env-file",
        "--file",
        "--parallel",
        "--profile",
        "--progress",
        "--project-directory",
        "--project-name",
        "-f",
        "-p",
    }
)

_CONTAINER_OPTIONS_WITH_VALUES = frozenset(
    {
        "--add-host",
        "--annotation",
        "--attach",
        "--blkio-weight",
        "--blkio-weight-device",
        "--cap-add",
        "--cap-drop",
        "--cgroup-parent",
        "--cgroupns",
        "--cidfile",
        "--cpu-period",
        "--cpu-quota",
        "--cpu-rt-period",
        "--cpu-rt-runtime",
        "--cpu-shares",
        "--cpus",
        "--cpuset-cpus",
        "--cpuset-mems",
        "--device",
        "--device-cgroup-rule",
        "--device-read-bps",
        "--device-read-iops",
        "--device-write-bps",
        "--device-write-iops",
        "--dns",
        "--dns-option",
        "--dns-search",
        "--domainname",
        "--entrypoint",
        "--env",
        "--env-file",
        "--expose",
        "--gpus",
        "--group-add",
        "--health-cmd",
        "--health-interval",
        "--health-retries",
        "--health-start-interval",
        "--health-start-period",
        "--health-timeout",
        "--hostname",
        "--init-path",
        "--ipc",
        "--ip",
        "--ip6",
        "--label",
        "--label-file",
        "--link",
        "--link-local-ip",
        "--log-driver",
        "--log-opt",
        "--mac-address",
        "--memory",
        "--memory-reservation",
        "--memory-swap",
        "--memory-swappiness",
        "--mount",
        "--name",
        "--network",
        "--network-alias",
        "--oom-score-adj",
        "--pid",
        "--pids-limit",
        "--platform",
        "--publish",
        "--pull",
        "--restart",
        "--runtime",
        "--security-opt",
        "--shm-size",
        "--stop-signal",
        "--stop-timeout",
        "--storage-opt",
        "--sysctl",
        "--tmpfs",
        "--ulimit",
        "--user",
        "--userns",
        "--uts",
        "--volume",
        "--volume-driver",
        "--volumes-from",
        "--workdir",
        "-a",
        "-e",
        "-h",
        "-l",
        "-m",
        "-p",
        "-u",
        "-v",
        "-w",
    }
)

_COMPOSE_RUN_OPTIONS_WITH_VALUES = frozenset(
    {
        "--cap-add",
        "--cap-drop",
        "--entrypoint",
        "--env",
        "--env-from-file",
        "--label",
        "--name",
        "--publish",
        "--pull",
        "--user",
        "--volume",
        "--workdir",
        "-e",
        "-l",
        "-p",
        "-u",
        "-v",
        "-w",
    }
)

_BUILD_OPTIONS_WITH_VALUES = frozenset(
    {
        "--add-host",
        "--annotation",
        "--build-arg",
        "--build-context",
        "--cache-from",
        "--cache-to",
        "--cgroup-parent",
        "--file",
        "--iidfile",
        "--label",
        "--network",
        "--output",
        "--platform",
        "--provenance",
        "--secret",
        "--shm-size",
        "--ssh",
        "--tag",
        "--target",
        "--ulimit",
        "-f",
        "-o",
        "-t",
    }
)

_PULL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--platform",
    }
)

_NESTED_COMMAND_GROUPS = frozenset(
    {
        "builder",
        "buildx",
        "container",
        "image",
        "network",
        "system",
        "volume",
    }
)

_CONTAINER_COMMANDS = frozenset(
    {
        "container-create",
        "container-run",
        "create",
        "run",
    }
)

_BUILD_COMMANDS = frozenset(
    {
        "build",
        "buildx-build",
        "compose-build",
    }
)

_PRUNE_COMMANDS = frozenset(
    {
        "builder-prune",
        "buildx-prune",
        "container-prune",
        "image-prune",
        "network-prune",
        "system-prune",
        "volume-prune",
    }
)

_SOCKET_PATHS = frozenset(
    {
        "//./pipe/docker_engine",
        "/run/docker.sock",
        "/var/run/docker.sock",
    }
)

_SENSITIVE_PATH_PREFIXES = (
    "/boot",
    "/dev",
    "/etc",
    "/proc",
    "/root",
    "/run",
    "/sys",
    "/var/lib/docker",
    "/var/run",
)

_DANGEROUS_SECURITY_OPTIONS = frozenset(
    {
        "apparmor=unconfined",
        "label=disable",
        "no-new-privileges=false",
        "no-new-privileges:false",
        "seccomp=unconfined",
        "systempaths=unconfined",
    }
)

_DANGEROUS_CAPABILITIES = frozenset(
    {
        "ALL",
        "SYS_ADMIN",
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
    r"TOKEN"
    r")"
    r"(?:$|_)",
    flags=re.IGNORECASE,
)

_IMAGE_DIGEST_PATTERN = re.compile(r"(?:@|^)sha256:[0-9a-fA-F]{64}$")


@dataclass(frozen=True, slots=True)
class _DockerInvocation:
    """Describe one normalized Docker or Compose command."""

    command: str
    arguments: tuple[str, ...]
    global_arguments: tuple[str, ...]
    compose: bool = False


@dataclass(frozen=True, slots=True)
class _CleanupProblem:
    """Describe one destructive Docker cleanup command."""

    severity: Severity
    message: str
    evidence: str


class DockerPack:
    """Detect insecure and destructive Docker documentation patterns."""

    name = "docker"

    def supports(self, result: ShellParseResult) -> bool:
        """Support successfully parsed Docker and Compose commands."""
        return (
            result.error is None
            and result.command.executable in _SUPPORTED_EXECUTABLES
            and _parse_invocation(result) is not None
        )

    def verify(
        self,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Return deterministic findings for one Docker command."""
        if result.error is not None:
            return ()

        invocation = _parse_invocation(result)

        if invocation is None or _is_help_request(invocation):
            return ()

        findings: list[Finding] = []

        transport_problem = _insecure_daemon_transport(
            result,
            invocation,
        )

        if transport_problem is not None:
            findings.append(
                _transport_security_finding(
                    result,
                    problem=transport_problem,
                )
            )

        if _uses_privileged_mode(invocation):
            findings.append(_privileged_mode_finding(result))

        host_namespaces = _host_namespaces(invocation)

        if host_namespaces:
            findings.append(
                _host_namespace_finding(
                    result,
                    namespaces=host_namespaces,
                )
            )

        mount_sources = _mount_sources(invocation)
        socket_mounts = tuple(
            source for source in mount_sources if _is_docker_socket(source)
        )

        if socket_mounts:
            findings.append(
                _docker_socket_finding(
                    result,
                    mounts=socket_mounts,
                )
            )

        sensitive_mounts = tuple(
            source
            for source in mount_sources
            if not _is_docker_socket(source) and _is_sensitive_host_path(source)
        )

        if sensitive_mounts:
            findings.append(
                _sensitive_mount_finding(
                    result,
                    mounts=sensitive_mounts,
                )
            )

        root_user = _explicit_root_user(invocation)

        if root_user is not None:
            findings.append(
                _root_user_finding(
                    result,
                    user=root_user,
                )
            )

        image = _container_image(invocation)

        if image is not None and not _is_digest_pinned(image):
            findings.append(
                _unpinned_image_finding(
                    result,
                    image=image,
                )
            )

        security_options = _dangerous_security_options(invocation)

        if security_options:
            findings.append(
                _weakened_security_finding(
                    result,
                    options=security_options,
                )
            )

        capabilities = _dangerous_capabilities(invocation)

        if capabilities:
            findings.append(
                _dangerous_capability_finding(
                    result,
                    capabilities=capabilities,
                )
            )

        cleanup_problem = _cleanup_problem(invocation)

        if cleanup_problem is not None:
            findings.append(
                _destructive_cleanup_finding(
                    result,
                    problem=cleanup_problem,
                )
            )

        secret_problem = _literal_secret_problem(invocation)

        if secret_problem is not None:
            findings.append(
                _literal_secret_finding(
                    result,
                    problem=secret_problem,
                )
            )

        return tuple(findings)


def _transport_security_finding(
    result: ShellParseResult,
    *,
    problem: str,
) -> Finding:
    """Create an error for an unverified remote Docker daemon."""
    return Finding(
        rule_id="RBP-DOCKER-001",
        severity=Severity.ERROR,
        message="Remote Docker daemon connection is not verified",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=problem,
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _privileged_mode_finding(
    result: ShellParseResult,
) -> Finding:
    """Create an error for privileged container execution."""
    return Finding(
        rule_id="RBP-DOCKER-002",
        severity=Severity.ERROR,
        message="Container is granted unrestricted host privileges",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message="Detected Docker privileged mode.",
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _host_namespace_finding(
    result: ShellParseResult,
    *,
    namespaces: tuple[str, ...],
) -> Finding:
    """Create an error for sharing host namespaces."""
    namespace_list = ", ".join(namespaces)

    return Finding(
        rule_id="RBP-DOCKER-003",
        severity=Severity.ERROR,
        message="Container shares host namespaces",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(f"Detected host namespace sharing for: {namespace_list}."),
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _docker_socket_finding(
    result: ShellParseResult,
    *,
    mounts: tuple[str, ...],
) -> Finding:
    """Create an error for mounting the Docker control socket."""
    mount_list = ", ".join(mounts)

    return Finding(
        rule_id="RBP-DOCKER-004",
        severity=Severity.ERROR,
        message="Container mounts the Docker daemon socket",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=f"Detected Docker socket mount: {mount_list}.",
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _sensitive_mount_finding(
    result: ShellParseResult,
    *,
    mounts: tuple[str, ...],
) -> Finding:
    """Create a warning for sensitive host filesystem mounts."""
    mount_list = ", ".join(mounts)

    return Finding(
        rule_id="RBP-DOCKER-005",
        severity=Severity.WARNING,
        message="Container mounts a sensitive host path",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    f"Detected bind mount from sensitive host path: {mount_list}."
                ),
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _root_user_finding(
    result: ShellParseResult,
    *,
    user: str,
) -> Finding:
    """Create a warning for an explicitly selected root user."""
    return Finding(
        rule_id="RBP-DOCKER-006",
        severity=Severity.WARNING,
        message="Container explicitly runs as root",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=f"Detected root container user: {user}.",
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _unpinned_image_finding(
    result: ShellParseResult,
    *,
    image: str,
) -> Finding:
    """Create a warning for an image not pinned by digest."""
    return Finding(
        rule_id="RBP-DOCKER-007",
        severity=Severity.WARNING,
        message="Container image is not pinned by digest",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected mutable image reference without an "
                    f"SHA-256 digest: {image}."
                ),
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _weakened_security_finding(
    result: ShellParseResult,
    *,
    options: tuple[str, ...],
) -> Finding:
    """Create an error for disabled container security controls."""
    option_list = ", ".join(options)

    return Finding(
        rule_id="RBP-DOCKER-008",
        severity=Severity.ERROR,
        message="Container security controls are disabled",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected weakened Docker security option"
                    f"{'s' if len(options) != 1 else ''}: "
                    f"{option_list}."
                ),
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _dangerous_capability_finding(
    result: ShellParseResult,
    *,
    capabilities: tuple[str, ...],
) -> Finding:
    """Create an error for dangerous Linux capabilities."""
    capability_list = ", ".join(capabilities)

    return Finding(
        rule_id="RBP-DOCKER-009",
        severity=Severity.ERROR,
        message="Container receives dangerous Linux capabilities",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(f"Detected dangerous capability addition: {capability_list}."),
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _destructive_cleanup_finding(
    result: ShellParseResult,
    *,
    problem: _CleanupProblem,
) -> Finding:
    """Create a finding for destructive Docker cleanup."""
    return Finding(
        rule_id="RBP-DOCKER-010",
        severity=problem.severity,
        message=problem.message,
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=problem.evidence,
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _literal_secret_finding(
    result: ShellParseResult,
    *,
    problem: str,
) -> Finding:
    """Create an error for a literal secret in command arguments."""
    return Finding(
        rule_id="RBP-DOCKER-011",
        severity=Severity.ERROR,
        message="Command contains a literal secret value",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=problem,
                source="RunbookProof Docker pack",
            ),
        ),
    )


def _parse_invocation(
    result: ShellParseResult,
) -> _DockerInvocation | None:
    """Normalize Docker and Docker Compose command structures."""
    executable = result.command.executable
    arguments = result.command.arguments

    if executable == "docker-compose":
        command, remaining, global_arguments = _split_command(
            arguments,
            options_with_values=_COMPOSE_GLOBAL_OPTIONS_WITH_VALUES,
        )

        if command is None:
            return None

        return _DockerInvocation(
            command=f"compose-{command}",
            arguments=remaining,
            global_arguments=global_arguments,
            compose=True,
        )

    if executable != "docker":
        return None

    command, remaining, global_arguments = _split_command(
        arguments,
        options_with_values=_DOCKER_GLOBAL_OPTIONS_WITH_VALUES,
    )

    if command is None:
        return None

    if command == "compose":
        (
            compose_command,
            compose_arguments,
            compose_global_arguments,
        ) = _split_command(
            remaining,
            options_with_values=_COMPOSE_GLOBAL_OPTIONS_WITH_VALUES,
        )

        if compose_command is None:
            return None

        return _DockerInvocation(
            command=f"compose-{compose_command}",
            arguments=compose_arguments,
            global_arguments=(
                *global_arguments,
                *compose_global_arguments,
            ),
            compose=True,
        )

    if command in _NESTED_COMMAND_GROUPS:
        nested_command, nested_arguments, nested_global_arguments = _split_command(
            remaining,
            options_with_values=frozenset(),
        )

        if nested_command is None:
            return None

        return _DockerInvocation(
            command=f"{command}-{nested_command}",
            arguments=nested_arguments,
            global_arguments=(
                *global_arguments,
                *nested_global_arguments,
            ),
        )

    return _DockerInvocation(
        command=command,
        arguments=remaining,
        global_arguments=global_arguments,
    )


def _split_command(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> tuple[
    str | None,
    tuple[str, ...],
    tuple[str, ...],
]:
    """Separate leading options from a Docker subcommand."""
    index = 0

    while index < len(arguments):
        argument = arguments[index]

        if argument == "--":
            index += 1
            break

        if not argument.startswith("-"):
            return (
                argument,
                arguments[index + 1 :],
                arguments[:index],
            )

        option_name = argument.split("=", maxsplit=1)[0]

        if option_name in options_with_values and "=" not in argument:
            index += 2
        else:
            index += 1

    if index < len(arguments):
        return (
            arguments[index],
            arguments[index + 1 :],
            arguments[:index],
        )

    return None, (), arguments


def _is_help_request(
    invocation: _DockerInvocation,
) -> bool:
    """Return whether the command requests help or version data."""
    if invocation.command in {
        "help",
        "version",
        "compose-version",
    }:
        return True

    return any(
        argument
        in {
            "-h",
            "--help",
        }
        for argument in invocation.arguments
    )


def _insecure_daemon_transport(
    result: ShellParseResult,
    invocation: _DockerInvocation,
) -> str | None:
    """Return evidence for an unverified TCP daemon connection."""
    hosts = _option_values(
        invocation.global_arguments,
        options=(
            "-H",
            "--host",
        ),
    )

    assignment_host = _assignment_value(
        result.assignments,
        name="DOCKER_HOST",
    )

    if assignment_host is not None:
        hosts = (*hosts, assignment_host)

    tcp_hosts = tuple(host for host in hosts if host.lower().startswith("tcp://"))

    if not tcp_hosts:
        return None

    if _tls_verification_enabled(
        result,
        invocation,
    ):
        return None

    host_list = ", ".join(tcp_hosts)

    return (
        "Detected a TCP Docker daemon connection without "
        f"certificate verification: {host_list}."
    )


def _tls_verification_enabled(
    result: ShellParseResult,
    invocation: _DockerInvocation,
) -> bool:
    """Return whether remote Docker certificate verification is enabled."""
    for argument in invocation.global_arguments:
        if argument == "--tlsverify":
            return True

        if argument.startswith("--tlsverify="):
            value = argument.split("=", maxsplit=1)[1].lower()

            return value not in {
                "0",
                "false",
                "no",
            }

    assignment = _assignment_value(
        result.assignments,
        name="DOCKER_TLS_VERIFY",
    )

    if assignment is None:
        return False

    return assignment.lower() not in {
        "",
        "0",
        "false",
        "no",
    }


def _assignment_value(
    assignments: tuple[str, ...],
    *,
    name: str,
) -> str | None:
    """Return the value of one leading shell assignment."""
    prefix = f"{name}="

    for assignment in assignments:
        if assignment.startswith(prefix):
            return assignment[len(prefix) :]

    return None


def _uses_privileged_mode(
    invocation: _DockerInvocation,
) -> bool:
    """Return whether unrestricted privileged mode is enabled."""
    if invocation.command not in _CONTAINER_COMMANDS:
        return False

    return _flag_enabled(
        invocation.arguments,
        option="--privileged",
    )


def _host_namespaces(
    invocation: _DockerInvocation,
) -> tuple[str, ...]:
    """Return host namespaces shared with one container."""
    if invocation.command not in _CONTAINER_COMMANDS:
        return ()

    namespaces: list[str] = []

    for label, options in (
        (
            "network",
            (
                "--net",
                "--network",
            ),
        ),
        (
            "PID",
            ("--pid",),
        ),
        (
            "IPC",
            ("--ipc",),
        ),
        (
            "UTS",
            ("--uts",),
        ),
    ):
        values = _option_values(
            invocation.arguments,
            options=options,
        )

        if any(value.lower() == "host" for value in values):
            namespaces.append(label)

    return tuple(namespaces)


def _mount_sources(
    invocation: _DockerInvocation,
) -> tuple[str, ...]:
    """Return host paths mounted into a container."""
    if invocation.command in _CONTAINER_COMMANDS or invocation.command == "compose-run":
        arguments = invocation.arguments
        volume_options = (
            "-v",
            "--volume",
        )
    else:
        return ()

    sources: list[str] = []

    for volume in _option_values(
        arguments,
        options=volume_options,
    ):
        source = _volume_source(volume)

        if source is not None and source not in sources:
            sources.append(source)

    if invocation.command in _CONTAINER_COMMANDS:
        for mount in _option_values(
            arguments,
            options=("--mount",),
        ):
            source = _mount_source(mount)

            if source is not None and source not in sources:
                sources.append(source)

    return tuple(sources)


def _volume_source(
    specification: str,
) -> str | None:
    """Return the host source from short volume syntax."""
    normalized = specification.strip().replace("\\", "/")

    if ":" not in normalized:
        return None

    if re.match(r"^[A-Za-z]:/", normalized):
        separator = normalized.find(":", 3)

        if separator == -1:
            return None

        return normalized[:separator]

    return normalized.split(":", maxsplit=1)[0]


def _mount_source(
    specification: str,
) -> str | None:
    """Return the source field from long mount syntax."""
    fields: dict[str, str] = {}

    for component in specification.split(","):
        if "=" not in component:
            continue

        key, value = component.split("=", maxsplit=1)
        fields[key.strip().lower()] = value.strip()

    return fields.get("source") or fields.get("src")


def _is_docker_socket(path: str) -> bool:
    """Return whether a path refers to the Docker control socket."""
    normalized = _normalize_path(path)

    return normalized in _SOCKET_PATHS or normalized.endswith("/docker.sock")


def _is_sensitive_host_path(path: str) -> bool:
    """Return whether a bind source exposes sensitive host content."""
    normalized = _normalize_path(path)

    if normalized == "/":
        return True

    if normalized in {
        "~/.aws",
        "~/.kube",
        "~/.ssh",
    }:
        return True

    return any(
        _path_matches_prefix(
            normalized,
            prefix=prefix,
        )
        for prefix in _SENSITIVE_PATH_PREFIXES
    )


def _normalize_path(path: str) -> str:
    """Normalize one host path for deterministic comparison."""
    normalized = path.strip().replace("\\", "/")

    if normalized != "/":
        normalized = normalized.rstrip("/")

    return normalized


def _path_matches_prefix(
    path: str,
    *,
    prefix: str,
) -> bool:
    """Return whether a path equals or descends from a prefix."""
    return path == prefix or path.startswith(f"{prefix}/")


def _explicit_root_user(
    invocation: _DockerInvocation,
) -> str | None:
    """Return an explicitly configured root user."""
    if (
        invocation.command not in _CONTAINER_COMMANDS
        and invocation.command != "compose-run"
    ):
        return None

    users = _option_values(
        invocation.arguments,
        options=(
            "-u",
            "--user",
        ),
    )

    for user in users:
        normalized = user.lower()

        if normalized in {
            "0",
            "0:0",
            "root",
            "root:root",
        }:
            return user

    return None


def _container_image(
    invocation: _DockerInvocation,
) -> str | None:
    """Return an image reference used by a Docker command."""
    if invocation.command in _CONTAINER_COMMANDS:
        return _first_operand(
            invocation.arguments,
            options_with_values=_CONTAINER_OPTIONS_WITH_VALUES,
        )

    if invocation.command in {
        "image-pull",
        "pull",
    }:
        return _first_operand(
            invocation.arguments,
            options_with_values=_PULL_OPTIONS_WITH_VALUES,
        )

    return None


def _is_digest_pinned(image: str) -> bool:
    """Return whether an image reference uses a full SHA-256 digest."""
    return _IMAGE_DIGEST_PATTERN.search(image) is not None


def _dangerous_security_options(
    invocation: _DockerInvocation,
) -> tuple[str, ...]:
    """Return security options that disable Docker confinement."""
    if invocation.command not in _CONTAINER_COMMANDS:
        return ()

    values = _option_values(
        invocation.arguments,
        options=("--security-opt",),
    )

    return tuple(
        value for value in values if value.lower() in _DANGEROUS_SECURITY_OPTIONS
    )


def _dangerous_capabilities(
    invocation: _DockerInvocation,
) -> tuple[str, ...]:
    """Return dangerous Linux capabilities added to a container."""
    if (
        invocation.command not in _CONTAINER_COMMANDS
        and invocation.command != "compose-run"
    ):
        return ()

    values = _option_values(
        invocation.arguments,
        options=("--cap-add",),
    )
    capabilities: list[str] = []

    for value in values:
        normalized = value.upper()

        if normalized in _DANGEROUS_CAPABILITIES and normalized not in capabilities:
            capabilities.append(normalized)

    return tuple(capabilities)


def _cleanup_problem(
    invocation: _DockerInvocation,
) -> _CleanupProblem | None:
    """Return destructive cleanup details for one command."""
    if invocation.command == "compose-down":
        removes_volumes = _has_exact_option(
            invocation.arguments,
            option="--volumes",
        ) or _short_flag_present(
            invocation.arguments,
            flag="v",
        )
        removes_all_images = _option_has_value(
            invocation.arguments,
            option="--rmi",
            expected="all",
        )

        if removes_volumes:
            return _CleanupProblem(
                severity=Severity.ERROR,
                message="Docker Compose removes persistent volumes",
                evidence=(
                    "Detected `docker compose down` with volume removal enabled."
                ),
            )

        if removes_all_images:
            return _CleanupProblem(
                severity=Severity.WARNING,
                message="Docker Compose removes service images",
                evidence=("Detected `docker compose down --rmi all`."),
            )

        return None

    if invocation.command not in _PRUNE_COMMANDS:
        return None

    force = _has_exact_option(
        invocation.arguments,
        option="--force",
    ) or _short_flag_present(
        invocation.arguments,
        flag="f",
    )
    all_objects = _has_exact_option(
        invocation.arguments,
        option="--all",
    ) or _short_flag_present(
        invocation.arguments,
        flag="a",
    )
    volumes = _has_exact_option(
        invocation.arguments,
        option="--volumes",
    )

    severe = invocation.command == "volume-prune" or force or all_objects or volumes

    severity = Severity.ERROR if severe else Severity.WARNING

    return _CleanupProblem(
        severity=severity,
        message="Docker cleanup can permanently remove local data",
        evidence=(
            f"Detected destructive Docker prune operation: {invocation.command}."
        ),
    )


def _literal_secret_problem(
    invocation: _DockerInvocation,
) -> str | None:
    """Return evidence for literal credentials in command arguments."""
    if invocation.command == "login":
        passwords = _option_values(
            invocation.arguments,
            options=(
                "-p",
                "--password",
            ),
        )

        if passwords:
            return (
                "Detected a Docker registry password passed directly "
                "through command-line arguments."
            )

    if invocation.command in _CONTAINER_COMMANDS or invocation.command == "compose-run":
        environment_values = _option_values(
            invocation.arguments,
            options=(
                "-e",
                "--env",
            ),
        )

        problem = _secret_environment_problem(environment_values)

        if problem is not None:
            return problem

    if invocation.command in _BUILD_COMMANDS:
        build_arguments = _option_values(
            invocation.arguments,
            options=("--build-arg",),
        )

        problem = _secret_environment_problem(build_arguments)

        if problem is not None:
            return problem

    return None


def _secret_environment_problem(
    assignments: tuple[str, ...],
) -> str | None:
    """Return evidence for one sensitive literal assignment."""
    for assignment in assignments:
        if "=" not in assignment:
            continue

        name, value = assignment.split("=", maxsplit=1)

        if not _SECRET_NAME_PATTERN.search(name):
            continue

        if not _is_literal_secret(value):
            continue

        return (
            "Detected a literal value for sensitive variable "
            f"`{name}` in command-line arguments."
        )

    return None


def _is_literal_secret(value: str) -> bool:
    """Return whether an assignment contains a literal secret value."""
    normalized = value.strip()

    if not normalized:
        return False

    if normalized.startswith(
        (
            "$",
            "${",
            "se://",
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


def _first_operand(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> str | None:
    """Return the first positional operand after command options."""
    index = 0

    while index < len(arguments):
        argument = arguments[index]

        if argument == "--":
            next_index = index + 1

            if next_index < len(arguments):
                return arguments[next_index]

            return None

        if argument.startswith("-"):
            option_name = argument.split("=", maxsplit=1)[0]

            if option_name in options_with_values and "=" not in argument:
                index += 2
            else:
                index += 1

            continue

        return argument

    return None


def _option_values(
    arguments: tuple[str, ...],
    *,
    options: tuple[str, ...],
) -> tuple[str, ...]:
    """Return all values assigned to selected command options."""
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

            if (
                len(option) == 2
                and option.startswith("-")
                and not option.startswith("--")
                and argument.startswith(option)
                and len(argument) > 2
            ):
                values.append(argument[2:])
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
    """Return whether a Boolean long option is enabled."""
    for argument in arguments:
        if argument == option:
            return True

        if argument.startswith(f"{option}="):
            value = argument.split("=", maxsplit=1)[1].lower()

            return value not in {
                "0",
                "false",
                "no",
            }

    return False


def _has_exact_option(
    arguments: tuple[str, ...],
    *,
    option: str,
) -> bool:
    """Return whether arguments contain one exact long option."""
    return any(
        argument == option or argument.startswith(f"{option}=")
        for argument in arguments
    )


def _short_flag_present(
    arguments: tuple[str, ...],
    *,
    flag: str,
) -> bool:
    """Return whether a short option token contains one flag."""
    return any(
        argument.startswith("-")
        and not argument.startswith("--")
        and flag in argument[1:]
        for argument in arguments
    )


def _option_has_value(
    arguments: tuple[str, ...],
    *,
    option: str,
    expected: str,
) -> bool:
    """Return whether an option has a selected value."""
    return any(
        value.lower() == expected.lower()
        for value in _option_values(
            arguments,
            options=(option,),
        )
    )

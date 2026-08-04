"""Static verification for kubectl commands."""

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
        "--as",
        "--as-group",
        "--as-uid",
        "--as-user-extra",
        "--cache-dir",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--cluster",
        "--context",
        "--kubeconfig",
        "--kuberc",
        "--namespace",
        "--password",
        "--profile",
        "--profile-output",
        "--request-timeout",
        "--server",
        "--tls-server-name",
        "--token",
        "--user",
        "--username",
        "-n",
        "-s",
    }
)

_COMMAND_OPTIONS_WITH_VALUES = frozenset(
    {
        "--cascade",
        "--container",
        "--dry-run",
        "--field-manager",
        "--filename",
        "--from-env-file",
        "--from-file",
        "--from-literal",
        "--grace-period",
        "--image",
        "--kustomize",
        "--output",
        "--overrides",
        "--patch",
        "--patch-file",
        "--patch-type",
        "--profile",
        "--raw",
        "--replicas",
        "--resource-version",
        "--selector",
        "--subresource",
        "--timeout",
        "--type",
        "--validate",
        "-c",
        "-f",
        "-k",
        "-l",
        "-o",
        "-p",
    }
)

_NESTED_GROUPS = frozenset(
    {
        "auth",
        "certificate",
        "cluster-info",
        "config",
        "create",
        "plugin",
        "rollout",
        "set",
        "top",
    }
)

_MUTATING_COMMANDS = frozenset(
    {
        "annotate",
        "apply",
        "autoscale",
        "cordon",
        "create",
        "delete",
        "drain",
        "edit",
        "expose",
        "label",
        "patch",
        "replace",
        "run",
        "scale",
        "taint",
        "uncordon",
    }
)

_DRY_RUN_COMMANDS = frozenset(
    {
        "apply",
        "create",
        "patch",
        "replace",
        "run",
        "set-env",
        "set-image",
    }
)

_INTERACTIVE_COMMANDS = frozenset(
    {
        "attach",
        "debug",
        "exec",
        "run",
    }
)

_SENSITIVE_RESOURCES = frozenset(
    {
        "clusterrole",
        "clusterrolebinding",
        "crd",
        "customresourcedefinition",
        "namespace",
        "node",
        "persistentvolume",
        "pv",
        "secret",
        "serviceaccount",
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

_DIGEST_PATTERN = re.compile(r"@sha256:[0-9a-fA-F]{64}$")

_PRIVILEGED_OVERRIDE_PATTERN = re.compile(
    r'"(?:privileged|hostNetwork|hostPID|hostIPC)"\s*:\s*true',
    flags=re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _Invocation:
    """Describe one normalized kubectl invocation."""

    command: str
    arguments: tuple[str, ...]
    all_arguments: tuple[str, ...]


class KubectlPack:
    """Detect dangerous and non-reviewable kubectl commands."""

    name = "kubectl"

    def supports(self, result: ShellParseResult) -> bool:
        """Support successfully parsed kubectl commands."""
        return (
            result.error is None
            and result.command.executable == "kubectl"
            and _parse_invocation(result) is not None
        )

    def verify(
        self,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Return deterministic findings for one kubectl command."""
        if result.error is not None:
            return ()

        invocation = _parse_invocation(result)

        if invocation is None or _is_help_request(invocation):
            return ()

        findings: list[Finding] = []

        if _flag_enabled(
            invocation.all_arguments,
            option="--insecure-skip-tls-verify",
        ):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-001",
                    severity=Severity.ERROR,
                    message=("Kubernetes API certificate verification is disabled"),
                    evidence=("Detected enabled `--insecure-skip-tls-verify`."),
                )
            )

        credential = _literal_credential(invocation)

        if credential is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-002",
                    severity=Severity.ERROR,
                    message=("kubectl command contains a literal credential"),
                    evidence=(
                        f"Detected a literal value passed through `{credential}`."
                    ),
                )
            )

        if _mutates_all_namespaces(invocation):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-003",
                    severity=Severity.ERROR,
                    message=("Mutation targets every Kubernetes namespace"),
                    evidence=(
                        "Detected a mutating command with `--all-namespaces` or `-A`."
                    ),
                )
            )

        delete_target = _delete_target(invocation)

        if delete_target is not None:
            resource = delete_target.lower().split("/", maxsplit=1)[0]
            severity = (
                Severity.ERROR if resource in _SENSITIVE_RESOURCES else Severity.WARNING
            )
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-004",
                    severity=severity,
                    message=("kubectl command deletes Kubernetes resources"),
                    evidence=(f"Detected deletion target: {delete_target}."),
                )
            )

        force_reason = _force_reason(invocation)

        if force_reason is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-005",
                    severity=Severity.ERROR,
                    message=("kubectl command bypasses graceful safety controls"),
                    evidence=force_reason,
                )
            )

        if _selects_all_resources(invocation):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-006",
                    severity=Severity.ERROR,
                    message=("Mutation selects all matching Kubernetes resources"),
                    evidence=(
                        "Detected `--all` or an `all` resource "
                        "operand on a mutating command."
                    ),
                )
            )

        if _writes_without_dry_run(invocation):
            replacement = shlex.join((*result.tokens, "--dry-run=server"))
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-007",
                    severity=Severity.WARNING,
                    message=("kubectl mutation has no dry-run preview"),
                    evidence=(
                        f"Detected `{invocation.command}` without "
                        "`--dry-run=client` or `--dry-run=server`."
                    ),
                    repair=RepairSuggestion(
                        replacement_text=replacement,
                        rationale=(
                            "A server-side dry run validates the "
                            "request without persisting it."
                        ),
                        confidence=RepairConfidence.LOW,
                    ),
                )
            )

        if invocation.command == "apply" and _flag_enabled(
            invocation.all_arguments,
            option="--force-conflicts",
        ):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-008",
                    severity=Severity.ERROR,
                    message=("Server-side apply forcibly overrides field conflicts"),
                    evidence=("Detected enabled `--force-conflicts`."),
                )
            )

        if _interactive_session(invocation):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-009",
                    severity=Severity.WARNING,
                    message=("kubectl command opens an interactive cluster session"),
                    evidence=("Detected interactive stdin or TTY options."),
                )
            )

        secret_problem = _literal_secret_problem(invocation)

        if secret_problem is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-010",
                    severity=Severity.ERROR,
                    message=("kubectl command contains a literal secret value"),
                    evidence=secret_problem,
                )
            )

        image = _mutable_image(invocation)

        if image is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-011",
                    severity=Severity.WARNING,
                    message=("Kubernetes workload image is not pinned by digest"),
                    evidence=(
                        "Detected a mutable image reference "
                        f"without a full SHA-256 digest: {image}."
                    ),
                )
            )

        privilege_reason = _privileged_reason(invocation)

        if privilege_reason is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-012",
                    severity=Severity.ERROR,
                    message=("kubectl command creates privileged workload access"),
                    evidence=privilege_reason,
                )
            )

        validation = _disabled_validation(invocation)

        if validation is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-013",
                    severity=Severity.WARNING,
                    message=("Kubernetes object schema validation is disabled"),
                    evidence=(f"Detected disabled validation value: {validation}."),
                )
            )

        raw_uri = _first_option_value(
            invocation.all_arguments,
            options=("--raw",),
        )

        if raw_uri is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-KUBECTL-014",
                    severity=Severity.WARNING,
                    message=("kubectl command accesses a raw Kubernetes API path"),
                    evidence=f"Detected raw API URI: {raw_uri}.",
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
    """Create one deterministic kubectl finding."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=evidence,
                source="RunbookProof kubectl pack",
            ),
        ),
        repair=repair,
    )


def _parse_invocation(
    result: ShellParseResult,
) -> _Invocation | None:
    """Normalize a kubectl command and selected subcommands."""
    if result.command.executable != "kubectl":
        return None

    arguments = result.command.arguments
    command, remaining = _split_command(
        arguments,
        options_with_values=_GLOBAL_OPTIONS_WITH_VALUES,
    )

    if command is None:
        return None

    if command not in _NESTED_GROUPS:
        return _Invocation(
            command=command,
            arguments=remaining,
            all_arguments=arguments,
        )

    nested, nested_arguments = _split_command(
        remaining,
        options_with_values=_COMMAND_OPTIONS_WITH_VALUES,
    )

    if nested is None:
        return _Invocation(
            command=command,
            arguments=remaining,
            all_arguments=arguments,
        )

    normalized = f"{command}-{nested}"
    final_arguments = nested_arguments

    if command == "create" and nested == "secret":
        secret_type, secret_arguments = _split_command(
            nested_arguments,
            options_with_values=_COMMAND_OPTIONS_WITH_VALUES,
        )

        if secret_type is not None:
            normalized = f"create-secret-{secret_type}"
            final_arguments = secret_arguments

    return _Invocation(
        command=normalized,
        arguments=final_arguments,
        all_arguments=arguments,
    )


def _split_command(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> tuple[str | None, tuple[str, ...]]:
    """Separate leading options from a command name."""
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


def _is_help_request(invocation: _Invocation) -> bool:
    """Return whether the command only requests help or version data."""
    if invocation.command in {
        "help",
        "options",
        "version",
    }:
        return True

    return any(
        argument
        in {
            "-h",
            "--help",
        }
        for argument in invocation.all_arguments
    )


def _literal_credential(invocation: _Invocation) -> str | None:
    """Return one credential option containing a literal value."""
    for option in (
        "--password",
        "--token",
    ):
        values = _option_values(
            invocation.all_arguments,
            options=(option,),
        )

        if any(_is_literal_secret(value) for value in values):
            return option

    return None


def _mutates_all_namespaces(invocation: _Invocation) -> bool:
    """Return whether a mutation targets every namespace."""
    if not _is_mutating(invocation.command):
        return False

    return _has_option(
        invocation.all_arguments,
        option="--all-namespaces",
    ) or _short_flag_present(
        invocation.all_arguments,
        flag="A",
    )


def _is_mutating(command: str) -> bool:
    """Return whether the normalized command changes cluster state."""
    return (
        command in _MUTATING_COMMANDS
        or command.startswith("create-")
        or command.startswith("rollout-")
        or command.startswith("set-")
    )


def _delete_target(invocation: _Invocation) -> str | None:
    """Return the main resource target of a delete command."""
    if invocation.command != "delete":
        return None

    return (
        _first_operand(
            invocation.arguments,
            options_with_values=_COMMAND_OPTIONS_WITH_VALUES,
        )
        or "manifest-selected resources"
    )


def _force_reason(invocation: _Invocation) -> str | None:
    """Return evidence for forced or immediate mutations."""
    if invocation.command not in {
        "apply",
        "delete",
        "replace",
    }:
        return None

    if _flag_enabled(
        invocation.all_arguments,
        option="--force",
    ):
        return "Detected an enabled `--force` option."

    if _flag_enabled(
        invocation.all_arguments,
        option="--now",
    ):
        return "Detected immediate deletion through `--now`."

    grace_period = _first_option_value(
        invocation.all_arguments,
        options=("--grace-period",),
    )

    if grace_period == "0":
        return "Detected a zero-second deletion grace period."

    return None


def _selects_all_resources(invocation: _Invocation) -> bool:
    """Return whether a mutation selects all matching resources."""
    if not _is_mutating(invocation.command):
        return False

    if _flag_enabled(
        invocation.all_arguments,
        option="--all",
    ):
        return True

    target = _first_operand(
        invocation.arguments,
        options_with_values=_COMMAND_OPTIONS_WITH_VALUES,
    )

    if target is None:
        return False

    return target.lower().split("/", maxsplit=1)[0] == "all"


def _writes_without_dry_run(invocation: _Invocation) -> bool:
    """Return whether a mutation has no dry-run preview."""
    recommends_dry_run = (
        invocation.command in _DRY_RUN_COMMANDS
        or invocation.command.startswith("create-")
    )

    if not recommends_dry_run:
        return False

    values = _option_values(
        invocation.all_arguments,
        options=("--dry-run",),
    )

    if not values:
        return True

    return all(
        value.lower()
        in {
            "",
            "false",
            "none",
        }
        for value in values
    )


def _interactive_session(invocation: _Invocation) -> bool:
    """Return whether the command requests stdin or a TTY."""
    if invocation.command not in _INTERACTIVE_COMMANDS:
        return False

    return (
        _has_option(
            invocation.all_arguments,
            option="--stdin",
        )
        or _has_option(
            invocation.all_arguments,
            option="--tty",
        )
        or _short_flag_present(
            invocation.all_arguments,
            flag="i",
        )
        or _short_flag_present(
            invocation.all_arguments,
            flag="t",
        )
    )


def _literal_secret_problem(
    invocation: _Invocation,
) -> str | None:
    """Return evidence for literal secret material in arguments."""
    if invocation.command.startswith("create-secret-"):
        values = _option_values(
            invocation.all_arguments,
            options=("--from-literal",),
        )

        for value in values:
            if "=" not in value:
                continue

            name, secret = value.split("=", maxsplit=1)

            if _is_literal_secret(secret):
                return f"Detected a literal Kubernetes Secret value for `{name}`."

    if invocation.command == "set-env":
        for argument in invocation.arguments:
            problem = _sensitive_assignment_problem(argument)

            if problem is not None:
                return problem

    if invocation.command == "run":
        values = _option_values(
            invocation.all_arguments,
            options=("--env",),
        )

        for value in values:
            problem = _sensitive_assignment_problem(value)

            if problem is not None:
                return problem

    return None


def _sensitive_assignment_problem(
    assignment: str,
) -> str | None:
    """Return evidence for a sensitive literal assignment."""
    if "=" not in assignment:
        return None

    name, value = assignment.split("=", maxsplit=1)

    if not _SECRET_NAME_PATTERN.search(name):
        return None

    if not _is_literal_secret(value):
        return None

    return f"Detected a literal value for sensitive variable `{name}`."


def _mutable_image(invocation: _Invocation) -> str | None:
    """Return a workload image that lacks an immutable digest."""
    images: list[str] = []

    if invocation.command == "set-image":
        for argument in invocation.arguments:
            if argument.startswith("-") or "=" not in argument:
                continue

            _, image = argument.split("=", maxsplit=1)
            images.append(image)

    if invocation.command in {
        "create-cronjob",
        "create-deployment",
        "create-job",
        "debug",
        "run",
    }:
        images.extend(
            _option_values(
                invocation.all_arguments,
                options=("--image",),
            )
        )

    for image in images:
        if _DIGEST_PATTERN.search(image) is None:
            return image

    return None


def _privileged_reason(invocation: _Invocation) -> str | None:
    """Return evidence for privileged debugging or pod overrides."""
    profile = _first_option_value(
        invocation.all_arguments,
        options=("--profile",),
    )

    if (
        invocation.command == "debug"
        and profile is not None
        and profile.lower() == "sysadmin"
    ):
        return "Detected the privileged kubectl debug `sysadmin` profile."

    overrides = _option_values(
        invocation.all_arguments,
        options=("--overrides",),
    )

    if any(_PRIVILEGED_OVERRIDE_PATTERN.search(value) for value in overrides):
        return (
            "Detected privileged or host-namespace settings inside `--overrides` JSON."
        )

    return None


def _disabled_validation(invocation: _Invocation) -> str | None:
    """Return a value that disables object schema validation."""
    values = _option_values(
        invocation.all_arguments,
        options=("--validate",),
    )

    for value in values:
        if value.lower() in {
            "false",
            "ignore",
        }:
            return value

    return None


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
            option = argument.split("=", maxsplit=1)[0]

            if option in options_with_values and "=" not in argument:
                index += 2
            else:
                index += 1

            continue

        return argument

    return None


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


def _has_option(
    arguments: tuple[str, ...],
    *,
    option: str,
) -> bool:
    """Return whether arguments contain one long option."""
    return any(
        argument == option or argument.startswith(f"{option}=")
        for argument in arguments
    )


def _short_flag_present(
    arguments: tuple[str, ...],
    *,
    flag: str,
) -> bool:
    """Return whether a short-option token contains one flag."""
    return any(
        argument.startswith("-")
        and not argument.startswith("--")
        and flag in argument[1:]
        for argument in arguments
    )

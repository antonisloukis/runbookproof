"""Static verification for Terraform CLI commands."""

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
        "-chdir",
    }
)

_COMMAND_OPTIONS_WITH_VALUES = frozenset(
    {
        "-backup",
        "-backend-config",
        "-input",
        "-json",
        "-lock",
        "-lock-timeout",
        "-out",
        "-parallelism",
        "-refresh",
        "-replace",
        "-state",
        "-state-out",
        "-target",
        "-var",
        "-var-file",
    }
)

_STATE_COMMANDS = frozenset(
    {
        "list",
        "mv",
        "pull",
        "push",
        "replace-provider",
        "rm",
        "show",
    }
)

_WORKSPACE_COMMANDS = frozenset(
    {
        "delete",
        "list",
        "new",
        "select",
        "show",
    }
)

_MUTATING_STATE_COMMANDS = frozenset(
    {
        "state-mv",
        "state-push",
        "state-replace-provider",
        "state-rm",
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


@dataclass(frozen=True, slots=True)
class _Invocation:
    """Describe one normalized Terraform invocation."""

    command: str
    arguments: tuple[str, ...]
    all_arguments: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _StateMutation:
    """Describe one manual Terraform state operation."""

    severity: Severity
    message: str
    evidence: str


class TerraformPack:
    """Detect dangerous and non-reviewable Terraform commands."""

    name = "terraform"

    def supports(self, result: ShellParseResult) -> bool:
        """Support successfully parsed Terraform CLI commands."""
        return (
            result.error is None
            and result.command.executable == "terraform"
            and _parse_invocation(result) is not None
        )

    def verify(
        self,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Return deterministic findings for one Terraform command."""
        if result.error is not None:
            return ()

        invocation = _parse_invocation(result)

        if invocation is None or _is_help_request(invocation):
            return ()

        findings: list[Finding] = []

        if _unreviewed_auto_approval(invocation):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-001",
                    severity=Severity.ERROR,
                    message=(
                        "Terraform changes are automatically approved "
                        "without a saved plan"
                    ),
                    evidence=(
                        "Detected `-auto-approve` on an apply or destroy "
                        "operation that does not consume a saved plan."
                    ),
                )
            )

        if _destroy_mode(invocation):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-002",
                    severity=Severity.ERROR,
                    message="Terraform command destroys managed infrastructure",
                    evidence=("Detected Terraform destroy planning or execution mode."),
                )
            )

        if _direct_apply_without_saved_plan(invocation):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-003",
                    severity=Severity.WARNING,
                    message=("Terraform apply generates a new plan at execution time"),
                    evidence=("Detected `terraform apply` without a saved plan file."),
                )
            )

        scope_options = _selective_scope_options(invocation)

        if scope_options:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-004",
                    severity=Severity.WARNING,
                    message=(
                        "Terraform operation uses targeted or forced resource scope"
                    ),
                    evidence=(
                        "Detected selective resource options: "
                        f"{', '.join(scope_options)}."
                    ),
                )
            )

        if _state_locking_disabled(invocation):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-005",
                    severity=Severity.ERROR,
                    message="Terraform state locking is disabled",
                    evidence="Detected `-lock=false`.",
                )
            )

        if invocation.command == "force-unlock":
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-006",
                    severity=Severity.ERROR,
                    message="Terraform state lock is forcibly removed",
                    evidence=(
                        "Detected `terraform force-unlock`, which can permit "
                        "multiple writers to modify state."
                    ),
                )
            )

        state_mutation = _state_mutation(invocation)

        if state_mutation is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-007",
                    severity=state_mutation.severity,
                    message=state_mutation.message,
                    evidence=state_mutation.evidence,
                )
            )

        if invocation.command == "state-push" and _flag_enabled(
            invocation.all_arguments,
            option="-force",
        ):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-008",
                    severity=Severity.ERROR,
                    message=(
                        "Terraform state push disables remote state safety checks"
                    ),
                    evidence=("Detected `terraform state push -force`."),
                )
            )

        secret_problem = _literal_secret_problem(
            result,
            invocation,
        )

        if secret_problem is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-009",
                    severity=Severity.ERROR,
                    message=("Terraform command contains a literal secret value"),
                    evidence=secret_problem,
                )
            )

        exposure = _sensitive_output_exposure(invocation)

        if exposure is not None:
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-010",
                    severity=Severity.WARNING,
                    message=(
                        "Terraform command exposes potentially sensitive "
                        "state or output data"
                    ),
                    evidence=exposure,
                )
            )

        if invocation.command == "refresh":
            replacement = shlex.join(
                (
                    "terraform",
                    "apply",
                    "-refresh-only",
                    *invocation.arguments,
                )
            )
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-011",
                    severity=Severity.WARNING,
                    message="Terraform refresh command is deprecated",
                    evidence=("Detected the legacy `terraform refresh` command."),
                    repair=RepairSuggestion(
                        replacement_text=replacement,
                        rationale=(
                            "Refresh-only apply allows detected state "
                            "changes to be reviewed before confirmation."
                        ),
                        confidence=RepairConfidence.LOW,
                    ),
                )
            )

        if invocation.command == "init" and _flag_enabled(
            invocation.all_arguments,
            option="-upgrade",
        ):
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-012",
                    severity=Severity.WARNING,
                    message=("Terraform initialization upgrades dependency selections"),
                    evidence=(
                        "Detected `terraform init -upgrade`, which may "
                        "select newer provider or module versions."
                    ),
                )
            )

        if invocation.command == "workspace-delete":
            workspace = _first_operand(
                invocation.arguments,
                options_with_values=_COMMAND_OPTIONS_WITH_VALUES,
            )
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-013",
                    severity=Severity.WARNING,
                    message="Terraform workspace is deleted",
                    evidence=(
                        "Detected deletion of Terraform workspace"
                        f"{f' `{workspace}`' if workspace else ''}."
                    ),
                )
            )

        if invocation.command == "import":
            findings.append(
                _finding(
                    result,
                    rule_id="RBP-TERRAFORM-014",
                    severity=Severity.WARNING,
                    message=("Terraform import modifies resource state directly"),
                    evidence=(
                        "Detected `terraform import`, which associates an "
                        "existing remote object with Terraform state."
                    ),
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
    """Create one deterministic Terraform finding."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=evidence,
                source="RunbookProof Terraform pack",
            ),
        ),
        repair=repair,
    )


def _parse_invocation(
    result: ShellParseResult,
) -> _Invocation | None:
    """Normalize Terraform commands and nested subcommands."""
    if result.command.executable != "terraform":
        return None

    arguments = result.command.arguments
    command, remaining = _split_command(
        arguments,
        options_with_values=_GLOBAL_OPTIONS_WITH_VALUES,
    )

    if command is None:
        return None

    if command == "state":
        nested, nested_arguments = _split_command(
            remaining,
            options_with_values=frozenset(),
        )

        if nested is None or nested not in _STATE_COMMANDS:
            return _Invocation(
                command=command,
                arguments=remaining,
                all_arguments=arguments,
            )

        return _Invocation(
            command=f"state-{nested}",
            arguments=nested_arguments,
            all_arguments=arguments,
        )

    if command == "workspace":
        nested, nested_arguments = _split_command(
            remaining,
            options_with_values=frozenset(),
        )

        if nested is None or nested not in _WORKSPACE_COMMANDS:
            return _Invocation(
                command=command,
                arguments=remaining,
                all_arguments=arguments,
            )

        return _Invocation(
            command=f"workspace-{nested}",
            arguments=nested_arguments,
            all_arguments=arguments,
        )

    return _Invocation(
        command=command,
        arguments=remaining,
        all_arguments=arguments,
    )


def _split_command(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> tuple[str | None, tuple[str, ...]]:
    """Separate leading options from a Terraform command."""
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
    """Return whether the invocation only requests help or version data."""
    if invocation.command in {
        "help",
        "version",
    }:
        return True

    return any(
        argument
        in {
            "-help",
            "--help",
            "-version",
            "--version",
        }
        for argument in invocation.all_arguments
    )


def _unreviewed_auto_approval(
    invocation: _Invocation,
) -> bool:
    """Return whether Terraform bypasses approval without a plan file."""
    if invocation.command not in {
        "apply",
        "destroy",
    }:
        return False

    if not _flag_enabled(
        invocation.all_arguments,
        option="-auto-approve",
    ):
        return False

    if invocation.command == "destroy":
        return True

    return _saved_plan_file(invocation) is None


def _destroy_mode(invocation: _Invocation) -> bool:
    """Return whether Terraform is planning or executing destruction."""
    if invocation.command == "destroy":
        return True

    if invocation.command not in {
        "apply",
        "plan",
    }:
        return False

    return _flag_enabled(
        invocation.all_arguments,
        option="-destroy",
    )


def _direct_apply_without_saved_plan(
    invocation: _Invocation,
) -> bool:
    """Return whether apply creates and executes a fresh plan."""
    if invocation.command != "apply":
        return False

    if _flag_enabled(
        invocation.all_arguments,
        option="-destroy",
    ):
        return False

    return _saved_plan_file(invocation) is None


def _saved_plan_file(
    invocation: _Invocation,
) -> str | None:
    """Return the saved plan supplied to terraform apply."""
    if invocation.command != "apply":
        return None

    return _first_operand(
        invocation.arguments,
        options_with_values=_COMMAND_OPTIONS_WITH_VALUES,
    )


def _selective_scope_options(
    invocation: _Invocation,
) -> tuple[str, ...]:
    """Return targeted resource-selection options."""
    if invocation.command not in {
        "apply",
        "destroy",
        "plan",
    }:
        return ()

    selections: list[str] = []

    for option in (
        "-target",
        "-replace",
    ):
        for value in _option_values(
            invocation.all_arguments,
            options=(option,),
        ):
            selection = f"{option}={value}"

            if selection not in selections:
                selections.append(selection)

    return tuple(selections)


def _state_locking_disabled(
    invocation: _Invocation,
) -> bool:
    """Return whether state locking is explicitly disabled."""
    values = _option_values(
        invocation.all_arguments,
        options=("-lock",),
    )

    return any(
        value.lower()
        in {
            "0",
            "false",
            "no",
        }
        for value in values
    )


def _state_mutation(
    invocation: _Invocation,
) -> _StateMutation | None:
    """Return details for one manual state modification."""
    if invocation.command not in _MUTATING_STATE_COMMANDS:
        return None

    if invocation.command == "state-rm" and _flag_enabled(
        invocation.all_arguments,
        option="-dry-run",
    ):
        return None

    if invocation.command == "state-push":
        return _StateMutation(
            severity=Severity.ERROR,
            message="Terraform state is overwritten manually",
            evidence=(
                "Detected `terraform state push`, which writes a local "
                "state snapshot to the configured backend."
            ),
        )

    if invocation.command == "state-rm":
        return _StateMutation(
            severity=Severity.ERROR,
            message="Terraform stops managing selected resources",
            evidence=("Detected `terraform state rm` without `-dry-run`."),
        )

    if invocation.command == "state-mv":
        return _StateMutation(
            severity=Severity.WARNING,
            message="Terraform resource bindings are moved manually",
            evidence="Detected `terraform state mv`.",
        )

    return _StateMutation(
        severity=Severity.WARNING,
        message="Terraform state provider bindings are replaced",
        evidence="Detected `terraform state replace-provider`.",
    )


def _literal_secret_problem(
    result: ShellParseResult,
    invocation: _Invocation,
) -> str | None:
    """Return evidence for literal secrets in Terraform arguments."""
    for assignment in result.assignments:
        if "=" not in assignment:
            continue

        name, value = assignment.split("=", maxsplit=1)

        if not name.startswith("TF_VAR_"):
            continue

        variable_name = name.removeprefix("TF_VAR_")

        if _is_sensitive_name(variable_name) and _is_literal_secret(value):
            return (
                "Detected a literal secret in Terraform environment "
                f"assignment `{name}`."
            )

    for option in (
        "-var",
        "-backend-config",
    ):
        values = _option_values(
            invocation.all_arguments,
            options=(option,),
        )

        for assignment in values:
            if "=" not in assignment:
                continue

            name, value = assignment.split("=", maxsplit=1)

            if _is_sensitive_name(name) and _is_literal_secret(value):
                return (
                    "Detected a literal secret in Terraform option "
                    f"`{option}` for `{name}`."
                )

    return None


def _is_sensitive_name(name: str) -> bool:
    """Return whether a variable name appears credential-related."""
    normalized = re.sub(
        r"[^A-Za-z0-9]+",
        "_",
        name,
    )

    return _SECRET_NAME_PATTERN.search(normalized) is not None


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
            "vault://",
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


def _sensitive_output_exposure(
    invocation: _Invocation,
) -> str | None:
    """Return evidence for raw state, plan, or output exposure."""
    if invocation.command == "state-pull":
        return (
            "Detected `terraform state pull`, which writes raw state "
            "content to standard output."
        )

    if invocation.command == "show" and _has_option(
        invocation.all_arguments,
        option="-json",
    ):
        return "Detected JSON rendering of Terraform state or a saved plan."

    if invocation.command == "output" and (
        _has_option(
            invocation.all_arguments,
            option="-json",
        )
        or _has_option(
            invocation.all_arguments,
            option="-raw",
        )
    ):
        return "Detected raw or JSON rendering of Terraform output values."

    return None


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


def _option_values(
    arguments: tuple[str, ...],
    *,
    options: tuple[str, ...],
) -> tuple[str, ...]:
    """Return values assigned to selected Terraform options."""
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
    """Return whether a Terraform Boolean option is enabled."""
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
    """Return whether arguments contain one Terraform option."""
    return any(
        argument == option or argument.startswith(f"{option}=")
        for argument in arguments
    )

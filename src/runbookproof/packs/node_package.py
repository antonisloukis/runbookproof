"""Static verification for npm, pnpm, Yarn, npx, and pnpx commands."""

from __future__ import annotations

import shlex

from runbookproof.models import (
    Evidence,
    EvidenceKind,
    Finding,
    RepairConfidence,
    RepairSuggestion,
    Severity,
    ShellParseResult,
)

_SUPPORTED_EXECUTABLES = frozenset(
    {
        "npm",
        "npx",
        "pnpm",
        "pnpx",
        "yarn",
        "yarnpkg",
    }
)

_INSTALL_SUBCOMMANDS = frozenset(
    {
        "add",
        "i",
        "install",
    }
)

_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--cache",
        "--prefix",
        "--registry",
        "--userconfig",
        "--workspace",
        "-C",
        "-c",
    }
)

_INSTALL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--cache",
        "--filter",
        "--omit",
        "--prefix",
        "--registry",
        "--workspace",
        "-C",
        "-c",
        "-w",
    }
)

_RUNNER_OPTIONS_WITH_VALUES = frozenset(
    {
        "--call",
        "--cache",
        "--package",
        "--registry",
        "--userconfig",
        "-c",
        "-p",
    }
)

_MUTABLE_PACKAGE_TAGS = frozenset(
    {
        "beta",
        "canary",
        "latest",
        "next",
        "nightly",
        "rc",
    }
)


class NodePackagePack:
    """Detect risky Node.js package-manager documentation patterns."""

    name = "node-package"

    def supports(self, result: ShellParseResult) -> bool:
        """Support successfully parsed Node package-manager commands."""
        return (
            result.error is None and result.command.executable in _SUPPORTED_EXECUTABLES
        )

    def verify(
        self,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Return deterministic findings for one package-manager command."""
        manager = result.command.executable

        if result.error is not None or manager not in _SUPPORTED_EXECUTABLES:
            return ()

        arguments = result.command.arguments

        if _is_help_request(arguments):
            return ()

        subcommand, subcommand_arguments = _split_subcommand(arguments)
        findings: list[Finding] = []

        transport_problem = _transport_security_problem(
            manager,
            subcommand,
            subcommand_arguments,
            arguments,
        )

        if transport_problem is not None:
            findings.append(
                _transport_security_finding(
                    result,
                    problem=transport_problem,
                )
            )

        package_spec = _runner_package_spec(
            manager,
            subcommand,
            subcommand_arguments,
            arguments,
        )

        if package_spec is not None and not _is_pinned_package_spec(package_spec):
            findings.append(
                _unpinned_execution_finding(
                    result,
                    package_spec=package_spec,
                )
            )

        if package_spec is not None and _suppresses_execution_confirmation(arguments):
            findings.append(
                _automatic_execution_finding(
                    result,
                    package_spec=package_spec,
                )
            )

        if _is_global_install(
            manager,
            subcommand,
            subcommand_arguments,
            arguments,
        ):
            findings.append(_global_install_finding(result))

        forced_option = _forced_resolution_option(arguments)

        if forced_option is not None:
            findings.append(
                _forced_resolution_finding(
                    result,
                    option=forced_option,
                )
            )

        reproducibility_problem = _reproducibility_problem(
            manager,
            subcommand,
            subcommand_arguments,
        )

        if reproducibility_problem is not None:
            findings.append(
                _reproducibility_finding(
                    result,
                    manager=manager,
                    problem=reproducibility_problem,
                )
            )

        lifecycle_option = _lifecycle_script_option(
            manager,
            subcommand,
            subcommand_arguments,
            arguments,
        )

        if lifecycle_option is not None:
            findings.append(
                _lifecycle_script_finding(
                    result,
                    option=lifecycle_option,
                )
            )

        security_option = _disabled_security_check(
            manager,
            subcommand,
            subcommand_arguments,
            arguments,
        )

        if security_option is not None:
            findings.append(
                _disabled_security_check_finding(
                    result,
                    option=security_option,
                )
            )

        if (
            manager == "npm"
            and subcommand in _INSTALL_SUBCOMMANDS
            and "--save" in subcommand_arguments
        ):
            findings.append(_legacy_save_finding(result))

        return tuple(findings)


def _transport_security_finding(
    result: ShellParseResult,
    *,
    problem: str,
) -> Finding:
    """Create an error for disabled package transport security."""
    return Finding(
        rule_id="RBP-NODE-001",
        severity=Severity.ERROR,
        message="Package manager disables transport security",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=problem,
                source="RunbookProof Node package pack",
            ),
        ),
    )


def _unpinned_execution_finding(
    result: ShellParseResult,
    *,
    package_spec: str,
) -> Finding:
    """Create a warning for executing an unpinned registry package."""
    return Finding(
        rule_id="RBP-NODE-002",
        severity=Severity.WARNING,
        message="Executed package does not specify a version",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected package execution without a stable "
                    f"version: {package_spec}."
                ),
                source="RunbookProof Node package pack",
            ),
        ),
    )


def _automatic_execution_finding(
    result: ShellParseResult,
    *,
    package_spec: str,
) -> Finding:
    """Create a warning when package execution skips confirmation."""
    return Finding(
        rule_id="RBP-NODE-003",
        severity=Severity.WARNING,
        message="Package execution suppresses confirmation",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected automatic confirmation while executing "
                    f"package: {package_spec}."
                ),
                source="RunbookProof Node package pack",
            ),
        ),
    )


def _global_install_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a warning for global package installation."""
    return Finding(
        rule_id="RBP-NODE-004",
        severity=Severity.WARNING,
        message="Command installs a package globally",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected a global package installation. Global "
                    "state can reduce reproducibility."
                ),
                source="RunbookProof Node package pack",
            ),
        ),
    )


def _forced_resolution_finding(
    result: ShellParseResult,
    *,
    option: str,
) -> Finding:
    """Create a warning for forced dependency resolution."""
    return Finding(
        rule_id="RBP-NODE-005",
        severity=Severity.WARNING,
        message="Dependency safety checks are bypassed",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=f"Detected dependency override option: {option}.",
                source="RunbookProof Node package pack",
            ),
        ),
    )


def _reproducibility_finding(
    result: ShellParseResult,
    *,
    manager: str,
    problem: str,
) -> Finding:
    """Create a warning for a non-reproducible installation."""
    repair: RepairSuggestion | None = None

    if (
        manager == "npm"
        and problem == "npm install without packages may modify the lockfile."
    ):
        repair = RepairSuggestion(
            replacement_text="npm ci",
            rationale=(
                "`npm ci` installs directly from the lockfile and "
                "is normally more appropriate for CI environments."
            ),
            confidence=RepairConfidence.LOW,
        )

    return Finding(
        rule_id="RBP-NODE-006",
        severity=Severity.WARNING,
        message="Dependency installation may not be reproducible",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=problem,
                source="RunbookProof Node package pack",
            ),
        ),
        repair=repair,
    )


def _lifecycle_script_finding(
    result: ShellParseResult,
    *,
    option: str,
) -> Finding:
    """Create a warning for explicitly enabled lifecycle scripts."""
    return Finding(
        rule_id="RBP-NODE-007",
        severity=Severity.WARNING,
        message="Package lifecycle scripts are explicitly enabled",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected an option or configuration that enables "
                    f"package lifecycle execution: {option}."
                ),
                source="RunbookProof Node package pack",
            ),
        ),
    )


def _disabled_security_check_finding(
    result: ShellParseResult,
    *,
    option: str,
) -> Finding:
    """Create a warning when package security checks are disabled."""
    return Finding(
        rule_id="RBP-NODE-008",
        severity=Severity.WARNING,
        message="Package security checks are disabled",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=f"Detected disabled security check: {option}.",
                source="RunbookProof Node package pack",
            ),
        ),
    )


def _legacy_save_finding(
    result: ShellParseResult,
) -> Finding:
    """Create an informational repair for redundant npm --save."""
    replacement_tokens = tuple(token for token in result.tokens if token != "--save")

    return Finding(
        rule_id="RBP-NODE-009",
        severity=Severity.INFO,
        message="npm --save is redundant in modern npm",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message="Detected the legacy npm `--save` option.",
                source="RunbookProof Node package pack",
            ),
        ),
        repair=RepairSuggestion(
            replacement_text=shlex.join(replacement_tokens),
            rationale=("Modern npm saves installed dependencies by default."),
            confidence=RepairConfidence.MEDIUM,
        ),
    )


def _split_subcommand(
    arguments: tuple[str, ...],
) -> tuple[str | None, tuple[str, ...]]:
    """Separate package-manager global options from its subcommand."""
    index = 0

    while index < len(arguments):
        argument = arguments[index]

        if argument == "--":
            index += 1
            break

        if not argument.startswith("-"):
            return argument, arguments[index + 1 :]

        option_name = argument.split("=", maxsplit=1)[0]

        if option_name in _GLOBAL_OPTIONS_WITH_VALUES and "=" not in argument:
            index += 2
        else:
            index += 1

    if index < len(arguments):
        return arguments[index], arguments[index + 1 :]

    return None, ()


def _is_help_request(arguments: tuple[str, ...]) -> bool:
    """Return whether the command only requests help or version data."""
    return any(
        argument
        in {
            "-h",
            "--help",
            "-v",
            "--version",
        }
        for argument in arguments
    )


def _transport_security_problem(
    manager: str,
    subcommand: str | None,
    subcommand_arguments: tuple[str, ...],
    arguments: tuple[str, ...],
) -> str | None:
    """Return evidence when TLS or registry security is disabled."""
    normalized_arguments = tuple(argument.lower() for argument in arguments)

    if any(
        argument
        in {
            "--strict-ssl=false",
            "--strict-ssl=0",
        }
        for argument in normalized_arguments
    ):
        return "Detected strict SSL verification set to false."

    if _contains_option_value(
        normalized_arguments,
        option="--strict-ssl",
        values=frozenset({"0", "false"}),
    ):
        return "Detected strict SSL verification set to false."

    if any(
        argument.startswith("--registry=http://") for argument in normalized_arguments
    ):
        return "Detected a package registry using unencrypted HTTP."

    if _contains_http_registry(normalized_arguments):
        return "Detected a package registry using unencrypted HTTP."

    normalized_subcommand_arguments = tuple(
        argument.lower() for argument in subcommand_arguments
    )

    if (
        manager in {"npm", "pnpm", "yarn", "yarnpkg"}
        and subcommand == "config"
        and normalized_subcommand_arguments[:3]
        == (
            "set",
            "strict-ssl",
            "false",
        )
    ):
        return "Detected package-manager configuration disabling SSL."

    return None


def _runner_package_spec(
    manager: str,
    subcommand: str | None,
    subcommand_arguments: tuple[str, ...],
    arguments: tuple[str, ...],
) -> str | None:
    """Return the registry package executed by a package runner."""
    if manager in {"npx", "pnpx"}:
        return _find_runner_package(arguments)

    if manager == "npm" and subcommand == "exec":
        return _find_runner_package(subcommand_arguments)

    if manager == "pnpm" and subcommand == "dlx":
        return _find_runner_package(subcommand_arguments)

    if manager in {"yarn", "yarnpkg"} and subcommand == "dlx":
        return _find_runner_package(subcommand_arguments)

    return None


def _find_runner_package(
    arguments: tuple[str, ...],
) -> str | None:
    """Find the package operand used by an execution command."""
    index = 0

    while index < len(arguments):
        argument = arguments[index]

        if argument == "--":
            index += 1

            if index < len(arguments):
                return arguments[index]

            return None

        if argument.startswith("--package="):
            return argument.split("=", maxsplit=1)[1]

        if argument in {"--package", "-p"}:
            next_index = index + 1

            if next_index < len(arguments):
                return arguments[next_index]

            return None

        if argument.startswith("-"):
            option_name = argument.split("=", maxsplit=1)[0]

            if option_name in _RUNNER_OPTIONS_WITH_VALUES and "=" not in argument:
                index += 2
            else:
                index += 1

            continue

        return argument

    return None


def _is_pinned_package_spec(package_spec: str) -> bool:
    """Return whether a registry package has an explicit stable version."""
    if package_spec.startswith(
        (
            ".",
            "/",
            "file:",
            "git+",
            "http://",
            "https://",
        )
    ):
        return True

    if package_spec.startswith("@"):
        slash_index = package_spec.find("/")

        if slash_index == -1:
            return False

        version_index = package_spec.rfind("@")

        if version_index <= slash_index:
            return False
    else:
        version_index = package_spec.rfind("@")

        if version_index <= 0:
            return False

    version = package_spec[version_index + 1 :].lower()

    return bool(version and version not in _MUTABLE_PACKAGE_TAGS)


def _suppresses_execution_confirmation(
    arguments: tuple[str, ...],
) -> bool:
    """Return whether package execution automatically confirms prompts."""
    return any(
        argument
        in {
            "--yes",
            "-y",
        }
        for argument in arguments
    )


def _is_global_install(
    manager: str,
    subcommand: str | None,
    subcommand_arguments: tuple[str, ...],
    arguments: tuple[str, ...],
) -> bool:
    """Return whether a command installs packages globally."""
    if (
        manager in {"npm", "pnpm"}
        and subcommand in _INSTALL_SUBCOMMANDS
        and _contains_global_flag(arguments)
    ):
        return True

    return (
        manager in {"yarn", "yarnpkg"}
        and subcommand == "global"
        and bool(subcommand_arguments)
        and subcommand_arguments[0] == "add"
    )


def _contains_global_flag(arguments: tuple[str, ...]) -> bool:
    """Return whether arguments contain a global-install option."""
    return any(
        argument
        in {
            "--global",
            "-g",
        }
        for argument in arguments
    )


def _forced_resolution_option(
    arguments: tuple[str, ...],
) -> str | None:
    """Return the first dependency-resolution override option."""
    for argument in arguments:
        if argument in {
            "--force",
            "-f",
            "--legacy-peer-deps",
        }:
            return argument

    return None


def _reproducibility_problem(
    manager: str,
    subcommand: str | None,
    arguments: tuple[str, ...],
) -> str | None:
    """Return evidence for package installations not locked exactly."""
    normalized_arguments = tuple(argument.lower() for argument in arguments)

    if (
        manager == "npm"
        and subcommand in {"i", "install"}
        and not _package_operands(arguments)
    ):
        return "npm install without packages may modify the lockfile."

    if (
        manager == "pnpm"
        and subcommand in {"i", "install"}
        and any(
            argument
            in {
                "--frozen-lockfile=false",
                "--no-frozen-lockfile",
            }
            for argument in normalized_arguments
        )
    ):
        return "pnpm frozen-lockfile enforcement is disabled."

    if (
        manager in {"yarn", "yarnpkg"}
        and subcommand == "install"
        and any(
            argument
            in {
                "--immutable=false",
                "--no-immutable",
            }
            for argument in normalized_arguments
        )
    ):
        return "Yarn immutable lockfile enforcement is disabled."

    if (
        manager == "npm"
        and subcommand in {"i", "install"}
        and any(
            argument
            in {
                "--no-package-lock",
                "--package-lock=false",
            }
            for argument in normalized_arguments
        )
    ):
        return "npm package-lock generation is disabled."

    return None


def _package_operands(
    arguments: tuple[str, ...],
) -> tuple[str, ...]:
    """Return package operands while skipping known option values."""
    operands: list[str] = []
    index = 0

    while index < len(arguments):
        argument = arguments[index]

        if argument == "--":
            operands.extend(arguments[index + 1 :])
            break

        if argument.startswith("-"):
            option_name = argument.split("=", maxsplit=1)[0]

            if option_name in _INSTALL_OPTIONS_WITH_VALUES and "=" not in argument:
                index += 2
            else:
                index += 1

            continue

        operands.append(argument)
        index += 1

    return tuple(operands)


def _lifecycle_script_option(
    manager: str,
    subcommand: str | None,
    subcommand_arguments: tuple[str, ...],
    arguments: tuple[str, ...],
) -> str | None:
    """Return an option explicitly enabling lifecycle execution."""
    normalized_arguments = tuple(argument.lower() for argument in arguments)

    for argument in normalized_arguments:
        if argument in {
            "--foreground-scripts",
            "--ignore-scripts=false",
            "--unsafe-perm",
            "--unsafe-perm=true",
        }:
            return argument

    normalized_subcommand_arguments = tuple(
        argument.lower() for argument in subcommand_arguments
    )

    if subcommand == "config" and normalized_subcommand_arguments[:3] == (
        "set",
        "ignore-scripts",
        "false",
    ):
        return f"{manager} config set ignore-scripts false"

    if (
        manager in {"yarn", "yarnpkg"}
        and subcommand == "config"
        and normalized_subcommand_arguments[:3]
        == (
            "set",
            "enablescripts",
            "true",
        )
    ):
        return "yarn config set enableScripts true"

    return None


def _disabled_security_check(
    manager: str,
    subcommand: str | None,
    subcommand_arguments: tuple[str, ...],
    arguments: tuple[str, ...],
) -> str | None:
    """Return an option disabling dependency security checks."""
    normalized_arguments = tuple(argument.lower() for argument in arguments)

    for argument in normalized_arguments:
        if argument in {
            "--audit=false",
            "--audit=0",
            "--no-audit",
        }:
            return argument

    normalized_subcommand_arguments = tuple(
        argument.lower() for argument in subcommand_arguments
    )

    if (
        manager == "npm"
        and subcommand == "config"
        and normalized_subcommand_arguments[:3]
        == (
            "set",
            "audit",
            "false",
        )
    ):
        return "npm config set audit false"

    return None


def _contains_option_value(
    arguments: tuple[str, ...],
    *,
    option: str,
    values: frozenset[str],
) -> bool:
    """Return whether one option is followed by a selected value."""
    for index, argument in enumerate(arguments):
        if argument != option:
            continue

        next_index = index + 1

        if next_index < len(arguments) and arguments[next_index] in values:
            return True

    return False


def _contains_http_registry(
    arguments: tuple[str, ...],
) -> bool:
    """Return whether --registry is followed by an HTTP URL."""
    for index, argument in enumerate(arguments):
        if argument != "--registry":
            continue

        next_index = index + 1

        if next_index < len(arguments) and arguments[next_index].startswith("http://"):
            return True

    return False

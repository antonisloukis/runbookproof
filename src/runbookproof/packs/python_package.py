"""Static verification for pip and uv package-management commands."""

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

_PIP_EXECUTABLES = frozenset({"pip", "pip3"})
_PYTHON_EXECUTABLES = frozenset(
    {
        "py",
        "python",
        "python3",
    }
)

_PIP_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--cache-dir",
        "--cert",
        "--client-cert",
        "--log",
        "--proxy",
        "--python",
        "--retries",
        "--timeout",
        "--trusted-host",
    }
)

_UV_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--allow-insecure-host",
        "--cache-dir",
        "--color",
        "--config-file",
        "--directory",
        "--index",
        "--managed-python",
        "--native-tls",
        "--offline",
        "--project",
        "--python",
        "--python-platform",
        "--trusted-host",
        "--working-directory",
    }
)

_INSTALL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--allow-insecure-host",
        "--build-constraint",
        "--cache-dir",
        "--cert",
        "--client-cert",
        "--config-settings",
        "--constraint",
        "--default-index",
        "--editable",
        "--extra-index-url",
        "--find-links",
        "--group",
        "--index",
        "--index-url",
        "--keyring-provider",
        "--only-binary",
        "--prefix",
        "--proxy",
        "--python",
        "--requirement",
        "--root",
        "--target",
        "--timeout",
        "--trusted-host",
        "--upgrade-strategy",
        "--userconfig",
        "-C",
        "-b",
        "-c",
        "-e",
        "-f",
        "-i",
        "-r",
        "-t",
    }
)

_REQUIREMENT_OPTIONS = frozenset(
    {
        "-r",
        "--requirement",
    }
)

_INSECURE_HOST_OPTIONS = frozenset(
    {
        "--allow-insecure-host",
        "--trusted-host",
    }
)

_INDEX_OPTIONS = frozenset(
    {
        "--default-index",
        "--extra-index-url",
        "--index",
        "--index-url",
    }
)

_HASH_DISABLE_OPTIONS = frozenset(
    {
        "--no-require-hashes",
        "--no-verify-hashes",
    }
)

_REMOTE_PREFIXES = (
    "git+",
    "http://",
    "https://",
)

_LOCAL_PREFIXES = (
    ".",
    "/",
    "~",
    "file:",
)

_ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".tgz",
    ".whl",
    ".zip",
)

_EXACT_PIN_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:\[[^\]]+\])?"
    r"(?:==|===)"
    r"([^;]+)"
)

_IMMUTABLE_GIT_REF_PATTERN = re.compile(r"@[0-9a-fA-F]{40}(?:#|$)")


@dataclass(frozen=True, slots=True)
class _Invocation:
    """Describe one normalized Python package-management command."""

    manager: str
    operation: str
    arguments: tuple[str, ...]
    all_arguments: tuple[str, ...]


class PythonPackagePack:
    """Detect insecure and non-reproducible Python package commands."""

    name = "python-package"

    def supports(self, result: ShellParseResult) -> bool:
        """Support successfully parsed pip, uv, and legacy commands."""
        return result.error is None and _parse_invocation(result) is not None

    def verify(
        self,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Return deterministic findings for one Python package command."""
        if result.error is not None:
            return ()

        invocation = _parse_invocation(result)

        if invocation is None or _is_help_request(invocation.all_arguments):
            return ()

        findings: list[Finding] = []

        transport_problem = _transport_security_problem(invocation.all_arguments)

        if transport_problem is not None:
            findings.append(
                _transport_security_finding(
                    result,
                    problem=transport_problem,
                )
            )

        unpinned_packages = _unpinned_packages(invocation)

        if unpinned_packages:
            findings.append(
                _unpinned_packages_finding(
                    result,
                    packages=unpinned_packages,
                )
            )

        remote_problem = _remote_source_problem(invocation)

        if remote_problem is not None:
            findings.append(
                _remote_source_finding(
                    result,
                    problem=remote_problem,
                )
            )

        system_option = _system_modification_option(invocation)

        if system_option is not None:
            findings.append(
                _system_modification_finding(
                    result,
                    option=system_option,
                )
            )

        requirements_file = _requirements_without_hashes(invocation)

        if requirements_file is not None:
            findings.append(
                _missing_hashes_finding(
                    result,
                    requirements_file=requirements_file,
                )
            )

        disabled_hash_option = _disabled_hash_option(invocation.all_arguments)

        if disabled_hash_option is not None:
            findings.append(
                _disabled_hashes_finding(
                    result,
                    option=disabled_hash_option,
                )
            )

        if _uv_sync_can_update_lockfile(invocation):
            findings.append(_mutable_uv_sync_finding(result))

        legacy_repair = _legacy_repair(invocation)

        if legacy_repair is not None:
            findings.append(
                _legacy_command_finding(
                    result,
                    repair=legacy_repair,
                )
            )

        return tuple(findings)


def _transport_security_finding(
    result: ShellParseResult,
    *,
    problem: str,
) -> Finding:
    """Create an error for insecure index or certificate behavior."""
    return Finding(
        rule_id="RBP-PYTHON-001",
        severity=Severity.ERROR,
        message="Python package transport security is disabled",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=problem,
                source="RunbookProof Python package pack",
            ),
        ),
    )


def _unpinned_packages_finding(
    result: ShellParseResult,
    *,
    packages: tuple[str, ...],
) -> Finding:
    """Create a warning for requirements without exact versions."""
    package_list = ", ".join(packages)

    return Finding(
        rule_id="RBP-PYTHON-002",
        severity=Severity.WARNING,
        message="Python package installation is not exactly pinned",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected package requirement"
                    f"{'s' if len(packages) != 1 else ''} without "
                    f"an exact version: {package_list}."
                ),
                source="RunbookProof Python package pack",
            ),
        ),
    )


def _remote_source_finding(
    result: ShellParseResult,
    *,
    problem: str,
) -> Finding:
    """Create a warning for mutable or unhashed remote sources."""
    return Finding(
        rule_id="RBP-PYTHON-003",
        severity=Severity.WARNING,
        message="Remote Python package source is not immutable",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=problem,
                source="RunbookProof Python package pack",
            ),
        ),
    )


def _system_modification_finding(
    result: ShellParseResult,
    *,
    option: str,
) -> Finding:
    """Create an error for modification of a managed Python."""
    return Finding(
        rule_id="RBP-PYTHON-004",
        severity=Severity.ERROR,
        message="Command can modify a system-managed Python installation",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected an option permitting system Python "
                    f"modification: {option}."
                ),
                source="RunbookProof Python package pack",
            ),
        ),
    )


def _missing_hashes_finding(
    result: ShellParseResult,
    *,
    requirements_file: str,
) -> Finding:
    """Create a warning for requirements without required hashes."""
    return Finding(
        rule_id="RBP-PYTHON-005",
        severity=Severity.WARNING,
        message="Requirements installation does not require hashes",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected requirements installation without "
                    f"`--require-hashes`: {requirements_file}."
                ),
                source="RunbookProof Python package pack",
            ),
        ),
    )


def _disabled_hashes_finding(
    result: ShellParseResult,
    *,
    option: str,
) -> Finding:
    """Create an error when available hash verification is disabled."""
    return Finding(
        rule_id="RBP-PYTHON-006",
        severity=Severity.ERROR,
        message="Package hash verification is disabled",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=f"Detected disabled hash verification: {option}.",
                source="RunbookProof Python package pack",
            ),
        ),
    )


def _mutable_uv_sync_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a warning when uv sync may update the lockfile."""
    replacement = shlex.join((*result.tokens, "--locked"))

    return Finding(
        rule_id="RBP-PYTHON-007",
        severity=Severity.WARNING,
        message="uv sync may update the project lockfile",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=("Detected `uv sync` without `--locked` or `--frozen`."),
                source="RunbookProof Python package pack",
            ),
        ),
        repair=RepairSuggestion(
            replacement_text=replacement,
            rationale=(
                "`--locked` prevents synchronization from changing "
                "the lockfile and fails when the lockfile is stale."
            ),
            confidence=RepairConfidence.LOW,
        ),
    )


def _legacy_command_finding(
    result: ShellParseResult,
    *,
    repair: RepairSuggestion,
) -> Finding:
    """Create an informational finding for legacy installers."""
    return Finding(
        rule_id="RBP-PYTHON-008",
        severity=Severity.INFO,
        message="Command uses a legacy Python installation interface",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=("Detected direct setuptools or easy_install usage."),
                source="RunbookProof Python package pack",
            ),
        ),
        repair=repair,
    )


def _parse_invocation(
    result: ShellParseResult,
) -> _Invocation | None:
    """Normalize supported package commands into one representation."""
    executable = result.command.executable
    arguments = result.command.arguments

    if executable in _PIP_EXECUTABLES:
        operation, remaining = _split_command(
            arguments,
            options_with_values=_PIP_GLOBAL_OPTIONS_WITH_VALUES,
        )

        if operation is None:
            return None

        return _Invocation(
            manager="pip",
            operation=f"pip-{operation}",
            arguments=remaining,
            all_arguments=arguments,
        )

    if executable == "uv":
        return _parse_uv_invocation(arguments)

    if executable == "easy_install":
        return _Invocation(
            manager="legacy",
            operation="easy-install",
            arguments=arguments,
            all_arguments=arguments,
        )

    if executable not in _PYTHON_EXECUTABLES:
        return None

    module_index = _find_module_pip(arguments)

    if module_index is not None:
        pip_arguments = arguments[module_index + 2 :]
        operation, remaining = _split_command(
            pip_arguments,
            options_with_values=_PIP_GLOBAL_OPTIONS_WITH_VALUES,
        )

        if operation is None:
            return None

        return _Invocation(
            manager="pip",
            operation=f"pip-{operation}",
            arguments=remaining,
            all_arguments=pip_arguments,
        )

    if (
        len(arguments) >= 2
        and arguments[0].endswith("setup.py")
        and arguments[1] in {"develop", "install"}
    ):
        return _Invocation(
            manager="legacy",
            operation=f"setup-{arguments[1]}",
            arguments=arguments[2:],
            all_arguments=arguments,
        )

    return None


def _parse_uv_invocation(
    arguments: tuple[str, ...],
) -> _Invocation | None:
    """Normalize one uv command."""
    operation, remaining = _split_command(
        arguments,
        options_with_values=_UV_GLOBAL_OPTIONS_WITH_VALUES,
    )

    if operation is None:
        return None

    if operation == "pip":
        pip_operation, pip_arguments = _split_command(
            remaining,
            options_with_values=_PIP_GLOBAL_OPTIONS_WITH_VALUES,
        )

        if pip_operation is None:
            return None

        return _Invocation(
            manager="uv",
            operation=f"uv-pip-{pip_operation}",
            arguments=pip_arguments,
            all_arguments=arguments,
        )

    if operation == "tool":
        tool_operation, tool_arguments = _split_command(
            remaining,
            options_with_values=_UV_GLOBAL_OPTIONS_WITH_VALUES,
        )

        if tool_operation is None:
            return None

        return _Invocation(
            manager="uv",
            operation=f"uv-tool-{tool_operation}",
            arguments=tool_arguments,
            all_arguments=arguments,
        )

    return _Invocation(
        manager="uv",
        operation=f"uv-{operation}",
        arguments=remaining,
        all_arguments=arguments,
    )


def _split_command(
    arguments: tuple[str, ...],
    *,
    options_with_values: frozenset[str],
) -> tuple[str | None, tuple[str, ...]]:
    """Separate leading global options from a command name."""
    index = 0

    while index < len(arguments):
        argument = arguments[index]

        if argument == "--":
            index += 1
            break

        if not argument.startswith("-"):
            return argument, arguments[index + 1 :]

        option_name = argument.split("=", maxsplit=1)[0]

        if option_name in options_with_values and "=" not in argument:
            index += 2
        else:
            index += 1

    if index < len(arguments):
        return arguments[index], arguments[index + 1 :]

    return None, ()


def _find_module_pip(
    arguments: tuple[str, ...],
) -> int | None:
    """Return the index of a `-m pip` module invocation."""
    for index, argument in enumerate(arguments[:-1]):
        if argument == "-m" and arguments[index + 1] == "pip":
            return index

    return None


def _is_help_request(
    arguments: tuple[str, ...],
) -> bool:
    """Return whether an invocation requests help or version data."""
    return any(
        argument
        in {
            "-h",
            "--help",
            "-V",
            "--version",
        }
        for argument in arguments
    )


def _transport_security_problem(
    arguments: tuple[str, ...],
) -> str | None:
    """Return evidence when certificate or index security is bypassed."""
    for index, argument in enumerate(arguments):
        option_name, inline_value = _split_option(argument)

        if option_name in _INSECURE_HOST_OPTIONS:
            host = inline_value

            if host is None and index + 1 < len(arguments):
                host = arguments[index + 1]

            return "Detected a trusted/insecure host bypass" + (
                f": {host}." if host else "."
            )

        if option_name not in _INDEX_OPTIONS:
            continue

        url = inline_value

        if url is None and index + 1 < len(arguments):
            url = arguments[index + 1]

        if url is not None and url.lower().startswith("http://"):
            return f"Detected an unencrypted package index: {url}."

    return None


def _unpinned_packages(
    invocation: _Invocation,
) -> tuple[str, ...]:
    """Return package operands lacking an exact version."""
    if invocation.operation not in {
        "easy-install",
        "pip-install",
        "uv-add",
        "uv-pip-install",
        "uv-tool-install",
    }:
        return ()

    packages = _package_operands(invocation.arguments)

    return tuple(
        package
        for package in packages
        if not _is_local_or_remote_requirement(package) and not _is_exact_pin(package)
    )


def _package_operands(
    arguments: tuple[str, ...],
) -> tuple[str, ...]:
    """Return package operands while excluding option values."""
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


def _is_local_or_remote_requirement(
    requirement: str,
) -> bool:
    """Return whether an operand is a path, archive, VCS, or URL."""
    normalized = requirement.strip()

    if normalized.startswith(_LOCAL_PREFIXES):
        return True

    if normalized.startswith(_REMOTE_PREFIXES):
        return True

    if " @ " in normalized:
        return True

    return normalized.lower().endswith(_ARCHIVE_SUFFIXES)


def _is_exact_pin(requirement: str) -> bool:
    """Return whether a package requirement uses one exact version."""
    requirement_without_marker = requirement.split(
        ";",
        maxsplit=1,
    )[0].strip()
    match = _EXACT_PIN_PATTERN.fullmatch(requirement_without_marker)

    if match is None:
        return False

    version = match.group(1).strip()

    return bool(version and "*" not in version)


def _remote_source_problem(
    invocation: _Invocation,
) -> str | None:
    """Return evidence for mutable VCS or unhashed archive sources."""
    for requirement in _package_operands(invocation.arguments):
        normalized = requirement.strip()

        if normalized.startswith("git+"):
            if not _IMMUTABLE_GIT_REF_PATTERN.search(normalized):
                return (
                    "Detected a VCS requirement without a full "
                    f"40-character commit identifier: {normalized}."
                )

            continue

        remote_url = _extract_direct_url(normalized)

        if remote_url is None:
            continue

        if (
            remote_url.startswith(("http://", "https://"))
            and "#sha256=" not in remote_url.lower()
        ):
            return (
                "Detected a remote package archive without an "
                f"embedded SHA-256 hash: {remote_url}."
            )

    return None


def _extract_direct_url(
    requirement: str,
) -> str | None:
    """Return the URL portion of a direct requirement."""
    if requirement.startswith(("http://", "https://")):
        return requirement

    if " @ " not in requirement:
        return None

    _, url = requirement.split(" @ ", maxsplit=1)

    return url.strip()


def _system_modification_option(
    invocation: _Invocation,
) -> str | None:
    """Return an option that modifies a managed Python installation."""
    for argument in invocation.all_arguments:
        option_name = argument.split("=", maxsplit=1)[0]

        if option_name == "--break-system-packages":
            return option_name

        if option_name == "--system" and invocation.operation.startswith("uv-pip-"):
            return option_name

    return None


def _requirements_without_hashes(
    invocation: _Invocation,
) -> str | None:
    """Return a requirements input lacking mandatory hash checks."""
    if "--require-hashes" in invocation.all_arguments:
        return None

    if _disabled_hash_option(invocation.all_arguments) is not None:
        return None

    if invocation.operation in {
        "pip-install",
        "uv-pip-install",
    }:
        return _requirement_option_value(invocation.arguments)

    if invocation.operation == "uv-pip-sync":
        operands = _package_operands(invocation.arguments)

        if operands:
            return operands[0]

    return None


def _requirement_option_value(
    arguments: tuple[str, ...],
) -> str | None:
    """Return the first requirements-file option value."""
    for index, argument in enumerate(arguments):
        option_name, inline_value = _split_option(argument)

        if option_name not in _REQUIREMENT_OPTIONS:
            continue

        if inline_value is not None:
            return inline_value

        next_index = index + 1

        if next_index < len(arguments):
            return arguments[next_index]

    return None


def _disabled_hash_option(
    arguments: tuple[str, ...],
) -> str | None:
    """Return an option disabling package hash validation."""
    for argument in arguments:
        option_name = argument.split("=", maxsplit=1)[0]

        if option_name in _HASH_DISABLE_OPTIONS:
            return option_name

    return None


def _uv_sync_can_update_lockfile(
    invocation: _Invocation,
) -> bool:
    """Return whether uv sync lacks immutable-lockfile behavior."""
    return (
        invocation.operation == "uv-sync"
        and "--locked" not in invocation.all_arguments
        and "--frozen" not in invocation.all_arguments
    )


def _legacy_repair(
    invocation: _Invocation,
) -> RepairSuggestion | None:
    """Return a modern replacement for a legacy installer command."""
    if invocation.operation == "setup-install":
        replacement = "python -m pip install ."
        rationale = (
            "Install the local project through pip instead of invoking "
            "the setuptools setup.py interface directly."
        )
    elif invocation.operation == "setup-develop":
        replacement = "python -m pip install -e ."
        rationale = (
            "Use pip's editable installation interface instead of `setup.py develop`."
        )
    elif invocation.operation == "easy-install":
        replacement = shlex.join(
            (
                "python",
                "-m",
                "pip",
                "install",
                *invocation.arguments,
            )
        )
        rationale = "Use pip instead of the legacy easy_install interface."
    else:
        return None

    return RepairSuggestion(
        replacement_text=replacement,
        rationale=rationale,
        confidence=RepairConfidence.MEDIUM,
    )


def _split_option(
    argument: str,
) -> tuple[str, str | None]:
    """Split a command-line option from its inline value."""
    if "=" not in argument:
        return argument, None

    option, value = argument.split("=", maxsplit=1)

    return option, value

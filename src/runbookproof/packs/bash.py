"""Static verification rules for Bash and POSIX shell commands."""

from __future__ import annotations

import re

from runbookproof.models import (
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    ShellParseResult,
)

_SHELL_LANGUAGES = frozenset({"bash", "sh", "zsh"})

_SHELL_INTERPRETERS = (
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
)

_RISKY_VARIABLE_COMMANDS = frozenset(
    {
        "chmod",
        "chown",
        "cp",
        "dd",
        "find",
        "mv",
        "rm",
        "tar",
    }
)

_SUDO_OPTIONS_WITH_VALUES = frozenset(
    {
        "-C",
        "-g",
        "-h",
        "-p",
        "-r",
        "-t",
        "-u",
        "--chdir",
        "--group",
        "--host",
        "--prompt",
        "--role",
        "--type",
        "--user",
    }
)

_REMOTE_SCRIPT_PATTERN = re.compile(
    r"(?:^|[;&]\s*)"
    r"(?:sudo\s+)?"
    r"(?:curl|wget)\b"
    r"[^|\n]*"
    r"\|\s*"
    r"(?:sudo\s+)?"
    r"(?:sh|bash|zsh|dash|ksh)\b",
    flags=re.IGNORECASE,
)

_FUNCTION_PATTERN = re.compile(
    r"(?:^|[\s;&|])function\s+[A-Za-z_][A-Za-z0-9_]*",
)

_VARIABLE_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class BashPack:
    """Detect dangerous and non-portable shell documentation patterns."""

    name = "bash"

    def supports(self, result: ShellParseResult) -> bool:
        """Support Bash, POSIX sh, and Zsh command blocks."""
        return result.command.language in _SHELL_LANGUAGES

    def verify(
        self,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Return deterministic static findings for one shell command."""
        if result.error is not None:
            return ()

        findings: list[Finding] = []

        if _executes_remote_script(result):
            findings.append(_remote_script_finding(result))

        recursive_deletion = _recursive_deletion_finding(result)

        if recursive_deletion is not None:
            findings.append(recursive_deletion)

        permission_finding = _world_writable_permission_finding(result)

        if permission_finding is not None:
            findings.append(permission_finding)

        if _uses_sudo(result):
            findings.append(_sudo_finding(result))

        variable_finding = _unquoted_variable_finding(result)

        if variable_finding is not None:
            findings.append(variable_finding)

        portability_finding = _portability_finding(result)

        if portability_finding is not None:
            findings.append(portability_finding)

        return tuple(findings)


def _remote_script_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a finding for downloading and immediately executing code."""
    return Finding(
        rule_id="RBP-BASH-001",
        severity=Severity.ERROR,
        message="Remote script is piped directly to a shell",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected a network downloader piped directly "
                    "to a shell interpreter."
                ),
                source="RunbookProof Bash pack",
            ),
        ),
    )


def _recursive_deletion_finding(
    result: ShellParseResult,
) -> Finding | None:
    """Return a finding when rm performs recursive deletion."""
    command_tokens = _effective_command_tokens(result)

    if not command_tokens or command_tokens[0] != "rm":
        return None

    arguments = command_tokens[1:]

    if not _contains_recursive_rm_option(arguments):
        return None

    targets = tuple(argument for argument in arguments if not argument.startswith("-"))
    critical_targets = tuple(
        target for target in targets if _is_critical_deletion_target(target)
    )

    if critical_targets:
        target_list = ", ".join(critical_targets)

        return Finding(
            rule_id="RBP-BASH-002",
            severity=Severity.ERROR,
            message="Recursive deletion targets a critical path",
            command=result.command,
            evidence=(
                Evidence(
                    kind=EvidenceKind.STATIC_ANALYSIS,
                    message=(
                        f"Detected recursive rm targeting critical path: {target_list}."
                    ),
                    source="RunbookProof Bash pack",
                ),
            ),
        )

    return Finding(
        rule_id="RBP-BASH-002",
        severity=Severity.WARNING,
        message="Command performs recursive deletion",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message="Detected rm with a recursive deletion option.",
                source="RunbookProof Bash pack",
            ),
        ),
    )


def _world_writable_permission_finding(
    result: ShellParseResult,
) -> Finding | None:
    """Return a finding for world-writable chmod modes."""
    command_tokens = _effective_command_tokens(result)

    if not command_tokens or command_tokens[0] != "chmod":
        return None

    mode = _find_chmod_mode(command_tokens[1:])

    if mode not in {
        "777",
        "0777",
        "a+rwx",
        "ugo+rwx",
    }:
        return None

    return Finding(
        rule_id="RBP-BASH-003",
        severity=Severity.ERROR,
        message="Command grants world-writable permissions",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=f"Detected unsafe chmod mode: {mode}.",
                source="RunbookProof Bash pack",
            ),
        ),
    )


def _sudo_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a finding for commands requiring elevated privileges."""
    return Finding(
        rule_id="RBP-BASH-004",
        severity=Severity.WARNING,
        message="Command requires elevated privileges",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected a sudo prefix. Documentation should "
                    "explain why elevated privileges are required."
                ),
                source="RunbookProof Bash pack",
            ),
        ),
    )


def _unquoted_variable_finding(
    result: ShellParseResult,
) -> Finding | None:
    """Return a finding for unquoted variables in destructive commands."""
    command_tokens = _effective_command_tokens(result)

    if not command_tokens or command_tokens[0] not in _RISKY_VARIABLE_COMMANDS:
        return None

    variables = _find_unquoted_variables(result.command.raw_text)

    if not variables:
        return None

    variable_list = ", ".join(variables)

    return Finding(
        rule_id="RBP-BASH-005",
        severity=Severity.WARNING,
        message="Destructive command contains an unquoted variable",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected unquoted shell variable reference"
                    f"{'s' if len(variables) != 1 else ''}: "
                    f"{variable_list}."
                ),
                source="RunbookProof Bash pack",
            ),
        ),
    )


def _portability_finding(
    result: ShellParseResult,
) -> Finding | None:
    """Return a finding for Bash-specific syntax in POSIX sh blocks."""
    if result.command.language != "sh":
        return None

    constructs: list[str] = []
    command_tokens = _effective_command_tokens(result)
    masked_text = _mask_quoted_text(result.command.raw_text)

    if command_tokens and command_tokens[0] == "source":
        constructs.append("source builtin")

    if "[[" in masked_text:
        constructs.append("double-bracket conditional")

    if _FUNCTION_PATTERN.search(masked_text):
        constructs.append("function keyword")

    if command_tokens and command_tokens[0] == "echo" and "-e" in command_tokens[1:]:
        constructs.append("echo -e")

    if command_tokens and command_tokens[0] == "read" and "-p" in command_tokens[1:]:
        constructs.append("read -p")

    if not constructs:
        return None

    construct_list = ", ".join(constructs)

    return Finding(
        rule_id="RBP-BASH-006",
        severity=Severity.WARNING,
        message="Command may not be portable across POSIX shells",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected shell syntax that is not reliably "
                    f"portable in sh: {construct_list}."
                ),
                source="RunbookProof Bash pack",
            ),
        ),
    )


def _executes_remote_script(
    result: ShellParseResult,
) -> bool:
    """Return whether a downloader is piped to a shell interpreter."""
    masked_text = _mask_quoted_text(result.command.raw_text)

    return _REMOTE_SCRIPT_PATTERN.search(masked_text) is not None


def _uses_sudo(result: ShellParseResult) -> bool:
    """Return whether the command begins with sudo."""
    command_tokens = _command_tokens(result)

    return bool(command_tokens and command_tokens[0] == "sudo")


def _command_tokens(
    result: ShellParseResult,
) -> tuple[str, ...]:
    """Return tokens after leading environment assignments."""
    assignment_count = len(result.assignments)

    return result.tokens[assignment_count:]


def _effective_command_tokens(
    result: ShellParseResult,
) -> tuple[str, ...]:
    """Return the underlying command after an optional sudo prefix."""
    command_tokens = _command_tokens(result)

    if not command_tokens or command_tokens[0] != "sudo":
        return command_tokens

    index = 1

    while index < len(command_tokens):
        token = command_tokens[index]

        if token == "--":
            index += 1
            break

        if not token.startswith("-"):
            break

        option_name = token.split("=", maxsplit=1)[0]

        if option_name in _SUDO_OPTIONS_WITH_VALUES and "=" not in token:
            index += 2
        else:
            index += 1

    return command_tokens[index:]


def _contains_recursive_rm_option(
    arguments: tuple[str, ...],
) -> bool:
    """Return whether rm arguments enable recursive deletion."""
    for argument in arguments:
        if argument in {"--recursive", "-r", "-R"}:
            return True

        if (
            argument.startswith("-")
            and not argument.startswith("--")
            and any(flag in argument[1:] for flag in ("r", "R"))
        ):
            return True

    return False


def _is_critical_deletion_target(target: str) -> bool:
    """Return whether a recursive deletion target is especially risky."""
    return target in {
        "/",
        "/*",
        ".",
        "./",
        "..",
        "../",
        "~",
        "~/",
        "~/*",
        "$HOME",
        "$HOME/*",
        "${HOME}",
        "${HOME}/*",
    }


def _find_chmod_mode(
    arguments: tuple[str, ...],
) -> str | None:
    """Return the chmod mode argument when one can be identified."""
    after_separator = False

    for argument in arguments:
        if argument == "--":
            after_separator = True
            continue

        if not after_separator and argument.startswith("-"):
            continue

        return argument

    return None


def _find_unquoted_variables(text: str) -> tuple[str, ...]:
    """Return unique variable references outside shell quotes."""
    variables: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0

    while index < len(text):
        character = text[index]

        if escaped:
            escaped = False
            index += 1
            continue

        if quote == "'":
            if character == "'":
                quote = None

            index += 1
            continue

        if quote == '"':
            if character == "\\":
                escaped = True
            elif character == '"':
                quote = None

            index += 1
            continue

        if character == "\\":
            escaped = True
            index += 1
            continue

        if character in {"'", '"'}:
            quote = character
            index += 1
            continue

        if character == "#" and (index == 0 or text[index - 1].isspace()):
            newline_index = text.find("\n", index)

            if newline_index == -1:
                break

            index = newline_index + 1
            continue

        if character != "$":
            index += 1
            continue

        variable, next_index = _read_variable(text, index)

        if variable is not None and variable not in variables:
            variables.append(variable)

        index = next_index

    return tuple(variables)


def _read_variable(
    text: str,
    index: int,
) -> tuple[str | None, int]:
    """Read a variable reference beginning at one dollar sign."""
    next_index = index + 1

    if next_index >= len(text):
        return None, next_index

    if text[next_index] == "{":
        closing_index = text.find("}", next_index + 1)

        if closing_index == -1:
            return None, next_index

        variable_name = text[next_index + 1 : closing_index]

        if _VARIABLE_NAME_PATTERN.fullmatch(variable_name):
            return (
                text[index : closing_index + 1],
                closing_index + 1,
            )

        return None, closing_index + 1

    match = _VARIABLE_NAME_PATTERN.match(text, next_index)

    if match is None:
        return None, next_index

    return text[index : match.end()], match.end()


def _mask_quoted_text(text: str) -> str:
    """Replace quoted content with spaces while preserving structure."""
    characters = list(text)
    quote: str | None = None
    escaped = False

    for index, character in enumerate(characters):
        if escaped:
            characters[index] = " "
            escaped = False
            continue

        if quote is not None:
            if character == "\\" and quote == '"':
                characters[index] = " "
                escaped = True
                continue

            if character == quote:
                quote = None

            characters[index] = " "
            continue

        if character == "\\":
            escaped = True
            continue

        if character in {"'", '"'}:
            quote = character
            characters[index] = " "

    return "".join(characters)

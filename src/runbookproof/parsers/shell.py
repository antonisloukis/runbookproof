"""Parse extracted shell commands without executing them."""

from __future__ import annotations

import re
import shlex
from dataclasses import replace

from runbookproof.models import (
    CommandCandidate,
    ShellOperator,
    ShellParseResult,
)

_ASSIGNMENT_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*=.*$",
    flags=re.DOTALL,
)

_LINE_CONTINUATION_PATTERN = re.compile(r"\\\r?\n[ \t]*")


def parse_shell_command(command: CommandCandidate) -> ShellParseResult:
    """Parse one shell command using deterministic lexical analysis."""
    operators = _detect_shell_operators(command.raw_text)
    normalized_text = _collapse_line_continuations(command.raw_text)

    try:
        tokens = tuple(
            shlex.split(
                normalized_text,
                comments=True,
                posix=True,
            )
        )
    except ValueError as error:
        return ShellParseResult(
            command=command,
            operators=operators,
            error=str(error),
        )

    assignments, command_tokens = _split_leading_assignments(tokens)

    if not command_tokens:
        return ShellParseResult(
            command=command,
            tokens=tokens,
            assignments=assignments,
            operators=operators,
            error="command contains no executable",
        )

    if operators:
        return ShellParseResult(
            command=command,
            tokens=tokens,
            assignments=assignments,
            operators=operators,
        )

    parsed_command = replace(
        command,
        executable=command_tokens[0],
        arguments=command_tokens[1:],
    )

    return ShellParseResult(
        command=parsed_command,
        tokens=tokens,
        assignments=assignments,
    )


def _collapse_line_continuations(text: str) -> str:
    """Replace shell backslash-newline continuations with spaces."""
    return _LINE_CONTINUATION_PATTERN.sub(" ", text)


def _split_leading_assignments(
    tokens: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Separate leading environment assignments from command tokens."""
    assignment_count = 0

    for token in tokens:
        if not _ASSIGNMENT_PATTERN.fullmatch(token):
            break

        assignment_count += 1

    return (
        tokens[:assignment_count],
        tokens[assignment_count:],
    )


def _detect_shell_operators(text: str) -> frozenset[ShellOperator]:
    """Detect meaningful unquoted shell operators without execution."""
    operators: set[ShellOperator] = set()
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
            elif text.startswith("$((", index):
                operators.add(ShellOperator.ARITHMETIC_EXPANSION)
                index += 3
                continue
            elif text.startswith("$(", index):
                operators.add(ShellOperator.COMMAND_SUBSTITUTION)
                index += 2
                continue
            elif character == "`":
                operators.add(ShellOperator.COMMAND_SUBSTITUTION)

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
            break

        if text.startswith("$((", index):
            operators.add(ShellOperator.ARITHMETIC_EXPANSION)
            index += 3
            continue

        if text.startswith("$(", index):
            operators.add(ShellOperator.COMMAND_SUBSTITUTION)
            index += 2
            continue

        if character == "`":
            operators.add(ShellOperator.COMMAND_SUBSTITUTION)
            index += 1
            continue

        if text.startswith("<(", index) or text.startswith(">(", index):
            operators.add(ShellOperator.PROCESS_SUBSTITUTION)
            index += 2
            continue

        if text.startswith("&&", index) or text.startswith("||", index):
            operators.add(ShellOperator.CHAIN)
            index += 2
            continue

        if text.startswith("|&", index):
            operators.add(ShellOperator.PIPE)
            index += 2
            continue

        if character == "|":
            operators.add(ShellOperator.PIPE)
            index += 1
            continue

        if character == ";":
            operators.add(ShellOperator.SEQUENCE)
            index += 1
            continue

        if character == "&":
            operators.add(ShellOperator.BACKGROUND)
            index += 1
            continue

        if character in {"<", ">"}:
            operators.add(ShellOperator.REDIRECTION)
            index = _skip_redirection_operator(text, index)
            continue

        index += 1

    return frozenset(operators)


def _skip_redirection_operator(text: str, index: int) -> int:
    """Move past one shell redirection operator."""
    next_index = index + 1

    while next_index < len(text) and text[next_index] in {"<", ">", "&", "|"}:
        next_index += 1

    return next_index

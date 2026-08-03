"""Data models describing shell parsing results."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from runbookproof.models.command import CommandCandidate


class ShellOperator(StrEnum):
    """Shell syntax features that make a command structurally complex."""

    PIPE = "pipe"
    CHAIN = "chain"
    SEQUENCE = "sequence"
    BACKGROUND = "background"
    REDIRECTION = "redirection"
    COMMAND_SUBSTITUTION = "command_substitution"
    PROCESS_SUBSTITUTION = "process_substitution"
    ARITHMETIC_EXPANSION = "arithmetic_expansion"


@dataclass(frozen=True, slots=True)
class ShellParseResult:
    """Represent the deterministic result of parsing one shell command."""

    command: CommandCandidate
    tokens: tuple[str, ...] = ()
    assignments: tuple[str, ...] = ()
    operators: frozenset[ShellOperator] = frozenset()
    error: str | None = None

    @property
    def is_simple(self) -> bool:
        """Return whether the command can use ordinary argument validation."""
        return (
            self.error is None
            and not self.operators
            and self.command.executable is not None
        )

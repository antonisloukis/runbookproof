"""Contracts and exceptions for RunbookProof verification packs."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from runbookproof.models import Finding, ShellParseResult


class VerificationPack(Protocol):
    """Define the interface implemented by every verification pack."""

    name: str

    def supports(self, result: ShellParseResult) -> bool:
        """Return whether this pack can verify the parsed command."""
        ...

    def verify(self, result: ShellParseResult) -> Iterable[Finding]:
        """Return evidence-backed findings for the parsed command."""
        ...


class PackExecutionError(RuntimeError):
    """Report an unexpected verification-pack failure."""

    def __init__(
        self,
        *,
        pack_name: str,
        command_identifier: str,
    ) -> None:
        """Create an error identifying the failed pack and command."""
        self.pack_name = pack_name
        self.command_identifier = command_identifier

        super().__init__(
            f"verification pack {pack_name!r} failed for command {command_identifier}"
        )

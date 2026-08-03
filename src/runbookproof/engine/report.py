"""Analysis report produced by the RunbookProof verification engine."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from runbookproof.models import (
    CommandCandidate,
    Finding,
    Severity,
    ShellParseResult,
)


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Contain the deterministic results of analyzing one document."""

    path: str
    parse_results: tuple[ShellParseResult, ...]
    findings: tuple[Finding, ...]
    pack_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate and normalize report metadata."""
        normalized_path = self.path.strip().replace("\\", "/")

        if not normalized_path:
            raise ValueError("report path must not be empty")

        normalized_path = str(PurePosixPath(normalized_path))
        normalized_pack_names = tuple(
            pack_name.strip() for pack_name in self.pack_names
        )

        if any(not pack_name for pack_name in normalized_pack_names):
            raise ValueError("pack names must not be empty")

        if len(set(normalized_pack_names)) != len(normalized_pack_names):
            raise ValueError("pack names must be unique")

        for result in self.parse_results:
            if result.command.source.path != normalized_path:
                raise ValueError("all parsed commands must belong to the report path")

        command_identifiers = {
            result.command.identifier for result in self.parse_results
        }

        for finding in self.findings:
            if finding.command.identifier not in command_identifiers:
                raise ValueError("all findings must belong to a parsed command")

        object.__setattr__(self, "path", normalized_path)
        object.__setattr__(
            self,
            "pack_names",
            normalized_pack_names,
        )

    @property
    def commands(self) -> tuple[CommandCandidate, ...]:
        """Return the parsed commands contained in this report."""
        return tuple(result.command for result in self.parse_results)

    @property
    def command_count(self) -> int:
        """Return the number of discovered commands."""
        return len(self.parse_results)

    @property
    def finding_count(self) -> int:
        """Return the total number of findings."""
        return len(self.findings)

    def count(self, severity: Severity) -> int:
        """Return the number of findings at one severity level."""
        return sum(finding.severity is severity for finding in self.findings)

    @property
    def error_count(self) -> int:
        """Return the number of error findings."""
        return self.count(Severity.ERROR)

    @property
    def warning_count(self) -> int:
        """Return the number of warning findings."""
        return self.count(Severity.WARNING)

    @property
    def info_count(self) -> int:
        """Return the number of informational findings."""
        return self.count(Severity.INFO)

    @property
    def has_errors(self) -> bool:
        """Return whether the report contains an error finding."""
        return self.error_count > 0

    @property
    def exit_code(self) -> int:
        """Return the default command-line exit code for this report."""
        return 1 if self.has_errors else 0

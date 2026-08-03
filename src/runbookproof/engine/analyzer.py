"""Orchestrate command extraction, parsing, and verification."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from runbookproof.engine.contracts import (
    PackExecutionError,
    VerificationPack,
)
from runbookproof.engine.report import AnalysisReport
from runbookproof.extractors import extract_commands_from_markdown
from runbookproof.models import Finding, Severity, ShellParseResult
from runbookproof.parsers import parse_shell_command

_SEVERITY_ORDER = {
    Severity.ERROR: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
}


@dataclass(frozen=True, slots=True)
class VerificationEngine:
    """Run registered verification packs against discovered commands."""

    packs: tuple[VerificationPack, ...] = ()
    _pack_names: tuple[str, ...] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Validate and normalize verification-pack metadata."""
        pack_names = tuple(pack.name.strip() for pack in self.packs)

        if any(not pack_name for pack_name in pack_names):
            raise ValueError("verification pack names must not be empty")

        if len(set(pack_names)) != len(pack_names):
            raise ValueError("verification pack names must be unique")

        object.__setattr__(self, "_pack_names", pack_names)

    @property
    def pack_names(self) -> tuple[str, ...]:
        """Return the registered verification-pack names."""
        return self._pack_names

    def analyze_markdown(
        self,
        markdown: str,
        *,
        path: str,
    ) -> AnalysisReport:
        """Analyze one Markdown document without executing commands."""
        commands = extract_commands_from_markdown(
            markdown,
            path=path,
        )
        parse_results = tuple(parse_shell_command(command) for command in commands)

        findings = self._run_packs(parse_results)

        return AnalysisReport(
            path=path,
            parse_results=parse_results,
            findings=findings,
            pack_names=self.pack_names,
        )

    def _run_packs(
        self,
        parse_results: tuple[ShellParseResult, ...],
    ) -> tuple[Finding, ...]:
        """Run all applicable packs and return deterministic findings."""
        findings_by_fingerprint: dict[str, Finding] = {}

        for result in parse_results:
            for pack in self.packs:
                produced_findings = self._run_pack(
                    pack,
                    result,
                )

                for finding in produced_findings:
                    findings_by_fingerprint.setdefault(
                        finding.fingerprint,
                        finding,
                    )

        return tuple(
            sorted(
                findings_by_fingerprint.values(),
                key=_finding_sort_key,
            )
        )

    @staticmethod
    def _run_pack(
        pack: VerificationPack,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Run one pack and attach useful context to pack failures."""
        try:
            if not pack.supports(result):
                return ()

            findings = tuple(pack.verify(result))

            for finding in findings:
                if finding.command.identifier != result.command.identifier:
                    raise ValueError(
                        "verification pack returned a finding for another command"
                    )

            return findings
        except PackExecutionError:
            raise
        except Exception as error:
            raise PackExecutionError(
                pack_name=pack.name.strip(),
                command_identifier=result.command.identifier,
            ) from error


def analyze_markdown(
    markdown: str,
    *,
    path: str,
    packs: Iterable[VerificationPack] = (),
) -> AnalysisReport:
    """Analyze Markdown using a temporary verification engine."""
    return VerificationEngine(
        packs=tuple(packs),
    ).analyze_markdown(
        markdown,
        path=path,
    )


def _finding_sort_key(
    finding: Finding,
) -> tuple[str, int, int, int, str, str]:
    """Return a stable ordering key for report findings."""
    source = finding.command.source

    return (
        source.path,
        source.start_line,
        source.end_line,
        _SEVERITY_ORDER[finding.severity],
        finding.rule_id,
        finding.fingerprint,
    )

"""Structured findings, evidence, and repair suggestions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256

from runbookproof.models.command import CommandCandidate

_RULE_ID_PATTERN = re.compile(r"^RBP-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3}$")


class Severity(StrEnum):
    """Severity levels used by RunbookProof findings."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class EvidenceKind(StrEnum):
    """Describe how a piece of verification evidence was produced."""

    STATIC_ANALYSIS = "static_analysis"
    TOOL_HELP = "tool_help"
    VERSION_CHECK = "version_check"
    DRY_RUN = "dry_run"
    POLICY = "policy"


class RepairConfidence(StrEnum):
    """Confidence assigned to a proposed documentation repair."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class Evidence:
    """Record one deterministic fact supporting a finding."""

    kind: EvidenceKind
    message: str
    source: str | None = None

    def __post_init__(self) -> None:
        """Validate and normalize evidence fields."""
        normalized_message = self.message.strip()

        if not normalized_message:
            raise ValueError("evidence message must not be empty")

        normalized_source = self._normalize_optional_source(self.source)

        object.__setattr__(self, "message", normalized_message)
        object.__setattr__(self, "source", normalized_source)

    @staticmethod
    def _normalize_optional_source(source: str | None) -> str | None:
        """Normalize an optional evidence source."""
        if source is None:
            return None

        normalized_source = source.strip()

        if not normalized_source:
            raise ValueError("evidence source must not be empty")

        return normalized_source


@dataclass(frozen=True, slots=True)
class RepairSuggestion:
    """Describe a proposed replacement for a documented command."""

    replacement_text: str
    rationale: str
    confidence: RepairConfidence
    safe_to_apply: bool = False

    def __post_init__(self) -> None:
        """Validate and normalize the repair suggestion."""
        normalized_replacement = self.replacement_text.strip()
        normalized_rationale = self.rationale.strip()

        if not normalized_replacement:
            raise ValueError("replacement_text must not be empty")

        if not normalized_rationale:
            raise ValueError("repair rationale must not be empty")

        if self.safe_to_apply and self.confidence is not RepairConfidence.HIGH:
            raise ValueError("safe_to_apply requires high repair confidence")

        object.__setattr__(
            self,
            "replacement_text",
            normalized_replacement,
        )
        object.__setattr__(self, "rationale", normalized_rationale)


@dataclass(frozen=True, slots=True)
class Finding:
    """Represent one evidence-backed verification result."""

    rule_id: str
    severity: Severity
    message: str
    command: CommandCandidate
    evidence: tuple[Evidence, ...]
    repair: RepairSuggestion | None = None

    def __post_init__(self) -> None:
        """Validate and normalize the finding."""
        normalized_rule_id = self.rule_id.strip().upper()
        normalized_message = self.message.strip()

        if not _RULE_ID_PATTERN.fullmatch(normalized_rule_id):
            raise ValueError("rule_id must follow the format RBP-PACK-001")

        if not normalized_message:
            raise ValueError("finding message must not be empty")

        if not self.evidence:
            raise ValueError("finding must contain evidence")

        object.__setattr__(self, "rule_id", normalized_rule_id)
        object.__setattr__(self, "message", normalized_message)

    @property
    def fingerprint(self) -> str:
        """Return a stable identifier for this rule and command."""
        payload = "\0".join(
            (
                self.rule_id,
                self.command.identifier,
            )
        )
        return sha256(payload.encode("utf-8")).hexdigest()[:16]

    @property
    def location(self) -> str:
        """Return a human-readable source location."""
        source = self.command.source

        if source.start_line == source.end_line:
            return f"{source.path}:{source.start_line}"

        return f"{source.path}:{source.start_line}-{source.end_line}"

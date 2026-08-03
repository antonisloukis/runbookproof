"""Universal static verification for every parsed shell command."""

from __future__ import annotations

from dataclasses import dataclass

from runbookproof.models import (
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    ShellOperator,
    ShellParseResult,
)


@dataclass(frozen=True, slots=True)
class _OperatorRule:
    """Describe the finding produced for one shell operator."""

    rule_id: str
    message: str
    evidence_message: str


_OPERATOR_RULES: tuple[
    tuple[ShellOperator, _OperatorRule],
    ...,
] = (
    (
        ShellOperator.PIPE,
        _OperatorRule(
            rule_id="RBP-UNIVERSAL-010",
            message="Command uses a shell pipeline",
            evidence_message=("Detected an unquoted pipe operator (`|` or `|&`)."),
        ),
    ),
    (
        ShellOperator.CHAIN,
        _OperatorRule(
            rule_id="RBP-UNIVERSAL-011",
            message="Command uses conditional command chaining",
            evidence_message=(
                "Detected an unquoted conditional operator (`&&` or `||`)."
            ),
        ),
    ),
    (
        ShellOperator.SEQUENCE,
        _OperatorRule(
            rule_id="RBP-UNIVERSAL-012",
            message="Command contains sequential operations",
            evidence_message=("Detected an unquoted command separator (`;`)."),
        ),
    ),
    (
        ShellOperator.BACKGROUND,
        _OperatorRule(
            rule_id="RBP-UNIVERSAL-013",
            message="Command starts a background operation",
            evidence_message=("Detected an unquoted background operator (`&`)."),
        ),
    ),
    (
        ShellOperator.REDIRECTION,
        _OperatorRule(
            rule_id="RBP-UNIVERSAL-014",
            message="Command redirects shell input or output",
            evidence_message=("Detected an unquoted shell redirection operator."),
        ),
    ),
    (
        ShellOperator.COMMAND_SUBSTITUTION,
        _OperatorRule(
            rule_id="RBP-UNIVERSAL-015",
            message="Command performs command substitution",
            evidence_message=(
                "Detected command substitution using `$(...)` or backticks."
            ),
        ),
    ),
    (
        ShellOperator.PROCESS_SUBSTITUTION,
        _OperatorRule(
            rule_id="RBP-UNIVERSAL-016",
            message="Command performs process substitution",
            evidence_message=(
                "Detected process substitution using `<(...)` or `>(...)`."
            ),
        ),
    ),
    (
        ShellOperator.ARITHMETIC_EXPANSION,
        _OperatorRule(
            rule_id="RBP-UNIVERSAL-017",
            message="Command performs arithmetic expansion",
            evidence_message=("Detected arithmetic expansion using `$((...))`."),
        ),
    ),
)


class UniversalPack:
    """Report shell structures requiring additional verification."""

    name = "universal"

    def supports(self, result: ShellParseResult) -> bool:
        """Support every extracted shell command."""
        return True

    def verify(
        self,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Return deterministic findings for general shell syntax."""
        if result.error is not None:
            return (
                _make_error_finding(
                    result,
                    error=result.error,
                ),
            )

        return tuple(
            _make_operator_finding(
                result,
                rule=rule,
            )
            for operator, rule in _OPERATOR_RULES
            if operator in result.operators
        )


def _make_error_finding(
    result: ShellParseResult,
    *,
    error: str,
) -> Finding:
    """Create a finding for an unsuccessful shell parse."""
    if error == "command contains no executable":
        return Finding(
            rule_id="RBP-UNIVERSAL-002",
            severity=Severity.ERROR,
            message="Command has no detectable executable",
            command=result.command,
            evidence=(
                Evidence(
                    kind=EvidenceKind.STATIC_ANALYSIS,
                    message=(
                        "Shell parsing found no executable after "
                        "processing assignments and comments."
                    ),
                    source="RunbookProof shell parser",
                ),
            ),
        )

    return Finding(
        rule_id="RBP-UNIVERSAL-001",
        severity=Severity.ERROR,
        message="Command contains invalid shell syntax",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=f"Shell parser reported: {error}.",
                source="RunbookProof shell parser",
            ),
        ),
    )


def _make_operator_finding(
    result: ShellParseResult,
    *,
    rule: _OperatorRule,
) -> Finding:
    """Create a warning for one detected complex shell operator."""
    return Finding(
        rule_id=rule.rule_id,
        severity=Severity.WARNING,
        message=rule.message,
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=rule.evidence_message,
                source="RunbookProof shell parser",
            ),
        ),
    )

"""Tests for the core command data model."""

from __future__ import annotations

import pytest

from runbookproof.models import CommandCandidate, SourceSpan


def test_source_span_normalizes_windows_path_separators() -> None:
    """Source paths should use stable forward-slash separators."""
    source = SourceSpan(
        path=r"docs\deployment\runbook.md",
        start_line=10,
        end_line=12,
    )

    assert source.path == "docs/deployment/runbook.md"


def test_source_span_rejects_empty_path() -> None:
    """A source location must contain a file path."""
    with pytest.raises(ValueError, match="path must not be empty"):
        SourceSpan(path="  ", start_line=1, end_line=1)


def test_source_span_rejects_line_number_below_one() -> None:
    """Line numbers should be one-based."""
    with pytest.raises(ValueError, match="start_line must be at least 1"):
        SourceSpan(path="README.md", start_line=0, end_line=1)


def test_source_span_rejects_reversed_line_range() -> None:
    """The ending line cannot appear before the starting line."""
    with pytest.raises(
        ValueError,
        match="end_line must be greater than or equal to start_line",
    ):
        SourceSpan(path="README.md", start_line=5, end_line=4)


def test_command_candidate_normalizes_values() -> None:
    """Command data should be normalized during construction."""
    command = CommandCandidate(
        source=SourceSpan("README.md", 8, 8),
        raw_text="  kubectl get pods  ",
        language=" BASH ",
        executable=" kubectl ",
        arguments=(" get ", " pods "),
        working_directory=r"examples\kubernetes",
    )

    assert command.raw_text == "kubectl get pods"
    assert command.language == "bash"
    assert command.executable == "kubectl"
    assert command.arguments == ("get", "pods")
    assert command.working_directory == "examples/kubernetes"


def test_command_candidate_accepts_missing_optional_values() -> None:
    """Optional parsed fields may remain unknown after extraction."""
    command = CommandCandidate(
        source=SourceSpan("README.md", 1, 1),
        raw_text="echo hello",
        language="sh",
    )

    assert command.executable is None
    assert command.working_directory is None
    assert command.arguments == ()


def test_command_candidate_rejects_empty_raw_text() -> None:
    """An extracted command must contain text."""
    with pytest.raises(ValueError, match="raw_text must not be empty"):
        CommandCandidate(
            source=SourceSpan("README.md", 1, 1),
            raw_text=" ",
            language="bash",
        )


def test_command_candidate_rejects_empty_language() -> None:
    """The extractor must record the source language."""
    with pytest.raises(ValueError, match="language must not be empty"):
        CommandCandidate(
            source=SourceSpan("README.md", 1, 1),
            raw_text="echo hello",
            language=" ",
        )


def test_command_candidate_rejects_empty_executable() -> None:
    """A parsed executable cannot be an empty string."""
    with pytest.raises(ValueError, match="executable must not be empty"):
        CommandCandidate(
            source=SourceSpan("README.md", 1, 1),
            raw_text="echo hello",
            language="bash",
            executable=" ",
        )


def test_command_candidate_rejects_empty_working_directory() -> None:
    """An explicitly supplied working directory cannot be empty."""
    with pytest.raises(
        ValueError,
        match="working_directory must not be empty",
    ):
        CommandCandidate(
            source=SourceSpan("README.md", 1, 1),
            raw_text="echo hello",
            language="bash",
            working_directory=" ",
        )


def test_command_candidate_rejects_empty_argument() -> None:
    """Parsed argument collections cannot contain empty entries."""
    with pytest.raises(
        ValueError,
        match="arguments must not contain empty values",
    ):
        CommandCandidate(
            source=SourceSpan("README.md", 1, 1),
            raw_text="echo hello",
            language="bash",
            arguments=("hello", " "),
        )


def test_command_identifier_is_stable() -> None:
    """Equivalent commands should receive the same identifier."""
    first = CommandCandidate(
        source=SourceSpan("README.md", 4, 4),
        raw_text="terraform validate",
        language="bash",
    )
    second = CommandCandidate(
        source=SourceSpan("README.md", 4, 4),
        raw_text="terraform validate",
        language="bash",
    )

    assert first.identifier == second.identifier
    assert len(first.identifier) == 16


def test_command_identifier_changes_with_source_location() -> None:
    """Moving a command should produce a different identifier."""
    first = CommandCandidate(
        source=SourceSpan("README.md", 4, 4),
        raw_text="terraform validate",
        language="bash",
    )
    second = CommandCandidate(
        source=SourceSpan("README.md", 5, 5),
        raw_text="terraform validate",
        language="bash",
    )

    assert first.identifier != second.identifier

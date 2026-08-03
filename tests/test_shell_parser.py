"""Tests for deterministic shell command parsing."""

from __future__ import annotations

import pytest

from runbookproof.models import (
    CommandCandidate,
    ShellOperator,
    SourceSpan,
)
from runbookproof.parsers import parse_shell_command


def make_command(raw_text: str) -> CommandCandidate:
    """Create a command candidate for parser tests."""
    return CommandCandidate(
        source=SourceSpan(
            path="README.md",
            start_line=1,
            end_line=1,
        ),
        raw_text=raw_text,
        language="bash",
    )


def test_parses_simple_command() -> None:
    """A simple command should expose its executable and arguments."""
    result = parse_shell_command(
        make_command("kubectl get pods --namespace production")
    )

    assert result.is_simple
    assert result.command.executable == "kubectl"
    assert result.command.arguments == (
        "get",
        "pods",
        "--namespace",
        "production",
    )
    assert result.tokens == (
        "kubectl",
        "get",
        "pods",
        "--namespace",
        "production",
    )
    assert result.error is None


def test_preserves_quoted_argument() -> None:
    """Quoted text should remain one logical argument."""
    result = parse_shell_command(
        make_command('aws s3 cp "my deployment file.txt" s3://example-bucket/')
    )

    assert result.is_simple
    assert result.command.executable == "aws"
    assert result.command.arguments == (
        "s3",
        "cp",
        "my deployment file.txt",
        "s3://example-bucket/",
    )


def test_ignores_inline_shell_comment() -> None:
    """Inline shell comments should not become arguments."""
    result = parse_shell_command(
        make_command("terraform validate # verify configuration")
    )

    assert result.is_simple
    assert result.command.executable == "terraform"
    assert result.command.arguments == ("validate",)


def test_collects_leading_environment_assignments() -> None:
    """Leading variable assignments should be separated from the executable."""
    result = parse_shell_command(
        make_command(
            "AWS_REGION=eu-west-1 AWS_PROFILE=production aws sts get-caller-identity"
        )
    )

    assert result.is_simple
    assert result.assignments == (
        "AWS_REGION=eu-west-1",
        "AWS_PROFILE=production",
    )
    assert result.command.executable == "aws"
    assert result.command.arguments == (
        "sts",
        "get-caller-identity",
    )


def test_collapses_backslash_line_continuations() -> None:
    """Continued shell lines should tokenize as one logical command."""
    result = parse_shell_command(
        make_command(
            "aws ec2 describe-instances \\\n--region eu-west-1 \\\n--output json"
        )
    )

    assert result.is_simple
    assert result.command.executable == "aws"
    assert result.command.arguments == (
        "ec2",
        "describe-instances",
        "--region",
        "eu-west-1",
        "--output",
        "json",
    )


@pytest.mark.parametrize(
    ("raw_text", "expected_operator"),
    [
        ("git status | grep clean", ShellOperator.PIPE),
        ("terraform fmt && terraform validate", ShellOperator.CHAIN),
        ("terraform fmt || echo failed", ShellOperator.CHAIN),
        ("echo first; echo second", ShellOperator.SEQUENCE),
        ("docker compose up &", ShellOperator.BACKGROUND),
        ("terraform plan > plan.txt", ShellOperator.REDIRECTION),
        ("echo $(whoami)", ShellOperator.COMMAND_SUBSTITUTION),
        ("cat <(git diff)", ShellOperator.PROCESS_SUBSTITUTION),
        ("echo $((1 + 2))", ShellOperator.ARITHMETIC_EXPANSION),
    ],
)
def test_detects_complex_shell_syntax(
    raw_text: str,
    expected_operator: ShellOperator,
) -> None:
    """Complex shell operators should prevent simple-command validation."""
    result = parse_shell_command(make_command(raw_text))

    assert not result.is_simple
    assert expected_operator in result.operators
    assert result.command.executable is None
    assert result.error is None


def test_quoted_operators_are_not_detected() -> None:
    """Operators inside quoted arguments should remain ordinary text."""
    result = parse_shell_command(make_command('echo "deployment | production && safe"'))

    assert result.is_simple
    assert result.operators == frozenset()
    assert result.command.arguments == ("deployment | production && safe",)


def test_escaped_operator_is_not_detected() -> None:
    """An escaped operator character should be treated as an argument."""
    result = parse_shell_command(make_command(r"echo \|"))

    assert result.is_simple
    assert result.operators == frozenset()
    assert result.command.arguments == ("|",)


def test_operators_inside_comment_are_not_detected() -> None:
    """Operators after an inline comment marker should be ignored."""
    result = parse_shell_command(make_command("echo complete # ignored | rm -rf /"))

    assert result.is_simple
    assert result.operators == frozenset()
    assert result.command.arguments == ("complete",)


def test_reports_malformed_quotes() -> None:
    """Malformed quoting should produce a deterministic parsing error."""
    result = parse_shell_command(make_command('echo "unfinished argument'))

    assert not result.is_simple
    assert result.error == "No closing quotation"
    assert result.command.executable is None


def test_rejects_comment_only_command() -> None:
    """A command containing only a comment has no executable."""
    result = parse_shell_command(make_command("# documentation comment"))

    assert not result.is_simple
    assert result.tokens == ()
    assert result.error == "command contains no executable"


def test_rejects_assignment_only_command() -> None:
    """Environment assignments without a command have no executable."""
    result = parse_shell_command(
        make_command("AWS_REGION=eu-west-1 AWS_PROFILE=production")
    )

    assert not result.is_simple
    assert result.assignments == (
        "AWS_REGION=eu-west-1",
        "AWS_PROFILE=production",
    )
    assert result.error == "command contains no executable"

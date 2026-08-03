"""Tests for Markdown command extraction."""

from __future__ import annotations

from runbookproof.extractors import extract_commands_from_markdown


def test_extracts_commands_from_bash_fence() -> None:
    """Supported fences should produce commands with exact source lines."""
    markdown = (
        "# Deployment\n"
        "\n"
        "```bash\n"
        "# Initialize Terraform\n"
        "terraform init\n"
        "\n"
        "terraform validate\n"
        "```\n"
    )

    commands = extract_commands_from_markdown(
        markdown,
        path="docs/deployment.md",
    )

    assert len(commands) == 2

    assert commands[0].raw_text == "terraform init"
    assert commands[0].language == "bash"
    assert commands[0].source.path == "docs/deployment.md"
    assert commands[0].source.start_line == 5
    assert commands[0].source.end_line == 5

    assert commands[1].raw_text == "terraform validate"
    assert commands[1].source.start_line == 7
    assert commands[1].source.end_line == 7


def test_strips_console_prompt() -> None:
    """Console-style dollar prompts should not become part of commands."""
    markdown = "```console\n$ git status\n```\n"

    commands = extract_commands_from_markdown(
        markdown,
        path="README.md",
    )

    assert len(commands) == 1
    assert commands[0].raw_text == "git status"
    assert commands[0].language == "sh"


def test_supports_tilde_fences_and_shell_alias() -> None:
    """Tilde fences and generic shell labels should be supported."""
    markdown = "~~~shell\ndocker compose config\n~~~\n"

    commands = extract_commands_from_markdown(
        markdown,
        path="README.md",
    )

    assert len(commands) == 1
    assert commands[0].raw_text == "docker compose config"
    assert commands[0].language == "sh"


def test_supports_markdown_attribute_language() -> None:
    """Markdown attribute syntax should expose language classes."""
    markdown = "```{.bash}\nkubectl get pods\n```\n"

    commands = extract_commands_from_markdown(
        markdown,
        path="runbooks/kubernetes.md",
    )

    assert len(commands) == 1
    assert commands[0].language == "bash"


def test_ignores_unsupported_and_unlabelled_fences() -> None:
    """Only explicitly supported shell-oriented fences should be scanned."""
    markdown = "```python\nprint('hello')\n```\n\n```\nterraform validate\n```\n"

    commands = extract_commands_from_markdown(
        markdown,
        path="README.md",
    )

    assert commands == ()


def test_combines_backslash_continuations() -> None:
    """Backslash-continued shell lines should form one command candidate."""
    markdown = (
        "```bash\n"
        "aws ec2 describe-instances \\\n"
        "  --region eu-west-1 \\\n"
        "  --output json\n"
        "```\n"
    )

    commands = extract_commands_from_markdown(
        markdown,
        path="docs/aws.md",
    )

    assert len(commands) == 1
    assert commands[0].raw_text == (
        "aws ec2 describe-instances \\\n--region eu-west-1 \\\n--output json"
    )
    assert commands[0].source.start_line == 2
    assert commands[0].source.end_line == 4


def test_preserves_unfinished_continuation_at_block_end() -> None:
    """An incomplete continued command should remain available for analysis."""
    markdown = "```bash\nterraform plan \\\n```\n"

    commands = extract_commands_from_markdown(
        markdown,
        path="README.md",
    )

    assert len(commands) == 1
    assert commands[0].raw_text == "terraform plan \\"


def test_ignores_unterminated_fence() -> None:
    """Unclosed Markdown blocks should not produce uncertain findings."""
    markdown = "```bash\nterraform validate\n"

    commands = extract_commands_from_markdown(
        markdown,
        path="README.md",
    )

    assert commands == ()


def test_closing_fence_must_match_marker_type() -> None:
    """A tilde fence cannot close a backtick fence."""
    markdown = "```bash\nterraform init\n~~~\nterraform validate\n```\n"

    commands = extract_commands_from_markdown(
        markdown,
        path="README.md",
    )

    assert [command.raw_text for command in commands] == [
        "terraform init",
        "~~~",
        "terraform validate",
    ]


def test_closing_fence_must_be_long_enough() -> None:
    """A shorter marker sequence cannot close a longer opening fence."""
    markdown = "````bash\nterraform init\n```\nterraform validate\n````\n"

    commands = extract_commands_from_markdown(
        markdown,
        path="README.md",
    )

    assert [command.raw_text for command in commands] == [
        "terraform init",
        "```",
        "terraform validate",
    ]


def test_ignores_overindented_opening_fence() -> None:
    """Opening fences indented by more than three spaces are not parsed."""
    markdown = "    ```bash\n    terraform validate\n    ```\n"

    commands = extract_commands_from_markdown(
        markdown,
        path="README.md",
    )

    assert commands == ()


def test_rejects_backtick_inside_backtick_fence_info() -> None:
    """Backtick fence information cannot itself contain backticks."""
    markdown = "```bash`invalid\nterraform validate\n```\n"

    commands = extract_commands_from_markdown(
        markdown,
        path="README.md",
    )

    assert commands == ()

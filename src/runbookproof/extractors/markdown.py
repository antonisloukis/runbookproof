"""Extract shell command candidates from Markdown documents."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from runbookproof.models import CommandCandidate, SourceSpan

_OPENING_FENCE_PATTERN = re.compile(
    r"^(?P<indent> {0,3})(?P<marker>`{3,}|~{3,})(?P<info>.*)$"
)

_LANGUAGE_ALIASES = {
    "bash": "bash",
    "console": "sh",
    "sh": "sh",
    "shell": "sh",
    "shell-session": "sh",
    "terminal": "sh",
    "zsh": "zsh",
}


@dataclass(frozen=True, slots=True)
class _Fence:
    """Describe an active Markdown fenced code block."""

    marker: str
    length: int
    language: str | None


def extract_commands_from_markdown(
    markdown: str,
    *,
    path: str,
) -> tuple[CommandCandidate, ...]:
    """Extract supported shell commands from Markdown fenced code blocks."""
    commands: list[CommandCandidate] = []
    active_fence: _Fence | None = None
    block_lines: list[tuple[int, str]] = []

    for line_number, line in enumerate(markdown.splitlines(), start=1):
        if active_fence is None:
            active_fence = _parse_opening_fence(line)

            if active_fence is not None:
                block_lines = []

            continue

        if _is_closing_fence(line, active_fence):
            if active_fence.language is not None:
                commands.extend(
                    _extract_commands_from_block(
                        block_lines,
                        path=path,
                        language=active_fence.language,
                    )
                )

            active_fence = None
            block_lines = []
            continue

        block_lines.append((line_number, line))

    return tuple(commands)


def _parse_opening_fence(line: str) -> _Fence | None:
    """Parse a Markdown opening fence when the line contains one."""
    match = _OPENING_FENCE_PATTERN.fullmatch(line)

    if match is None:
        return None

    marker_text = match.group("marker")
    info = match.group("info").strip()

    if marker_text.startswith("`") and "`" in info:
        return None

    return _Fence(
        marker=marker_text[0],
        length=len(marker_text),
        language=_parse_language(info),
    )


def _parse_language(info: str) -> str | None:
    """Return a canonical supported shell language from a fence info string."""
    if not info:
        return None

    language: str | None = None

    if info.startswith("{") and info.endswith("}"):
        for attribute in info[1:-1].split():
            if attribute.startswith(".") and len(attribute) > 1:
                language = attribute[1:]
                break
    else:
        language = info.split(maxsplit=1)[0]

    if language is None:
        return None

    return _LANGUAGE_ALIASES.get(language.lower())


def _is_closing_fence(line: str, fence: _Fence) -> bool:
    """Return whether a line closes the active Markdown fence."""
    stripped = line.lstrip(" ")
    indentation = len(line) - len(stripped)

    if indentation > 3:
        return False

    candidate = stripped.rstrip()

    return len(candidate) >= fence.length and candidate == fence.marker * len(candidate)


def _extract_commands_from_block(
    lines: Iterable[tuple[int, str]],
    *,
    path: str,
    language: str,
) -> tuple[CommandCandidate, ...]:
    """Convert the lines inside one shell block into command candidates."""
    commands: list[CommandCandidate] = []
    pending_lines: list[str] = []
    start_line: int | None = None
    end_line: int | None = None

    for line_number, line in lines:
        normalized_line = _normalize_command_line(line)

        if normalized_line is None:
            continue

        if start_line is None:
            start_line = line_number

        end_line = line_number
        pending_lines.append(normalized_line)

        if _has_line_continuation(normalized_line):
            continue

        commands.append(
            _build_command(
                pending_lines,
                path=path,
                language=language,
                start_line=start_line,
                end_line=end_line,
            )
        )
        pending_lines = []
        start_line = None
        end_line = None

    if pending_lines and start_line is not None and end_line is not None:
        commands.append(
            _build_command(
                pending_lines,
                path=path,
                language=language,
                start_line=start_line,
                end_line=end_line,
            )
        )

    return tuple(commands)


def _normalize_command_line(line: str) -> str | None:
    """Normalize a possible command line from a fenced block."""
    normalized_line = line.strip()

    if not normalized_line or normalized_line.startswith("#"):
        return None

    if normalized_line.startswith("$ "):
        normalized_line = normalized_line[2:].lstrip()

    if not normalized_line:
        return None

    return normalized_line


def _has_line_continuation(line: str) -> bool:
    """Return whether a shell line ends with an unescaped backslash."""
    trailing_backslashes = len(line) - len(line.rstrip("\\"))

    return trailing_backslashes % 2 == 1


def _build_command(
    lines: list[str],
    *,
    path: str,
    language: str,
    start_line: int,
    end_line: int,
) -> CommandCandidate:
    """Create one command candidate from normalized logical command lines."""
    return CommandCandidate(
        source=SourceSpan(
            path=path,
            start_line=start_line,
            end_line=end_line,
        ),
        raw_text="\n".join(lines),
        language=language,
    )

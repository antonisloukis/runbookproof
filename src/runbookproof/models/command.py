"""Core data models for commands discovered in source documents."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """Identify the exact source location of a discovered command."""

    path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        """Validate and normalize the source location."""
        normalized_path = self.path.strip().replace("\\", "/")

        if not normalized_path:
            raise ValueError("path must not be empty")

        if self.start_line < 1:
            raise ValueError("start_line must be at least 1")

        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")

        object.__setattr__(
            self,
            "path",
            str(PurePosixPath(normalized_path)),
        )


@dataclass(frozen=True, slots=True)
class CommandCandidate:
    """Represent a command extracted from documentation or a script."""

    source: SourceSpan
    raw_text: str
    language: str
    executable: str | None = None
    arguments: tuple[str, ...] = ()
    working_directory: str | None = None

    def __post_init__(self) -> None:
        """Validate and normalize the extracted command."""
        normalized_text = self.raw_text.strip()
        normalized_language = self.language.strip().lower()

        if not normalized_text:
            raise ValueError("raw_text must not be empty")

        if not normalized_language:
            raise ValueError("language must not be empty")

        normalized_executable = self._normalize_optional_value(
            self.executable,
            field_name="executable",
        )
        normalized_working_directory = self._normalize_optional_value(
            self.working_directory,
            field_name="working_directory",
            normalize_path=True,
        )

        normalized_arguments = tuple(argument.strip() for argument in self.arguments)

        if any(not argument for argument in normalized_arguments):
            raise ValueError("arguments must not contain empty values")

        object.__setattr__(self, "raw_text", normalized_text)
        object.__setattr__(self, "language", normalized_language)
        object.__setattr__(self, "executable", normalized_executable)
        object.__setattr__(self, "arguments", normalized_arguments)
        object.__setattr__(
            self,
            "working_directory",
            normalized_working_directory,
        )

    @staticmethod
    def _normalize_optional_value(
        value: str | None,
        *,
        field_name: str,
        normalize_path: bool = False,
    ) -> str | None:
        """Normalize an optional non-empty string value."""
        if value is None:
            return None

        normalized_value = value.strip()

        if not normalized_value:
            raise ValueError(f"{field_name} must not be empty")

        if normalize_path:
            normalized_value = normalized_value.replace("\\", "/")
            normalized_value = str(PurePosixPath(normalized_value))

        return normalized_value

    @property
    def identifier(self) -> str:
        """Return a stable identifier for this command and source location."""
        payload = "\0".join(
            (
                self.source.path,
                str(self.source.start_line),
                str(self.source.end_line),
                self.raw_text,
            )
        )
        return sha256(payload.encode("utf-8")).hexdigest()[:16]

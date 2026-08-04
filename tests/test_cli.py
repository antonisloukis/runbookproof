"""Tests for the RunbookProof command-line interface."""

from __future__ import annotations

from pathlib import Path

import pytest

from runbookproof import __version__
from runbookproof.cli import main


def test_main_without_arguments_displays_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The empty command should display help and succeed."""
    assert main([]) == 0

    captured = capsys.readouterr()

    assert "usage: runbookproof" in captured.out
    assert "scan" in captured.out
    assert captured.err == ""


def test_version_option_displays_package_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The version option should display the installed package version."""
    with pytest.raises(SystemExit) as error:
        main(["--version"])

    assert error.value.code == 0
    assert capsys.readouterr().out == f"runbookproof {__version__}\n"


def test_scan_safe_markdown_returns_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A document without findings should return success."""
    monkeypatch.chdir(tmp_path)

    path = Path("safe.md")
    path.write_text(
        "```bash\naz group list\n```\n",
        encoding="utf-8",
    )

    assert main(["scan", str(path)]) == 0

    captured = capsys.readouterr()

    assert captured.out == (
        "Scanned safe.md: 1 command, 0 errors, 0 warnings, 0 info\n"
    )
    assert captured.err == ""


def test_scan_risky_markdown_returns_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An error-level finding should produce exit code one."""
    monkeypatch.chdir(tmp_path)

    path = Path("risky.md")
    path.write_text(
        "```bash\naz group delete --name production --yes\n```\n",
        encoding="utf-8",
    )

    assert main(["scan", str(path)]) == 1

    captured = capsys.readouterr()

    assert captured.out == (
        "ERROR RBP-AZURE-001 risky.md:2: "
        "Azure CLI command deletes a resource group\n"
        "Scanned risky.md: "
        "1 command, 1 error, 0 warnings, 0 info\n"
    )
    assert captured.err == ""


def test_scan_missing_file_returns_usage_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing input file should produce exit code two."""
    monkeypatch.chdir(tmp_path)

    assert main(["scan", "missing.md"]) == 2

    captured = capsys.readouterr()

    assert captured.out == ""
    assert "runbookproof: error: cannot read missing.md" in captured.err


def test_scan_invalid_utf8_returns_usage_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A non-UTF-8 document should produce exit code two."""
    monkeypatch.chdir(tmp_path)

    path = Path("invalid.md")
    path.write_bytes(b"\xff\xfe\x00")

    assert main(["scan", str(path)]) == 2

    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err == ("runbookproof: error: invalid.md is not valid UTF-8\n")

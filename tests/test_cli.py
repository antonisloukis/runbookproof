"""Tests for the RunbookProof command-line interface."""

from __future__ import annotations

import pytest

from runbookproof import __version__
from runbookproof.cli import main


def test_main_without_arguments_returns_success() -> None:
    """The empty command should complete successfully."""
    assert main([]) == 0


def test_version_option_displays_package_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The version option should display the installed package version."""
    with pytest.raises(SystemExit) as error:
        main(["--version"])

    assert error.value.code == 0
    assert capsys.readouterr().out == f"runbookproof {__version__}\n"

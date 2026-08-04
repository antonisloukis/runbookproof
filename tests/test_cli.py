"""Tests for the RunbookProof command-line interface."""

from __future__ import annotations

import json
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
    """The version option should display the package version."""
    with pytest.raises(SystemExit) as error:
        main(["--version"])

    assert error.value.code == 0
    assert capsys.readouterr().out == (f"runbookproof {__version__}\n")


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


def test_scan_directory_recursively_scans_markdown_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A directory should be scanned recursively."""
    monkeypatch.chdir(tmp_path)

    docs = Path("docs")
    nested = docs / "operations"

    nested.mkdir(parents=True)

    (docs / "safe.md").write_text(
        "```bash\naz group list\n```\n",
        encoding="utf-8",
    )
    (nested / "risky.MD").write_text(
        "```bash\naz group delete --name production --yes\n```\n",
        encoding="utf-8",
    )
    (docs / "ignored.txt").write_text(
        "az group delete --name ignored",
        encoding="utf-8",
    )

    assert main(["scan", str(docs)]) == 1

    captured = capsys.readouterr()

    assert captured.out == (
        "ERROR RBP-AZURE-001 "
        "docs/operations/risky.MD:2: "
        "Azure CLI command deletes a resource group\n"
        "Scanned docs: "
        "2 Markdown files, "
        "2 commands, "
        "1 error, "
        "0 warnings, "
        "0 info\n"
    )
    assert captured.err == ""


def test_scan_empty_directory_returns_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An empty directory should produce an empty report."""
    monkeypatch.chdir(tmp_path)

    docs = Path("docs")
    docs.mkdir()

    assert main(["scan", str(docs)]) == 0

    captured = capsys.readouterr()

    assert captured.out == (
        "Scanned docs: 0 Markdown files, 0 commands, 0 errors, 0 warnings, 0 info\n"
    )
    assert captured.err == ""


def test_scan_directory_reports_invalid_utf8(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Invalid Markdown inside a directory should return two."""
    monkeypatch.chdir(tmp_path)

    docs = Path("docs")
    docs.mkdir()

    (docs / "invalid.md").write_bytes(b"\xff\xfe\x00")

    assert main(["scan", str(docs)]) == 2

    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err == ("runbookproof: error: docs/invalid.md is not valid UTF-8\n")


def test_scan_file_supports_json_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A single-file scan should support JSON output."""
    monkeypatch.chdir(tmp_path)

    path = Path("risky.md")
    path.write_text(
        "```bash\naz group delete --name production --yes\n```\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "scan",
                str(path),
                "--format",
                "json",
            ]
        )
        == 1
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert captured.err == ""
    assert payload["kind"] == "file"
    assert payload["path"] == "risky.md"
    assert payload["command_count"] == 1
    assert payload["finding_count"] == 1
    assert payload["error_count"] == 1
    assert payload["warning_count"] == 0
    assert payload["info_count"] == 0
    assert payload["exit_code"] == 1

    finding = payload["findings"][0]

    assert finding["rule_id"] == "RBP-AZURE-001"
    assert finding["severity"] == "error"
    assert finding["location"] == "risky.md:2"
    assert finding["command"]["raw_text"] == ("az group delete --name production --yes")
    assert finding["command"]["source"] == {
        "path": "risky.md",
        "start_line": 2,
        "end_line": 2,
    }


def test_scan_directory_supports_json_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A directory scan should return aggregated JSON."""
    monkeypatch.chdir(tmp_path)

    docs = Path("docs")
    nested = docs / "operations"
    nested.mkdir(parents=True)

    (docs / "safe.md").write_text(
        "```bash\naz group list\n```\n",
        encoding="utf-8",
    )
    (nested / "risky.md").write_text(
        "```bash\naz group delete --name production --yes\n```\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "scan",
                str(docs),
                "--format",
                "json",
            ]
        )
        == 1
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert captured.err == ""
    assert payload["kind"] == "directory"
    assert payload["path"] == "docs"
    assert payload["markdown_file_count"] == 2
    assert payload["command_count"] == 2
    assert payload["finding_count"] == 1
    assert payload["error_count"] == 1
    assert payload["warning_count"] == 0
    assert payload["info_count"] == 0
    assert payload["exit_code"] == 1

    reports = payload["reports"]

    assert [report["path"] for report in reports] == [
        "docs/operations/risky.md",
        "docs/safe.md",
    ]

    assert reports[0]["findings"][0]["rule_id"] == ("RBP-AZURE-001")
    assert reports[1]["findings"] == []


def test_scan_empty_directory_supports_json_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An empty directory should produce valid JSON."""
    monkeypatch.chdir(tmp_path)

    docs = Path("docs")
    docs.mkdir()

    assert (
        main(
            [
                "scan",
                str(docs),
                "--format",
                "json",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert captured.err == ""
    assert payload == {
        "kind": "directory",
        "path": "docs",
        "markdown_file_count": 0,
        "command_count": 0,
        "finding_count": 0,
        "error_count": 0,
        "warning_count": 0,
        "info_count": 0,
        "exit_code": 0,
        "reports": [],
    }


def test_scan_file_supports_sarif_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A file scan should support SARIF output."""
    monkeypatch.chdir(tmp_path)

    path = Path("risky.md")
    path.write_text(
        "```bash\naz group delete --name production --yes\n```\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "scan",
                str(path),
                "--format",
                "sarif",
            ]
        )
        == 1
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert captured.err == ""
    assert payload["version"] == "2.1.0"
    assert payload["$schema"] == ("https://json.schemastore.org/sarif-2.1.0.json")

    run = payload["runs"][0]
    driver = run["tool"]["driver"]

    assert driver["name"] == "RunbookProof"
    assert driver["version"] == __version__
    assert driver["informationUri"] == ("https://github.com/antonisloukis/runbookproof")
    assert driver["rules"] == [
        {
            "id": "RBP-AZURE-001",
            "shortDescription": {
                "text": ("Azure CLI command deletes a resource group"),
            },
            "defaultConfiguration": {
                "level": "error",
            },
        }
    ]

    result = run["results"][0]

    assert result["ruleId"] == "RBP-AZURE-001"
    assert result["level"] == "error"
    assert result["message"] == {
        "text": ("Azure CLI command deletes a resource group"),
    }
    assert result["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": "risky.md",
                },
                "region": {
                    "startLine": 2,
                    "endLine": 2,
                },
            }
        }
    ]
    assert result["properties"]["command"] == (
        "az group delete --name production --yes"
    )
    assert len(result["partialFingerprints"]["runbookproofFingerprint"]) == 16


def test_scan_directory_supports_sarif_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A directory scan should aggregate SARIF."""
    monkeypatch.chdir(tmp_path)

    docs = Path("docs")
    nested = docs / "operations"
    nested.mkdir(parents=True)

    (docs / "safe.md").write_text(
        "```bash\naz group list\n```\n",
        encoding="utf-8",
    )
    (nested / "risky.md").write_text(
        "```bash\naz group delete --name production --yes\n```\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "scan",
                str(docs),
                "--format",
                "sarif",
            ]
        )
        == 1
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert captured.err == ""

    run = payload["runs"][0]

    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1

    result = run["results"][0]

    assert result["ruleId"] == "RBP-AZURE-001"
    assert (
        (result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        == "docs/operations/risky.md"
    )


def test_scan_empty_directory_supports_sarif_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An empty directory should produce valid SARIF."""
    monkeypatch.chdir(tmp_path)

    docs = Path("docs")
    docs.mkdir()

    assert (
        main(
            [
                "scan",
                str(docs),
                "--format",
                "sarif",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert captured.err == ""
    assert payload["version"] == "2.1.0"

    run = payload["runs"][0]

    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []

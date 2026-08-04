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


def test_scan_writes_json_output_to_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """JSON output should be written to the requested file."""
    monkeypatch.chdir(tmp_path)

    input_path = Path("risky.md")
    output_path = Path("report.json")

    input_path.write_text(
        "```bash\naz group delete --name production --yes\n```\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "scan",
                str(input_path),
                "--format",
                "json",
                "--output",
                str(output_path),
            ]
        )
        == 1
    )

    captured = capsys.readouterr()
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert captured.out == ""
    assert captured.err == ""
    assert payload["kind"] == "file"
    assert payload["path"] == "risky.md"
    assert payload["error_count"] == 1
    assert payload["exit_code"] == 1


def test_scan_writes_sarif_output_with_short_option(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The short output option should write valid SARIF."""
    monkeypatch.chdir(tmp_path)

    input_path = Path("risky.md")
    output_path = Path("report.sarif")

    input_path.write_text(
        "```bash\naz group delete --name production --yes\n```\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "scan",
                str(input_path),
                "--format",
                "sarif",
                "-o",
                str(output_path),
            ]
        )
        == 1
    )

    captured = capsys.readouterr()
    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert captured.out == ""
    assert captured.err == ""
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == ("RBP-AZURE-001")


def test_scan_rejects_input_file_as_output_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The input document must not be overwritten by output."""
    monkeypatch.chdir(tmp_path)

    path = Path("runbook.md")
    original = "```bash\naz group list\n```\n"
    path.write_text(original, encoding="utf-8")

    assert (
        main(
            [
                "scan",
                str(path),
                "--output",
                str(path),
            ]
        )
        == 2
    )

    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err == (
        "runbookproof: error: output path matches input file: runbook.md\n"
    )
    assert path.read_text(encoding="utf-8") == original


def test_scan_reports_output_write_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unwritable output destination should return two."""
    monkeypatch.chdir(tmp_path)

    input_path = Path("safe.md")
    input_path.write_text(
        "```bash\naz group list\n```\n",
        encoding="utf-8",
    )

    assert (
        main(
            [
                "scan",
                str(input_path),
                "--format",
                "json",
                "--output",
                "missing/report.json",
            ]
        )
        == 2
    )

    captured = capsys.readouterr()

    assert captured.out == ""
    assert ("runbookproof: error: cannot write missing/report.json") in captured.err


def test_scan_can_ignore_rule_in_text_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An ignored rule should be removed from text output."""
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
                "--ignore-rule",
                "RBP-FAKE-999",
                "--ignore-rule",
                "rbp-azure-001",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()

    assert captured.out == (
        "Scanned risky.md: 1 command, 0 errors, 0 warnings, 0 info\n"
    )
    assert captured.err == ""


def test_scan_can_ignore_rule_in_json_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ignored rules should be absent from JSON reports."""
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
                "--ignore-rule",
                "RBP-AZURE-001",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert captured.err == ""
    assert payload["finding_count"] == 0
    assert payload["error_count"] == 0
    assert payload["exit_code"] == 0
    assert payload["findings"] == []


def test_scan_can_ignore_rule_in_sarif_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ignored rules should be absent from SARIF output."""
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
                "--ignore-rule",
                "RBP-AZURE-001",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    run = payload["runs"][0]

    assert captured.err == ""
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_scan_rejects_invalid_ignored_rule_id(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Malformed ignored rule IDs should be rejected."""
    with pytest.raises(SystemExit) as error:
        main(
            [
                "scan",
                "README.md",
                "--ignore-rule",
                "not-a-rule",
            ]
        )

    assert error.value.code == 2

    captured = capsys.readouterr()

    assert captured.out == ""
    assert "rule ID must follow the format RBP-PACK-001" in captured.err


def test_scan_loads_default_config_ignore_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The default configuration should provide ignored rules."""
    monkeypatch.chdir(tmp_path)

    Path(".runbookproof.toml").write_text(
        '[scan]\nignore_rules = ["rbp-azure-001"]\n',
        encoding="utf-8",
    )

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
        == 0
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert captured.err == ""
    assert payload["finding_count"] == 0
    assert payload["error_count"] == 0
    assert payload["exit_code"] == 0
    assert payload["findings"] == []


def test_scan_combines_config_and_cli_ignored_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI and configuration ignored rules should be combined."""
    monkeypatch.chdir(tmp_path)

    Path(".runbookproof.toml").write_text(
        '[scan]\nignore_rules = ["RBP-FAKE-999"]\n',
        encoding="utf-8",
    )

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
                "--ignore-rule",
                "RBP-AZURE-001",
            ]
        )
        == 0
    )

    captured = capsys.readouterr()

    assert captured.out == (
        "Scanned risky.md: 1 command, 0 errors, 0 warnings, 0 info\n"
    )
    assert captured.err == ""


def test_scan_loads_explicit_config_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An explicit configuration path should be supported."""
    monkeypatch.chdir(tmp_path)

    config_path = Path("config/settings.toml")
    config_path.parent.mkdir()
    config_path.write_text(
        '[scan]\nignore_rules = ["RBP-AZURE-001"]\n',
        encoding="utf-8",
    )

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
                "--config",
                str(config_path),
            ]
        )
        == 0
    )

    captured = capsys.readouterr()

    assert captured.out == (
        "Scanned risky.md: 1 command, 0 errors, 0 warnings, 0 info\n"
    )
    assert captured.err == ""


def test_scan_reports_missing_explicit_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing explicit configuration should return two."""
    monkeypatch.chdir(tmp_path)

    assert (
        main(
            [
                "scan",
                "README.md",
                "--config",
                "missing.toml",
            ]
        )
        == 2
    )

    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err == ("runbookproof: error: missing.toml: file not found\n")


def test_scan_reports_invalid_toml_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Malformed TOML should return two."""
    monkeypatch.chdir(tmp_path)

    Path(".runbookproof.toml").write_text(
        "[scan\n",
        encoding="utf-8",
    )

    assert main(["scan", "README.md"]) == 2

    captured = capsys.readouterr()

    assert captured.out == ""
    assert ("runbookproof: error: .runbookproof.toml: invalid TOML:") in captured.err


def test_scan_rejects_non_array_config_ignore_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Configuration ignore_rules must be a TOML array."""
    monkeypatch.chdir(tmp_path)

    Path(".runbookproof.toml").write_text(
        '[scan]\nignore_rules = "RBP-AZURE-001"\n',
        encoding="utf-8",
    )

    assert main(["scan", "README.md"]) == 2

    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err == (
        "runbookproof: error: "
        ".runbookproof.toml: "
        "scan.ignore_rules must be an array of rule IDs\n"
    )


def test_scan_rejects_invalid_config_rule_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Malformed configuration rule IDs should be rejected."""
    monkeypatch.chdir(tmp_path)

    Path(".runbookproof.toml").write_text(
        '[scan]\nignore_rules = ["not-a-rule"]\n',
        encoding="utf-8",
    )

    assert main(["scan", "README.md"]) == 2

    captured = capsys.readouterr()

    assert captured.out == ""
    assert (
        "invalid rule ID 'not-a-rule': rule ID must follow the format RBP-PACK-001"
    ) in captured.err

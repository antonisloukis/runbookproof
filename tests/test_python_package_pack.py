"""Tests for pip and uv package-management verification."""

from __future__ import annotations

import pytest

from runbookproof.engine import VerificationEngine
from runbookproof.models import (
    CommandCandidate,
    RepairConfidence,
    Severity,
    ShellParseResult,
    SourceSpan,
)
from runbookproof.packs import PythonPackagePack
from runbookproof.parsers import parse_shell_command


def make_result(raw_text: str) -> ShellParseResult:
    """Parse a command for Python package-manager tests."""
    command = CommandCandidate(
        source=SourceSpan(
            path="README.md",
            start_line=4,
            end_line=4,
        ),
        raw_text=raw_text,
        language="bash",
    )

    return parse_shell_command(command)


def rule_ids(raw_text: str) -> tuple[str, ...]:
    """Return the rule identifiers produced for one command."""
    return tuple(
        finding.rule_id for finding in PythonPackagePack().verify(make_result(raw_text))
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        "pip install requests",
        "pip3 install requests",
        "python -m pip install requests",
        "python3 -m pip install requests",
        "py -m pip install requests",
        "uv add requests",
        "uv pip install requests",
        "uv tool install ruff",
        "easy_install requests",
        "python setup.py install",
    ],
)
def test_supports_python_package_commands(
    raw_text: str,
) -> None:
    """The pack should support pip, uv, and recognized legacy commands."""
    assert PythonPackagePack().supports(make_result(raw_text))


@pytest.mark.parametrize(
    "raw_text",
    [
        "git status",
        "npm install react",
        "terraform validate",
        "python application.py",
        "python setup.py build",
        "uv",
        "pip",
    ],
)
def test_ignores_unrelated_or_incomplete_commands(
    raw_text: str,
) -> None:
    """Unsupported commands should not be claimed by this pack."""
    assert not PythonPackagePack().supports(make_result(raw_text))


def test_malformed_command_is_not_supported() -> None:
    """Malformed commands should remain the universal pack's concern."""
    result = make_result('pip install "unfinished')

    assert not PythonPackagePack().supports(result)
    assert PythonPackagePack().verify(result) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "pip --help",
        "pip install --help",
        "pip --version",
        "python -m pip --version",
        "uv --help",
        "uv --version",
        "uv pip install --help",
        "easy_install --help",
    ],
)
def test_help_and_version_commands_produce_no_findings(
    raw_text: str,
) -> None:
    """Informational invocations should not produce findings."""
    assert PythonPackagePack().verify(make_result(raw_text)) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        ("pip install requests==2.32.3 --trusted-host pypi.org"),
        ("pip install requests==2.32.3 --trusted-host=pypi.org"),
        ("uv pip install requests==2.32.3 --allow-insecure-host packages.example.com"),
        ("uv pip install requests==2.32.3 --allow-insecure-host=packages.example.com"),
        ("pip install requests==2.32.3 --index-url http://packages.example.com/simple"),
        ("pip install requests==2.32.3 --index-url=http://packages.example.com/simple"),
        ("uv add requests==2.32.3 --default-index=http://packages.example.com/simple"),
    ],
)
def test_detects_insecure_transport_configuration(
    raw_text: str,
) -> None:
    """Certificate bypasses and HTTP indexes should be errors."""
    findings = PythonPackagePack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-PYTHON-001"
    assert findings[0].severity is Severity.ERROR
    assert findings[0].message == ("Python package transport security is disabled")


def test_https_index_produces_no_transport_finding() -> None:
    """A package index using HTTPS should pass transport checks."""
    assert (
        PythonPackagePack().verify(
            make_result(
                "pip install requests==2.32.3 --index-url=https://pypi.org/simple"
            )
        )
        == ()
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        "pip install requests",
        'pip3 install "requests>=2"',
        "python -m pip install requests~=2.32",
        "uv add requests",
        "uv pip install requests!=2.31.0",
        "uv tool install ruff",
        "pip install requests==2.*",
    ],
)
def test_detects_unpinned_packages(
    raw_text: str,
) -> None:
    """Package installations should use exact stable versions."""
    findings = PythonPackagePack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-PYTHON-002"
    assert findings[0].severity is Severity.WARNING
    assert findings[0].message == ("Python package installation is not exactly pinned")


@pytest.mark.parametrize(
    "raw_text",
    [
        "pip install requests==2.32.3",
        "pip install requests===2.32.3",
        "pip install requests[socks]==2.32.3",
        "uv add requests==2.32.3",
        "uv pip install requests==2.32.3",
        "uv tool install ruff==0.6.9",
    ],
)
def test_exact_pins_produce_no_version_finding(
    raw_text: str,
) -> None:
    """Exact package versions should be reproducible."""
    assert "RBP-PYTHON-002" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "pip install .",
        "pip install ../local-package",
        "pip install file:../local-package",
        "pip install package.whl",
        "pip install package.tar.gz",
    ],
)
def test_local_packages_are_not_treated_as_unpinned(
    raw_text: str,
) -> None:
    """Local paths and archives do not need registry version syntax."""
    assert "RBP-PYTHON-002" not in rule_ids(raw_text)


def test_package_after_separator_is_detected() -> None:
    """The explicit option separator should preserve package operands."""
    assert rule_ids("pip install -- requests") == ("RBP-PYTHON-002",)


def test_option_value_is_not_treated_as_package() -> None:
    """Values belonging to options should not become package operands."""
    assert rule_ids("pip install --target build/site-packages") == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        ("pip install git+https://github.com/pallets/flask.git@main"),
        ("pip install git+https://github.com/pallets/flask.git"),
        ("pip install https://example.com/packages/tool-1.0.0.whl"),
        ("pip install 'tool @ https://example.com/tool-1.0.0.tar.gz'"),
    ],
)
def test_detects_mutable_or_unhashed_remote_sources(
    raw_text: str,
) -> None:
    """Remote dependencies should identify immutable content."""
    findings = PythonPackagePack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-PYTHON-003"
    assert findings[0].severity is Severity.WARNING
    assert findings[0].message == ("Remote Python package source is not immutable")


def test_git_dependency_with_full_commit_is_immutable() -> None:
    """A full Git commit identifier should pass the VCS check."""
    commit = "0123456789abcdef0123456789abcdef01234567"

    assert "RBP-PYTHON-003" not in rule_ids(
        f"pip install git+https://github.com/pallets/flask.git@{commit}"
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        ('pip install "https://example.com/tool.whl#sha256=deadbeef"'),
        ("pip install 'tool @ https://example.com/tool.tar.gz#sha256=deadbeef'"),
    ],
)
def test_remote_archives_with_hashes_pass(
    raw_text: str,
) -> None:
    """A direct URL with an embedded SHA-256 hash is immutable."""
    assert "RBP-PYTHON-003" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    ("raw_text", "option"),
    [
        (
            "pip install requests==2.32.3 --break-system-packages",
            "--break-system-packages",
        ),
        (
            "python -m pip install requests==2.32.3 --break-system-packages",
            "--break-system-packages",
        ),
        (
            "uv pip install requests==2.32.3 --system",
            "--system",
        ),
        (
            "uv pip install requests==2.32.3 --break-system-packages",
            "--break-system-packages",
        ),
    ],
)
def test_detects_system_python_modification(
    raw_text: str,
    option: str,
) -> None:
    """Managed Python environments should not be modified implicitly."""
    findings = PythonPackagePack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-PYTHON-004"
    assert findings[0].severity is Severity.ERROR
    assert option in findings[0].evidence[0].message


def test_pip_system_text_does_not_trigger_uv_system_rule() -> None:
    """The uv-specific --system rule should not apply to plain pip."""
    assert "RBP-PYTHON-004" not in rule_ids("pip install requests==2.32.3 --system")


@pytest.mark.parametrize(
    "raw_text",
    [
        "pip install -r requirements.txt",
        "pip install --requirement requirements.txt",
        "pip install --requirement=requirements.txt",
        "python -m pip install -r requirements.txt",
        "uv pip install -r requirements.txt",
        "uv pip sync requirements.txt",
    ],
)
def test_detects_requirements_without_required_hashes(
    raw_text: str,
) -> None:
    """Requirements files should require package hashes."""
    findings = PythonPackagePack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-PYTHON-005"
    assert findings[0].severity is Severity.WARNING


@pytest.mark.parametrize(
    "raw_text",
    [
        "pip install -r requirements.txt --require-hashes",
        ("python -m pip install --requirement requirements.txt --require-hashes"),
        ("uv pip install -r requirements.txt --require-hashes"),
        ("uv pip sync requirements.txt --require-hashes"),
    ],
)
def test_requirements_with_hash_enforcement_pass(
    raw_text: str,
) -> None:
    """Required hashes should satisfy the requirements-file rule."""
    assert "RBP-PYTHON-005" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    ("raw_text", "option"),
    [
        (
            "pip install -r requirements.txt --no-require-hashes",
            "--no-require-hashes",
        ),
        (
            "uv pip sync requirements.txt --no-verify-hashes",
            "--no-verify-hashes",
        ),
    ],
)
def test_detects_disabled_hash_verification(
    raw_text: str,
    option: str,
) -> None:
    """Explicit hash-verification bypasses should be errors."""
    findings = PythonPackagePack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-PYTHON-006"
    assert findings[0].severity is Severity.ERROR
    assert option in findings[0].evidence[0].message


def test_plain_uv_sync_has_locked_repair() -> None:
    """uv sync should preserve the existing lockfile in automation."""
    findings = PythonPackagePack().verify(make_result("uv sync"))

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "RBP-PYTHON-007"
    assert finding.severity is Severity.WARNING
    assert finding.repair is not None
    assert finding.repair.replacement_text == "uv sync --locked"
    assert finding.repair.confidence is RepairConfidence.LOW
    assert not finding.repair.safe_to_apply


def test_uv_global_options_do_not_hide_sync() -> None:
    """uv global options should not hide the actual operation."""
    findings = PythonPackagePack().verify(make_result("uv --directory . sync"))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-PYTHON-007"
    assert findings[0].repair is not None
    assert findings[0].repair.replacement_text == ("uv --directory . sync --locked")


@pytest.mark.parametrize(
    "raw_text",
    [
        "uv sync --locked",
        "uv sync --frozen",
    ],
)
def test_immutable_uv_sync_produces_no_finding(
    raw_text: str,
) -> None:
    """Locked and frozen synchronization should not mutate the lockfile."""
    assert PythonPackagePack().verify(make_result(raw_text)) == ()


@pytest.mark.parametrize(
    (
        "raw_text",
        "replacement",
    ),
    [
        (
            "python setup.py install",
            "python -m pip install .",
        ),
        (
            "python ./setup.py develop",
            "python -m pip install -e .",
        ),
        (
            "easy_install requests==2.32.3",
            "python -m pip install requests==2.32.3",
        ),
    ],
)
def test_legacy_commands_have_modern_repairs(
    raw_text: str,
    replacement: str,
) -> None:
    """Legacy Python installers should include modern replacements."""
    findings = PythonPackagePack().verify(make_result(raw_text))

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "RBP-PYTHON-008"
    assert finding.severity is Severity.INFO
    assert finding.repair is not None
    assert finding.repair.replacement_text == replacement
    assert finding.repair.confidence is RepairConfidence.MEDIUM


def test_unpinned_easy_install_has_two_findings() -> None:
    """Legacy unpinned installs should report both problems."""
    assert rule_ids("easy_install requests") == (
        "RBP-PYTHON-002",
        "RBP-PYTHON-008",
    )


def test_python_options_do_not_hide_module_pip() -> None:
    """Python interpreter options should not hide `-m pip`."""
    assert rule_ids("python -I -m pip install requests") == ("RBP-PYTHON-002",)


def test_uv_command_separator_preserves_operation() -> None:
    """The uv global option separator should preserve its operation."""
    assert rule_ids("uv -- sync") == ("RBP-PYTHON-007",)


def test_multiple_findings_have_deterministic_order() -> None:
    """Findings should follow the pack's published rule order."""
    findings = PythonPackagePack().verify(
        make_result(
            "uv pip install requests "
            "--trusted-host pypi.org "
            "--system "
            "--no-verify-hashes"
        )
    )

    assert tuple(finding.rule_id for finding in findings) == (
        "RBP-PYTHON-001",
        "RBP-PYTHON-002",
        "RBP-PYTHON-004",
        "RBP-PYTHON-006",
    )


def test_python_package_pack_integrates_with_engine() -> None:
    """The verification engine should run this pack end to end."""
    report = VerificationEngine(
        packs=(PythonPackagePack(),),
    ).analyze_markdown(
        "```bash\npip install requests\n```\n",
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.warning_count == 1
    assert report.error_count == 0
    assert report.pack_names == ("python-package",)
    assert report.findings[0].rule_id == "RBP-PYTHON-002"

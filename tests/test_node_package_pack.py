"""Tests for npm, pnpm, Yarn, npx, and pnpx verification."""

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
from runbookproof.packs import NodePackagePack
from runbookproof.parsers import parse_shell_command


def make_result(raw_text: str) -> ShellParseResult:
    """Parse a command for Node package-manager tests."""
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
        finding.rule_id for finding in NodePackagePack().verify(make_result(raw_text))
    )


@pytest.mark.parametrize(
    "manager",
    [
        "npm",
        "npx",
        "pnpm",
        "pnpx",
        "yarn",
        "yarnpkg",
    ],
)
def test_supports_node_package_managers(manager: str) -> None:
    """The pack should support all launch package managers."""
    assert NodePackagePack().supports(make_result(f"{manager} --version"))


def test_does_not_support_unrelated_command() -> None:
    """The pack should ignore unrelated executables."""
    assert not NodePackagePack().supports(make_result("pip install requests"))


def test_does_not_support_malformed_command() -> None:
    """A malformed package command should be handled by universal mode."""
    assert not NodePackagePack().supports(make_result('npm install "unfinished'))


def test_direct_verification_ignores_malformed_command() -> None:
    """Direct pack calls should safely ignore parsing failures."""
    assert NodePackagePack().verify(make_result('npm install "unfinished')) == ()


def test_direct_verification_ignores_unrelated_command() -> None:
    """Direct pack calls should safely ignore unsupported tools."""
    assert NodePackagePack().verify(make_result("pip install requests")) == ()


def test_simple_script_command_produces_no_findings() -> None:
    """Running a local package script should pass static verification."""
    assert NodePackagePack().verify(make_result("npm run test")) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "npm --help",
        "npm install --help",
        "pnpm --version",
        "yarn -v",
        "npx -h",
    ],
)
def test_help_and_version_commands_produce_no_findings(
    raw_text: str,
) -> None:
    """Informational invocations should not produce findings."""
    assert NodePackagePack().verify(make_result(raw_text)) == ()


@pytest.mark.parametrize(
    "raw_text",
    [
        "npm install react --strict-ssl=false",
        "npm install react --strict-ssl false",
        ("npm install react --registry=http://registry.example.com"),
        ("pnpm add react --registry http://registry.example.com"),
        "npm config set strict-ssl false",
        "yarn config set strict-ssl false",
    ],
)
def test_detects_disabled_transport_security(
    raw_text: str,
) -> None:
    """TLS verification and HTTPS registries should remain enabled."""
    findings = NodePackagePack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-NODE-001"
    assert findings[0].severity is Severity.ERROR
    assert findings[0].message == ("Package manager disables transport security")


def test_secure_registry_produces_no_transport_finding() -> None:
    """An HTTPS package registry should pass transport checks."""
    assert (
        NodePackagePack().verify(
            make_result("npm install react --registry=https://registry.npmjs.org")
        )
        == ()
    )


@pytest.mark.parametrize(
    "raw_text",
    [
        "npx cowsay",
        "pnpx cowsay",
        "npm exec cowsay",
        "pnpm dlx cowsay",
        "yarn dlx cowsay",
        "yarnpkg dlx cowsay",
        "npx @example/tool",
        "npx cowsay@latest",
        "pnpm dlx cowsay@next",
    ],
)
def test_detects_unpinned_package_execution(
    raw_text: str,
) -> None:
    """Registry packages should specify a stable version."""
    findings = NodePackagePack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-NODE-002"
    assert findings[0].severity is Severity.WARNING
    assert findings[0].message == ("Executed package does not specify a version")


@pytest.mark.parametrize(
    "raw_text",
    [
        "npx cowsay@1.6.0",
        "npx @example/tool@2.1.0",
        "npx cowsay@^1.6.0",
        "npm exec file:../local-tool",
        "pnpm dlx https://example.com/tool.js",
    ],
)
def test_pinned_or_local_execution_avoids_version_finding(
    raw_text: str,
) -> None:
    """Stable versions and explicit local sources are deterministic."""
    assert "RBP-NODE-002" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "npx --package cowsay echo ready",
        "npx --package=cowsay echo ready",
        "npm exec -p cowsay -- echo ready",
        "npx --cache /tmp/npm-cache cowsay",
        "npx -- cowsay",
    ],
)
def test_finds_package_behind_runner_options(
    raw_text: str,
) -> None:
    """Runner options should not hide the executed package."""
    assert "RBP-NODE-002" in rule_ids(raw_text)


def test_automatic_confirmation_with_unpinned_package() -> None:
    """Automatic execution should be separate from version pinning."""
    assert rule_ids("npx --yes cowsay") == (
        "RBP-NODE-002",
        "RBP-NODE-003",
    )


def test_automatic_confirmation_with_pinned_package() -> None:
    """A pinned package can still suppress execution confirmation."""
    findings = NodePackagePack().verify(make_result("npx -y cowsay@1.6.0"))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-NODE-003"
    assert findings[0].message == ("Package execution suppresses confirmation")


@pytest.mark.parametrize(
    "raw_text",
    [
        "npm install --global typescript",
        "npm i -g typescript",
        "pnpm add --global typescript",
        "yarn global add typescript",
        "yarnpkg global add typescript",
    ],
)
def test_detects_global_package_installation(
    raw_text: str,
) -> None:
    """Global installation should be reported as non-reproducible state."""
    findings = NodePackagePack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-NODE-004"
    assert findings[0].severity is Severity.WARNING


@pytest.mark.parametrize(
    "raw_text",
    [
        "npm install typescript",
        "pnpm add typescript",
        "yarn add typescript",
        "yarn global list",
    ],
)
def test_local_or_non_install_commands_avoid_global_finding(
    raw_text: str,
) -> None:
    """Local installations and global queries are not global installs."""
    assert "RBP-NODE-004" not in rule_ids(raw_text)


@pytest.mark.parametrize(
    ("raw_text", "option"),
    [
        ("npm install react --force", "--force"),
        ("npm install react -f", "-f"),
        (
            "npm install react --legacy-peer-deps",
            "--legacy-peer-deps",
        ),
        ("pnpm add react --force", "--force"),
    ],
)
def test_detects_forced_dependency_resolution(
    raw_text: str,
    option: str,
) -> None:
    """Dependency compatibility checks should not be bypassed silently."""
    findings = NodePackagePack().verify(make_result(raw_text))

    assert len(findings) == 1
    assert findings[0].rule_id == "RBP-NODE-005"
    assert findings[0].evidence[0].message == (
        f"Detected dependency override option: {option}."
    )


def test_npm_install_without_packages_has_ci_repair() -> None:
    """A plain npm install should suggest the CI-specific command."""
    findings = NodePackagePack().verify(make_result("npm install"))

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "RBP-NODE-006"
    assert finding.severity is Severity.WARNING
    assert finding.repair is not None
    assert finding.repair.replacement_text == "npm ci"
    assert finding.repair.confidence is RepairConfidence.LOW
    assert not finding.repair.safe_to_apply


def test_npm_global_options_do_not_hide_install() -> None:
    """Package-manager global options should not hide the subcommand."""
    assert rule_ids("npm --registry https://registry.npmjs.org install") == (
        "RBP-NODE-006",
    )


def test_npm_ci_is_reproducible() -> None:
    """npm ci should not trigger the lockfile reproducibility rule."""
    assert "RBP-NODE-006" not in rule_ids("npm ci")


def test_npm_installing_named_package_avoids_ci_finding() -> None:
    """Installing a named package is distinct from restoring a project."""
    assert "RBP-NODE-006" not in rule_ids("npm install react")


def test_package_after_separator_is_detected() -> None:
    """The explicit option separator should preserve package operands."""
    assert "RBP-NODE-006" not in rule_ids("npm install -- react")


def test_install_option_value_is_not_treated_as_package() -> None:
    """Values belonging to install options are not package operands."""
    assert rule_ids("npm install --workspace frontend") == ("RBP-NODE-006",)


@pytest.mark.parametrize(
    "raw_text",
    [
        "pnpm install --no-frozen-lockfile",
        "pnpm install --frozen-lockfile=false",
        "yarn install --no-immutable",
        "yarn install --immutable=false",
        "npm install react --no-package-lock",
        "npm install react --package-lock=false",
    ],
)
def test_detects_disabled_lockfile_enforcement(
    raw_text: str,
) -> None:
    """Commands should preserve deterministic lockfile behavior."""
    assert "RBP-NODE-006" in rule_ids(raw_text)


@pytest.mark.parametrize(
    "raw_text",
    [
        "npm install react --foreground-scripts",
        "npm install react --ignore-scripts=false",
        "npm install react --unsafe-perm",
        "pnpm add react --unsafe-perm=true",
        "npm config set ignore-scripts false",
        "yarn config set enableScripts true",
    ],
)
def test_detects_explicit_lifecycle_script_execution(
    raw_text: str,
) -> None:
    """Lifecycle scripts can execute package-supplied code."""
    findings = NodePackagePack().verify(make_result(raw_text))

    assert any(finding.rule_id == "RBP-NODE-007" for finding in findings)


def test_ignored_lifecycle_scripts_produce_no_finding() -> None:
    """Disabling lifecycle scripts is not an execution risk."""
    assert "RBP-NODE-007" not in rule_ids("npm install react --ignore-scripts")


@pytest.mark.parametrize(
    "raw_text",
    [
        "npm install react --no-audit",
        "npm install react --audit=false",
        "npm install react --audit=0",
        "npm config set audit false",
        "pnpm add react --no-audit",
    ],
)
def test_detects_disabled_security_checks(
    raw_text: str,
) -> None:
    """Explicitly disabled audit checks should be visible."""
    findings = NodePackagePack().verify(make_result(raw_text))

    assert any(finding.rule_id == "RBP-NODE-008" for finding in findings)


def test_normal_audit_behavior_produces_no_finding() -> None:
    """Normal installations should not trigger the audit rule."""
    assert "RBP-NODE-008" not in rule_ids("npm install react")


def test_legacy_npm_save_option_has_repair() -> None:
    """Redundant npm --save should include a modern replacement."""
    findings = NodePackagePack().verify(make_result("npm install react --save"))

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "RBP-NODE-009"
    assert finding.severity is Severity.INFO
    assert finding.repair is not None
    assert finding.repair.replacement_text == "npm install react"
    assert finding.repair.confidence is RepairConfidence.MEDIUM


def test_save_rule_only_applies_to_npm() -> None:
    """Other package managers should not receive the npm repair."""
    assert "RBP-NODE-009" not in rule_ids("pnpm add react --save")


def test_multiple_findings_have_deterministic_order() -> None:
    """Findings should follow the pack's published rule order."""
    findings = NodePackagePack().verify(
        make_result(
            "npm install -g eslint --force --foreground-scripts --no-audit --save"
        )
    )

    assert tuple(finding.rule_id for finding in findings) == (
        "RBP-NODE-004",
        "RBP-NODE-005",
        "RBP-NODE-007",
        "RBP-NODE-008",
        "RBP-NODE-009",
    )


def test_node_package_pack_integrates_with_engine() -> None:
    """The verification engine should run this pack end to end."""
    report = VerificationEngine(
        packs=(NodePackagePack(),),
    ).analyze_markdown(
        "```bash\nnpx cowsay\n```\n",
        path="README.md",
    )

    assert report.command_count == 1
    assert report.finding_count == 1
    assert report.warning_count == 1
    assert report.error_count == 0
    assert report.pack_names == ("node-package",)
    assert report.findings[0].rule_id == "RBP-NODE-002"

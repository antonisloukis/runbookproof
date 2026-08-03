"""Static verification rules for Git commands in documentation."""

from __future__ import annotations

from runbookproof.models import (
    Evidence,
    EvidenceKind,
    Finding,
    RepairConfidence,
    RepairSuggestion,
    Severity,
    ShellParseResult,
)

_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {
        "-C",
        "-c",
        "--exec-path",
        "--git-dir",
        "--namespace",
        "--super-prefix",
        "--work-tree",
    }
)

_PULL_STRATEGY_OPTIONS = frozenset(
    {
        "--ff",
        "--ff-only",
        "--no-ff",
        "--rebase",
        "--no-rebase",
    }
)


class GitPack:
    """Detect destructive, ambiguous, and outdated Git commands."""

    name = "git"

    def supports(self, result: ShellParseResult) -> bool:
        """Support successfully parsed Git commands."""
        return result.error is None and result.command.executable == "git"

    def verify(
        self,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Return deterministic static findings for one Git command."""
        subcommand, arguments = _split_git_command(result.command.arguments)

        if subcommand is None or _is_help_request(arguments):
            return ()

        findings: list[Finding] = []

        if subcommand == "reset" and "--hard" in arguments:
            findings.append(_hard_reset_finding(result))

        if subcommand == "push":
            if _uses_unsafe_force(arguments):
                findings.append(_force_push_finding(result))
            elif "--force-with-lease" in arguments:
                findings.append(_force_with_lease_finding(result))

        clean_finding = _clean_finding(
            result,
            subcommand=subcommand,
            arguments=arguments,
        )

        if clean_finding is not None:
            findings.append(clean_finding)

        if _forces_branch_deletion(subcommand, arguments):
            findings.append(_forced_branch_deletion_finding(result))

        if _discards_working_tree(subcommand, arguments):
            findings.append(_discarded_changes_finding(result))

        if _deletes_remote_branch(subcommand, arguments):
            findings.append(_remote_branch_deletion_finding(result))

        if subcommand == "pull" and not _has_pull_strategy(arguments):
            findings.append(_ambiguous_pull_finding(result))

        checkout_finding = _legacy_checkout_finding(
            result,
            subcommand=subcommand,
            arguments=arguments,
        )

        if checkout_finding is not None:
            findings.append(checkout_finding)

        if subcommand == "stash" and arguments and arguments[0] in {"clear", "drop"}:
            findings.append(
                _destructive_stash_finding(
                    result,
                    operation=arguments[0],
                )
            )

        return tuple(findings)


def _hard_reset_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a finding for git reset --hard."""
    return Finding(
        rule_id="RBP-GIT-001",
        severity=Severity.ERROR,
        message="Hard reset can permanently discard local changes",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message="Detected `git reset --hard`.",
                source="RunbookProof Git pack",
            ),
        ),
    )


def _force_push_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a finding for an unrestricted forced push."""
    return Finding(
        rule_id="RBP-GIT-002",
        severity=Severity.ERROR,
        message="Forced push can overwrite remote history",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=("Detected an unrestricted Git push force option."),
                source="RunbookProof Git pack",
            ),
        ),
    )


def _force_with_lease_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a finding for the safer forced-push variant."""
    return Finding(
        rule_id="RBP-GIT-003",
        severity=Severity.WARNING,
        message="Force-with-lease can rewrite remote history",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message="Detected `git push --force-with-lease`.",
                source="RunbookProof Git pack",
            ),
        ),
    )


def _clean_finding(
    result: ShellParseResult,
    *,
    subcommand: str,
    arguments: tuple[str, ...],
) -> Finding | None:
    """Return a finding for destructive git clean commands."""
    if subcommand != "clean" or not _has_force_option(arguments):
        return None

    broad_cleanup = (
        _short_option_contains(arguments, "d")
        or _short_option_contains(arguments, "x")
        or "--directories" in arguments
        or "--ignored" in arguments
    )

    if broad_cleanup:
        return Finding(
            rule_id="RBP-GIT-004",
            severity=Severity.ERROR,
            message="Git clean can remove untracked directories or files",
            command=result.command,
            evidence=(
                Evidence(
                    kind=EvidenceKind.STATIC_ANALYSIS,
                    message=(
                        "Detected forced Git cleanup including "
                        "directories or ignored files."
                    ),
                    source="RunbookProof Git pack",
                ),
            ),
        )

    return Finding(
        rule_id="RBP-GIT-004",
        severity=Severity.WARNING,
        message="Git clean permanently removes untracked files",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message="Detected forced execution of `git clean`.",
                source="RunbookProof Git pack",
            ),
        ),
    )


def _forced_branch_deletion_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a finding for forced local branch deletion."""
    return Finding(
        rule_id="RBP-GIT-005",
        severity=Severity.WARNING,
        message="Forced branch deletion can remove unmerged work",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message="Detected forced local branch deletion.",
                source="RunbookProof Git pack",
            ),
        ),
    )


def _discarded_changes_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a finding for commands discarding working-tree changes."""
    return Finding(
        rule_id="RBP-GIT-006",
        severity=Severity.WARNING,
        message="Command can discard working-tree changes",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=(
                    "Detected a checkout or restore operation that "
                    "replaces working-tree content."
                ),
                source="RunbookProof Git pack",
            ),
        ),
    )


def _remote_branch_deletion_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a finding for deleting a remote branch."""
    return Finding(
        rule_id="RBP-GIT-007",
        severity=Severity.WARNING,
        message="Command deletes a remote Git branch",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message="Detected a remote branch deletion push.",
                source="RunbookProof Git pack",
            ),
        ),
    )


def _ambiguous_pull_finding(
    result: ShellParseResult,
) -> Finding:
    """Create a finding for git pull without an explicit strategy."""
    return Finding(
        rule_id="RBP-GIT-008",
        severity=Severity.WARNING,
        message="Git pull does not specify an integration strategy",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=("No explicit fast-forward or rebase strategy was found."),
                source="RunbookProof Git pack",
            ),
        ),
    )


def _legacy_checkout_finding(
    result: ShellParseResult,
    *,
    subcommand: str,
    arguments: tuple[str, ...],
) -> Finding | None:
    """Return a finding for legacy branch-creation checkout syntax."""
    if subcommand != "checkout":
        return None

    branch_name = _argument_after_option(
        arguments,
        options=("-b", "-B"),
    )

    if branch_name is None:
        return None

    replacement = f"git switch -c {branch_name}"

    return Finding(
        rule_id="RBP-GIT-009",
        severity=Severity.INFO,
        message="Branch creation uses legacy checkout syntax",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=("Detected `git checkout -b` or `git checkout -B`."),
                source="RunbookProof Git pack",
            ),
        ),
        repair=RepairSuggestion(
            replacement_text=replacement,
            rationale=(
                "`git switch -c` expresses branch creation more "
                "clearly in modern Git documentation."
            ),
            confidence=RepairConfidence.MEDIUM,
        ),
    )


def _destructive_stash_finding(
    result: ShellParseResult,
    *,
    operation: str,
) -> Finding:
    """Create a finding for deleting Git stash entries."""
    return Finding(
        rule_id="RBP-GIT-010",
        severity=Severity.WARNING,
        message="Command permanently removes Git stash entries",
        command=result.command,
        evidence=(
            Evidence(
                kind=EvidenceKind.STATIC_ANALYSIS,
                message=f"Detected `git stash {operation}`.",
                source="RunbookProof Git pack",
            ),
        ),
    )


def _split_git_command(
    arguments: tuple[str, ...],
) -> tuple[str | None, tuple[str, ...]]:
    """Separate Git global options from its subcommand."""
    index = 0

    while index < len(arguments):
        argument = arguments[index]

        if argument == "--":
            index += 1
            break

        if not argument.startswith("-"):
            return argument, arguments[index + 1 :]

        option_name = argument.split("=", maxsplit=1)[0]

        if option_name in _GLOBAL_OPTIONS_WITH_VALUES and "=" not in argument:
            index += 2
        else:
            index += 1

    if index < len(arguments):
        return arguments[index], arguments[index + 1 :]

    return None, ()


def _is_help_request(arguments: tuple[str, ...]) -> bool:
    """Return whether the Git invocation only requests help."""
    return any(argument in {"-h", "--help"} for argument in arguments)


def _uses_unsafe_force(
    arguments: tuple[str, ...],
) -> bool:
    """Return whether push uses unrestricted force."""
    return "--force" in arguments or _short_option_contains(arguments, "f")


def _has_force_option(
    arguments: tuple[str, ...],
) -> bool:
    """Return whether a Git command contains a force option."""
    return "--force" in arguments or _short_option_contains(arguments, "f")


def _short_option_contains(
    arguments: tuple[str, ...],
    option: str,
) -> bool:
    """Return whether a combined short-option token contains a flag."""
    return any(
        argument.startswith("-")
        and not argument.startswith("--")
        and option in argument[1:]
        for argument in arguments
    )


def _forces_branch_deletion(
    subcommand: str,
    arguments: tuple[str, ...],
) -> bool:
    """Return whether git branch forces deletion."""
    if subcommand != "branch":
        return False

    return "-D" in arguments or (
        ("-d" in arguments or "--delete" in arguments) and _has_force_option(arguments)
    )


def _discards_working_tree(
    subcommand: str,
    arguments: tuple[str, ...],
) -> bool:
    """Return whether checkout or restore may discard local changes."""
    if subcommand == "checkout":
        return "--" in arguments

    if subcommand != "restore":
        return False

    has_target = any(not argument.startswith("-") for argument in arguments)

    affects_worktree = "--worktree" in arguments or "--staged" not in arguments

    return has_target and affects_worktree


def _deletes_remote_branch(
    subcommand: str,
    arguments: tuple[str, ...],
) -> bool:
    """Return whether a push deletes a remote branch."""
    if subcommand != "push":
        return False

    return "--delete" in arguments or any(
        argument.startswith(":") and len(argument) > 1 for argument in arguments
    )


def _has_pull_strategy(
    arguments: tuple[str, ...],
) -> bool:
    """Return whether git pull specifies integration behavior."""
    return any(
        argument in _PULL_STRATEGY_OPTIONS or argument.startswith("--rebase=")
        for argument in arguments
    )


def _argument_after_option(
    arguments: tuple[str, ...],
    *,
    options: tuple[str, ...],
) -> str | None:
    """Return the argument immediately following one option."""
    for index, argument in enumerate(arguments):
        if argument not in options:
            continue

        next_index = index + 1

        if next_index >= len(arguments):
            return None

        candidate = arguments[next_index]

        if candidate.startswith("-"):
            return None

        return candidate

    return None

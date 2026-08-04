import shlex
from dataclasses import dataclass

from runbookproof.models import (
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    ShellParseResult,
)

_AZURE_GLOBAL_FLAGS = {
    "--debug",
    "--help",
    "--only-show-errors",
    "--verbose",
}

_AZURE_GLOBAL_OPTIONS_WITH_VALUES = {
    "--output",
    "--query",
    "--subscription",
    "--tenant",
    "-o",
}

_PRIVILEGED_ROLES = {
    "contributor",
    "owner",
    "role based access control administrator",
    "user access administrator",
}

_PUBLIC_SOURCES = {
    "*",
    "0.0.0.0/0",
    "::/0",
    "any",
    "internet",
}

_PUBLIC_ACCESS_LEVELS = {
    "blob",
    "container",
}


@dataclass(frozen=True)
class AzureInvocation:
    command: tuple[str, ...]
    arguments: tuple[str, ...]

    @property
    def group(self) -> str:
        if not self.command:
            return ""
        return self.command[0]

    @property
    def operation(self) -> str:
        if not self.command:
            return ""
        return self.command[-1]


def parse_azure_command(command: str) -> AzureInvocation | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None

    if not tokens or tokens[0].lower() != "az":
        return None

    index = 1

    # Skip Azure global options placed before the command group.
    while index < len(tokens) and tokens[index].startswith("-"):
        option = tokens[index].lower()

        if option in _AZURE_GLOBAL_FLAGS or "=" in option:
            index += 1
            continue

        if option in _AZURE_GLOBAL_OPTIONS_WITH_VALUES:
            if index + 1 >= len(tokens):
                return None

            index += 2
            continue

        return None

    command_parts: list[str] = []

    while index < len(tokens) and not tokens[index].startswith("-"):
        command_parts.append(tokens[index].lower())
        index += 1

    if len(command_parts) < 2:
        return None

    return AzureInvocation(
        command=tuple(command_parts),
        arguments=tuple(tokens[index:]),
    )


def _option_value(
    arguments: tuple[str, ...],
    *option_names: str,
) -> str | None:
    normalized_names = {name.lower() for name in option_names}

    for index, argument in enumerate(arguments):
        normalized_argument = argument.lower()

        if normalized_argument in normalized_names:
            if index + 1 >= len(arguments):
                return None

            value = arguments[index + 1]

            if value.startswith("-"):
                return None

            return value

        for option_name in normalized_names:
            prefix = f"{option_name}="

            if normalized_argument.startswith(prefix):
                return argument[len(prefix) :]

    return None


def _normalized_option(
    arguments: tuple[str, ...],
    *option_names: str,
) -> str | None:
    value = _option_value(arguments, *option_names)

    if value is None:
        return None

    return value.strip().lower()


def _is_broad_scope(scope: str | None) -> bool:
    if scope is None:
        return False

    normalized_scope = scope.strip().lower().strip("/")
    parts = normalized_scope.split("/")

    # /subscriptions/<subscription-id>
    if len(parts) == 2 and parts[0] == "subscriptions":
        return True

    return normalized_scope.startswith(
        "providers/microsoft.management/managementgroups/"
    )


def detect_azure_problem(
    invocation: AzureInvocation,
) -> str | None:
    if invocation.command == ("group", "delete"):
        return "Detected deletion of an Azure resource group."

    if invocation.command == ("role", "assignment", "create"):
        role = _normalized_option(
            invocation.arguments,
            "--role",
        )
        scope = _normalized_option(
            invocation.arguments,
            "--scope",
        )

        if role in _PRIVILEGED_ROLES:
            return "Detected assignment of a privileged Azure role."

        if _is_broad_scope(scope):
            return (
                "Detected Azure role assignment at subscription "
                "or management-group scope."
            )

    if invocation.command in {
        ("network", "nsg", "rule", "create"),
        ("network", "nsg", "rule", "update"),
    }:
        access = _normalized_option(
            invocation.arguments,
            "--access",
        )
        direction = _normalized_option(
            invocation.arguments,
            "--direction",
        )
        source = _normalized_option(
            invocation.arguments,
            "--source-address-prefix",
            "--source-address-prefixes",
        )

        if access == "allow" and direction == "inbound" and source in _PUBLIC_SOURCES:
            return "Detected an inbound Azure NSG rule open to the public internet."

    if invocation.command == (
        "storage",
        "container",
        "set-permission",
    ):
        public_access = _normalized_option(
            invocation.arguments,
            "--public-access",
        )

        if public_access in _PUBLIC_ACCESS_LEVELS:
            return "Detected public access on an Azure Storage container."

    return None


def analyze_azure_command(command: str) -> str | None:
    invocation = parse_azure_command(command)

    if invocation is None:
        return None

    return detect_azure_problem(invocation)


_AZURE_FINDING_METADATA: dict[
    str,
    tuple[str, Severity, str],
] = {
    "Detected deletion of an Azure resource group.": (
        "RBP-AZURE-001",
        Severity.ERROR,
        "Azure CLI command deletes a resource group",
    ),
    "Detected assignment of a privileged Azure role.": (
        "RBP-AZURE-002",
        Severity.ERROR,
        "Azure CLI command assigns a privileged role",
    ),
    ("Detected Azure role assignment at subscription or management-group scope."): (
        "RBP-AZURE-003",
        Severity.WARNING,
        "Azure role assignment uses a broad scope",
    ),
    ("Detected an inbound Azure NSG rule open to the public internet."): (
        "RBP-AZURE-004",
        Severity.ERROR,
        "Azure NSG ingress is open to the public internet",
    ),
    "Detected public access on an Azure Storage container.": (
        "RBP-AZURE-005",
        Severity.ERROR,
        "Azure Storage container allows public access",
    ),
}


class AzureCliPack:
    """Detect dangerous and overly permissive Azure CLI commands."""

    name = "azure-cli"

    def supports(self, result: ShellParseResult) -> bool:
        """Support successfully parsed Azure CLI operations."""
        return (
            result.error is None
            and result.command.executable == "az"
            and parse_azure_command(result.command.raw_text) is not None
        )

    def verify(
        self,
        result: ShellParseResult,
    ) -> tuple[Finding, ...]:
        """Return deterministic findings for one Azure CLI command."""
        if result.error is not None:
            return ()

        invocation = parse_azure_command(result.command.raw_text)

        if invocation is None:
            return ()

        problem = detect_azure_problem(invocation)

        if problem is None:
            return ()

        rule_id, severity, message = _AZURE_FINDING_METADATA[problem]

        return (
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                command=result.command,
                evidence=(
                    Evidence(
                        kind=EvidenceKind.STATIC_ANALYSIS,
                        message=problem,
                        source="RunbookProof Azure CLI pack",
                    ),
                ),
            ),
        )

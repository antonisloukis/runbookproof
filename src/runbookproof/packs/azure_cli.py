import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class AzureInvocation:
    group: str
    operation: str
    arguments: tuple[str, ...]


def parse_azure_command(command: str) -> AzureInvocation | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None

    if len(tokens) < 3:
        return None

    if tokens[0] != "az":
        return None

    return AzureInvocation(
        group=tokens[1].lower(),
        operation=tokens[2].lower(),
        arguments=tuple(tokens[3:]),
    )


def detect_azure_problem(
    invocation: AzureInvocation,
) -> str | None:
    if (
        invocation.group == "group"
        and invocation.operation == "delete"
    ):
        return "Detected deletion of an Azure resource group."

    return None


def analyze_azure_command(command: str) -> str | None:
    invocation = parse_azure_command(command)

    if invocation is None:
        return None

    return detect_azure_problem(invocation)
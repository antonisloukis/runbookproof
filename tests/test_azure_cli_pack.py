from runbookproof.packs.azure_cli import (
    AzureInvocation,
    analyze_azure_command,
    detect_azure_problem,
    parse_azure_command,
)


def test_parses_basic_azure_command():
    invocation = parse_azure_command(
        "az group delete --name production --yes"
    )

    assert invocation is not None
    assert invocation.group == "group"
    assert invocation.operation == "delete"
    assert invocation.arguments == (
        "--name",
        "production",
        "--yes",
    )


def test_parses_quoted_argument():
    invocation = parse_azure_command(
        'az group delete --name "production resources"'
    )

    assert invocation is not None
    assert invocation.arguments == (
        "--name",
        "production resources",
    )


def test_parser_ignores_non_azure_command():
    assert parse_azure_command("aws s3 ls") is None


def test_rejects_empty_command():
    assert parse_azure_command("") is None


def test_rejects_incomplete_azure_command():
    assert parse_azure_command("az group") is None


def test_rejects_invalid_quotes():
    command = 'az group delete --name "broken'

    assert parse_azure_command(command) is None


def test_detects_resource_group_deletion():
    invocation = AzureInvocation(
        group="group",
        operation="delete",
        arguments=("--name", "production"),
    )

    result = detect_azure_problem(invocation)

    assert result == "Detected deletion of an Azure resource group."


def test_safe_resource_group_list_has_no_problem():
    invocation = AzureInvocation(
        group="group",
        operation="list",
        arguments=(),
    )

    assert detect_azure_problem(invocation) is None


def test_analyzes_destructive_command():
    result = analyze_azure_command(
        "az group delete --name production"
    )

    assert result == "Detected deletion of an Azure resource group."


def test_analyzes_safe_command():
    assert analyze_azure_command("az group list") is None


def test_analyzer_ignores_non_azure_command():
    assert analyze_azure_command("kubectl get pods") is None
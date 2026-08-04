from runbookproof.packs.azure_cli import (
    AzureInvocation,
    analyze_azure_command,
    detect_azure_problem,
    parse_azure_command,
)


def test_parses_basic_azure_command():
    invocation = parse_azure_command("az group delete --name production --yes")

    assert invocation is not None
    assert invocation.command == ("group", "delete")
    assert invocation.group == "group"
    assert invocation.operation == "delete"
    assert invocation.arguments == (
        "--name",
        "production",
        "--yes",
    )


def test_parses_nested_azure_command():
    invocation = parse_azure_command(
        "az role assignment create --role Owner --scope /subscriptions/example"
    )

    assert invocation is not None
    assert invocation.command == (
        "role",
        "assignment",
        "create",
    )


def test_parses_quoted_argument():
    invocation = parse_azure_command('az group delete --name "production resources"')

    assert invocation is not None
    assert invocation.arguments == (
        "--name",
        "production resources",
    )


def test_parses_leading_global_option():
    invocation = parse_azure_command(
        "az --subscription example-subscription group list"
    )

    assert invocation is not None
    assert invocation.command == ("group", "list")
    assert invocation.arguments == ()


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
        command=("group", "delete"),
        arguments=("--name", "production"),
    )

    result = detect_azure_problem(invocation)

    assert result == "Detected deletion of an Azure resource group."


def test_safe_resource_group_list_has_no_problem():
    invocation = AzureInvocation(
        command=("group", "list"),
        arguments=(),
    )

    assert detect_azure_problem(invocation) is None


def test_detects_privileged_owner_assignment():
    command = (
        "az role assignment create "
        "--assignee admin@example.com "
        "--role Owner "
        "--scope /subscriptions/example"
    )

    result = analyze_azure_command(command)

    assert result == "Detected assignment of a privileged Azure role."


def test_detects_privileged_contributor_assignment():
    command = (
        "az role assignment create "
        "--assignee automation-account "
        "--role Contributor "
        "--scope /subscriptions/example/resourceGroups/app"
    )

    result = analyze_azure_command(command)

    assert result == "Detected assignment of a privileged Azure role."


def test_detects_subscription_scope_assignment():
    command = (
        "az role assignment create "
        "--assignee developer@example.com "
        "--role Reader "
        "--scope /subscriptions/example"
    )

    result = analyze_azure_command(command)

    assert result == (
        "Detected Azure role assignment at subscription or management-group scope."
    )


def test_resource_scoped_reader_assignment_has_no_problem():
    command = (
        "az role assignment create "
        "--assignee developer@example.com "
        "--role Reader "
        "--scope /subscriptions/example/resourceGroups/app/"
        "providers/Microsoft.Storage/storageAccounts/example"
    )

    assert analyze_azure_command(command) is None


def test_detects_public_inbound_nsg_rule():
    command = (
        "az network nsg rule create "
        "--resource-group production "
        "--nsg-name web-nsg "
        "--name allow-public "
        "--priority 100 "
        "--direction Inbound "
        "--access Allow "
        "--source-address-prefixes 0.0.0.0/0 "
        "--destination-port-ranges 22"
    )

    result = analyze_azure_command(command)

    assert result == ("Detected an inbound Azure NSG rule open to the public internet.")


def test_private_inbound_nsg_rule_has_no_problem():
    command = (
        "az network nsg rule create "
        "--resource-group production "
        "--nsg-name web-nsg "
        "--name allow-private "
        "--priority 100 "
        "--direction Inbound "
        "--access Allow "
        "--source-address-prefixes 10.0.0.0/8 "
        "--destination-port-ranges 443"
    )

    assert analyze_azure_command(command) is None


def test_outbound_public_nsg_rule_has_no_problem():
    command = (
        "az network nsg rule create "
        "--resource-group production "
        "--nsg-name web-nsg "
        "--name outbound-rule "
        "--priority 100 "
        "--direction Outbound "
        "--access Allow "
        "--source-address-prefixes 0.0.0.0/0"
    )

    assert analyze_azure_command(command) is None


def test_detects_public_storage_container():
    command = (
        "az storage container set-permission "
        "--name public-assets "
        "--account-name example "
        "--public-access container"
    )

    result = analyze_azure_command(command)

    assert result == ("Detected public access on an Azure Storage container.")


def test_detects_blob_public_access():
    command = (
        "az storage container set-permission "
        "--name public-assets "
        "--account-name example "
        "--public-access blob"
    )

    result = analyze_azure_command(command)

    assert result == ("Detected public access on an Azure Storage container.")


def test_private_storage_container_has_no_problem():
    command = (
        "az storage container set-permission "
        "--name private-assets "
        "--account-name example "
        "--public-access off"
    )

    assert analyze_azure_command(command) is None


def test_analyzes_safe_command():
    assert analyze_azure_command("az group list") is None


def test_analyzer_ignores_non_azure_command():
    assert analyze_azure_command("kubectl get pods") is None

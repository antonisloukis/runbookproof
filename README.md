<p align="center">
  <img
    src="docs/assets/runbookproof-icon.png"
    alt="RunbookProof logo"
    width="170"
  />
</p>

# RunbookProof

[![CI](https://github.com/antonisloukis/runbookproof/actions/workflows/ci.yml/badge.svg)](https://github.com/antonisloukis/runbookproof/actions/workflows/ci.yml)
[![Code Scanning](https://github.com/antonisloukis/runbookproof/actions/workflows/code-scanning.yml/badge.svg)](https://github.com/antonisloukis/runbookproof/actions/workflows/code-scanning.yml)

**Static analysis for commands embedded in documentation, operational runbooks, and AI-generated instructions.**

RunbookProof finds risky infrastructure and shell commands before they are copied, reviewed, or executed. It scans Markdown files without running any command and produces human-readable, JSON, or SARIF 2.1.0 reports.

> **Project status:** Pre-alpha `0.1.0`. Rule coverage and interfaces may change before the first stable release.

## Why RunbookProof?

Operational commands increasingly live in:

- deployment and incident-response runbooks
- project documentation
- internal knowledge bases
- AI-generated troubleshooting instructions
- pull requests and code reviews

A command can look reasonable while still deleting resources, exposing services publicly, assigning excessive privileges, or using unsafe shell behavior.

RunbookProof provides an automated verification layer between written instructions and execution.

## Highlights

- Static analysis only — commands are never executed
- Scans individual Markdown files or complete directories
- Recursively discovers `.md` files
- Detects commands inside fenced code blocks
- Uses specialized verification packs for common DevOps tools
- Reports rule IDs, severities, evidence, source lines, and stable fingerprints
- Supports text, JSON, and SARIF 2.1.0 output
- Writes reports directly to files with `-o` or `--output`
- Integrates with GitHub Code Scanning
- Produces deterministic machine-readable output
- Supports Python 3.11 through Python 3.14

## Quick start

RunbookProof currently installs from source.

```bash
git clone https://github.com/antonisloukis/runbookproof.git
cd runbookproof
uv sync --frozen
uv run runbookproof --version
```

Scan one Markdown file:

```bash
uv run runbookproof scan README.md
```

Scan every Markdown file in a directory:

```bash
uv run runbookproof scan docs/
```

## Usage

```text
runbookproof scan PATH [--format {text,json,sarif}] [-o OUTPUT] [--ignore-rule RULE_ID] [--config PATH]
runbookproof rules [--format {text,json}]
```

### Human-readable output

Text is the default output format:

```bash
uv run runbookproof scan docs/
```

### JSON output

Print JSON to standard output:

```bash
uv run runbookproof scan docs/ --format json
```

Write JSON directly to a file:

```bash
uv run runbookproof scan docs/ \
  --format json \
  --output report.json
```

JSON reports include:

- scan and finding counts
- error, warning, and informational counts
- activated verification packs
- command metadata and source locations
- finding evidence
- stable fingerprints
- the resulting process exit code

### SARIF output

Generate a SARIF 2.1.0 report:

```bash
uv run runbookproof scan docs/ \
  --format sarif \
  --output runbookproof.sarif
```

SARIF output can be consumed by GitHub Code Scanning and other SARIF-compatible analysis platforms.

### Short output option

`-o` is an alias for `--output`:

```bash
uv run runbookproof scan README.md \
  --format sarif \
  -o runbookproof.sarif
```

### Ignore selected rules

Ignore a finding by its rule ID:

```bash
uv run runbookproof scan docs/ \
  --ignore-rule RBP-AZURE-001
```

The option can be repeated and rule IDs are case-insensitive:

```bash
uv run runbookproof scan docs/ \
  --ignore-rule RBP-AZURE-001 \
  --ignore-rule RBP-AWS-002
```

Ignored findings are removed from text, JSON, and SARIF output. They are also excluded from finding counts and exit-code calculation.

### Configuration file

RunbookProof automatically loads `.runbookproof.toml` from the current working directory when the file exists:

```toml
[scan]
ignore_rules = [
  "RBP-AZURE-001",
  "RBP-AWS-002",
]
```

Run the scan normally:

```bash
uv run runbookproof scan docs/
```

Rules from the configuration file are combined with any `--ignore-rule` options supplied on the command line.

Use a different configuration file with `--config`:

```bash
uv run runbookproof scan docs/ \
  --config config/runbookproof.toml
```

An explicitly selected configuration file must exist and contain valid TOML.

## Rule catalogue

List every built-in rule:

```bash
uv run runbookproof rules
```

Generate machine-readable output:

```bash
uv run runbookproof rules --format json
```

The complete reference is available in
[`docs/rules.md`](docs/rules.md).

## Built-in verification packs

| Pack | Command family |
|---|---|
| AWS CLI | `aws` |
| Azure CLI | `az` |
| Bash | shell commands and operators |
| Docker | `docker` |
| Git | `git` |
| Kubernetes | `kubectl` |
| Node packages | npm-compatible package commands |
| Python packages | pip-compatible package commands |
| Terraform | `terraform` |
| Universal | cross-tool safety checks |

The verification engine runs applicable packs against each extracted command and combines their findings into a single report.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Scan completed without error-level findings |
| `1` | Scan completed and detected one or more error-level findings |
| `2` | RunbookProof could not complete the scan or write its output |

Warnings and informational findings do not produce exit code `1`.

## GitHub Code Scanning

This repository contains a workflow that:

1. scans repository Markdown files
2. generates a SARIF report
3. uploads the report to GitHub Code Scanning
4. fails the workflow when error-level findings are present

A minimal integration follows the same pattern:

```yaml
name: RunbookProof

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v6

      - uses: astral-sh/setup-uv@v8
        with:
          python-version: "3.11"

      - name: Generate SARIF
        run: |
          uvx --from . runbookproof scan . \
            --format sarif \
            --output runbookproof.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: runbookproof.sarif
```

For production workflows, pin third-party actions to full commit SHAs.

## How it works

```text
Markdown input
      │
      ▼
Command extraction
      │
      ▼
Normalized command model
      │
      ▼
Applicable verification packs
      │
      ▼
Findings and supporting evidence
      │
      ▼
Text, JSON, or SARIF report
```

RunbookProof separates extraction, command modeling, verification, and report rendering. This makes individual verification packs independently testable and allows new command families to be added without redesigning the analysis engine.

## Development

Install the locked development environment:

```bash
uv sync --frozen
```

Run formatting checks:

```bash
uv run ruff format --check .
```

Run linting:

```bash
uv run ruff check .
```

Run strict type checking:

```bash
uv run mypy
```

Run the complete test suite:

```bash
uv run pytest
```

Run all local validation commands together:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
git diff --check
```

## Release process

Release preparation and publishing instructions are documented in
[`docs/releasing.md`](docs/releasing.md).

Release history is maintained in
[`CHANGELOG.md`](CHANGELOG.md).

## Roadmap

- Finding suppression with documented justifications
- Custom and third-party verification packs
- Reusable GitHub Action distribution
- First public package release

## Security model

RunbookProof analyzes command text only. It does not execute commands, access cloud accounts, change infrastructure, or require cloud credentials.

Because static analysis cannot understand every operational context, findings should support — not replace — human review.

## License

Licensed under the [Apache License 2.0](LICENSE).

---

Built by [Antonis Loukis](https://github.com/antonisloukis).

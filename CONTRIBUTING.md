# Contributing to RunbookProof

Thank you for your interest in contributing to RunbookProof.

RunbookProof is a static-analysis tool for identifying risky commands inside documentation, operational runbooks, and AI-generated instructions.

Contributions involving detection rules, tests, documentation, integrations, bug fixes, and code-quality improvements are welcome.

## Before Contributing

Before opening an issue or pull request:

1. Search the existing issues and pull requests.
2. Confirm that the problem or suggestion has not already been reported.
3. Open an issue before beginning a large feature or architectural change.
4. Do not publicly report security vulnerabilities. Follow the instructions in `SECURITY.md`.

Small documentation fixes and straightforward bug fixes do not normally require prior discussion.

## Development Setup

Fork the repository and clone your fork:

```bash
git clone https://github.com/YOUR-USERNAME/runbookproof.git
cd runbookproof
```

Add the original repository as the upstream remote:

```bash
git remote add upstream https://github.com/antonisloukis/runbookproof.git
```

Install the project and development dependencies:

```bash
uv sync --frozen
```

Confirm that the CLI works:

```bash
uv run runbookproof --version
```

## Create a Branch

Create a focused branch for your change:

```bash
git checkout -b feature/your-feature-name
```

Suggested branch prefixes:

- `feature/` for new functionality
- `fix/` for bug fixes
- `docs/` for documentation
- `rule/` for detection-rule additions
- `test/` for test improvements
- `refactor/` for internal restructuring

Examples:

```text
feature/add-sarif-metadata
fix/markdown-line-numbers
rule/detect-unsafe-kubectl-delete
docs/improve-installation-guide
```

## Code Standards

Contributions should:

- Support Python 3.11 or newer.
- Follow the existing project structure.
- Use clear and descriptive names.
- Include type annotations.
- Avoid unnecessary dependencies.
- Keep static analysis deterministic.
- Never execute commands being scanned.
- Include tests for new behavior.
- Update documentation when user-facing behavior changes.

RunbookProof must remain a static-analysis tool. A contribution must not execute commands extracted from documentation.

## Detection Rules

New or modified detection rules should include:

- A stable rule ID
- A clear description
- An appropriate severity
- Evidence explaining why the command matched
- Positive test cases that should produce findings
- Negative test cases that should not produce findings
- Documentation when the rule changes user-visible behavior

Avoid rules that produce excessive false positives without providing meaningful security value.

## Run the Quality Checks

Before submitting a pull request, run:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

All checks must pass.

## Commit Messages

Use concise and descriptive commit messages.

Good examples:

```text
Add detection for unsafe Terraform destroy commands
Fix Markdown source line tracking
Improve SARIF result metadata
Add tests for kubectl exposure rules
Update installation documentation
```

Avoid unclear messages such as:

```text
Update files
Fix stuff
Changes
Final
```

## Pull Requests

Each pull request should:

1. Focus on one feature, fix, or improvement.
2. Explain what changed and why.
3. Link the related issue when applicable.
4. Describe how the change was tested.
5. Include tests for new behavior.
6. Pass all automated checks.
7. Avoid unrelated formatting or refactoring changes.

For rule changes, include examples of commands that should and should not generate findings.

## Reporting Bugs

A useful bug report should contain:

- The RunbookProof version
- The Python version
- The operating system
- The command that was run
- A minimal Markdown example
- Expected behavior
- Actual behavior
- Relevant terminal output

Remove credentials, tokens, private infrastructure names, and other sensitive information before posting examples.

## Feature Requests

Feature requests should describe:

- The problem being solved
- The proposed behavior
- The expected users
- Possible implementation considerations
- Alternative approaches considered

## Code of Conduct

All contributors must follow the repository's `CODE_OF_CONDUCT.md`.

## License

By contributing to RunbookProof, you agree that your contribution may be distributed under the repository's Apache License 2.0.

Thank you for helping improve RunbookProof.

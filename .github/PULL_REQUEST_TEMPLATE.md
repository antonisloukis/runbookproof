## Summary

Describe the purpose of this pull request and the problem it solves.

## Changes

List the main changes included in this pull request.

- 
- 
- 

## Related Issue

Link the issue related to this pull request.

```text
Closes #
```

Remove this section if there is no related issue.

## Type of Change

Select every option that applies.

- [ ] Bug fix
- [ ] New feature
- [ ] Detection-rule addition
- [ ] Detection-rule modification
- [ ] Documentation update
- [ ] Refactoring
- [ ] Test improvement
- [ ] Performance improvement
- [ ] CI or GitHub Actions change
- [ ] Maintenance change
- [ ] Breaking change

## Testing

Describe how you tested the changes.

Include:

- The commands you ran
- The operating system used
- The Python version used
- Any relevant input files
- The expected and actual results

### Quality checks

Confirm that you ran:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

Test results:

```text
Paste or summarize the relevant test results here.
```

## Example Input and Output

Include this section when the pull request changes scanning behavior, CLI output, JSON output, or SARIF output.

### Example input

```markdown
Add a minimal example that demonstrates the change.
```

### Previous output

```text
Add the previous output when relevant.
```

### New output

```text
Add the new output when relevant.
```

## Detection-Rule Checklist

Complete this section when adding or modifying a detection rule.

- [ ] The rule has a stable and descriptive rule ID.
- [ ] The rule description clearly explains the detected risk.
- [ ] The severity level is appropriate.
- [ ] The finding includes useful evidence.
- [ ] The finding reports the correct source file.
- [ ] The finding reports the correct source line.
- [ ] Positive test cases were added.
- [ ] Negative test cases were added.
- [ ] False-positive risks were considered.
- [ ] False-negative risks were considered.
- [ ] The rule behaves deterministically.
- [ ] User-facing documentation was updated where necessary.

## Security Checklist

- [ ] This change does not execute commands extracted from scanned files.
- [ ] This change does not expose secrets or credentials.
- [ ] This change does not include private infrastructure information.
- [ ] Untrusted file paths and input are handled safely.
- [ ] Error messages do not expose sensitive information.
- [ ] New dependencies were reviewed before being added.
- [ ] Security-relevant behavior is covered by tests.

## Documentation Checklist

- [ ] The README was updated where necessary.
- [ ] CLI usage documentation was updated where necessary.
- [ ] Configuration documentation was updated where necessary.
- [ ] The changelog was updated where appropriate.
- [ ] Examples match the current project behavior.
- [ ] No documentation update is required.

## General Checklist

- [ ] My pull request focuses on one feature, fix, or improvement.
- [ ] I reviewed my own changes.
- [ ] I followed the existing project structure and code style.
- [ ] I used clear names for functions, classes, variables, and files.
- [ ] I added or updated type annotations where appropriate.
- [ ] I added or updated tests where necessary.
- [ ] All local tests pass.
- [ ] All formatting, linting, and type-checking commands pass.
- [ ] I removed debugging code and temporary files.
- [ ] I did not include unrelated formatting or refactoring changes.
- [ ] I did not include passwords, tokens, credentials, or private information.
- [ ] I followed the repository's contributing guidelines.
- [ ] I followed the repository's Code of Conduct.

## Breaking Changes

Describe any breaking changes and explain what users must do to migrate.

Write:

```text
None
```

when this pull request introduces no breaking changes.

## Screenshots or Recordings

Add screenshots, terminal output, or recordings when the change affects visible behavior.

Remove this section when it is not applicable.

## Additional Context

Add any other information that reviewers should know.

This may include:

- Design decisions
- Alternatives considered
- Known limitations
- Follow-up work
- Compatibility considerations
- Performance implications

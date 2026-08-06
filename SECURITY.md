# Security Policy

## Supported Versions

RunbookProof is currently a pre-alpha project.

Security updates are applied to the latest available version. Older development versions may not receive separate security patches.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.

Report potential vulnerabilities privately by emailing:

```text
contact@antonisloukis.dev
```

Please include:

- A clear description of the vulnerability
- The affected RunbookProof version
- Steps to reproduce the issue
- A minimal proof of concept when possible
- The potential security impact
- Suggested remediation, if available

Remove unrelated credentials, tokens, private infrastructure information, and personal data from the report.

## Response Process

After receiving a report, the maintainer will attempt to:

1. Acknowledge the report.
2. Reproduce and evaluate the issue.
3. Determine its severity and affected versions.
4. Develop and test an appropriate fix.
5. Coordinate disclosure when necessary.
6. Publish the fix and relevant release information.

Please allow reasonable time for investigation before publicly disclosing a vulnerability.

## Scope

Examples of relevant security issues include:

- Command execution caused by scanning untrusted input
- Path traversal or unintended file access
- Unsafe temporary-file handling
- Incorrect handling of malicious Markdown
- SARIF or JSON output injection
- Dependency vulnerabilities affecting RunbookProof
- Detection bypasses that create a meaningful security impact

Ordinary false positives, false negatives, feature requests, and non-security bugs should be reported through the normal GitHub issue templates.

## Safe Harbor

Security research conducted in good faith and in accordance with this policy will be treated as authorized.

Please:

- Avoid accessing, modifying, or deleting data that does not belong to you.
- Avoid disrupting services or other users.
- Use only the minimum testing necessary to demonstrate the vulnerability.
- Stop testing and report the issue if sensitive information is encountered.
- Keep vulnerability details private until a fix or coordinated disclosure is agreed upon.

## Disclosure

Please do not publicly disclose a vulnerability before the maintainer has had a reasonable opportunity to investigate and address it.

Where appropriate, the reporter may be credited in the release notes or security advisory unless anonymity is requested.

Thank you for responsibly reporting security issues.

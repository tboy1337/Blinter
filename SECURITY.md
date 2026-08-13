# Security Policy

## Supported Versions

Security fixes are provided for the latest release on [PyPI](https://pypi.org/project/Blinter/) and the `main` branch of this repository.

| Version | Supported |
| ------- | --------- |
| Latest  | Yes       |
| Older   | No        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use one of the following channels:

1. **GitHub private vulnerability reporting (preferred)**  
   Open the [Security](https://github.com/tboy1337/Blinter/security) tab on this repository and choose **Report a vulnerability**. GitHub keeps the report private while we investigate.

2. **Email**  
   Send details to [tboy1337@proton.me](mailto:tboy1337@proton.me) with the subject line `Blinter security`. Encrypt sensitive details with PGP if possible.

Include as much of the following as you can:

- A description of the issue and its impact
- Steps to reproduce, or a proof-of-concept
- Affected version(s)
- Any suggested fix or mitigation

## Response Timeline

- **Initial response:** within 14 days of a valid report
- **Status updates:** at least every 14 days until the issue is resolved
- **Fix target:** critical issues as soon as practical; other confirmed issues in the next planned release when feasible

We will credit reporters in release notes when they wish to be named.

## Secure Use

Blinter is a static analyzer for batch files. It reads files you point it at and does not execute batch code. For safe operation:

- Run Blinter only on files and directories you trust
- Review findings before applying suggested changes to production scripts
- Keep Blinter updated to receive security fixes in dependencies and the linter itself

Dependency vulnerabilities are monitored in CI with [pip-audit](https://pypi.org/project/pip-audit/) and addressed through routine releases.

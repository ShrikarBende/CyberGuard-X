# Security Policy

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report vulnerabilities privately to the project maintainer (**Shrikar Bende**) via GitHub's private vulnerability reporting ("Report a vulnerability" under the repository's **Security** tab) or direct private contact, including:

- A description of the vulnerability and affected component/file path
- Steps to reproduce or a minimal proof of concept
- Potential impact and any suggested remediation

You should receive an acknowledgment within 7 days. Please allow time to investigate and release a fix before public disclosure.

## Model Artifact Security

For details on model bundle SHA-256/HMAC-SHA256 verification, `ARTIFACT_HMAC_KEY` management and rotation, `ALLOW_UNSIGNED_MODELS` behavior, and the safe-format migration roadmap, see [docs/MODEL_ARTIFACT_SECURITY.md](docs/MODEL_ARTIFACT_SECURITY.md).

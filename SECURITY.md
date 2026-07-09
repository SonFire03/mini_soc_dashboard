# Security Policy

## Supported Versions

Security fixes are provided on a best-effort basis for the most recent release on `main`.

| Version | Supported |
| --- | --- |
| latest | yes |
| older releases | no |

## Reporting a Vulnerability

Do not open a public GitHub issue for a security vulnerability.

Report security issues privately to the maintainer with:
- a clear summary of the issue,
- impact assessment,
- affected version or commit,
- reproduction steps,
- proof of concept if available,
- suggested remediation if you have one.

If a dedicated security contact is later added to the project, this file should be updated to point to it explicitly.

Until then, use GitHub private reporting if enabled for the repository. If private reporting is not available, contact the maintainer directly through a private channel.

## Scope

This policy applies in particular to:
- authentication and session handling,
- role or permission bypass,
- log ingestion abuse,
- path traversal or filesystem escape,
- live-tail access control,
- report export exposure,
- stored or reflected XSS in the dashboard,
- SQLite backup and restore abuse,
- secrets handling and unsafe defaults.

## Out of Scope

The following are generally out of scope unless they create a real security impact:
- self-XSS without privilege impact,
- missing best practices without an exploitable path,
- vulnerabilities in third-party software without a project-specific exploit path,
- issues requiring local shell access already equivalent to full compromise,
- denial of service based only on unrealistic local lab conditions.

## Handling Expectations

Target handling expectations:
- initial acknowledgement within 7 days,
- triage after reproduction,
- remediation timeline based on severity and exploitability,
- coordinated disclosure after a fix is available.

## Sensitive Data

Do not send:
- real production logs,
- credentials,
- API keys,
- tokens,
- personal data,
- internal infrastructure details that are not required to reproduce the issue.

Use sanitized samples whenever possible.

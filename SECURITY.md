# Security Policy

## Authorized Use

Bug Hunter Pro is intended for defensive testing of systems you own or are explicitly authorized to assess. Contributors and users must not use the project to access, disrupt, or test third-party systems without permission.

## Reporting a Vulnerability

Do not disclose a vulnerability in Bug Hunter Pro through a public issue.

Send a private report to the repository security contact and include:

- Affected version and component
- Reproduction steps or a minimal proof of concept
- Security impact and realistic attack conditions
- Suggested remediation, when available

Avoid including real credentials, access tokens, private keys, or sensitive target data. The maintainers will acknowledge a complete report, investigate it, and coordinate a fix and disclosure timeline.

## Supported Versions

Security fixes are applied to the latest release on the default branch. Users should upgrade before reporting an issue already corrected in a newer version.

## Scanner Safety

- Define target scope before scanning.
- Coordinate request volume and credential checks with the system owner.
- Use test accounts where authentication checks are permitted.
- Store `.env`, reports, and SQLite databases as sensitive material.
- Review every automated finding before acting on it or sharing a report.

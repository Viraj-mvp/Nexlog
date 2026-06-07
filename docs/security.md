# Security Policy - NexLog

NexLog is a local-first DFIR log investigation cockpit. It is designed to keep
evidence on the analyst workstation by default.

## Supported Versions

Security fixes target the current `v1.x` release line.

## Reporting A Vulnerability

Please open a private advisory or contact the maintainer before publishing
exploit details. Include:

- Affected version or commit.
- Reproduction steps.
- Impact and affected component.
- Suggested fix if available.

## Secret Handling

Never commit real API keys, cloud tokens, private keys, case databases, or
evidence logs. Use `.env.example` for placeholders and keep `.env` local.

NexLog uses `NEXLOG_*` environment variables for public configuration.

## Evidence Handling

Case files, exported reports, IOC bundles, generated logs, and runtime
workspaces are excluded from release packages by default.

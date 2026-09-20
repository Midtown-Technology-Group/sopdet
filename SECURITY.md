# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the repository Security tab), or email
security@midtowntg.com. Do not open a public issue for a security report.

Include the affected version/commit, a description, reproduction steps, and any
impact assessment. We aim to acknowledge within 2 business days.

## Scope and handling

Sopdet collects device metadata and posts it to a Bifrost ingest endpoint. Treat
all collected output as personal data.

- **Secrets:** ingest keys are per-engagement, scoped, expiring, and revocable.
  They must never be committed or embedded in documentation. Signing
  configuration lives in `scripts/artifact-signing.env` (gitignored).
- **Samples and fixtures:** must be synthetic. Never commit output containing
  real hostnames, users, serials, MACs, GUIDs, or subscription identifiers.
- **Endpoint safety:** collectors are read-only and require no administrator
  rights. Changes that would mutate the target, require elevation, or broaden
  collection must be reviewed explicitly.
- **Supply chain:** dependencies are watched by Dependabot and scanned with
  `govulncheck` in CI; releases are code-signed (see `docs/appcontrol.md`).

## Supported versions

Pre-1.0: only the latest `main` is supported.

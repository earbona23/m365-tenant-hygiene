# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-19

First release.

### Added

- Six read-only hygiene checks over Microsoft Graph: MFA registration, inactive
  accounts, privileged role assignments, high-risk application permissions, external
  mail forwarding rules, and Intune device compliance.
- `Invoke-M365HygieneAudit`, which separates findings from coverage: a check that could
  not run reports `Skipped` with the reason, never a clean result.
- Self-contained HTML report with severity grading, per-finding evidence, remediation
  guidance, light and dark rendering, filtering, and a print layout. No external assets.
- CSV exports for both findings and check coverage.
- `Connect-M365Hygiene`, which derives the consent request from the checks selected, so
  running fewer checks requests fewer permissions.
- `Test-M365HygienePermission`, which compares granted scopes against what each check
  needs before a long run starts.
- `Get-M365HygieneCheck`, which documents each check's scopes, endpoints and coverage
  limits.
- 72 tests, including per-check logic exercised against a mocked Microsoft Graph, and a
  read-only suite that fails the build if a write path is ever introduced.

### Security

- No write path exists. All Graph traffic passes through a single gateway with the HTTP
  verb hardcoded to `GET` and no caller-supplied method or body.
- Only least-privileged read scopes are requested, each verified against the Microsoft
  Graph API reference.
- Report output escapes all tenant-controlled text, so a display name containing markup
  cannot execute in the reader's browser.

[1.0.0]: https://github.com/earbona23/m365-tenant-hygiene/releases/tag/v1.0.0

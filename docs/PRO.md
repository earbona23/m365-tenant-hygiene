# M365TenantHygiene Pro

**Everything that audits and reports is free** — all six checks, the terminal summary, the
self-contained HTML report, and both CSV exports (findings and coverage). The module is
MIT-licensed and read-only by design. Pro exists so teams and consultants who rely on it can
fund its upkeep, and it unlocks *additive* exports — never the audit itself.

## What Pro unlocks

| Feature | How |
|---|---|
| **SARIF export** — findings in GitHub code-scanning, Azure DevOps, or any SARIF-aware SIEM | `Export-M365HygieneReport -Audit $a -Path ./r -Format Sarif` |
| **Baseline comparison** — score a tenant against a stored earlier audit to catch regressions | *(rolling out)* |

## How activation works

A license key is an **ECDSA P-256** token verified **entirely offline** against a public key
embedded in the module — no account, no network, no telemetry. (.NET has no native Ed25519
verifier, so this module uses P-256, which `System.Security.Cryptography.ECDsa` verifies with
no third-party dependency.)

```powershell
Enable-M365HygienePro -LicenseKey 'M365HYGIENE-xxxxx.yyyyy'
Get-M365HygieneLicense
```

The key can also be supplied per-session via the `M365HYGIENE_LICENSE_KEY` environment
variable, handy for CI secrets.

## Support the project

- **GitHub Sponsors:** https://github.com/sponsors/earbona23
- **Patreon:** https://www.patreon.com/EduardArbona

Sponsoring is never required to run an audit — Pro is additive exports only.

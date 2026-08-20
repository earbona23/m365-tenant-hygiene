# Contributing

Contributions are welcome. A few rules follow from what this module is.

## The read-only rule

This module must never be able to write to a tenant. That is not a style preference;
people run it against production because of it.

- All Microsoft Graph traffic goes through `Invoke-HygieneGraphRequest`. Do not call
  `Invoke-MgGraphRequest`, `Invoke-RestMethod` or `Invoke-WebRequest` anywhere else.
- Do not add a `-Method` or `-Body` parameter to the gateway.
- Only request read scopes.

`tests/ReadOnly.Tests.ps1` enforces all of the above and will fail the build. If a
change requires editing that test to pass, the change is out of scope for this project.

## Adding a check

1. Add an entry to `Get-HygieneCheckRegistry` with its least-privileged delegated
   scopes, the Graph endpoints it reads, a `RunOrder`, and a `Notes` field that states
   honestly what the check cannot see.
2. Verify the scopes against the Microsoft Graph API reference for the specific
   endpoint. Do not copy them from another script, including this one.
3. Implement `Test-Hygiene<Name>` in `Checks/`, returning `New-HygieneCheckResult`.
4. **Handle the absence of data explicitly.** If a licence, permission or access grant
   is missing, return `Skipped` with a reason. Never return `Completed` with no findings
   when the check could not see the data — that is the one bug in an audit tool that is
   invisible in production, because it looks like good news.
5. Add tests to `tests/Checks.Tests.ps1` covering the severity decisions *and* the
   refusal path.

## Severity

- **Critical** — leads directly to tenant compromise: an administrator without MFA, an
  application that can escalate its own privileges, a covert external forward.
- **High** — tenant-wide data exposure, or a privileged assignment that should not exist.
- **Medium** — meaningful risk that is not immediately exploitable.
- **Low** — hygiene and accuracy issues.
- **Informational** — inventory. Not a problem; context for judging the problems.

## Before opening a pull request

```powershell
Invoke-Pester ./tests -Output Detailed
Invoke-ScriptAnalyzer -Path ./src -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

Both must be clean. Write comment-based help for any new public function.

## Reporting a security issue

Open a GitHub issue for defects in this module. Do not include real tenant data,
report output, user principal names, or tokens in an issue.

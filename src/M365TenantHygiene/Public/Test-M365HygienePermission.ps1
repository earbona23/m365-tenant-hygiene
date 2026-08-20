<#
.SYNOPSIS
    Compares the scopes actually granted to the scopes each check needs.

.DESCRIPTION
    Run this after signing in and before a long audit. Consent can be narrower than
    what was requested -- an administrator may have approved part of the request, or a
    policy may restrict what a user can consent to. Without this comparison the first
    sign that a check lacks its permission is a 403 partway through the run.

    This is a read-only comparison of the token's scope claim. It cannot detect the
    other half of delegated access: whether the signed-in user's directory role lets
    them see the data the scope covers. That surfaces at call time and is handled by
    each check reporting Skipped rather than clean.

.PARAMETER CheckId
    Limit the comparison to these checks.

.EXAMPLE
    Test-M365HygienePermission | Where-Object { -not $_.Satisfied }

    Lists the checks that will not be able to run.
#>
function Test-M365HygienePermission {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string[]] $CheckId)

    $context = Get-MgContext
    if (-not $context) {
        throw 'Not connected to Microsoft Graph. Run Connect-M365Hygiene first.'
    }

    $granted = [System.Collections.Generic.HashSet[string]]::new(
        [string[]] @($context.Scopes), [StringComparer]::OrdinalIgnoreCase)

    $registry = Get-HygieneCheckRegistry
    $ids = if ($CheckId) { $CheckId } else { @($registry.Keys) }

    foreach ($id in $ids) {
        if (-not $registry.Contains($id)) {
            Write-Error "Unknown check '$id'."
            continue
        }

        $entry   = $registry[$id]
        $missing = @($entry.RequiredScopes | Where-Object { -not $granted.Contains($_) })

        [pscustomobject]@{
            PSTypeName     = 'M365TenantHygiene.PermissionStatus'
            CheckId        = $entry.Id
            CheckName      = $entry.Name
            RequiredScopes = $entry.RequiredScopes
            MissingScopes  = $missing
            Satisfied      = ($missing.Count -eq 0)
        }
    }
}

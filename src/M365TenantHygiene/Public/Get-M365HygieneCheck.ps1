<#
.SYNOPSIS
    Lists the available checks, what each one needs, and what it reads.

.DESCRIPTION
    The self-documenting half of the permission story. Before consenting to anything,
    you can see every check, the exact delegated scopes it will ask for, the exact
    Graph endpoints it will call, and its known coverage limits.

.PARAMETER CheckId
    Return only these checks. Omit for all of them.

.EXAMPLE
    Get-M365HygieneCheck | Format-Table Id, Category, RequiredScopes

.EXAMPLE
    (Get-M365HygieneCheck -CheckId MailForwarding).Notes

    Shows the coverage limit that applies to mailbox access before you rely on it.
#>
function Get-M365HygieneCheck {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string[]] $CheckId)

    $registry = Get-HygieneCheckRegistry
    $ids = if ($CheckId) { $CheckId } else { @($registry.Keys) }

    foreach ($id in $ids) {
        if (-not $registry.Contains($id)) {
            Write-Error "Unknown check '$id'. Known checks: $($registry.Keys -join ', ')"
            continue
        }
        $entry = $registry[$id]
        [pscustomobject]@{
            PSTypeName     = 'M365TenantHygiene.Check'
            Id             = $entry.Id
            Name           = $entry.Name
            Category       = $entry.Category
            Description    = $entry.Description
            RequiredScopes = $entry.RequiredScopes
            GraphEndpoints = $entry.GraphEndpoints
            Notes          = $entry.Notes
        }
    }
}

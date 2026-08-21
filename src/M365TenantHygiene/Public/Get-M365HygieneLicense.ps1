<#
.SYNOPSIS
    Shows the current M365TenantHygiene entitlement (free or Pro), re-verified offline.

.DESCRIPTION
    Reads the stored license (or the M365HYGIENE_LICENSE_KEY environment variable) and
    verifies it afresh against the embedded public key. Nothing leaves the machine.

.EXAMPLE
    Get-M365HygieneLicense
#>
function Get-M365HygieneLicense {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $ent = Get-HygieneEntitlement
    [pscustomobject]@{
        PSTypeName = 'M365TenantHygiene.License'
        Pro        = $ent.Pro
        Plan       = $ent.Plan
        Sub        = $ent.Sub
        Features   = $ent.Features
        Reason     = $ent.Reason
    }
}

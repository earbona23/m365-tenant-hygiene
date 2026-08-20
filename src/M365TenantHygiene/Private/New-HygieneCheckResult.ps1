<#
.SYNOPSIS
    Wraps one check's outcome, including the case where it could not run.
.DESCRIPTION
    A check that could not run is not the same as a check that found nothing, and
    conflating the two is how an audit tool ends up reporting a clean tenant it never
    looked at. Status is therefore explicit:

      Completed - the check ran against live data.
      Skipped   - the caller excluded it, or a prerequisite (licence, permission,
                  Intune subscription) is absent. Reason says which.
      Failed    - the check ran and broke. Error carries the detail.

    Only 'Completed' counts as evidence of anything. The HTML report renders Skipped
    and Failed checks in their own section rather than hiding them behind a green tick.
#>
function New-HygieneCheckResult {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [string] $CheckName,
        [Parameter(Mandatory)] [string] $Category,

        [Parameter(Mandatory)]
        [ValidateSet('Completed', 'Skipped', 'Failed')]
        [string] $Status,

        [object[]] $Findings = @(),
        [int] $ObjectsEvaluated = 0,
        [string] $Reason,

        # Not named -Error: that would shadow PowerShell's automatic $Error variable
        # inside this function, which is exactly where you want it intact.
        [string] $ErrorMessage,
        [timespan] $Duration = [timespan]::Zero,
        [string[]] $RequiredScopes = @()
    )

    [pscustomobject]@{
        PSTypeName       = 'M365TenantHygiene.CheckResult'
        CheckId          = $CheckId
        CheckName        = $CheckName
        Category         = $Category
        Status           = $Status
        Findings         = @($Findings)
        FindingCount     = @($Findings).Count
        ObjectsEvaluated = $ObjectsEvaluated
        Reason           = $Reason
        Error            = $ErrorMessage
        Duration         = $Duration
        RequiredScopes   = @($RequiredScopes)
    }
}

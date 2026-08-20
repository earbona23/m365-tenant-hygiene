<#
.SYNOPSIS
    Builds one finding. Every check emits these and nothing else.
.DESCRIPTION
    A finding is the module's unit of output: one problem, about one object, with a
    severity, the evidence behind it, and what to do about it. Keeping the shape fixed
    is what lets the HTML renderer, the CSV export and the summary counters stay simple
    and stay honest -- they never have to guess what a check meant.

    Evidence is a hashtable of the raw values the judgement was made from, so a reader
    can disagree with the module without re-running the audit.
#>
function New-HygieneFinding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [string] $CheckName,
        [Parameter(Mandatory)] [string] $Category,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string] $Severity,

        [Parameter(Mandatory)] [string] $Title,

        [string] $ObjectType = 'Unknown',
        [string] $ObjectId,
        [string] $ObjectName,
        [string] $Detail,
        [string] $Recommendation,
        [string] $Reference,
        [hashtable] $Evidence = @{}
    )

    [pscustomobject]@{
        PSTypeName     = 'M365TenantHygiene.Finding'
        CheckId        = $CheckId
        CheckName      = $CheckName
        Category       = $Category
        Severity       = $Severity
        SeverityRank   = (Get-HygieneSeverityRank -Severity $Severity)
        Title          = $Title
        ObjectType     = $ObjectType
        ObjectId       = $ObjectId
        ObjectName     = $ObjectName
        Detail         = $Detail
        Recommendation = $Recommendation
        Reference      = $Reference
        Evidence       = $Evidence
        DetectedAt     = [datetime]::UtcNow
    }
}

<#
.SYNOPSIS
    Maps a severity name to a sort key, so Critical sorts above High everywhere.
#>
function Get-HygieneSeverityRank {
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][string] $Severity)

    switch ($Severity) {
        'Critical'      { 0 }
        'High'          { 1 }
        'Medium'        { 2 }
        'Low'           { 3 }
        'Informational' { 4 }
        default         { 5 }
    }
}

<#
.SYNOPSIS
    Single logging entry point for the module.
.DESCRIPTION
    Routes through the standard PowerShell streams so a caller can silence, redirect
    or capture module output with the usual preference variables, instead of the module
    printing straight to the host and being impossible to quiet down.
#>
function Write-HygieneLog {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [ValidateSet('Verbose', 'Information', 'Warning')]
        [string] $Level = 'Verbose'
    )

    $stamp = (Get-Date).ToString('HH:mm:ss')
    switch ($Level) {
        'Warning'     { Write-Warning "[$stamp] $Message" }
        'Information' { Write-Information "[$stamp] $Message" -InformationAction Continue }
        default       { Write-Verbose "[$stamp] $Message" }
    }
}

<#
.SYNOPSIS
    Signs out of Microsoft Graph and clears the cached token.
.DESCRIPTION
    Worth calling explicitly at the end of an audit, especially on a shared or
    jump host, so the next person at the console does not inherit the session.
.EXAMPLE
    Disconnect-M365Hygiene
#>
function Disconnect-M365Hygiene {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([void])]
    param()

    if (-not (Get-MgContext)) {
        Write-HygieneLog -Level Information -Message 'No active Microsoft Graph session.'
        return
    }

    if ($PSCmdlet.ShouldProcess('Microsoft Graph', 'Disconnect the current session')) {
        $null = Disconnect-MgGraph
        Write-HygieneLog -Level Information -Message 'Disconnected from Microsoft Graph.'
    }
}

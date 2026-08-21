<#
.SYNOPSIS
    Activates an M365TenantHygiene Pro license (verified offline) for this machine.

.DESCRIPTION
    Everything that audits and reports is free. A Pro license unlocks additive exports --
    the SARIF report today, baseline comparison next. The license is an ECDSA P-256 token
    verified entirely offline against a public key embedded in the module: no account, no
    network call, no telemetry. This command verifies the key and, if valid, stores it in
    your user config directory so later runs pick it up.

.PARAMETER LicenseKey
    The key string, of the form M365HYGIENE-xxxxx.yyyyy.

.EXAMPLE
    Enable-M365HygienePro -LicenseKey 'M365HYGIENE-...'

.LINK
    https://github.com/earbona23/m365-tenant-hygiene#pro
#>
function Enable-M365HygienePro {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $LicenseKey
    )

    $result = Test-HygieneLicenseKey -Key $LicenseKey
    if (-not $result.Valid) {
        throw "Activation failed: $($result.Reason)"
    }

    $path = Get-HygieneLicensePath
    if ($PSCmdlet.ShouldProcess($path, 'Store the activated Pro license')) {
        $dir = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        @{ key = $LicenseKey } | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding utf8
        Write-HygieneLog -Level Information -Message "Pro license for $($result.Payload.sub) stored at $path"
    }

    [pscustomobject]@{
        PSTypeName = 'M365TenantHygiene.License'
        Plan       = $result.Payload.plan
        Sub        = $result.Payload.sub
        Features   = (Get-HygieneEntitlement).Features
    }
}

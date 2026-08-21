<#
.SYNOPSIS
    Offline verification of an M365TenantHygiene Pro license, and the entitlement the rest
    of the module reads.

.DESCRIPTION
    Everything that audits and reports is free. A Pro license unlocks additive exports (a
    SARIF report for GitHub code-scanning / SIEM ingestion, and baseline comparison). The
    licence is an ECDSA P-256 token verified **entirely offline** against a public key
    embedded below -- no account, no network, no telemetry. Ed25519 has no native verifier
    in .NET, so this module uses P-256, which `System.Security.Cryptography.ECDsa` verifies
    with no third-party dependency, keeping the module's zero-dependency posture.

    A key is  M365HYGIENE-<base64url(payloadJson)>.<base64url(DER-signature)>.
#>

# Embedded verification public key (SubjectPublicKeyInfo, base64). Public by design: it can
# only verify a signature, never mint one. The signing key stays with the project owner.
$script:LicensePublicKeySpki = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0Mw/wUkwPp0kyGTV6v+DAVX4Hn7vQBIX97z8rzPO+m2RI0TJM8HP6lkQBJJc/GM5OhYUQYoqgUoRizjsTGTL8Q=='

$script:LicenseKeyPrefix = 'M365HYGIENE-'
$script:ProFeatures = @('sarif', 'baseline')

<#
.SYNOPSIS
    Decode a base64url string to bytes.
#>
function ConvertFrom-HygieneBase64Url {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][string] $Text)
    $s = $Text.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [Convert]::FromBase64String($s)
}

<#
.SYNOPSIS
    Verify a licence key offline. Returns an object with Valid, Payload and Reason.
.PARAMETER Key
    The licence key string.
.PARAMETER PublicKeySpki
    Override the embedded key (base64 SPKI). For tests.
.PARAMETER NowUnix
    Current time as epoch seconds. For deterministic tests.
#>
function Test-HygieneLicenseKey {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $Key,
        [string] $PublicKeySpki = $script:LicensePublicKeySpki,
        [int64] $NowUnix = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    )

    function fail($reason) { [pscustomobject]@{ Valid = $false; Payload = $null; Reason = $reason } }

    if ([string]::IsNullOrWhiteSpace($Key) -or -not $Key.StartsWith($script:LicenseKeyPrefix)) {
        return fail('The key is not an M365TenantHygiene license key.')
    }
    $body = $Key.Substring($script:LicenseKeyPrefix.Length)
    $dot = $body.IndexOf('.')
    if ($dot -lt 1) { return fail('The key is malformed (missing signature).') }

    try {
        $payloadBytes = ConvertFrom-HygieneBase64Url -Text $body.Substring(0, $dot)
        $signature = ConvertFrom-HygieneBase64Url -Text $body.Substring($dot + 1)
    } catch {
        return fail('The key is not valid base64url.')
    }

    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $ecdsa.ImportSubjectPublicKeyInfo([Convert]::FromBase64String($PublicKeySpki), [ref] 0)
    } catch {
        return fail('The embedded public key could not be loaded.')
    }

    $ok = $false
    try {
        $ok = $ecdsa.VerifyData(
            $payloadBytes, $signature,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
    } catch { $ok = $false }

    if (-not $ok) { return fail('The signature does not verify. This key was not issued for M365TenantHygiene.') }

    try {
        $payload = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json
    } catch {
        return fail('The signed payload is not valid JSON.')
    }

    if ($payload.PSObject.Properties.Name -contains 'exp' -and $NowUnix -gt [int64]$payload.exp) {
        return [pscustomobject]@{ Valid = $false; Payload = $payload; Reason = 'The license expired.' }
    }
    return [pscustomobject]@{ Valid = $true; Payload = $payload; Reason = $null }
}

<#
.SYNOPSIS
    Path to the stored licence (XDG on Linux, %APPDATA% on Windows, ~/Library on macOS).
#>
function Get-HygieneLicensePath {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if ($env:M365HYGIENE_CONFIG_DIR) { $base = $env:M365HYGIENE_CONFIG_DIR }
    elseif ($IsWindows) { $base = $env:APPDATA }
    elseif ($IsMacOS) { $base = Join-Path $HOME 'Library/Application Support' }
    else { $base = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path $HOME '.config' } }
    return Join-Path (Join-Path $base 'M365TenantHygiene') 'license.json'
}

<#
.SYNOPSIS
    The current entitlement, re-verified from disk (or $env:M365HYGIENE_LICENSE_KEY) each call.
#>
function Get-HygieneEntitlement {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string] $Key)

    if (-not $Key) { $Key = $env:M365HYGIENE_LICENSE_KEY }
    if (-not $Key) {
        $path = Get-HygieneLicensePath
        if (Test-Path -LiteralPath $path) {
            try { $Key = (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).key } catch { $Key = $null }
        }
    }
    if (-not $Key) {
        return [pscustomobject]@{ Pro = $false; Plan = $null; Features = @(); Sub = $null; Reason = 'No license activated.' }
    }
    $r = Test-HygieneLicenseKey -Key $Key
    if (-not $r.Valid) {
        return [pscustomobject]@{ Pro = $false; Plan = $null; Features = @(); Sub = $null; Reason = $r.Reason }
    }
    $features = if ($r.Payload.PSObject.Properties.Name -contains 'features' -and $r.Payload.features) { $r.Payload.features } else { $script:ProFeatures }
    [pscustomobject]@{ Pro = $true; Plan = $r.Payload.plan; Features = $features; Sub = $r.Payload.sub; Reason = $null }
}

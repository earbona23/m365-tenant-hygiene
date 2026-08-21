<#
.SYNOPSIS
    Mints a signed M365TenantHygiene Pro license key. Owner-only: needs the private
    signing key, which never ships with the module.

.EXAMPLE
    ./scripts/mint-license.ps1 -Sub 'Acme Inc' -Plan team -Days 365 `
        -SigningKeyPath ./.secrets/license-signing-key.pem
#>
param(
    [Parameter(Mandatory)][string] $Sub,
    [ValidateSet('pro', 'team')][string] $Plan = 'pro',
    [int] $Days = 0,
    [string] $SigningKeyPath = './.secrets/license-signing-key.pem'
)

$ecdsa = [System.Security.Cryptography.ECDsa]::Create()
$ecdsa.ImportFromPem((Get-Content -LiteralPath $SigningKeyPath -Raw))

$now = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$payload = [ordered]@{ sub = $Sub; plan = $Plan; iat = $now }
if ($Days -gt 0) { $payload['exp'] = $now + ($Days * 86400) }

$json = ($payload | ConvertTo-Json -Compress)
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$sig = $ecdsa.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)

function ToB64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
$key = "M365HYGIENE-$(ToB64Url $bytes).$(ToB64Url $sig)"

Write-Host "Minted $Plan license for '$Sub'$(if ($Days -gt 0) { ", $Days days" } else { ' (perpetual)' }):" -ForegroundColor Green
Write-Output $key

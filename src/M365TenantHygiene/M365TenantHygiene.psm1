#Requires -Version 7.2

<#
    M365TenantHygiene - read-only Microsoft 365 tenant security hygiene auditing.

    Loader. Files are dot-sourced in dependency order: private helpers first, then the
    checks that use them, then the public surface. Only the functions in Public/ are
    exported; everything else stays internal so the module's contract is the small set
    of commands documented in the README, not whatever happens to be defined.
#>

# Version 1.0 on purpose, not Latest. Microsoft Graph returns JSON whose optional
# properties are simply absent -- signInActivity on an unlicensed tenant,
# isEncrypted on some device types, @odata.nextLink on a final page. Strict mode 2.0
# and above turn reading an absent property into a terminating error, which would
# convert "Graph did not return this field" into "the check crashed". Version 1.0
# keeps the guard that actually pays off here (uninitialised variables) without
# making the module brittle against payloads it does not control.
Set-StrictMode -Version 1.0

$folders = @('Private', 'Checks', 'Public')

foreach ($folder in $folders) {
    $path = Join-Path -Path $PSScriptRoot -ChildPath $folder
    if (-not (Test-Path -LiteralPath $path)) { continue }

    foreach ($file in (Get-ChildItem -Path $path -Filter '*.ps1' -File | Sort-Object Name)) {
        try {
            . $file.FullName
        }
        catch {
            throw "Failed to load '$($file.FullName)': $($_.Exception.Message)"
        }
    }
}

$publicPath = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
$publicFunctions = @(
    Get-ChildItem -Path $publicPath -Filter '*.ps1' -File -ErrorAction SilentlyContinue |
        ForEach-Object { $_.BaseName }
)

Export-ModuleMember -Function $publicFunctions

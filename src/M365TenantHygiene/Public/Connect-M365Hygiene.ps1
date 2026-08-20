<#
.SYNOPSIS
    Signs in to Microsoft Graph with only the scopes the requested checks need.

.DESCRIPTION
    Wraps Connect-MgGraph, but derives the scope list from the checks you selected
    rather than asking for a fixed block of permissions. Running a single check
    consents to a single check's permissions.

    Every scope requested is a read scope. The module contains no code path that can
    write to Microsoft Graph -- see Invoke-HygieneGraphRequest, where the HTTP verb is
    hardcoded, and tests/ReadOnly.Tests.ps1, which fails the build if that changes.

.PARAMETER ClientId
    Application (client) ID of your app registration. See the setup walkthrough in the
    README: the app must be registered as a public client with delegated permissions.

.PARAMETER TenantId
    Directory (tenant) ID, or a verified domain name.

.PARAMETER CheckId
    Restrict the requested scopes to these checks. Omit for all checks.

.PARAMETER UseDeviceCode
    Authenticate by device code instead of an interactive browser. Use this on a
    headless host or over SSH.

.PARAMETER Environment
    Microsoft cloud instance for sovereign clouds. Defaults to the global cloud.

.EXAMPLE
    Connect-M365Hygiene -ClientId $app -TenantId contoso.onmicrosoft.com

    Requests the scopes for the full check set.

.EXAMPLE
    Connect-M365Hygiene -ClientId $app -TenantId $tenant -CheckId MfaRegistration, PrivilegedRole

    Requests only AuditLog.Read.All and RoleManagement.Read.Directory (plus User.Read).

.LINK
    https://github.com/earbona23/m365-tenant-hygiene
#>
function Connect-M365Hygiene {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ClientId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $TenantId,

        [string[]] $CheckId,

        [switch] $UseDeviceCode,

        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
        [string] $Environment = 'Global'
    )

    $scopes = Get-HygieneRequiredScope -CheckId $CheckId

    Write-HygieneLog -Level Information -Message "Requesting $($scopes.Count) delegated scope(s): $($scopes -join ', ')"

    $params = @{
        ClientId    = $ClientId
        TenantId    = $TenantId
        Scopes      = $scopes
        NoWelcome   = $true
        ErrorAction = 'Stop'
    }
    if ($UseDeviceCode) { $params['UseDeviceCode'] = $true }
    if ($Environment -ne 'Global') { $params['Environment'] = $Environment }

    Connect-MgGraph @params

    $context = Get-MgContext
    if (-not $context) { throw 'Connect-MgGraph returned without establishing a context.' }

    Write-HygieneLog -Level Information -Message "Signed in as $($context.Account) on tenant $($context.TenantId)."

    [pscustomobject]@{
        PSTypeName     = 'M365TenantHygiene.Connection'
        Account        = $context.Account
        TenantId       = $context.TenantId
        ClientId       = $context.ClientId
        AuthType       = $context.AuthType
        Environment    = $context.Environment
        RequestedScopes = $scopes
        GrantedScopes  = @($context.Scopes)
    }
}

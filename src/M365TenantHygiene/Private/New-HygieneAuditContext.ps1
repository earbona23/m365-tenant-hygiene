<#
.SYNOPSIS
    Shared state passed to every check during one audit run.
.DESCRIPTION
    Several checks need the same expensive collections -- the user list above all.
    The context carries a small cache so a full audit reads /users once rather than
    once per check, and carries the tenant's verified domains, which the mail
    forwarding check needs to decide what 'external' means.
#>
function New-HygieneAuditContext {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [int] $InactiveDayThreshold = 90,
        [int] $GlobalAdminWarnThreshold = 4,
        [int] $MaxPages = 200
    )

    @{
        StartedAt                = [datetime]::UtcNow
        InactiveDayThreshold     = $InactiveDayThreshold
        GlobalAdminWarnThreshold = $GlobalAdminWarnThreshold
        MaxPages                 = $MaxPages
        Tenant                   = $null
        VerifiedDomains          = @()
        Cache                    = @{}
    }
}

<#
.SYNOPSIS
    Reads the tenant's identity: display name, id and verified domains.
.DESCRIPTION
    Uses /organization, which accepts the least-privileged delegated permission
    User.Read for exactly the three properties needed here. Requesting
    Organization.Read.All would return more fields and require more consent for
    no benefit.
#>
function Initialize-HygieneTenantInfo {
    [CmdletBinding()]
    [OutputType([void])]
    param([Parameter(Mandatory)][hashtable] $Context)

    $org = @(Invoke-HygieneGraphRequest -Uri 'organization?$select=id,displayName,verifiedDomains' -MaxPages 1)
    if ($org.Count -eq 0) {
        Write-HygieneLog -Level Warning -Message 'Could not read /organization; the report will show the tenant as unknown.'
        return
    }

    $first = $org[0]
    $Context.Tenant = [pscustomobject]@{
        Id          = $first.id
        DisplayName = $first.displayName
    }
    $Context.VerifiedDomains = @($first.verifiedDomains | ForEach-Object { $_.name } | Where-Object { $_ })

    Write-HygieneLog -Message "Tenant '$($Context.Tenant.DisplayName)' has $($Context.VerifiedDomains.Count) verified domain(s)."
}

<#
.SYNOPSIS
    Returns the tenant's users, reading them from Graph at most once per audit.
.DESCRIPTION
    signInActivity is only returned when explicitly selected, and selecting it caps
    the page size at 500 -- both documented Graph behaviours that are easy to miss and
    produce silently empty results when missed.
#>
function Get-HygieneUser {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [hashtable] $Context,
        [switch] $IncludeSignInActivity
    )

    $key = if ($IncludeSignInActivity) { 'UsersWithSignIn' } else { 'Users' }
    if ($Context.Cache.ContainsKey($key)) { return $Context.Cache[$key] }

    # A cached richer set answers the poorer question too.
    if (-not $IncludeSignInActivity -and $Context.Cache.ContainsKey('UsersWithSignIn')) {
        return $Context.Cache['UsersWithSignIn']
    }

    $select = 'id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,assignedLicenses'
    $top    = 999
    if ($IncludeSignInActivity) {
        $select += ',signInActivity'
        # Documented Graph limit: selecting signInActivity caps $top at 500.
        $top = 500
    }

    Write-HygieneLog -Message "Reading users from Graph (signInActivity: $($IncludeSignInActivity.IsPresent))."
    $users = Invoke-HygieneGraphRequest -Uri "users?`$select=$select&`$top=$top" -MaxPages $Context.MaxPages

    $Context.Cache[$key] = $users
    return $users
}

<#
.SYNOPSIS
    True when an address sits outside every verified domain of the tenant.
.DESCRIPTION
    Deliberately fails closed: with no verified domain list, nothing is called
    external, because guessing would manufacture findings out of missing data.
#>
function Test-HygieneExternalAddress {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string] $Address,
        [string[]] $VerifiedDomain
    )

    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    if (-not $VerifiedDomain -or $VerifiedDomain.Count -eq 0) { return $false }
    if ($Address -notmatch '@') { return $false }

    $domain = ($Address -split '@')[-1].Trim().TrimEnd('>').ToLowerInvariant()
    if (-not $domain) { return $false }

    foreach ($known in $VerifiedDomain) {
        $k = $known.Trim().ToLowerInvariant()
        if ($domain -eq $k -or $domain.EndsWith(".$k")) { return $false }
    }

    return $true
}

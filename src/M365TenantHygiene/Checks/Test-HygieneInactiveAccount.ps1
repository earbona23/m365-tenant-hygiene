<#
.SYNOPSIS
    Finds enabled accounts that nobody has signed into for a long time.

.DESCRIPTION
    Dormant enabled accounts are attractive targets: the password is usually old, and
    nobody notices unusual activity on an account nobody watches.

    The check reads signInActivity and separates two cases that deserve different
    treatment:

      Stale    signed in once, but not within the threshold.
      Never    no interactive sign-in has ever been recorded.

    "Never" is reported only when the account is older than the threshold, so accounts
    created last week are not flagged for not having been used yet.

    Severity is raised for accounts that hold a licence (they cost money as well as
    presenting risk) and raised again for accounts that hold a privileged role, which
    is read from the privileged role check when that check also ran.

.PARAMETER Context
    Shared audit context from New-HygieneAuditContext.

.OUTPUTS
    M365TenantHygiene.Finding objects.

.NOTES
    Graph endpoint : GET /users?$select=...,signInActivity
    Scopes required: User.Read.All, AuditLog.Read.All (delegated)

    signInActivity requires Microsoft Entra ID P1 or P2. Without that licence Graph
    omits the property, every account looks like it never signed in, and the check
    would report the whole tenant as dormant. It therefore refuses to guess: if no user
    in the tenant carries signInActivity, the check reports Skipped and says why.
#>
function Test-HygieneInactiveAccount {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][hashtable] $Context)

    $meta      = (Get-HygieneCheckRegistry)['InactiveAccount']
    $threshold = $Context.InactiveDayThreshold
    $cutoff    = [datetime]::UtcNow.AddDays(-$threshold)

    $users   = @(Get-HygieneUser -Context $Context -IncludeSignInActivity)
    $enabled = @($users | Where-Object { $_.accountEnabled })

    # Fail closed rather than reporting a dormant tenant that simply lacks the licence.
    $anySignInData = @($users | Where-Object { $null -ne $_.signInActivity }).Count
    if ($users.Count -gt 0 -and $anySignInData -eq 0) {
        return New-HygieneCheckResult `
            -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
            -Status 'Skipped' `
            -ObjectsEvaluated $users.Count `
            -RequiredScopes $meta.RequiredScopes `
            -Reason ('Microsoft Graph returned no signInActivity for any of the {0} users read. This property requires a Microsoft Entra ID P1 or P2 licence. Reporting every account as inactive on missing data would be wrong, so this check did not run.' -f $users.Count)
    }

    $privileged = @()
    if ($Context.Cache.ContainsKey('PrivilegedPrincipalIds')) {
        $privileged = $Context.Cache['PrivilegedPrincipalIds']
    }

    $findings = foreach ($user in $enabled) {

        $activity   = $user.signInActivity
        $lastSignIn = $null

        if ($activity) {
            foreach ($prop in 'lastSuccessfulSignInDateTime', 'lastSignInDateTime', 'lastNonInteractiveSignInDateTime') {
                $value = $activity.$prop
                if ($value) {
                    $parsed = [datetime]::MinValue
                    if ([datetime]::TryParse($value, [ref] $parsed)) {
                        $utc = $parsed.ToUniversalTime()
                        if ($null -eq $lastSignIn -or $utc -gt $lastSignIn) { $lastSignIn = $utc }
                    }
                }
            }
        }

        $created = [datetime]::MinValue
        $hasCreated = $user.createdDateTime -and [datetime]::TryParse($user.createdDateTime, [ref] $created)
        if ($hasCreated) { $created = $created.ToUniversalTime() }

        $neverSignedIn = ($null -eq $lastSignIn)

        if ($neverSignedIn) {
            # A brand new account has not had the chance to be dormant.
            if ($hasCreated -and $created -gt $cutoff) { continue }
            $daysIdle = if ($hasCreated) { [int] ([datetime]::UtcNow - $created).TotalDays } else { $null }
            $title    = 'Enabled account has never signed in'
            $detail   = if ($null -ne $daysIdle) {
                "No interactive sign-in has ever been recorded, and the account was created $daysIdle day(s) ago."
            } else {
                'No interactive sign-in has ever been recorded and the creation date is unavailable.'
            }
        }
        else {
            if ($lastSignIn -gt $cutoff) { continue }
            $daysIdle = [int] ([datetime]::UtcNow - $lastSignIn).TotalDays
            $title    = 'Enabled account is inactive'
            $detail   = "Last sign-in was $daysIdle day(s) ago, beyond the $threshold day threshold."
        }

        $licensed     = @($user.assignedLicenses).Count -gt 0
        $isPrivileged = $privileged -contains $user.id

        $severity = 'Low'
        if ($licensed) { $severity = 'Medium' }
        if ($isPrivileged) { $severity = 'High' }

        if ($isPrivileged) {
            $detail += ' The account also holds a privileged directory role, which makes a dormant account a standing administrative foothold.'
        }

        New-HygieneFinding `
            -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
            -Severity $severity `
            -Title $title `
            -ObjectType 'User' `
            -ObjectId $user.id `
            -ObjectName $user.userPrincipalName `
            -Detail $detail `
            -Recommendation 'Confirm the account is still needed. If it is not, disable it, reclaim the licence, and delete it once the retention period allows. If it is a shared or break-glass account, document it and exclude it from this check.' `
            -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
            -Evidence @{
                displayName    = $user.displayName
                userType       = $user.userType
                licensed       = $licensed
                licenseCount   = @($user.assignedLicenses).Count
                privileged     = $isPrivileged
                createdDateTime = $user.createdDateTime
                lastSignInUtc  = if ($lastSignIn) { $lastSignIn.ToString('o') } else { $null }
                daysIdle       = $daysIdle
                thresholdDays  = $threshold
            }
    }

    New-HygieneCheckResult `
        -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
        -Status 'Completed' `
        -Findings @($findings) `
        -ObjectsEvaluated $enabled.Count `
        -RequiredScopes $meta.RequiredScopes
}

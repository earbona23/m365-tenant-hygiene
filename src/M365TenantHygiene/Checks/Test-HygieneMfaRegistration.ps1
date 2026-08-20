<#
.SYNOPSIS
    Finds enabled accounts with no usable multi-factor authentication method.

.DESCRIPTION
    Reads the authentication methods registration report and flags every user who is
    not MFA-capable.

    Two distinctions matter and the check keeps them apart rather than collapsing them
    into a single "has MFA" boolean:

    isMfaRegistered  the user registered a method at some point.
    isMfaCapable     a registered method is actually usable for MFA today.

    Capability is what decides the finding, because a user can be registered and still
    unable to complete a challenge -- the account looks protected in a spreadsheet and
    is not.

    Severity follows blast radius: an administrator without MFA is the single most
    exploitable state in a tenant, so it is Critical regardless of how many others exist.

.PARAMETER Context
    Shared audit context from New-HygieneAuditContext.

.OUTPUTS
    M365TenantHygiene.Finding objects.

.NOTES
    Graph endpoint : GET /reports/authenticationMethods/userRegistrationDetails
    Scope required : AuditLog.Read.All (delegated)

    The report excludes disabled users by design, which is why this check does not
    filter on accountEnabled itself.

    Registration is not enforcement. A tenant where every user is MFA-capable can still
    let sign-ins through unchallenged if no Conditional Access policy or security default
    requires MFA. This check cannot see that; it is called out in the README limitations.
#>
function Test-HygieneMfaRegistration {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][hashtable] $Context)

    $meta = (Get-HygieneCheckRegistry)['MfaRegistration']

    $details = Invoke-HygieneGraphRequest `
        -Uri 'reports/authenticationMethods/userRegistrationDetails' `
        -MaxPages $Context.MaxPages

    $Context.Cache['MfaRegistrationDetails'] = $details
    Write-HygieneLog -Message "Evaluated $($details.Count) user registration record(s)."

    $findings = foreach ($record in $details) {

        $capable = [bool] $record.isMfaCapable
        if ($capable) { continue }

        $isAdmin    = [bool] $record.isAdmin
        $isGuest    = ($record.userType -eq 'Guest')
        $registered = [bool] $record.isMfaRegistered

        $severity = if ($isAdmin) { 'Critical' } elseif ($isGuest) { 'Medium' } else { 'High' }

        $detail = if ($registered) {
            'The account has a registered method, but none of the registered methods can currently satisfy an MFA challenge.'
        } else {
            'The account has no registered multi-factor authentication method.'
        }
        if ($isAdmin) {
            $detail += ' This account holds at least one administrative role, so a single stolen password is enough to reach tenant administration.'
        }

        New-HygieneFinding `
            -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
            -Severity $severity `
            -Title 'Account is not capable of multi-factor authentication' `
            -ObjectType 'User' `
            -ObjectId $record.id `
            -ObjectName $record.userPrincipalName `
            -Detail $detail `
            -Recommendation 'Require MFA registration through a Conditional Access policy, then confirm the user completes registration. For administrators, treat this as an immediate action.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-mfa-getstarted' `
            -Evidence @{
                displayName      = $record.userDisplayName
                userType         = $record.userType
                isAdmin          = $isAdmin
                isMfaRegistered  = $registered
                isMfaCapable     = $capable
                methodsRegistered = @($record.methodsRegistered)
                defaultMfaMethod = $record.defaultMfaMethod
                lastUpdated      = $record.lastUpdatedDateTime
            }
    }

    New-HygieneCheckResult `
        -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
        -Status 'Completed' `
        -Findings @($findings) `
        -ObjectsEvaluated $details.Count `
        -RequiredScopes $meta.RequiredScopes
}

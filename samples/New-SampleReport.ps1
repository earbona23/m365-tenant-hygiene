#Requires -Version 7.2
<#
.SYNOPSIS
    Generates the example report shown in the README, from synthetic data.

.DESCRIPTION
    Renders a report without touching a real tenant, so the screenshots in the README
    are reproducible by anyone and contain no real user, device or application.

    Everything below is invented. The tenant is fictional, the addresses are in
    reserved example domains, and the identifiers are obviously not real GUIDs. Nothing
    here comes from any tenant, and no part of this script authenticates to anything.

    The data is chosen to exercise the parts of the report that are easy to get wrong:
    one of every severity, a check that was skipped for a missing licence, a check that
    was skipped for a denied permission, and evidence blocks of different shapes.

.EXAMPLE
    ./samples/New-SampleReport.ps1 -Path ./docs/images

.NOTES
    The report is produced by exactly the same renderer used for real audits. If the
    sample looks right, the real one is laid out the same way.
#>
[CmdletBinding()]
param(
    [string] $Path = (Join-Path $PSScriptRoot '..' 'docs' 'images'),
    [string] $Prefix = 'sample'
)

$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot '..' 'src' 'M365TenantHygiene' 'M365TenantHygiene.psd1'
Import-Module $modulePath -Force

$module = Get-Module M365TenantHygiene

$audit = & $module {

    $now = [datetime]::new(2026, 3, 14, 9, 41, 0, [DateTimeKind]::Utc)

    # --- Identity -------------------------------------------------------------

    $mfaFindings = @(
        New-HygieneFinding -CheckId 'MfaRegistration' -CheckName 'Users without MFA' -Category 'Identity' `
            -Severity 'Critical' -Title 'Account is not capable of multi-factor authentication' `
            -ObjectType 'User' -ObjectId '00000000-0000-4000-a000-000000000101' -ObjectName 'dana.whitfield@contoso.example' `
            -Detail 'The account has no registered multi-factor authentication method. This account holds at least one administrative role, so a single stolen password is enough to reach tenant administration.' `
            -Recommendation 'Require MFA registration through a Conditional Access policy, then confirm the user completes registration. For administrators, treat this as an immediate action.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-mfa-getstarted' `
            -Evidence @{ displayName = 'Dana Whitfield'; userType = 'Member'; isAdmin = $true; isMfaRegistered = $false; isMfaCapable = $false; methodsRegistered = @(); defaultMfaMethod = $null; lastUpdated = '2026-03-11T22:04:00Z' }

        New-HygieneFinding -CheckId 'MfaRegistration' -CheckName 'Users without MFA' -Category 'Identity' `
            -Severity 'High' -Title 'Account is not capable of multi-factor authentication' `
            -ObjectType 'User' -ObjectId '00000000-0000-4000-a000-000000000102' -ObjectName 'operations.scanner@contoso.example' `
            -Detail 'The account has a registered method, but none of the registered methods can currently satisfy an MFA challenge.' `
            -Recommendation 'Require MFA registration through a Conditional Access policy, then confirm the user completes registration.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-mfa-getstarted' `
            -Evidence @{ displayName = 'Operations Scanner'; userType = 'Member'; isAdmin = $false; isMfaRegistered = $true; isMfaCapable = $false; methodsRegistered = @('mobilePhone'); defaultMfaMethod = 'none'; lastUpdated = '2025-08-02T11:19:00Z' }

        New-HygieneFinding -CheckId 'MfaRegistration' -CheckName 'Users without MFA' -Category 'Identity' `
            -Severity 'Medium' -Title 'Account is not capable of multi-factor authentication' `
            -ObjectType 'User' -ObjectId '00000000-0000-4000-a000-000000000103' -ObjectName 'r.okonkwo_partner.example#EXT#@contoso.example' `
            -Detail 'The account has no registered multi-factor authentication method.' `
            -Recommendation 'Require MFA registration through a Conditional Access policy, then confirm the user completes registration.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-mfa-getstarted' `
            -Evidence @{ displayName = 'Rita Okonkwo (Partner)'; userType = 'Guest'; isAdmin = $false; isMfaRegistered = $false; isMfaCapable = $false; methodsRegistered = @() }
    )

    $inactiveFindings = @(
        New-HygieneFinding -CheckId 'InactiveAccount' -CheckName 'Inactive accounts' -Category 'Identity' `
            -Severity 'High' -Title 'Enabled account is inactive' `
            -ObjectType 'User' -ObjectId '00000000-0000-4000-a000-000000000104' -ObjectName 'p.stavros@contoso.example' `
            -Detail 'Last sign-in was 214 day(s) ago, beyond the 90 day threshold. The account also holds a privileged directory role, which makes a dormant account a standing administrative foothold.' `
            -Recommendation 'Confirm the account is still needed. If it is not, disable it, reclaim the licence, and delete it once the retention period allows.' `
            -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
            -Evidence @{ displayName = 'Petros Stavros'; userType = 'Member'; licensed = $true; licenseCount = 2; privileged = $true; lastSignInUtc = '2025-08-12T07:55:00.0000000Z'; daysIdle = 214; thresholdDays = 90 }

        New-HygieneFinding -CheckId 'InactiveAccount' -CheckName 'Inactive accounts' -Category 'Identity' `
            -Severity 'Medium' -Title 'Enabled account has never signed in' `
            -ObjectType 'User' -ObjectId '00000000-0000-4000-a000-000000000105' -ObjectName 'temp.contractor03@contoso.example' `
            -Detail 'No interactive sign-in has ever been recorded, and the account was created 402 day(s) ago.' `
            -Recommendation 'Confirm the account is still needed. If it is not, disable it and reclaim the licence.' `
            -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
            -Evidence @{ displayName = 'Temporary Contractor 03'; userType = 'Member'; licensed = $true; licenseCount = 1; privileged = $false; createdDateTime = '2025-02-05T14:00:00Z'; daysIdle = 402; thresholdDays = 90 }
    )

    # --- Privileged access ----------------------------------------------------

    $roleFindings = @(
        New-HygieneFinding -CheckId 'PrivilegedRole' -CheckName 'Privileged role assignments' -Category 'Privileged access' `
            -Severity 'Critical' -Title 'Guest account holds the Global Administrator role' `
            -ObjectType 'user' -ObjectId '00000000-0000-4000-a000-000000000106' -ObjectName 'consultant_msp.example#EXT#@contoso.example' `
            -Detail 'An account external to this tenant holds Global Administrator. Guest identities are governed by another organisation''s password, MFA and offboarding processes, none of which this tenant controls.' `
            -Recommendation 'Remove the role from the guest account. Where an external party genuinely needs administrative access, issue them an internal account subject to this tenant''s Conditional Access and lifecycle controls.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -Evidence @{ roleName = 'Global Administrator'; roleTier = 'Tier0'; principalType = 'user'; userType = 'Guest'; directoryScopeId = '/'; accountEnabled = $true }

        New-HygieneFinding -CheckId 'PrivilegedRole' -CheckName 'Privileged role assignments' -Category 'Privileged access' `
            -Severity 'High' -Title '7 principals hold Global Administrator' `
            -ObjectType 'Tenant' -ObjectId '00000000-0000-4000-b000-0000000000ff' -ObjectName 'Contoso Example Ltd' `
            -Detail 'Microsoft''s guidance is to keep the number of permanent Global Administrators small -- commonly no more than 4. Every additional holder is another account whose compromise is a full tenant compromise.' `
            -Recommendation 'Move day-to-day work onto the least-privileged role that covers it, and make the remaining Global Administrator access eligible rather than permanent through Privileged Identity Management.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -Evidence @{ globalAdministratorCount = 7; threshold = 4; holders = @('Dana Whitfield', 'Petros Stavros', 'Rita Okonkwo (Partner)', 'break-glass-01', 'break-glass-02', 'IT Automation', 'Legacy Migration Account') }

        New-HygieneFinding -CheckId 'PrivilegedRole' -CheckName 'Privileged role assignments' -Category 'Privileged access' `
            -Severity 'Medium' -Title 'Disabled account still holds the Exchange Administrator role' `
            -ObjectType 'user' -ObjectId '00000000-0000-4000-a000-000000000107' -ObjectName 'j.laurent@contoso.example' `
            -Detail 'The account is disabled but the Exchange Administrator assignment remains. Re-enabling the account -- during an offboarding reversal, a migration, or an attack -- restores administrative access with it.' `
            -Recommendation 'Remove role assignments as part of offboarding rather than relying on the account being disabled.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -Evidence @{ roleName = 'Exchange Administrator'; roleTier = 'Tier1'; principalType = 'user'; accountEnabled = $false; directoryScopeId = '/' }

        New-HygieneFinding -CheckId 'PrivilegedRole' -CheckName 'Privileged role assignments' -Category 'Privileged access' `
            -Severity 'Informational' -Title 'Global Administrator assignment' `
            -ObjectType 'user' -ObjectId '00000000-0000-4000-a000-000000000108' -ObjectName 'break-glass-01@contoso.example' `
            -Detail 'break-glass-01@contoso.example holds Global Administrator. Entire directory.' `
            -Recommendation 'Confirm this assignment is still required and that the account is protected by phishing-resistant MFA.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -Evidence @{ roleName = 'Global Administrator'; roleTier = 'Tier0'; principalType = 'user'; userType = 'Member'; accountEnabled = $true; directoryScopeId = '/' }
    )

    # --- Applications ---------------------------------------------------------

    $appFindings = @(
        New-HygieneFinding -CheckId 'RiskyApplication' -CheckName 'Applications with high-risk permissions' -Category 'Applications' `
            -Severity 'Critical' -Title 'Application can escalate its own privileges' `
            -ObjectType 'ServicePrincipal' -ObjectId '00000000-0000-4000-c000-000000000201' -ObjectName 'Legacy Reporting Connector' `
            -Detail 'This application holds Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All as an application permission. Permissions in this group let the holder assign roles or credentials, so whoever controls this application''s secret can make themselves a Global Administrator without ever signing in as a user. The application is published by another tenant, so the credential that uses this grant is held outside your organisation.' `
            -Recommendation 'Identify the workload behind this application and confirm it needs tenant-wide access. Where it does not, replace the grant with a narrower permission. Remove grants belonging to applications nobody can account for.' `
            -Reference 'https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview' `
            -Evidence @{ grantType = 'Application permission (app role)'; resource = 'Microsoft Graph'; permissions = @('AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All', 'User.Read.All'); escalationPermissions = @('AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All'); publishedExternally = $true; accountEnabled = $true }

        New-HygieneFinding -CheckId 'RiskyApplication' -CheckName 'Applications with high-risk permissions' -Category 'Applications' `
            -Severity 'High' -Title 'Application has tenant-wide access to organisation data' `
            -ObjectType 'ServicePrincipal' -ObjectId '00000000-0000-4000-c000-000000000202' -ObjectName 'Invoice Archiver' `
            -Detail 'This application holds Mail.ReadWrite, Files.ReadWrite.All as an application permission. Application permissions are not scoped to a user and are not subject to MFA, so this grant covers every mailbox, site or file in the tenant, permanently.' `
            -Recommendation 'Scope mail and file access with an application access policy so the application only reaches the mailboxes it needs.' `
            -Reference 'https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview' `
            -Evidence @{ grantType = 'Application permission (app role)'; resource = 'Microsoft Graph'; permissions = @('Files.ReadWrite.All', 'Mail.ReadWrite'); bulkDataPermissions = @('Files.ReadWrite.All', 'Mail.ReadWrite'); publishedExternally = $false; accountEnabled = $true }

        New-HygieneFinding -CheckId 'RiskyApplication' -CheckName 'Applications with high-risk permissions' -Category 'Applications' `
            -Severity 'Medium' -Title 'Sensitive delegated permission granted for all users' `
            -ObjectType 'ServicePrincipal' -ObjectId '00000000-0000-4000-c000-000000000203' -ObjectName 'Team Productivity Add-in' `
            -Detail 'An administrator consented to Files.Read.All, Sites.Read.All on Microsoft Graph for every user in the tenant. Any user of this application acts with these permissions without being asked, so the grant is only as trustworthy as the application itself.' `
            -Recommendation 'Confirm the application is one your organisation deliberately adopted. Where tenant-wide consent is not required, revoke it and restrict the app to an assigned group.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests' `
            -Evidence @{ grantType = 'Delegated permission (AllPrincipals)'; resource = 'Microsoft Graph'; scopes = @('Files.Read.All', 'Sites.Read.All', 'User.Read', 'offline_access'); riskyScopes = @('Files.Read.All', 'Sites.Read.All') }
    )

    # --- Devices --------------------------------------------------------------

    $deviceFindings = @(
        New-HygieneFinding -CheckId 'DeviceCompliance' -CheckName 'Non-compliant Intune devices' -Category 'Devices' `
            -Severity 'High' -Title 'Device is non-compliant' `
            -ObjectType 'Device' -ObjectId '00000000-0000-4000-d000-000000000301' -ObjectName 'CTS-LAPTOP-0417' `
            -Detail 'The device failed the compliance policies targeting it. If a Conditional Access policy requires a compliant device, this device is being blocked; if no such policy exists, it is reaching corporate data while failing your own baseline.' `
            -Recommendation 'Open the device in Intune to see which settings failed, and fix the setting rather than the compliance policy.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
            -Evidence @{ operatingSystem = 'Windows'; osVersion = '10.0.19045.4291'; complianceState = 'noncompliant'; isEncrypted = $false; daysSinceSync = 2; assignedUser = 'p.stavros@contoso.example'; manufacturer = 'Contoso Devices'; model = 'Pro 14' }

        New-HygieneFinding -CheckId 'DeviceCompliance' -CheckName 'Non-compliant Intune devices' -Category 'Devices' `
            -Severity 'Medium' -Title 'No compliance policy applies to this device' `
            -ObjectType 'Device' -ObjectId '00000000-0000-4000-d000-000000000302' -ObjectName 'CTS-IPAD-0022' `
            -Detail "The device reports 'notApplicable', meaning no Intune compliance policy targets it. It will never be reported as non-compliant, because nothing is evaluating it -- and a Conditional Access policy requiring compliance may still let it through." `
            -Recommendation 'Extend a compliance policy to cover this device''s platform and group. Gaps in policy targeting are the most common reason a fleet looks compliant.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
            -Evidence @{ operatingSystem = 'iOS'; osVersion = '17.4.1'; complianceState = 'notApplicable'; daysSinceSync = 6; assignedUser = 'dana.whitfield@contoso.example' }

        New-HygieneFinding -CheckId 'DeviceCompliance' -CheckName 'Non-compliant Intune devices' -Category 'Devices' `
            -Severity 'Low' -Title 'Compliant verdict is stale' `
            -ObjectType 'Device' -ObjectId '00000000-0000-4000-d000-000000000303' -ObjectName 'CTS-DESKTOP-0090' `
            -Detail 'The device is recorded as compliant but last synchronised 118 day(s) ago, beyond the 30 day threshold. The verdict describes the device as it was then, not as it is now.' `
            -Recommendation 'Confirm the device is still in service. Retire records for devices that are gone so the compliance figures describe the real estate.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
            -Evidence @{ operatingSystem = 'Windows'; osVersion = '10.0.22631.3447'; complianceState = 'compliant'; daysSinceSync = 118; isEncrypted = $true }
    )

    $checks = @(
        New-HygieneCheckResult -CheckId 'PrivilegedRole' -CheckName 'Privileged role assignments' -Category 'Privileged access' `
            -Status 'Completed' -Findings $roleFindings -ObjectsEvaluated 41 -Duration ([timespan]::FromSeconds(2.4)) `
            -RequiredScopes @('RoleManagement.Read.Directory')

        New-HygieneCheckResult -CheckId 'MfaRegistration' -CheckName 'Users without MFA' -Category 'Identity' `
            -Status 'Completed' -Findings $mfaFindings -ObjectsEvaluated 318 -Duration ([timespan]::FromSeconds(3.1)) `
            -RequiredScopes @('AuditLog.Read.All')

        New-HygieneCheckResult -CheckId 'InactiveAccount' -CheckName 'Inactive accounts' -Category 'Identity' `
            -Status 'Completed' -Findings $inactiveFindings -ObjectsEvaluated 296 -Duration ([timespan]::FromSeconds(4.8)) `
            -RequiredScopes @('User.Read.All', 'AuditLog.Read.All')

        New-HygieneCheckResult -CheckId 'RiskyApplication' -CheckName 'Applications with high-risk permissions' -Category 'Applications' `
            -Status 'Completed' -Findings $appFindings -ObjectsEvaluated 63 -Duration ([timespan]::FromSeconds(5.6)) `
            -RequiredScopes @('Application.Read.All', 'Directory.Read.All')

        New-HygieneCheckResult -CheckId 'MailForwarding' -CheckName 'Inbox rules forwarding outside the tenant' -Category 'Exchange Online' `
            -Status 'Skipped' -ObjectsEvaluated 0 -Duration ([timespan]::FromSeconds(1.2)) `
            -RequiredScopes @('MailboxSettings.Read', 'User.Read.All') `
            -Reason 'Microsoft Graph refused access to all 296 mailbox(es) tried. With delegated permissions the module can only read mailboxes the signed-in user can already open; an administrative role does not by itself grant mailbox access. No conclusion about external forwarding can be drawn from this run.'

        New-HygieneCheckResult -CheckId 'DeviceCompliance' -CheckName 'Non-compliant Intune devices' -Category 'Devices' `
            -Status 'Completed' -Findings $deviceFindings -ObjectsEvaluated 174 -Duration ([timespan]::FromSeconds(3.9)) `
            -RequiredScopes @('DeviceManagementManagedDevices.Read.All')
    )

    $findings = @(
        $checks |
            Where-Object { $_.Status -eq 'Completed' } |
            ForEach-Object { $_.Findings } |
            Sort-Object SeverityRank, Category, CheckName, ObjectName
    )

    [pscustomobject]@{
        PSTypeName      = 'M365TenantHygiene.AuditResult'
        Tenant          = [pscustomobject]@{ Id = '00000000-0000-4000-b000-0000000000ff'; DisplayName = 'Contoso Example Ltd' }
        VerifiedDomains = @('contoso.example', 'contoso.onmicrosoft.example')
        Account         = 'security.reader@contoso.example'
        Environment     = 'Global'
        StartedAt       = $now.AddSeconds(-21)
        CompletedAt     = $now
        Duration        = [timespan]::FromSeconds(21)
        ModuleVersion   = (Get-Module M365TenantHygiene).Version.ToString()
        Parameters      = [ordered]@{ InactiveDays = 90; GlobalAdminThreshold = 4; MaxMailbox = 0; MaxPages = 200 }
        Checks          = $checks
        Findings        = $findings
        Summary         = (New-HygieneSummary -CheckResult $checks -Finding $findings)
    }
}

$files = Export-M365HygieneReport -Audit $audit -Path $Path -Prefix $Prefix -PassThru
$files | ForEach-Object { Write-Host "wrote $($_.FullName)" }

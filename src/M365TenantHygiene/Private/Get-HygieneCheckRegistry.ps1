<#
.SYNOPSIS
    The catalogue of checks: what exists, what it needs, and what implements it.
.DESCRIPTION
    Everything the module knows about its own checks lives here in one place.

    This matters for the permission story. The scopes requested at sign-in are derived
    from this table and from the checks the caller actually selected, so asking for
    fewer checks really does mean consenting to fewer permissions -- it is not a
    fixed block of scopes with a filter applied afterwards.

    Each entry:
      Id             Stable identifier used on the command line and in exports.
      Name           Human-readable name shown in the report.
      Category       Grouping used by the report's navigation.
      Description    One line, shown by Get-M365HygieneCheck.
      RequiredScopes Delegated Microsoft Graph scopes, least-privileged, verified
                     against the API reference (see docs/permissions.md).
      Function       The implementing function in Checks/.
      GraphEndpoints Read endpoints touched, so the blast radius is auditable.
      RunOrder       Execution order. Not cosmetic: PrivilegedRole runs first because
                     it caches the set of privileged principals, which the inactive
                     account check uses to raise the severity of a dormant admin. Any
                     check that consumes another's cache degrades gracefully when that
                     check was not selected -- it loses the enrichment, never correctness.
      Notes          Prerequisites and known coverage limits.
#>
function Get-HygieneCheckRegistry {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $registry = [ordered]@{

        MfaRegistration = [ordered]@{
            Id             = 'MfaRegistration'
            RunOrder       = 20
            Name           = 'Users without MFA'
            Category       = 'Identity'
            Description    = 'Finds enabled accounts that have not registered a multi-factor authentication method.'
            RequiredScopes = @('AuditLog.Read.All')
            Function       = 'Test-HygieneMfaRegistration'
            GraphEndpoints = @('GET /reports/authenticationMethods/userRegistrationDetails')
            Notes          = 'The registration report excludes disabled users. Registration is not the same as enforcement: a user can be registered and still never be challenged if no Conditional Access policy requires it.'
        }

        InactiveAccount = [ordered]@{
            Id             = 'InactiveAccount'
            RunOrder       = 30
            Name           = 'Inactive accounts'
            Category       = 'Identity'
            Description    = 'Finds enabled accounts with no interactive sign-in within the threshold (90 days by default).'
            RequiredScopes = @('User.Read.All', 'AuditLog.Read.All')
            Function       = 'Test-HygieneInactiveAccount'
            GraphEndpoints = @('GET /users?$select=...,signInActivity')
            Notes          = 'signInActivity requires a Microsoft Entra ID P1 or P2 licence. It is absent for users who never signed in, and for sign-ins before April 2020.'
        }

        PrivilegedRole = [ordered]@{
            Id             = 'PrivilegedRole'
            RunOrder       = 10
            Name           = 'Privileged role assignments'
            Category       = 'Privileged access'
            Description    = 'Inventories directory role assignments and flags risky ones: too many Global Administrators, guests or service principals holding admin roles, disabled admin accounts.'
            RequiredScopes = @('RoleManagement.Read.Directory')
            Function       = 'Test-HygienePrivilegedRole'
            GraphEndpoints = @('GET /roleManagement/directory/roleDefinitions', 'GET /roleManagement/directory/roleAssignments?$expand=principal')
            Notes          = 'Reads active assignments only. Eligible (not yet activated) PIM assignments are not covered; see the Limitations section of the README.'
        }

        RiskyApplication = [ordered]@{
            Id             = 'RiskyApplication'
            RunOrder       = 40
            Name           = 'Applications with high-risk permissions'
            Category       = 'Applications'
            Description    = 'Flags service principals holding high-impact application permissions on Microsoft Graph, and tenant-wide delegated grants.'
            RequiredScopes = @('Application.Read.All', 'Directory.Read.All')
            Function       = 'Test-HygieneRiskyApplication'
            GraphEndpoints = @(
                "GET /servicePrincipals(appId='00000003-0000-0000-c000-000000000000')",
                "GET /servicePrincipals(appId='00000003-0000-0000-c000-000000000000')/appRoleAssignedTo",
                'GET /oauth2PermissionGrants'
            )
            Notes          = 'Scoped to permissions granted on the Microsoft Graph API, which is where the highest-impact application permissions live. Permissions on other resource APIs are out of scope.'
        }

        MailForwarding = [ordered]@{
            Id             = 'MailForwarding'
            RunOrder       = 50
            Name           = 'Inbox rules forwarding outside the tenant'
            Category       = 'Exchange Online'
            Description    = 'Finds inbox rules that forward or redirect mail to an address outside the tenant''s verified domains.'
            RequiredScopes = @('MailboxSettings.Read', 'User.Read.All')
            Function       = 'Test-HygieneMailForwarding'
            GraphEndpoints = @('GET /users/{id}/mailFolders/inbox/messageRules')
            Notes          = 'Delegated permissions only reach mailboxes the signed-in user can already open. Read the Limitations section before trusting a clean result here.'
        }

        DeviceCompliance = [ordered]@{
            Id             = 'DeviceCompliance'
            RunOrder       = 60
            Name           = 'Non-compliant Intune devices'
            Category       = 'Devices'
            Description    = 'Finds managed devices that are non-compliant, in grace period, or have never evaluated a compliance policy.'
            RequiredScopes = @('DeviceManagementManagedDevices.Read.All')
            Function       = 'Test-HygieneDeviceCompliance'
            GraphEndpoints = @('GET /deviceManagement/managedDevices')
            Notes          = 'Requires an active Intune licence on the tenant. Without one the endpoint is unavailable and the check reports Skipped rather than clean.'
        }
    }

    return $registry
}

<#
.SYNOPSIS
    Works out the exact set of delegated scopes a given selection of checks needs.
.DESCRIPTION
    Always includes User.Read, which the module uses to read the tenant's own display
    name and verified domains from /organization. User.Read is the least-privileged
    permission that endpoint accepts and is enough for the three properties needed.
#>
function Get-HygieneRequiredScope {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([string[]] $CheckId)

    $registry = Get-HygieneCheckRegistry
    if (-not $CheckId -or $CheckId.Count -eq 0) { $CheckId = @($registry.Keys) }

    $scopes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void] $scopes.Add('User.Read')

    foreach ($id in $CheckId) {
        if (-not $registry.Contains($id)) {
            throw "Unknown check '$id'. Run Get-M365HygieneCheck to list the available checks."
        }
        foreach ($scope in $registry[$id].RequiredScopes) { [void] $scopes.Add($scope) }
    }

    return @($scopes) | Sort-Object
}

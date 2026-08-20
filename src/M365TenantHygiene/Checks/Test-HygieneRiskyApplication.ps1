<#
.SYNOPSIS
    Flags service principals that hold high-impact permissions on Microsoft Graph.

.DESCRIPTION
    Application permissions are the quietest way to own a tenant. They belong to a
    non-human identity, they are not challenged by MFA, they survive every password
    reset, and nobody receives a sign-in notification when they are used.

    The check looks at two distinct grant types, because they fail differently:

      Application permissions (app roles) act with no user present and apply to the
      whole tenant. Mail.ReadWrite here means every mailbox, always.

      Delegated permissions granted with consentType 'AllPrincipals' act on behalf of
      any user who uses the app, tenant-wide, without each user consenting.

    Permissions are graded by what they let the holder become, not by how alarming
    the name sounds. Anything that can assign roles or credentials -- RoleManagement,
    AppRoleAssignment, Application.ReadWrite.All, Directory.ReadWrite.All -- is
    Critical, because a holder can promote itself to Global Administrator. Bulk access
    to mail, files or sites is High: total data loss, but no privilege escalation.

.PARAMETER Context
    Shared audit context from New-HygieneAuditContext.

.OUTPUTS
    M365TenantHygiene.Finding objects.

.NOTES
    Graph endpoints: GET /servicePrincipals
                     GET /servicePrincipals(appId='00000003-0000-0000-c000-000000000000')
                     GET /servicePrincipals(appId='...')/appRoleAssignedTo
                     GET /oauth2PermissionGrants
    Scopes required: Application.Read.All, Directory.Read.All (delegated)

    Scoped to permissions granted on the Microsoft Graph API. That is one call rather
    than one per service principal, and it is where the highest-impact application
    permissions in a Microsoft 365 tenant live -- but permissions granted on other
    resource APIs, including the legacy Exchange Online API, are outside this check.
#>
function Test-HygieneRiskyApplication {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][hashtable] $Context)

    $meta = (Get-HygieneCheckRegistry)['RiskyApplication']

    # The Microsoft Graph resource application. This identifier is a well-known
    # constant, the same in every tenant.
    $graphAppId = '00000003-0000-0000-c000-000000000000'

    # Permissions that let the holder grant itself or another principal more access.
    # Holding any of these is equivalent to holding Global Administrator.
    $escalation = @(
        'RoleManagement.ReadWrite.Directory'
        'AppRoleAssignment.ReadWrite.All'
        'Application.ReadWrite.All'
        'Directory.ReadWrite.All'
        'PrivilegedAccess.ReadWrite.AzureAD'
        'RoleManagement.ReadWrite.All'
        'Directory.AccessAsUser.All'
    )

    # Permissions that expose or alter organisation-wide data without escalating.
    $bulkData = @(
        'Mail.Read'
        'Mail.ReadWrite'
        'Mail.Send'
        'MailboxSettings.ReadWrite'
        'Files.Read.All'
        'Files.ReadWrite.All'
        'Sites.Read.All'
        'Sites.ReadWrite.All'
        'Sites.FullControl.All'
        'User.ReadWrite.All'
        'Group.ReadWrite.All'
        'ChannelMessage.Read.All'
        'Chat.Read.All'
        'full_access_as_app'
    )

    $servicePrincipals = Invoke-HygieneGraphRequest `
        -Uri 'servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId&$top=999' `
        -MaxPages $Context.MaxPages

    $spById = @{}
    foreach ($sp in $servicePrincipals) { $spById[$sp.id] = $sp }
    Write-HygieneLog -Message "Read $($servicePrincipals.Count) service principal(s)."

    $graphSp = @(Invoke-HygieneGraphRequest `
        -Uri "servicePrincipals(appId='$graphAppId')?`$select=id,appId,displayName,appRoles" `
        -MaxPages 1)

    if ($graphSp.Count -eq 0 -or -not $graphSp[0].id) {
        return New-HygieneCheckResult `
            -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
            -Status 'Failed' `
            -RequiredScopes $meta.RequiredScopes `
            -ErrorMessage 'The Microsoft Graph service principal could not be read, so application permissions could not be resolved to permission names.'
    }

    $graphSp = $graphSp[0]

    # appRoleAssignedTo returns an opaque appRoleId. Without this map the report would
    # list GUIDs, which nobody can act on.
    $roleValueById = @{}
    foreach ($role in $graphSp.appRoles) { $roleValueById[$role.id] = $role.value }

    $tenantId = if ($Context.Tenant) { $Context.Tenant.Id } else { $null }
    $findings = [System.Collections.Generic.List[object]]::new()
    $evaluated = 0

    # --- Application permissions on Microsoft Graph -------------------------------

    $appGrants = Invoke-HygieneGraphRequest `
        -Uri "servicePrincipals(appId='$graphAppId')/appRoleAssignedTo" `
        -MaxPages $Context.MaxPages

    Write-HygieneLog -Message "Read $($appGrants.Count) application permission grant(s) on Microsoft Graph."

    $byClient = $appGrants | Group-Object -Property principalId
    foreach ($group in $byClient) {

        $evaluated++
        $clientId   = $group.Name
        $clientName = $group.Group[0].principalDisplayName
        $client     = $spById[$clientId]

        $permissions = @(
            $group.Group |
                ForEach-Object { $roleValueById[$_.appRoleId] } |
                Where-Object { $_ } |
                Sort-Object -Unique
        )

        $hasEscalation = @($permissions | Where-Object { $escalation -contains $_ })
        $hasBulk       = @($permissions | Where-Object { $bulkData -contains $_ })

        if ($hasEscalation.Count -eq 0 -and $hasBulk.Count -eq 0) { continue }

        $external = $false
        if ($client -and $client.appOwnerOrganizationId -and $tenantId) {
            $external = ($client.appOwnerOrganizationId -ne $tenantId)
        }

        if ($hasEscalation.Count -gt 0) {
            $severity = 'Critical'
            $title    = 'Application can escalate its own privileges'
            $detail   = "This application holds $($hasEscalation -join ', ') as an application permission. Permissions in this group let the holder assign roles or credentials, so whoever controls this application's secret can make themselves a Global Administrator without ever signing in as a user."
        }
        else {
            $severity = 'High'
            $title    = 'Application has tenant-wide access to organisation data'
            $detail   = "This application holds $($hasBulk -join ', ') as an application permission. Application permissions are not scoped to a user and are not subject to MFA, so this grant covers every mailbox, site or file in the tenant, permanently."
        }

        if ($external) {
            $detail += ' The application is published by another tenant, so the credential that uses this grant is held outside your organisation.'
        }
        if ($client -and $client.accountEnabled -eq $false) {
            $detail += ' The service principal is currently disabled, which suspends but does not remove the grant.'
        }

        $findings.Add((New-HygieneFinding `
            -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
            -Severity $severity `
            -Title $title `
            -ObjectType 'ServicePrincipal' `
            -ObjectId $clientId `
            -ObjectName $clientName `
            -Detail $detail `
            -Recommendation 'Identify the workload behind this application and confirm it needs tenant-wide access. Where it does not, replace the grant with a narrower permission, or scope mail and file access with an application access policy. Remove grants belonging to applications nobody can account for.' `
            -Reference 'https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview' `
            -Evidence @{
                grantType            = 'Application permission (app role)'
                resource             = 'Microsoft Graph'
                permissions          = $permissions
                escalationPermissions = $hasEscalation
                bulkDataPermissions  = $hasBulk
                appId                = if ($client) { $client.appId } else { $null }
                publishedExternally  = $external
                appOwnerOrganizationId = if ($client) { $client.appOwnerOrganizationId } else { $null }
                accountEnabled       = if ($client) { $client.accountEnabled } else { $null }
            }))
    }

    # --- Tenant-wide delegated grants ---------------------------------------------

    $delegatedGrants = Invoke-HygieneGraphRequest -Uri 'oauth2PermissionGrants' -MaxPages $Context.MaxPages
    Write-HygieneLog -Message "Read $($delegatedGrants.Count) delegated permission grant(s)."

    foreach ($grant in $delegatedGrants) {

        if ($grant.consentType -ne 'AllPrincipals') { continue }
        $evaluated++

        $scopes = @(($grant.scope -split '\s+') | Where-Object { $_ })
        $hasEscalation = @($scopes | Where-Object { $escalation -contains $_ })
        $hasBulk       = @($scopes | Where-Object { $bulkData -contains $_ })

        if ($hasEscalation.Count -eq 0 -and $hasBulk.Count -eq 0) { continue }

        $client       = $spById[$grant.clientId]
        $clientName   = if ($client) { $client.displayName } else { $grant.clientId }
        $resource     = $spById[$grant.resourceId]
        $resourceName = if ($resource) { $resource.displayName } else { $grant.resourceId }

        $severity = if ($hasEscalation.Count -gt 0) { 'High' } else { 'Medium' }
        $risky    = @($hasEscalation + $hasBulk | Sort-Object -Unique)

        $findings.Add((New-HygieneFinding `
            -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
            -Severity $severity `
            -Title 'Sensitive delegated permission granted for all users' `
            -ObjectType 'ServicePrincipal' `
            -ObjectId $grant.clientId `
            -ObjectName $clientName `
            -Detail "An administrator consented to $($risky -join ', ') on $resourceName for every user in the tenant. Any user of this application acts with these permissions without being asked, so the grant is only as trustworthy as the application itself." `
            -Recommendation 'Confirm the application is one your organisation deliberately adopted. Where tenant-wide consent is not required, revoke it and let individual users consent, or restrict the app to an assigned group.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests' `
            -Evidence @{
                grantType      = 'Delegated permission (AllPrincipals)'
                resource       = $resourceName
                scopes         = $scopes
                riskyScopes    = $risky
                grantId        = $grant.id
                clientAppId    = if ($client) { $client.appId } else { $null }
            }))
    }

    New-HygieneCheckResult `
        -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
        -Status 'Completed' `
        -Findings @($findings) `
        -ObjectsEvaluated $evaluated `
        -RequiredScopes $meta.RequiredScopes
}

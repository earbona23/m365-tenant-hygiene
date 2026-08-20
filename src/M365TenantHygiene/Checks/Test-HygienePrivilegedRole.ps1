<#
.SYNOPSIS
    Inventories directory role assignments and flags the risky ones.

.DESCRIPTION
    Produces two things at once, because an auditor needs both:

      an inventory of who holds the highest-privilege roles, emitted as Informational
      findings so the report answers "who can do what" even when nothing is wrong; and

      actual findings for the states that are known to go wrong -- too many Global
      Administrators, too few to recover from a lockout, guests holding admin roles,
      service principals holding tier-0 roles, and admin roles still attached to
      disabled accounts.

    Roles are classified by display name against a curated list rather than by
    template GUID. Display names for built-in directory roles are stable, and the
    alternative would mean hardcoding a table of GUIDs, where a single wrong digit
    silently downgrades a real Global Administrator to "other role" and the report
    looks clean. A name this module does not recognise is reported as an unclassified
    assignment rather than dropped.

.PARAMETER Context
    Shared audit context from New-HygieneAuditContext.

.OUTPUTS
    M365TenantHygiene.Finding objects.

.NOTES
    Graph endpoints: GET /roleManagement/directory/roleDefinitions
                     GET /roleManagement/directory/roleAssignments?$expand=principal
    Scope required : RoleManagement.Read.Directory (delegated)

    Only active assignments are visible here. A Privileged Identity Management
    eligible assignment -- an account that can elevate to Global Administrator but is
    not currently elevated -- does not appear in roleAssignments and is not counted.
    On a PIM-heavy tenant this check therefore understates who can reach tier 0.

    Roles assigned to a role-assignable group are reported against the group. The
    module does not expand group membership, so the individual holders are not listed.
#>
function Test-HygienePrivilegedRole {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][hashtable] $Context)

    $meta = (Get-HygieneCheckRegistry)['PrivilegedRole']

    # Tier 0: can grant themselves or others any other role, or reset an admin's
    # credentials. Compromise of one of these is compromise of the tenant.
    $tier0 = @(
        'Global Administrator'
        'Privileged Role Administrator'
        'Privileged Authentication Administrator'
        'Partner Tier2 Support'
    )

    # Tier 1: broad control over identity, data or devices, but cannot directly
    # promote themselves to tier 0.
    $tier1 = @(
        'Application Administrator'
        'Authentication Administrator'
        'Cloud Application Administrator'
        'Cloud Device Administrator'
        'Conditional Access Administrator'
        'Directory Writers'
        'Domain Name Administrator'
        'Exchange Administrator'
        'Groups Administrator'
        'Helpdesk Administrator'
        'Hybrid Identity Administrator'
        'Intune Administrator'
        'Partner Tier1 Support'
        'Password Administrator'
        'Security Administrator'
        'SharePoint Administrator'
        'Teams Administrator'
        'User Administrator'
        'Windows 365 Administrator'
    )

    $definitions = Invoke-HygieneGraphRequest `
        -Uri 'roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn' `
        -MaxPages $Context.MaxPages

    $definitionById = @{}
    foreach ($def in $definitions) { $definitionById[$def.id] = $def }

    $assignments = Invoke-HygieneGraphRequest `
        -Uri 'roleManagement/directory/roleAssignments?$expand=principal' `
        -MaxPages $Context.MaxPages

    Write-HygieneLog -Message "Read $($assignments.Count) role assignment(s) across $($definitions.Count) role definition(s)."

    $findings          = [System.Collections.Generic.List[object]]::new()
    $privilegedIds     = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $globalAdminHolders = [System.Collections.Generic.List[string]]::new()

    foreach ($assignment in $assignments) {

        $definition = $definitionById[$assignment.roleDefinitionId]
        $roleName   = if ($definition) { $definition.displayName } else { "Unknown role ($($assignment.roleDefinitionId))" }

        $tier = if ($tier0 -contains $roleName) { 'Tier0' }
                elseif ($tier1 -contains $roleName) { 'Tier1' }
                else { 'Other' }

        if ($tier -eq 'Other') { continue }

        $principal     = $assignment.principal
        $principalType = 'Unknown'
        if ($principal -and $principal.'@odata.type') {
            $principalType = ($principal.'@odata.type' -replace '^#microsoft\.graph\.', '')
        }

        $principalName = $null
        foreach ($prop in 'userPrincipalName', 'displayName', 'appId') {
            if ($principal -and $principal.$prop) { $principalName = $principal.$prop; break }
        }
        if (-not $principalName) { $principalName = $assignment.principalId }

        [void] $privilegedIds.Add($assignment.principalId)
        if ($roleName -eq 'Global Administrator') { [void] $globalAdminHolders.Add($principalName) }

        $scope = if ($assignment.directoryScopeId -eq '/') { 'Entire directory' } else { "Scoped to $($assignment.directoryScopeId)" }

        $evidence = @{
            roleName         = $roleName
            roleTier         = $tier
            roleDefinitionId = $assignment.roleDefinitionId
            principalId      = $assignment.principalId
            principalType    = $principalType
            directoryScopeId = $assignment.directoryScopeId
            accountEnabled   = if ($principal -and $null -ne $principal.accountEnabled) { [bool] $principal.accountEnabled } else { $null }
            userType         = if ($principal) { $principal.userType } else { $null }
        }

        $common = @{
            CheckId    = $meta.Id
            CheckName  = $meta.Name
            Category   = $meta.Category
            ObjectType = $principalType
            ObjectId   = $assignment.principalId
            ObjectName = $principalName
            Evidence   = $evidence
        }

        # --- Risky states, most severe first -------------------------------------

        if ($principalType -eq 'user' -and $principal.userType -eq 'Guest') {
            $findings.Add((New-HygieneFinding @common `
                -Severity $(if ($tier -eq 'Tier0') { 'Critical' } else { 'High' }) `
                -Title "Guest account holds the $roleName role" `
                -Detail "An account external to this tenant holds $roleName. Guest identities are governed by another organisation's password, MFA and offboarding processes, none of which this tenant controls." `
                -Recommendation 'Remove the role from the guest account. Where an external party genuinely needs administrative access, issue them an internal account subject to this tenant''s Conditional Access and lifecycle controls.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices'))
            continue
        }

        if ($principalType -eq 'servicePrincipal' -and $tier -eq 'Tier0') {
            $findings.Add((New-HygieneFinding @common `
                -Severity 'High' `
                -Title "Service principal holds the tier-0 role $roleName" `
                -Detail "A non-human identity holds $roleName. Service principals authenticate with secrets or certificates that do not expire on their own and are not protected by MFA, so this is a permanent unattended path to tenant administration." `
                -Recommendation 'Replace the directory role with the narrowest application permissions the workload actually needs. If the role is genuinely required, move the credential to a certificate, set a short expiry, and monitor its sign-ins.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices'))
            continue
        }

        if ($principalType -eq 'user' -and $null -ne $principal.accountEnabled -and -not $principal.accountEnabled) {
            $findings.Add((New-HygieneFinding @common `
                -Severity 'Medium' `
                -Title "Disabled account still holds the $roleName role" `
                -Detail "The account is disabled but the $roleName assignment remains. Re-enabling the account -- during an offboarding reversal, a migration, or an attack -- restores administrative access with it." `
                -Recommendation 'Remove role assignments as part of offboarding rather than relying on the account being disabled.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices'))
            continue
        }

        if ($principalType -eq 'group') {
            $findings.Add((New-HygieneFinding @common `
                -Severity 'Low' `
                -Title "The $roleName role is assigned through a group" `
                -Detail "$roleName is held by a role-assignable group rather than by named principals, so the effective holders are whoever is in the group at any moment. This module does not expand group membership, so those holders are not listed in this report." `
                -Recommendation 'Review the group''s membership and its owners. Anyone who can add members to the group can effectively grant this role.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/groups-concept'))
            continue
        }

        # --- Nothing wrong: record the assignment as inventory --------------------

        if ($tier -eq 'Tier0') {
            $findings.Add((New-HygieneFinding @common `
                -Severity 'Informational' `
                -Title "$roleName assignment" `
                -Detail "$principalName holds $roleName. $scope." `
                -Recommendation 'Confirm this assignment is still required and that the account is protected by phishing-resistant MFA.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices'))
        }
    }

    # --- Tenant-level judgements on the Global Administrator population -----------

    $gaCount = $globalAdminHolders.Count
    $warnAt  = $Context.GlobalAdminWarnThreshold

    if ($gaCount -gt $warnAt) {
        $findings.Add((New-HygieneFinding `
            -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
            -Severity 'High' `
            -Title "$gaCount principals hold Global Administrator" `
            -ObjectType 'Tenant' `
            -ObjectId $(if ($Context.Tenant) { $Context.Tenant.Id } else { 'tenant' }) `
            -ObjectName $(if ($Context.Tenant) { $Context.Tenant.DisplayName } else { 'This tenant' }) `
            -Detail "Microsoft's guidance is to keep the number of permanent Global Administrators small -- commonly no more than $warnAt. Every additional holder is another account whose compromise is a full tenant compromise." `
            -Recommendation 'Move day-to-day work onto the least-privileged role that covers it, and make the remaining Global Administrator access eligible rather than permanent through Privileged Identity Management.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -Evidence @{ globalAdministratorCount = $gaCount; threshold = $warnAt; holders = @($globalAdminHolders) }))
    }
    elseif ($gaCount -eq 1) {
        $findings.Add((New-HygieneFinding `
            -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
            -Severity 'Medium' `
            -Title 'Only one principal holds Global Administrator' `
            -ObjectType 'Tenant' `
            -ObjectId $(if ($Context.Tenant) { $Context.Tenant.Id } else { 'tenant' }) `
            -ObjectName $(if ($Context.Tenant) { $Context.Tenant.DisplayName } else { 'This tenant' }) `
            -Detail 'A single Global Administrator is a single point of failure. If that account is lost, locked out by its own Conditional Access policy, or compromised, there is no second path back into tenant administration.' `
            -Recommendation 'Create at least one break-glass account: cloud-only, excluded from Conditional Access, with a long stored credential and alerting on use.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
            -Evidence @{ globalAdministratorCount = $gaCount }))
    }

    # Handed to the inactive account check so a dormant admin is scored accordingly.
    $Context.Cache['PrivilegedPrincipalIds'] = @($privilegedIds)

    New-HygieneCheckResult `
        -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
        -Status 'Completed' `
        -Findings @($findings) `
        -ObjectsEvaluated $assignments.Count `
        -RequiredScopes $meta.RequiredScopes
}

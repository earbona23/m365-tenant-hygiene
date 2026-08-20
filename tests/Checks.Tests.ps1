#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Each check executed against a simulated Microsoft Graph.

    The Graph gateway is mocked and answers by URI, so the check logic runs for real --
    the severity decisions, the classification tables, and above all the paths that are
    supposed to refuse to conclude anything. Those refusal paths are the ones worth
    testing: a check that reports "clean" when it could not see the data is the single
    most expensive bug an audit tool can have, and it is invisible in production
    precisely because it looks like good news.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'M365TenantHygiene' 'M365TenantHygiene.psd1') -Force
}

Describe 'MFA registration check' {

    It 'grades an administrator without MFA above an ordinary user, and a guest below' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                @(
                    [pscustomobject]@{ id = 'u1'; userPrincipalName = 'admin@c.example'; userDisplayName = 'Admin'
                                       userType = 'Member'; isAdmin = $true;  isMfaRegistered = $false; isMfaCapable = $false; methodsRegistered = @() }
                    [pscustomobject]@{ id = 'u2'; userPrincipalName = 'staff@c.example'; userDisplayName = 'Staff'
                                       userType = 'Member'; isAdmin = $false; isMfaRegistered = $true;  isMfaCapable = $false; methodsRegistered = @('mobilePhone') }
                    [pscustomobject]@{ id = 'u3'; userPrincipalName = 'guest@c.example'; userDisplayName = 'Guest'
                                       userType = 'Guest';  isAdmin = $false; isMfaRegistered = $false; isMfaCapable = $false; methodsRegistered = @() }
                    [pscustomobject]@{ id = 'u4'; userPrincipalName = 'safe@c.example';  userDisplayName = 'Safe'
                                       userType = 'Member'; isAdmin = $false; isMfaRegistered = $true;  isMfaCapable = $true;  methodsRegistered = @('microsoftAuthenticatorPush') }
                )
            }

            $result = Test-HygieneMfaRegistration -Context (New-HygieneAuditContext)

            $result.Status           | Should -Be 'Completed'
            $result.ObjectsEvaluated | Should -Be 4
            $result.FindingCount     | Should -Be 3

            ($result.Findings | Where-Object ObjectName -eq 'admin@c.example').Severity | Should -Be 'Critical'
            ($result.Findings | Where-Object ObjectName -eq 'staff@c.example').Severity | Should -Be 'High'
            ($result.Findings | Where-Object ObjectName -eq 'guest@c.example').Severity | Should -Be 'Medium'
            ($result.Findings | Where-Object ObjectName -eq 'safe@c.example')            | Should -BeNullOrEmpty
        }
    }

    It 'distinguishes "registered but unusable" from "never registered"' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                @([pscustomobject]@{ id = 'u2'; userPrincipalName = 'staff@c.example'; userDisplayName = 'Staff'
                                     userType = 'Member'; isAdmin = $false; isMfaRegistered = $true; isMfaCapable = $false; methodsRegistered = @('mobilePhone') })
            }

            $finding = (Test-HygieneMfaRegistration -Context (New-HygieneAuditContext)).Findings[0]
            $finding.Detail | Should -Match 'registered method, but none'
            $finding.Evidence.isMfaRegistered | Should -BeTrue
            $finding.Evidence.isMfaCapable    | Should -BeFalse
        }
    }
}

Describe 'Inactive account check' {

    It 'refuses to run when Graph returned no sign-in activity at all' {
        # Without an Entra ID P1/P2 licence the property is simply absent. Treating that
        # as "nobody has signed in" would flag the entire tenant as dormant.
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                @(
                    [pscustomobject]@{ id = 'u1'; userPrincipalName = 'a@c.example'; accountEnabled = $true; userType = 'Member'
                                       createdDateTime = '2020-01-01T00:00:00Z'; assignedLicenses = @(); signInActivity = $null }
                    [pscustomobject]@{ id = 'u2'; userPrincipalName = 'b@c.example'; accountEnabled = $true; userType = 'Member'
                                       createdDateTime = '2020-01-01T00:00:00Z'; assignedLicenses = @(); signInActivity = $null }
                )
            }

            $result = Test-HygieneInactiveAccount -Context (New-HygieneAuditContext)

            $result.Status       | Should -Be 'Skipped'
            $result.FindingCount | Should -Be 0
            $result.Reason       | Should -Match 'P1 or P2'
        }
    }

    It 'flags a dormant account but leaves a recently active one alone' {
        InModuleScope M365TenantHygiene {
            $recent = [datetime]::UtcNow.AddDays(-3).ToString('o')
            $old    = [datetime]::UtcNow.AddDays(-214).ToString('o')

            Mock Invoke-HygieneGraphRequest {
                @(
                    [pscustomobject]@{ id = 'u1'; userPrincipalName = 'dormant@c.example'; accountEnabled = $true; userType = 'Member'
                                       createdDateTime = '2020-01-01T00:00:00Z'; assignedLicenses = @(@{ skuId = 's1' })
                                       signInActivity = [pscustomobject]@{ lastSuccessfulSignInDateTime = $old } }
                    [pscustomobject]@{ id = 'u2'; userPrincipalName = 'active@c.example'; accountEnabled = $true; userType = 'Member'
                                       createdDateTime = '2020-01-01T00:00:00Z'; assignedLicenses = @()
                                       signInActivity = [pscustomobject]@{ lastSuccessfulSignInDateTime = $recent } }
                    [pscustomobject]@{ id = 'u3'; userPrincipalName = 'disabled@c.example'; accountEnabled = $false; userType = 'Member'
                                       createdDateTime = '2020-01-01T00:00:00Z'; assignedLicenses = @()
                                       signInActivity = [pscustomobject]@{ lastSuccessfulSignInDateTime = $old } }
                )
            }

            $result = Test-HygieneInactiveAccount -Context (New-HygieneAuditContext)

            $result.Status       | Should -Be 'Completed'
            $result.FindingCount | Should -Be 1
            $result.Findings[0].ObjectName        | Should -Be 'dormant@c.example'
            $result.Findings[0].Severity          | Should -Be 'Medium'
            $result.Findings[0].Evidence.daysIdle | Should -BeGreaterThan 200
        }
    }

    It 'does not call a newly created account dormant for never having signed in' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                @(
                    [pscustomobject]@{ id = 'new'; userPrincipalName = 'new@c.example'; accountEnabled = $true; userType = 'Member'
                                       createdDateTime = [datetime]::UtcNow.AddDays(-5).ToString('o'); assignedLicenses = @()
                                       signInActivity = $null }
                    [pscustomobject]@{ id = 'ref'; userPrincipalName = 'ref@c.example'; accountEnabled = $true; userType = 'Member'
                                       createdDateTime = '2020-01-01T00:00:00Z'; assignedLicenses = @()
                                       signInActivity = [pscustomobject]@{ lastSuccessfulSignInDateTime = [datetime]::UtcNow.AddDays(-1).ToString('o') } }
                )
            }

            (Test-HygieneInactiveAccount -Context (New-HygieneAuditContext)).FindingCount | Should -Be 0
        }
    }

    It 'raises the severity of a dormant account that holds a privileged role' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                @([pscustomobject]@{ id = 'admin1'; userPrincipalName = 'sleepy.admin@c.example'; accountEnabled = $true; userType = 'Member'
                                     createdDateTime = '2020-01-01T00:00:00Z'; assignedLicenses = @()
                                     signInActivity = [pscustomobject]@{ lastSuccessfulSignInDateTime = [datetime]::UtcNow.AddDays(-300).ToString('o') } })
            }

            $context = New-HygieneAuditContext
            $context.Cache['PrivilegedPrincipalIds'] = @('admin1')

            $result = Test-HygieneInactiveAccount -Context $context
            $result.Findings[0].Severity            | Should -Be 'High'
            $result.Findings[0].Evidence.privileged | Should -BeTrue
        }
    }
}

Describe 'Privileged role check' {

    BeforeAll {
        $script:RoleMock = {
            param($Uri)
            if ($Uri -match 'roleDefinitions') {
                return @(
                    [pscustomobject]@{ id = 'r-ga'; displayName = 'Global Administrator'; isBuiltIn = $true }
                    [pscustomobject]@{ id = 'r-ex'; displayName = 'Exchange Administrator'; isBuiltIn = $true }
                    [pscustomobject]@{ id = 'r-rp'; displayName = 'Reports Reader'; isBuiltIn = $true }
                )
            }
            return @(
                [pscustomobject]@{ id = 'a1'; principalId = 'p-guest'; roleDefinitionId = 'r-ga'; directoryScopeId = '/'
                                   principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'p-guest'
                                                                  displayName = 'External Consultant'; userPrincipalName = 'ext#EXT#@c.example'
                                                                  userType = 'Guest'; accountEnabled = $true } }
                [pscustomobject]@{ id = 'a2'; principalId = 'p-ok'; roleDefinitionId = 'r-ga'; directoryScopeId = '/'
                                   principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'p-ok'
                                                                  displayName = 'Break Glass'; userPrincipalName = 'bg@c.example'
                                                                  userType = 'Member'; accountEnabled = $true } }
                [pscustomobject]@{ id = 'a3'; principalId = 'p-off'; roleDefinitionId = 'r-ex'; directoryScopeId = '/'
                                   principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'p-off'
                                                                  displayName = 'Left Company'; userPrincipalName = 'gone@c.example'
                                                                  userType = 'Member'; accountEnabled = $false } }
                [pscustomobject]@{ id = 'a4'; principalId = 'p-sp'; roleDefinitionId = 'r-ga'; directoryScopeId = '/'
                                   principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'p-sp'
                                                                  displayName = 'Automation Runner'; appId = 'app-1' } }
                [pscustomobject]@{ id = 'a5'; principalId = 'p-noise'; roleDefinitionId = 'r-rp'; directoryScopeId = '/'
                                   principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'p-noise'
                                                                  displayName = 'Analyst'; userPrincipalName = 'an@c.example'
                                                                  userType = 'Member'; accountEnabled = $true } }
            )
        }
    }

    It 'classifies each risky assignment and ignores unprivileged roles' {
        InModuleScope M365TenantHygiene -Parameters @{ RoleMock = $script:RoleMock } {
            param($RoleMock)
            Mock Invoke-HygieneGraphRequest $RoleMock

            $result = Test-HygienePrivilegedRole -Context (New-HygieneAuditContext)
            $result.Status | Should -Be 'Completed'

            ($result.Findings | Where-Object ObjectName -eq 'ext#EXT#@c.example').Severity | Should -Be 'Critical'
            ($result.Findings | Where-Object ObjectName -eq 'gone@c.example').Severity     | Should -Be 'Medium'
            ($result.Findings | Where-Object ObjectName -eq 'Automation Runner').Severity  | Should -Be 'High'

            # Reports Reader is not a privileged role and must not appear at all.
            ($result.Findings | Where-Object ObjectName -eq 'an@c.example') | Should -BeNullOrEmpty

            # A healthy tier-0 assignment is still inventoried.
            ($result.Findings | Where-Object ObjectName -eq 'bg@c.example').Severity | Should -Be 'Informational'
        }
    }

    It 'hands the privileged principal set to the rest of the audit' {
        InModuleScope M365TenantHygiene -Parameters @{ RoleMock = $script:RoleMock } {
            param($RoleMock)
            Mock Invoke-HygieneGraphRequest $RoleMock

            $context = New-HygieneAuditContext
            $null = Test-HygienePrivilegedRole -Context $context

            $context.Cache['PrivilegedPrincipalIds'] | Should -Contain 'p-guest'
            $context.Cache['PrivilegedPrincipalIds'] | Should -Not -Contain 'p-noise'
        }
    }

    It 'warns when a single Global Administrator leaves no way back in' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                param($Uri)
                if ($Uri -match 'roleDefinitions') {
                    return @([pscustomobject]@{ id = 'r-ga'; displayName = 'Global Administrator'; isBuiltIn = $true })
                }
                return @([pscustomobject]@{ id = 'a1'; principalId = 'p1'; roleDefinitionId = 'r-ga'; directoryScopeId = '/'
                                            principal = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'p1'
                                                                           displayName = 'Only Admin'; userPrincipalName = 'only@c.example'
                                                                           userType = 'Member'; accountEnabled = $true } })
            }

            $result = Test-HygienePrivilegedRole -Context (New-HygieneAuditContext)
            ($result.Findings | Where-Object { $_.Title -match 'Only one principal' }).Severity | Should -Be 'Medium'
        }
    }
}

Describe 'Risky application check' {

    It 'resolves permission GUIDs to names and grades escalation above bulk data access' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                param($Uri)
                if ($Uri -match '^servicePrincipals\?') {
                    return @(
                        [pscustomobject]@{ id = 'sp-bad';  appId = 'a1'; displayName = 'Legacy Connector'; accountEnabled = $true;  appOwnerOrganizationId = 'other-tenant' }
                        [pscustomobject]@{ id = 'sp-mail'; appId = 'a2'; displayName = 'Invoice Archiver'; accountEnabled = $true;  appOwnerOrganizationId = 'tenant-1' }
                        [pscustomobject]@{ id = 'sp-ok';   appId = 'a3'; displayName = 'Harmless App';     accountEnabled = $true;  appOwnerOrganizationId = 'tenant-1' }
                    )
                }
                if ($Uri -match 'appRoleAssignedTo') {
                    return @(
                        [pscustomobject]@{ principalId = 'sp-bad';  principalDisplayName = 'Legacy Connector'; appRoleId = 'role-dirw' }
                        [pscustomobject]@{ principalId = 'sp-mail'; principalDisplayName = 'Invoice Archiver'; appRoleId = 'role-mailrw' }
                        [pscustomobject]@{ principalId = 'sp-ok';   principalDisplayName = 'Harmless App';     appRoleId = 'role-userread' }
                    )
                }
                if ($Uri -match 'oauth2PermissionGrants') { return @() }
                # The Microsoft Graph service principal, with its app role catalogue.
                return @([pscustomobject]@{
                    id = 'graph-sp'; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph'
                    appRoles = @(
                        [pscustomobject]@{ id = 'role-dirw';     value = 'Directory.ReadWrite.All' }
                        [pscustomobject]@{ id = 'role-mailrw';   value = 'Mail.ReadWrite' }
                        [pscustomobject]@{ id = 'role-userread'; value = 'User.Read.All' }
                    )
                })
            }

            $context = New-HygieneAuditContext
            $context.Tenant = [pscustomobject]@{ Id = 'tenant-1'; DisplayName = 'Contoso' }

            $result = Test-HygieneRiskyApplication -Context $context
            $result.Status | Should -Be 'Completed'

            $escalation = $result.Findings | Where-Object ObjectName -eq 'Legacy Connector'
            $escalation.Severity | Should -Be 'Critical'
            $escalation.Evidence.permissions | Should -Contain 'Directory.ReadWrite.All'
            $escalation.Detail | Should -Match 'published by another tenant'

            ($result.Findings | Where-Object ObjectName -eq 'Invoice Archiver').Severity | Should -Be 'High'

            # User.Read.All alone is broad but neither escalation nor bulk content access.
            ($result.Findings | Where-Object ObjectName -eq 'Harmless App') | Should -BeNullOrEmpty
        }
    }

    It 'flags a tenant-wide delegated grant but ignores a per-user one' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                param($Uri)
                if ($Uri -match '^servicePrincipals\?') {
                    return @(
                        [pscustomobject]@{ id = 'c1'; appId = 'a1'; displayName = 'Add-in'; accountEnabled = $true; appOwnerOrganizationId = 'tenant-1' }
                        [pscustomobject]@{ id = 'graph-sp'; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph'; accountEnabled = $true; appOwnerOrganizationId = $null }
                    )
                }
                if ($Uri -match 'appRoleAssignedTo') { return @() }
                if ($Uri -match 'oauth2PermissionGrants') {
                    return @(
                        [pscustomobject]@{ id = 'g1'; clientId = 'c1'; resourceId = 'graph-sp'; consentType = 'AllPrincipals'; scope = 'User.Read Mail.ReadWrite' }
                        [pscustomobject]@{ id = 'g2'; clientId = 'c1'; resourceId = 'graph-sp'; consentType = 'Principal'; principalId = 'u1'; scope = 'Mail.ReadWrite' }
                    )
                }
                return @([pscustomobject]@{ id = 'graph-sp'; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph'; appRoles = @() })
            }

            $context = New-HygieneAuditContext
            $context.Tenant = [pscustomobject]@{ Id = 'tenant-1'; DisplayName = 'Contoso' }

            $result = Test-HygieneRiskyApplication -Context $context
            $result.FindingCount | Should -Be 1
            $result.Findings[0].Evidence.grantType  | Should -Match 'AllPrincipals'
            $result.Findings[0].Evidence.riskyScopes | Should -Contain 'Mail.ReadWrite'
        }
    }
}

Describe 'Mail forwarding check' {

    It 'treats a covert external forward as more severe than a plain one' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                @(
                    [pscustomobject]@{ id = 'r1'; displayName = 'Backup'; isEnabled = $true; sequence = 1
                                       actions = [pscustomobject]@{ forwardTo = @(@{ emailAddress = @{ address = 'attacker@evil.example' } })
                                                                    delete = $true; markAsRead = $true } }
                    [pscustomobject]@{ id = 'r2'; displayName = 'To my other address'; isEnabled = $true; sequence = 2
                                       actions = [pscustomobject]@{ redirectTo = @(@{ emailAddress = @{ address = 'me@partner.example' } }) } }
                    [pscustomobject]@{ id = 'r3'; displayName = 'Internal handoff'; isEnabled = $true; sequence = 3
                                       actions = [pscustomobject]@{ forwardTo = @(@{ emailAddress = @{ address = 'colleague@c.example' } }) } }
                )
            }

            $context = New-HygieneAuditContext
            $context.VerifiedDomains = @('c.example')
            $context.Cache['Users'] = @(
                [pscustomobject]@{ id = 'u1'; userPrincipalName = 'victim@c.example'; accountEnabled = $true; userType = 'Member' }
            )

            $result = Test-HygieneMailForwarding -Context $context

            $result.Status       | Should -Be 'Completed'
            $result.FindingCount | Should -Be 2

            $covert = $result.Findings | Where-Object { $_.Evidence.ruleName -eq 'Backup' }
            $covert.Severity | Should -Be 'Critical'
            $covert.Evidence.concealmentActions | Should -Not -BeNullOrEmpty

            ($result.Findings | Where-Object { $_.Evidence.ruleName -eq 'To my other address' }).Severity | Should -Be 'High'
            ($result.Findings | Where-Object { $_.Evidence.ruleName -eq 'Internal handoff' }) | Should -BeNullOrEmpty
        }
    }

    It 'reports Skipped, not clean, when Graph denies every mailbox' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                $ex = [System.InvalidOperationException]::new('Access denied')
                $ex.Data['Kind'] = 'Permission'
                throw $ex
            }

            $context = New-HygieneAuditContext
            $context.VerifiedDomains = @('c.example')
            $context.Cache['Users'] = @(
                [pscustomobject]@{ id = 'u1'; userPrincipalName = 'victim@c.example'; accountEnabled = $true; userType = 'Member' }
            )

            $result = Test-HygieneMailForwarding -Context $context

            $result.Status       | Should -Be 'Skipped'
            $result.FindingCount | Should -Be 0
            $result.Reason       | Should -Match 'refused access'
        }
    }

    It 'refuses to run without the tenant verified domain list' {
        InModuleScope M365TenantHygiene {
            $result = Test-HygieneMailForwarding -Context (New-HygieneAuditContext)
            $result.Status | Should -Be 'Skipped'
            $result.Reason | Should -Match 'verified domains'
        }
    }
}

Describe 'Device compliance check' {

    It 'grades each compliance state, including the states that look like a pass' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                @(
                    [pscustomobject]@{ id = 'd1'; deviceName = 'FAILING';   complianceState = 'noncompliant';  operatingSystem = 'Windows'; lastSyncDateTime = [datetime]::UtcNow.AddDays(-1).ToString('o') }
                    [pscustomobject]@{ id = 'd2'; deviceName = 'GRACE';     complianceState = 'inGracePeriod'; operatingSystem = 'Windows'; lastSyncDateTime = [datetime]::UtcNow.AddDays(-1).ToString('o') }
                    [pscustomobject]@{ id = 'd3'; deviceName = 'UNKNOWN';   complianceState = 'unknown';       operatingSystem = 'iOS';     lastSyncDateTime = [datetime]::UtcNow.AddDays(-9).ToString('o') }
                    [pscustomobject]@{ id = 'd4'; deviceName = 'UNTARGETED'; complianceState = 'notApplicable'; operatingSystem = 'iOS';    lastSyncDateTime = [datetime]::UtcNow.AddDays(-2).ToString('o') }
                    [pscustomobject]@{ id = 'd5'; deviceName = 'STALE';     complianceState = 'compliant';     operatingSystem = 'Windows'; lastSyncDateTime = [datetime]::UtcNow.AddDays(-118).ToString('o') }
                    [pscustomobject]@{ id = 'd6'; deviceName = 'HEALTHY';   complianceState = 'compliant';     operatingSystem = 'Windows'; lastSyncDateTime = [datetime]::UtcNow.AddDays(-1).ToString('o') }
                )
            }

            $result = Test-HygieneDeviceCompliance -Context (New-HygieneAuditContext)

            $result.ObjectsEvaluated | Should -Be 6
            ($result.Findings | Where-Object ObjectName -eq 'FAILING').Severity    | Should -Be 'High'
            ($result.Findings | Where-Object ObjectName -eq 'GRACE').Severity      | Should -Be 'Medium'
            ($result.Findings | Where-Object ObjectName -eq 'UNKNOWN').Severity    | Should -Be 'Medium'
            ($result.Findings | Where-Object ObjectName -eq 'UNTARGETED').Severity | Should -Be 'Medium'
            ($result.Findings | Where-Object ObjectName -eq 'STALE').Severity      | Should -Be 'Low'
            ($result.Findings | Where-Object ObjectName -eq 'HEALTHY')             | Should -BeNullOrEmpty
        }
    }

    It 'reports Skipped, not zero non-compliant devices, when Intune is unavailable' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                $ex = [System.InvalidOperationException]::new('Resource not found')
                $ex.Data['Kind'] = 'NotFound'
                throw $ex
            }

            $result = Test-HygieneDeviceCompliance -Context (New-HygieneAuditContext)
            $result.Status | Should -Be 'Skipped'
            $result.Reason | Should -Match 'Intune'
        }
    }

    It 'surfaces an unrecognised compliance state rather than assuming it is fine' {
        InModuleScope M365TenantHygiene {
            Mock Invoke-HygieneGraphRequest {
                @([pscustomobject]@{ id = 'd9'; deviceName = 'ODD'; complianceState = 'someFutureState'; operatingSystem = 'Windows'; lastSyncDateTime = [datetime]::UtcNow.ToString('o') })
            }

            $result = Test-HygieneDeviceCompliance -Context (New-HygieneAuditContext)
            $result.FindingCount | Should -Be 1
            $result.Findings[0].Title | Should -Match 'Unrecognised compliance state'
        }
    }
}

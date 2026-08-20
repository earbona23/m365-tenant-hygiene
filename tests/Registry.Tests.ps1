#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The check registry is the module's contract: it drives which scopes are requested
    at sign-in, which functions run, and what the report claims was covered. A registry
    that has drifted from the code produces a report that describes an audit that did
    not happen.
#>

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..' 'src' 'M365TenantHygiene' 'M365TenantHygiene.psd1'
    Import-Module $script:ModulePath -Force
    $script:Module = Get-Module M365TenantHygiene
    $script:Registry = & $script:Module { Get-HygieneCheckRegistry }
}

Describe 'Check registry' {

    It 'defines the six documented checks' {
        @($script:Registry.Keys) | Should -HaveCount 6
    }

    It 'has an implementing function for <_>' -ForEach @('MfaRegistration', 'InactiveAccount', 'PrivilegedRole', 'RiskyApplication', 'MailForwarding', 'DeviceCompliance') {
        $entry = $script:Registry[$_]
        $entry | Should -Not -BeNullOrEmpty

        $exists = & $script:Module ([scriptblock]::Create("[bool](Get-Command '$($entry.Function)' -ErrorAction SilentlyContinue)"))
        $exists | Should -BeTrue -Because "the registry points at $($entry.Function)"
    }

    It 'gives every check at least one required scope, a category and a description' {
        foreach ($key in $script:Registry.Keys) {
            $entry = $script:Registry[$key]
            @($entry.RequiredScopes).Count | Should -BeGreaterThan 0 -Because "$key must declare what it needs"
            $entry.Category    | Should -Not -BeNullOrEmpty
            $entry.Description | Should -Not -BeNullOrEmpty
            $entry.Notes       | Should -Not -BeNullOrEmpty -Because "$key must state its coverage limits"
            @($entry.GraphEndpoints).Count | Should -BeGreaterThan 0
        }
    }

    It 'gives every check a distinct run order' {
        $orders = @($script:Registry.Keys | ForEach-Object { $script:Registry[$_].RunOrder })
        @($orders | Sort-Object -Unique).Count | Should -Be $orders.Count
    }

    It 'runs the privileged role check before the inactive account check' {
        # InactiveAccount raises severity using the privileged principal set that
        # PrivilegedRole caches. Reversing the order silently loses that enrichment.
        $script:Registry['PrivilegedRole'].RunOrder |
            Should -BeLessThan $script:Registry['InactiveAccount'].RunOrder
    }

    It 'exports exactly the functions the manifest advertises' {
        $manifest = Import-PowerShellDataFile -Path $script:ModulePath
        $exported = @((Get-Command -Module M365TenantHygiene).Name | Sort-Object)
        $exported | Should -Be @($manifest.FunctionsToExport | Sort-Object)
    }
}

Describe 'Least-privilege scope derivation' {

    It 'asks for fewer scopes when fewer checks are selected' {
        $all = & $script:Module { Get-HygieneRequiredScope }
        $one = & $script:Module { Get-HygieneRequiredScope -CheckId 'MfaRegistration' }

        @($one).Count | Should -BeLessThan @($all).Count
        $one | Should -Contain 'AuditLog.Read.All'
        $one | Should -Not -Contain 'DeviceManagementManagedDevices.Read.All'
    }

    It 'always includes User.Read for reading the tenant name and verified domains' {
        $scopes = & $script:Module { Get-HygieneRequiredScope -CheckId 'DeviceCompliance' }
        $scopes | Should -Contain 'User.Read'
    }

    It 'returns each scope once even when several checks need it' {
        $scopes = & $script:Module { Get-HygieneRequiredScope -CheckId @('InactiveAccount', 'MailForwarding') }
        @($scopes | Group-Object | Where-Object Count -gt 1) | Should -BeNullOrEmpty
        $scopes | Should -Contain 'User.Read.All'
    }

    It 'rejects an unknown check instead of silently ignoring it' {
        { & $script:Module { Get-HygieneRequiredScope -CheckId 'NoSuchCheck' } } | Should -Throw
    }
}

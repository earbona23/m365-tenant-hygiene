#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Findings and the judgements behind them. The external-address test matters most:
    it decides whether a forwarding rule becomes a Critical finding about a possible
    mailbox compromise, so both of its failure directions are worth pinning down.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'M365TenantHygiene' 'M365TenantHygiene.psd1') -Force
    $script:Module = Get-Module M365TenantHygiene
}

Describe 'New-HygieneFinding' {

    It 'orders severities so the worst sorts first' {
        $ranks = & $script:Module {
            'Critical', 'High', 'Medium', 'Low', 'Informational' | ForEach-Object { Get-HygieneSeverityRank -Severity $_ }
        }
        $ranks | Should -Be @(0, 1, 2, 3, 4)
    }

    It 'rejects a severity outside the defined scale' {
        { & $script:Module {
            New-HygieneFinding -CheckId 'x' -CheckName 'x' -Category 'x' -Severity 'Catastrophic' -Title 'x'
        } } | Should -Throw
    }

    It 'carries the evidence through unchanged' {
        $finding = & $script:Module {
            New-HygieneFinding -CheckId 'c' -CheckName 'n' -Category 'cat' -Severity 'High' `
                -Title 't' -Evidence @{ daysIdle = 214; licensed = $true }
        }
        $finding.Evidence.daysIdle | Should -Be 214
        $finding.Evidence.licensed | Should -BeTrue
        $finding.SeverityRank      | Should -Be 1
    }
}

Describe 'New-HygieneCheckResult' {

    It 'keeps "could not run" separate from "found nothing"' {
        $skipped = & $script:Module {
            New-HygieneCheckResult -CheckId 'c' -CheckName 'n' -Category 'cat' -Status 'Skipped' -Reason 'no licence'
        }
        $completed = & $script:Module {
            New-HygieneCheckResult -CheckId 'c' -CheckName 'n' -Category 'cat' -Status 'Completed' -ObjectsEvaluated 40
        }

        $skipped.Status       | Should -Be 'Skipped'
        $skipped.FindingCount | Should -Be 0
        $skipped.Reason       | Should -Not -BeNullOrEmpty

        $completed.Status           | Should -Be 'Completed'
        $completed.FindingCount     | Should -Be 0
        $completed.ObjectsEvaluated | Should -Be 40
    }

    It 'rejects a status outside the three defined outcomes' {
        { & $script:Module {
            New-HygieneCheckResult -CheckId 'c' -CheckName 'n' -Category 'cat' -Status 'Probably fine'
        } } | Should -Throw
    }
}

Describe 'Test-HygieneExternalAddress' {

    BeforeAll {
        $script:Domains = @('contoso.example', 'contoso.onmicrosoft.example')
    }

    It 'treats <Address> as external: <Expected>' -ForEach @(
        @{ Address = 'attacker@evil.example';            Expected = $true }
        @{ Address = 'user@contoso.example';             Expected = $false }
        @{ Address = 'USER@CONTOSO.EXAMPLE';             Expected = $false }
        @{ Address = 'user@sub.contoso.example';         Expected = $false }
        @{ Address = 'user@contoso.onmicrosoft.example'; Expected = $false }
        @{ Address = 'user@notcontoso.example';          Expected = $true }
        @{ Address = 'user@contoso.example.evil.test';   Expected = $true }
    ) {
        $domains = $script:Domains
        $result = & $script:Module ([scriptblock]::Create(
            "Test-HygieneExternalAddress -Address '$Address' -VerifiedDomain @('$($domains -join "','")')"))
        $result | Should -Be $Expected
    }

    It 'calls nothing external when the verified domain list is unavailable' {
        # Fail closed: with no list to compare against, inventing findings would be
        # worse than reporting none, and the check reports Skipped in that case.
        $result = & $script:Module { Test-HygieneExternalAddress -Address 'a@evil.example' -VerifiedDomain @() }
        $result | Should -BeFalse
    }

    It 'handles empty and malformed input without throwing' {
        $domains = $script:Domains
        foreach ($value in @('', $null, 'not-an-address')) {
            $result = & $script:Module ([scriptblock]::Create(
                "Test-HygieneExternalAddress -Address '$value' -VerifiedDomain @('$($domains -join "','")')"))
            $result | Should -BeFalse
        }
    }
}

Describe 'Retry delay' {

    It 'honours the server Retry-After header' {
        $delay = & $script:Module { Get-HygieneRetryDelay -Headers @{ 'Retry-After' = '17' } -Attempt 0 }
        $delay | Should -Be 17
    }

    It 'caps an absurd Retry-After value' {
        $delay = & $script:Module { Get-HygieneRetryDelay -Headers @{ 'Retry-After' = '99999' } -Attempt 0 }
        $delay | Should -Be 120
    }

    It 'backs off exponentially when the header is missing' {
        $first  = & $script:Module { Get-HygieneRetryDelay -Headers @{} -Attempt 0 }
        $third  = & $script:Module { Get-HygieneRetryDelay -Headers @{} -Attempt 2 }
        $third | Should -BeGreaterThan $first
    }
}

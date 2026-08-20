#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The report is what leaves the building. It gets emailed, attached to tickets and
    opened months later on machines with no network, so two properties are load-bearing:
    it must be genuinely self-contained, and it must never execute tenant-controlled
    text as markup.
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'M365TenantHygiene' 'M365TenantHygiene.psd1') -Force
    $script:Module = Get-Module M365TenantHygiene

    $script:Audit = & $script:Module {
        $findings = @(
            New-HygieneFinding -CheckId 'MfaRegistration' -CheckName 'Users without MFA' -Category 'Identity' `
                -Severity 'Critical' -Title 'Account is not capable of multi-factor authentication' `
                -ObjectType 'User' -ObjectId '11111111-1111-4111-8111-111111111111' `
                -ObjectName '<script>alert("xss")</script>@contoso.example' `
                -Detail 'Detail with <b>markup</b> & an ampersand.' `
                -Recommendation 'Do the thing.' -Reference 'https://learn.microsoft.com/entra/' `
                -Evidence @{ isAdmin = $true; methodsRegistered = @() }

            New-HygieneFinding -CheckId 'DeviceCompliance' -CheckName 'Non-compliant Intune devices' -Category 'Devices' `
                -Severity 'Low' -Title 'Compliant verdict is stale' `
                -ObjectType 'Device' -ObjectId 'd1' -ObjectName 'LAPTOP-01' `
                -Detail 'Stale.' -Evidence @{ daysSinceSync = 118 }
        )

        $checks = @(
            New-HygieneCheckResult -CheckId 'MfaRegistration' -CheckName 'Users without MFA' -Category 'Identity' `
                -Status 'Completed' -Findings @($findings[0]) -ObjectsEvaluated 10
            New-HygieneCheckResult -CheckId 'DeviceCompliance' -CheckName 'Non-compliant Intune devices' -Category 'Devices' `
                -Status 'Completed' -Findings @($findings[1]) -ObjectsEvaluated 5
            New-HygieneCheckResult -CheckId 'MailForwarding' -CheckName 'Inbox rules forwarding outside the tenant' -Category 'Exchange Online' `
                -Status 'Skipped' -Reason 'Graph denied access to every mailbox tried.'
        )

        [pscustomobject]@{
            PSTypeName      = 'M365TenantHygiene.AuditResult'
            Tenant          = [pscustomobject]@{ Id = 'tenant-id'; DisplayName = 'Contoso Example Ltd' }
            VerifiedDomains = @('contoso.example')
            Account         = 'reader@contoso.example'
            Environment     = 'Global'
            StartedAt       = [datetime]::new(2026, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            CompletedAt     = [datetime]::new(2026, 1, 1, 0, 0, 30, [DateTimeKind]::Utc)
            Duration        = [timespan]::FromSeconds(30)
            ModuleVersion   = '1.0.0'
            Parameters      = [ordered]@{ InactiveDays = 90; GlobalAdminThreshold = 4; MaxMailbox = 0; MaxPages = 200 }
            Checks          = $checks
            Findings        = $findings
            Summary         = (New-HygieneSummary -CheckResult $checks -Finding $findings)
        }
    }

    $script:Html = & $script:Module ([scriptblock]::Create('ConvertTo-HygieneHtmlReport -Audit $args[0]')) $script:Audit
}

Describe 'HTML report' {

    It 'produces a complete HTML document' {
        $script:Html | Should -Match '(?i)^\s*<!DOCTYPE html>'
        $script:Html | Should -Match '(?i)</html>\s*$'
    }

    It 'loads nothing from the network' -ForEach @(
        @{ Pattern = '(?i)<script[^>]+src\s*='         ; What = 'an external script' }
        @{ Pattern = '(?i)<link[^>]+stylesheet'        ; What = 'an external stylesheet' }
        @{ Pattern = '(?i)<img[^>]+src\s*='            ; What = 'a remote image' }
        @{ Pattern = '(?i)@import'                     ; What = 'an imported stylesheet' }
        @{ Pattern = '(?i)url\(\s*[''"]?https?:'       ; What = 'a remote CSS asset' }
    ) {
        # Hyperlinks to Microsoft documentation are fine: they are navigation, not
        # resources the page needs in order to render.
        $script:Html | Should -Not -Match $Pattern -Because "the report must not need $What to display"
    }

    It 'escapes tenant-controlled text instead of rendering it as markup' {
        # Display names are attacker-controllable. A user named "<script>" must appear
        # as text in the report, not run in the auditor's browser.
        $script:Html | Should -Not -Match '<script>alert'
        $script:Html | Should -Match '&lt;script&gt;alert'
        $script:Html | Should -Match 'Detail with &lt;b&gt;markup&lt;/b&gt; &amp; an ampersand'
    }

    It 'states that the audit was incomplete before listing findings' {
        $script:Html | Should -Match 'This audit is incomplete'
        $script:Html | Should -Match 'Graph denied access to every mailbox tried'

        $noticeIndex  = $script:Html.IndexOf('This audit is incomplete')
        $findingIndex = $script:Html.IndexOf('<h2>Findings</h2>')
        $noticeIndex | Should -BeLessThan $findingIndex -Because 'coverage gaps must be read before the findings are believed'
    }

    It 'shows the severity counts' {
        $script:Html | Should -Match 'Critical'
        $script:Html | Should -Match 'sev-critical'
        $script:Audit.Summary.BySeverity['Critical'] | Should -Be 1
        $script:Audit.Summary.ChecksSkipped          | Should -Be 1
        $script:Audit.Summary.ChecksCompleted        | Should -Be 2
    }

    It 'renders the evidence for each finding' {
        $script:Html | Should -Match 'isAdmin'
        $script:Html | Should -Match 'daysSinceSync'
    }
}

Describe 'Export-M365HygieneReport' {

    BeforeAll {
        $script:OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("hygiene-tests-" + [guid]::NewGuid().ToString('N'))
    }

    AfterAll {
        if (Test-Path -LiteralPath $script:OutDir) {
            Remove-Item -LiteralPath $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'writes the HTML report and both CSV exports' {
        $files = Export-M365HygieneReport -Audit $script:Audit -Path $script:OutDir -Prefix 'test' -PassThru

        @($files).Count | Should -Be 3
        (Join-Path $script:OutDir 'test-report.html')  | Should -Exist
        (Join-Path $script:OutDir 'test-findings.csv') | Should -Exist
        (Join-Path $script:OutDir 'test-checks.csv')   | Should -Exist
    }

    It 'writes one CSV row per finding' {
        $rows = Import-Csv -LiteralPath (Join-Path $script:OutDir 'test-findings.csv')
        @($rows).Count | Should -Be 2
        $rows[0].Severity | Should -Not -BeNullOrEmpty
        $rows[0].Evidence | Should -Not -BeNullOrEmpty
    }

    It 'carries the skipped check into the coverage CSV' {
        # The reason a check did not run must survive the export, or a spreadsheet of
        # findings reads as a complete audit.
        $rows = Import-Csv -LiteralPath (Join-Path $script:OutDir 'test-checks.csv')
        $skipped = @($rows | Where-Object { $_.Status -eq 'Skipped' })

        @($skipped).Count  | Should -Be 1
        $skipped[0].Reason | Should -Match 'denied access'
    }

    It 'rejects an object that is not an audit result' {
        { Export-M365HygieneReport -Audit ([pscustomobject]@{ Nope = 1 }) -Path $script:OutDir } | Should -Throw
    }
}

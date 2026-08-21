#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The Pro license layer. Verified with an EPHEMERAL ECDSA keypair injected as the public
    key, so the real signing key is never needed to test the mechanism. Plus the SARIF
    export and the Pro gate on Export-M365HygieneReport.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'M365TenantHygiene'
    Import-Module (Join-Path $script:SourceRoot 'M365TenantHygiene.psd1') -Force
    $script:Module = Get-Module M365TenantHygiene

    # An ephemeral P-256 keypair for signing test licenses.
    $script:Ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $script:PubSpki = [Convert]::ToBase64String($script:Ecdsa.ExportSubjectPublicKeyInfo())

    function script:Mint([hashtable]$Payload) {
        $json = ($Payload | ConvertTo-Json -Compress)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $sig = $script:Ecdsa.SignData($bytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        function b64u([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }
        return "M365HYGIENE-$(b64u $bytes).$(b64u $sig)"
    }
}

Describe 'License verification (offline, ECDSA P-256)' {

    It 'accepts a properly signed key' {
        $key = script:Mint @{ sub = 'Acme'; plan = 'team'; iat = 1000 }
        $r = & $script:Module { param($k, $pub) Test-HygieneLicenseKey -Key $k -PublicKeySpki $pub -NowUnix 2000 } $key $script:PubSpki
        $r.Valid | Should -BeTrue
        $r.Payload.plan | Should -Be 'team'
    }

    It 'rejects an expired key' {
        $key = script:Mint @{ sub = 'Acme'; plan = 'pro'; iat = 1000; exp = 1500 }
        $r = & $script:Module { param($k, $pub) Test-HygieneLicenseKey -Key $k -PublicKeySpki $pub -NowUnix 2000 } $key $script:PubSpki
        $r.Valid | Should -BeFalse
        $r.Reason | Should -Match 'expired'
    }

    It 'rejects a key signed by a different key' {
        $other = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $json = (@{ sub = 'x'; plan = 'team'; iat = 1 } | ConvertTo-Json -Compress)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $sig = $other.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        function b64u([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }
        $key = "M365HYGIENE-$(b64u $bytes).$(b64u $sig)"
        $r = & $script:Module { param($k, $pub) Test-HygieneLicenseKey -Key $k -PublicKeySpki $pub } $key $script:PubSpki
        $r.Valid | Should -BeFalse
    }

    It 'rejects junk and non-M365 keys cleanly' {
        foreach ($junk in @('', 'nope', 'M365HYGIENE-bad', 'CERTADEL-a.b')) {
            $r = & $script:Module { param($k, $pub) Test-HygieneLicenseKey -Key $k -PublicKeySpki $pub } $junk $script:PubSpki
            $r.Valid | Should -BeFalse
            $r.Reason | Should -Not -BeNullOrEmpty
        }
    }

    It 'the embedded default public key rejects an ephemeral key' {
        $key = script:Mint @{ sub = 'x'; plan = 'pro'; iat = 1 }
        $r = & $script:Module { param($k) Test-HygieneLicenseKey -Key $k } $key
        $r.Valid | Should -BeFalse -Because 'the ephemeral key is not the real signing key'
    }
}

Describe 'Pro gating and SARIF export' {

    It 'the SARIF converter emits a result per finding with the check id as rule' {
        $sarif = & $script:Module {
            $finding = New-HygieneFinding -CheckId 'mfa' -CheckName 'Users without MFA' -Category 'Identity' `
                -Severity 'Critical' -Title 'No MFA' -ObjectType 'User' -ObjectId 'u1' -ObjectName 'a@x' -Detail 'no mfa'
            $check = New-HygieneCheckResult -CheckId 'mfa' -CheckName 'Users without MFA' -Category 'Identity' `
                -Status 'Completed' -Findings @($finding) -ObjectsEvaluated 1
            $audit = [pscustomobject]@{ Findings = @($finding); Checks = @($check) }
            ConvertTo-HygieneSarif -Audit $audit
        }
        $doc = $sarif | ConvertFrom-Json
        $doc.version | Should -Be '2.1.0'
        $doc.runs[0].tool.driver.name | Should -Be 'M365TenantHygiene'
        @($doc.runs[0].results).Count | Should -Be 1
        $doc.runs[0].results[0].ruleId | Should -Be 'mfa'
        $doc.runs[0].results[0].level | Should -Be 'error'
    }

    It 'Export -Format Sarif is refused on the free tier (warns, writes nothing)' {
        $env:M365HYGIENE_CONFIG_DIR = Join-Path ([System.IO.Path]::GetTempPath()) ("m365-nolic-" + [guid]::NewGuid())
        $env:M365HYGIENE_LICENSE_KEY = $null
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("m365-sarif-" + [guid]::NewGuid())
        $audit = & $script:Module {
            $f = New-HygieneFinding -CheckId 'c' -CheckName 'n' -Category 'Identity' -Severity 'High' -Title 't' -ObjectName 'o'
            $c = New-HygieneCheckResult -CheckId 'c' -CheckName 'n' -Category 'Identity' -Status 'Completed' -Findings @($f)
            [pscustomobject]@{
                PSTypeName = 'M365TenantHygiene.AuditResult'
                Findings = @($f); Checks = @($c)
                CompletedAt = [datetime]::UtcNow
            }
        }
        $files = Export-M365HygieneReport -Audit $audit -Path $out -Prefix 'x' -Format Sarif -PassThru -WarningAction SilentlyContinue
        (Test-Path (Join-Path $out 'x.sarif')) | Should -BeFalse -Because 'no Pro license was active'
    }
}

#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    The read-only guarantee, enforced instead of promised.

    A README that says "this tool never writes" is worth nothing on its own; the next
    contributor adds a convenient Remove-MgUser and the sentence is quietly false.
    These tests fail the build if the module ever grows a way to write, so the claim
    in the README stays true by construction.
#>

BeforeAll {
    $script:SourceRoot = Join-Path $PSScriptRoot '..' 'src' 'M365TenantHygiene'
    $script:GatewayFile = 'Invoke-HygieneGraphRequest.ps1'

    $script:SourceFiles = @(
        Get-ChildItem -Path $script:SourceRoot -Recurse -Include '*.ps1', '*.psm1' -File
    )
}

Describe 'Read-only enforcement' {

    It 'ships source files to inspect' {
        $script:SourceFiles.Count | Should -BeGreaterThan 10
    }

    It 'issues Graph requests from exactly one place' {
        # Every check funnels through the gateway. More than one call site means some
        # code path can set its own HTTP verb.
        $callSites = @(
            $script:SourceFiles |
                Select-String -Pattern '\bInvoke-MgGraphRequest\b' -SimpleMatch:$false |
                Where-Object { $_.Line -notmatch '^\s*#' }
        )

        $callSites.Count | Should -Be 1 -Because 'all Graph traffic must pass through the single read-only gateway'
        ([System.IO.Path]::GetFileName($callSites[0].Path)) | Should -Be $script:GatewayFile
    }

    It 'hardcodes the HTTP verb to GET at that call site' {
        $gateway = Get-Content -Raw -LiteralPath (Join-Path $script:SourceRoot 'Private' $script:GatewayFile)
        $gateway | Should -Match "Method\s*=\s*'GET'"
    }

    It 'does not expose a way for a caller to choose the HTTP verb' {
        $gateway = Get-Content -Raw -LiteralPath (Join-Path $script:SourceRoot 'Private' $script:GatewayFile)

        $ast = [System.Management.Automation.Language.Parser]::ParseInput($gateway, [ref]$null, [ref]$null)
        $function = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Invoke-HygieneGraphRequest'
        }, $true) | Select-Object -First 1

        $function | Should -Not -BeNullOrEmpty

        $parameterNames = @($function.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $parameterNames | Should -Not -Contain 'Method'
        $parameterNames | Should -Not -Contain 'Body'
    }

    It 'contains no write verb against Microsoft Graph' -ForEach @(
        @{ Pattern = "-Method\s+['`"]?(POST|PATCH|PUT|DELETE)"; What = 'an explicit write HTTP method' }
        @{ Pattern = '\b(New|Set|Remove|Update|Add|Revoke|Reset|Disable|Enable)-Mg\w+'; What = 'a Microsoft Graph write cmdlet' }
        @{ Pattern = '\bInvoke-RestMethod\b';  What = 'a raw HTTP client that bypasses the gateway' }
        @{ Pattern = '\bInvoke-WebRequest\b';  What = 'a raw HTTP client that bypasses the gateway' }
    ) {
        $hits = @(
            $script:SourceFiles |
                Select-String -Pattern $Pattern |
                Where-Object { $_.Line -notmatch '^\s*#' -and $_.Line -notmatch '^\s*<#' }
        )

        $detail = ($hits | ForEach-Object { "$([System.IO.Path]::GetFileName($_.Path)):$($_.LineNumber)" }) -join ', '
        $hits.Count | Should -Be 0 -Because "the module must not contain $What (found at: $detail)"
    }

    It 'requests only read scopes' {
        Import-Module (Join-Path $script:SourceRoot 'M365TenantHygiene.psd1') -Force

        $scopes = @(Get-M365HygieneCheck | ForEach-Object { $_.RequiredScopes } | Sort-Object -Unique)
        $scopes.Count | Should -BeGreaterThan 0

        foreach ($scope in $scopes) {
            $scope | Should -Match '\.Read(\.|$)|^User\.Read$' -Because "'$scope' must be a read scope"
            $scope | Should -Not -Match 'ReadWrite|\.Write|\.All\.Write'
        }
    }
}

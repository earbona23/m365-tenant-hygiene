@{
    RootModule        = 'M365TenantHygiene.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '3f5b1e2c-9a47-4d38-8c61-7b0d2e4f9a15'

    Author            = 'Eduard Arbona'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2026 Eduard Arbona. Released under the MIT licence.'

    Description       = 'Read-only Microsoft 365 tenant security hygiene auditing over Microsoft Graph. Checks MFA registration, inactive accounts, privileged role assignments, high-risk application permissions, external mail forwarding rules and Intune device compliance, then renders a self-contained HTML report with CSV exports. Performs no write operations.'

    PowerShellVersion = '7.2'

    # The Microsoft Graph authentication module is the only dependency. The full
    # Microsoft.Graph meta-module is deliberately not required: every call in this
    # module goes through Invoke-MgGraphRequest, so pulling in dozens of generated
    # sub-modules would add install weight and attack surface for no benefit.
    RequiredModules   = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
    )

    FunctionsToExport = @(
        'Connect-M365Hygiene'
        'Disconnect-M365Hygiene'
        'Enable-M365HygienePro'
        'Export-M365HygieneReport'
        'Get-M365HygieneLicense'
        'Get-M365HygieneCheck'
        'Invoke-M365HygieneAudit'
        'Test-M365HygienePermission'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Microsoft365', 'MicrosoftGraph', 'Security', 'Audit', 'Entra', 'Intune', 'ReadOnly', 'Compliance', 'MFA', 'PSEdition_Core')
            LicenseUri   = 'https://github.com/earbona23/m365-tenant-hygiene/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/earbona23/m365-tenant-hygiene'
            ReleaseNotes = 'https://github.com/earbona23/m365-tenant-hygiene/blob/main/CHANGELOG.md'
        }
    }
}

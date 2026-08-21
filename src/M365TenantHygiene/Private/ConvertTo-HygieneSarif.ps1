<#
.SYNOPSIS
    Renders an audit as a SARIF 2.1.0 document (a Pro output).

.DESCRIPTION
    Turns each finding into a SARIF result so an M365TenantHygiene audit drops straight
    into GitHub code-scanning, Azure DevOps, or any SARIF-aware SIEM. The rule id is the
    check id, and the affected object (a user, a role, an app) becomes the result's logical
    location, so findings group and trend the way a security team expects.

.PARAMETER Audit
    The object from Invoke-M365HygieneAudit.

.OUTPUTS
    The SARIF document as a JSON string.
#>
function ConvertTo-HygieneSarif {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Audit)

    $levelFor = @{
        Critical = 'error'; High = 'error'; Medium = 'warning'; Low = 'note'; Informational = 'note'
    }

    $rules = [ordered]@{}
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($finding in $Audit.Findings) {
        if (-not $rules.Contains($finding.CheckId)) {
            $rules[$finding.CheckId] = [ordered]@{
                id = $finding.CheckId
                name = ($finding.CheckName -replace '[^A-Za-z0-9]', '')
                shortDescription = @{ text = $finding.CheckName }
                fullDescription = @{ text = if ($finding.Recommendation) { $finding.Recommendation } else { $finding.CheckName } }
                helpUri = if ($finding.Reference) { $finding.Reference } else { 'https://github.com/earbona23/m365-tenant-hygiene#readme' }
                defaultConfiguration = @{ level = $levelFor[$finding.Severity] }
                properties = @{ category = $finding.Category }
            }
        }

        $results.Add([ordered]@{
            ruleId = $finding.CheckId
            level = $levelFor[$finding.Severity]
            message = @{ text = "$($finding.ObjectName): $($finding.Detail)$(if ($finding.Recommendation) { " -- $($finding.Recommendation)" })" }
            locations = @(@{
                logicalLocations = @(@{
                    name = $finding.ObjectName
                    fullyQualifiedName = "$($finding.ObjectType)/$($finding.ObjectId)"
                    kind = $finding.ObjectType
                })
            })
            properties = @{
                severity = $finding.Severity
                category = $finding.Category
                objectType = $finding.ObjectType
                objectId = $finding.ObjectId
            }
        })
    }

    $moduleVersion = try { (Get-Module M365TenantHygiene).Version.ToString() } catch { '1.0.0' }

    $doc = [ordered]@{
        '$schema' = 'https://json.schemastore.org/sarif-2.1.0.json'
        version = '2.1.0'
        runs = @(@{
            tool = @{
                driver = [ordered]@{
                    name = 'M365TenantHygiene'
                    informationUri = 'https://github.com/earbona23/m365-tenant-hygiene'
                    version = $moduleVersion
                    rules = @($rules.Values)
                }
            }
            results = @($results)
        })
    }

    return ($doc | ConvertTo-Json -Depth 12)
}

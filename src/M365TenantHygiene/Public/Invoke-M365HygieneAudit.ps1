<#
.SYNOPSIS
    Runs the hygiene checks against the connected tenant and returns the result.

.DESCRIPTION
    Executes each selected check, collects the findings, and returns one audit object
    that Export-M365HygieneReport turns into HTML and CSV.

    The audit object separates what was found from what was looked at. A check that
    could not run -- missing permission, missing licence, mailbox access denied -- is
    recorded as Skipped with the reason attached, never folded in with the checks that
    ran and found nothing. That distinction is the difference between "your tenant is
    clean" and "this tool did not look", and a report that blurs it is worse than no
    report at all.

    Nothing here writes to the tenant. All Graph traffic goes through a gateway with
    the HTTP verb hardcoded to GET.

.PARAMETER CheckId
    Run only these checks. Omit to run all of them. Use Get-M365HygieneCheck to list them.

.PARAMETER InactiveDays
    How many days without an interactive sign-in makes an enabled account inactive.

.PARAMETER GlobalAdminThreshold
    Number of permanent Global Administrators above which a finding is raised.
    Microsoft's guidance is a small number of permanent holders; the default is 4.

.PARAMETER MaxMailbox
    Cap on how many mailboxes the forwarding check examines. Any mailbox skipped by
    this cap is reported in the check's Reason, never silently dropped.

.PARAMETER MaxPages
    Cap on Graph result pages per request, as a safety valve on very large tenants.
    Truncation is reported, not hidden.

.EXAMPLE
    $audit = Invoke-M365HygieneAudit
    $audit.Summary

.EXAMPLE
    $audit = Invoke-M365HygieneAudit -CheckId MfaRegistration, PrivilegedRole -InactiveDays 60
    $audit.Findings | Where-Object Severity -eq 'Critical'

.EXAMPLE
    Invoke-M365HygieneAudit | Export-M365HygieneReport -Path ./reports

.OUTPUTS
    M365TenantHygiene.AuditResult
#>
function Invoke-M365HygieneAudit {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string[]] $CheckId,

        [ValidateRange(1, 3650)]
        [int] $InactiveDays = 90,

        [ValidateRange(1, 100)]
        [int] $GlobalAdminThreshold = 4,

        [ValidateRange(0, 100000)]
        [int] $MaxMailbox = 0,

        [ValidateRange(1, 10000)]
        [int] $MaxPages = 200
    )

    $graphContext = Get-MgContext
    if (-not $graphContext) {
        throw 'Not connected to Microsoft Graph. Run Connect-M365Hygiene first.'
    }

    $registry = Get-HygieneCheckRegistry
    $selected = if ($CheckId) { $CheckId } else { @($registry.Keys) }

    foreach ($id in $selected) {
        if (-not $registry.Contains($id)) {
            throw "Unknown check '$id'. Run Get-M365HygieneCheck to list the available checks."
        }
    }

    # RunOrder is not cosmetic: PrivilegedRole populates the cache that lets the
    # inactive account check raise the severity of a dormant administrator.
    $ordered = @($selected | Sort-Object { $registry[$_].RunOrder })

    $context = New-HygieneAuditContext `
        -InactiveDayThreshold $InactiveDays `
        -GlobalAdminWarnThreshold $GlobalAdminThreshold `
        -MaxPages $MaxPages
    $context['MailboxLimit'] = $MaxMailbox

    $startedAt = [datetime]::UtcNow
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Initialize-HygieneTenantInfo -Context $context

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($id in $ordered) {

        $entry = $registry[$id]
        Write-HygieneLog -Level Information -Message "Running check '$($entry.Name)'."

        $checkTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $result = $null

        try {
            $result = & $entry.Function -Context $context
        }
        catch {
            $kind = $_.Exception.Data['Kind']

            if ($kind -in @('Permission', 'Authentication')) {
                # A missing permission is a gap in coverage, not a clean result.
                $result = New-HygieneCheckResult `
                    -CheckId $entry.Id -CheckName $entry.Name -Category $entry.Category `
                    -Status 'Skipped' `
                    -RequiredScopes $entry.RequiredScopes `
                    -Reason ("Microsoft Graph denied access ({0}). Required delegated scope(s): {1}. The signed-in account also needs a directory role that can read this data. Nothing was evaluated for this check." -f $_.Exception.Message, ($entry.RequiredScopes -join ', '))
                Write-HygieneLog -Level Warning -Message "Check '$($entry.Name)' skipped: access denied."
            }
            else {
                $result = New-HygieneCheckResult `
                    -CheckId $entry.Id -CheckName $entry.Name -Category $entry.Category `
                    -Status 'Failed' `
                    -RequiredScopes $entry.RequiredScopes `
                    -ErrorMessage $_.Exception.Message
                Write-HygieneLog -Level Warning -Message "Check '$($entry.Name)' failed: $($_.Exception.Message)"
            }
        }
        finally {
            $checkTimer.Stop()
        }

        if ($result) {
            $result.Duration = $checkTimer.Elapsed
            $results.Add($result)
        }
    }

    $stopwatch.Stop()

    $findings = @(
        $results |
            Where-Object { $_.Status -eq 'Completed' } |
            ForEach-Object { $_.Findings } |
            Sort-Object SeverityRank, Category, CheckName, ObjectName
    )

    $moduleVersion = try { (Get-Module M365TenantHygiene).Version.ToString() } catch { 'unknown' }

    [pscustomobject]@{
        PSTypeName    = 'M365TenantHygiene.AuditResult'
        Tenant        = $context.Tenant
        VerifiedDomains = $context.VerifiedDomains
        Account       = $graphContext.Account
        Environment   = $graphContext.Environment
        StartedAt     = $startedAt
        CompletedAt   = [datetime]::UtcNow
        Duration      = $stopwatch.Elapsed
        ModuleVersion = $moduleVersion
        Parameters    = [ordered]@{
            InactiveDays         = $InactiveDays
            GlobalAdminThreshold = $GlobalAdminThreshold
            MaxMailbox           = $MaxMailbox
            MaxPages             = $MaxPages
        }
        Checks        = @($results)
        Findings      = $findings
        Summary       = (New-HygieneSummary -CheckResult @($results) -Finding $findings)
    }
}

<#
.SYNOPSIS
    Aggregates an audit into the counters the report header shows.
.DESCRIPTION
    Counts skipped and failed checks alongside the findings, so the headline can never
    say "0 issues" without also saying how much of the tenant was never examined.
#>
function New-HygieneSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [object[]] $CheckResult = @(),
        [object[]] $Finding = @()
    )

    $bySeverity = [ordered]@{}
    foreach ($severity in 'Critical', 'High', 'Medium', 'Low', 'Informational') {
        $bySeverity[$severity] = @($Finding | Where-Object { $_.Severity -eq $severity }).Count
    }

    $actionable = $bySeverity['Critical'] + $bySeverity['High'] + $bySeverity['Medium'] + $bySeverity['Low']

    [pscustomobject]@{
        PSTypeName        = 'M365TenantHygiene.Summary'
        TotalFindings     = @($Finding).Count
        ActionableFindings = $actionable
        BySeverity        = $bySeverity
        ChecksRun         = @($CheckResult).Count
        ChecksCompleted   = @($CheckResult | Where-Object { $_.Status -eq 'Completed' }).Count
        ChecksSkipped     = @($CheckResult | Where-Object { $_.Status -eq 'Skipped' }).Count
        ChecksFailed      = @($CheckResult | Where-Object { $_.Status -eq 'Failed' }).Count
        ObjectsEvaluated  = (@($CheckResult | Where-Object { $_.Status -eq 'Completed' }) |
                             Measure-Object -Property ObjectsEvaluated -Sum).Sum
    }
}

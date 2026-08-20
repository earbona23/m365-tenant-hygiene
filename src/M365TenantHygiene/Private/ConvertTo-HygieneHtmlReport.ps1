<#
.SYNOPSIS
    Renders an audit result as a single self-contained HTML file.
.DESCRIPTION
    No external stylesheets, scripts, fonts or images: the report is one file that
    opens correctly from a USB stick, an air-gapped machine, or an email attachment
    three months from now. Security reports get forwarded, and a report that needs a
    CDN to render is a report that renders as a blank page in front of an auditor.

    The layout leads with coverage, not with a score. If checks were skipped, that is
    stated above the findings, because a low finding count on a partial audit is not
    good news and should not look like it.
#>
function ConvertTo-HygieneHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Audit)

    $summary   = $Audit.Summary
    $tenant    = if ($Audit.Tenant) { $Audit.Tenant.DisplayName } else { 'Unknown tenant' }
    $tenantId  = if ($Audit.Tenant) { $Audit.Tenant.Id } else { 'unknown' }
    $generated = $Audit.CompletedAt.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    $severities = @('Critical', 'High', 'Medium', 'Low', 'Informational')

    # --- Head ---------------------------------------------------------------------

    $sb = [System.Text.StringBuilder]::new()
    [void] $sb.AppendLine('<!DOCTYPE html>')
    [void] $sb.AppendLine('<html lang="en">')
    [void] $sb.AppendLine('<head>')
    [void] $sb.AppendLine('<meta charset="utf-8">')
    [void] $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void] $sb.AppendLine("<title>Tenant hygiene report - $(ConvertTo-HygieneHtmlText $tenant)</title>")
    [void] $sb.AppendLine('<style>')
    [void] $sb.AppendLine((Get-HygieneReportStyle))
    [void] $sb.AppendLine('</style>')
    [void] $sb.AppendLine('</head>')
    [void] $sb.AppendLine('<body>')

    # --- Header -------------------------------------------------------------------

    [void] $sb.AppendLine('<header class="masthead">')
    [void] $sb.AppendLine('  <div class="wrap">')
    [void] $sb.AppendLine('    <p class="eyebrow">Microsoft 365 tenant hygiene</p>')
    [void] $sb.AppendLine("    <h1>$(ConvertTo-HygieneHtmlText $tenant)</h1>")
    [void] $sb.AppendLine('    <dl class="meta">')
    [void] $sb.AppendLine("      <div><dt>Generated</dt><dd>$(ConvertTo-HygieneHtmlText $generated)</dd></div>")
    [void] $sb.AppendLine("      <div><dt>Tenant ID</dt><dd class='mono'>$(ConvertTo-HygieneHtmlText $tenantId)</dd></div>")
    [void] $sb.AppendLine("      <div><dt>Signed in as</dt><dd>$(ConvertTo-HygieneHtmlText $Audit.Account)</dd></div>")
    [void] $sb.AppendLine("      <div><dt>Duration</dt><dd>$([math]::Round($Audit.Duration.TotalSeconds, 1)) s</dd></div>")
    [void] $sb.AppendLine("      <div><dt>Module</dt><dd>M365TenantHygiene $(ConvertTo-HygieneHtmlText $Audit.ModuleVersion)</dd></div>")
    [void] $sb.AppendLine('    </dl>')
    [void] $sb.AppendLine('  </div>')
    [void] $sb.AppendLine('</header>')
    [void] $sb.AppendLine('<main class="wrap">')

    # --- Coverage first, before any findings --------------------------------------

    $incomplete = @($Audit.Checks | Where-Object { $_.Status -ne 'Completed' })
    if ($incomplete.Count -gt 0) {
        [void] $sb.AppendLine('<section class="notice" role="alert">')
        [void] $sb.AppendLine('  <h2>This audit is incomplete</h2>')
        [void] $sb.AppendLine("  <p>$($incomplete.Count) of $($summary.ChecksRun) checks did not run. The findings below cover only the checks that did. Treat a low count as unproven, not as clean.</p>")
        [void] $sb.AppendLine('  <ul>')
        foreach ($check in $incomplete) {
            $why = if ($check.Reason) { $check.Reason } elseif ($check.Error) { $check.Error } else { 'No reason recorded.' }
            [void] $sb.AppendLine("    <li><strong>$(ConvertTo-HygieneHtmlText $check.CheckName)</strong> &mdash; <span class='status status-$($check.Status.ToLower())'>$(ConvertTo-HygieneHtmlText $check.Status)</span> $(ConvertTo-HygieneHtmlText $why)</li>")
        }
        [void] $sb.AppendLine('  </ul>')
        [void] $sb.AppendLine('</section>')
    }

    # --- Severity cards -----------------------------------------------------------

    [void] $sb.AppendLine('<section class="cards" aria-label="Findings by severity">')
    foreach ($severity in $severities) {
        $count = $summary.BySeverity[$severity]
        $class = $severity.ToLower()
        [void] $sb.AppendLine("  <div class='card sev-$class'><span class='count'>$count</span><span class='label'>$severity</span></div>")
    }
    [void] $sb.AppendLine("  <div class='card neutral'><span class='count'>$($summary.ObjectsEvaluated)</span><span class='label'>Objects examined</span></div>")
    [void] $sb.AppendLine('</section>')

    # --- Check coverage table -----------------------------------------------------

    [void] $sb.AppendLine('<section>')
    [void] $sb.AppendLine('  <h2>Coverage</h2>')
    [void] $sb.AppendLine('  <table class="grid">')
    [void] $sb.AppendLine('    <thead><tr><th>Check</th><th>Category</th><th>Status</th><th class="num">Objects</th><th class="num">Findings</th><th>Notes</th></tr></thead>')
    [void] $sb.AppendLine('    <tbody>')
    foreach ($check in $Audit.Checks) {
        $note = if ($check.Reason) { $check.Reason } elseif ($check.Error) { $check.Error } else { '' }
        [void] $sb.AppendLine('      <tr>')
        [void] $sb.AppendLine("        <td>$(ConvertTo-HygieneHtmlText $check.CheckName)</td>")
        [void] $sb.AppendLine("        <td>$(ConvertTo-HygieneHtmlText $check.Category)</td>")
        [void] $sb.AppendLine("        <td><span class='status status-$($check.Status.ToLower())'>$(ConvertTo-HygieneHtmlText $check.Status)</span></td>")
        [void] $sb.AppendLine("        <td class='num'>$($check.ObjectsEvaluated)</td>")
        [void] $sb.AppendLine("        <td class='num'>$($check.FindingCount)</td>")
        [void] $sb.AppendLine("        <td class='note'>$(ConvertTo-HygieneHtmlText $note)</td>")
        [void] $sb.AppendLine('      </tr>')
    }
    [void] $sb.AppendLine('    </tbody>')
    [void] $sb.AppendLine('  </table>')
    [void] $sb.AppendLine('</section>')

    # --- Findings -----------------------------------------------------------------

    [void] $sb.AppendLine('<section>')
    [void] $sb.AppendLine('  <h2>Findings</h2>')

    if (@($Audit.Findings).Count -eq 0) {
        [void] $sb.AppendLine('  <p class="empty">No findings were raised by the checks that completed.</p>')
    }
    else {
        [void] $sb.AppendLine('  <div class="filters no-print">')
        [void] $sb.AppendLine('    <label class="search"><span>Filter</span><input type="search" id="q" placeholder="user, device, application, rule..." autocomplete="off"></label>')
        [void] $sb.AppendLine('    <div class="chips" id="sev-filters">')
        foreach ($severity in $severities) {
            $class = $severity.ToLower()
            [void] $sb.AppendLine("      <label class='chip sev-$class'><input type='checkbox' value='$class' checked> $severity</label>")
        }
        [void] $sb.AppendLine('    </div>')
        [void] $sb.AppendLine('    <p class="result-count" id="shown"></p>')
        [void] $sb.AppendLine('  </div>')

        $grouped = $Audit.Findings | Group-Object CheckName | Sort-Object { ($_.Group | Measure-Object SeverityRank -Minimum).Minimum }

        foreach ($group in $grouped) {
            $checkName = $group.Name
            [void] $sb.AppendLine("  <h3 class='check-heading'>$(ConvertTo-HygieneHtmlText $checkName) <span class='badge'>$($group.Count)</span></h3>")

            foreach ($finding in ($group.Group | Sort-Object SeverityRank, ObjectName)) {
                $class = $finding.Severity.ToLower()
                $haystack = (@($finding.ObjectName, $finding.Title, $finding.Detail, $finding.ObjectId, $finding.Category) -join ' ').ToLowerInvariant()

                [void] $sb.AppendLine("  <details class='finding sev-$class' data-severity='$class' data-search='$(ConvertTo-HygieneHtmlAttribute $haystack)'>")
                [void] $sb.AppendLine('    <summary>')
                [void] $sb.AppendLine("      <span class='pill sev-$class'>$($finding.Severity)</span>")
                [void] $sb.AppendLine("      <span class='object'>$(ConvertTo-HygieneHtmlText $finding.ObjectName)</span>")
                [void] $sb.AppendLine("      <span class='headline'>$(ConvertTo-HygieneHtmlText $finding.Title)</span>")
                [void] $sb.AppendLine('    </summary>')
                [void] $sb.AppendLine('    <div class="body">')
                [void] $sb.AppendLine("      <p class='detail'>$(ConvertTo-HygieneHtmlText $finding.Detail)</p>")

                if ($finding.Recommendation) {
                    [void] $sb.AppendLine("      <p class='recommendation'><strong>What to do</strong> $(ConvertTo-HygieneHtmlText $finding.Recommendation)</p>")
                }

                [void] $sb.AppendLine('      <dl class="facts">')
                [void] $sb.AppendLine("        <div><dt>Object type</dt><dd>$(ConvertTo-HygieneHtmlText $finding.ObjectType)</dd></div>")
                [void] $sb.AppendLine("        <div><dt>Object ID</dt><dd class='mono'>$(ConvertTo-HygieneHtmlText $finding.ObjectId)</dd></div>")
                [void] $sb.AppendLine("        <div><dt>Category</dt><dd>$(ConvertTo-HygieneHtmlText $finding.Category)</dd></div>")
                [void] $sb.AppendLine('      </dl>')

                if ($finding.Evidence -and $finding.Evidence.Count -gt 0) {
                    $json = ConvertTo-HygieneEvidenceJson -Evidence $finding.Evidence
                    [void] $sb.AppendLine('      <p class="evidence-label">Evidence</p>')
                    [void] $sb.AppendLine("      <pre class='evidence'>$(ConvertTo-HygieneHtmlText $json)</pre>")
                }

                if ($finding.Reference) {
                    $href = ConvertTo-HygieneHtmlAttribute $finding.Reference
                    [void] $sb.AppendLine("      <p class='reference'><a href='$href' rel='noreferrer noopener' target='_blank'>Microsoft documentation</a></p>")
                }

                [void] $sb.AppendLine('    </div>')
                [void] $sb.AppendLine('  </details>')
            }
        }
    }

    [void] $sb.AppendLine('</section>')

    # --- Footer -------------------------------------------------------------------

    [void] $sb.AppendLine('<footer>')
    [void] $sb.AppendLine('  <p>Produced by <strong>M365TenantHygiene</strong>, a read-only auditing module. No configuration in this tenant was changed to produce this report.</p>')
    [void] $sb.AppendLine("  <p class='params'>Parameters: inactivity threshold $($Audit.Parameters.InactiveDays) days &middot; Global Administrator threshold $($Audit.Parameters.GlobalAdminThreshold)$(if ($Audit.Parameters.MaxMailbox -gt 0) { " &middot; mailbox cap $($Audit.Parameters.MaxMailbox)" }).</p>")
    [void] $sb.AppendLine('</footer>')
    [void] $sb.AppendLine('</main>')
    [void] $sb.AppendLine('<script>')
    [void] $sb.AppendLine((Get-HygieneReportScript))
    [void] $sb.AppendLine('</script>')
    [void] $sb.AppendLine('</body>')
    [void] $sb.AppendLine('</html>')

    return $sb.ToString()
}

<#
.SYNOPSIS
    Escapes text for HTML element content.
.DESCRIPTION
    Every value that reaches the report comes from the tenant, and display names are
    attacker-controllable. A user called "<script>" must render as text, not execute.
#>
function ConvertTo-HygieneHtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)] $Value)

    if ($null -eq $Value) { return '' }
    $text = [string] $Value
    $text = $text.Replace('&', '&amp;')
    $text = $text.Replace('<', '&lt;')
    $text = $text.Replace('>', '&gt;')
    $text = $text.Replace('"', '&quot;')
    $text = $text.Replace("'", '&#39;')
    return $text
}

<#
.SYNOPSIS
    Escapes text for use inside an HTML attribute value.
#>
function ConvertTo-HygieneHtmlAttribute {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)] $Value)

    return (ConvertTo-HygieneHtmlText $Value)
}

<#
.SYNOPSIS
    Renders a finding's evidence hashtable as readable JSON.
.DESCRIPTION
    Sorted by key so two reports on the same tenant diff cleanly.
#>
function ConvertTo-HygieneEvidenceJson {
    [CmdletBinding()]
    [OutputType([string])]
    param([hashtable] $Evidence)

    $ordered = [ordered]@{}
    foreach ($key in ($Evidence.Keys | Sort-Object)) { $ordered[$key] = $Evidence[$key] }

    try   { return ($ordered | ConvertTo-Json -Depth 6) }
    catch { return ($ordered.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join [Environment]::NewLine }
}

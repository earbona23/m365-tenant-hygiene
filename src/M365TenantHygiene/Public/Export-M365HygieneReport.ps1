<#
.SYNOPSIS
    Writes an audit result to a self-contained HTML report and CSV exports.

.DESCRIPTION
    Produces three files in the output directory:

      *-report.html   the readable report: severity summary, coverage, findings with
                      evidence and remediation. One file, no external assets.
      *-findings.csv  one row per finding, for a spreadsheet or a ticket queue.
      *-checks.csv    one row per check, including the ones that were skipped or
                      failed and why.

    The coverage CSV exists so the incompleteness survives the export. A findings CSV
    on its own cannot tell a reader that three checks never ran, and that is exactly
    the fact most likely to be lost once the data is pasted into a spreadsheet.

.PARAMETER Audit
    The object returned by Invoke-M365HygieneAudit. Accepts pipeline input.

.PARAMETER Path
    Output directory. Created if it does not exist.

.PARAMETER Prefix
    File name prefix. Defaults to a timestamp, so repeated runs do not overwrite
    each other and a history builds up on its own.

.PARAMETER Format
    Which artefacts to produce. Defaults to all of them.

.PARAMETER PassThru
    Emit the created file paths.

.EXAMPLE
    Invoke-M365HygieneAudit | Export-M365HygieneReport -Path ./reports

.EXAMPLE
    Export-M365HygieneReport -Audit $audit -Path ./reports -Format Html -PassThru

.OUTPUTS
    System.IO.FileInfo when -PassThru is used.
#>
function Export-M365HygieneReport {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        $Audit,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [string] $Prefix,

        [ValidateSet('Html', 'Csv', 'All')]
        [string] $Format = 'All',

        [switch] $PassThru
    )

    process {

        if (-not $Audit.PSObject.Properties.Name.Contains('Findings')) {
            throw 'The object supplied to -Audit is not an audit result. Pass the output of Invoke-M365HygieneAudit.'
        }

        $directory = New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
        if (-not $Prefix) {
            $Prefix = 'hygiene-' + $Audit.CompletedAt.ToString('yyyyMMdd-HHmmss')
        }

        $created = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

        # --- HTML -----------------------------------------------------------------

        if ($Format -in @('Html', 'All')) {
            $htmlPath = Join-Path $directory.FullName "$Prefix-report.html"
            if ($PSCmdlet.ShouldProcess($htmlPath, 'Write HTML report')) {
                $html = ConvertTo-HygieneHtmlReport -Audit $Audit
                # UTF-8 without BOM: browsers honour the meta charset, and a BOM
                # shows up as stray characters in some downstream tooling.
                $encoding = [System.Text.UTF8Encoding]::new($false)
                [System.IO.File]::WriteAllText($htmlPath, $html, $encoding)
                $created.Add((Get-Item -LiteralPath $htmlPath))
                Write-HygieneLog -Level Information -Message "HTML report written to $htmlPath"
            }
        }

        # --- CSV ------------------------------------------------------------------

        if ($Format -in @('Csv', 'All')) {

            $findingsPath = Join-Path $directory.FullName "$Prefix-findings.csv"
            if ($PSCmdlet.ShouldProcess($findingsPath, 'Write findings CSV')) {
                $rows = foreach ($finding in $Audit.Findings) {
                    [pscustomobject]@{
                        Severity       = $finding.Severity
                        Category       = $finding.Category
                        Check          = $finding.CheckName
                        CheckId        = $finding.CheckId
                        ObjectType     = $finding.ObjectType
                        ObjectName     = $finding.ObjectName
                        ObjectId       = $finding.ObjectId
                        Title          = $finding.Title
                        Detail         = $finding.Detail
                        Recommendation = $finding.Recommendation
                        Reference      = $finding.Reference
                        DetectedAtUtc  = $finding.DetectedAt.ToString('o')
                        Evidence       = (ConvertTo-HygieneEvidenceJson -Evidence $finding.Evidence) -replace '\r?\n', ' '
                    }
                }
                # -NoTypeInformation keeps the header row usable in Excel.
                @($rows) | Export-Csv -LiteralPath $findingsPath -NoTypeInformation -Encoding utf8
                $created.Add((Get-Item -LiteralPath $findingsPath))
                Write-HygieneLog -Level Information -Message "Findings CSV written to $findingsPath ($(@($rows).Count) row(s))."
            }

            $checksPath = Join-Path $directory.FullName "$Prefix-checks.csv"
            if ($PSCmdlet.ShouldProcess($checksPath, 'Write coverage CSV')) {
                $checkRows = foreach ($check in $Audit.Checks) {
                    [pscustomobject]@{
                        CheckId          = $check.CheckId
                        Check            = $check.CheckName
                        Category         = $check.Category
                        Status           = $check.Status
                        ObjectsEvaluated = $check.ObjectsEvaluated
                        FindingCount     = $check.FindingCount
                        DurationSeconds  = [math]::Round($check.Duration.TotalSeconds, 2)
                        RequiredScopes   = ($check.RequiredScopes -join '; ')
                        Reason           = $check.Reason
                        Error            = $check.Error
                    }
                }
                @($checkRows) | Export-Csv -LiteralPath $checksPath -NoTypeInformation -Encoding utf8
                $created.Add((Get-Item -LiteralPath $checksPath))
                Write-HygieneLog -Level Information -Message "Coverage CSV written to $checksPath"
            }
        }

        if ($PassThru) { $created }
    }
}

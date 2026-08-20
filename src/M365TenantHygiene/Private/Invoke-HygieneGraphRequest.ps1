<#
.SYNOPSIS
    The single, read-only gateway every Graph call in this module goes through.

.DESCRIPTION
    This function is the module's read-only guarantee, expressed as code rather than
    as a promise in a README.

    There is deliberately no -Method parameter and no -Body parameter. The HTTP verb
    is hardcoded to GET at the only place where an HTTP request is issued, so no check
    -- present or future -- can perform a write even by mistake. Adding a write would
    require editing this file, which the read-only test in tests/ReadOnly.Tests.ps1
    is designed to catch.

    It also centralises the two things every real Graph client needs and most sample
    scripts omit: @odata.nextLink paging, and honouring Retry-After on HTTP 429/503.

.PARAMETER Uri
    Either a Graph-relative path ('users?$select=id') or an absolute URL, which is
    what @odata.nextLink hands back.

.PARAMETER ApiVersion
    Graph endpoint version. Every production check in this module uses v1.0.

.PARAMETER MaxPages
    Safety valve for very large tenants. Paging stops after this many pages and the
    caller is told through -ResultInfo that the collection was truncated.

.PARAMETER ConsistencyLevel
    Set to 'eventual' for advanced queries ($count, $search, some $filter forms).

.PARAMETER ResultInfo
    Name of a variable, in the caller's scope, that receives a summary of the call:
    page count, whether the result was truncated, and the final HTTP status.

.OUTPUTS
    The elements of the 'value' array for collection responses; the response object
    itself for single-entity responses.
#>
function Invoke-HygieneGraphRequest {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Uri,

        [ValidateSet('v1.0', 'beta')]
        [string] $ApiVersion = 'v1.0',

        [ValidateRange(1, [int]::MaxValue)]
        [int] $MaxPages = 200,

        [ValidateSet('eventual')]
        [string] $ConsistencyLevel,

        [ValidateRange(0, 10)]
        [int] $MaxRetry = 4,

        [string] $ResultInfo
    )

    $headers = @{}
    if ($ConsistencyLevel) { $headers['ConsistencyLevel'] = $ConsistencyLevel }

    $next     = $Uri
    $page     = 0
    $items    = [System.Collections.Generic.List[object]]::new()
    $status   = 0
    $truncated = $false

    while ($next) {
        if ($page -ge $MaxPages) { $truncated = $true; break }

        $attempt  = 0
        $response = $null

        while ($true) {
            $params = @{
                # Hardcoded on purpose. See the .DESCRIPTION above.
                Method              = 'GET'
                Uri                 = $next
                OutputType          = 'PSObject'
                SkipHttpErrorCheck  = $true
                StatusCodeVariable  = 'httpStatus'
                ResponseHeadersVariable = 'httpHeaders'
                ErrorAction         = 'Stop'
            }
            if ($headers.Count -gt 0) { $params['Headers'] = $headers }

            # Relative paths need the version prefix; an @odata.nextLink is already absolute.
            if ($params['Uri'] -notmatch '^https?://') {
                $params['Uri'] = "https://graph.microsoft.com/$ApiVersion/" + $params['Uri'].TrimStart('/')
            }

            $response = Invoke-MgGraphRequest @params
            $status   = $httpStatus

            if ($status -eq 429 -or $status -eq 503 -or $status -eq 504) {
                if ($attempt -ge $MaxRetry) {
                    throw [System.InvalidOperationException]::new(
                        "Microsoft Graph kept throttling '$($params['Uri'])' (HTTP $status) after $MaxRetry retries.")
                }
                $wait = Get-HygieneRetryDelay -Headers $httpHeaders -Attempt $attempt
                Write-HygieneLog -Level Warning -Message "Graph returned HTTP $status; waiting $wait s before retry $($attempt + 1)/$MaxRetry."
                Start-Sleep -Seconds $wait
                $attempt++
                continue
            }

            break
        }

        if ($status -ge 400) {
            throw (New-HygieneGraphError -StatusCode $status -Response $response -Uri $params['Uri'])
        }

        if ($null -ne $response -and $response.PSObject.Properties.Name -contains 'value') {
            foreach ($item in $response.value) { $items.Add($item) }

            # Absent on the final page, so it is read defensively rather than assumed.
            $next = $null
            if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
                $next = $response.'@odata.nextLink'
            }
        }
        else {
            # Single entity, not a collection. Emit as-is and stop.
            $items.Add($response)
            $next = $null
        }

        $page++
    }

    if ($ResultInfo) {
        $info = [pscustomobject]@{
            Pages      = $page
            Count      = $items.Count
            Truncated  = $truncated
            StatusCode = $status
        }
        Set-Variable -Name $ResultInfo -Value $info -Scope 1
    }

    if ($truncated) {
        Write-HygieneLog -Level Warning -Message "Stopped paging '$Uri' after $MaxPages pages. Results are incomplete; raise -MaxPages if you need the full set."
    }

    return $items.ToArray()
}

<#
.SYNOPSIS
    Chooses how long to wait after a throttled Graph response.
.DESCRIPTION
    Prefers the server's own Retry-After header. Falls back to capped exponential
    backoff when the header is missing, which some Graph endpoints do omit.
#>
function Get-HygieneRetryDelay {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [System.Collections.IDictionary] $Headers,
        [int] $Attempt = 0
    )

    if ($Headers -and $Headers.Contains('Retry-After')) {
        $raw = @($Headers['Retry-After'])[0]
        $parsed = 0
        if ([int]::TryParse($raw, [ref] $parsed) -and $parsed -gt 0) {
            return [Math]::Min($parsed, 120)
        }
    }

    return [Math]::Min([Math]::Pow(2, $Attempt) * 2, 60)
}

<#
.SYNOPSIS
    Turns a failed Graph response into an exception carrying the detail a caller needs.
.DESCRIPTION
    Checks catch this to tell apart "you lack the permission" (403/401, which downgrades
    the check to Skipped) from "something genuinely broke" (which fails the check).
#>
function New-HygieneGraphError {
    [CmdletBinding()]
    [OutputType([System.Exception])]
    param(
        [int] $StatusCode,
        [object] $Response,
        [string] $Uri
    )

    $detail = $null
    if ($Response -and $Response.PSObject.Properties.Name -contains 'error') {
        $detail = $Response.error.message
        if (-not $detail) { $detail = $Response.error.code }
    }
    if (-not $detail) { $detail = 'no error body returned' }

    $kind = switch ($StatusCode) {
        401     { 'Authentication' }
        403     { 'Permission' }
        404     { 'NotFound' }
        default { 'Request' }
    }

    $message = "[$kind] Graph GET $Uri failed with HTTP $StatusCode : $detail"
    $ex = [System.InvalidOperationException]::new($message)
    $ex.Data['StatusCode'] = $StatusCode
    $ex.Data['Kind']       = $kind
    $ex.Data['Uri']        = $Uri
    return $ex
}

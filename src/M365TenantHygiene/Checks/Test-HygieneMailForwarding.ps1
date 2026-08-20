<#
.SYNOPSIS
    Finds inbox rules that forward or redirect mail outside the tenant.

.DESCRIPTION
    A rule that quietly forwards mail to an outside address is one of the oldest and
    most reliable signs of a compromised mailbox: the attacker keeps reading after the
    password is reset, and the victim sees nothing.

    Every enabled rule on every reachable mailbox is examined for forwardTo,
    forwardAsAttachmentTo and redirectTo actions, and each recipient is checked against
    the tenant's own verified domains. A rule that hides its traces -- deleting or
    marking messages as read alongside the forward -- is treated as more severe,
    because that combination is characteristic of an attacker rather than a user who
    set up a convenience rule.

    Read the delegated-access note below before treating a clean result as good news.

.PARAMETER Context
    Shared audit context from New-HygieneAuditContext.

.OUTPUTS
    M365TenantHygiene.Finding objects.

.NOTES
    Graph endpoint : GET /users/{id}/mailFolders/inbox/messageRules
    Scopes required: MailboxSettings.Read, User.Read.All (delegated)

    THE COVERAGE LIMIT THAT MATTERS: with delegated permissions, Graph grants the
    intersection of the application's consent and what the signed-in user can already
    do. Being a Global Administrator does not by itself grant the right to open another
    person's mailbox. In practice this check reaches the signed-in user's own mailbox
    plus any mailbox they hold Full Access on, and Graph returns 403 for the rest.

    Rather than counting those refusals as clean, the check tracks them: if every
    mailbox it tried was denied, it reports Skipped, and if only some were denied it
    reports the number it could not read. Full tenant coverage needs application
    permissions, which is a different consent model than the one this module is
    built around -- see the Limitations section of the README.

    Scope note: this reads inbox RULES. Mailbox-level forwarding configured through
    Exchange (ForwardingSmtpAddress) is not exposed by this Graph endpoint and is not
    covered.
#>
function Test-HygieneMailForwarding {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][hashtable] $Context)

    $meta = (Get-HygieneCheckRegistry)['MailForwarding']

    if (-not $Context.VerifiedDomains -or $Context.VerifiedDomains.Count -eq 0) {
        return New-HygieneCheckResult `
            -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
            -Status 'Skipped' `
            -RequiredScopes $meta.RequiredScopes `
            -Reason 'The tenant''s verified domains could not be read, so there is no way to tell an internal recipient from an external one. Calling every forward external would invent findings; calling none external would hide them.'
    }

    $users = @(Get-HygieneUser -Context $Context)
    $candidates = @(
        $users |
            Where-Object { $_.accountEnabled -and $_.userType -ne 'Guest' -and $_.userPrincipalName } |
            Sort-Object userPrincipalName
    )

    $limit = if ($Context.ContainsKey('MailboxLimit') -and $Context.MailboxLimit -gt 0) { $Context.MailboxLimit } else { $candidates.Count }
    $targets = @($candidates | Select-Object -First $limit)

    if ($targets.Count -lt $candidates.Count) {
        Write-HygieneLog -Level Warning -Message "Mailbox scan capped at $($targets.Count) of $($candidates.Count) mailboxes by -MaxMailbox. The remaining $($candidates.Count - $targets.Count) were not examined."
    }

    $findings   = [System.Collections.Generic.List[object]]::new()
    $inspected  = 0
    $denied     = 0
    $notFound   = 0

    foreach ($user in $targets) {

        $rules = $null
        try {
            $rules = Invoke-HygieneGraphRequest `
                -Uri "users/$($user.id)/mailFolders/inbox/messageRules" `
                -MaxPages 5
        }
        catch {
            $kind = $_.Exception.Data['Kind']

            # Deliberately if/elseif rather than switch: in PowerShell, `continue`
            # inside a switch ends the switch, not the enclosing loop, so a denied
            # mailbox would fall through and be counted as examined -- which is how
            # an audit that saw nothing ends up reporting that it saw nothing wrong.
            if ($kind -eq 'Permission' -or $kind -eq 'Authentication') {
                $denied++
                continue
            }
            elseif ($kind -eq 'NotFound') {
                # No Exchange Online mailbox: an unlicensed or on-premises account.
                $notFound++
                continue
            }
            else {
                throw
            }
        }

        $inspected++

        foreach ($rule in $rules) {

            $actions = $rule.actions
            if (-not $actions) { continue }

            $recipients = @(
                @($actions.forwardTo) + @($actions.forwardAsAttachmentTo) + @($actions.redirectTo) |
                    Where-Object { $_ -and $_.emailAddress -and $_.emailAddress.address } |
                    ForEach-Object { $_.emailAddress.address }
            )
            if ($recipients.Count -eq 0) { continue }

            $external = @($recipients | Where-Object {
                Test-HygieneExternalAddress -Address $_ -VerifiedDomain $Context.VerifiedDomains
            })
            if ($external.Count -eq 0) { continue }

            $covertActions = @()
            if ($actions.delete)         { $covertActions += 'deletes the message' }
            if ($actions.markAsRead)     { $covertActions += 'marks the message as read' }
            if ($actions.permanentDelete) { $covertActions += 'permanently deletes the message' }
            if ($actions.moveToFolder)   { $covertActions += 'moves the message to another folder' }

            $covert   = $covertActions.Count -gt 0
            $enabled  = ($rule.isEnabled -ne $false)

            $severity = if (-not $enabled) { 'Low' } elseif ($covert) { 'Critical' } else { 'High' }

            $detail = "The inbox rule '$($rule.displayName)' sends mail to $($external -join ', '), which is outside every verified domain of this tenant."
            if ($covert) {
                $detail += " The same rule also $($covertActions -join ' and '), so the mailbox owner does not see the messages being forwarded. That combination is characteristic of a compromised mailbox rather than a convenience rule."
            }
            if (-not $enabled) {
                $detail += ' The rule is currently disabled, so it is not forwarding today, but it remains in place and can be re-enabled.'
            }

            $findings.Add((New-HygieneFinding `
                -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
                -Severity $severity `
                -Title $(if ($covert) { 'Inbox rule forwards externally and hides the evidence' } else { 'Inbox rule forwards mail outside the tenant' }) `
                -ObjectType 'Mailbox' `
                -ObjectId $user.id `
                -ObjectName $user.userPrincipalName `
                -Detail $detail `
                -Recommendation 'Confirm with the mailbox owner that they created this rule. If they did not, treat the mailbox as compromised: revoke sessions, reset credentials, review the sign-in logs, and remove the rule. Consider blocking automatic external forwarding tenant-wide through an outbound spam policy.' `
                -Reference 'https://learn.microsoft.com/defender-office-365/outbound-spam-policies-external-email-forwarding' `
                -Evidence @{
                    ruleId             = $rule.id
                    ruleName           = $rule.displayName
                    ruleEnabled        = $enabled
                    externalRecipients = $external
                    allRecipients      = $recipients
                    concealmentActions = $covertActions
                    sequence           = $rule.sequence
                }))
        }
    }

    if ($inspected -eq 0 -and $denied -gt 0) {
        return New-HygieneCheckResult `
            -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
            -Status 'Skipped' `
            -ObjectsEvaluated 0 `
            -RequiredScopes $meta.RequiredScopes `
            -Reason ("Microsoft Graph refused access to all {0} mailbox(es) tried. With delegated permissions the module can only read mailboxes the signed-in user can already open; an administrative role does not by itself grant mailbox access. No conclusion about external forwarding can be drawn from this run." -f $denied)
    }

    $reason = $null
    if ($denied -gt 0 -or $notFound -gt 0 -or $targets.Count -lt $candidates.Count) {
        $parts = @("Examined $inspected of $($candidates.Count) mailbox(es).")
        if ($denied -gt 0)   { $parts += "$denied were denied by Microsoft Graph and were NOT examined." }
        if ($notFound -gt 0) { $parts += "$notFound have no Exchange Online mailbox." }
        if ($targets.Count -lt $candidates.Count) { $parts += "$($candidates.Count - $targets.Count) were skipped by the -MaxMailbox cap." }
        $reason = $parts -join ' '
        Write-HygieneLog -Level Warning -Message $reason
    }

    New-HygieneCheckResult `
        -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
        -Status 'Completed' `
        -Findings @($findings) `
        -ObjectsEvaluated $inspected `
        -Reason $reason `
        -RequiredScopes $meta.RequiredScopes
}

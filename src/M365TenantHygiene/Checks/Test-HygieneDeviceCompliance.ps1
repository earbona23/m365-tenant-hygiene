<#
.SYNOPSIS
    Finds Intune-managed devices that are not meeting their compliance policies.

.DESCRIPTION
    Conditional Access policies that require a compliant device are only as good as
    the compliance state underneath them. This check reports the devices that would
    fail such a policy, and -- more usefully -- the ones that would quietly pass it
    while nothing has actually been verified.

    The states are treated separately because they mean different things:

      noncompliant  a policy was evaluated and the device failed it.
      inGracePeriod failing, but inside the window before enforcement bites. This is
                    a deadline, not a pass.
      unknown       the device has not checked in recently enough to say.
      notApplicable no compliance policy targets the device at all. This is the one
      / no policy   worth caring about: the device reports no failure because nothing
                    ever asked it a question, and on a dashboard it looks fine.

    Devices that have not contacted Intune for a long time are flagged separately,
    since a stale compliant verdict describes a device as it was months ago.

.PARAMETER Context
    Shared audit context from New-HygieneAuditContext.

.OUTPUTS
    M365TenantHygiene.Finding objects.

.NOTES
    Graph endpoint : GET /deviceManagement/managedDevices
    Scope required : DeviceManagementManagedDevices.Read.All (delegated)

    Requires an active Intune licence on the tenant. Without one the endpoint is not
    available, and the check reports Skipped rather than reporting zero non-compliant
    devices, which would read as a clean estate.
#>
function Test-HygieneDeviceCompliance {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][hashtable] $Context)

    $meta          = (Get-HygieneCheckRegistry)['DeviceCompliance']
    $staleDayLimit = 30

    try {
        $devices = Invoke-HygieneGraphRequest `
            -Uri 'deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,managementAgent,lastSyncDateTime,enrolledDateTime,isEncrypted,jailBroken,manufacturer,model' `
            -MaxPages $Context.MaxPages
    }
    catch {
        $kind = $_.Exception.Data['Kind']
        if ($kind -in @('Permission', 'NotFound')) {
            return New-HygieneCheckResult `
                -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
                -Status 'Skipped' `
                -RequiredScopes $meta.RequiredScopes `
                -Reason ('Microsoft Intune device management is not reachable for this tenant ({0}). This usually means no active Intune licence. No conclusion about device compliance can be drawn from this run.' -f $_.Exception.Message)
        }
        throw
    }

    Write-HygieneLog -Message "Read $($devices.Count) managed device(s)."

    $findings = [System.Collections.Generic.List[object]]::new()

    foreach ($device in $devices) {

        $state = $device.complianceState
        $name  = if ($device.deviceName) { $device.deviceName } else { $device.id }

        $lastSync = $null
        if ($device.lastSyncDateTime) {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse($device.lastSyncDateTime, [ref] $parsed)) { $lastSync = $parsed.ToUniversalTime() }
        }
        $daysSinceSync = if ($lastSync) { [int] ([datetime]::UtcNow - $lastSync).TotalDays } else { $null }

        $evidence = @{
            deviceId        = $device.id
            operatingSystem = $device.operatingSystem
            osVersion       = $device.osVersion
            complianceState = $state
            managementAgent = $device.managementAgent
            lastSyncUtc     = if ($lastSync) { $lastSync.ToString('o') } else { $null }
            daysSinceSync   = $daysSinceSync
            enrolledDateTime = $device.enrolledDateTime
            isEncrypted     = $device.isEncrypted
            jailBroken      = $device.jailBroken
            manufacturer    = $device.manufacturer
            model           = $device.model
            assignedUser    = $device.userPrincipalName
        }

        $common = @{
            CheckId    = $meta.Id
            CheckName  = $meta.Name
            Category   = $meta.Category
            ObjectType = 'Device'
            ObjectId   = $device.id
            ObjectName = $name
            Evidence   = $evidence
            Reference  = 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started'
        }

        switch ($state) {

            'noncompliant' {
                $findings.Add((New-HygieneFinding @common `
                    -Severity 'High' `
                    -Title 'Device is non-compliant' `
                    -Detail "The device failed the compliance policies targeting it. If a Conditional Access policy requires a compliant device, this device is being blocked; if no such policy exists, it is reaching corporate data while failing your own baseline." `
                    -Recommendation 'Open the device in Intune to see which settings failed, and fix the setting rather than the compliance policy.'))
            }

            'inGracePeriod' {
                $findings.Add((New-HygieneFinding @common `
                    -Severity 'Medium' `
                    -Title 'Device is non-compliant but still inside its grace period' `
                    -Detail 'The device is failing its compliance policies and is inside the grace window before enforcement applies. It reports as tolerated today and will be blocked when the window closes.' `
                    -Recommendation 'Treat this as a deadline. Remediate before the grace period ends, rather than extending the grace period.'))
            }

            'unknown' {
                $findings.Add((New-HygieneFinding @common `
                    -Severity 'Medium' `
                    -Title 'Device compliance is unknown' `
                    -Detail "Intune has no current compliance verdict for this device$(if ($null -ne $daysSinceSync) { "; it last synchronised $daysSinceSync day(s) ago" }). An unknown state is not a pass: nothing about this device has been verified." `
                    -Recommendation 'Confirm the device is still in use and still enrolled. Retire the record if the device is gone, and investigate why it stopped checking in if it is not.'))
            }

            { $_ -in @('notApplicable', 'configManager') } {
                $findings.Add((New-HygieneFinding @common `
                    -Severity 'Medium' `
                    -Title 'No compliance policy applies to this device' `
                    -Detail "The device reports '$state', meaning no Intune compliance policy targets it. It will never be reported as non-compliant, because nothing is evaluating it -- and a Conditional Access policy requiring compliance may still let it through." `
                    -Recommendation 'Extend a compliance policy to cover this device''s platform and group. Gaps in policy targeting are the most common reason a fleet looks compliant.'))
            }

            'compliant' {
                if ($null -ne $daysSinceSync -and $daysSinceSync -gt $staleDayLimit) {
                    $findings.Add((New-HygieneFinding @common `
                        -Severity 'Low' `
                        -Title 'Compliant verdict is stale' `
                        -Detail "The device is recorded as compliant but last synchronised $daysSinceSync day(s) ago, beyond the $staleDayLimit day threshold. The verdict describes the device as it was then, not as it is now." `
                        -Recommendation 'Confirm the device is still in service. Retire records for devices that are gone so the compliance figures describe the real estate.'))
                }
            }

            default {
                $findings.Add((New-HygieneFinding @common `
                    -Severity 'Low' `
                    -Title "Unrecognised compliance state '$state'" `
                    -Detail "Intune reported a compliance state this module does not classify. It is surfaced rather than dropped so it is not silently treated as compliant." `
                    -Recommendation 'Review the device in Intune directly.'))
            }
        }
    }

    New-HygieneCheckResult `
        -CheckId $meta.Id -CheckName $meta.Name -Category $meta.Category `
        -Status 'Completed' `
        -Findings @($findings) `
        -ObjectsEvaluated $devices.Count `
        -RequiredScopes $meta.RequiredScopes
}

@{
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # PSUseShouldProcessForStateChangingFunctions fires on the New-* factory
        # functions in Private/, which build in-memory objects (a finding, a check
        # result, an audit context) and touch nothing outside the process.
        #
        # The rule exists to catch functions that mutate a system without asking. This
        # module cannot mutate anything: it has no write path to Microsoft Graph, and
        # tests/ReadOnly.Tests.ps1 fails the build if one is ever added. The two public
        # functions with any real side effect -- Export-M365HygieneReport, which writes
        # files, and Disconnect-M365Hygiene, which ends a session -- do implement
        # SupportsShouldProcess.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}

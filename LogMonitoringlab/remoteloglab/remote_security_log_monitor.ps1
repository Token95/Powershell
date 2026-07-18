# remote_security_log_monitor.ps1
# Student: Devon Brown
# Lab: Remote Security Event Log Monitoring
# Purpose: Remoretly query windows security log for failed logins
# and suspicious authentication activity.

clear-host

write-host "starting remote security log analysis..." -foregroundcolor cyan
write-host "student: devon brown" -foregroundcolor green
write-host "remote system: roejin.com" -foregroundcolor yellow
write-host "------------------------------------------------------------"

# remote system information
$computername = "roejin.com"
$username = "dbrown"

# report settings
$reportfolder = "c:\powershellautomationlab\remoteloglab\Reports"
$reportfile = "$reportfolder\remote_security_report.csv"

# number of previous days to search
$daysback = 7
$starttime = (get-date).adddays(-$daysback)

# authentication and security-related event ids
$eventids = @(
    4625, # failed logon
    4648, # logon attempted using explicit credentials
    4672, # special privileges assigned to a new logon
    4740, # user account locked out
    4771, # kerberos pre-authentication failed
    4776  # domain controller attempted to validate credentials
)

# create the report folder if it does not exist
if (!(test-path $reportfolder)) {

    new-item `
        -itemtype directory `
        -path $reportfolder `
        -force | out-null
}

write-host "search period: previous $daysback days"
write-host "start time: $starttime"
write-host "event ids: $($eventids -join ', ')"
write-host "------------------------------------------------------------"

# request the password securely
$credential = get-credential `
    -username $username `
    -message "enter the password for the dbrown account on roejin.com"

try {

    write-host "connecting to roejin.com..." -foregroundcolor cyan

    # remotely retrieve the selected security events
    $events = invoke-command `
        -computername $computername `
        -credential $credential `
        -erroraction stop `
        -scriptblock {

            param(
                $remoteeventids,
                $remotestarttime
            )

            get-winevent `
                -filterhashtable @{
                    logname   = "security"
                    id        = $remoteeventids
                    starttime = $remotestarttime
                } `
                -erroraction silentlycontinue

        } `
        -argumentlist $eventids, $starttime

    write-host "remote events retrieved successfully." -foregroundcolor green

    # process each event into a report-friendly format
    $reportresults = foreach ($event in $events) {

        try {

            [xml]$eventxml = $event.toxml()

            # attempt to retrieve the target user
            $targetuser = (
                $eventxml.event.eventdata.data |
                where-object {
                    $_.name -eq "TargetUserName"
                }
            )."#text"

            # attempt to retrieve the subject user
            $subjectuser = (
                $eventxml.event.eventdata.data |
                where-object {
                    $_.name -eq "SubjectUserName"
                }
            )."#text"

            # attempt to retrieve an account name
            $accountname = (
                $eventxml.event.eventdata.data |
                where-object {
                    $_.name -eq "AccountName"
                }
            )."#text"

            # select the best available username
            if ($targetuser) {

                $user = $targetuser
            }
            elseif ($subjectuser) {

                $user = $subjectuser
            }
            elseif ($accountname) {

                $user = $accountname
            }
            else {

                $user = "unknown"
            }

            # remove line breaks from the event message
            $cleanmessage = (
                $event.message `
                -replace "`r`n", " " `
                -replace "`n", " " `
                -replace "\s+", " "
            ).trim()

            [pscustomobject]@{
                Time       = $event.timecreated
                User       = $user
                "Event ID" = $event.id
                Message    = $cleanmessage
            }
        }
        catch {

            [pscustomobject]@{
                Time       = $event.timecreated
                User       = "unknown"
                "Event ID" = $event.id
                Message    = "event retrieved, but the event details could not be fully parsed."
            }
        }
    }

    if ($reportresults) {

        $reportresults |
        sort-object Time -descending |
        export-csv `
            -path $reportfile `
            -notypeinformation `
            -encoding utf8

        write-host "------------------------------------------------------------"
        write-host "security report created successfully." -foregroundcolor green
        write-host "report location: $reportfile" -foregroundcolor yellow
        write-host "events found: $($reportresults.count)" -foregroundcolor cyan
    }
    else {

        [pscustomobject]@{
            Time       = get-date
            User       = "no matching events"
            "Event ID" = "n/a"
            Message    = "no matching authentication events were found on roejin.com during the selected time period."
        } |
        export-csv `
            -path $reportfile `
            -notypeinformation `
            -encoding utf8

        write-host "------------------------------------------------------------"
        write-host "no matching security events were found." -foregroundcolor yellow
        write-host "an example report was still created." -foregroundcolor yellow
        write-host "report location: $reportfile"
    }
}
catch {

    write-host "------------------------------------------------------------"
    write-host "remote security log query failed." -foregroundcolor red
    write-host "error: $($_.exception.message)" -foregroundcolor red

    write-host ""
    write-host "check the following:" -foregroundcolor yellow
    write-host "1. verify roejin.com is online."
    write-host "2. verify the dbrown password is correct."
    write-host "3. verify powershell remoting is enabled."
    write-host "4. verify winrm is allowed through the firewall."
    write-host "5. verify dbrown can read the security event log."
    write-host "6. verify vpn or network access is active if required."
}

write-host "------------------------------------------------------------"
write-host "remote log analysis completed."
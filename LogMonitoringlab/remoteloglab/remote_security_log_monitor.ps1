# remote_security_log_monitor.ps1
# Student: Devon Brown
# Lab: Remote Security Event Log Monitoring
# Purpose: Remoretly query windows security log for failed logins
# and suspicious authentication activity.

Write-Host " Starting Remote Security Log Monitoring..." -ForegroundColor Cyan
Write-Host " Student Name: Devon Brown" -ForegroundColor Green
Write-Host "-----------------------------------------------------------------"

# Remote system settings
$computername ="Win-monitor-vm-01"
$reportfolder ="C:\PowershellAutomationLab\remoteloglab\reports"
$reportfile = "$reportfolder\remote_security_report.csv"

# Number of days of logs to review 
$daysback = 7

# Authorentication-related event IDS
$eventids = @(4624, 4625, 4648, 4672, 4740, 4771, 4776)

# Create report folder ig needed
if (!(test-path $reportfolder)) {
    new-item -itemtype directory -path $reportfolder | Out-Null
}

write-host "Remote Computer: $computername"
Write-Host "Reviewing the previous $daysback days"
write-host "Event IDs: $($eventids -join ', ')"

# Remote Credentials for the remote system
$credential = Get-Credential

try {
    $events = invoke-command `
        -ComputerName $computername `
        -Credential $credential `
        -erroraction stop `
        -scriptblock {
            
            param (
                $remoteeventids
                $remotestarttime
            )

            get-winevent -filterhashtable @{
                logname   = "Security"
                in        = $remoteeventids
                starttime = $remotestarttime
            } -erroraction SilentlyContinue

        } -argumentlist $eventids, (get-date).adddays(-$daysback)
    $reportresults = foreach ($event in $events) {
        [xml]$eventxml =$events.toxml()

        $targetuser =(

  $eventxml.event.eventdata.data |
            where-object { $_.name -eq "TargetUserName" }
        )."#text"

        $subjectuser = (
            $eventxml.event.eventdata.data |
            where-object { $_.name -eq "SubjectUserName" }
        )."#text"

        $accountname = (
            $eventxml.event.eventdata.data |
            where-object { $_.name -eq "AccountName" }
        )."#text"

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

        [pscustomobject]@{
            Time       = $event.timecreated
            User       = $user
            "Event ID" = $event.id
            Message    = (
                $event.message `
                -replace "`r`n", " " `
                -replace "`n", " "
            )
        }
    }

    if ($reportresults) {
        $reportresults |
        sort-object Time -descending |
        export-csv -path $reportfile -notypeinformation

        write-host "remote security report created successfully." -foregroundcolor green
        write-host "report saved to: $reportfile" -foregroundcolor yellow
    }
    else {
        [pscustomobject]@{
            Time       = get-date
            User       = "no matching events"
            "Event ID" = "n/a"
            Message    = "no matching authentication events were found during the selected time range."
        } | export-csv -path $reportfile -notypeinformation

        write-host "no matching events were found." -foregroundcolor yellow
        write-host "an empty report was created at: $reportfile" -foregroundcolor yellow
    }
}
catch {
    write-host "remote log query failed." -foregroundcolor red
    write-host "error: $($_.exception.message)" -foregroundcolor red
    write-host "verify winrm, credentials, firewall access, and permissions." -foregroundcolor yellow
}

write-host "-------------------------------------------------------"
write-host "remote security monitoring completed."
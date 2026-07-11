# Security_Event_Monitoring.ps1
# Student: Devon Brown
# Lab: PowerShell Security Event Log Monitoring
# Purpose: Monitor Windows/VM Server security logs for failed logins,
# privilege escalaton attemps, and suspicious accout activity.

write-host "Starting Security Event Monitoring Script..." -ForegroundColor Cyan
write-host "Student Name: Devon Brown" -ForegroundColor Green
write-host "Monitoring local Windows/VM server security logs for VLAN and edge-device support environment."
write-host "-------------------------------------------------------------"

# Report folder and output file
$reportfolder = "c:\PowershellAutomationLab\LogMonitoringLab\Reports"
$reportfile = "$reportfolder\Security_Event_Report.csv"

# Create report folder if it does not file 
if (!(test-path $reportfolder)) {
	new-item -itemtype directory -path $reportfolder | out-null
}

# Event IDs to Monitor
# 4625 = Failed logon
# 4672 = Speical privilege assigned to new logon
# 4720 = User account created
# 4728 = User added to global security-enabled group
# 4732 = User added to local security-enabled group
# 4740 = User account locked out 
$eventids = @(4625, 4672, 4720, 4728, 4732, 4740)

# Time range to search
# Change AddDays(-7) to another number if you want more or fewer days
$starttime =(get-date).adddays(-7)

write-host "Searching security logs from :$starttime"
write-host "Filtering by EventIDs: $($eventids -join ',')"
write-host "--------------------------------------------"

# Retrieve security events
$events = get-winevent -filterhashtable @{
	logname   = "Security"
	id        = $eventids
	starttime = $starttime
} -erroraction silentlycontinue	

# Parse and format results
$reportresults = foreach($event in $events) {
	
	# Coverting Events to Execl so i can pull users field more cleanly
	[xml]$eventxml =$event.toxml()
	
	# Trying to collect Common username fields from the event 
	$targetuser =($eventxml.event.eventdata.data | where-object {$_.name -eq "TargetUserName" })."#text"
	$subjectuser = ($eventxml.event.eventdata.data | where-object {$_.name -eq "SubjectUserName"})."#text"
	$accountname = ($eventxml.event.eventdata.data | where-object {$_.name -eq "AccountName"})."#text"
	
	# Create the best available user value
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

    # Develop a clean objects for the report
    [pscustomobject]@{
        time       = $event.timecreated
		user       = $user
		"Event ID" = $event.id
		message    = ($event.message -replace "`r`n, "" -replace ""`n", " ")
	}
}


# Export report
if ($reportresults) {
	$reportresults |
	sort-object time -descending |
	export-csv -path $reportfile -notypeinformation
	
	write-host "Security event report created successfully." -ForegroundColor Green
	write-host "Report saved to: $reportfile" -ForegroundColor Yellow
}
else{
	# Create an empty report with the required colums if no events are found
	[pscustomobject]@{
		time        = get-date
		user        = "No matching events found"
		"Event ID"  = "N/A"
		message     = "No failed login, privilege escalaton, account lockout, or change events were found in the selected time range."
    } | export-csv -path $reportfile -notypeinformation
	
	write-host "No matching security events were found." -ForegroundColor Yellow
	write-host "A sample report was still created at: $reportfile" -ForegroundColor Yellow
}

write-host "--------------------------------------------"
write-host "Security event monitoring completed."

# Security_Check_Report.ps1
# Student: Devon Brown
# Powershell Automation Lab

Write-Host "Running Security Check Report..." -ForegroundColor Cyan

# Set report folder and report file path
$ReportFolder = "C:\PowershellAutomationLab\Reports"
$ReportFile = "$ReportFolder\Security_Check_Report.txt"

# Create the Reports Folder if it does not already exist
if (!(Test-Path $ReportFolder)) {
	New-Item -ItemType Directory -Path $ReportFolder
}

# Start the security report
"Security Check Report" | Out-File $ReportFile
"Student Name: Devon Brown" | Out-File $ReportFile -Append
"Date: $(Get-Date)" | Out-File $ReportFile -Append
"Compuer Name: $env:COMPUTERNAME" | Out-File $ReportFile -Append
"--------------------------------------" | Out-File $ReportFile -Append

# Check Windows Firewall status
"Firewall Profile Status:" | Out-File $ReportFile -Append
Get-NetFirewallProfile | Select-Object Name, Enable | Out-File $ReportFile -Append

"------------------------------------------" | Out-File $ReportFile -Append

# Check Mircosoft Defender Status
"Microsoft Defender Status:" | Out-File $ReportFile -Append

try {
	Get-MpComputerStatus |
	Select-Object AMserviceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, Antispyware
	Out-File $ReportFile -Append
}
catch {
	"Unable to retrieve Microsoft Defender status. Try running Powershell as Admistrator."
}

"-----------------------------------------------------" | Out-File $ReportFile -Append

# Check local adminstrator accounts
"Local adminstrator Group Members." | Out-File $ReportFile -Append

try {
	Get-LocalGroupMember -Group "Admistrators" |
	sel  Name, ObjectClass | 
	Out-File $ReportFile -Append
}
catch {
	"Unable to retrieve local adminstrator group members." | Out-File $ReportFile -Append
}

"-----------------------------------------------------------------" | Out-File $ReportFile -Append

# Check running services
"Top 10 Running Services:" | Out-File $ReportFile -Append
Get-Service |
Where-Object {$_.Status -eq "Running"} |
Select-Object -First 10 Name, Status, DisplayName |
Out-File $ReportFile -Append

Write-Host "Security check report created successfully." -ForegroundColor Green
Write-Host "Report saved to :$ReportFile" -ForegroundColor Yellow
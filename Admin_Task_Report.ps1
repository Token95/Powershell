# Admin_Task_Report.ps1
# Student: Devon Brown
# Powershell Automation Lab

Write-Host "Running Admistrative Task Report..." -ForegroundColor Cyan

# Set report folder and report file path
$ReportFolder ="C:\PowershellAutomationLab\Reports"
$ReportFile = "$ReportFolder\Admin_Task_Report.txt"

# Create the Reports folder if it does not already exist
if (!(Test-Path $ReportFolder)) {
	New-Item -Itemtype Directory -Path $ReportFolder
}

# Collect basic Adminstration system information
$ComputerName =$env:ComputerName
$UserName = $env:USERNAME
$Date = Get-Date
$OSInfo = Get-CimInstance Win32_OperatingSystem
$CPUInfo = Get-CimInstance Win32_Processor
$MemoryGB = [math]::Round($OSInfo.TotalVisibleMemorySize / 1MB,2)
$FreeMemoryGB =[math]::Round($OSInfo.FreePhysicalMemory / 1MB, 2)

# Create the Report
"Admistrative Task Report" | Out-File $ReportFile
"Student Name: Devon Brown" | Out-File $ReportFile -Append
"Date: $Date" | Out-File $ReportFile -Append
"Computer Name: $ComputerName" | Out-File $ReportFile -Append
"Logged-in User: $UserName" | Out-File $ReportFile -Append
"Operating System: $($OSInfo.Caption)" | Out-File $ReportFile -Append
"OS Version: $($OSInfo.Version)" | Out-File $ReportFile -Append
"Processor: $($CPUInfo.Name)" | Out-File $ReportFile -Append
"Total Memory: $MemoryGB GB" | Out-File $ReportFile -Append
"Free Memory: $FreeMemoryGB GB" | Out-File $ReportFile -Append

Write-Host "Admistrative report created successfully." -ForegroundColor Green
Write-Host "Report saved to: $ReportFile" -ForegroundColor Yellow
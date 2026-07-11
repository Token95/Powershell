# Load asset inventory (sourced from CMDB, IPAM, CSV)
$vpnDevices = Import-Csv -Path "C:\inventory\VPN_Appliances.csv"

$vulnerableVersions = @("22.7R2", "22.7R2.1", "22.7R2.2", "22.7R2.3", "22.7R2.4")

foreach($device in $vpnDevices) {
    $currentVersion = $device.CurrentVersion # Dynamically queried in production via secure API or SNMP
    if ($currentVersion -in $vulnerableVersions -or [sting] : :IsNullOrEmpty($currentVersion)) {
        Write-Warning "Device $($device.DeviceName) $($device.IP)) is running a vulnerable version: $currentVersion"
    # Verify Integrity Chesker Tool report
    $reportPath = "C:\Reports\IntegrityChecker_$($device.DeviceName).txt"
    if (-not (Test-Path $reportPath)) {
        Write-Error "Integrity Checker report missing for $($device.DeviceName) - Investigation is needed."
    
    }
} 


# AppCheck-NG - Unofficial API Client Module Testing Script for AppCheck-NG API
# 
# API Documentation can be found at https://api.appcheck-ng.com/index.html
#
# Author: Chris Harris (chris@utopianit.co.uk)
#
# Date  : 20201125
#
## Test Script for AppCheck-NG
Remove-Module AppCheck-NG -ErrorAction SilentlyContinue
Import-Module .\AppCheck-NG.psm1 -Verbose -Force

$APIKeyPath   = '.\APIKey.txt'
if(Test-Path $APIKeyPath) {
    $APIKey       = Get-Content -Path $APIKeyPath
} else {
    write-host "No API Key file found at $APIKeyPath." -foregroundcolor Red
    write-host " - This file must contain the user specific API key provided by AppCheck-NG" -ForegroundColor Red
    throw "No API Key file found"
}

# Helper function to convert Unix Datetime to PS Datetime to work out time differences
Function Convert-FromUnixDate ($UnixDate) {
   [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($UnixDate))
}

$ScanName     = 'APITest_MySite'
$NewScanName  = 'APITest_MySite_Renamed'
$Targets      = @('https://my.site/')

# IF behind a corporate proxy. Use this following line to ensure REST calls use it. Optional to use -NoDefaultCredentials if unauthenticated Proxy.
Set-AppCheckNGCorpProxyUse

# Set the API Key and Set the API Client Mode (test or live)
Set-AppCheckNGKey -apikey $APIKey
Set-AppCheckNGMode -mode Live

####################################################################

$Scan = ''
# New-AppCheckNGScan
$Scan = New-AppCheckNGScan -Name $ScanName -targets $Targets
if($Scan.success -eq $True) {
    write-host "New-AppCheckNGScan: Scan $ScanName created successfully. Scan ID was $($Scan.scan_id)" -ForegroundColor Green
} else {
    write-host "New-AppCheckNGScan: Scan $ScanName failed to be created" -ForegroundColor Red
    #throw "Scan $ScanName failed to be created"
}

# Get-AppCheckNGScan
$ScanResults = Get-AppCheckNGScan -scanid $Scan.scan_id
if($ScanResults.message -eq 'OK' -and $ScanResults.data._id -eq $Scan.scan_id) {
    write-host "Get-AppCheckNGScan: Scan ID $($Scan.scan_id) found" -ForegroundColor Green
} else {
    write-host "Get-AppCheckNGScan: Scan ID $($Scan.scan_id) NOT found" -ForegroundColor Red
}

#Get-AppCheckNGScanProfiles
$Profile = Get-AppCheckNGScanProfiles | Where name -like 'Basic-Profile*'
if($Profile.profile_id) {
    write-host "Get-AppCheckNGScanProfiles: Profile ID $($Profile.profile_id) found matching 'Basic-Profile*'" -ForegroundColor Green
} else {
    write-host "Get-AppCheckNGScanProfiles: Profile ID matching 'Basic-Profile*' NOT found" -ForegroundColor Red
}

$ScanProfiles = Get-AppCheckNGScanProfiles
if($ScanProfiles.data.count -ge 1) {
    write-host "Get-AppCheckNGScanProfiles: Found ($($ScanProfiles.data.count)) Scan Profiles existing" -ForegroundColor Green
} else {
    write-host "Get-AppCheckNGScanProfiles: No existing Scan Profiles found" -ForegroundColor Red
}

# Update-AppCheckNGScan (PASS)
$UpdateResults = Update-AppCheckNGScan -scanid $Scan.scan_id -ProfileID $Profile.profile_id
if($UpdateResults.success -eq $True) {
    write-host "Update-AppCheckNGScan: Profile set on Scan OK" -ForegroundColor Green
} else {
    write-host "Update-AppCheckNGScan: Failed to set Profile on Scan" -ForegroundColor Red
}

# Get-AppCheckNGScanByName (PASS)
$ScanResults = Get-AppCheckNGScanByName -name $ScanName
if($ScanResults.message -eq 'OK' -and $ScanResults.data._id -eq $Scan.scan_id) {
    write-host "Get-AppCheckNGScanByName: Scan ID $($Scan.scan_id) found by name" -ForegroundColor Green
} else {
    write-host "Get-AppCheckNGScanByName: Scan ID $($Scan.scan_id) NOT found by name" -ForegroundColor Red
}

# Get-AppCheckNGScanByName (FAIL)
$ScanResults = Get-AppCheckNGScanByName -name 'Non-ExistantScanName'
if($ScanResults -eq $false) {
    write-host "Get-AppCheckNGScanByName: Bogus Scan name not found" -ForegroundColor Green
} else {
    write-host "Get-AppCheckNGScanByName: Bogus Scan name not handled as expected" -ForegroundColor Red
}

# Update-AppCheckNGScan (PASS)
$UpdateResults = Update-AppCheckNGScan -scanid $Scan.scan_id -name $NewScanName
if($UpdateResults.success -eq $True) {
    write-host "Update-AppCheckNGScan: Renamed Scan name OK (Set to $NewScanName)" -ForegroundColor Green
} else {
    write-host "Update-AppCheckNGScan: Rename of Scan failed (Set to $NewScanName)" -ForegroundColor Red
}

# Get-AppCheckNGScanByName (PASS)
$ScanResults = Get-AppCheckNGScanByName -name $NewScanName
if($ScanResults.success -eq $True) {
    write-host "Get-AppCheckNGScanByName: New Scan name ($NewScanName) found" -ForegroundColor Green
} else {
    write-host "Get-AppCheckNGScanByName: New Scan name not found" -ForegroundColor Red
}

# Get-AppCheckNGScanHubs
$ScanHubs = Get-AppCheckNGScanHubs
if($ScanHubs.scan_hubs.count -ge 1) {
    write-host "Get-AppCheckNGScanHubs: Scan Hubs ($($ScanHubs.scan_hubs.count)) Returned OK" -ForegroundColor Green
    $ScanHubs.scan_hubs
} else {
    write-host "Get-AppCheckNGScanHubs: Scan Hubs failed to be returned" -ForegroundColor Red
}

# Start-AppCheckNGScan
$StartScan = Start-AppCheckNGScan -ScanID $Scan.scan_id
if($StartScan.success -eq $True) {
    write-host "Start-AppCheckNGScan: Scan started OK" -ForegroundColor Green
    write-host "...Waiting 10 seconds while scan starts..." -ForegroundColor Magenta
    Start-Sleep 10
} else {
    write-host "Start-AppCheckNGScan: Scan failed to be started" -ForegroundColor Red
}

# Watch-AppCheckNGScan - Watch Scan for a max of 300 seconds. Will return once COMPLETED or timeout is reached
Watch-AppCheckNGScan -ScanID $ScanResults.data._id -Timeout 5 -Frequency 10 -MaxFailedChecks 3

# Report on Vulnerabilities (Completed or not)
$LatestScanRun = Get-AppCheckNGScanRunLatest -ScanID $ScanResults.data._id
if($LatestScanRun.status -eq 'COMPLETED' -or $LatestScanRun.status -eq 'RUNNING') {
    $ScanVulns = Get-AppCheckNGScanRunVulns -ScanID $ScanResults.data._id -RunID $LatestScanRun.run_id -IncludeInfo
    if($ScanVulns.count -ge 1) {
        write-host "Get-AppCheckNGScanRunVulns: Scan Status is $($LatestScanRun.status). Found $($ScanVulns.count) Vulnerabilities" -ForegroundColor Green
        $ScanVulns.data | Out-String
    } else {
        write-host "Get-AppCheckNGScanRunVulns: Scan Status is $($LatestScanRun.status). Found NO Vulnerabilities" -ForegroundColor Green
    }
}

$VulnResults = Get-AppCheckNGVulns -Short
if($VulnResults.count -ge 1) {
    write-host "Get-AppCheckNGVulns: Found ($($VulnResults.count)) vulnerabilities on existing scans" -ForegroundColor Green
} else {
    write-host "Get-AppCheckNGVulns: No existing vulnerabilities found" -ForegroundColor Red
}

#$FilteredVulnResults = Get-AppCheckNGScanVulns -Severity high -scanid

# Stop-AppCheckNGScan
$Status = Stop-AppCheckNGScan -ScanID $ScanResults.data._id

# Remove-AppCheckNGScanByName
$ScanResults = Remove-AppCheckNGScanByName -name $NewScanName

write-host "DONE" -ForegroundColor Green

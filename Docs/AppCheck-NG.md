# AppCheck-NG API Client PowerShell Module (AppCheck-NG) 

## [Delete-AppCheckNGScanRun]
## Synopsis
Remove (Delete) a Run of an existing Scan Definition 

## Syntax
```PowerShell
Remove-AppCheckNGScanRun [-ScanID] <String> [-RunID] <String> [<CommonParameters>]
```
## Description
Delete a Run of an existing Scan Definition.
Returns true or false depending on success status.

## Parameters
### ScanID

ID of the Scan to remove the Run from





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 1
- **Required**: true
### RunID

ID of the Run to remove





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 2
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Remove-AppCheckNGScanRun -ScanID '0123456789abcdef' -RunID '6d9a2783bc0145ef'
```














###  Example 2 
```PowerShell
Delete-AppCheckNGScanRun -ScanID '0123456789abcdef' -RunID '6d9a2783bc0145ef'
```













## [Pause-AppCheckNGScan]
## Synopsis
Suspend (Pause) a single Scan 

## Syntax
```PowerShell
Suspend-AppCheckNGScan [-ScanID] <String> [<CommonParameters>]
```
## Description
Pause a Scan and Returns true or false depending on success. 
POST /api/v1/(api_key)/scan/(scan_id)/pause

## Parameters
### ScanID

ID of the Scan to be suspended





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Suspend-AppCheckNGScan -ScanID '0123456789abcdef'
```














###  Example 2 
```PowerShell
Pause-AppCheckNGScan -ScanID '0123456789abcdef'
```













## [Delete-AppCheckNGScan]
## Synopsis
Delete a single Scan Definition 

## Syntax
```PowerShell
Delete-AppCheckNGScan [-ScanID] <String> [<CommonParameters>]
```
## Description
Deletes a Scan Definition and Returns true or false depending on success.
POST /api/v1/(api_key)/scan/(scan_id)/delete

## Parameters
### ScanID

ID of the Scan to be deleted





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Delete-AppCheckNGScan -ScanID '0123456789abcdef'
```













## [Delete-AppCheckNGVuln]
## Synopsis
Delete a Vulnerability 

## Syntax
```PowerShell
Delete-AppCheckNGVuln [-VulnID] <String> [<CommonParameters>]
```
## Description
Deletes a Vulnerability based on the ID. This Vulnerability is associated with a Scan.
POST /api/v1/(api_key)/vulnerability/(vuln_id)/delete

## Parameters
### VulnID

ID of the Vulnerability to be deleted





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Delete-AppCheckNGVuln -Vuln '5a597bf3af963f118022e08429bc076e437442ba'
```













## [Get-AppCheckNGScan]
## Synopsis
Gets a specific scan 

## Syntax
```PowerShell
Get-AppCheckNGScan [-ScanID] <String> [<CommonParameters>]
```
## Description
Gets the status for a specific Scan.
GET /api/v1/(api_key)/scan/(scan_id)

## Parameters
### ScanID

ID of the Scan to get details of





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGScan -ScanID '0123456789abcdef'
```













## [Get-AppCheckNGScanByName]
## Synopsis
Gets a specific scan by name rather than scan ID 

## Syntax
```PowerShell
Get-AppCheckNGScanByName [-Name] <String> [-UseLike] [<CommonParameters>]
```
## Description
Get a specific scan by name where the scan definition EQUALS the name.
To have the search done with wildcards, use the -UseLike switch.
WARNING: Be careful not to feed or pipe the results into a Delete operation 
without being sure of the results as if -UseLike is set, you may end up deleting more than intended!

## Parameters
### Name

Mandatory String of the name to search for scans with a matching definition name





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
### UseLike

Optional switch to use -LIKE comparison rather than -EQuals. This allows for wildcards in the name paramater





- **Type**: SwitchParameter
- **DefaultValue**: False
- **ParameterValue**: SwitchParameter
- **PipelineInput**: false
- **Position**: named
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGScanByName -Name 'PetShop-DevelopmentSite'
```














###  Example 2 
```PowerShell
Get-AppCheckNGScanByName -Name 'PetShop-*' -UseLike
```













## [Get-AppCheckNGScanHubs]
## Synopsis
Get a list of the AppCheck Scan Hubs for your instance 

## Syntax
```PowerShell
Get-AppCheckNGScanHubs [<CommonParameters>]
```
## Description
Returns an object containing the Scan Hub details including the ScanHub_ID that can be used when creating or updating a Scan Definition.
GET /api/v1/(api_key)/scan/hubs

## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGScanHubs
```













## [Get-AppCheckNGScanProfiles]
## Synopsis
Get ALL Scan Peofiles from the AppCheck instance 

## Syntax
```PowerShell
Get-AppCheckNGScanProfiles [<CommonParameters>]
```
## Description
Gets an object containing all of the Scan Profiles.
GET /api/v1/(api_key)/scanprofiles

## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGScanProfiles
```













## [Get-AppCheckNGScanRun]
## Synopsis
Get details of a specific Scan Run 

## Syntax
```PowerShell
Get-AppCheckNGScanRun [-ScanID] <String> [-RunID] <String> [<CommonParameters>]
```
## Description
Gets the details of a specific Run of a specific Scan.
GET /api/v1/(api_key)/scan/(scan_id)/run/(run_id)

## Parameters
### ScanID

ID of the Scan to get details of the Run





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 1
- **Required**: true
### RunID

ID of the Run to get details of





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 2
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGScanRun -ScanID '0123456789abcdef' -RunID 'b3c3866b74f24cd5'
```













## [Get-AppCheckNGScanRunLatest]
## Synopsis

Get-AppCheckNGScanRunLatest [-ScanID] <string> [<CommonParameters>]
 

## Syntax
```PowerShell
syntaxItem                                                                                                             
----------                                                                                                             
{@{name=Get-AppCheckNGScanRunLatest; CommonParameters=True; WorkflowCommonParameters=False; parameter=System.Object[]}}
```
## Parameters
### ScanID


- **Type**: string
- **ParameterValue**: string
- **PipelineInput**: true (ByPropertyName)
- **Position**: 0
- **Required**: true
## [Get-AppCheckNGScanRuns]
## Synopsis
Gets a list of all Runs for a specific Scan 

## Syntax
```PowerShell
Get-AppCheckNGScanRuns [-ScanID] <String> [[-Status] <String>] [<CommonParameters>]
```
## Description
Gets a list of all Runs for a specific Scan.
Use Get-AppCheckNGScanRunLatest to get the most recent Run, irrespective of the Status.
GET /api/v1/(api_key)/scan/(scan_id)/runs

## Parameters
### ScanID

ID of the Scan to return the Runs for





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
### Status

Optional status field to filter by ('RUNNING','PAUSED','ABORTED','DETACHED','COMPLETED','FAILED')





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 2
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGScanRuns -ScanID '0123456789abcdef'
```













## [Get-AppCheckNGScanRunVulns]
## Synopsis
Gets a list of Vulnerabilities for a specific Scan Run 

## Syntax
```PowerShell
Get-AppCheckNGScanRunVulns [-ScanID] <String> [-RunID] <String> [[-Status] <String>] [[-Severity] <String>] [[-CVSS] <Int32>] [-IncludeInfo] [<CommonParameters>]
```
## Description
Gets a list of Vulnerabilities for a specific Scan Run.
GET /api/v1/(api_key)/scan/(scan_id)/run/(run_id)/vulnerabilities

## Parameters
### ScanID

ID of the Scan to list the vulnerabilities of





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 1
- **Required**: true
### RunID

ID of the Run to list the vulnerabilities of





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 2
- **Required**: true
### Status

Optional Status parameter to filter by ('unfixed','fixed','false_positive','acceptable_risk')





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 3
- **Required**: false
### Severity

Optional Severity parameter to filter by ('info','low','medium','high')





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 4
- **Required**: false
### CVSS

Optional integer based CVSS parameter to filter by a CVSS score limit





- **Type**: Int32
- **DefaultValue**: 0
- **ParameterValue**: Int32
- **PipelineInput**: false
- **Position**: 5
- **Required**: false
### IncludeInfo

Optional switch IncludeInfo to include more detailed information about the Vulnerability





- **Type**: SwitchParameter
- **DefaultValue**: False
- **ParameterValue**: SwitchParameter
- **PipelineInput**: false
- **Position**: named
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGScanRunVulns -ScanID '0123456789abcdef' -RunID '74bbcd2fc4686335'
```














###  Example 2 
```PowerShell
Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -RunID '74bbcd2fc4686335' -Status 'unfixed'
```














###  Example 3 
```PowerShell
Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -RunID '74bbcd2fc4686335' -Severity 'high'
```














###  Example 4 
```PowerShell
Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -RunID '74bbcd2fc4686335' -CVSS 7
```













## [Get-AppCheckNGScans]
## Synopsis
Get ALL Scans from the AppCheck instance 

## Syntax
```PowerShell
Get-AppCheckNGScans [<CommonParameters>]
```
## Description
Gets an object containing all of the Scan Definitions.
Used in Get-AppCheckNGScanByName to filter by name of a specific Scan Definition.
GET /api/v1/(api_key)/scans

## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGScans
```














###  Example 2 
```PowerShell
$Name = 'Scan-I-Really-Want'
```

$Scan = $(Get-AppCheckNGScans).data | Where name -eq $Name | Select scan_id











## [Get-AppCheckNGScanStatus]
## Synopsis
Gets the status of a scan 

## Syntax
```PowerShell
Get-AppCheckNGScanStatus [-ScanID] <String> [<CommonParameters>]
```
## Description
Gets the status for a specific Scan.
GET /api/v1/(api_key)/scan/(scan_id)/status

## Parameters
### ScanID

ID of the Scan to list the status of





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGScanStatus -ScanID '0123456789abcdef'
```













## [Get-AppCheckNGScanVulns]
## Synopsis
Gets a list of Vulnerabilities for a specific Scan 

## Syntax
```PowerShell
Get-AppCheckNGScanVulns [-ScanID] <String> [[-Status] <String>] [[-Severity] <String>] [[-CVSS] <Int32>] [-IncludeInfo] [<CommonParameters>]
```
## Description
Gets a list of Vulnerabilities for a specific Scan.
GET /api/v1/(api_key)/scan/(scan_id)/vulnerabilities

## Parameters
### ScanID

ID of the Scan to list the vulnerabilities of





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
### Status

Optional Status parameter to filter by ('unfixed','fixed','false_positive','acceptable_risk')





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 2
- **Required**: false
### Severity

Optional Severity parameter to filter by ('info','low','medium','high')





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 3
- **Required**: false
### CVSS

Optional integer based CVSS parameter to filter by a CVSS score limit





- **Type**: Int32
- **DefaultValue**: 0
- **ParameterValue**: Int32
- **PipelineInput**: false
- **Position**: 4
- **Required**: false
### IncludeInfo

Optional switch IncludeInfo to include more detailed information about the Vulnerability





- **Type**: SwitchParameter
- **DefaultValue**: False
- **ParameterValue**: SwitchParameter
- **PipelineInput**: false
- **Position**: named
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGScanVulns -ScanID '0123456789abcdef'
```














###  Example 2 
```PowerShell
Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -Status 'unfixed'
```














###  Example 3 
```PowerShell
Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -Severity 'high'
```














###  Example 4 
```PowerShell
Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -CVSS 7
```













## [Get-AppCheckNGVuln]
## Synopsis
Gets a specific vulnerability 

## Syntax
```PowerShell
Get-AppCheckNGVuln [-VulnID] <String> [<CommonParameters>]
```
## Description
Gets the details for a specific vulnerability.
GET /api/v1/(api_key)/vulnerability/(vulnerability_id)

## Parameters
### VulnID

ID of the Vulnerability to get details of





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGVuln -Vuln '5a597bf3af963f118022e08429bc076e437442ba'
```













## [Get-AppCheckNGVulns]
## Synopsis
Gets a list of ALL Vulnerabilities 

## Syntax
```PowerShell
Get-AppCheckNGVulns [[-Status] <String>] [-Short] [[-Severity] <String>] [[-CVSS] <Int32>] [-IncludeInfo] [<CommonParameters>]
```
## Description
Gets a list of all Vulnerabilities from the instance
GET /api/v1/(api_key)/vulnerabilities

## Parameters
### Status

Optional Status parameter to filter by ('unfixed','fixed','false_positive','acceptable_risk')





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 1
- **Required**: false
### Short

Optional switch Short to only list Short information about the Vulnerabilities





- **Type**: SwitchParameter
- **DefaultValue**: False
- **ParameterValue**: SwitchParameter
- **PipelineInput**: false
- **Position**: named
- **Required**: false
### Severity

Optional Severity parameter to filter by ('info','low','medium','high')





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 2
- **Required**: false
### CVSS

Optional integer based CVSS parameter to filter by a CVSS score limit





- **Type**: Int32
- **DefaultValue**: 0
- **ParameterValue**: Int32
- **PipelineInput**: false
- **Position**: 3
- **Required**: false
### IncludeInfo

Optional switch IncludeInfo to include more detailed information about the Vulnerability





- **Type**: SwitchParameter
- **DefaultValue**: False
- **ParameterValue**: SwitchParameter
- **PipelineInput**: false
- **Position**: named
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
Get-AppCheckNGVulns
```














###  Example 2 
```PowerShell
Get-AppCheckNGVulns -Status 'unfixed'
```














###  Example 3 
```PowerShell
Get-AppCheckNGVulns -Severity 'high'
```














###  Example 4 
```PowerShell
Get-AppCheckNGVulns -CVSS 7
```













## [Invoke-AppCheckNGREST]
## Synopsis
Helper function to make REST call. 

## Syntax
```PowerShell
Invoke-AppCheckNGREST [-Uri] <String> [-Method] <String> [[-Body] <Object>] [[-Headers] <Object>] [<CommonParameters>]
```
## Description
Helper function to make REST call which validates input, controls output and logs.
Uses $script:AppCheckNGUserAgent for the User Agent header (polite API client).
Uses $script:AppCheckNGRESTTimeout as a timeout for the REST call.
Function is generally not used outside of the Module.
Logs to path defined in $script:AppCheckNGLogPath

## Parameters
### Uri

Full URI used for the REST call complete with protocol, domain, path and query parameters as required





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
### Method

The HTTP methods supported are GET and POST only





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 2
- **Required**: true
### Body

The Body of the HTTP Request. Used when making POST calls





- **Type**: Object
- **ParameterValue**: Object
- **PipelineInput**: false
- **Position**: 3
- **Required**: false
### Headers

The Headers of the HTTP Request. Used when making POST calls as determines the Accept-Encoding





- **Type**: Object
- **ParameterValue**: Object
- **PipelineInput**: false
- **Position**: 4
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
Invoke-AppCheckNGREST -Uri $uri -Method POST -Body 'name=test&profile_id=12345678abc' -Headers $MyHeaders
```













## [New-AppCheckNGScan]
## Synopsis
Creates a new AppCheck Scan Definition 

## Syntax
```PowerShell
New-AppCheckNGScan [-Name] <String> [-Targets] <String[]> [[-ProfileID] <String>] [[-ScanHub] <String>] [<CommonParameters>]
```
## Description
Creates a new AppCheck Scan Definition based on a number of parameters.
The Name and Target(s) are mandatory but ProfileID and ScanHub can be set later using the Update-AppCheckNGScan function
POST /api/v1/(api_key)/scan/new

## Parameters
### Name

Name of the Scan Definition to Create





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
### Targets

List of Target URLs, IP addresses or hostnames to target with the scan.





- **Type**: String[]
- **ParameterValue**: String[]
- **PipelineInput**: false
- **Position**: 2
- **Required**: true
### ProfileID

ID of the Profile to assign to the scan





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 3
- **Required**: false
### ScanHub

ID of the ScanHub to assign to the scan. This is often already set in the Profile but can be overridden by the Scan Definition





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 4
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
New-AppCheckNGScan -Name 'MyNewScan' -Targets @('http://mynewwebsite.com','10.1.3.4')
```













## [Remove-AppCheckNGScanByName]
## Synopsis
Removes a specific scan by name rather than scan ID 

## Syntax
```PowerShell
Remove-AppCheckNGScanByName [-Name] <String> [<CommonParameters>]
```
## Description
Get a specific scan by name where the scan definition EQUALS the name.
To have the search done with wildcards, use the Get-AppCheckNGScanByName with the -UseLike switch first.
WARNING: There is no -UseLike switch for this service function for a reason as all scans could then be deleted by specifying the name as '*'!
Returns true or false depending on success.

## Parameters
### Name

Mandatory String of the name to search for scans with a matching definition name





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Remove-AppCheckNGScanByName -Name 'PetShop-DevelopmentSite'
```













## [Remove-AppCheckNGScanRun]
## Synopsis
Remove (Delete) a Run of an existing Scan Definition 

## Syntax
```PowerShell
Remove-AppCheckNGScanRun [-ScanID] <String> [-RunID] <String> [<CommonParameters>]
```
## Description
Delete a Run of an existing Scan Definition.
Returns true or false depending on success status.

## Parameters
### ScanID

ID of the Scan to remove the Run from





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 1
- **Required**: true
### RunID

ID of the Run to remove





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 2
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Remove-AppCheckNGScanRun -ScanID '0123456789abcdef' -RunID '6d9a2783bc0145ef'
```














###  Example 2 
```PowerShell
Delete-AppCheckNGScanRun -ScanID '0123456789abcdef' -RunID '6d9a2783bc0145ef'
```













## [Resume-AppCheckNGScan]
## Synopsis
Resume a previous paused or suspended Scan 

## Syntax
```PowerShell
Resume-AppCheckNGScan [-ScanID] <String> [<CommonParameters>]
```
## Description
Resume a Scan and Returns true or false depending on success.
POST /api/v1/(api_key)/scan/(scan_id)/resume

## Parameters
### ScanID

ID of the Scan to be resumed





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Resume-AppCheckNGScan -ScanID '0123456789abcdef'
```













## [Set-AppCheckNGCorpProxyUse]
## Synopsis
Sets the PowerShell session to use a Corporate or Default Forward Proxy 

## Syntax
```PowerShell
Set-AppCheckNGCorpProxyUse [-NoDefaultCredentials] [<CommonParameters>]
```
## Description
Ensure that Invoke-RestMethod accesses the Internet via a Corporate Proxy.
Relies on current user IE Proxy settings.
Set to use default proxy creds when making internet calls.
If a transparent Proxy is in use, this should not be required.
If the Proxy does not need authentication, then the -NoDefaultCredentials switch can be added.

## Parameters
### NoDefaultCredentials

An optional switch to attempt to use the Proxy without credentials being provided.
If the proxy requests authentication to access the API endpoint (HTTP 401), proxy access will fail.
This is mainly for use where the API endpoint has been whitelisted for no-authentication.





- **Type**: SwitchParameter
- **DefaultValue**: False
- **ParameterValue**: SwitchParameter
- **PipelineInput**: false
- **Position**: named
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
Set-AppCheckNGCorpProxyUse
```













## [Set-AppCheckNGKey]
## Synopsis
Sets the AppCheckNG API Key 

## Syntax
```PowerShell
Set-AppCheckNGKey [-apikey] <String> [<CommonParameters>]
```
## Description
This function sets the API key for use by the REST calls. The API is also validated by Validate-AppCheckNGKey function when setting.

## Parameters
### apikey

This parameter is a string of the API Key itself.
This is a 32 character, per user API key as provided by AppCheck-NG





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Set-AppCheckNGKey -apikey 'abcdef123456789abcdef123456789ab'
```













## [Set-AppCheckNGMode]
## Synopsis
Sets the mode that the script should work in. Test or Live. 

## Syntax
```PowerShell
Set-AppCheckNGMode [-mode] <String> [<CommonParameters>]
```
## Description
Sets the mode for the script to work in and sets the AppCheckNGTestMode script variable.
Default is FALSE so Default mode for the script is LIVE.

## Parameters
### mode

if 'test', the module will NOT make REST calls but will merely log them for testing purposes.
if 'live', the module WILL make REST calls and talk to the AppCheckNG API endpoint





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Set-AppCheckNGMode -mode test
```














###  Example 2 
```PowerShell
Set-AppCheckNGMode -mode live
```













## [Start-AppCheckNGScan]
## Synopsis
Start a single Scan. Creates a new Scan Run that can be queried 

## Syntax
```PowerShell
Start-AppCheckNGScan [-ScanID] <String> [<CommonParameters>]
```
## Description
Starts a Scan Definition and Returns true or false depending on success.
POST /api/v1/(api_key)/scan/(scan_id)/start

## Parameters
### ScanID

ID of the Scan to be started





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Start-AppCheckNGScan -ScanID '0123456789abcdef'
```













## [Stop-AppCheckNGScan]
## Synopsis
Stop (Abort) a single Scan 

## Syntax
```PowerShell
Stop-AppCheckNGScan [-ScanID] <String> [<CommonParameters>]
```
## Description
Stop a Scan and Returns true or false depending on success.
POST /api/v1/(api_key)/scan/(scan_id)/abort

## Parameters
### ScanID

ID of the Scan to be stopped





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Stop-AppCheckNGScan -ScanID '0123456789abcdef'
```













## [Suspend-AppCheckNGScan]
## Synopsis
Suspend (Pause) a single Scan 

## Syntax
```PowerShell
Suspend-AppCheckNGScan [-ScanID] <String> [<CommonParameters>]
```
## Description
Pause a Scan and Returns true or false depending on success. 
POST /api/v1/(api_key)/scan/(scan_id)/pause

## Parameters
### ScanID

ID of the Scan to be suspended





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
## Examples 


###  Example 1 
```PowerShell
Suspend-AppCheckNGScan -ScanID '0123456789abcdef'
```














###  Example 2 
```PowerShell
Pause-AppCheckNGScan -ScanID '0123456789abcdef'
```













## [Update-AppCheckNGScan]
## Synopsis
Updates an existing AppCheck Scan Definition 

## Syntax
```PowerShell
Update-AppCheckNGScan [-ScanID] <String> [[-Name] <String>] [[-Targets] <String[]>] [[-ProfileID] <String>] [[-ScanHub] <String>] [<CommonParameters>]
```
## Description
Updates a AppCheck Scan Definition based on a number of parameters.
The ScanID is mandatory but all others are optional, however at least one must be supplied.
POST /api/v1/(api_key)/scan/(scan_id)/update

## Parameters
### ScanID

Mandatory ID of the Scan Definition to Update





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
### Name

Name of the Scan Definition to Update





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 2
- **Required**: false
### Targets

List of Target URLs, IP addresses or hostnames to target with the scan.





- **Type**: String[]
- **ParameterValue**: String[]
- **PipelineInput**: false
- **Position**: 3
- **Required**: false
### ProfileID

ID of the Profile to assign to the scan





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 4
- **Required**: false
### ScanHub

ID of the ScanHub to assign to the scan. This is often already set in the Profile but can be overridden by the Scan Definition





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 5
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
Update-AppCheckNGScan -ScanID '0123456789abcdef' -Name 'MyNewScan_Renamed' -Targets @('http://mynewwebsite.com','10.1.3.4')
```













## [Update-AppCheckNGVuln]
## Synopsis
Update the status of a Vulnerability 

## Syntax
```PowerShell
Update-AppCheckNGVuln [-VulnID] <String> [-Notes] <String> [[-Priority] <String>] [[-Status] <String>] [<CommonParameters>]
```
## Description
Update a Vulnerability status or add notes.
POST /api/v1/(api_key)/vulnerability/(vulnerability_id)/update

## Parameters
### VulnID

ID of the Vulnerability too be updated





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 1
- **Required**: true
### Notes

Notes for the Vulnerability





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: true (ByPropertyName)
- **Position**: 2
- **Required**: true
### Priority

Priority of the Vulnerability ('low','medium','high')





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 3
- **Required**: false
### Status

Status to give of the Vulnerability ('unfixed','fixed','false_positive','acceptable_risk')





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 4
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
Update-AppCheckNGVuln -VulnID '0123456789abcdef'
```













## [Watch-AppCheckNGScan]
## Synopsis
Watches a specific scan given a scan ID 

## Syntax
```PowerShell
Watch-AppCheckNGScan [-ScanID] <String> [[-Timeout] <Int32>] [[-Frequency] <Int32>] [[-MaxFailedChecks] <Int32>] [<CommonParameters>]
```
## Description
Monitors the status of a specific scan for a period of time by checking and reporting every 30 seconds (by default).
This service function outputs the current status and how long the scan has been running for.
The scan will continue to be watched while the status is 'RUNNING'.
If the scan becomes COMPLETED status then the watch exits.
If the scan becomes 'PAUSED', 'ABORTED', 'DETACHED' or 'FAILED' then the watch exits.
If the timeout is exceeded then the watch exits.

## Parameters
### ScanID

ID of the scan required to be watched





- **Type**: String
- **ParameterValue**: String
- **PipelineInput**: false
- **Position**: 1
- **Required**: true
### Timeout

Optional Integer of the number of minutes to watch for a COMPLETED scan. If the timeout is exceeded, the watch just exits. 
If the scan is COMPLETED, the watch also exits. The Default Timeout is 5 minutes which is generally insufficient to 
see a full completed scan, but adequate for testing. This will often need to be set to something like 180 (or higher) to 
be given a timeout of 3 hours.





- **Type**: Int32
- **DefaultValue**: 0
- **ParameterValue**: Int32
- **PipelineInput**: false
- **Position**: 2
- **Required**: false
### Frequency

Optional Integer of the number of seconds to wait before checking the status again. Default is 30 seconds.





- **Type**: Int32
- **DefaultValue**: 0
- **ParameterValue**: Int32
- **PipelineInput**: false
- **Position**: 3
- **Required**: false
### MaxFailedChecks

Optional Integer of the maximum number of failed attempts to check on the scan status before aborting





- **Type**: Int32
- **DefaultValue**: 0
- **ParameterValue**: Int32
- **PipelineInput**: false
- **Position**: 4
- **Required**: false
## Examples 


###  Example 1 
```PowerShell
Watch-AppCheckNGScan -ScanID '0123456789abcdef'
```














###  Example 2 
```PowerShell
Watch-AppCheckNGScan -ScanID '0123456789abcdef' -TimeOut 180 -Frequency 60 -MaxFailedChecks 10
```















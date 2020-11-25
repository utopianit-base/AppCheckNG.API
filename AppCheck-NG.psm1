# AppCheck-NG - Unofficial API Client Module for AppCheck-NG API
# 
# API Documentation can be found at https://api.appcheck-ng.com/index.html
#
# Author: Chris Harris (chris@utopianit.co.uk)
#
# Date  : 20201125
#
$script:AppCheckNGClientVersion    = '20201125'
$script:AppCheckNGBaseUri          = "https://api.appcheck-ng.com/api/v1"
$script:AppCheckNGTestMode         = $false
$script:AppCheckNGUnavailableError = 'unavailable'
$script:AppCheckNGUserAgent        = "PS-AppCheckNG-API-Client_v$script:AppCheckNGClientVersion"
$script:AppCheckNGRESTTimeout      = 120 # Seconds for timeout
$script:AppCheckNGLogPath          = './AppCheck-NG_REST.log'

$script:AppCheckNGInvokeParams = @{ # Header Params used for POST requests
     'Accept-Encoding' = 'identity'
}

#########################################################################################
# Function List
#########################################################################################
# * Scan Configuration (https://api.appcheck-ng.com/apidoc-00.html)
#  - New-AppCheckNGScan
#  - Update-AppCheckNGScan
#  - Get-AppCheckNGHubs
#  - Delete-AppCheckScan

#  - New-AppCheckNGScan
#  - Update-AppCheckNGScan
#  - Get-AppCheckNGScanHubs
#  - Delete-AppCheckNGScan
#  - Start-AppCheckNGScan
#  - Stop-AppCheckNGScan
#  - Pause-AppCheckNGScan
#  - Resume-AppCheckNGScan
#  - Remove-AppCheckNGScanRun
#  - Update-AppCheckNGVuln
#  - Delete-AppCheckNGVuln
#  - Get-AppCheckNGScans
#  - Get-AppCheckNGScanProfiles
#  - Get-AppCheckNGScanRuns
#  - Get-AppCheckNGVulns
#  - Get-AppCheckNGScanVulns
#  - Get-AppCheckNGScanRunVulns
#  - Get-AppCheckNGScanStatus
#  - Get-AppCheckNGScan
#  - Get-AppCheckNGScanRun
#  - Get-AppCheckNGVuln

# * Service Functions
#  - Set-AppCheckNGKey
#  - Set-AppCheckNGMode
#  - Set-AppCheckNGCorpProxyUse
#  - Get-AppCheckNGScanByName
#  - Remove-AppCheckNGScanByName
#  - Watch-AppCheckNGScan
#  - Get-AppCheckNGScanRunLatest
#
# * Private Functions
#  - Invoke-AppCheckNGREST
#  - URL-Encode
#  - Add-FormParam
#
#########################################################################################

# Set the AppCheck API Key for the script to use. This is then pre-validated
Function Set-AppCheckNGKey {
    <#
        .SYNOPSIS
        Sets the AppCheckNG API Key

        .PARAMETER apikey
        This parameter is a string of the API Key itself.
        This is a 32 character, per user API key as provided by AppCheck-NG

        .DESCRIPTION
        This function sets the API key for use by the REST calls. The API is also validated by Validate-AppCheckNGKey function when setting.

        .EXAMPLE 
        Set-AppCheckNGKey -apikey 'abcdef123456789abcdef123456789ab'
    #>
     param(
             # API Key to use for access
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$apikey
     )
     if(Validate-AppCheckNGKey($apikey)) { 
        $script:AppCheckNGKey = $apikey
     } else {
        write-error 'Invalid API Key provided'
     }
}

# Validate the AppCheck API Key.
Function Validate-AppCheckNGKey {
    <#
        .SYNOPSIS
        Validates the AppCheckNG API Key

        .PARAMETER apikey
        This optional parameter is a string of the API Key itself.
        If not provided, it uses the script AppCheckNGKey variable instead which is set using Set-AppCheckNGKey
        This is a 32 character, per user API key as provided by AppCheck-NG

        .DESCRIPTION
        This function validates the API key for use by the REST calls.

        .EXAMPLE 
        Validate-AppCheckNGKey -apikey 'abcdef123456789abcdef123456789ab'
    #>
    param(
             # Optional API Key to validate
         [Parameter()]
         [string]$apikey        
    )
    if($apikey -ne ''){
        #write-host "Using provided API Key"
        $testapikey = [string]$apikey
    } else {
        #write-host "Using script API Key"
        $testapikey = [string]$script:AppCheckNGKey
    }
    
    if($testapikey.Length -eq 32) { 
        return $true
     } else {
        # Only report error if not called by set-appcheckngkey
        if($apikey -eq '') {
            write-error "Invalid API Key provided ($testapikey)"
        }
        return $false
     }
}

# Set Mode for the script. Either Test or Live.
# If live, REST calls are made. If test, proposed REST calls are logged.
Function Set-AppCheckNGMode {
    <#
        .SYNOPSIS
        Sets the mode that the script should work in. Test or Live.

        .PARAMETER mode
        if 'test', the module will NOT make REST calls but will merely log them for testing purposes.
        if 'live', the module WILL make REST calls and talk to the AppCheckNG API endpoint

        .DESCRIPTION
        Sets the mode for the script to work in and sets the AppCheckNGTestMode script variable.
        Default is FALSE so Default mode for the script is LIVE.

        .EXAMPLE 
        Set-AppCheckNGMode -mode test

        .EXAMPLE 
        Set-AppCheckNGMode -mode live

    #>
     param(
         # Set Mode for the script
         [Parameter(Mandatory)]
         [ValidateSet('test','live')]
         [string]$mode
     )

     if($mode -eq 'test') {
        $script:AppCheckNGTestMode = $true
        write-host "TESTMODE ENABLED" -ForegroundColor Magenta
     } else{
        $script:AppCheckNGTestMode = $false
        write-verbose "LIVEMODE ENABLED"
     }
}

# Custom version of Invoke-RESTMethod to better control output for each call
function Invoke-AppCheckNGREST {
    <#
        .SYNOPSIS
        Helper function to make REST call.

        .PARAMETER Uri
        Full URI used for the REST call complete with protocol, domain, path and query parameters as required

        .PARAMETER Method
        The HTTP methods supported are GET and POST only

        .PARAMETER Body
        The Body of the HTTP Request. Used when making POST calls

        .PARAMETER Headers
        The Headers of the HTTP Request. Used when making POST calls as determines the Accept-Encoding    

        .DESCRIPTION
        Helper function to make REST call which validates input, controls output and logs.
        Uses $script:AppCheckNGUserAgent for the User Agent header (polite API client).
        Uses $script:AppCheckNGRESTTimeout as a timeout for the REST call.
        Function is generally not used outside of the Module.
        Logs to path defined in $script:AppCheckNGLogPath

        .EXAMPLE 
        Invoke-AppCheckNGREST -Uri $uri -Method POST -Body 'name=test&profile_id=12345678abc' -Headers $MyHeaders
    #>
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Uri,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('GET','POST')]
        [string]$Method,
        [Parameter()]
        [object]$Body,
        [Parameter()]
        [Alias('Header')]
        [object]$Headers
        )

    [PSCustomObject]$SetItem = @{}
    $SetItem.Add('DateTime',$(Get-Date -Format 'yyyyMMdd-HH:mm:ss.ff'))
    $SetItem.Add('Uri',$Uri)
    $SetItem.Add('Method',$Method)
    $SetItem.Add('Body',$Body)
    $SetItem.Add('Headers',$Headers)
    $SetItem.Add('TimeOut',$script:AppCheckNGRESTTimeout)
    $SetItem.Add('UserAgent',$script:AppCheckNGUserAgent)
    $SetItem | Out-File -FilePath $script:AppCheckNGLogPath -Append -Encoding utf8
    
    if(-not $script:AppCheckNGTestMode)
    {
        if($Headers) {
            $Result = Invoke-RestMethod -Uri $Uri -TimeoutSec $script:AppCheckNGRESTTimeout -UserAgent $script:AppCheckNGUserAgent -Method $Method -Headers $Headers -Body $Body -ErrorAction SilentlyContinue
        } else {
            $Result = Invoke-RestMethod -Uri $Uri -TimeoutSec $script:AppCheckNGRESTTimeout -UserAgent $script:AppCheckNGUserAgent -Method $Method -Body $Body -ErrorAction SilentlyContinue
        }
        if($Result -contains $script:AppCheckNGUnavailableError) {

            [PSCustomObject]$SetItem = @{}
            $SetItem.Add('status','error')
            $SetItem.Add('success','false')
            $SetItem.Add('errors','Error - API Unavailable')
            return New-Object -TypeName psobject -Property $SetItem
        } else {
            Return $Result
        }
    } else {
        write-host "TESTMODE: " -ForegroundColor Magenta
        $Output = $SetItem | Out-String
        write-host $Output -ForegroundColor Cyan
    }
}

# Return a Dummy error message when the API calls fails to ensure the calling script has a standardise return.
function Get-DummyErrorPSO {
    <#
        .SYNOPSIS
        Returns a dummy PSO error object

        .PARAMETER message
        Optional message variable to be used to provide better description for the error that occured.
        If not specified, the DEFAULT is 'Error - API Unavailable'

        .DESCRIPTION
        Returns a dummy PS Object when a REST call doesn't return one correctly
        This is to be used internal to the script only.

        .EXAMPLE 
        Get-DummyErrorPSO

        .EXAMPLE 
        Get-DummyErrorPSO -message 'REST Call Timed out'
    #>     
    param(
         # Error Message
         [Parameter()]
         [string]$message
     )

     if(-not $message) {
        $message = 'Error - API Unavailable'
     }
     
     [PSCustomObject]$SetItem = @{}
     $SetItem.Add('status','error')
     $SetItem.Add('success','false')
     $SetItem.Add('errors',$message)
     return New-Object -TypeName psobject -Property $SetItem
}

# Ensure that Invoke-RestMethod accesses the Internet via a Corporate Proxy. Defined in IE/Edge already
Function Set-AppCheckNGCorpProxyUse {
    <#
        .SYNOPSIS
        Sets the PowerShell session to use a Corporate or Default Forward Proxy
        
        .PARAMETER NoDefaultCredentials
        An optional switch to attempt to use the Proxy without credentials being provided.
        If the proxy requests authentication to access the API endpoint (HTTP 401), proxy access will fail.
        This is mainly for use where the API endpoint has been whitelisted for no-authentication.

        .DESCRIPTION
        Ensure that Invoke-RestMethod accesses the Internet via a Corporate Proxy.
        Relies on current user IE Proxy settings.
        Set to use default proxy creds when making internet calls.
        If a transparent Proxy is in use, this should not be required.
        If the Proxy does not need authentication, then the -NoDefaultCredentials switch can be added.

        .EXAMPLE 
        Set-AppCheckNGCorpProxyUse
    #>  
    [cmdletbinding()]
    param(
         # Error Message
         [Parameter()]
         [switch]$NoDefaultCredentials
     )

    # Set to use default proxy creds when making internet calls. Relies on current user IE Proxy settings
    if(-not $NoDefaultCredentials) {
        [System.Net.WebRequest]::DefaultWebProxy.Credentials =  [System.Net.CredentialCache]::DefaultCredentials
    }

    # Ignore Proxy Self-Signed Cert if required (for HTTPS Inspection Proxies)
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
        Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
}

# URL Encode a string
Function URL-Encode {
     [cmdletbinding()]
     param(
         # URL or String to URL Encode
         [Parameter()]
         [string]$Name
     )
     if($Name) {
         Add-Type -AssemblyName System.Web
         return [System.Web.HttpUtility]::UrlEncode($Name)
     } else {
        return ''
     }
}

# Return a www-form-urlencoded string for inclusion in a GET request or POST body
function Add-FormParam {
     [cmdletbinding()]
     param(
         # URL or String to URL Encode
         [Parameter(Mandatory)]
         [string]$Name,
         [Parameter()]
         [string]$Value
     )
     return "$Name=$(URL-Encode($Value))&"
}

#########################################################################################################
## START OF FORMAL PUBLIC API FUNCTIONS

# POST /api/v1/(api_key)/scan/new
# New in version 1.0.
# Create a new scan definition.
Function New-AppCheckNGScan {
    <#
        .SYNOPSIS
        Creates a new AppCheck Scan Definition

        .PARAMETER Name
        Name of the Scan Definition to Create

        .PARAMETER Targets
        List of Target URLs, IP addresses or hostnames to target with the scan.

        .PARAMETER ProfileID
        ID of the Profile to assign to the scan

        .PARAMETER ScanHub
        ID of the ScanHub to assign to the scan. This is often already set in the Profile but can be overridden by the Scan Definition

        .DESCRIPTION
        Creates a new AppCheck Scan Definition based on a number of parameters.
        The Name and Target(s) are mandatory but ProfileID and ScanHub can be set later using the Update-AppCheckNGScan function
        POST /api/v1/(api_key)/scan/new

        .EXAMPLE 
        New-AppCheckNGScan -Name 'MyNewScan' -Targets @('http://mynewwebsite.com','10.1.3.4')
    #>  
     [cmdletbinding()]
     param(
             # name to identify the scan definition
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$Name,
 
             # string array of targets - (multiple) URL, hostname, or IP address
         [Parameter(Mandatory)]
         [string[]]$Targets,
 
             # (optional) ID of a profile to apply
         [Parameter()]
         [string]$ProfileID,
 
             # (optional) Which scanhub or hub group to use
         [Parameter()]
         [string]$ScanHub 
 
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/new"
     }
     Process {
         # Create the query body that we'll post to the endpoint
         
         $Body = "name=$(URL-Encode($name))&"

         foreach($onetarget in $Targets) {
            $Body += "targets=$(URL-Encode($onetarget))"
         }

         if($ProfileID) {
            $Body += "&profile_id=$(URL-Encode($ProfileID))"
         }

         if($ScanHub) {
            $Body += "&scan_hub=$(URL-Encode($ScanHub))"
         }
          
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method POST -Body $Body -Headers $script:AppCheckNGInvokeParams
         if($Result) {
            $Result
         }
     }
 }

# POST /api/v1/(api_key)/scan/(scan_id)/update
# New in version 1.0.
# Update a scan definition.
Function Update-AppCheckNGScan {
    <#
        .SYNOPSIS
        Updates an existing AppCheck Scan Definition

        .PARAMETER ScanID
        Mandatory ID of the Scan Definition to Update

        .PARAMETER Name
        Name of the Scan Definition to Update

        .PARAMETER Targets
        List of Target URLs, IP addresses or hostnames to target with the scan.

        .PARAMETER ProfileID
        ID of the Profile to assign to the scan

        .PARAMETER ScanHub
        ID of the ScanHub to assign to the scan. This is often already set in the Profile but can be overridden by the Scan Definition

        .DESCRIPTION
        Updates a AppCheck Scan Definition based on a number of parameters.
        The ScanID is mandatory but all others are optional, however at least one must be supplied.
        POST /api/v1/(api_key)/scan/(scan_id)/update

        .EXAMPLE                       
        Update-AppCheckNGScan -ScanID '0123456789abcdef' -Name 'MyNewScan_Renamed' -Targets @('http://mynewwebsite.com','10.1.3.4')
    #> 
     [cmdletbinding()]
     param(
             # scanid of ID of the scan to update
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$ScanID,
            
            # name to identify the scan definition
         [Parameter()]
         [string]$Name,
 
             # string array of targets - (multiple) URL, hostname, or IP address
         [Parameter()]
         [string[]]$Targets,
 
             # (optional) ID of a profile to apply
         [Parameter()]
         [string]$ProfileID,
 
             # (optional) Which scanhub or hub group to use
         [Parameter()]
         [string]$ScanHub 
 
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/update"
     }
     Process {
         
         # Create the query body that we'll post to the endpoint
         
         if(-not $Name -and -not $ProfileID -and -not $ScanHub -and -not $Targets) {
            Return Get-DummyErrorPSO
         }
         
         if($Name) {
            $Body += "name=$(URL-Encode($Name))&"
         }

         foreach($OneTarget in $Targets) {
            $Body += "targets=$(URL-Encode($OneTarget))&"
         }

         if($ProfileID) {
            $Body += "profile_id=$(URL-Encode($ProfileID))&"
         }

         if($ScanHub) {
            $Body += "scan_hub=$(URL-Encode($ScanHub))&"
         }
          
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method POST -Body $Body -Headers $script:AppCheckNGInvokeParams
         if($Result) {
            Return $Result
         } else {
            Return Get-DummyErrorPSO
         }
     }
}

# GET /api/v1/(api_key)/scan/hubs
# New in version 1.2.
# Provides a list of the available hubs to run a scan on
Function Get-AppCheckNGScanHubs {
    <#
        .SYNOPSIS
        Get a list of the AppCheck Scan Hubs for your instance

        .DESCRIPTION
        Returns an object containing the Scan Hub details including the ScanHub_ID that can be used when creating or updating a Scan Definition.
        GET /api/v1/(api_key)/scan/hubs

        .EXAMPLE                       
        Get-AppCheckNGScanHubs
    #> 
     [cmdletbinding()]
     param()

     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/hubs"
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET
         if($Result) {
            $Result
         }
     }
}

# POST /api/v1/(api_key)/scan/(scan_id)/delete
# New in version 1.0.
# Delete a scan definition and all associated runs.
Function Delete-AppCheckNGScan {
    <#
        .SYNOPSIS
        Delete a single Scan Definition
        
        .PARAMETER ScanID
        ID of the Scan to be deleted

        .DESCRIPTION
        Deletes a Scan Definition and Returns true or false depending on success.
        POST /api/v1/(api_key)/scan/(scan_id)/delete

        .EXAMPLE                       
        Delete-AppCheckNGScan -ScanID '0123456789abcdef'
    #> 
     [cmdletbinding()]
     param(
             # scanid of ID of the scan to update
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$ScanID
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/delete"
     }
     Process {
         # Create the query body that we'll post to the endpoint
         $Body = ''         
         
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method POST -Body $Body -Headers $script:AppCheckNGInvokeParams
             
         if($Result.success -eq 'true') {
            return $Result
         } else {
            return Get-DummyErrorPSO
         }
     }
}

# POST /api/v1/(api_key)/scan/(scan_id)/start
# New in version 1.0.
# Run a scan.
Function Start-AppCheckNGScan {
    <#
        .SYNOPSIS
        Start a single Scan. Creates a new Scan Run that can be queried
        
        .PARAMETER ScanID
        ID of the Scan to be started

        .DESCRIPTION
        Starts a Scan Definition and Returns true or false depending on success.
        POST /api/v1/(api_key)/scan/(scan_id)/start

        .EXAMPLE                       
        Start-AppCheckNGScan -ScanID '0123456789abcdef'
    #> 
     [cmdletbinding()]
     param(
         # scanid of ID of the scan to update
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$ScanID
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/start"
     }
     Process {
         # Create the query body that we'll post to the endpoint
         $Body = ''         
         
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method POST -Body $Body -Headers $script:AppCheckNGInvokeParams
            
         if($Result.success -eq 'true') {
            return $Result
         } else {
            return Get-DummyErrorPSO
         }
     }
}

# POST /api/v1/(api_key)/scan/(scan_id)/abort
# New in version 1.0.
# Abort a running scan.
Function Stop-AppCheckNGScan {
    <#
        .SYNOPSIS
        Stop (Abort) a single Scan
        
        .PARAMETER ScanID
        ID of the Scan to be stopped

        .DESCRIPTION
        Stop a Scan and Returns true or false depending on success.
        POST /api/v1/(api_key)/scan/(scan_id)/abort

        .EXAMPLE                       
        Stop-AppCheckNGScan -ScanID '0123456789abcdef'
    #> 
     [cmdletbinding()]
     param(
             # scanid of ID of the scan to update
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$ScanID
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/abort"
     }
     Process {
         # Create the query body that we'll post to the endpoint
         $Body = ''         
         
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method POST -Body $Body -Headers $script:AppCheckNGInvokeParams
            
         if($Result.success -eq 'true') {
            return $true
         } else {
            return $false
         }
     }
}

# POST /api/v1/(api_key)/scan/(scan_id)/pause
# New in version 1.0.
# Suspend (Pause) a running scan.
Function Suspend-AppCheckNGScan {
    <#
        .SYNOPSIS
        Suspend (Pause) a single Scan
        
        .PARAMETER ScanID
        ID of the Scan to be suspended

        .DESCRIPTION
        Pause a Scan and Returns true or false depending on success. 
        POST /api/v1/(api_key)/scan/(scan_id)/pause

        .EXAMPLE                       
        Suspend-AppCheckNGScan -ScanID '0123456789abcdef'

        .EXAMPLE                       
        Pause-AppCheckNGScan -ScanID '0123456789abcdef'
    #> 
     [cmdletbinding()]
     [Alias("Pause-AppCheckNGScan")]
     param(
             # scanid of ID of the scan to update
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$ScanID
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/pause"
     }
     Process {
         # Create the query body that we'll post to the endpoint
         $Body = ''         
         
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method POST -Body $Body -Headers $script:AppCheckNGInvokeParams
            
         if($Result.success -eq 'true') {
            return $true
         } else {
            return $false
         }
     }
}

#POST /api/v1/(api_key)/scan/(scan_id)/resume
#New in version 1.0.
#Resume a paused scan.
Function Resume-AppCheckNGScan {
    <#
        .SYNOPSIS
        Resume a previous paused or suspended Scan
        
        .PARAMETER ScanID
        ID of the Scan to be resumed

        .DESCRIPTION
        Resume a Scan and Returns true or false depending on success.
        POST /api/v1/(api_key)/scan/(scan_id)/resume

        .EXAMPLE                       
        Resume-AppCheckNGScan -ScanID '0123456789abcdef'
    #> 
     [cmdletbinding()]
     param(
             # scanid of ID of the scan to update
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$ScanID
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/resume"
     }
     Process {
         # Create the query body that we'll post to the endpoint
         $Body = ''         
         
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method POST -Body $Body -Headers $script:AppCheckNGInvokeParams
            
         if($Result.success -eq 'true') {
            return $true
         } else {
            return $false
         }
     }
}

# POST /api/v1/(api_key)/scan/(scan_id)/run/(run_id)/delete
# New in version 1.0.
# Delete the results of a finished scan
Function Remove-AppCheckNGScanRun {
    <#
        .SYNOPSIS
        Remove (Delete) a Run of an existing Scan Definition
        
        .PARAMETER ScanID
        ID of the Scan to remove the Run from

        .PARAMETER RunID
        ID of the Run to remove
         
         .DESCRIPTION
        Delete a Run of an existing Scan Definition.
        Returns true or false depending on success status.

        .EXAMPLE                       
        Remove-AppCheckNGScanRun -ScanID '0123456789abcdef' -RunID '6d9a2783bc0145ef'

        .EXAMPLE                       
        Delete-AppCheckNGScanRun -ScanID '0123456789abcdef' -RunID '6d9a2783bc0145ef'
    #> 
     [cmdletbinding()]
     [Alias("Delete-AppCheckNGScanRun")]
     param(
             # scanid of ID of the scan to update
         [Parameter(Mandatory)]
         [string]$ScanID,
             # runid of ID of the scan run to action
         [Parameter(Mandatory)]
         [string]$RunID

     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/run/$(URL-Encode($RunID))/delete"
     }
     Process {
         # Create the query body that we'll post to the endpoint
         $Body = ''         
         
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method POST -Body $Body -Headers $script:AppCheckNGInvokeParams
            
         if($Result.success -eq 'true') {
            return $true
         } else {
            return $false
         }
     }
}

# POST /api/v1/(api_key)/vulnerability/(vulnerability_id)/update
# New in version 1.0.
# Update a vulnerability.
Function Update-AppCheckNGVuln {
    <#
        .SYNOPSIS
        Update the status of a Vulnerability
        
        .PARAMETER VulnID
        ID of the Vulnerability too be updated

        .PARAMETER Notes
        Notes for the Vulnerability

        .PARAMETER Priority
        Priority of the Vulnerability ('low','medium','high')
        
        .PARAMETER Status
        Status to give of the Vulnerability ('unfixed','fixed','false_positive','acceptable_risk')

        .DESCRIPTION
        Update a Vulnerability status or add notes.
        POST /api/v1/(api_key)/vulnerability/(vulnerability_id)/update

        .EXAMPLE                       
        Update-AppCheckNGVuln -VulnID '0123456789abcdef'
    #> 
     [cmdletbinding()]
     param(
             # vulnid of ID of the vulnerability to action
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [Alias("name")]
         [string]$VulnID,
            
            # notes for the vulnerability
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$Notes,
 
             # priority of the vulnerability 
         [Parameter()]
         [ValidateSet('low','medium','high',IgnoreCase)]
         [string]$Priority,
 
             # status of the vulnerability
         [Parameter()]
         [ValidateSet('unfixed','fixed','false_positive','acceptable_risk',IgnoreCase)]
         [string]$Status
 
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/vulnerability/$(URL-Encode($VulnID))/update"
     }
     Process {
         # Create the query body that we'll post to the endpoint
         
         $Body = Add-FormParam -name 'notes' -value $Notes

         if($Priority) {
            $Body += Add-FormParam -name 'priority' -value $Priority
         }
         
         if($ScanHub) {
            $Body += Add-FormParam -name 'status' -value $Status
         }
          
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method POST -Body $Body -Headers $script:AppCheckNGInvokeParams
         if($Result.success) {
            Return $True
         } elseif($Result.errors) {
            Return $Result.errors
         } else {
            Return $false
         }
     }
}

# POST /api/v1/(api_key)/vulnerability/(vuln_id)/delete
# New in version 1.0.
# Delete a vulnerability
Function Delete-AppCheckNGVuln {
    <#
        .SYNOPSIS
        Delete a Vulnerability
        
        .PARAMETER VulnID
        ID of the Vulnerability to be deleted

        .DESCRIPTION
        Deletes a Vulnerability based on the ID. This Vulnerability is associated with a Scan.
        POST /api/v1/(api_key)/vulnerability/(vuln_id)/delete

        .EXAMPLE                       
        Delete-AppCheckNGVuln -Vuln '5a597bf3af963f118022e08429bc076e437442ba'
    #> 
     [cmdletbinding()]
     param(
         # vulnid of ID of the vulnerability to delete
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$VulnID
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/vulnerability/$(URL-Encode($VulnID))/delete"
     }
     Process {
         # Create the query body that we'll post to the endpoint
         $Body = ''         
         
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method POST -Body $Body -Headers $script:AppCheckNGInvokeParams
            
         if($Result.success -eq 'true') {
            return $true
         } else {
            return $false
         }
     }
}

# GET /api/v1/(api_key)/scans
# New in version 1.0.
# Get the list of all scans of your organisation.
Function Get-AppCheckNGScans {
    <#
        .SYNOPSIS
        Get ALL Scans from the AppCheck instance

        .DESCRIPTION
        Gets an object containing all of the Scan Definitions.
        Used in Get-AppCheckNGScanByName to filter by name of a specific Scan Definition.
        GET /api/v1/(api_key)/scans

        .EXAMPLE                       
        Get-AppCheckNGScans

        .EXAMPLE                       
        $Name = 'Scan-I-Really-Want'
        $Scan = $(Get-AppCheckNGScans).data | Where name -eq $Name | Select scan_id
    #> 
     [cmdletbinding()]
     param()
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scans"
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET
            
         if($Result.success -eq 'true') {
            return $Result
         } else {
            return $false
         }
     }
}

#GET /api/v1/(api_key)/scanprofiles
#New in version 1.1.
#Get the list of all scan profiles of your organisation.
Function Get-AppCheckNGScanProfiles {
    <#
        .SYNOPSIS
        Get ALL Scan Peofiles from the AppCheck instance

        .DESCRIPTION
        Gets an object containing all of the Scan Profiles.
        GET /api/v1/(api_key)/scanprofiles

        .EXAMPLE                       
        Get-AppCheckNGScanProfiles
    #> 
     [cmdletbinding()]
     param()
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scanprofiles"
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET
            
         if($Result.success -eq 'true' -and $Result.data) {
            return $Result.data
         } else {
            return $false
         }

     }
}

# GET /api/v1/(api_key)/scan/(scan_id)/runs
# New in version 1.0.
# Get a list of all runs of a scan in descending chronological order, i.e. data[0] is always the latest run.
Function Get-AppCheckNGScanRuns {
    <#
        .SYNOPSIS
        Gets a list of all Runs for a specific Scan
        
        .PARAMETER ScanID
        ID of the Scan to return the Runs for

        .PARAMETER Status
        Optional status field to filter by ('RUNNING','PAUSED','ABORTED','DETACHED','COMPLETED','FAILED')

        .DESCRIPTION
        Gets a list of all Runs for a specific Scan.
        Use Get-AppCheckNGScanRunLatest to get the most recent Run, irrespective of the Status.
        GET /api/v1/(api_key)/scan/(scan_id)/runs

        .EXAMPLE                       
        Get-AppCheckNGScanRuns -ScanID '0123456789abcdef'
    #> 
     [cmdletbinding()]
     param(
             # scanid of ID of the scan to get the run list (with option for status)
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$ScanID,
             # optional status of the run to filter by
         [Parameter()]
         [ValidateSet('RUNNING','PAUSED','ABORTED','DETACHED','COMPLETED','FAILED',IgnoreCase)]
         [string]$Status

     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey

         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/runs"

         if($Status) {
            $Uri += '?'
            $Uri += Add-FormParam -name 'status' -value $Status.ToUpper()
         }
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET
            
         if($Result.success -eq 'true') {
            return $Result
         } else {
            return $false
         }
     }
}

Function Get-AppCheckNGVulns {
    <#
        .SYNOPSIS
        Gets a list of ALL Vulnerabilities
        
        .PARAMETER Status
        Optional Status parameter to filter by ('unfixed','fixed','false_positive','acceptable_risk')

        .PARAMETER Short
        Optional switch Short to only list Short information about the Vulnerabilities

        .PARAMETER Severity
        Optional Severity parameter to filter by ('info','low','medium','high')

        .PARAMETER CVSS
        Optional integer based CVSS parameter to filter by a CVSS score limit

        .PARAMETER IncludeInfo
        Optional switch IncludeInfo to include more detailed information about the Vulnerability

        .DESCRIPTION
        Gets a list of all Vulnerabilities from the instance
        GET /api/v1/(api_key)/vulnerabilities

        .EXAMPLE                       
        Get-AppCheckNGVulns

        .EXAMPLE                       
        Get-AppCheckNGVulns -Status 'unfixed'

        .EXAMPLE                       
        Get-AppCheckNGVulns -Severity 'high'

        .EXAMPLE                       
        Get-AppCheckNGVulns -CVSS 7
    #> 
     [cmdletbinding()]
     param(
             # optional status of the vulnerabilities to filter by
         [Parameter()]
         [ValidateSet('unfixed','fixed','false_positive','acceptable_risk',IgnoreCase)]
         [string]$Status,
             # optional short format boolean (switch)
         [Parameter()]
         [switch]$Short,
             # optional severity status to filter by
         [Parameter()]
         [ValidateSet('info','low','medium','high',IgnoreCase)]
         [string]$Severity,
             # optional CVSS integer to filter by
         [Parameter()]
         [int]$CVSS,
             # optional Info boolean (switch) to include info in output
         [Parameter()]
         [switch]$IncludeInfo

     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey

         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/vulnerabilities"

         if($Status -or $short -or $Severity -or $CVSS -or $IncludeInfo) {
            $Uri += "?"
         }

         if($Status) {
            $Uri += Add-FormParam -name 'status' -value $Status.ToLower()
         }
         if($Short) {
            $Uri += Add-FormParam -name 'short' -value 'True'
         }
         if($Severity) {
            $Uri += Add-FormParam -name 'severity' -value $Severity.ToLower()
         }
         if($CVSS) {
            $Uri += Add-FormParam -name 'cvss' -value [string]$CVSS
         }
         if($IncludeInfo) {
            $Uri += Add-FormParam -name 'return_info' -value 'True'
         }
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET
            
         if($Result.count -ge 1) {
            return $Result
         } else {
            return $false
         }
     }
}
# GET /api/v1/(api_key)/scan/(scan_id)/vulnerabilities
# New in version 1.0.
# Get a list of all vulnerabilities discovered by a scan.
Function Get-AppCheckNGScanVulns {
    <#
        .SYNOPSIS
        Gets a list of Vulnerabilities for a specific Scan
        
        .PARAMETER ScanID
        ID of the Scan to list the vulnerabilities of

        .PARAMETER Status
        Optional Status parameter to filter by ('unfixed','fixed','false_positive','acceptable_risk')

        .PARAMETER Severity
        Optional Severity parameter to filter by ('info','low','medium','high')

        .PARAMETER CVSS
        Optional integer based CVSS parameter to filter by a CVSS score limit

        .PARAMETER IncludeInfo
        Optional switch IncludeInfo to include more detailed information about the Vulnerability

        .DESCRIPTION
        Gets a list of Vulnerabilities for a specific Scan.
        GET /api/v1/(api_key)/scan/(scan_id)/vulnerabilities

        .EXAMPLE                       
        Get-AppCheckNGScanVulns -ScanID '0123456789abcdef'

        .EXAMPLE                       
        Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -Status 'unfixed'

        .EXAMPLE                       
        Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -Severity 'high'

        .EXAMPLE                       
        Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -CVSS 7
    #> 
     [cmdletbinding()]
     param(
             # Scan ID of scan to report vulnerabilities
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$ScanID,
         [Parameter()]
         [ValidateSet('unfixed','fixed','false_positive','acceptable_risk',IgnoreCase)]
         [string]$Status,
             # optional severity status to filter by
         [Parameter()]
         [ValidateSet('info','low','medium','high',IgnoreCase)]
         [string]$Severity,
             # optional CVSS integer to filter by
         [Parameter()]
         [int]$CVSS,
             # optional Info boolean (switch) to include info in output
         [Parameter()]
         [switch]$IncludeInfo

     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey

         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/vulnerabilities"

         if($Status -or $Severity -or $CVSS -or $IncludeInfo) {
            $Uri += "?"
         }
         if($Status) {
            $Uri += Add-FormParam -name 'status' -value $Status.ToLower()
         }
         if($Severity) {
            $Uri += Add-FormParam -name 'severity' -value $Severity.ToLower()
         }
         if($CVSS) {
            $Uri += Add-FormParam -name 'cvss' -value [string]$CVSS
         }
         if($IncludeInfo) {
            $Uri += Add-FormParam -name 'return_info' -value 'True'
         }
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET
            
         if($Result.count -ge 1) {
            return $Result
         } else {
            return $false
         }
     }
}

# GET /api/v1/(api_key)/scan/(scan_id)/run/(run_id)/vulnerabilities
# New in version 1.0.
# Get a list of all vulnerabilities discovered by a particular run of a scan.
Function Get-AppCheckNGScanRunVulns {
    <#
        .SYNOPSIS
        Gets a list of Vulnerabilities for a specific Scan Run
        
        .PARAMETER ScanID
        ID of the Scan to list the vulnerabilities of

        .PARAMETER RunID
        ID of the Run to list the vulnerabilities of

        .PARAMETER Status
        Optional Status parameter to filter by ('unfixed','fixed','false_positive','acceptable_risk')

        .PARAMETER Severity
        Optional Severity parameter to filter by ('info','low','medium','high')

        .PARAMETER CVSS
        Optional integer based CVSS parameter to filter by a CVSS score limit

        .PARAMETER IncludeInfo
        Optional switch IncludeInfo to include more detailed information about the Vulnerability

        .DESCRIPTION
        Gets a list of Vulnerabilities for a specific Scan Run.
        GET /api/v1/(api_key)/scan/(scan_id)/run/(run_id)/vulnerabilities

        .EXAMPLE                       
        Get-AppCheckNGScanRunVulns -ScanID '0123456789abcdef' -RunID '74bbcd2fc4686335'

        .EXAMPLE                       
        Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -RunID '74bbcd2fc4686335' -Status 'unfixed'

        .EXAMPLE                       
        Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -RunID '74bbcd2fc4686335' -Severity 'high'

        .EXAMPLE                       
        Get-AppCheckNGScanVulns -ScanID '0123456789abcdef' -RunID '74bbcd2fc4686335' -CVSS 7
    #> 
     [cmdletbinding()]
     param(
             # Scan ID of scan to report vulnerabilities
         [Parameter(Mandatory)]
         [string]$ScanID,
             # Run ID of scan run to report vulnerabilities
         [Parameter(Mandatory)]
         [string]$RunID,
             # optional vulnerability status to filter by
         [Parameter()]
         [ValidateSet('unfixed','fixed','false_positive','acceptable_risk',IgnoreCase)]
         [string]$Status,
             # optional severity status to filter by
         [Parameter()]
         [ValidateSet('info','low','medium','high',IgnoreCase)]
         [string]$Severity,
             # optional CVSS integer to filter by
         [Parameter()]
         [int]$CVSS,
             # optional Info boolean (switch) to include info in output
         [Parameter()]
         [switch]$IncludeInfo

     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey

         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/run/$(URL-Encode($RunID))/vulnerabilities"

         if($Status -or $Severity -or $CVSS -or $IncludeInfo) {
            $Uri += "?"
         }

         if($Status) {
            $Uri += Add-FormParam -name 'status' -value $Status.ToLower()
         }
         if($Severity) {
            $Uri += Add-FormParam -name 'severity' -value $Severity.ToLower()
         }
         if($CVSS) {
            $Uri += Add-FormParam -name 'cvss' -value [string]$CVSS
         }
         if($IncludeInfo) {
            $Uri += Add-FormParam -name 'return_info' -value 'true'
         }
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET
            
         if($Result.count -ge 1) {
            return $Result
         } else {
            return $false
         }
     }
}

# GET /api/v1/(api_key)/scan/(scan_id)/status
# New in version 1.0.
# Get the status of the last run of a scan. The same information can be optained from the first element of the list returned by GET
Function Get-AppCheckNGScanStatus {
    <#
        .SYNOPSIS
        Gets the status of a scan
        
        .PARAMETER ScanID
        ID of the Scan to list the status of

        .DESCRIPTION
        Gets the status for a specific Scan.
        GET /api/v1/(api_key)/scan/(scan_id)/status

        .EXAMPLE                       
        Get-AppCheckNGScanStatus -ScanID '0123456789abcdef'
    #> 
     [cmdletbinding()]
     param(
             # scanid of ID of the scan to get
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$ScanID
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/status"
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET
            
         if($Result.success -eq 'true') {
            return $Result
         } else {
            return $false
         }
     }
}

# GET /api/v1/(api_key)/scan/(scan_id)
# New in version 1.0.
# Get details of a scan definition.
Function Get-AppCheckNGScan {
    <#
        .SYNOPSIS
        Gets a specific scan
        
        .PARAMETER ScanID
        ID of the Scan to get details of

        .DESCRIPTION
        Gets the status for a specific Scan.
        GET /api/v1/(api_key)/scan/(scan_id)

        .EXAMPLE                       
        Get-AppCheckNGScan -ScanID '0123456789abcdef'
    #> 
     [cmdletbinding()]
     param(
             # scanid of ID of the scan to get
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [Alias("scan_id")]
         [string]$ScanID
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))"
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET -ErrorAction SilentlyContinue
            
         if($Result.success -eq 'true') {
            return $Result
         } else {
            return $false
         }
     }
}

# GET /api/v1/(api_key)/scan/(scan_id)/run/(run_id)
# New in version 1.0.
# Get details of a specific run of a scan
Function Get-AppCheckNGScanRun {
    <#
        .SYNOPSIS
        Get details of a specific Scan Run
        
        .PARAMETER ScanID
        ID of the Scan to get details of the Run

        .PARAMETER RunID
        ID of the Run to get details of

        .DESCRIPTION
        Gets the details of a specific Run of a specific Scan.
        GET /api/v1/(api_key)/scan/(scan_id)/run/(run_id)

        .EXAMPLE                       
        Get-AppCheckNGScanRun -ScanID '0123456789abcdef' -RunID 'b3c3866b74f24cd5'
    #> 
     [cmdletbinding()]
     param(
             # scanid of ID of the scan to get
         [Parameter(Mandatory)]
         [string]$ScanID,
             # runisof ID of the scan run to get
         [Parameter(Mandatory)]
         [string]$RunID
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/scan/$(URL-Encode($ScanID))/run/$(URL-Encode($RunID))"
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET
            
         if($Result.success -eq 'true') {
            return $Result
         } else {
            return $false
         }
     }
}

# GET /api/v1/(api_key)/vulnerability/(vulnerability_id)
# New in version 1.0.
# Get details of a vulnerability.
Function Get-AppCheckNGVuln {
    <#
        .SYNOPSIS
        Gets a specific vulnerability
        
        .PARAMETER VulnID
        ID of the Vulnerability to get details of

        .DESCRIPTION
        Gets the details for a specific vulnerability.
        GET /api/v1/(api_key)/vulnerability/(vulnerability_id)

        .EXAMPLE                       
        Get-AppCheckNGVuln -Vuln '5a597bf3af963f118022e08429bc076e437442ba'
    #> 
     [cmdletbinding()]
     param(
             # vulnid (Vulnerability ID) of the Vulnerability to get
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$VulnID
     )
     Begin {
         $isValidKey = Validate-AppCheckNGKey
         $Uri = "$script:AppCheckNGBaseUri/$script:AppCheckNGKey/vulnerability/$(URL-Encode($VulnID))"
     }
     Process {
         # Call the API endpoint using the $Uri
         $Result = Invoke-AppCheckNGREST -Uri $Uri -Method GET
            
         if($Result.success -eq 'true') {
            return $Result
         } else {
            return $false
         }
     }
}

####################################
# SERVICE FUNCTIONS START HERE
####################################

# Get Scan Details by Name rather than Scan ID. Can return multiple scan details if named the same (equal)
function Get-AppCheckNGScanByName {
    <#
        .SYNOPSIS
        Gets a specific scan by name rather than scan ID
        
        .PARAMETER Name
        Mandatory String of the name to search for scans with a matching definition name
        
        .PARAMETER UseLike
        Optional switch to use -LIKE comparison rather than -EQuals. This allows for wildcards in the name paramater

        .DESCRIPTION
        Get a specific scan by name where the scan definition EQUALS the name.
        To have the search done with wildcards, use the -UseLike switch.
        WARNING: Be careful not to feed or pipe the results into a Delete operation 
        without being sure of the results as if -UseLike is set, you may end up deleting more than intended!

        .EXAMPLE                       
        Get-AppCheckNGScanByName -Name 'PetShop-DevelopmentSite'

        .EXAMPLE                       
        Get-AppCheckNGScanByName -Name 'PetShop-*' -UseLike
    #> 
     [cmdletbinding()]
     param(
             # Name of Scan to find ID of and then per scan ID output Get-AppCheckNGScan
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$Name,
         [Parameter()]
         [switch]$UseLike
     )    
    $AllScans = Get-AppCheckNGScans
    if($AllScans) {
        
        if($UseLike) {
            $ScanIDList = $($AllScans.data | Where name -like $Name | Select scan_id).scan_id
        } else {
            $ScanIDList = $($AllScans.data | Where name -eq $Name | Select scan_id).scan_id
        }

        if($ScanIDList) {
            ForEach($ScanID in $ScanIDList) {
                Get-AppCheckNGScan -scanid $ScanID
            }
        } else {
            return $false
        }
    } else {
        return $false
    }
}

# Remove Scan(s) by Name. Can remove multiple scans if named the same (equal)
function Remove-AppCheckNGScanByName {
    <#
        .SYNOPSIS
        Removes a specific scan by name rather than scan ID
        
        .PARAMETER Name
        Mandatory String of the name to search for scans with a matching definition name
        
        .DESCRIPTION
        Get a specific scan by name where the scan definition EQUALS the name.
        To have the search done with wildcards, use the Get-AppCheckNGScanByName with the -UseLike switch first.
        WARNING: There is no -UseLike switch for this service function for a reason as all scans could then be deleted by specifying the name as '*'!
        Returns true or false depending on success.

        .EXAMPLE                       
        Remove-AppCheckNGScanByName -Name 'PetShop-DevelopmentSite'
    #> 
     [cmdletbinding()]
     param(
             # Name of Scan to find ID of and then per scan ID output Delete-AppCheckNGScan
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$Name
     )    
    $AllScans = Get-AppCheckNGScans
    if($AllScans) {
        $ScanIDList = $($AllScans.data | Where name -eq $Name | Select scan_id).scan_id
        
        if($ScanIDList) {
            $DeletedSuccessCount = 0
            
            ForEach($ScanID in $ScanIDList) {
                write-verbose "Removing Scan ID $ScanID..."
                $Status = Delete-AppCheckNGScan -scanid $ScanID
                if($Status) {
                    $DeletedSuccessCount +=1
                }
            }

            # Handle status return of true,false or count when deleting multiple or single scans
            if($DeletedSuccessCount -gt 1) {
                $DeletedSuccessCount
            } elseif($DeletedSuccessCount -eq 0) {
                Return $false
            } else {
                Return $true
            }
        } else {
            return $false
        } #if($ScanIDList)
    } else {
        return $false
    } #if($AllScans)
}

# Get-AppCheckNGScanRuns - Check Scan Status every 10 seconds for 2 minutes
Function Watch-AppCheckNGScan {
    <#
        .SYNOPSIS
        Watches a specific scan given a scan ID
        
        .PARAMETER ScanID
        ID of the scan required to be watched
        
        .PARAMETER Timeout
        Optional Integer of the number of minutes to watch for a COMPLETED scan. If the timeout is exceeded, the watch just exits. 
        If the scan is COMPLETED, the watch also exits. The Default Timeout is 5 minutes which is generally insufficient to 
        see a full completed scan, but adequate for testing. This will often need to be set to something like 180 (or higher) to 
        be given a timeout of 3 hours.

        .PARAMETER Frequency
        Optional Integer of the number of seconds to wait before checking the status again. Default is 30 seconds.

        .PARAMETER MaxFailedChecks
        Optional Integer of the maximum number of failed attempts to check on the scan status before aborting

        .DESCRIPTION
        Monitors the status of a specific scan for a period of time by checking and reporting every 30 seconds (by default).
        This service function outputs the current status and how long the scan has been running for.
        The scan will continue to be watched while the status is 'RUNNING'.
        If the scan becomes COMPLETED status then the watch exits.
        If the scan becomes 'PAUSED', 'ABORTED', 'DETACHED' or 'FAILED' then the watch exits.
        If the timeout is exceeded then the watch exits.

        .EXAMPLE                       
        Watch-AppCheckNGScan -ScanID '0123456789abcdef'

        .EXAMPLE                       
        Watch-AppCheckNGScan -ScanID '0123456789abcdef' -TimeOut 180 -Frequency 60 -MaxFailedChecks 10
    #> 
     [cmdletbinding()]
     param(
         # Timeout
         [Parameter(Mandatory)]
         [string]$ScanID,
         # Timeout
         [Parameter()]
         [int]$Timeout,
         # Check Frequency
         [Parameter()]
         [int]$Frequency,
         [Parameter()]
         [int]$MaxFailedChecks
    )
    Begin {
        if(-not $Timeout) {
            $Timeout = 5  # Default to 5 minute timeout if not specified
        }
        if(-not $Frequency) {
            $Frequency = 30 # Default to sleep for 30 seconds between checks
        }
        if(-not $MaxFailedChecks) {
            $MaxFailedChecks = 3 # Default to maximum failed checks before aborting
        }
    }
    Process {
        write-host "Getting Scan Details..." -ForegroundColor Green
        $WatchScan = $(Get-AppCheckNGScan -ScanID $ScanID).data
        if(-not $WatchScan._id) {
            write-host "Failed to find scan with that the Scan ID provided ($($WatchScan._id))"
            Return
        }
        # Initialise counter for failed checks. If this reaches 3 then we abort
        $FailedChecks = 0
        $BadScanStatusList = @('PAUSED','ABORTED','DETACHED','FAILED')

        write-host "Watching Scan '$($WatchScan.description)' - ID $($WatchScan._id) for a maximum of $Timeout minutes" -ForegroundColor Magenta
        $stopwatch = [system.diagnostics.stopwatch]::StartNew()
        $ScanOK = $true
        Do{
            $ScanRunsStatus = Get-AppCheckNGScanRuns -ScanID $WatchScan._id
            $LatestScanRun = $ScanRunsStatus.data | Sort Started_at -Descending | Select -First 1
            $LatestScanRunStart = Convert-FromUnixDate $LatestScanRun.started_at
            if($LatestScanRun.completed_at) {
                $LatestScanRunEnd   = Convert-FromUnixDate $LatestScanRun.completed_at
            }
            $LatestScanRunTime  = New-TimeSpan -Start $LatestScanRunStart -End $(Get-Date)
            $LatestScanRunTimeFormatted = "$($LatestScanRunTime.Hours) Hours $($LatestScanRunTime.Minutes) Minutes $($LatestScanRunTime.Seconds) Seconds"
            if($LatestScanRun.status -eq 'RUNNING') {
                write-host " - $($LatestScanRun.status) for $LatestScanRunTimeFormatted" -ForegroundColor Gray
                Start-Sleep $Frequency

            } elseif($LatestScanRun.status -eq 'COMPLETED') {
                write-host " -  $($LatestScanRun.status) on $LatestScanRunEnd" -ForegroundColor Green
                $ScanOK = $false

            } elseif($LatestScanRun.status -in $BadScanStatusList) {
                # Check for @('PAUSED','ABORTED','DETACHED','FAILED')
                write-host " -  $($LatestScanRun.status) at $LatestScanRunEnd" -ForegroundColor Yellow
                $ScanOK = $false

            } else {
                write-host " - Scan status failed to be returned (Attempt #$($FailedChecks+1))" -ForegroundColor Red
                Start-Sleep $Frequency

                $FailedChecks +=1
                if($FailedChecks -ge $MaxFailedChecks) {
                    write-host " - Scan status failed to be returned after $MaxFailedChecks attempts. Aborting" -ForegroundColor Red
                    $ScanOK = $false
                }
            }
        } While($ScanOK -and $stopwatch.Elapsed.TotalMinutes -lt $timeout)
        $stopwatch.Stop()
    }
}

Function Get-AppCheckNGScanRunLatest {
     [cmdletbinding()]
     param(
             # scanid of ID of the scan to get
         [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
         [string]$ScanID
     )
     Begin {
         
     }
     Process {
         $ScanRunsStatus = Get-AppCheckNGScanRuns -ScanID $ScanID
         if($ScanRunsStatus) {
             $LatestScanRun = $ScanRunsStatus.data | Sort Started_at -Descending | Select -First 1
         }
         if($LatestScanRun) {
            Return $LatestScanRun
         } else {
            Return Get-DummyErrorPSO
         }
     }
}

# EXPORT MODULE FUNCTIONS
Export-ModuleMember -Function Set-AppCheckNGKey,Set-AppCheckNGMode,Set-AppCheckNGCorpProxyUse,New-AppCheckNGScan,Update-AppCheckNGScan,Get-AppCheckNGScanHubs, `
                              Delete-AppCheckNGScan,Start-AppCheckNGScan,Stop-AppCheckNGScan,Suspend-AppCheckNGScan, `
                              Resume-AppCheckNGScan,Remove-AppCheckNGScanRun,Update-AppCheckNGVuln,Delete-AppCheckNGVuln, `
                              Get-AppCheckNGScans,Get-AppCheckNGScanProfiles,Get-AppCheckNGScanRuns,Get-AppCheckNGVulns, `
                              Get-AppCheckNGScanVulns,Get-AppCheckNGScanRunVulns,Get-AppCheckNGScanStatus,Get-AppCheckNGScan, `
                              Get-AppCheckNGScanRun,Get-AppCheckNGVuln,Get-AppCheckNGScanByName,Remove-AppCheckNGScanByName, Watch-AppCheckNGScan, `
                              Get-AppCheckNGScanRunLatest,Invoke-AppCheckNGREST -Alias *


Param(
    [Parameter(Mandatory=$true)]
    [String]$vbrUser,
    [Parameter(Mandatory=$true)]
    [String]$vbrServer,
    [Parameter(Mandatory=$true)]
    [String]$cyAppId,
    [Parameter(Mandatory=$true)]
    [String]$cySafe,
    [Switch]$refreshCache
)
# General Variables - Please change where necessary
$apiVersion   = "v1"
$veeamAPI     = "https://$($vbrServer):9419"
$xAPIVersion  = "1.1-rev1"

function Retrieve-Password {
    param (
        [string]$vbrUser,
        [string]$vbrServer,
        [string]$cyAppId,
        [string]$cySafe
    )

    $cyberArkExecutable = 'C:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK64.exe'
    if (-not (Test-Path $cyberArkExecutable)) {
        throw "CyberArk Password SDK executable not found at '$cyberArkExecutable'."
    }

    $password = & $cyberArkExecutable GetPassword /p AppDescs.AppID=$cyAppId /p Query="Safe=$cySafe;Folder=Root;Object=Operating System-WinServerLocal-$vbrServer-$vbrUser" /o Password
    return $password
}

function Refresh-Cache {
    $appPrvMgrExecutable = 'C:\Program Files\CyberArk\ApplicationPasswordProvider\AppPrvMgr.exe'
    if (-not (Test-Path $appPrvMgrExecutable)) {
        throw "AppPrvMgr.exe not found at '$appPrvMgrExecutable'."
    }

    & $appPrvMgrExecutable RefreshCache
}

function Connect-VeeamRestAPI {
    [CmdletBinding()]
    param (
        [string] $AppUri,
        [string] $User,
        [string] $Password
    )

    begin {
        $header = @{
            "Content-Type"  = "application/x-www-form-urlencoded"
            "x-api-version" = $xAPIVersion
            "accept"        = "application/json"
        }
        
        $body = @{
            "grant_type" = "password"
            "username" = $vbrUser
            "password" = $vbrPassword
            "refresh_token" = " "
            "rememberMe" = " "
        }

        $requestURI = $veeamAPI + $appUri

        $tokenRequest = Invoke-RestMethod -Uri $requestURI -Headers $header -Body $body -Method Post 
        Write-Output $tokenRequest.access_token
    }
    
}

function Get-VeeamRestAPI {
    [CmdletBinding()]
    param (
        [string] $AppUri,
        [string] $Token
    )

    begin {
        $header = @{
            "accept" = "application/json"
            "x-api-version" = $xAPIVersion
            "Authorization" = "Bearer $Token"
        }
        $requestURI = $veeamAPI + $AppUri
        $results = Invoke-RestMethod -Method GET -Uri $requestUri -Headers $header
        Write-Output $results
    }
}

Clear-Host

try {
    if ($refreshCache) {
        Refresh-Cache
    }

    #Ignore any self-signed certificate
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    # Get password from CyberArk Safe
    $vbrPassword = Retrieve-Password -vbrUser $vbrUser -vbrServer $vbrServer -cyAppId $cyAppId -cySafe $cySafe
    Write-Host "Password successfully retrieved from CyberArk Safe" -ForegroundColor White

    #Request Bearer Token
    Write-Host "Get Bearer Token...." -ForegroundColor White
    $appURI             = "/api/oauth2/token"
    $bearerToken        = Connect-VeeamRestAPI -AppUri $appURI -User $vbrUser -Password $vbrPassword

    # Get all malware detection events
    Write-Host "Getting malware detection events...." -ForegroundColor White
    Write-Host ""
    Write-Host "Last 10 events"
    Write-Host "--------------"
    $appURI             = "/api/$APIversion/malwareDetection/events/"
    $vbrMalwareEvt      = Get-VeeamRestAPI -AppUri $appURI -Token $bearerToken
    $tableData          = @()

    foreach ($entry in $vbrMalwareEvt.data) {
        $rowData = New-Object PSObject -property @{
            'TimeUtc'    = $entry.detectionTimeUtc
            'Severity'   = $entry.severity
            'Source'     = $entry.source
            'Details'    = $entry.Details
        }
        $tableData      += $rowData
    }
    $tableData = $tableData | Sort-Object TimeUtc -Descending
    $tableData | Select-Object -Last 10 | Format-Table -Property TimeUtc, Severity, Source, Details -AutoSize 
    
} catch {
    Write-Host "Error: $_"
}

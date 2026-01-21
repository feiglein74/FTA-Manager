#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    FTA-Manager Service - Processes FTA change requests from user registry queues

.DESCRIPTION
    This script is designed to run as a Scheduled Task with SYSTEM privileges.
    It processes File Type Association (FTA) and Protocol Association (PTA) change
    requests that users have placed in their registry queues.

    Users (without admin rights) can request FTA changes by writing to:
        HKCU:\Software\FTA-Manager\Requests\
        - Name: Extension or Protocol (e.g., ".pdf", "http")
        - Value: ProgId (e.g., "ChromePDF", "MSEdgeHTM")

    This service runs as SYSTEM, reads all user requests from HKU, validates them,
    applies the changes using regini.exe (bypasses UCPD), and logs results to EventLog.

.NOTES
    Author: FTA-Manager Project
    License: MIT
    Requires: Administrator/SYSTEM privileges
    Trigger: Scheduled Task at user logon + 30 seconds delay

.EXAMPLE
    # Run manually as Administrator for testing:
    & "C:\Program Files\FTA-Manager\FTA-Manager-Service.ps1"
#>

[CmdletBinding()]
param()

# ============================================================================
# CONFIGURATION
# ============================================================================

$script:Config = @{
    EventLogSource   = 'FTA-Manager'
    EventLogName     = 'Application'
    RequestKeyPath   = 'Software\FTA-Manager\Requests'
    # Event IDs
    EventIdSuccess   = 1000
    EventIdProgIdNotFound = 2000
    EventIdReginiFailed   = 2001
    EventIdError     = 3000
}

# ============================================================================
# EVENTLOG FUNCTIONS
# ============================================================================

function Initialize-FTAEventLog {
    <#
    .SYNOPSIS
        Registers the EventLog source if not already registered
    #>
    [CmdletBinding()]
    param()

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:Config.EventLogSource)) {
            [System.Diagnostics.EventLog]::CreateEventSource(
                $script:Config.EventLogSource,
                $script:Config.EventLogName
            )
            Write-Verbose "EventLog source '$($script:Config.EventLogSource)' created"
        }
        return $true
    }
    catch {
        Write-Warning "Failed to initialize EventLog: $($_.Exception.Message)"
        return $false
    }
}

function Write-FTAEventLog {
    <#
    .SYNOPSIS
        Writes an entry to the EventLog
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$EventId,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$EntryType = 'Information'
    )

    try {
        Write-EventLog -LogName $script:Config.EventLogName `
                       -Source $script:Config.EventLogSource `
                       -EventId $EventId `
                       -EntryType $EntryType `
                       -Message $Message
        Write-Verbose "EventLog: [$EntryType] ID=$EventId - $Message"
    }
    catch {
        Write-Warning "Failed to write EventLog: $($_.Exception.Message)"
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-UserSidFromHKU {
    <#
    .SYNOPSIS
        Returns all user SIDs from loaded HKU hives (excludes system accounts)
    #>
    [CmdletBinding()]
    param()

    $hkuPath = 'Registry::HKEY_USERS'
    $systemSidPatterns = @(
        'S-1-5-18',      # Local System
        'S-1-5-19',      # Local Service
        'S-1-5-20',      # Network Service
        '_Classes'       # Suffix for virtualized keys
    )

    Get-ChildItem -Path $hkuPath -ErrorAction SilentlyContinue |
        Where-Object {
            $sid = $_.PSChildName
            # Only include user SIDs (S-1-5-21-...)
            $sid -match '^S-1-5-21-' -and
            -not ($systemSidPatterns | Where-Object { $sid -like "*$_*" })
        } |
        ForEach-Object { $_.PSChildName }
}

function Get-UsernameFromSid {
    <#
    .SYNOPSIS
        Resolves a SID to a username
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Sid
    )

    try {
        $sidObject = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $account = $sidObject.Translate([System.Security.Principal.NTAccount])
        return $account.Value
    }
    catch {
        return $Sid  # Return SID if translation fails
    }
}

function Test-ProgIdExists {
    <#
    .SYNOPSIS
        Tests if a ProgId exists in HKCR (HKLM\SOFTWARE\Classes or HKCU\SOFTWARE\Classes)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProgId
    )

    # Check HKLM
    $hklmPath = "HKLM:\SOFTWARE\Classes\$ProgId"
    if (Test-Path $hklmPath) {
        return $true
    }

    # Check in all user hives (for user-installed apps)
    foreach ($sid in (Get-UserSidFromHKU)) {
        $hkuPath = "Registry::HKEY_USERS\$sid\SOFTWARE\Classes\$ProgId"
        if (Test-Path $hkuPath) {
            return $true
        }
    }

    return $false
}

function Test-IsProtocol {
    <#
    .SYNOPSIS
        Determines if the identifier is a protocol (not starting with .)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identifier
    )

    return -not $Identifier.StartsWith('.')
}

# ============================================================================
# HASH CALCULATION (duplicated from FTA-Manager.psm1 for standalone operation)
# ============================================================================

function Get-HexDateTime {
    [CmdletBinding()]
    param()

    $now = [DateTime]::Now
    $roundedTime = [DateTime]::new($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
    $fileTime = $roundedTime.ToFileTime()
    return $fileTime.ToString("x16")
}

function Get-Hash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseInfo
    )

    function local:Get-ShiftRight {
        param([long]$iValue, [int]$iCount)
        if ($iValue -band 0x80000000) {
            return ($iValue -shr $iCount) -bxor 0xFFFF0000
        }
        return $iValue -shr $iCount
    }

    function local:Get-Long {
        param([byte[]]$Bytes, [int]$Index = 0)
        return [BitConverter]::ToInt32($Bytes, $Index)
    }

    function local:Convert-Int32 {
        param([long]$Value)
        [byte[]]$bytes = [BitConverter]::GetBytes($Value)
        return [BitConverter]::ToInt32($bytes, 0)
    }

    [byte[]]$bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($BaseInfo)
    $bytesBaseInfo += 0x00, 0x00

    $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    [byte[]]$bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)

    $lengthBase = ($BaseInfo.Length * 2) + 2
    $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase 2) - 1
    $base64Hash = ""

    if ($length -gt 1) {
        $map = @{
            PDATA = 0; CACHE = 0; COUNTER = 0; INDEX = 0
            MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0
            R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0
            R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
        }

        $map.CACHE = 0
        $map.OUTHASH1 = 0
        $map.PDATA = 0
        $map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
        $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
        $map.INDEX = Get-ShiftRight ($length - 2) 1
        $map.COUNTER = $map.INDEX + 1

        while ($map.COUNTER) {
            $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
            $map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
            $map.PDATA = $map.PDATA + 8
            $map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
            $map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
            $map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16)))
            $map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
            $map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
            $map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
            $map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
            $map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
            $map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
            $map.CACHE = ([long]$map.OUTHASH2)
            $map.COUNTER = $map.COUNTER - 1
        }

        [byte[]]$outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        [byte[]]$buffer = [BitConverter]::GetBytes($map.OUTHASH1)
        $buffer.CopyTo($outHash, 0)
        $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
        $buffer.CopyTo($outHash, 4)

        $map = @{
            PDATA = 0; CACHE = 0; COUNTER = 0; INDEX = 0
            MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0
            R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0
            R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
        }

        $map.CACHE = 0
        $map.OUTHASH1 = 0
        $map.PDATA = 0
        $map.MD51 = ((Get-Long $bytesMD5) -bor 1)
        $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
        $map.INDEX = Get-ShiftRight ($length - 2) 1
        $map.COUNTER = $map.INDEX + 1

        while ($map.COUNTER) {
            $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
            $map.PDATA = $map.PDATA + 8
            $map.R1[0] = Convert-Int32 ($map.R0 * [long]$map.MD51)
            $map.R1[1] = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
            $map.R2[0] = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
            $map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
            $map.R3 = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
            $map.R4[0] = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
            $map.R4[1] = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
            $map.R5[0] = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
            $map.R5[1] = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
            $map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
            $map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3)
            $map.CACHE = ([long]$map.OUTHASH2)
            $map.COUNTER = $map.COUNTER - 1
        }

        $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
        $buffer.CopyTo($outHash, 8)
        $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
        $buffer.CopyTo($outHash, 12)

        [byte[]]$outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        $hashValue1 = ((Get-Long $outHash 8) -bxor (Get-Long $outHash))
        $hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))

        $buffer = [BitConverter]::GetBytes($hashValue1)
        $buffer.CopyTo($outHashBase, 0)
        $buffer = [BitConverter]::GetBytes($hashValue2)
        $buffer.CopyTo($outHashBase, 4)
        $base64Hash = [Convert]::ToBase64String($outHashBase)
    }

    return $base64Hash
}

function Get-UserExperience {
    return "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
}

function Get-UserChoiceHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Extension,

        [Parameter(Mandatory)]
        [string]$UserSid,

        [Parameter(Mandatory)]
        [string]$ProgId,

        [Parameter(Mandatory)]
        [string]$Timestamp
    )

    $userExperience = Get-UserExperience
    $baseInfo = "$Extension$UserSid$ProgId$Timestamp$userExperience".ToLower()

    return Get-Hash -BaseInfo $baseInfo
}

# ============================================================================
# REGINI EXECUTION
# ============================================================================

function Set-UserChoiceViaReginiService {
    <#
    .SYNOPSIS
        Sets UserChoice via regini.exe for a specific user SID
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Extension,

        [Parameter(Mandatory)]
        [string]$ProgId,

        [Parameter(Mandatory)]
        [string]$UserSID,

        [Parameter()]
        [switch]$IsProtocol
    )

    # Build registry path (NT format for regini)
    if ($IsProtocol) {
        $regPath = "\Registry\User\$UserSID\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice"
    }
    else {
        $regPath = "\Registry\User\$UserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
    }

    # Calculate timestamp and hash
    $timestamp = Get-HexDateTime
    $hash = Get-UserChoiceHash -Extension $Extension -UserSid $UserSID -ProgId $ProgId -Timestamp $timestamp

    Write-Verbose "Set-UserChoiceViaReginiService: $Extension -> $ProgId for SID $UserSID (Hash: $hash)"

    # Create temp folder for INI files
    $tempFolder = Join-Path $env:TEMP ([Guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $tempFolder -Force -ErrorAction Stop | Out-Null

        # Create DELETE INI file
        $deleteIni = Join-Path $tempFolder 'delete.ini'
        $deleteContent = "$regPath [DELETE]`r`n"
        [System.IO.File]::WriteAllText($deleteIni, $deleteContent, [System.Text.Encoding]::ASCII)

        # Create SET INI file
        $setIni = Join-Path $tempFolder 'set.ini'
        $setContent = @"
$regPath
ProgId="$ProgId"
Hash="$hash"
0
"@
        [System.IO.File]::WriteAllText($setIni, $setContent, [System.Text.Encoding]::ASCII)

        # Execute regini.exe - DELETE
        Write-Verbose "Executing regini.exe DELETE..."
        $null = & regini.exe $deleteIni 2>&1

        # Brief pause
        Start-Sleep -Milliseconds 100

        # Execute regini.exe - SET
        Write-Verbose "Executing regini.exe SET..."
        $setResult = & regini.exe $setIni 2>&1
        $setExitCode = $LASTEXITCODE

        if ($setExitCode -ne 0) {
            throw "regini.exe SET failed with exit code $setExitCode : $setResult"
        }

        # Verify
        if ($IsProtocol) {
            $verifyPath = "Registry::HKEY_USERS\$UserSID\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice"
        }
        else {
            $verifyPath = "Registry::HKEY_USERS\$UserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
        }

        if (Test-Path $verifyPath) {
            $currentProgId = (Get-ItemProperty -Path $verifyPath -ErrorAction SilentlyContinue).ProgId
            if ($currentProgId -eq $ProgId) {
                Write-Verbose "Set-UserChoiceViaReginiService: SUCCESS - Verified $Extension -> $currentProgId"
                return @{ Success = $true; Hash = $hash }
            }
            else {
                throw "Verification failed - expected '$ProgId', got '$currentProgId'"
            }
        }
        else {
            throw "Verification failed - UserChoice key does not exist after write"
        }
    }
    finally {
        # Cleanup temp folder
        if (Test-Path $tempFolder) {
            Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ============================================================================
# REQUEST PROCESSING
# ============================================================================

function Get-FTARequests {
    <#
    .SYNOPSIS
        Gets all pending FTA requests from all loaded user hives
    #>
    [CmdletBinding()]
    param()

    $requests = @()

    foreach ($sid in (Get-UserSidFromHKU)) {
        $requestPath = "Registry::HKEY_USERS\$sid\$($script:Config.RequestKeyPath)"

        if (Test-Path $requestPath) {
            $username = Get-UsernameFromSid -Sid $sid

            $props = Get-ItemProperty -Path $requestPath -ErrorAction SilentlyContinue
            $props.PSObject.Properties |
                Where-Object { $_.Name -notlike 'PS*' } |
                ForEach-Object {
                    $requests += [PSCustomObject]@{
                        UserSID    = $sid
                        Username   = $username
                        Identifier = $_.Name
                        ProgId     = $_.Value
                        IsProtocol = Test-IsProtocol -Identifier $_.Name
                        RegistryPath = $requestPath
                    }
                }
        }
    }

    return $requests
}

function Remove-FTARequest {
    <#
    .SYNOPSIS
        Removes a processed request from the queue
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RegistryPath,

        [Parameter(Mandatory)]
        [string]$Identifier
    )

    try {
        Remove-ItemProperty -Path $RegistryPath -Name $Identifier -ErrorAction Stop
        Write-Verbose "Removed request: $Identifier from $RegistryPath"
        return $true
    }
    catch {
        Write-Warning "Failed to remove request $Identifier : $($_.Exception.Message)"
        return $false
    }
}

function Invoke-ProcessFTARequest {
    <#
    .SYNOPSIS
        Processes a single FTA request
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$Request
    )

    process {
        $identifier = $Request.Identifier
        $progId = $Request.ProgId
        $username = $Request.Username
        $sid = $Request.UserSID

        Write-Verbose "Processing request: $identifier -> $progId for $username ($sid)"

        # Step 1: Validate ProgId exists
        if (-not (Test-ProgIdExists -ProgId $progId)) {
            $message = "ProgId '$progId' not found for $identifier (User: $username)"
            Write-FTAEventLog -EventId $script:Config.EventIdProgIdNotFound `
                              -Message $message `
                              -EntryType Warning
            # Remove request anyway (no retry)
            Remove-FTARequest -RegistryPath $Request.RegistryPath -Identifier $identifier
            return [PSCustomObject]@{
                Success    = $false
                Identifier = $identifier
                ProgId     = $progId
                Username   = $username
                Error      = "ProgId not found"
            }
        }

        # Step 2: Apply the change via regini.exe
        try {
            $result = Set-UserChoiceViaReginiService -Extension $identifier `
                                                      -ProgId $progId `
                                                      -UserSID $sid `
                                                      -IsProtocol:$Request.IsProtocol

            if ($result.Success) {
                $message = "FTA successfully set: $identifier -> $progId (User: $username, Hash: $($result.Hash))"
                Write-FTAEventLog -EventId $script:Config.EventIdSuccess `
                                  -Message $message `
                                  -EntryType Information

                # Remove processed request
                Remove-FTARequest -RegistryPath $Request.RegistryPath -Identifier $identifier

                return [PSCustomObject]@{
                    Success    = $true
                    Identifier = $identifier
                    ProgId     = $progId
                    Username   = $username
                    Hash       = $result.Hash
                }
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            $message = "regini.exe failed for $identifier -> $progId (User: $username): $errorMessage"
            Write-FTAEventLog -EventId $script:Config.EventIdReginiFailed `
                              -Message $message `
                              -EntryType Warning

            # Remove request anyway (no retry)
            Remove-FTARequest -RegistryPath $Request.RegistryPath -Identifier $identifier

            return [PSCustomObject]@{
                Success    = $false
                Identifier = $identifier
                ProgId     = $progId
                Username   = $username
                Error      = $errorMessage
            }
        }
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Invoke-FTAManagerService {
    <#
    .SYNOPSIS
        Main entry point for the FTA-Manager Service
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "FTA-Manager-Service starting..."

    # Initialize EventLog
    if (-not (Initialize-FTAEventLog)) {
        Write-Error "Failed to initialize EventLog - continuing without logging"
    }

    # Get all pending requests
    $requests = Get-FTARequests

    if ($requests.Count -eq 0) {
        Write-Verbose "No pending FTA requests found"
        return @{
            Processed = 0
            Succeeded = 0
            Failed    = 0
            Results   = @()
        }
    }

    Write-Verbose "Found $($requests.Count) pending request(s)"

    # Process all requests
    $results = $requests | Invoke-ProcessFTARequest

    # Summary
    $succeeded = @($results | Where-Object { $_.Success }).Count
    $failed = @($results | Where-Object { -not $_.Success }).Count

    Write-Verbose "FTA-Manager-Service completed: $succeeded succeeded, $failed failed"

    return @{
        Processed = $requests.Count
        Succeeded = $succeeded
        Failed    = $failed
        Results   = $results
    }
}

# Run the service
$serviceResult = Invoke-FTAManagerService -Verbose:$VerbosePreference
$serviceResult

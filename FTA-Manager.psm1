#Requires -Version 5.1
<#
.SYNOPSIS
    FTA-Manager - File Type Association Manager for Windows 10/11

.DESCRIPTION
    PowerShell module to manage file type associations (FTA) and protocol associations (PTA)
    by computing the correct UserChoice hash that Windows requires since Windows 8.

.NOTES
    Author: FTA-Manager Project
    License: MIT
    Based on research from PS-SFTA and SetUserFTA projects
#>

# ============================================================================
# INTERNAL HELPER FUNCTIONS
# ============================================================================

function Get-UserSid {
    [CmdletBinding()]
    param()
    return ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
}

function Get-HexDateTime {
    [CmdletBinding()]
    param()

    $now = [DateTime]::Now
    $roundedTime = [DateTime]::new($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
    $fileTime = $roundedTime.ToFileTime()
    return $fileTime.ToString("x16")
}

function Get-Hash {
    <#
    .SYNOPSIS
        Computes the UserChoice hash using the Windows algorithm
    .DESCRIPTION
        Implementation based on PS-SFTA (https://github.com/DanysysTeam/PS-SFTA)
        Uses two-pass algorithm with proper 32-bit integer truncation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BaseInfo
    )

    function local:Get-ShiftRight {
        param(
            [long]$iValue,
            [int]$iCount
        )
        if ($iValue -band 0x80000000) {
            return ($iValue -shr $iCount) -bxor 0xFFFF0000
        }
        return $iValue -shr $iCount
    }

    function local:Get-Long {
        param(
            [byte[]]$Bytes,
            [int]$Index = 0
        )
        return [BitConverter]::ToInt32($Bytes, $Index)
    }

    function local:Convert-Int32 {
        param([long]$Value)
        [byte[]]$bytes = [BitConverter]::GetBytes($Value)
        return [BitConverter]::ToInt32($bytes, 0)
    }

    # Convert to UTF-16LE bytes with null terminator
    [byte[]]$bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($BaseInfo)
    $bytesBaseInfo += 0x00, 0x00

    # Compute MD5
    $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    [byte[]]$bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)

    $lengthBase = ($BaseInfo.Length * 2) + 2
    $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase 2) - 1
    $base64Hash = ""

    if ($length -gt 1) {
        # Initialize map for first pass
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

        # First pass
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

        # Store first pass results
        [byte[]]$outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        [byte[]]$buffer = [BitConverter]::GetBytes($map.OUTHASH1)
        $buffer.CopyTo($outHash, 0)
        $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
        $buffer.CopyTo($outHash, 4)

        # Reinitialize map for second pass
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

        # Second pass
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

        # Store second pass results
        $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
        $buffer.CopyTo($outHash, 8)
        $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
        $buffer.CopyTo($outHash, 12)

        # Combine results
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
    [CmdletBinding()]
    param()
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
# UCPD (User Choice Protection Driver) FUNCTIONS
# ============================================================================

function Test-UCPDEnabled {
    <#
    .SYNOPSIS
        Tests if the User Choice Protection Driver (UCPD) is enabled

    .DESCRIPTION
        Windows 10/11 (Feb 2022+) introduced UCPD which blocks changes to
        http, https, and .pdf associations via registry manipulation.
    #>
    [CmdletBinding()]
    param()

    $ucpdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UCPD"

    if (Test-Path $ucpdPath) {
        $startValue = (Get-ItemProperty -Path $ucpdPath -Name "Start" -ErrorAction SilentlyContinue).Start
        # Start = 4 means disabled
        return ($startValue -ne 4)
    }

    return $false
}

function Get-UCPDStatus {
    <#
    .SYNOPSIS
        Gets detailed UCPD status information
    #>
    [CmdletBinding()]
    param()

    $ucpdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UCPD"

    if (Test-Path $ucpdPath) {
        $props = Get-ItemProperty -Path $ucpdPath -ErrorAction SilentlyContinue
        $enabled = ($props.Start -ne 4)

        return [PSCustomObject]@{
            Exists       = $true
            Enabled      = $enabled
            StartValue   = $props.Start
            ImagePath    = $props.ImagePath
            Description  = "User Choice Protection Driver - Blocks changes to HTTP/HTTPS/PDF associations"
            CanDisable   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    }

    return [PSCustomObject]@{
        Exists     = $false
        Enabled    = $false
        StartValue = $null
        ImagePath  = $null
        Description = "UCPD not found (older Windows version)"
        CanDisable = $false
    }
}

function Disable-UCPD {
    <#
    .SYNOPSIS
        Disables the User Choice Protection Driver (requires Admin + Reboot)

    .DESCRIPTION
        WARNING: This modifies system settings. Requires administrator privileges.
        A reboot is required for changes to take effect.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Error "Administrator privileges required to disable UCPD"
        return $false
    }

    $ucpdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UCPD"

    if ($PSCmdlet.ShouldProcess("UCPD Service", "Disable (Start = 4)")) {
        try {
            New-ItemProperty -Path $ucpdPath -Name "Start" -Value 4 -PropertyType DWORD -Force | Out-Null
            Write-Warning "UCPD disabled. A REBOOT is required for changes to take effect."
            return $true
        }
        catch {
            Write-Error "Failed to disable UCPD: $_"
            return $false
        }
    }
}

function Enable-UCPD {
    <#
    .SYNOPSIS
        Re-enables the User Choice Protection Driver
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Error "Administrator privileges required to enable UCPD"
        return $false
    }

    $ucpdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UCPD"

    if ($PSCmdlet.ShouldProcess("UCPD Service", "Enable (Start = 2)")) {
        try {
            New-ItemProperty -Path $ucpdPath -Name "Start" -Value 2 -PropertyType DWORD -Force | Out-Null
            Write-Warning "UCPD enabled. A REBOOT is required for changes to take effect."
            return $true
        }
        catch {
            Write-Error "Failed to enable UCPD: $_"
            return $false
        }
    }
}

function Test-IsWindowsServer {
    <#
    .SYNOPSIS
        Tests if the current system is Windows Server

    .DESCRIPTION
        Windows Server does NOT have UCPD installed.
        All file type and protocol associations can be set without restrictions.

    .EXAMPLE
        if (Test-IsWindowsServer) { "No UCPD restrictions here!" }
    #>
    [CmdletBinding()]
    param()

    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($osInfo) {
        # ProductType: 1 = Workstation, 2 = Domain Controller, 3 = Server
        return ($osInfo.ProductType -ne 1)
    }

    # Fallback: check OS caption
    $caption = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).ProductName
    return ($caption -like "*Server*")
}

function Get-UCPDScheduledTask {
    <#
    .SYNOPSIS
        Gets the UCPD velocity scheduled task status

    .DESCRIPTION
        The 'UCPD velocity' scheduled task can re-enable UCPD after it has been disabled.
        This function checks its current state.
    #>
    [CmdletBinding()]
    param()

    try {
        $task = Get-ScheduledTask -TaskName "UCPD velocity" -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -ErrorAction SilentlyContinue
        if ($task) {
            return [PSCustomObject]@{
                Exists  = $true
                State   = $task.State
                Enabled = ($task.State -ne 'Disabled')
                TaskPath = "\Microsoft\Windows\AppxDeploymentClient\UCPD velocity"
            }
        }
    }
    catch {}

    return [PSCustomObject]@{
        Exists   = $false
        State    = $null
        Enabled  = $false
        TaskPath = $null
    }
}

function Disable-UCPDScheduledTask {
    <#
    .SYNOPSIS
        Disables the UCPD velocity scheduled task (requires Admin)

    .DESCRIPTION
        The 'UCPD velocity' task can re-enable UCPD after Windows updates.
        Disabling this task prevents UCPD from being automatically re-enabled.

        WARNING: This should only be done in controlled environments where
        UCPD protection is not desired.

    .EXAMPLE
        Disable-UCPDScheduledTask
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Error "Administrator privileges required to disable UCPD scheduled task"
        return $false
    }

    if ($PSCmdlet.ShouldProcess("UCPD velocity", "Disable Scheduled Task")) {
        try {
            Disable-ScheduledTask -TaskName "UCPD velocity" -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -ErrorAction Stop | Out-Null
            Write-Warning "UCPD velocity scheduled task disabled. UCPD will no longer be automatically re-enabled."
            return $true
        }
        catch {
            Write-Error "Failed to disable UCPD scheduled task: $_"
            return $false
        }
    }
}

function Enable-UCPDScheduledTask {
    <#
    .SYNOPSIS
        Re-enables the UCPD velocity scheduled task (requires Admin)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Error "Administrator privileges required to enable UCPD scheduled task"
        return $false
    }

    if ($PSCmdlet.ShouldProcess("UCPD velocity", "Enable Scheduled Task")) {
        try {
            Enable-ScheduledTask -TaskName "UCPD velocity" -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -ErrorAction Stop | Out-Null
            Write-Verbose "UCPD velocity scheduled task enabled."
            return $true
        }
        catch {
            Write-Error "Failed to enable UCPD scheduled task: $_"
            return $false
        }
    }
}

function Open-DefaultAppsSettings {
    <#
    .SYNOPSIS
        Opens Windows Default Apps settings

    .DESCRIPTION
        Since UCPD blocks programmatic changes to protected associations (PDF, HTTP, HTTPS),
        this function opens the Windows Settings page where users can manually change defaults.

        This is the ONLY reliable way to change protected associations on Windows 10/11
        with UCPD enabled.

    .PARAMETER Extension
        Optional: Opens settings for a specific file extension (e.g., ".pdf")

    .PARAMETER Protocol
        Optional: Opens settings for a specific protocol (e.g., "http")

    .EXAMPLE
        Open-DefaultAppsSettings

    .EXAMPLE
        Open-DefaultAppsSettings -Extension ".pdf"

    .EXAMPLE
        Open-DefaultAppsSettings -Protocol "http"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Extension,

        [Parameter()]
        [string]$Protocol
    )

    if ($Extension) {
        # Open default apps settings for specific extension
        if (-not $Extension.StartsWith(".")) {
            $Extension = ".$Extension"
        }
        Write-Host "Opening Windows Settings for '$Extension'..." -ForegroundColor Cyan
        Write-Host "Please select your preferred application manually." -ForegroundColor Yellow
        Start-Process "ms-settings:defaultapps" -Wait:$false
    }
    elseif ($Protocol) {
        Write-Host "Opening Windows Settings for '$Protocol' protocol..." -ForegroundColor Cyan
        Write-Host "Please select your preferred application manually." -ForegroundColor Yellow
        Start-Process "ms-settings:defaultapps" -Wait:$false
    }
    else {
        Write-Host "Opening Windows Default Apps Settings..." -ForegroundColor Cyan
        Start-Process "ms-settings:defaultapps" -Wait:$false
    }

    return $true
}

function Get-EDRStatus {
    <#
    .SYNOPSIS
        Detects installed EDR/XDR solutions

    .DESCRIPTION
        Checks for common EDR/XDR solutions that provide protection against
        malware and browser hijacking. This is used by Disable-UCPDSafely
        to verify that alternative protection is in place.

    .EXAMPLE
        Get-EDRStatus

    .EXAMPLE
        if ((Get-EDRStatus).IsProtected) { "EDR protection active" }
    #>
    [CmdletBinding()]
    param()

    $edrProducts = @()

    # Check Windows Security Center for registered AV/EDR products
    try {
        $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
        foreach ($av in $avProducts) {
            $edrProducts += [PSCustomObject]@{
                Name       = $av.displayName
                State      = $av.productState
                Source     = "SecurityCenter2"
                IsEDR      = $av.displayName -match "Defender for Endpoint|CrowdStrike|SentinelOne|Carbon Black|Cortex|Sophos|ESET|Trend Micro|McAfee|Symantec|Cylance"
            }
        }
    }
    catch {}

    # Check for Microsoft Defender for Endpoint (ATP)
    $defenderATP = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
    if ($defenderATP -and $defenderATP.Status -eq "Running") {
        $edrProducts += [PSCustomObject]@{
            Name       = "Microsoft Defender for Endpoint"
            State      = "Running"
            Source     = "Service:Sense"
            IsEDR      = $true
        }
    }

    # Check for CrowdStrike Falcon
    $crowdstrike = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
    if ($crowdstrike -and $crowdstrike.Status -eq "Running") {
        $edrProducts += [PSCustomObject]@{
            Name       = "CrowdStrike Falcon"
            State      = "Running"
            Source     = "Service:CSFalconService"
            IsEDR      = $true
        }
    }

    # Check for SentinelOne
    $sentinelone = Get-Service -Name "SentinelAgent" -ErrorAction SilentlyContinue
    if ($sentinelone -and $sentinelone.Status -eq "Running") {
        $edrProducts += [PSCustomObject]@{
            Name       = "SentinelOne"
            State      = "Running"
            Source     = "Service:SentinelAgent"
            IsEDR      = $true
        }
    }

    # Check for Carbon Black
    $carbonblack = Get-Service -Name "CbDefense" -ErrorAction SilentlyContinue
    if (-not $carbonblack) { $carbonblack = Get-Service -Name "CbDefenseSensor" -ErrorAction SilentlyContinue }
    if ($carbonblack -and $carbonblack.Status -eq "Running") {
        $edrProducts += [PSCustomObject]@{
            Name       = "VMware Carbon Black"
            State      = "Running"
            Source     = "Service:CbDefense"
            IsEDR      = $true
        }
    }

    # Check for Cortex XDR
    $cortex = Get-Service -Name "CortexXDR" -ErrorAction SilentlyContinue
    if (-not $cortex) { $cortex = Get-Service -Name "Traps" -ErrorAction SilentlyContinue }
    if ($cortex -and $cortex.Status -eq "Running") {
        $edrProducts += [PSCustomObject]@{
            Name       = "Palo Alto Cortex XDR"
            State      = "Running"
            Source     = "Service:CortexXDR"
            IsEDR      = $true
        }
    }

    # Check for Sophos
    $sophos = Get-Service -Name "Sophos Endpoint Defense Service" -ErrorAction SilentlyContinue
    if ($sophos -and $sophos.Status -eq "Running") {
        $edrProducts += [PSCustomObject]@{
            Name       = "Sophos Endpoint"
            State      = "Running"
            Source     = "Service:Sophos"
            IsEDR      = $true
        }
    }

    # Deduplicate by name
    $uniqueProducts = $edrProducts | Sort-Object Name -Unique

    # Determine if any real EDR is present
    $hasEDR = ($uniqueProducts | Where-Object { $_.IsEDR }).Count -gt 0

    return [PSCustomObject]@{
        IsProtected   = $hasEDR
        Products      = $uniqueProducts
        EDRCount      = ($uniqueProducts | Where-Object { $_.IsEDR }).Count
        HasDefenderATP = ($uniqueProducts | Where-Object { $_.Name -eq "Microsoft Defender for Endpoint" }).Count -gt 0
        Timestamp     = Get-Date
    }
}

function Disable-UCPDSafely {
    <#
    .SYNOPSIS
        Safely disables UCPD with EDR verification and logging (requires Admin)

    .DESCRIPTION
        This function provides a "safe" way to disable UCPD in enterprise environments
        where EDR/XDR protection is in place. It:

        1. Checks for active EDR/XDR solutions
        2. Warns if no EDR is detected
        3. Disables UCPD driver (Start = 4)
        4. Disables the UCPD velocity scheduled task
        5. Logs the action to Windows Event Log and optionally to a file

        This is intended for enterprise environments where:
        - Central EDR/XDR provides malware protection
        - Automated FTA deployment is required
        - Security team has approved UCPD deactivation

    .PARAMETER Reason
        Mandatory reason for disabling UCPD (for audit logging)

    .PARAMETER Force
        Bypass the EDR check warning (use with caution!)

    .PARAMETER LogPath
        Optional path for log file. Default: C:\Windows\Logs\FTA-Manager\UCPD.log

    .EXAMPLE
        Disable-UCPDSafely -Reason "FTA Deployment for Adobe Acrobat"

    .EXAMPLE
        Disable-UCPDSafely -Reason "Browser standardization" -Force

    .NOTES
        Requires Administrator privileges and a REBOOT to take effect.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Reason,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [string]$LogPath = "C:\Windows\Logs\FTA-Manager\UCPD.log"
    )

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "Administrator privileges required for Disable-UCPDSafely"
        return [PSCustomObject]@{ Success = $false; Error = "Not running as Administrator" }
    }

    # Check if Windows Server (UCPD doesn't exist there)
    if (Test-IsWindowsServer) {
        Write-Host "Windows Server detected - UCPD is not present on Server editions." -ForegroundColor Green
        return [PSCustomObject]@{
            Success     = $true
            Message     = "UCPD not present on Windows Server"
            IsServer    = $true
            RebootRequired = $false
        }
    }

    # Check EDR status
    $edrStatus = Get-EDRStatus
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $computerName = $env:COMPUTERNAME
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    if (-not $edrStatus.IsProtected -and -not $Force) {
        Write-Warning @"
NO EDR/XDR PROTECTION DETECTED!

Disabling UCPD without EDR protection is a security risk.
Malware could hijack browser and PDF associations.

Detected security products:
$($edrStatus.Products | ForEach-Object { "  - $($_.Name)" } | Out-String)

If you have EDR that wasn't detected, or accept the risk, use -Force.
"@
        return [PSCustomObject]@{
            Success       = $false
            Error         = "No EDR protection detected"
            EDRStatus     = $edrStatus
            Recommendation = "Install EDR/XDR or use -Force (not recommended)"
        }
    }

    if ($PSCmdlet.ShouldProcess("UCPD", "Disable safely with logging")) {
        $results = @{
            UCPDDisabled = $false
            TaskDisabled = $false
            LogWritten   = $false
            Errors       = @()
        }

        # 1. Disable UCPD driver
        try {
            $ucpdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UCPD"
            New-ItemProperty -Path $ucpdPath -Name "Start" -Value 4 -PropertyType DWORD -Force | Out-Null
            $results.UCPDDisabled = $true
            Write-Host "[OK] UCPD driver disabled (Start = 4)" -ForegroundColor Green
        }
        catch {
            $results.Errors += "Failed to disable UCPD: $_"
            Write-Error "Failed to disable UCPD driver: $_"
        }

        # 2. Disable scheduled task
        try {
            Disable-ScheduledTask -TaskName "UCPD velocity" -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -ErrorAction Stop | Out-Null
            $results.TaskDisabled = $true
            Write-Host "[OK] UCPD velocity scheduled task disabled" -ForegroundColor Green
        }
        catch {
            $results.Errors += "Failed to disable scheduled task: $_"
            Write-Warning "Failed to disable UCPD scheduled task: $_"
        }

        # 3. Write log
        $logEntry = @"
================================================================================
UCPD DEACTIVATION LOG
================================================================================
Timestamp:    $timestamp
Computer:     $computerName
User:         $currentUser
Reason:       $Reason
EDR Status:   $(if ($edrStatus.IsProtected) { "PROTECTED" } else { "NOT PROTECTED (Force used)" })
EDR Products: $($edrStatus.Products | Where-Object { $_.IsEDR } | ForEach-Object { $_.Name } | Join-String -Separator ", ")

Actions:
  - UCPD Driver:    $(if ($results.UCPDDisabled) { "Disabled" } else { "FAILED" })
  - Scheduled Task: $(if ($results.TaskDisabled) { "Disabled" } else { "FAILED" })

Errors: $(if ($results.Errors.Count -eq 0) { "None" } else { $results.Errors -join "; " })
================================================================================

"@

        try {
            $logDir = Split-Path $LogPath -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8
            $results.LogWritten = $true
            Write-Host "[OK] Action logged to: $LogPath" -ForegroundColor Green
        }
        catch {
            $results.Errors += "Failed to write log: $_"
            Write-Warning "Failed to write log file: $_"
        }

        # 4. Write to Windows Event Log
        try {
            $eventMessage = "UCPD disabled by $currentUser. Reason: $Reason. EDR: $(if ($edrStatus.IsProtected) { $edrStatus.Products | Where-Object { $_.IsEDR } | ForEach-Object { $_.Name } | Join-String -Separator ', ' } else { 'None detected (Force used)' })"
            Write-EventLog -LogName "Application" -Source "FTA-Manager" -EventId 1000 -EntryType Warning -Message $eventMessage -ErrorAction SilentlyContinue
        }
        catch {
            # Event source might not exist, that's OK
        }

        # Summary
        $success = $results.UCPDDisabled
        Write-Host ""
        if ($success) {
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host " UCPD SUCCESSFULLY DISABLED" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host " A REBOOT IS REQUIRED for changes to take effect!" -ForegroundColor Red
            Write-Host ""
            Write-Host " After reboot, Set-FTA and Set-PTA will work for:" -ForegroundColor Cyan
            Write-Host "   - .pdf, .htm, .html" -ForegroundColor White
            Write-Host "   - http, https protocols" -ForegroundColor White
            Write-Host ""
            if ($edrStatus.IsProtected) {
                Write-Host " EDR Protection: $($edrStatus.Products | Where-Object { $_.IsEDR } | ForEach-Object { $_.Name } | Join-String -Separator ', ')" -ForegroundColor Green
            }
        }

        return [PSCustomObject]@{
            Success        = $success
            UCPDDisabled   = $results.UCPDDisabled
            TaskDisabled   = $results.TaskDisabled
            LogWritten     = $results.LogWritten
            LogPath        = $LogPath
            EDRStatus      = $edrStatus
            RebootRequired = $true
            Timestamp      = $timestamp
            User           = $currentUser
            Reason         = $Reason
            Errors         = $results.Errors
        }
    }
}

function Enable-UCPDSafely {
    <#
    .SYNOPSIS
        Re-enables UCPD with logging (requires Admin)

    .DESCRIPTION
        Re-enables UCPD driver and scheduled task, with logging.

    .PARAMETER Reason
        Optional reason for re-enabling UCPD

    .PARAMETER LogPath
        Optional path for log file. Default: C:\Windows\Logs\FTA-Manager\UCPD.log

    .EXAMPLE
        Enable-UCPDSafely -Reason "FTA deployment completed"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Position = 0)]
        [string]$Reason = "Manual re-enablement",

        [Parameter()]
        [string]$LogPath = "C:\Windows\Logs\FTA-Manager\UCPD.log"
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "Administrator privileges required for Enable-UCPDSafely"
        return [PSCustomObject]@{ Success = $false; Error = "Not running as Administrator" }
    }

    if (Test-IsWindowsServer) {
        Write-Host "Windows Server detected - UCPD is not present on Server editions." -ForegroundColor Green
        return [PSCustomObject]@{ Success = $true; Message = "UCPD not present on Windows Server"; IsServer = $true }
    }

    if ($PSCmdlet.ShouldProcess("UCPD", "Re-enable with logging")) {
        $results = @{ UCPDEnabled = $false; TaskEnabled = $false; Errors = @() }
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # Enable UCPD driver
        try {
            $ucpdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\UCPD"
            New-ItemProperty -Path $ucpdPath -Name "Start" -Value 2 -PropertyType DWORD -Force | Out-Null
            $results.UCPDEnabled = $true
            Write-Host "[OK] UCPD driver enabled (Start = 2)" -ForegroundColor Green
        }
        catch {
            $results.Errors += "Failed to enable UCPD: $_"
            Write-Error "Failed to enable UCPD driver: $_"
        }

        # Enable scheduled task
        try {
            Enable-ScheduledTask -TaskName "UCPD velocity" -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -ErrorAction Stop | Out-Null
            $results.TaskEnabled = $true
            Write-Host "[OK] UCPD velocity scheduled task enabled" -ForegroundColor Green
        }
        catch {
            $results.Errors += "Failed to enable scheduled task: $_"
            Write-Warning "Failed to enable UCPD scheduled task: $_"
        }

        # Log
        $logEntry = @"
================================================================================
UCPD RE-ACTIVATION LOG
================================================================================
Timestamp:    $timestamp
User:         $currentUser
Reason:       $Reason
UCPD Driver:  $(if ($results.UCPDEnabled) { "Enabled" } else { "FAILED" })
Scheduled Task: $(if ($results.TaskEnabled) { "Enabled" } else { "FAILED" })
================================================================================

"@
        try {
            Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        catch {}

        Write-Host ""
        Write-Warning "A REBOOT is required for UCPD to become active again."

        return [PSCustomObject]@{
            Success        = $results.UCPDEnabled
            UCPDEnabled    = $results.UCPDEnabled
            TaskEnabled    = $results.TaskEnabled
            RebootRequired = $true
            Timestamp      = $timestamp
            Reason         = $Reason
            Errors         = $results.Errors
        }
    }
}

# ============================================================================
# REGISTRY OPERATIONS
# ============================================================================

function Get-RegistryUserChoice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Extension,

        [Parameter()]
        [switch]$Protocol
    )

    if ($Protocol) {
        $regPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice"
    }
    else {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
    }

    if (Test-Path $regPath) {
        return Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    }

    return $null
}

function Set-RegistryUserChoice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Extension,

        [Parameter(Mandatory)]
        [string]$ProgId,

        [Parameter(Mandatory)]
        [string]$Hash,

        [Parameter()]
        [switch]$Protocol
    )

    if ($Protocol) {
        $regPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice"
        $regPathWin32 = "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Extension\UserChoice"
    }
    else {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
        $regPathWin32 = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
    }

    # Remove existing UserChoice key using .NET Registry API (more reliable)
    if (Test-Path $regPath) {
        try {
            $parentPath = Split-Path $regPath -Parent
            $keyName = Split-Path $regPath -Leaf
            $parentKey = Get-Item $parentPath
            $parentKey.DeleteSubKeyTree($keyName, $false)
        }
        catch {
            Remove-Item -Path $regPath -Force -Recurse -ErrorAction SilentlyContinue
        }
    }

    # Use Win32 API for setting values (more reliable across Windows versions)
    $writeError = $null
    try {
        [Microsoft.Win32.Registry]::SetValue($regPathWin32, "Hash", $Hash)
        [Microsoft.Win32.Registry]::SetValue($regPathWin32, "ProgId", $ProgId)
    }
    catch {
        # Fallback to PowerShell method with explicit error handling
        try {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $regPath -Name "ProgId" -Value $ProgId -PropertyType String -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $regPath -Name "Hash" -Value $Hash -PropertyType String -Force -ErrorAction Stop | Out-Null
        }
        catch {
            $writeError = $_
        }
    }

    # Verify the write was successful
    if ($writeError) {
        throw "Failed to write registry: $($writeError.Exception.Message)"
    }

    # Double-check by reading back
    $verification = Get-RegistryUserChoice -Extension $Extension -Protocol:$Protocol
    if (-not $verification -or $verification.ProgId -ne $ProgId) {
        throw "Registry verification failed: UserChoice was not set correctly (expected '$ProgId', got '$($verification.ProgId)')"
    }

    return $true
}

function Set-ApplicationAssociationToast {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Extension,

        [Parameter(Mandatory)]
        [string]$ProgId
    )

    $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"

    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    $valueName = "${ProgId}_$Extension"
    New-ItemProperty -Path $regPath -Name $valueName -Value 0 -PropertyType DWord -Force | Out-Null
}

# ============================================================================
# PUBLIC FUNCTIONS - FILE TYPE ASSOCIATIONS
# ============================================================================

function Get-FTA {
    <#
    .SYNOPSIS
        Gets the current file type association for an extension

    .PARAMETER Extension
        The file extension (e.g., ".pdf", ".txt")

    .EXAMPLE
        Get-FTA ".pdf"

    .EXAMPLE
        Get-FTA txt
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Extension
    )

    if (-not $Extension.StartsWith(".")) {
        $Extension = ".$Extension"
    }

    $userChoice = Get-RegistryUserChoice -Extension $Extension

    if ($userChoice) {
        return [PSCustomObject]@{
            Extension = $Extension
            ProgId    = $userChoice.ProgId
            Hash      = $userChoice.Hash
        }
    }

    return $null
}

function Set-FTA {
    <#
    .SYNOPSIS
        Sets the file type association for an extension

    .PARAMETER ProgId
        The programmatic identifier (e.g., "AcroExch.Document.DC", "Applications\notepad.exe")

    .PARAMETER Extension
        The file extension (e.g., ".pdf")

    .PARAMETER Force
        Bypass UCPD warning for protected extensions

    .EXAMPLE
        Set-FTA "AcroExch.Document.DC" ".pdf"

    .EXAMPLE
        Set-FTA "Applications\notepad.exe" ".txt"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ProgId,

        [Parameter(Mandatory, Position = 1)]
        [string]$Extension,

        [Parameter()]
        [switch]$Force
    )

    if (-not $Extension.StartsWith(".")) {
        $Extension = ".$Extension"
    }

    # Check for UCPD-protected extensions (skip check on Windows Server)
    $protectedExtensions = @(".pdf", ".htm", ".html")
    $isServer = Test-IsWindowsServer
    $ucpdActive = -not $isServer -and (Test-UCPDEnabled)

    if ($Extension -in $protectedExtensions -and $ucpdActive -and -not $Force) {
        Write-Warning @"
Extension '$Extension' is protected by UCPD (User Choice Protection Driver).

This is a Windows security feature that blocks programmatic changes to PDF/HTML associations.
Even Adobe, Chrome, and Firefox cannot bypass this - they all ask users to change it manually.

Your options:
  1. Open-DefaultAppsSettings -Extension '$Extension'  # User changes manually (recommended)
  2. Export-DefaultAssociations / Import-DefaultAssociations  # For new user profiles
  3. Use -Force to attempt anyway (will likely fail)
  4. Disable-UCPD (requires Admin + Reboot, security risk)
"@
        return [PSCustomObject]@{
            Extension     = $Extension
            ProgId        = $ProgId
            Success       = $false
            Error         = "UCPD protection active"
            Recommendation = "Use Open-DefaultAppsSettings -Extension '$Extension' for manual change"
        }
    }

    if ($PSCmdlet.ShouldProcess("$Extension -> $ProgId", "Set File Type Association")) {
        try {
            $userSid = Get-UserSid
            $timestamp = Get-HexDateTime
            $hash = Get-UserChoiceHash -Extension $Extension -UserSid $userSid -ProgId $ProgId -Timestamp $timestamp

            Set-ApplicationAssociationToast -Extension $Extension -ProgId $ProgId
            Set-RegistryUserChoice -Extension $Extension -ProgId $ProgId -Hash $hash

            Write-Verbose "Set $Extension -> $ProgId (Hash: $hash)"

            return [PSCustomObject]@{
                Extension = $Extension
                ProgId    = $ProgId
                Hash      = $hash
                Success   = $true
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
            $isUcpdError = $errorMsg -like "*permission*" -or $errorMsg -like "*access*" -or $errorMsg -like "*verification failed*"

            if ($isUcpdError -and $Extension -in $protectedExtensions) {
                Write-Error @"
Failed to set file type association: $errorMsg

This is likely due to UCPD blocking the change. Your options:
  1. Open-DefaultAppsSettings -Extension '$Extension'  # User changes manually
  2. Export-DefaultAssociations for new user profiles (DISM)
"@
            }
            else {
                Write-Error "Failed to set file type association: $errorMsg"
            }

            return [PSCustomObject]@{
                Extension      = $Extension
                ProgId         = $ProgId
                Success        = $false
                Error          = $errorMsg
                Recommendation = if ($isUcpdError) { "Use Open-DefaultAppsSettings -Extension '$Extension'" } else { $null }
            }
        }
    }
}

function Remove-FTA {
    <#
    .SYNOPSIS
        Removes a file type association

    .PARAMETER Extension
        The file extension to remove

    .EXAMPLE
        Remove-FTA ".pdf"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Extension
    )

    if (-not $Extension.StartsWith(".")) {
        $Extension = ".$Extension"
    }

    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"

    if ($PSCmdlet.ShouldProcess($Extension, "Remove File Type Association")) {
        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Force
            Write-Verbose "Removed $Extension association"
            return $true
        }
        Write-Warning "No UserChoice entry found for $Extension"
        return $false
    }
}

function Get-AllFTA {
    <#
    .SYNOPSIS
        Gets all current file type associations

    .EXAMPLE
        Get-AllFTA

    .EXAMPLE
        Get-AllFTA | Where-Object { $_.ProgId -like "*chrome*" }
    #>
    [CmdletBinding()]
    param()

    $results = @()
    $basePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"

    if (Test-Path $basePath) {
        Get-ChildItem $basePath -ErrorAction SilentlyContinue | ForEach-Object {
            $extension = $_.PSChildName
            $userChoicePath = "$($_.PSPath)\UserChoice"

            if (Test-Path $userChoicePath) {
                $props = Get-ItemProperty $userChoicePath -ErrorAction SilentlyContinue
                if ($props.ProgId) {
                    $results += [PSCustomObject]@{
                        Extension = $extension
                        ProgId    = $props.ProgId
                        Hash      = $props.Hash
                    }
                }
            }
        }
    }

    return $results | Sort-Object Extension
}

# ============================================================================
# PUBLIC FUNCTIONS - PROTOCOL ASSOCIATIONS
# ============================================================================

function Get-PTA {
    <#
    .SYNOPSIS
        Gets the current protocol association

    .PARAMETER Protocol
        The protocol (e.g., "http", "https", "mailto")

    .EXAMPLE
        Get-PTA "http"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Protocol
    )

    $userChoice = Get-RegistryUserChoice -Extension $Protocol -Protocol

    if ($userChoice) {
        return [PSCustomObject]@{
            Protocol = $Protocol
            ProgId   = $userChoice.ProgId
            Hash     = $userChoice.Hash
        }
    }

    return $null
}

function Set-PTA {
    <#
    .SYNOPSIS
        Sets the protocol association

    .PARAMETER ProgId
        The programmatic identifier (e.g., "ChromeHTML", "MSEdgeHTM")

    .PARAMETER Protocol
        The protocol (e.g., "http", "https")

    .PARAMETER Force
        Bypass UCPD warning

    .EXAMPLE
        Set-PTA "ChromeHTML" "http"

    .EXAMPLE
        Set-PTA "FirefoxURL-308046B0AF4A39CB" "https"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ProgId,

        [Parameter(Mandatory, Position = 1)]
        [string]$Protocol,

        [Parameter()]
        [switch]$Force
    )

    # Check for UCPD-protected protocols (skip check on Windows Server)
    $protectedProtocols = @("http", "https")
    $isServer = Test-IsWindowsServer
    $ucpdActive = -not $isServer -and (Test-UCPDEnabled)

    if ($Protocol -in $protectedProtocols -and $ucpdActive -and -not $Force) {
        Write-Warning @"
Protocol '$Protocol' is protected by UCPD (User Choice Protection Driver).

This is a Windows security feature that blocks programmatic changes to browser associations.
Even Chrome and Firefox cannot bypass this - they all ask users to change it manually.

Your options:
  1. Open-DefaultAppsSettings -Protocol '$Protocol'  # User changes manually (recommended)
  2. Export-DefaultAssociations / Import-DefaultAssociations  # For new user profiles
  3. Use -Force to attempt anyway (will likely fail)
  4. Disable-UCPD (requires Admin + Reboot, security risk)
"@
        return [PSCustomObject]@{
            Protocol       = $Protocol
            ProgId         = $ProgId
            Success        = $false
            Error          = "UCPD protection active"
            Recommendation = "Use Open-DefaultAppsSettings -Protocol '$Protocol' for manual change"
        }
    }

    if ($PSCmdlet.ShouldProcess("$Protocol -> $ProgId", "Set Protocol Association")) {
        try {
            $userSid = Get-UserSid
            $timestamp = Get-HexDateTime
            $hash = Get-UserChoiceHash -Extension $Protocol -UserSid $userSid -ProgId $ProgId -Timestamp $timestamp

            Set-ApplicationAssociationToast -Extension $Protocol -ProgId $ProgId
            Set-RegistryUserChoice -Extension $Protocol -ProgId $ProgId -Hash $hash -Protocol

            Write-Verbose "Set $Protocol -> $ProgId (Hash: $hash)"

            return [PSCustomObject]@{
                Protocol = $Protocol
                ProgId   = $ProgId
                Hash     = $hash
                Success  = $true
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
            $isUcpdError = $errorMsg -like "*permission*" -or $errorMsg -like "*access*" -or $errorMsg -like "*verification failed*"

            if ($isUcpdError -and $Protocol -in $protectedProtocols) {
                Write-Error @"
Failed to set protocol association: $errorMsg

This is likely due to UCPD blocking the change. Your options:
  1. Open-DefaultAppsSettings -Protocol '$Protocol'  # User changes manually
  2. Export-DefaultAssociations for new user profiles (DISM)
"@
            }
            else {
                Write-Error "Failed to set protocol association: $errorMsg"
            }

            return [PSCustomObject]@{
                Protocol       = $Protocol
                ProgId         = $ProgId
                Success        = $false
                Error          = $errorMsg
                Recommendation = if ($isUcpdError) { "Use Open-DefaultAppsSettings -Protocol '$Protocol'" } else { $null }
            }
        }
    }
}

function Remove-PTA {
    <#
    .SYNOPSIS
        Removes a protocol association

    .PARAMETER Protocol
        The protocol to remove

    .EXAMPLE
        Remove-PTA "http"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Protocol
    )

    $regPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"

    if ($PSCmdlet.ShouldProcess($Protocol, "Remove Protocol Association")) {
        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Force
            Write-Verbose "Removed $Protocol association"
            return $true
        }
        Write-Warning "No UserChoice entry found for $Protocol"
        return $false
    }
}

function Get-AllPTA {
    <#
    .SYNOPSIS
        Gets all current protocol associations

    .EXAMPLE
        Get-AllPTA
    #>
    [CmdletBinding()]
    param()

    $results = @()
    $basePath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations"

    if (Test-Path $basePath) {
        Get-ChildItem $basePath -ErrorAction SilentlyContinue | ForEach-Object {
            $protocol = $_.PSChildName
            $userChoicePath = "$($_.PSPath)\UserChoice"

            if (Test-Path $userChoicePath) {
                $props = Get-ItemProperty $userChoicePath -ErrorAction SilentlyContinue
                if ($props.ProgId) {
                    $results += [PSCustomObject]@{
                        Protocol = $protocol
                        ProgId   = $props.ProgId
                        Hash     = $props.Hash
                    }
                }
            }
        }
    }

    return $results | Sort-Object Protocol
}

# ============================================================================
# PUBLIC FUNCTIONS - UTILITY
# ============================================================================

function Get-RegisteredApplications {
    <#
    .SYNOPSIS
        Lists all registered applications (ProgIds) that can handle file types

    .PARAMETER Filter
        Optional filter for ProgId names

    .EXAMPLE
        Get-RegisteredApplications

    .EXAMPLE
        Get-RegisteredApplications -Filter "*chrome*"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Filter = "*"
    )

    $apps = @()

    foreach ($hive in @("HKCU:\SOFTWARE\Classes", "HKLM:\SOFTWARE\Classes")) {
        if (Test-Path $hive) {
            Get-ChildItem $hive -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like $Filter } |
                Where-Object { Test-Path "$($_.PSPath)\shell\open\command" } |
                ForEach-Object {
                    $command = (Get-ItemProperty "$($_.PSPath)\shell\open\command" -ErrorAction SilentlyContinue).'(Default)'
                    if ($command) {
                        $apps += [PSCustomObject]@{
                            ProgId  = $_.PSChildName
                            Command = $command
                            Source  = if ($hive -like "HKCU:*") { "HKCU" } else { "HKLM" }
                        }
                    }
                }
        }
    }

    return $apps | Sort-Object ProgId -Unique
}

function Find-ProgIdForExtension {
    <#
    .SYNOPSIS
        Finds available ProgIds that can handle a specific extension

    .PARAMETER Extension
        The file extension

    .EXAMPLE
        Find-ProgIdForExtension ".pdf"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Extension
    )

    if (-not $Extension.StartsWith(".")) {
        $Extension = ".$Extension"
    }

    $results = @()

    # Check OpenWithProgids
    $openWithPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\OpenWithProgids"
    if (Test-Path $openWithPath) {
        $props = Get-ItemProperty $openWithPath -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            $results += [PSCustomObject]@{
                ProgId    = $_.Name
                Extension = $Extension
                Source    = "OpenWithProgids"
            }
        }
    }

    # Check HKLM Classes for extension
    $hklmPath = "HKLM:\SOFTWARE\Classes\$Extension"
    if (Test-Path $hklmPath) {
        $defaultProgId = (Get-ItemProperty $hklmPath -ErrorAction SilentlyContinue).'(Default)'
        if ($defaultProgId) {
            $results += [PSCustomObject]@{
                ProgId    = $defaultProgId
                Extension = $Extension
                Source    = "HKLM Default"
            }
        }
    }

    return $results | Sort-Object ProgId -Unique
}

# ============================================================================
# DISM DEFAULT ASSOCIATIONS (Enterprise Deployment)
# ============================================================================

function Get-ApplicationNameForProgId {
    <#
    .SYNOPSIS
        Gets the display name for a ProgId
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ProgId
    )

    # Try HKCU first, then HKLM
    foreach ($hive in @("HKCU:\SOFTWARE\Classes", "HKLM:\SOFTWARE\Classes")) {
        $progIdPath = "$hive\$ProgId"
        if (Test-Path $progIdPath) {
            # Try FriendlyTypeName first
            $friendlyName = (Get-ItemProperty $progIdPath -Name "FriendlyTypeName" -ErrorAction SilentlyContinue).FriendlyTypeName
            if ($friendlyName -and $friendlyName -notlike "@*") {
                return $friendlyName
            }

            # Fall back to default value
            $defaultName = (Get-ItemProperty $progIdPath -ErrorAction SilentlyContinue).'(Default)'
            if ($defaultName) {
                return $defaultName
            }
        }
    }

    return $ProgId
}

function Export-DefaultAssociations {
    <#
    .SYNOPSIS
        Exports current file type and protocol associations to a DISM-compatible XML file

    .DESCRIPTION
        Creates an XML file that can be used with:
        - DISM /online /import-defaultappassociations:file.xml
        - GPO "Set a default associations configuration file"
        - Intune/MDM deployment

        This is the recommended way to deploy PDF/HTML/HTTP associations in enterprise
        environments, as it bypasses UCPD restrictions.

    .PARAMETER Path
        The output path for the XML file

    .PARAMETER Extensions
        Optional array of extensions to export (e.g., ".pdf", ".html")
        If not specified, exports all current user associations

    .PARAMETER Protocols
        Optional array of protocols to export (e.g., "http", "https")
        If not specified, exports all current user protocol associations

    .PARAMETER IncludeAll
        Include all file type and protocol associations

    .EXAMPLE
        Export-DefaultAssociations -Path "C:\Deploy\associations.xml"

    .EXAMPLE
        Export-DefaultAssociations -Path ".\defaults.xml" -Extensions ".pdf", ".html" -Protocols "http", "https"

    .EXAMPLE
        # Export from reference PC, then import on target:
        Export-DefaultAssociations -Path "\\server\share\defaults.xml" -IncludeAll
        # On target (as Admin): dism /online /import-defaultappassociations:\\server\share\defaults.xml
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,

        [Parameter()]
        [string[]]$Extensions,

        [Parameter()]
        [string[]]$Protocols,

        [Parameter()]
        [switch]$IncludeAll
    )

    $associations = @()

    # Get file type associations
    if ($IncludeAll -or $Extensions) {
        $allFta = Get-AllFTA

        if ($Extensions) {
            # Normalize extensions
            $normalizedExt = $Extensions | ForEach-Object {
                if (-not $_.StartsWith(".")) { ".$_" } else { $_ }
            }
            $allFta = $allFta | Where-Object { $_.Extension -in $normalizedExt }
        }

        foreach ($fta in $allFta) {
            $appName = Get-ApplicationNameForProgId -ProgId $fta.ProgId
            $associations += [PSCustomObject]@{
                Identifier      = $fta.Extension
                ProgId          = $fta.ProgId
                ApplicationName = $appName
            }
        }
    }

    # Get protocol associations
    if ($IncludeAll -or $Protocols) {
        $allPta = Get-AllPTA

        if ($Protocols) {
            $allPta = $allPta | Where-Object { $_.Protocol -in $Protocols }
        }

        foreach ($pta in $allPta) {
            $appName = Get-ApplicationNameForProgId -ProgId $pta.ProgId
            $associations += [PSCustomObject]@{
                Identifier      = $pta.Protocol
                ProgId          = $pta.ProgId
                ApplicationName = $appName
            }
        }
    }

    if ($associations.Count -eq 0) {
        Write-Warning "No associations found to export. Use -IncludeAll, -Extensions, or -Protocols parameter."
        return $null
    }

    # Build XML
    $xmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
"@

    foreach ($assoc in ($associations | Sort-Object Identifier)) {
        $xmlContent += "`n  <Association Identifier=`"$($assoc.Identifier)`" ProgId=`"$($assoc.ProgId)`" ApplicationName=`"$($assoc.ApplicationName)`" />"
    }

    $xmlContent += "`n</DefaultAssociations>"

    # Write file
    $xmlContent | Out-File -FilePath $Path -Encoding UTF8 -Force

    Write-Verbose "Exported $($associations.Count) associations to $Path"

    return [PSCustomObject]@{
        Path              = (Resolve-Path $Path).Path
        AssociationCount  = $associations.Count
        FileTypes         = ($associations | Where-Object { $_.Identifier.StartsWith(".") }).Count
        Protocols         = ($associations | Where-Object { -not $_.Identifier.StartsWith(".") }).Count
    }
}

function Import-DefaultAssociations {
    <#
    .SYNOPSIS
        Imports default associations from a DISM-compatible XML file (requires Admin)

    .DESCRIPTION
        Wrapper for: dism /online /import-defaultappassociations:file.xml

        This sets the DEFAULT associations for NEW users. Existing user profiles
        are not affected. For existing users, use Set-FTA/Set-PTA or GPO.

    .PARAMETER Path
        Path to the XML file created by Export-DefaultAssociations or DISM export

    .PARAMETER RemoveExisting
        Remove current default associations before importing

    .EXAMPLE
        Import-DefaultAssociations -Path "C:\Deploy\associations.xml"

    .NOTES
        Requires Administrator privileges
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path
    )

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "Administrator privileges required for Import-DefaultAssociations"
        return $false
    }

    if (-not (Test-Path $Path)) {
        Write-Error "File not found: $Path"
        return $false
    }

    $fullPath = (Resolve-Path $Path).Path

    if ($PSCmdlet.ShouldProcess($fullPath, "Import Default Associations via DISM")) {
        try {
            $result = & dism /online /import-defaultappassociations:"$fullPath" 2>&1

            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Successfully imported default associations"
                Write-Warning "Default associations imported. These apply to NEW user profiles only."
                return $true
            }
            else {
                Write-Error "DISM failed with exit code $LASTEXITCODE : $result"
                return $false
            }
        }
        catch {
            Write-Error "Failed to import associations: $_"
            return $false
        }
    }
}

function Remove-DefaultAssociations {
    <#
    .SYNOPSIS
        Removes the deployed default associations (requires Admin)

    .DESCRIPTION
        Wrapper for: dism /online /remove-defaultappassociations

        Removes previously deployed default associations. Windows defaults will be restored.

    .EXAMPLE
        Remove-DefaultAssociations

    .NOTES
        Requires Administrator privileges
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "Administrator privileges required for Remove-DefaultAssociations"
        return $false
    }

    if ($PSCmdlet.ShouldProcess("Default Associations", "Remove via DISM")) {
        try {
            $result = & dism /online /remove-defaultappassociations 2>&1

            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Successfully removed default associations"
                return $true
            }
            else {
                Write-Error "DISM failed with exit code $LASTEXITCODE : $result"
                return $false
            }
        }
        catch {
            Write-Error "Failed to remove associations: $_"
            return $false
        }
    }
}

# ============================================================================
# EXPORT MODULE MEMBERS
# ============================================================================

Export-ModuleMember -Function @(
    # File Type Associations
    'Get-FTA',
    'Set-FTA',
    'Remove-FTA',
    'Get-AllFTA',
    # Protocol Associations
    'Get-PTA',
    'Set-PTA',
    'Remove-PTA',
    'Get-AllPTA',
    # UCPD Management (Basic)
    'Test-UCPDEnabled',
    'Get-UCPDStatus',
    'Disable-UCPD',
    'Enable-UCPD',
    'Get-UCPDScheduledTask',
    'Disable-UCPDScheduledTask',
    'Enable-UCPDScheduledTask',
    # UCPD Management (Enterprise - with EDR check)
    'Get-EDRStatus',
    'Disable-UCPDSafely',
    'Enable-UCPDSafely',
    # DISM Default Associations (Enterprise)
    'Export-DefaultAssociations',
    'Import-DefaultAssociations',
    'Remove-DefaultAssociations',
    # Utility
    'Test-IsWindowsServer',
    'Open-DefaultAppsSettings',
    'Get-RegisteredApplications',
    'Find-ProgIdForExtension'
)

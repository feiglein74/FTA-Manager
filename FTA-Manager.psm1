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
    try {
        [Microsoft.Win32.Registry]::SetValue($regPathWin32, "Hash", $Hash)
        [Microsoft.Win32.Registry]::SetValue($regPathWin32, "ProgId", $ProgId)
    }
    catch {
        # Fallback to PowerShell method
        New-Item -Path $regPath -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "ProgId" -Value $ProgId -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "Hash" -Value $Hash -PropertyType String -Force | Out-Null
    }
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

    # Check for UCPD-protected extensions
    $protectedExtensions = @(".pdf")
    if ($Extension -in $protectedExtensions -and (Test-UCPDEnabled) -and -not $Force) {
        Write-Warning "Extension '$Extension' is protected by UCPD. Use Disable-UCPD (requires Admin + Reboot) or -Force to attempt anyway."
        return [PSCustomObject]@{
            Extension = $Extension
            ProgId    = $ProgId
            Success   = $false
            Error     = "UCPD protection active"
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
            Write-Error "Failed to set file type association: $_"
            return [PSCustomObject]@{
                Extension = $Extension
                ProgId    = $ProgId
                Success   = $false
                Error     = $_.Exception.Message
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

    # Check for UCPD-protected protocols
    $protectedProtocols = @("http", "https")
    if ($Protocol -in $protectedProtocols -and (Test-UCPDEnabled) -and -not $Force) {
        Write-Warning "Protocol '$Protocol' is protected by UCPD. Use Disable-UCPD (requires Admin + Reboot) or -Force to attempt anyway."
        return [PSCustomObject]@{
            Protocol = $Protocol
            ProgId   = $ProgId
            Success  = $false
            Error    = "UCPD protection active"
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
            Write-Error "Failed to set protocol association: $_"
            return [PSCustomObject]@{
                Protocol = $Protocol
                ProgId   = $ProgId
                Success  = $false
                Error    = $_.Exception.Message
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
    # UCPD Management
    'Test-UCPDEnabled',
    'Get-UCPDStatus',
    'Disable-UCPD',
    'Enable-UCPD',
    # Utility
    'Get-RegisteredApplications',
    'Find-ProgIdForExtension'
)

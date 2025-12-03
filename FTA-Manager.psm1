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
# LOCALIZATION
# ============================================================================

$script:Messages = @{
    'de' = @{
        UCPDExtensionWarning = @"
Die Extension '{0}' ist durch UCPD (User Choice Protection Driver) geschuetzt.

Loesungsmoeglichkeiten:
  1. 'Disable-UCPD' als Administrator ausfuehren, dann NEUSTART erforderlich
  2. -Force verwenden (schlaegt fehl, wenn UserChoice bereits existiert)
  3. SetFTA.exe verwenden: .\src\SetFTA\bin\Release\net472\SetFTA.exe set-fta <ProgId> {0}

Mehr Infos: Get-Help about_UCPD
"@
        UCPDProtocolWarning = @"
Das Protokoll '{0}' ist durch UCPD (User Choice Protection Driver) geschuetzt.

Loesungsmoeglichkeiten:
  1. 'Disable-UCPD' als Administrator ausfuehren, dann NEUSTART erforderlich
  2. -Force verwenden (schlaegt fehl, wenn UserChoice bereits existiert)
  3. SetFTA.exe verwenden: .\src\SetFTA\bin\Release\net472\SetFTA.exe set-pta <ProgId> {0}

Mehr Infos: Get-Help about_UCPD
"@
        UCPDProtectedError = "UCPD-Schutz aktiv"
        UCPDModifyError = "UserChoice kann nicht geaendert werden - Schluessel ist geschuetzt (UCPD aktiv). UCPD mit Disable-UCPD deaktivieren und neu starten."
        RegistryProtectedError = @"
UserChoice-Schluessel ist schreibgeschuetzt (Registry-ACL).

Loesungsmoeglichkeiten:
  1. SetFTA.exe verwenden: .\src\SetFTA\bin\Release\net472\SetFTA.exe
  2. Manuell in Windows-Einstellungen: Einstellungen > Apps > Standard-Apps
  3. ACL-Berechtigung auf dem Registry-Schluessel pruefen/aendern
"@
    }
    'en' = @{
        UCPDExtensionWarning = @"
Extension '{0}' is protected by UCPD (User Choice Protection Driver).

Options to resolve this:
  1. Run 'Disable-UCPD' as Administrator, then REBOOT the system
  2. Use -Force to attempt anyway (will fail if UserChoice already exists)
  3. Use SetFTA.exe: .\src\SetFTA\bin\Release\net472\SetFTA.exe set-fta <ProgId> {0}

For more info: Get-Help about_UCPD
"@
        UCPDProtocolWarning = @"
Protocol '{0}' is protected by UCPD (User Choice Protection Driver).

Options to resolve this:
  1. Run 'Disable-UCPD' as Administrator, then REBOOT the system
  2. Use -Force to attempt anyway (will fail if UserChoice already exists)
  3. Use SetFTA.exe: .\src\SetFTA\bin\Release\net472\SetFTA.exe set-pta <ProgId> {0}

For more info: Get-Help about_UCPD
"@
        UCPDProtectedError = "UCPD protection active"
        UCPDModifyError = "Cannot modify UserChoice - key is protected (UCPD active). Disable UCPD with Disable-UCPD and reboot."
        RegistryProtectedError = @"
UserChoice key is write-protected (Registry ACL).

Options to resolve this:
  1. Use SetFTA.exe: .\src\SetFTA\bin\Release\net472\SetFTA.exe
  2. Manually in Windows Settings: Settings > Apps > Default Apps
  3. Check/modify ACL permissions on the registry key
"@
    }
}

function Get-LocalizedMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MessageKey,

        [Parameter()]
        [string[]]$Arguments
    )

    # Check thread culture first (allows override), then fall back to system UI culture
    $lang = [System.Threading.Thread]::CurrentThread.CurrentUICulture.TwoLetterISOLanguageName
    if (-not $script:Messages.ContainsKey($lang)) {
        $lang = (Get-UICulture).TwoLetterISOLanguageName
    }
    if (-not $script:Messages.ContainsKey($lang)) {
        $lang = 'en'
    }

    $message = $script:Messages[$lang][$MessageKey]
    if ($Arguments) {
        $message = $message -f $Arguments
    }
    return $message
}

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

    # Ensure parent path exists
    $parentPath = Split-Path $regPath -Parent
    if (-not (Test-Path $parentPath)) {
        New-Item -Path $parentPath -Force -ErrorAction SilentlyContinue | Out-Null
    }

    # Remove existing UserChoice key using .NET Registry API (more reliable)
    $deleteError = $null
    if (Test-Path $regPath) {
        try {
            $keyName = Split-Path $regPath -Leaf
            $parentKey = Get-Item $parentPath
            $parentKey.DeleteSubKey($keyName)
        }
        catch {
            $deleteError = $_
            # Key exists but cannot be deleted - likely UCPD protection
            Write-Verbose "Could not delete existing UserChoice key: $($_.Exception.Message)"
        }
    }

    # Set the registry values
    $writeError = $null
    try {
        # Create key if it doesn't exist (or was successfully deleted)
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        }

        # Try to set values - this will work if key is new or we have write access
        [Microsoft.Win32.Registry]::SetValue($regPathWin32, "ProgId", $ProgId)
        [Microsoft.Win32.Registry]::SetValue($regPathWin32, "Hash", $Hash)
    }
    catch {
        # If delete failed and write failed, report appropriate error
        if ($deleteError) {
            if (Test-UCPDEnabled) {
                throw (Get-LocalizedMessage -MessageKey 'UCPDModifyError')
            } else {
                throw (Get-LocalizedMessage -MessageKey 'RegistryProtectedError')
            }
        }

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

    # Check for UCPD-protected extensions
    $protectedExtensions = @(".pdf", ".htm", ".html")
    if ($Extension -in $protectedExtensions -and (Test-UCPDEnabled) -and -not $Force) {
        Write-Warning (Get-LocalizedMessage -MessageKey 'UCPDExtensionWarning' -Arguments $Extension)
        return [PSCustomObject]@{
            Extension = $Extension
            ProgId    = $ProgId
            Success   = $false
            Error     = (Get-LocalizedMessage -MessageKey 'UCPDProtectedError')
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
        Write-Warning (Get-LocalizedMessage -MessageKey 'UCPDProtocolWarning' -Arguments $Protocol)
        return [PSCustomObject]@{
            Protocol = $Protocol
            ProgId   = $ProgId
            Success  = $false
            Error    = (Get-LocalizedMessage -MessageKey 'UCPDProtectedError')
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
# ENTERPRISE FUNCTIONS - Windows Server & UCPD Safe Management
# ============================================================================

function Test-IsWindowsServer {
    <#
    .SYNOPSIS
        Tests if the current system is Windows Server

    .DESCRIPTION
        Windows Server does not have UCPD (User Choice Protection Driver).
        This function helps determine if UCPD-related functions are relevant.

    .OUTPUTS
        [bool] True if Windows Server, False if Windows Client

    .EXAMPLE
        if (Test-IsWindowsServer) {
            Write-Host "Running on Windows Server - UCPD not present"
        }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        # ProductType: 1 = Workstation, 2 = Domain Controller, 3 = Server
        return ($os.ProductType -ne 1)
    }
    catch {
        Write-Warning "Could not determine OS type: $_"
        return $false
    }
}

function Get-UCPDScheduledTask {
    <#
    .SYNOPSIS
        Gets the status of the UCPD (User Choice Protection Driver) scheduled task

    .DESCRIPTION
        The UCPD scheduled task is responsible for re-enabling the UCPD driver after reboot.
        This function retrieves the task status and configuration.

    .OUTPUTS
        [PSCustomObject] Task information or $null if not found

    .EXAMPLE
        Get-UCPDScheduledTask
    #>
    [CmdletBinding()]
    param()

    $taskPath = "\Microsoft\Windows\Shell\"

    # UCPD is managed through multiple mechanisms, check the main ones
    $result = [PSCustomObject]@{
        TaskExists     = $false
        TaskEnabled    = $false
        TaskState      = "Unknown"
        DriverExists   = (Test-Path "$env:SystemRoot\System32\drivers\UCPD.sys")
        DriverEnabled  = (Test-UCPDEnabled)
        LastRunTime    = $null
        NextRunTime    = $null
    }

    try {
        # Check for UCPD-related scheduled tasks
        $tasks = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue |
                 Where-Object { $_.TaskName -like "*UCPD*" -or $_.TaskName -like "*UserChoice*" }

        if ($tasks) {
            $task = $tasks | Select-Object -First 1
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

            $result.TaskExists = $true
            $result.TaskEnabled = ($task.State -ne 'Disabled')
            $result.TaskState = $task.State.ToString()
            $result.LastRunTime = $taskInfo.LastRunTime
            $result.NextRunTime = $taskInfo.NextRunTime
        }
    }
    catch {
        Write-Verbose "Could not query scheduled tasks: $_"
    }

    return $result
}

function Disable-UCPDScheduledTask {
    <#
    .SYNOPSIS
        Disables UCPD-related scheduled tasks

    .DESCRIPTION
        Disables scheduled tasks that may re-enable UCPD protection.
        Requires Administrator privileges.

    .PARAMETER Force
        Skip confirmation prompts

    .EXAMPLE
        Disable-UCPDScheduledTask

    .NOTES
        Requires Administrator privileges
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [switch]$Force
    )

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "Administrator privileges required to disable UCPD scheduled tasks"
        return $false
    }

    if (Test-IsWindowsServer) {
        Write-Warning "Windows Server detected - UCPD is not present on Server editions"
        return $true
    }

    $taskPath = "\Microsoft\Windows\Shell\"

    try {
        $tasks = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue |
                 Where-Object { $_.TaskName -like "*UCPD*" -or $_.TaskName -like "*UserChoice*" }

        if (-not $tasks) {
            Write-Verbose "No UCPD-related scheduled tasks found"
            return $true
        }

        foreach ($task in $tasks) {
            if ($Force -or $PSCmdlet.ShouldProcess($task.TaskName, "Disable scheduled task")) {
                Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                Write-Verbose "Disabled task: $($task.TaskName)"
            }
        }

        return $true
    }
    catch {
        Write-Error "Failed to disable UCPD scheduled tasks: $_"
        return $false
    }
}

function Enable-UCPDScheduledTask {
    <#
    .SYNOPSIS
        Enables UCPD-related scheduled tasks

    .DESCRIPTION
        Re-enables scheduled tasks that manage UCPD protection.
        Requires Administrator privileges.

    .EXAMPLE
        Enable-UCPDScheduledTask

    .NOTES
        Requires Administrator privileges
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "Administrator privileges required to enable UCPD scheduled tasks"
        return $false
    }

    if (Test-IsWindowsServer) {
        Write-Warning "Windows Server detected - UCPD is not present on Server editions"
        return $true
    }

    $taskPath = "\Microsoft\Windows\Shell\"

    try {
        $tasks = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue |
                 Where-Object { $_.TaskName -like "*UCPD*" -or $_.TaskName -like "*UserChoice*" }

        if (-not $tasks) {
            Write-Verbose "No UCPD-related scheduled tasks found"
            return $true
        }

        foreach ($task in $tasks) {
            if ($PSCmdlet.ShouldProcess($task.TaskName, "Enable scheduled task")) {
                Enable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                Write-Verbose "Enabled task: $($task.TaskName)"
            }
        }

        return $true
    }
    catch {
        Write-Error "Failed to enable UCPD scheduled tasks: $_"
        return $false
    }
}

function Open-DefaultAppsSettings {
    <#
    .SYNOPSIS
        Opens the Windows Default Apps settings page

    .DESCRIPTION
        Opens the Windows Settings app to the Default Apps page where users can
        manually change file type and protocol associations.

        This is useful when UCPD blocks programmatic changes - the user can
        make the change manually through the Settings UI.

    .EXAMPLE
        Open-DefaultAppsSettings
        # Opens Settings > Apps > Default apps

    .EXAMPLE
        Open-DefaultAppsSettings -Extension ".pdf"
        # Opens Settings filtered to .pdf extension

    .NOTES
        Available on Windows 10 version 1703 and later
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Extension
    )

    try {
        if ($Extension) {
            # Open settings for specific extension
            $uri = "ms-settings:defaultapps?registeredAppMachine=$Extension"
        }
        else {
            # Open general default apps settings
            $uri = "ms-settings:defaultapps"
        }

        Start-Process $uri
        Write-Verbose "Opened Windows Settings: $uri"
        return $true
    }
    catch {
        Write-Error "Failed to open Default Apps settings: $_"
        return $false
    }
}

function Get-EDRStatus {
    <#
    .SYNOPSIS
        Detects installed EDR/XDR security solutions

    .DESCRIPTION
        Checks for common Enterprise Detection and Response (EDR) and
        Extended Detection and Response (XDR) solutions that may monitor
        or block registry modifications.

        This information is useful for enterprise deployments where
        security software may interfere with FTA changes.

    .OUTPUTS
        [PSCustomObject] with detected security solutions

    .EXAMPLE
        Get-EDRStatus
    #>
    [CmdletBinding()]
    param()

    $edrProducts = @(
        @{ Name = "CrowdStrike Falcon"; Service = "CSFalconService"; Process = "CSFalconService" }
        @{ Name = "Microsoft Defender for Endpoint"; Service = "Sense"; Process = "MsSense" }
        @{ Name = "Microsoft Defender Antivirus"; Service = "WinDefend"; Process = "MsMpEng" }
        @{ Name = "Carbon Black"; Service = "CbDefense"; Process = "RepMgr" }
        @{ Name = "SentinelOne"; Service = "SentinelAgent"; Process = "SentinelAgent" }
        @{ Name = "Symantec Endpoint Protection"; Service = "SepMasterService"; Process = "ccSvcHst" }
        @{ Name = "McAfee Endpoint Security"; Service = "mfefire"; Process = "mfefire" }
        @{ Name = "Trend Micro"; Service = "Ntrtscan"; Process = "Ntrtscan" }
        @{ Name = "Sophos"; Service = "Sophos Endpoint Defense Service"; Process = "SophosHealth" }
        @{ Name = "ESET"; Service = "ekrn"; Process = "ekrn" }
        @{ Name = "Kaspersky"; Service = "AVP"; Process = "avp" }
        @{ Name = "Bitdefender"; Service = "EPSecurityService"; Process = "bdservicehost" }
        @{ Name = "Palo Alto Cortex XDR"; Service = "CortexXDR"; Process = "CortexXDR" }
        @{ Name = "Cylance"; Service = "CylanceSvc"; Process = "CylanceSvc" }
    )

    $detected = @()

    foreach ($edr in $edrProducts) {
        $serviceExists = $false
        $serviceRunning = $false
        $processRunning = $false

        # Check service
        $service = Get-Service -Name $edr.Service -ErrorAction SilentlyContinue
        if ($service) {
            $serviceExists = $true
            $serviceRunning = ($service.Status -eq 'Running')
        }

        # Check process
        $process = Get-Process -Name $edr.Process -ErrorAction SilentlyContinue
        if ($process) {
            $processRunning = $true
        }

        if ($serviceExists -or $processRunning) {
            $detected += [PSCustomObject]@{
                Name           = $edr.Name
                ServiceExists  = $serviceExists
                ServiceRunning = $serviceRunning
                ProcessRunning = $processRunning
                Status         = if ($serviceRunning -or $processRunning) { "Active" } else { "Installed" }
            }
        }
    }

    return [PSCustomObject]@{
        EDRDetected    = ($detected.Count -gt 0)
        ProductCount   = $detected.Count
        Products       = $detected
        ScanTime       = Get-Date
    }
}

function Disable-UCPDSafely {
    <#
    .SYNOPSIS
        Safely disables UCPD with pre-flight checks and logging

    .DESCRIPTION
        Enterprise-safe function to disable UCPD with:
        - Windows Server detection (skips if Server)
        - EDR detection and warning
        - Logging support
        - Rollback information

    .PARAMETER Force
        Skip EDR warnings and proceed anyway

    .PARAMETER LogPath
        Path to write operation log

    .OUTPUTS
        [PSCustomObject] with operation result and details

    .EXAMPLE
        Disable-UCPDSafely -LogPath "C:\Logs\ucpd.log"

    .NOTES
        Requires Administrator privileges and system reboot to take effect
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [switch]$Force,

        [Parameter()]
        [string]$LogPath
    )

    $result = [PSCustomObject]@{
        Success         = $false
        Message         = ""
        IsWindowsServer = $false
        UCPDWasEnabled  = $false
        EDRDetected     = $false
        EDRProducts     = @()
        RebootRequired  = $false
        Timestamp       = Get-Date
    }

    # Helper function to write log
    function Write-Log {
        param([string]$Message)
        $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
        Write-Verbose $logEntry
        if ($LogPath) {
            Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
        }
    }

    Write-Log "Starting Disable-UCPDSafely operation"

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $result.Message = "Administrator privileges required"
        Write-Error $result.Message
        Write-Log "FAILED: $($result.Message)"
        return $result
    }

    # Check Windows Server
    $result.IsWindowsServer = Test-IsWindowsServer
    if ($result.IsWindowsServer) {
        $result.Success = $true
        $result.Message = "Windows Server detected - UCPD not present, no action needed"
        Write-Log $result.Message
        return $result
    }

    # Check current UCPD status
    $result.UCPDWasEnabled = Test-UCPDEnabled
    if (-not $result.UCPDWasEnabled) {
        $result.Success = $true
        $result.Message = "UCPD is already disabled"
        Write-Log $result.Message
        return $result
    }

    # Check EDR
    $edrStatus = Get-EDRStatus
    $result.EDRDetected = $edrStatus.EDRDetected
    $result.EDRProducts = $edrStatus.Products | ForEach-Object { $_.Name }

    if ($result.EDRDetected -and -not $Force) {
        $edrNames = ($result.EDRProducts -join ", ")
        $result.Message = "EDR solution(s) detected: $edrNames. Use -Force to proceed anyway."
        Write-Warning $result.Message
        Write-Log "WARNING: $($result.Message)"
        return $result
    }

    # Perform the disable operation
    if ($PSCmdlet.ShouldProcess("UCPD Driver", "Disable")) {
        Write-Log "Disabling UCPD driver..."

        $disableResult = Disable-UCPD -Force:$Force
        if ($disableResult) {
            $result.Success = $true
            $result.RebootRequired = $true
            $result.Message = "UCPD disabled successfully. Reboot required for changes to take effect."
            Write-Log "SUCCESS: $($result.Message)"
        }
        else {
            $result.Message = "Failed to disable UCPD driver"
            Write-Log "FAILED: $($result.Message)"
        }
    }

    return $result
}

function Enable-UCPDSafely {
    <#
    .SYNOPSIS
        Safely enables UCPD with logging support

    .DESCRIPTION
        Enterprise-safe function to re-enable UCPD with:
        - Windows Server detection (skips if Server)
        - Logging support
        - Status verification

    .PARAMETER LogPath
        Path to write operation log

    .OUTPUTS
        [PSCustomObject] with operation result and details

    .EXAMPLE
        Enable-UCPDSafely -LogPath "C:\Logs\ucpd.log"

    .NOTES
        Requires Administrator privileges and system reboot to take effect
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$LogPath
    )

    $result = [PSCustomObject]@{
        Success         = $false
        Message         = ""
        IsWindowsServer = $false
        UCPDWasEnabled  = $false
        RebootRequired  = $false
        Timestamp       = Get-Date
    }

    # Helper function to write log
    function Write-Log {
        param([string]$Message)
        $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
        Write-Verbose $logEntry
        if ($LogPath) {
            Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
        }
    }

    Write-Log "Starting Enable-UCPDSafely operation"

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $result.Message = "Administrator privileges required"
        Write-Error $result.Message
        Write-Log "FAILED: $($result.Message)"
        return $result
    }

    # Check Windows Server
    $result.IsWindowsServer = Test-IsWindowsServer
    if ($result.IsWindowsServer) {
        $result.Success = $true
        $result.Message = "Windows Server detected - UCPD not present, no action needed"
        Write-Log $result.Message
        return $result
    }

    # Check current UCPD status
    $result.UCPDWasEnabled = Test-UCPDEnabled
    if ($result.UCPDWasEnabled) {
        $result.Success = $true
        $result.Message = "UCPD is already enabled"
        Write-Log $result.Message
        return $result
    }

    # Perform the enable operation
    if ($PSCmdlet.ShouldProcess("UCPD Driver", "Enable")) {
        Write-Log "Enabling UCPD driver..."

        $enableResult = Enable-UCPD
        if ($enableResult) {
            $result.Success = $true
            $result.RebootRequired = $true
            $result.Message = "UCPD enabled successfully. Reboot required for changes to take effect."
            Write-Log "SUCCESS: $($result.Message)"
        }
        else {
            $result.Message = "Failed to enable UCPD driver"
            Write-Log "FAILED: $($result.Message)"
        }
    }

    return $result
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
    # UCPD Scheduled Task Management
    'Get-UCPDScheduledTask',
    'Disable-UCPDScheduledTask',
    'Enable-UCPDScheduledTask',
    # Enterprise UCPD Safe Management
    'Disable-UCPDSafely',
    'Enable-UCPDSafely',
    # DISM Default Associations (Enterprise)
    'Export-DefaultAssociations',
    'Import-DefaultAssociations',
    'Remove-DefaultAssociations',
    # Utility & Detection
    'Get-RegisteredApplications',
    'Find-ProgIdForExtension',
    'Test-IsWindowsServer',
    'Open-DefaultAppsSettings',
    'Get-EDRStatus'
)

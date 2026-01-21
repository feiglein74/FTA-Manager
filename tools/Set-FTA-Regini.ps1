<#
.SYNOPSIS
    Setzt File Type Association mit regini.exe (PDFXChange-Methode)

.DESCRIPTION
    Umgeht UCPD und DENY-ACL durch Verwendung von regini.exe:
    1. Loescht den UserChoice Key mit [DELETE]
    2. Erstellt neuen Key mit ProgId und Hash

.PARAMETER Extension
    Die Dateiendung (z.B. ".pdf")

.PARAMETER ProgId
    Die ProgId des Programms (z.B. "PDFXEdit.PDF")

.EXAMPLE
    .\Set-FTA-Regini.ps1 -Extension ".pdf" -ProgId "PDFXEdit.PDF"

.NOTES
    Basiert auf Reverse-Engineering von PDF-XChange Editor
    Erfordert Administrator-Rechte
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Extension,

    [Parameter(Mandatory)]
    [string]$ProgId,

    [switch]$WhatIf
)

#region Hash-Funktionen (aus FTA-Manager)

function Get-Hash {
    param([string]$BaseInfo)

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

function Get-UserChoiceHash {
    param(
        [string]$Extension,
        [string]$UserSid,
        [string]$ProgId,
        [string]$Timestamp
    )

    $userExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
    $baseInfo = "$Extension$UserSid$ProgId$Timestamp$userExperience".ToLower()

    return Get-Hash -BaseInfo $baseInfo
}

function Get-HexDateTime {
    # Timestamp im Windows FileTime Format (gerundet auf Minute)
    $now = [DateTime]::Now
    $minuteRounded = New-Object DateTime($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
    $fileTime = $minuteRounded.ToFileTime()
    return $fileTime.ToString("X16")
}

#endregion

#region Hauptlogik

Write-Host "=== Set-FTA-Regini ===" -ForegroundColor Yellow
Write-Host "Extension: $Extension" -ForegroundColor Cyan
Write-Host "ProgId:    $ProgId" -ForegroundColor Cyan
Write-Host ""

# Admin-Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "FEHLER: Administrator-Rechte erforderlich!" -ForegroundColor Red
    exit 1
}

# SID holen
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Write-Host "User SID:  $userSid" -ForegroundColor Gray

# Timestamp berechnen
$timestamp = Get-HexDateTime
Write-Host "Timestamp: $timestamp" -ForegroundColor Gray

# Hash berechnen
$hash = Get-UserChoiceHash -Extension $Extension -UserSid $userSid -ProgId $ProgId -Timestamp $timestamp
Write-Host "Hash:      $hash" -ForegroundColor Gray
Write-Host ""

# Registry-Pfad
$regPath = "\Registry\User\$userSid\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"

# Temp-Ordner fuer .ini Dateien
$tempFolder = Join-Path $env:TEMP ([Guid]::NewGuid().ToString("B").ToUpper())
New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

# DELETE .ini erstellen
$deleteIni = Join-Path $tempFolder "delete.ini"
$deleteContent = "$regPath [DELETE]`r`n"
[System.IO.File]::WriteAllText($deleteIni, $deleteContent, [System.Text.Encoding]::ASCII)

Write-Host "[1] DELETE .ini erstellt:" -ForegroundColor Cyan
Write-Host "    $deleteIni" -ForegroundColor Gray

# SET .ini erstellen
$setIni = Join-Path $tempFolder "set.ini"
$setContent = @"
$regPath
ProgId="$ProgId"
Hash="$hash"
0
"@
[System.IO.File]::WriteAllText($setIni, $setContent, [System.Text.Encoding]::ASCII)

Write-Host "[2] SET .ini erstellt:" -ForegroundColor Cyan
Write-Host "    $setIni" -ForegroundColor Gray

if ($WhatIf) {
    Write-Host ""
    Write-Host "[WhatIf] Wuerde ausfuehren:" -ForegroundColor Magenta
    Write-Host "    regini.exe `"$deleteIni`"" -ForegroundColor White
    Write-Host "    regini.exe `"$setIni`"" -ForegroundColor White
    Write-Host ""
    Write-Host "DELETE .ini Inhalt:" -ForegroundColor Yellow
    Get-Content $deleteIni
    Write-Host ""
    Write-Host "SET .ini Inhalt:" -ForegroundColor Yellow
    Get-Content $setIni

    # Aufraeumen
    Remove-Item $tempFolder -Recurse -Force
    exit 0
}

# regini.exe ausfuehren - DELETE
Write-Host ""
Write-Host "[3] Fuehre regini.exe aus (DELETE)..." -ForegroundColor Cyan
$result = & regini.exe $deleteIni 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "    WARNUNG: regini.exe DELETE exitcode $LASTEXITCODE" -ForegroundColor Yellow
    Write-Host "    $result" -ForegroundColor Gray
} else {
    Write-Host "    OK - Key geloescht" -ForegroundColor Green
}

# Kurze Pause
Start-Sleep -Milliseconds 100

# regini.exe ausfuehren - SET
Write-Host "[4] Fuehre regini.exe aus (SET)..." -ForegroundColor Cyan
$result = & regini.exe $setIni 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "    FEHLER: regini.exe SET exitcode $LASTEXITCODE" -ForegroundColor Red
    Write-Host "    $result" -ForegroundColor Gray
} else {
    Write-Host "    OK - Werte geschrieben" -ForegroundColor Green
}

# Aufraeumen
Remove-Item $tempFolder -Recurse -Force

# Verifizieren
Write-Host ""
Write-Host "[5] Verifiziere..." -ForegroundColor Cyan
$hkcuPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
if (Test-Path $hkcuPath) {
    $currentProgId = (Get-ItemProperty -Path $hkcuPath -ErrorAction SilentlyContinue).ProgId
    $currentHash = (Get-ItemProperty -Path $hkcuPath -ErrorAction SilentlyContinue).Hash

    if ($currentProgId -eq $ProgId) {
        Write-Host "    ERFOLG!" -ForegroundColor Green
        Write-Host "    ProgId: $currentProgId" -ForegroundColor Gray
        Write-Host "    Hash:   $currentHash" -ForegroundColor Gray
    } else {
        Write-Host "    WARNUNG: ProgId stimmt nicht ueberein" -ForegroundColor Yellow
        Write-Host "    Erwartet: $ProgId" -ForegroundColor Gray
        Write-Host "    Aktuell:  $currentProgId" -ForegroundColor Gray
    }
} else {
    Write-Host "    FEHLER: UserChoice Key existiert nicht" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== FERTIG ===" -ForegroundColor Yellow

#endregion

# DENY-ACL Entfernung - VORSICHTIG!
# Fuehre dieses Script als Administrator aus

param(
    [switch]$WhatIf,  # Nur anzeigen, nicht aendern
    [switch]$Force    # Ohne Bestaetigung ausfuehren
)

$keyPath = 'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice'
$fullPath = "HKCU:\$keyPath"

Write-Host "============================================" -ForegroundColor Yellow
Write-Host " DENY-ACL Entfernung fuer UserChoice" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

# Schritt 1: Aktuelle ACL anzeigen
Write-Host "[1] Aktuelle ACL lesen..." -ForegroundColor Cyan
try {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        $keyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
        [System.Security.AccessControl.RegistryRights]::ReadPermissions
    )

    if (-not $key) {
        Write-Host "FEHLER: Key konnte nicht geoeffnet werden!" -ForegroundColor Red
        exit 1
    }

    $acl = $key.GetAccessControl()
    Write-Host "    OK - ACL gelesen" -ForegroundColor Green
}
catch {
    Write-Host "FEHLER beim Oeffnen: $_" -ForegroundColor Red
    exit 1
}

# Schritt 2: DENY-Regeln finden
Write-Host ""
Write-Host "[2] DENY-Regeln suchen..." -ForegroundColor Cyan
$denyRules = $acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' }

if (-not $denyRules) {
    Write-Host "    Keine DENY-Regeln gefunden!" -ForegroundColor Yellow
    $key.Close()
    exit 0
}

Write-Host "    Gefundene DENY-Regeln:" -ForegroundColor Yellow
foreach ($rule in $denyRules) {
    Write-Host "    - $($rule.IdentityReference): $($rule.RegistryRights)" -ForegroundColor Red
}

# Schritt 3: WhatIf - nur anzeigen
if ($WhatIf) {
    Write-Host ""
    Write-Host "[WhatIf] Wuerde diese DENY-Regeln entfernen. Keine Aenderung vorgenommen." -ForegroundColor Magenta
    $key.Close()
    exit 0
}

# Schritt 4: Bestaetigung
if (-not $Force) {
    Write-Host ""
    Write-Host "WARNUNG: Dies wird die DENY-Regeln entfernen!" -ForegroundColor Red
    Write-Host "Backup vorhanden? C:\temp\backup-pdf-userchoice.reg" -ForegroundColor Yellow
    $confirm = Read-Host "Fortfahren? (j/n)"
    if ($confirm -ne 'j') {
        Write-Host "Abgebrochen." -ForegroundColor Yellow
        $key.Close()
        exit 0
    }
}

# Schritt 5: DENY-Regeln entfernen
Write-Host ""
Write-Host "[3] DENY-Regeln entfernen..." -ForegroundColor Cyan
$removed = 0
foreach ($rule in $denyRules) {
    try {
        $result = $acl.RemoveAccessRule($rule)
        if ($result) {
            Write-Host "    Entfernt: $($rule.IdentityReference)" -ForegroundColor Green
            $removed++
        } else {
            Write-Host "    Konnte nicht entfernen: $($rule.IdentityReference)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "    FEHLER bei $($rule.IdentityReference): $_" -ForegroundColor Red
    }
}

if ($removed -eq 0) {
    Write-Host "    Keine Regeln entfernt - breche ab" -ForegroundColor Yellow
    $key.Close()
    exit 1
}

# Schritt 6: ACL zurueckschreiben
Write-Host ""
Write-Host "[4] Neue ACL schreiben..." -ForegroundColor Cyan
try {
    $key.SetAccessControl($acl)
    Write-Host "    OK - ACL geschrieben!" -ForegroundColor Green
}
catch {
    Write-Host "    FEHLER beim Schreiben: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "!!! ACL KONNTE NICHT GESCHRIEBEN WERDEN !!!" -ForegroundColor Red
    Write-Host "Der Key sollte noch im alten Zustand sein." -ForegroundColor Yellow
    $key.Close()
    exit 1
}

$key.Close()

# Schritt 7: Verifizierung
Write-Host ""
Write-Host "[5] Verifizierung..." -ForegroundColor Cyan
Start-Sleep -Milliseconds 500

# Kann ich noch lesen?
try {
    $testKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($keyPath)
    if ($testKey) {
        $progId = $testKey.GetValue("ProgId")
        Write-Host "    Lesen OK - ProgId: $progId" -ForegroundColor Green
        $testKey.Close()
    } else {
        Write-Host "    WARNUNG: Key konnte nicht geoeffnet werden!" -ForegroundColor Red
    }
}
catch {
    Write-Host "    FEHLER beim Verifizieren: $_" -ForegroundColor Red
}

# Pruefe ob DENY-Regeln weg sind
try {
    $key2 = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        $keyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
        [System.Security.AccessControl.RegistryRights]::ReadPermissions
    )
    $acl2 = $key2.GetAccessControl()
    $denyRules2 = $acl2.Access | Where-Object { $_.AccessControlType -eq 'Deny' }

    if ($denyRules2) {
        Write-Host "    WARNUNG: Es gibt noch DENY-Regeln!" -ForegroundColor Red
        foreach ($r in $denyRules2) {
            Write-Host "    - $($r.IdentityReference)" -ForegroundColor Red
        }
    } else {
        Write-Host "    Keine DENY-Regeln mehr vorhanden!" -ForegroundColor Green
    }
    $key2.Close()
}
catch {
    Write-Host "    Konnte ACL nicht pruefen: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Yellow
Write-Host " FERTIG" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Falls etwas schief geht:" -ForegroundColor Yellow
Write-Host "  reg import C:\temp\backup-pdf-userchoice.reg" -ForegroundColor White

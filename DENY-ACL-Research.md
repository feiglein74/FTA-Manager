# DENY-ACL Forschung - UserChoice Registry Key

## Status: DURCHBRUCH ERZIELT!

**Ziel**: DENY-ACL auf UserChoice-Schlüssel entfernen, um Schreibzugriff zu ermöglichen.

**UPDATE 2026-01-21**: PDFXChange-Methode entdeckt - funktioniert auch bei aktivem UCPD!

---

## Das Problem

Windows setzt auf bestimmte UserChoice-Schlüssel (z.B. `.pdf`, `.htm`, `http`, `https`) eine DENY-ACL, die Schreibzugriff verhindert. Diese DENY-Regel blockiert Änderungen selbst wenn:
- UCPD deaktiviert ist
- Der Benutzer Administrator ist
- Man als SYSTEM ausführt

**Betroffene Registry-Pfade:**
```
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm\UserChoice
HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice
HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice
```

---

## Fehlgeschlagene Versuche

### Versuch 1: PowerShell Get-Acl / Set-Acl

**Ansatz**: DENY-Regeln mit PowerShell-Cmdlets entfernen.

```powershell
$acl = Get-Acl -Path $regPath
$denyRules = $acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' }
foreach ($rule in $denyRules) {
    $acl.RemoveAccessRule($rule)
}
Set-Acl -Path $regPath -AclObject $acl
```

**Ergebnis**: Fehlgeschlagen - `Set-Acl` wird blockiert (vermutlich durch UCPD oder die DENY-ACL selbst).

---

### Versuch 2: Scheduled Task als SYSTEM

**Ansatz**: Task als SYSTEM ausführen, um höhere Rechte zu haben.

```powershell
$action = New-ScheduledTaskAction -Execute "reg.exe" -Argument 'delete "HKCU\..." /f'
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "FixUserChoice" -Action $action -Principal $principal -Force
Start-ScheduledTask -TaskName "FixUserChoice"
```

**Ergebnis**: Fehlgeschlagen - SYSTEM kann den Key auch nicht löschen.

---

### Versuch 3: regini.exe mit ACL-Code [17]

**Ansatz**: Mit regini.exe die ACL überschreiben.

**Datei `test.ini`:**
```ini
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice [17]
```

**Ausführung:**
```cmd
regini.exe test.ini
```

**Ergebnis**: KATASTROPHE!

#### Was passiert ist:
- Der Code `[17]` bedeutet "SYSTEM Full Control" - und **NUR** das
- regini.exe **ersetzt** die gesamte ACL (fügt nicht hinzu!)
- Nach der Ausführung:
  - Aktueller Benutzer: KEIN Zugriff
  - Administrators: KEIN Zugriff
  - SYSTEM: Full Control (aber nützt nichts)

#### Symptome nach dem Fehler:
- Icons von Programmen flackerten im 2-Sekunden-Takt
- Windows versuchte ständig, den UserChoice zu reparieren
- Kein Zugriff mehr möglich - weder als User noch als Admin
- Selbst ein zweiter Admin-Benutzer konnte nicht helfen
- Deaktivieren von UCPD half nicht
- **Einzige Lösung: Profil komplett zurücksetzen**

#### Warum das passiert ist:
1. regini.exe ersetzt die ACL **komplett** statt sie zu modifizieren
2. Der UserChoice-Hash wurde ungültig (Windows validiert den)
3. Windows Explorer läuft als User (ohne Zugriff) und versuchte den Key zu lesen
4. Endlosschleife: Windows erkennt Problem → versucht zu reparieren → kein Zugriff → erkennt Problem...

---

## regini.exe ACL-Codes (Referenz)

| Code | Bedeutung |
|------|-----------|
| 1 | Administrators Full Control |
| 2 | Administrators Read |
| 3 | Administrators Read/Write |
| 4 | Administrators Read/Write/Delete |
| 5 | Creator Full Control |
| 6 | Creator Read/Write |
| 7 | World (Everyone) Full Control |
| 8 | World Read |
| 9 | World Read/Write |
| 17 | SYSTEM Full Control |
| 18 | SYSTEM Read/Write |
| 19 | SYSTEM Read |

**WICHTIG**: Codes werden kombiniert, z.B. `[1 7 17]` = Admin + World + System Full Control

**ABER**: regini.exe kann keine DENY-Regeln gezielt entfernen - es ersetzt immer die komplette ACL!

---

## Vorsichtsmaßnahmen für weitere Versuche

### VOR jedem Versuch:

1. **Backup des Registry-Zweigs erstellen:**
   ```cmd
   reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf" C:\temp\backup-pdf-before.reg
   ```

2. **ACL dokumentieren:**
   ```powershell
   # check-acl.ps1 ausführen und Output speichern
   .\check-acl.ps1 | Out-File C:\temp\acl-before.txt
   ```

3. **Systemwiederherstellungspunkt erstellen:**
   ```powershell
   Checkpoint-Computer -Description "Vor DENY-ACL Test" -RestorePointType MODIFY_SETTINGS
   ```

4. **Test-Extension verwenden:**
   - Nicht mit `.pdf` oder `.htm` testen!
   - Eigene Test-Extension registrieren (z.B. `.testfta`)
   - Oder eine unwichtige Extension verwenden

### WÄHREND des Versuchs:

5. **Timeouts einbauen:**
   - Wenn nach 10 Sekunden keine Änderung sichtbar → abbrechen
   - Nicht mehrfach hintereinander versuchen

6. **Monitoring:**
   ```powershell
   # In separatem Fenster laufen lassen
   while ($true) {
       $exists = Test-Path "HKCU:\...\UserChoice"
       $time = Get-Date -Format "HH:mm:ss"
       Write-Host "$time - UserChoice exists: $exists"
       Start-Sleep -Seconds 2
   }
   ```

### NACH dem Versuch:

7. **Sofort prüfen ob Zugriff noch möglich:**
   ```powershell
   Get-ItemProperty "HKCU:\...\UserChoice" -ErrorAction SilentlyContinue
   ```

8. **Bei Problemen sofort Backup wiederherstellen:**
   ```cmd
   reg import C:\temp\backup-pdf-before.reg
   ```

---

## DURCHBRUCH: PDFXChange-Methode (2026-01-21)

### Entdeckung

Durch Procmon-Analyse wurde entdeckt, wie **PDF-XChange Editor** die UserChoice-Zuordnung erfolgreich ändert - **auch bei aktivem UCPD**!

### Wie es funktioniert

PDFXChange nutzt `regini.exe` als Helfer-Tool in einem **zweistufigen Prozess**:

#### Schritt 1: Key löschen (regini.exe PID 20620)
```
08:18:44,1397771  regini.exe  RegDeleteKey  .pdf\UserChoice  SUCCESS
```

#### Schritt 2: Neuen Key erstellen (PDFXEdit.exe)
```
08:18:44,1463787  PDFXEdit.exe  RegCreateKey  .pdf\UserChoice  REG_CREATED_NEW_KEY
```

#### Schritt 3: Werte schreiben (regini.exe PID 12460)
```
08:18:44,2386978  regini.exe  RegSetValue  ProgId = "PDFXEdit.PDF"
08:18:44,2404794  regini.exe  RegSetValue  Hash = "h7GW3/yQOm8="
```

### Die fileassoc.ini Dateien

PDFXChange erstellt temporäre .ini Dateien für regini.exe:

**DELETE-Datei (147 Bytes)** - löscht den Key:
```ini
\Registry\User\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice [DELETE]
```

**SET-Datei (182 Bytes)** - schreibt die Werte:
```ini
\Registry\User\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice
ProgId="<PROGID>"
Hash="<HASH>"
0
```

**Wichtig:** Die `[DELETE]` Syntax ist undokumentiert! Die `0` am Ende ist ein Terminator.

### Warum regini.exe funktioniert

1. **regini.exe ist ein Windows-Systemtool** - wird nicht von UCPD blockiert
2. **Läuft als erhöhter Admin-Prozess** - umgeht die DENY-ACL
3. **Löscht den Key komplett** statt ihn zu modifizieren - umgeht SetValue-Blockade
4. **Neuer Key hat keine DENY-ACL** - kann direkt beschrieben werden

### Kritische Erkenntnis

Der Trick ist **NICHT** die ACL zu ändern, sondern:
1. Den gesamten Key **löschen** (mit regini.exe als Admin)
2. Einen **neuen Key erstellen** (hat keine DENY-ACL)
3. Die Werte **schreiben** (mit regini.exe)

Windows setzt die DENY-ACL erst später wieder - genug Zeit für den Schreibvorgang!

### Procmon-Beweise

Siehe Log-Dateien im `tools/` Ordner:
- `Logfile-pdfxchange-als-default-pdf.CSV` - Hauptlog
- `Logfile-pdfxchange-als-default-pdf-regini.CSV` - regini.exe Details
- `Logfile-pdfxchange-als-default-pdf-fileassoc.CSV` - fileassoc.ini Zugriffe

---

## Noch zu untersuchende Ansätze

### Ansatz A: SetSecurityInfo Win32 API
- Kann gezielt einzelne ACEs entfernen (nicht die ganze ACL ersetzen)
- Benötigt P/Invoke in PowerShell oder C#
- Unklar ob UCPD das auch blockiert

### Ansatz B: Token-Manipulation
- SeTakeOwnershipPrivilege aktivieren
- SeRestorePrivilege aktivieren
- Als Owner übernehmen, dann ACL ändern

### Ansatz C: SubInACL.exe (Microsoft Tool)
- Altes Microsoft-Tool für Registry-ACLs
- Kann möglicherweise gezielter arbeiten als regini.exe
- Download: Microsoft Website (veraltet, aber funktioniert)

### Ansatz D: Registry Hive offline bearbeiten
- Benutzer abmelden
- NTUSER.DAT als anderer Admin laden
- ACL offline ändern
- Hive wieder entladen

### Ansatz E: Kernel-Mode Lösung
- Eigener Treiber der UCPD umgeht
- Extrem komplex und riskant
- Wahrscheinlich nicht praktikabel

---

## Testumgebung einrichten

Bevor weitere Versuche unternommen werden, sollte eine sichere Testumgebung existieren:

1. **VM mit Windows 10/11** (Snapshot vor jedem Test!)
2. **Oder**: Separates lokales Benutzerprofil zum "Wegwerfen"
3. **Oder**: Test mit unwichtiger Dateiendung

---

## Aktueller Stand

- [ ] Sichere Testumgebung einrichten
- [ ] SetSecurityInfo API recherchieren
- [ ] SubInACL.exe testen
- [ ] Offline-Hive-Bearbeitung testen

---

## Referenzen

- [regini.exe Dokumentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regini)
- [Registry Key Security](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)
- [SetSecurityInfo Function](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)

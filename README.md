# FTA-Manager

PowerShell-Modul zur Verwaltung von Windows File Type Associations (FTA) und Protocol Associations (PTA).

## Übersicht

FTA-Manager ermöglicht das programmatische Setzen von Dateityp- und Protokoll-Zuordnungen unter Windows 10/11, indem es den korrekten UserChoice-Hash berechnet, den Windows seit Windows 8 zur Validierung benötigt.

### NEU: UCPD-Bypass mit regini.exe (Januar 2026)

**Durchbruch!** Wir haben eine Methode entdeckt, die auch UCPD-geschützte Extensions (`.pdf`, `.htm`, `http`, `https`) ändern kann - durch Reverse-Engineering von PDF-XChange Editor:

```powershell
# Als Administrator ausführen:
.\tools\Set-FTA-Regini.ps1 -Extension ".pdf" -ProgId "ChromePDF"
.\tools\Set-FTA-Regini.ps1 -Extension ".htm" -ProgId "ChromeHTML"
```

**Warum funktioniert das?**
- Nutzt `regini.exe` (Windows-Systemtool) mit undokumentierter `[DELETE]` Syntax
- Löscht den UserChoice-Key komplett → erstellt neuen → schreibt Werte
- regini.exe wird nicht von UCPD blockiert (ist ein vertrauenswürdiges Systemtool)
- Überlebt Neustarts! ✅

Siehe [UCPD-Bypass mit regini.exe](#ucpd-bypass-mit-reginiexe-der-durchbruch) für Details.

## Installation

```powershell
# Modul importieren
Import-Module .\FTA-Manager.psd1
```

## Schnellstart: Logon-Script

Das Modul wurde für den Einsatz in Logon-Scripts entwickelt. Hier die gängigsten Anwendungsfälle:

**Einfacher Oneliner (Netzwerkpfad):**
```powershell
Import-Module "\\server\share\FTA-Manager\FTA-Manager.psd1"; Set-FTA "MSEdgePDF" ".pdf"; Set-FTA "ChromeHTML" ".html"
```

**Mehrere Zuordnungen per Hashtable:**
```powershell
Import-Module "\\server\share\FTA-Manager\FTA-Manager.psd1"; @{".pdf"="MSEdgePDF";".html"="ChromeHTML";".txt"="Applications\notepad.exe"}.GetEnumerator() | ForEach-Object { Set-FTA $_.Value $_.Key }
```

**Als GPO/Logon-Script (CMD-Aufruf):**
```cmd
powershell.exe -ExecutionPolicy Bypass -Command "Import-Module '\\server\share\FTA-Manager\FTA-Manager.psd1'; Set-FTA 'MSEdgePDF' '.pdf'"
```

**Typisches Firmen-Logon-Script:**
```powershell
# Logon.ps1
Import-Module "\\fileserver\scripts$\FTA-Manager\FTA-Manager.psd1"
Set-FTA "MSEdgePDF" ".pdf"           # PDF mit Edge
Set-FTA "ChromeHTML" ".html"         # HTML mit Chrome
Set-PTA "ChromeHTML" "http"          # HTTP mit Chrome
Set-PTA "ChromeHTML" "https"         # HTTPS mit Chrome
```

> **Hinweis:** Bei UCPD-geschützten Extensions (`.pdf`, `http`, `https`) auf Windows 10/11 Client wird die Änderung vom Kernel blockiert. Siehe [UCPD-Problematik](#ucpd-problematik) für Lösungen.

## Funktionen

### File Type Associations (FTA)

| Funktion | Beschreibung |
|----------|--------------|
| `Get-FTA` | Aktuelle Dateityp-Zuordnung abrufen |
| `Set-FTA` | Dateityp-Zuordnung setzen |
| `Remove-FTA` | Dateityp-Zuordnung entfernen |
| `Get-AllFTA` | Alle Dateityp-Zuordnungen auflisten |

### Protocol Associations (PTA)

| Funktion | Beschreibung |
|----------|--------------|
| `Get-PTA` | Aktuelle Protokoll-Zuordnung abrufen |
| `Set-PTA` | Protokoll-Zuordnung setzen |
| `Remove-PTA` | Protokoll-Zuordnung entfernen |
| `Get-AllPTA` | Alle Protokoll-Zuordnungen auflisten |

### UCPD-Verwaltung (Basic)

| Funktion | Beschreibung |
|----------|--------------|
| `Test-UCPDEnabled` | Prüft, ob UCPD aktiv ist |
| `Get-UCPDStatus` | Detaillierter UCPD-Status |
| `Disable-UCPD` | UCPD deaktivieren (Admin + Reboot erforderlich) |
| `Enable-UCPD` | UCPD aktivieren (Admin + Reboot erforderlich) |
| `Get-UCPDScheduledTask` | Status des UCPD velocity Tasks |
| `Disable-UCPDScheduledTask` | Verhindert UCPD Re-Aktivierung |
| `Enable-UCPDScheduledTask` | Erlaubt UCPD Re-Aktivierung |

### UCPD-Verwaltung (Enterprise mit EDR)

| Funktion | Beschreibung |
|----------|--------------|
| `Get-EDRStatus` | Erkennt installierte EDR/XDR-Lösungen |
| `Disable-UCPDSafely` | UCPD deaktivieren mit EDR-Check und Audit-Logging |
| `Enable-UCPDSafely` | UCPD reaktivieren mit Logging |

### Enterprise-Deployment (DISM)

| Funktion | Beschreibung |
|----------|--------------|
| `Export-DefaultAssociations` | Exportiert FTA/PTA als DISM-kompatible XML |
| `Import-DefaultAssociations` | Importiert XML via DISM (Admin erforderlich) |
| `Remove-DefaultAssociations` | Entfernt deployed Defaults (Admin erforderlich) |

### Hilfsfunktionen

| Funktion | Beschreibung |
|----------|--------------|
| `Test-IsWindowsServer` | Prüft ob Windows Server (kein UCPD) |
| `Open-DefaultAppsSettings` | Öffnet Windows-Einstellungen für manuelle Änderung |
| `Find-ProgIdForExtension` | Verfügbare ProgIds für eine Extension finden |
| `Get-RegisteredApplications` | Alle registrierten Anwendungen auflisten |

## Verwendung

### Dateityp-Zuordnung setzen

```powershell
# PDF mit Adobe Reader öffnen
Set-FTA "AcroExch.Document.DC" ".pdf"

# Textdateien mit VS Code öffnen
Set-FTA "Applications\code.exe" ".txt"
```

### Protokoll-Zuordnung setzen

```powershell
# Chrome als Standard-Browser
Set-PTA "ChromeHTML" "http"
Set-PTA "ChromeHTML" "https"

# Firefox als Standard-Browser
Set-PTA "FirefoxURL-308046B0AF4A39CB" "http"
```

### Aktuelle Zuordnungen abrufen

```powershell
# Einzelne Zuordnung
Get-FTA ".pdf"
Get-PTA "http"

# Alle Zuordnungen
Get-AllFTA
Get-AllPTA
```

### ProgId finden

```powershell
# Welche Programme können PDFs öffnen?
Find-ProgIdForExtension ".pdf"
```

## UCPD (User Choice Protection Driver)

Windows 10/11 (ab Februar 2022) enthält UCPD, das programmatische Änderungen an folgenden Zuordnungen **auf Kernel-Ebene blockiert**:

- `.pdf`, `.htm`, `.html` Dateien
- `http` und `https` Protokolle

### Warum schützt Windows genau diese Zuordnungen?

**Browser (http/https)** sind das Haupteinfallstor für Cyberangriffe:
- Malware könnte heimlich einen manipulierten Browser als Standard setzen
- Umleitung auf Phishing-Seiten ohne dass der Nutzer es bemerkt
- Abfangen von Login-Daten, Banking-Informationen, etc.
- Man-in-the-Middle-Angriffe durch gefälschte Browser

**PDF/HTML** ist der zweitgrößte Angriffsvektor:
- PDFs können JavaScript, eingebettete Objekte und Links enthalten
- Malware könnte einen unsicheren oder manipulierten PDF-Reader setzen
- Exploit-Kits nutzen häufig präparierte PDF-Dateien

Ohne UCPD könnte Schadsoftware sich als Browser registrieren, alle Web-Anfragen abfangen und Credentials stehlen - daher gelten diese Zuordnungen als "kritische Infrastruktur".

**Und natürlich rein zufällig...** 😉
- ...ist Microsoft Edge der Standard-Browser nach jeder Windows-Installation
- ...ist Microsoft Edge der Standard-PDF-Reader nach jeder Windows-Installation
- ...macht UCPD es Chrome, Firefox und Adobe ausgesprochen schwer, sich als Default zu setzen
- ...kam UCPD genau dann, als die EU Microsoft wegen Browser-Bundling untersuchte

*Aber das hat natürlich nichts miteinander zu tun. Das ist alles nur zum Schutz der Nutzer.* 🙃

### UCPD-Status prüfen

```powershell
Test-UCPDEnabled    # True/False
Get-UCPDStatus      # Detaillierte Infos
```

### Wie geht UCPD mit existierenden Einträgen um?

UCPD hat zwei Verhaltensweisen:

**1. Blockiert neue Schreibzugriffe**
- Programme erhalten `PermissionDenied` beim Versuch, die Registry zu ändern
- Der bestehende Eintrag bleibt unverändert

**2. Lässt existierende Einträge in Ruhe** (meistens)
- Manuell über Windows-Einstellungen gesetzte Zuordnungen bleiben bestehen
- UCPD "repariert" oder überschreibt keine alten Einträge aktiv

**Aber Achtung:** Windows selbst kann Zuordnungen zurücksetzen:

| Situation | Was passiert |
|-----------|--------------|
| Windows Feature-Update | Kann Zuordnungen auf Microsoft-Defaults zurücksetzen |
| Edge/Browser-Update | Setzt manchmal http/https auf Edge zurück |
| Hash-Mismatch | Ungültiger Hash → Eintrag wird ignoriert, Windows fragt neu |
| "App Defaults Reset" | Windows zeigt Notification und setzt zurück |

**Prüfen ob ein Eintrag gültig ist:**

```powershell
# Wenn ProgId und Hash vorhanden sind, ist der Eintrag gültig
Get-FTA ".pdf"
Get-PTA "http"
```

**Zusammenfassung:** UCPD schützt den *Schreibzugriff*, nicht existierende Daten. Das eigentliche Problem ist, dass Windows bei Updates manchmal selbst die Zuordnungen auf Microsoft-Produkte zurücksetzt - unabhängig von UCPD.

---

## WICHTIG: Was funktioniert und was nicht

### Übersicht nach Extension-Typ

| Extension/Protokoll | Set-FTA/Set-PTA | Set-FTA-Regini | Login-Script | DISM Import | GPO |
|---------------------|-----------------|----------------|--------------|-------------|-----|
| `.txt`, `.jpg`, `.docx`, etc. | ✅ | ✅ | ✅ | ✅ | ✅ |
| `.pdf`, `.htm`, `.html` | ❌ UCPD blockiert | ✅ **NEU!** | ❌ | ✅ Nur neue User | ✅ |
| `http`, `https` | ❌ UCPD blockiert | ✅ **NEU!** | ❌ | ✅ Nur neue User | ✅ |
| `mailto`, `tel`, etc. | ✅ | ✅ | ✅ | ✅ | ✅ |

### Übersicht nach Szenario

| Szenario | Methode | Funktioniert für UCPD-geschützte? |
|----------|---------|-----------------------------------|
| Einzelner PC, manuell | Windows-Einstellungen | ✅ Ja |
| Einzelner PC, Script | `Set-FTA` / `Set-PTA` | ❌ Nein |
| **Einzelner PC, Admin-Script** | **`Set-FTA-Regini.ps1`** | **✅ Ja (NEU!)** |
| Neue Benutzerprofile | DISM Import | ✅ Ja |
| Bestehende User, Enterprise | GPO + XML | ⚠️ Nur bei erstem Login nach GPO |
| Bestehende User, Login-Script | `Set-FTA` im Script | ❌ Nein |
| **Bestehende User, Admin-Deployment** | **`Set-FTA-Regini.ps1`** | **✅ Ja (NEU!)** |
| Bestehende User, manuell | User ändert selbst | ✅ Ja |

### ~~Die harte Wahrheit~~ Die gute Nachricht für Enterprise-Admins

~~Für bestehende Benutzerprofile mit UCPD gibt es KEINEN programmatischen Weg, PDF/HTML/HTTP-Zuordnungen zu ändern.~~

**UPDATE Januar 2026:** Mit der `Set-FTA-Regini.ps1` Methode gibt es jetzt einen funktionierenden Weg!

**Optionen für UCPD-geschützte Extensions:**

1. **NEU: `Set-FTA-Regini.ps1`** - Funktioniert mit Admin-Rechten, auch bei aktivem UCPD! ✅
2. **User ändert es selbst** in Windows-Einstellungen → Standard-Apps
3. **UCPD deaktivieren** (nicht empfohlen, Sicherheitsrisiko)
4. **Neues Benutzerprofil** mit DISM-importierten Defaults

### Wie machen es Adobe, Chrome, Firefox und SetUserFTA?

**Kurze Antwort:** Genauso - sie haben auch keine Lösung.

| Anbieter | "Lösung" |
|----------|----------|
| **Adobe Acrobat** | Zeigt Popup "Make Adobe your default PDF app" → User muss selbst in Windows-Einstellungen ändern |
| **Google Chrome** | Zeigt Popup "Set as default browser" → Öffnet Windows-Einstellungen |
| **Mozilla Firefox** | Zeigt Popup "Set as default browser" → Öffnet Windows-Einstellungen |
| **SetUserFTA** | Katz-und-Maus-Spiel mit Microsoft (siehe unten) |

**SetUserFTA** (von Christoph Kolbicz, dem Reverse-Engineer des Hash-Algorithmus):
- Wurde im Februar 2024 von UCPD blockiert
- Mai 2024: Update veröffentlicht, das wieder funktioniert
- Kolbicz selbst sagt: *"This is probably not a permanent solution, because Microsoft can block it with an updated UCPD.sys very quickly."*

### Technische Details: Wie SetUserFTA UCPD umgeht

**UCPD blockiert nur bestimmte Executables:**
```
dllhost.exe, reg.exe, rundll32.exe, powershell.exe, regedit.exe,
wscript.exe, cscript.exe, cmd.exe, pwsh.exe, WmiPrvSE.exe
```

`SetUserFTA.exe` steht nicht auf dieser Liste - das war der erste "Trick".

**Bypass-Techniken und deren Schicksal:**

| Technik | Beschreibung | Status |
|---------|--------------|--------|
| Eigene .exe | Nicht auf Blocklist | ⚠️ Kann jederzeit blockiert werden |
| ACL Manipulation | `RegSetKeySecurity()` → Rechte zurücksetzen | ❌ Blockiert in UCPD v4.3 |
| Value Deletion | ProgId/Hash löschen statt überschreiben | ❌ Blockiert in UCPD v4.3 |
| Direct NT API | Low-Level Kernel-Calls | ⚠️ Teilweise blockiert |

**Das Katz-und-Maus-Spiel:**

| Zeitpunkt | SetUserFTA | Microsoft Reaktion |
|-----------|------------|-------------------|
| Feb 2024 | ❌ Funktioniert nicht mehr | UCPD v3.1 released |
| Apr 2024 | ✅ ACL-Trick | ❌ Blockiert in v4.2 |
| Mai 2024 | ✅ Neuer Workaround | ❌ Blockiert in v4.3 |
| Laufend | ? | Telemetrie erkennt Angriffe **bevor** sie veröffentlicht werden |

**Microsoft kann die Blocklist "on the fly" updaten** - ohne Treiber-Update, ohne Reboot. Sie nutzen Telemetrie und Windows Defender um neue Bypass-Methoden zu erkennen.

### Windows Server: Nicht betroffen!

**Wichtig:** Windows Server hat kein UCPD. Dort funktioniert `Set-FTA` und `Set-PTA` problemlos für alle Extensions und Protokolle, einschließlich `.pdf`, `http`, `https`.

**Was UCPD v4.3 (Stand 2024) alles blockiert:**
- Registry Write/Delete/Rename auf geschützte Keys
- Alle üblichen Tools: `powershell.exe`, `cmd.exe`, `reg.exe`, `regedit.exe`, `wscript.exe`
- UI Automation Attacks (simulierte Mausklicks auf Windows-Einstellungen)
- DLL Injection Attacks
- ACL-Änderungen auf geschützte Keys

**Fazit:** Selbst große Software-Hersteller wie Adobe können UCPD nicht umgehen. Sie alle bitten den User, die Einstellung manuell zu ändern. Das ist kein Versäumnis unsererseits - es ist by Design.

### Unser Experiment: Eigene C# .exe (SetFTA.exe)

Wir haben versucht, den SetUserFTA-Ansatz nachzubauen - eine eigenständige `.exe`, die nicht auf der UCPD-Blocklist steht:

**Was wir gebaut haben:**
- Standalone C# .exe (`src/SetFTA/SetFTA.exe`)
- Hash-Algorithmus in C# implementiert (identisch zu PowerShell)
- Drei Methoden: Win32 API, .NET Registry API, Delete-and-Recreate
- Direkte `advapi32.dll` Calls: `RegCreateKeyEx`, `RegSetValueEx`, `RegDeleteTree`

**Testergebnisse (November 2024):**

| Test | Extension | Ergebnis |
|------|-----------|----------|
| SetFTA.exe set-fta "Applications\notepad.exe" ".txt" | `.txt` | ✅ **Funktioniert!** |
| SetFTA.exe set-fta "MSEdgePDF" ".pdf" | `.pdf` | ❌ **Error 5 (Access Denied)** |
| SetFTA.exe set-pta "ChromeHTML" "http" | `http` | ❌ **Error 5 (Access Denied)** |

**Alle drei Methoden schlugen fehl:**
```
[INFO] Win32 API failed: RegSetValueEx (ProgId) failed with error 5
[INFO] .NET API failed: Es wurde versucht, einen nicht autorisierten Vorgang auszuführen.
[INFO] Delete-recreate failed: Es wurde versucht, einen nicht autorisierten Vorgang auszuführen.
```

**Erkenntnis:** UCPD ist **nicht nur eine Prozess-Blocklist** - es überwacht die Registry-Keys **direkt auf Kernel-Ebene**. Selbst ein komplett neuer, unbekannter Prozess mit direkten Win32 API Calls wird blockiert.

Das erklärt, warum SetUserFTA ein permanentes Katz-und-Maus-Spiel mit Microsoft führen muss - jede neue Bypass-Methode wird irgendwann blockiert.

**Quellen:**
- [SetUserFTA Blog: UCPD.sys](https://kolbi.cz/blog/2024/04/03/userchoice-protection-driver-ucpd-sys/)
- [SetUserFTA Blog: UCPD.sys Part 2](https://kolbi.cz/blog/2025/07/15/ucpd-sys-userchoice-protection-driver-part-2/)
- [SetUserFTA FAQ](https://setuserfta.com/faq/)
- [gHacks: UCPD stops non-Microsoft software](https://www.ghacks.net/2024/04/08/new-sneaky-windows-driver-ucdp-stops-non-microsoft-software-from-setting-defaults/)
- [Adobe: Set Acrobat as default](https://helpx.adobe.com/acrobat/kb/not-default-pdf-owner-windows10.html)

---

## UCPD-Bypass mit regini.exe (Der Durchbruch!)

### Entdeckung (Januar 2026)

Durch Procmon-Analyse von **PDF-XChange Editor** haben wir entdeckt, wie dieses Programm die UserChoice-Zuordnung erfolgreich ändert - **auch bei aktivem UCPD**!

### Das Geheimnis: regini.exe

`regini.exe` ist ein Windows-Systemtool (seit Windows 2000) für Registry-Operationen. Es hat eine **undokumentierte `[DELETE]` Syntax**, die den Key vollständig löscht.

**Warum funktioniert regini.exe?**
1. Es ist ein **signiertes Windows-Systemtool** - wird nicht von UCPD blockiert
2. Läuft als **erhöhter Admin-Prozess** - umgeht die DENY-ACL
3. **Löscht den Key komplett** statt ihn zu modifizieren
4. Der **neue Key hat keine DENY-ACL** - kann direkt beschrieben werden

### Verwendung

```powershell
# Als Administrator ausführen!

# PDF mit Chrome öffnen
.\tools\Set-FTA-Regini.ps1 -Extension ".pdf" -ProgId "ChromePDF"

# HTML mit Chrome öffnen
.\tools\Set-FTA-Regini.ps1 -Extension ".htm" -ProgId "ChromeHTML"
.\tools\Set-FTA-Regini.ps1 -Extension ".html" -ProgId "ChromeHTML"

# Erst testen mit -WhatIf
.\tools\Set-FTA-Regini.ps1 -Extension ".pdf" -ProgId "AcroExch.Document.DC" -WhatIf
```

### Wie es funktioniert

Das Script führt einen **zweistufigen Prozess** aus:

**Schritt 1: Key löschen** (DELETE.ini)
```ini
\Registry\User\<SID>\...\UserChoice [DELETE]
```

**Schritt 2: Neue Werte schreiben** (SET.ini)
```ini
\Registry\User\<SID>\...\UserChoice
ProgId="<PROGID>"
Hash="<HASH>"
0
```

Der Hash wird korrekt berechnet (gleicher Algorithmus wie im Hauptmodul).

### Wichtige Hinweise

| Aspekt | Details |
|--------|---------|
| **Admin-Rechte** | Erforderlich! |
| **UCPD aktiv** | Funktioniert trotzdem ✅ |
| **Neustart** | Nicht erforderlich, Änderung sofort aktiv |
| **Persistenz** | Überlebt Neustarts ✅ |
| **Getestet mit** | `.pdf`, `.htm`, `.html` |

### Einschränkungen

- Erfordert **Administrator-Rechte** (nicht als normaler User)
- Funktioniert nur für den **aktuellen Benutzer** (HKCU)
- Für andere Benutzer müsste das Script im Kontext des jeweiligen Users laufen

### Technische Details

Die undokumentierte `[DELETE]` Syntax wurde durch Reverse-Engineering von PDF-XChange Editor entdeckt. Die Procmon-Logs zeigen:

```
08:18:44,1397771  regini.exe  RegDeleteKey  .pdf\UserChoice  SUCCESS
08:18:44,1463787  PDFXEdit.exe  RegCreateKey  .pdf\UserChoice  REG_CREATED_NEW_KEY
08:18:44,2386978  regini.exe  RegSetValue  ProgId = "PDFXEdit.PDF"
08:18:44,2404794  regini.exe  RegSetValue  Hash = "h7GW3/yQOm8="
```

Siehe `tools/DENY-ACL-Research.md` für die vollständige Forschungsdokumentation.

---

## Enterprise-Deployment: FTA-Manager-Service (Scheduled Task)

Für Unternehmensumgebungen, in denen User keine Admin-Rechte haben, bietet der FTA-Manager-Service eine elegante Lösung: User können FTA-Änderungen **anfordern**, ein Scheduled Task mit SYSTEM-Rechten führt sie aus.

### Architektur

```
[User-Kontext]                           [SYSTEM-Kontext]
Logon-Script / GPO                       Scheduled Task "FTA-Manager-Service"
(keine Admin-Rechte)                     (SYSTEM-Rechte)

HKCU\Software\FTA-Manager\Requests\
    .pdf = ChromePDF        ─────────►   Liest HKU\<SID>\...\Requests
    .html = MSEdgeHTM                    Validiert ProgId
                                         Berechnet Hash
                                         Führt regini.exe aus
                                         Löscht Request
                                         Loggt nach EventLog
```

### Installation

```powershell
# Als Administrator ausführen:
.\Install-FTAManagerService.ps1

# Oder mit benutzerdefiniertem Pfad:
.\Install-FTAManagerService.ps1 -InstallPath "D:\Tools\FTA-Manager"

# Deinstallation:
.\Install-FTAManagerService.ps1 -Uninstall
```

**Was wird installiert:**
- `C:\Program Files\FTA-Manager\FTA-Manager-Service.ps1`
- Scheduled Task `\FTA-Manager\FTA-Manager-Service`
- EventLog Source `FTA-Manager` im Application-Log

### User-Seite: FTA-Änderung anfordern

User (oder Logon-Scripts/GPOs) schreiben ihre Wünsche in die Registry:

```powershell
# Im Logon-Script oder via GPO Registry Preference:
$requestPath = "HKCU:\Software\FTA-Manager\Requests"
if (-not (Test-Path $requestPath)) {
    New-Item -Path $requestPath -Force | Out-Null
}

# FTA-Änderungen anfordern:
Set-ItemProperty -Path $requestPath -Name ".pdf" -Value "ChromePDF"
Set-ItemProperty -Path $requestPath -Name ".html" -Value "MSEdgeHTM"

# Protokoll-Änderungen anfordern:
Set-ItemProperty -Path $requestPath -Name "http" -Value "MSEdgeHTM"
Set-ItemProperty -Path $requestPath -Name "https" -Value "MSEdgeHTM"
```

**GPO Registry Preference:**
- Pfad: `HKCU\Software\FTA-Manager\Requests`
- Wertname: `.pdf` (oder andere Extension/Protokoll)
- Wertdaten: `ChromePDF` (oder andere ProgId)
- Typ: `REG_SZ`

### Trigger und Verarbeitung

Der Scheduled Task wird ausgelöst:
- **Trigger:** Bei Anmeldung eines beliebigen Benutzers + 30 Sekunden Verzögerung
- **Ausführen als:** NT AUTHORITY\SYSTEM
- **Timeout:** 5 Minuten

Der Service:
1. Durchsucht alle geladenen User-Hives (HKU)
2. Liest Requests aus `HKU\<SID>\Software\FTA-Manager\Requests`
3. Validiert jede ProgId (existiert in HKCR?)
4. Berechnet den korrekten UserChoice-Hash
5. Führt regini.exe aus (umgeht UCPD)
6. Löscht den verarbeiteten Request
7. Schreibt Ergebnis ins EventLog

### EventLog

Alle Aktionen werden ins Windows EventLog geschrieben:

| Event ID | Level | Beschreibung |
|----------|-------|--------------|
| 1000 | Information | FTA erfolgreich gesetzt |
| 2000 | Warning | ProgId nicht gefunden |
| 2001 | Warning | regini.exe fehlgeschlagen |
| 3000 | Error | Unerwarteter Fehler |

```powershell
# EventLog abfragen:
Get-EventLog -LogName Application -Source FTA-Manager -Newest 10
```

### Manueller Test

```powershell
# 1. Als User: Request erstellen
$requestPath = "HKCU:\Software\FTA-Manager\Requests"
if (-not (Test-Path $requestPath)) { New-Item -Path $requestPath -Force | Out-Null }
Set-ItemProperty -Path $requestPath -Name ".pdf" -Value "ChromePDF"

# 2. Als Admin: Service-Script manuell ausführen
& "C:\Program Files\FTA-Manager\FTA-Manager-Service.ps1" -Verbose

# 3. Prüfen: FTA gesetzt?
Import-Module .\FTA-Manager.psd1
Get-FTA -Extension .pdf

# 4. Prüfen: Request gelöscht?
Get-ItemProperty "HKCU:\Software\FTA-Manager\Requests" -ErrorAction SilentlyContinue

# 5. Prüfen: EventLog
Get-EventLog -LogName Application -Source FTA-Manager -Newest 5
```

### Vorteile gegenüber anderen Methoden

| Methode | Admin erforderlich? | UCPD-Bypass? | Bestehende User? |
|---------|---------------------|--------------|------------------|
| Set-FTA (Standard) | Nein | ❌ Nein | ✅ Ja |
| Set-FTA-Regini.ps1 | ✅ Ja | ✅ Ja | ✅ Ja |
| DISM Import | ✅ Ja | ✅ Ja | ❌ Nur neue User |
| GPO XML | ✅ Ja | ✅ Ja | ⚠️ Erster Login |
| **FTA-Manager-Service** | ❌ User nein, Task ja | ✅ Ja | ✅ Ja |

**Der Service kombiniert das Beste aus beiden Welten:**
- User brauchen **keine Admin-Rechte**
- Funktioniert für **UCPD-geschützte Extensions**
- Wirkt auf **bestehende Benutzerprofile**
- **Zentral verwaltbar** via GPO/Logon-Script
- **Audit-Trail** via EventLog

---

## Enterprise-Deployment (DISM)

Für Unternehmensumgebungen ist der DISM-Import der empfohlene Weg für **neue Benutzerprofile**:

### Funktionen

| Funktion | Beschreibung |
|----------|--------------|
| `Export-DefaultAssociations` | Exportiert FTA/PTA als DISM-kompatible XML |
| `Import-DefaultAssociations` | Importiert XML via DISM (Admin erforderlich) |
| `Remove-DefaultAssociations` | Entfernt deployed Defaults (Admin erforderlich) |

### Workflow

```powershell
# 1. Auf Referenz-PC: Einstellungen manuell konfigurieren (Windows-Einstellungen)

# 2. Export der Konfiguration
Export-DefaultAssociations -Path ".\defaults.xml" -Extensions ".pdf", ".html" -Protocols "http", "https"

# Oder alle Zuordnungen exportieren:
Export-DefaultAssociations -Path ".\defaults.xml" -IncludeAll

# 3. Auf Ziel-PCs (als Administrator):
Import-DefaultAssociations -Path "\\server\share\defaults.xml"

# 4. Optional: Zurücksetzen auf Windows-Defaults
Remove-DefaultAssociations
```

### Alternative: GPO

1. XML-Datei auf Netzwerkfreigabe ablegen
2. GPO erstellen: `Computer Configuration → Administrative Templates → Windows Components → File Explorer`
3. "Set a default associations configuration file" aktivieren
4. Pfad zur XML-Datei angeben

**Hinweis:** Sowohl DISM-Import als auch GPO gelten primär für **neue Benutzerprofile**. Bestehende Profile werden nur bei bestimmten Bedingungen aktualisiert.

---

## Login-Scripts (nur für nicht-geschützte Extensions!)

Login-Scripts funktionieren **NUR** für Extensions, die nicht von UCPD geschützt sind:

```powershell
# LoginScript-SetFTA.ps1
# ⚠️ Funktioniert NICHT für .pdf, .htm, .html, http, https!

$modulePath = "\\server\share\FTA-Manager\FTA-Manager.psm1"
Import-Module $modulePath -Force

# Diese funktionieren:
Set-FTA "Applications\notepad.exe" ".txt"
Set-FTA "Applications\code.exe" ".log"
Set-FTA "Applications\photoviewer.dll" ".jpg"

# Diese werden von UCPD blockiert (Fehler):
# Set-FTA "AcroExch.Document.DC" ".pdf"      # ❌ Blockiert
# Set-PTA "ChromeHTML" "http"                 # ❌ Blockiert
```

---

## UCPD deaktivieren mit EDR/XDR (Enterprise-Strategie)

In Enterprise-Umgebungen mit aktiver EDR/XDR-Lösung kann UCPD **verantwortungsvoll** deaktiviert werden, da der EDR den Schutz übernimmt.

### Unterstützte EDR/XDR-Lösungen

Das Modul erkennt automatisch:

| EDR/XDR | Service Name |
|---------|--------------|
| Microsoft Defender for Endpoint | Sense |
| CrowdStrike Falcon | CSFalconService |
| SentinelOne | SentinelAgent |
| VMware Carbon Black | CbDefense |
| Palo Alto Cortex XDR | CortexXDR |
| Sophos Endpoint | Sophos Endpoint Defense Service |

### Funktionen

| Funktion | Beschreibung |
|----------|--------------|
| `Get-EDRStatus` | Erkennt installierte EDR/XDR-Lösungen |
| `Disable-UCPDSafely` | Deaktiviert UCPD mit EDR-Check und Logging |
| `Enable-UCPDSafely` | Reaktiviert UCPD mit Logging |

### Workflow

```powershell
# 1. EDR-Status prüfen
Get-EDRStatus

# 2. UCPD sicher deaktivieren (prüft EDR, loggt Aktion)
Disable-UCPDSafely -Reason "FTA Deployment für Adobe Acrobat"

# Output:
# [OK] UCPD driver disabled (Start = 4)
# [OK] UCPD velocity scheduled task disabled
# [OK] Action logged to: C:\Windows\Logs\FTA-Manager\UCPD.log
#
# ========================================
#  UCPD SUCCESSFULLY DISABLED
# ========================================
#  A REBOOT IS REQUIRED for changes to take effect!
#  EDR Protection: Microsoft Defender for Endpoint

# 3. REBOOT

# 4. Nach Reboot: FTA setzen (funktioniert jetzt!)
Set-FTA "AcroExch.Document.DC" ".pdf"
Set-PTA "ChromeHTML" "http"

# 5. Optional: UCPD wieder aktivieren
Enable-UCPDSafely -Reason "FTA Deployment abgeschlossen"
```

### Was wird geloggt?

Alle UCPD-Änderungen werden protokolliert in `C:\Windows\Logs\FTA-Manager\UCPD.log`:

```
================================================================================
UCPD DEACTIVATION LOG
================================================================================
Timestamp:    2024-03-15 14:32:01
Computer:     WORKSTATION01
User:         DOMAIN\admin
Reason:       FTA Deployment für Adobe Acrobat
EDR Status:   PROTECTED
EDR Products: Microsoft Defender for Endpoint

Actions:
  - UCPD Driver:    Disabled
  - Scheduled Task: Disabled
================================================================================
```

### Ohne EDR: Warnung und -Force

Wenn kein EDR erkannt wird, verweigert `Disable-UCPDSafely` die Ausführung:

```powershell
PS> Disable-UCPDSafely -Reason "Test"

WARNING: NO EDR/XDR PROTECTION DETECTED!
Disabling UCPD without EDR protection is a security risk.
```

Mit `-Force` kann trotzdem fortgefahren werden - es erscheint dann eine deutliche Warnung:

```powershell
PS> Disable-UCPDSafely -Reason "Bewusste Entscheidung ohne EDR" -Force

╔══════════════════════════════════════════════════════════════════╗
║                    ⚠️  SECURITY WARNING  ⚠️                       ║
╠══════════════════════════════════════════════════════════════════╣
║  You are disabling UCPD WITHOUT EDR/XDR protection!              ║
║                                                                  ║
║  RISKS:                                                          ║
║  • Malware can hijack your default browser                       ║
║  • Malware can redirect PDF files to malicious readers           ║
║  • Phishing attacks become easier                                ║
║  • No endpoint protection to detect malicious changes            ║
║                                                                  ║
║  This action will be logged for audit purposes.                  ║
╚══════════════════════════════════════════════════════════════════╝

WARNING: Proceeding WITHOUT EDR protection as -Force was specified...

[OK] UCPD driver disabled (Start = 4)
[OK] UCPD velocity scheduled task disabled
[OK] Action logged to: C:\Windows\Logs\FTA-Manager\UCPD.log
```

**Wichtig:** Auch mit `-Force` wird die Aktion vollständig geloggt für Audit-Zwecke.

---

## UCPD deaktivieren (manuell - nicht empfohlen)

### Warum "kurz deaktivieren" NICHT funktioniert

Eine häufige Idee: "Können wir UCPD bei jedem Login kurz deaktivieren, die Änderung machen, und wieder aktivieren?"

**Nein** - UCPD ist ein **Kernel-Treiber** (`UCPD.sys`), der beim Booten geladen wird und bis zum nächsten Reboot aktiv bleibt:

| Schritt | Aktion | UCPD Status |
|---------|--------|-------------|
| 1 | System startet | ✅ Aktiv (Treiber geladen) |
| 2 | Script: `Disable-UCPD` | ✅ **Noch aktiv!** (nur Registry geändert) |
| 3 | Script: `Set-FTA ".pdf"` | ❌ **Blockiert** (Treiber läuft noch) |
| 4 | Reboot #1 | ❌ Jetzt erst deaktiviert |
| 5 | Script: `Set-FTA ".pdf"` | ✅ Funktioniert |
| 6 | Script: `Enable-UCPD` | ❌ Noch deaktiviert |
| 7 | Reboot #2 | ✅ Wieder aktiv |

**Probleme:**
- **2 Reboots erforderlich** für eine einzige Änderung
- **Sicherheitslücke** zwischen Reboot #1 und #2 (System ungeschützt)
- **Unpraktikabel** für Login-Scripts oder Automatisierung

Microsoft hat das absichtlich so designt - es gibt keinen Weg, UCPD "mal kurz" zu deaktivieren.

### Falls Sie UCPD trotzdem permanent deaktivieren müssen

```powershell
# Erfordert Administrator-Rechte
Disable-UCPD

# Neustart erforderlich!
Restart-Computer

# Nach Neustart funktioniert Set-FTA auch für .pdf, http, etc.

# Später wieder aktivieren:
Enable-UCPD
Restart-Computer
```

**Warnung:** Das permanente Deaktivieren von UCPD ist ein Sicherheitsrisiko. Malware könnte dann Browser- und PDF-Zuordnungen manipulieren.

## Gängige ProgIds

```
# Browser
ChromeHTML              - Google Chrome
MSEdgeHTM               - Microsoft Edge
FirefoxURL-*            - Mozilla Firefox (GUID variiert)

# PDF-Reader
AcroExch.Document.DC    - Adobe Acrobat Reader DC
FoxitReader.Document    - Foxit Reader

# Allgemein
Applications\notepad.exe    - Notepad
Applications\code.exe       - VS Code
```

## Systemanforderungen

- Windows 10/11
- PowerShell 5.1 oder höher

## Technische Details

### Registry-Pfade

Die Zuordnungen werden in folgenden Registry-Pfaden gespeichert:

- **Dateiendungen**: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{ext}\UserChoice`
- **Protokolle**: `HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{protocol}\UserChoice`
- **Toast-Benachrichtigungen**: `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts`

### Hash-Algorithmus

Das Modul berechnet den UserChoice-Hash nach folgendem Algorithmus:

1. Eingabe: `extension + userSid + progId + timestamp + userExperienceString`
2. UTF-16LE Kodierung mit Null-Terminator
3. MD5-Hash als Seed für Schlüssel
4. Zwei-Pass-Transformation mit Konstante `0x0E79A9C1`
5. Base64-Kodierung des Ergebnisses

Der Magic String ist: `"User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"`

### Wichtige Hinweise zur Implementierung

- Der Hash-Algorithmus ist **zeit-sensitiv** (verwendet aktuelle Minute, abgerundet)
- Hash und ProgId müssen **atomar** geschrieben werden (Key erst löschen, dann neu erstellen)
- Ein `ApplicationAssociationToasts`-Eintrag ist erforderlich, damit die Zuordnung funktioniert
- Die Eingabe für den Hash muss immer **lowercase** sein

## SetFTA.exe (C# Tool)

Zusätzlich zum PowerShell-Modul enthält dieses Projekt eine standalone C# Executable:

### Build

```cmd
dotnet build src/SetFTA/SetFTA.csproj -c Release
```

Die Executable wird erstellt unter: `src/SetFTA/bin/Release/net472/SetFTA.exe`

### Verwendung

```cmd
# Hilfe anzeigen
SetFTA.exe --help

# File Type Association setzen
SetFTA.exe set-fta "Applications\notepad.exe" ".txt"
SetFTA.exe set-fta "AcroExch.Document.DC" ".pdf"

# Protocol Association setzen
SetFTA.exe set-pta "ChromeHTML" "http"

# Aktuelle Zuordnung anzeigen
SetFTA.exe get-fta ".pdf"
SetFTA.exe get-pta "http"

# Hash-Berechnung testen (Debug)
SetFTA.exe test-hash ".pdf" "AcroExch.Document.DC"
```

### Warum eine C# .exe?

Die Idee war, UCPD zu umgehen, da es ursprünglich nur bestimmte Prozesse (`powershell.exe`, `cmd.exe`, etc.) blockierte. Leider hat Microsoft UCPD so erweitert, dass es die Registry-Keys **direkt auf Kernel-Ebene** überwacht - unabhängig vom aufrufenden Prozess.

**Ergebnis:** Die C# .exe funktioniert perfekt für nicht-geschützte Extensions (`.txt`, `.jpg`, etc.), wird aber wie PowerShell bei geschützten Extensions (`.pdf`, `http`, etc.) blockiert.

**Trotzdem nützlich für:**
- Deployment in Umgebungen ohne PowerShell
- Batch-Scripting
- Integration in andere Tools
- Setzen von nicht-geschützten Extensions

## Referenzen

- [PS-SFTA](https://github.com/DanysysTeam/PS-SFTA) - Ursprüngliche PowerShell-Implementierung
- [SetUserFTA](https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user/) - Reverse Engineering des Hash-Algorithmus

## Lizenz

MIT License - siehe [LICENSE](LICENSE)

# FTA-Manager

PowerShell-Modul zur Verwaltung von Windows File Type Associations (FTA) und Protocol Associations (PTA).

## Übersicht

FTA-Manager ermöglicht das programmatische Setzen von Dateityp- und Protokoll-Zuordnungen unter Windows 10/11, indem es den korrekten UserChoice-Hash berechnet, den Windows seit Windows 8 zur Validierung benötigt.

## Installation

```powershell
# Modul importieren
Import-Module .\FTA-Manager.psd1
```

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

### UCPD-Verwaltung

| Funktion | Beschreibung |
|----------|--------------|
| `Test-UCPDEnabled` | Prüft, ob UCPD aktiv ist |
| `Get-UCPDStatus` | Detaillierter UCPD-Status |
| `Disable-UCPD` | UCPD deaktivieren (Admin + Reboot erforderlich) |
| `Enable-UCPD` | UCPD aktivieren (Admin + Reboot erforderlich) |

### Enterprise-Deployment (DISM)

| Funktion | Beschreibung |
|----------|--------------|
| `Export-DefaultAssociations` | Exportiert FTA/PTA als DISM-kompatible XML |
| `Import-DefaultAssociations` | Importiert XML via DISM (Admin erforderlich) |
| `Remove-DefaultAssociations` | Entfernt deployed Defaults (Admin erforderlich) |

### Hilfsfunktionen

| Funktion | Beschreibung |
|----------|--------------|
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

### UCPD-Status prüfen

```powershell
Test-UCPDEnabled    # True/False
Get-UCPDStatus      # Detaillierte Infos
```

---

## WICHTIG: Was funktioniert und was nicht

### Übersicht nach Extension-Typ

| Extension/Protokoll | Set-FTA/Set-PTA | Login-Script | DISM Import | GPO |
|---------------------|-----------------|--------------|-------------|-----|
| `.txt`, `.jpg`, `.docx`, etc. | ✅ | ✅ | ✅ | ✅ |
| `.pdf`, `.htm`, `.html` | ❌ UCPD blockiert | ❌ | ✅ Nur neue User | ✅ |
| `http`, `https` | ❌ UCPD blockiert | ❌ | ✅ Nur neue User | ✅ |
| `mailto`, `tel`, etc. | ✅ | ✅ | ✅ | ✅ |

### Übersicht nach Szenario

| Szenario | Methode | Funktioniert für UCPD-geschützte? |
|----------|---------|-----------------------------------|
| Einzelner PC, manuell | Windows-Einstellungen | ✅ Ja |
| Einzelner PC, Script | `Set-FTA` / `Set-PTA` | ❌ Nein |
| Neue Benutzerprofile | DISM Import | ✅ Ja |
| Bestehende User, Enterprise | GPO + XML | ⚠️ Nur bei erstem Login nach GPO |
| Bestehende User, Login-Script | `Set-FTA` im Script | ❌ Nein |
| Bestehende User, manuell | User ändert selbst | ✅ Ja |

### Die harte Wahrheit für Enterprise-Admins

**Für bestehende Benutzerprofile mit UCPD gibt es KEINEN programmatischen Weg, PDF/HTML/HTTP-Zuordnungen zu ändern.**

Microsoft hat das absichtlich so implementiert. Die einzigen Optionen sind:

1. **User ändert es selbst** in Windows-Einstellungen → Standard-Apps
2. **UCPD deaktivieren** (nicht empfohlen, Sicherheitsrisiko)
3. **Neues Benutzerprofil** mit DISM-importierten Defaults

---

## Enterprise-Deployment (DISM)

Für Unternehmensumgebungen ist der DISM-Import der empfohlene Weg:

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

## UCPD deaktivieren (nicht empfohlen)

Falls Sie UCPD trotzdem deaktivieren müssen:

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

**Warnung:** Das Deaktivieren von UCPD ist ein Sicherheitsrisiko und wird nicht empfohlen. Malware könnte dann Browser- und PDF-Zuordnungen manipulieren.

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

## Referenzen

- [PS-SFTA](https://github.com/DanysysTeam/PS-SFTA) - Ursprüngliche PowerShell-Implementierung
- [SetUserFTA](https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user/) - Reverse Engineering des Hash-Algorithmus

## Lizenz

MIT License - siehe [LICENSE](LICENSE)

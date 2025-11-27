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

Windows 10/11 (ab Februar 2022) enthält UCPD, das programmatische Änderungen an folgenden Zuordnungen blockiert:

- `.pdf` Dateien
- `http` und `https` Protokolle

### Warum schützt Windows genau diese Zuordnungen?

**Browser (http/https)** sind das Haupteinfallstor für Cyberangriffe:
- Malware könnte heimlich einen manipulierten Browser als Standard setzen
- Umleitung auf Phishing-Seiten ohne dass der Nutzer es bemerkt
- Abfangen von Login-Daten, Banking-Informationen, etc.
- Man-in-the-Middle-Angriffe durch gefälschte Browser

**PDF** ist der zweitgrößte Angriffsvektor:
- PDFs können JavaScript, eingebettete Objekte und Links enthalten
- Malware könnte einen unsicheren oder manipulierten PDF-Reader setzen
- Exploit-Kits nutzen häufig präparierte PDF-Dateien

Ohne UCPD könnte Schadsoftware sich als Browser registrieren, alle Web-Anfragen abfangen und Credentials stehlen - daher gelten diese Zuordnungen als "kritische Infrastruktur".

### UCPD-Status prüfen

```powershell
Test-UCPDEnabled    # True/False
Get-UCPDStatus      # Detaillierte Infos
```

### UCPD deaktivieren

```powershell
# Erfordert Administrator-Rechte und Neustart
Disable-UCPD
```

**Hinweis:** Mit dem `-Force` Parameter kann versucht werden, geschützte Zuordnungen trotzdem zu setzen. UCPD macht diese Änderungen jedoch beim nächsten Lauf rückgängig.

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

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

**Quellen:**
- [SetUserFTA Blog: UCPD.sys](https://kolbi.cz/blog/2024/04/03/userchoice-protection-driver-ucpd-sys/)
- [SetUserFTA Blog: UCPD.sys Part 2](https://kolbi.cz/blog/2025/07/15/ucpd-sys-userchoice-protection-driver-part-2/)
- [SetUserFTA FAQ](https://setuserfta.com/faq/)
- [gHacks: UCPD stops non-Microsoft software](https://www.ghacks.net/2024/04/08/new-sneaky-windows-driver-ucdp-stops-non-microsoft-software-from-setting-defaults/)
- [Adobe: Set Acrobat as default](https://helpx.adobe.com/acrobat/kb/not-default-pdf-owner-windows10.html)

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

## Referenzen

- [PS-SFTA](https://github.com/DanysysTeam/PS-SFTA) - Ursprüngliche PowerShell-Implementierung
- [SetUserFTA](https://kolbi.cz/blog/2017/10/25/setuserfta-userchoice-hash-defeated-set-file-type-associations-per-user/) - Reverse Engineering des Hash-Algorithmus

## Lizenz

MIT License - siehe [LICENSE](LICENSE)

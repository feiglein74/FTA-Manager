# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

## [1.2.0] - 2026-01-21 - UCPD-Bypass via regini.exe

### Hinzugefügt

- **Automatischer UCPD-Bypass in Set-FTA und Set-PTA** 🎉
  - Für UCPD-geschützte Extensions (`.pdf`, `.htm`, `.html`) und Protokolle (`http`, `https`)
  - Verwendet automatisch regini.exe wenn als Administrator ausgeführt
  - Fallback auf Standard-Methode mit Warnung wenn regini.exe fehlschlägt
  - Neue `Method` Property im Rückgabewert (`Regini` oder `Registry`)

- **Neue Funktion: `Test-IsUCPDProtected`**
  - Prüft ob eine Extension oder ein Protokoll UCPD-geschützt ist
  - Parameter: `-Extension` oder `-Protocol`

- **Interne Funktion: `Set-UserChoiceViaRegini`**
  - Nutzt undokumentierte `[DELETE]` Syntax von regini.exe
  - Entdeckt durch Reverse-Engineering von PDF-XChange Editor

- **Standalone-Tool: `tools/Set-FTA-Regini.ps1`**
  - Unabhängiges Script für direkten Bypass
  - Nützlich für Tests und spezielle Anwendungsfälle

- **Forschungsdokumentation**
  - `DENY-ACL-Research.md` - Vollständige Dokumentation der Forschung
  - `tools/README.md` - Übersicht der Tools
  - Procmon-Logs als Beweise

### Technische Details

Die Methode basiert auf:
1. regini.exe ist ein signiertes Windows-Systemtool (wird nicht von UCPD blockiert)
2. Undokumentierte `[DELETE]` Syntax löscht den UserChoice-Key komplett
3. Neuer Key hat keine DENY-ACL und kann beschrieben werden

## [1.1.0] - 2024-11-28

### Hinzugefügt

- **UCPD Scheduled Task Management**
  - `Get-UCPDScheduledTask` - Status des UCPD Scheduled Tasks
  - `Disable-UCPDScheduledTask` - UCPD Task deaktivieren (verhindert Re-Aktivierung)
  - `Enable-UCPDScheduledTask` - UCPD Task aktivieren

- **Enterprise UCPD Safe Management**
  - `Disable-UCPDSafely` - UCPD deaktivieren mit EDR-Check und Audit-Logging
  - `Enable-UCPDSafely` - UCPD reaktivieren mit Logging

- **Enterprise Deployment (DISM)**
  - `Export-DefaultAssociations` - Exportiert FTA/PTA als DISM-kompatible XML
  - `Import-DefaultAssociations` - Importiert XML via DISM (Admin erforderlich)
  - `Remove-DefaultAssociations` - Entfernt deployed Defaults (Admin erforderlich)

- **Hilfsfunktionen**
  - `Test-IsWindowsServer` - Prüft ob Windows Server (kein UCPD)
  - `Open-DefaultAppsSettings` - Öffnet Windows-Einstellungen für manuelle Änderung
  - `Get-EDRStatus` - Erkennt installierte EDR/XDR-Lösungen (14 Produkte)

### Geändert

- PSScriptAnalyzer Warnings behoben

## [1.0.0] - 2024-11-26

### Hinzugefügt

- **File Type Associations (FTA)**
  - `Get-FTA` - Aktuelle Dateityp-Zuordnung abrufen
  - `Set-FTA` - Dateityp-Zuordnung setzen
  - `Remove-FTA` - Dateityp-Zuordnung entfernen
  - `Get-AllFTA` - Alle Dateityp-Zuordnungen auflisten

- **Protocol Associations (PTA)**
  - `Get-PTA` - Aktuelle Protokoll-Zuordnung abrufen
  - `Set-PTA` - Protokoll-Zuordnung setzen
  - `Remove-PTA` - Protokoll-Zuordnung entfernen
  - `Get-AllPTA` - Alle Protokoll-Zuordnungen auflisten

- **UCPD-Verwaltung**
  - `Test-UCPDEnabled` - Prüft, ob UCPD aktiv ist
  - `Get-UCPDStatus` - Detaillierter UCPD-Status
  - `Disable-UCPD` - UCPD deaktivieren (Admin + Reboot erforderlich)
  - `Enable-UCPD` - UCPD aktivieren (Admin + Reboot erforderlich)

- **Hilfsfunktionen**
  - `Find-ProgIdForExtension` - Verfügbare ProgIds für eine Extension finden
  - `Get-RegisteredApplications` - Alle registrierten Anwendungen auflisten

- Kern-Hash-Algorithmus für Windows UserChoice
- Unterstützung für Windows 10/11
- UCPD-Schutz-Erkennung für `.pdf`, `http`, `https`

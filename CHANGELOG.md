# Changelog

Alle wichtigen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

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

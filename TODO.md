# TODO

## Offen

- [ ] PowerShell Gallery Veröffentlichung vorbereiten
- [ ] CI/CD Pipeline einrichten (GitHub Actions)
- [ ] Beispiel-Skripte für häufige Anwendungsfälle erstellen

## Ideen

- [ ] GUI-Wrapper für einfache Bedienung
- [ ] Batch-Import von Zuordnungen aus CSV/JSON
- [ ] Backup/Restore von Zuordnungen
- [ ] Unterstützung für maschinenweite Zuordnungen (HKLM)

## Erledigt

- [x] **v1.1.0 Enterprise Features**
  - [x] Test-IsWindowsServer - Windows Server Erkennung
  - [x] Get-UCPDScheduledTask / Disable- / Enable-UCPDScheduledTask
  - [x] Open-DefaultAppsSettings - Windows Einstellungen öffnen
  - [x] Get-EDRStatus - EDR/XDR Erkennung (14 Produkte)
  - [x] Disable-UCPDSafely / Enable-UCPDSafely - Enterprise UCPD Management
  - [x] Export- / Import- / Remove-DefaultAssociations - DISM Deployment
  - [x] PSScriptAnalyzer Warnings behoben
- [x] Pester-Tests erstellen (52 Tests)
- [x] Kern-Hash-Algorithmus implementieren
- [x] FTA-Funktionen (Get/Set/Remove/GetAll)
- [x] PTA-Funktionen (Get/Set/Remove/GetAll)
- [x] UCPD-Erkennung und -Verwaltung
- [x] Find-ProgIdForExtension Hilfsfunktion
- [x] Get-RegisteredApplications Hilfsfunktion
- [x] Modul-Manifest erstellen
- [x] CLAUDE.md Dokumentation
- [x] README.md erstellen
- [x] C# SetFTA.exe Tool erstellen (UCPD-Bypass-Versuch)
  - Hash-Algorithmus in C# portiert
  - Win32 API Registry-Zugriff implementiert
  - Getestet: Funktioniert für nicht-geschützte Extensions
  - Ergebnis: UCPD blockiert auch eigene .exe auf Kernel-Ebene

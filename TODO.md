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

# TODO

## Nächster Meilenstein: C# SetFTA.exe Integration

### Phase 2: C# SetFTA.exe Integration

#### 2.1 Neue Klasse `ReginiHelper`
- [ ] Methode `DeleteAndSetUserChoice(extension, progId, hash)`
- [ ] Temp-INI-Dateien generieren (DELETE + SET)
- [ ] `Process.Start("regini.exe", iniFile)` aufrufen
- [ ] Exit-Code prüfen
- [ ] Cleanup

#### 2.2 Auto-Erkennung in Program.cs
- [ ] UCPD-Liste prüfen vor Registry-Zugriff
- [ ] Regini versuchen, bei Fehler Fallback
- [ ] Konsolen-Output für Feedback

### PSScriptAnalyzer Findings (2026-01-21)

#### Gefixt
- [x] `$deleteResult` in `Set-UserChoiceViaRegini` - `$null = ...` verwendet
- [x] `-Force` Parameter in `Set-FTA` - entfernt (regini bypass ist automatisch)
- [x] `-Force` Parameter in `Set-PTA` - entfernt (regini bypass ist automatisch)

#### False Positives (kein Fix nötig)
- `-LogPath` in `Disable-UCPDSafely` / `Enable-UCPDSafely`
  - Wird in innerer `Write-Log` Funktion verwendet
  - PSScriptAnalyzer erkennt verschachtelte Scopes nicht

#### Bewusst ignoriert (Design-Entscheidung)
- PSUseSingularNouns bei `Get-RegisteredApplications`, `*-DefaultAssociations`, `Open-DefaultAppsSettings`
  - Begründung: Namen sind etabliert, Plural ist hier semantisch korrekt
- PSUseShouldProcessForStateChangingFunctions bei internen Funktionen
  - Begründung: Interne Funktionen, ShouldProcess auf öffentlicher Ebene (Set-FTA/Set-PTA)

### Ausstehende Tests

- [ ] Pester-Tests für `Set-UserChoiceViaRegini`
- [ ] Pester-Tests für `Test-IsUCPDProtected`
- [ ] Manueller Test: `.pdf` mit aktivem UCPD (als Admin)
- [ ] Manueller Test: Neustart-Persistenz
- [ ] SetFTA.exe als Admin testen mit `.pdf`
- [ ] Nach Konsolenneustart: `dotnet` im PATH prüfen (dann kein voller Pfad mehr nötig)

---

## Design-Entscheidungen (GEKLÄRT)

1. **Auto-Erkennung**: ✅ JA
   - Bei UCPD-geschützten Extensions (`.pdf`, `.htm`, `.html`, `http`, `https`) automatisch Regini-Methode verwenden
   - Kein extra Parameter nötig - "es funktioniert einfach"

2. **Fehlerbehandlung**: ✅ Fallback mit Meldung
   - Wenn Regini fehlschlägt (z.B. keine Admin-Rechte): Fallback auf Registry-Methode
   - `Write-Warning` mit Hinweis was passiert ist
   - Beispiel: "WARNUNG: regini.exe fehlgeschlagen (keine Admin-Rechte?), verwende Standard-Methode..."

3. **Meldungen bei Regini-Nutzung**:
   - `Write-Verbose`: "Verwende regini.exe für UCPD-geschützte Extension .pdf"
   - Bei Erfolg: Keine extra Meldung (oder nur Verbose)
   - Bei Fallback: `Write-Warning` mit Erklärung

---

## Später / Backlog

- [ ] PowerShell Gallery Veröffentlichung vorbereiten
- [ ] CI/CD Pipeline einrichten (GitHub Actions)
- [ ] Beispiel-Skripte für häufige Anwendungsfälle erstellen

## Ideen

- [ ] GUI-Wrapper für einfache Bedienung
- [ ] Batch-Import von Zuordnungen aus CSV/JSON
- [ ] Backup/Restore von Zuordnungen
- [ ] Unterstützung für maschinenweite Zuordnungen (HKLM)
- [ ] Unterstützung für andere Benutzer (regini mit deren SID)

## Erledigt

- [x] **v1.2.0 - regini.exe Bypass in Hauptmodul integriert** (Januar 2026)
  - [x] `Set-UserChoiceViaRegini` interne Funktion erstellt
  - [x] `Test-IsUCPDProtected` Hilfsfunktion erstellt
  - [x] `Set-FTA` erweitert mit Auto-Erkennung und Fallback
  - [x] `Set-PTA` erweitert mit Auto-Erkennung und Fallback
  - [x] Lokalisierte Meldungen (DE/EN) hinzugefügt
  - [x] Modul-Manifest aktualisiert (v1.2.0)
  - [x] CHANGELOG.md aktualisiert
  - [x] README.md aktualisiert

- [x] **UCPD-Bypass mit regini.exe entdeckt und implementiert** (Januar 2026)
  - [x] Procmon-Analyse von PDF-XChange Editor
  - [x] Undokumentierte `[DELETE]` Syntax entdeckt
  - [x] `Set-FTA-Regini.ps1` Tool erstellt
  - [x] Getestet: Funktioniert für `.pdf`, `.htm`, `.html`
  - [x] Getestet: Überlebt Neustarts!
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

# ACL-Tools fuer UserChoice Forschung

Diese Tools dienen der Analyse und Manipulation von ACLs auf UserChoice Registry-Keys.

## HAUPTTOOL: Set-FTA-Regini.ps1

**Funktionierender Bypass fuer UCPD und DENY-ACL!**

```powershell
# Als Administrator ausfuehren:
.\Set-FTA-Regini.ps1 -Extension ".pdf" -ProgId "ChromePDF"
.\Set-FTA-Regini.ps1 -Extension ".pdf" -ProgId "PDFXEdit.PDF"
.\Set-FTA-Regini.ps1 -Extension ".htm" -ProgId "ChromeHTML"

# Erst testen mit -WhatIf:
.\Set-FTA-Regini.ps1 -Extension ".pdf" -ProgId "ChromePDF" -WhatIf
```

Basiert auf Reverse-Engineering von PDF-XChange Editor (siehe DENY-ACL-Research.md).

## Analyse-Scripts

| Script | Beschreibung |
|--------|--------------|
| `check-acl.ps1` | Zeigt ACL-Eintraege (einfach) |
| `check-acl-detailed.ps1` | Zeigt ACL mit allen Details (Rights, Inherited) |
| `check-acl-admin.ps1` | ACL-Check mit TakeOwnership-Versuch |
| `save-acl-sddl.ps1` | Speichert ACL als SDDL in Datei |
| `remove-deny-acl.ps1` | Entfernt DENY-Regeln (alter Ansatz, nicht empfohlen) |
| `fix-userchoice.ps1` | Versuch mit Scheduled Task als SYSTEM |

## Gefangene PDFXChange INI-Dateien

| Datei | Beschreibung |
|-------|--------------|
| `pdfxchange-DELETE.ini` | Original DELETE-Syntax von PDFXChange |
| `pdfxchange-SET.ini` | Original SET-Syntax von PDFXChange |

### regini.exe Syntax (entdeckt durch Reverse-Engineering)

**DELETE** (Key loeschen):
```ini
\Registry\User\<SID>\...\UserChoice [DELETE]
```

**SET** (Werte schreiben):
```ini
\Registry\User\<SID>\...\UserChoice
ProgId="<PROGID>"
Hash="<HASH>"
0
```

## Backup-Dateien

| Datei | Beschreibung |
|-------|--------------|
| `backup-pdf-userchoice.reg` | Registry-Export von .pdf (fuer Wiederherstellung) |
| `userchoice-acl-sddl.txt` | ACL als SDDL (fuer Referenz) |

## Procmon-Captures

Aufnahmen mit Process Monitor zur Analyse, was SetUserFTA und PDFXChange bei Dateizuordnungen machen.

| Datei | Beschreibung |
|-------|--------------|
| `procmon-setuserfta-del-pdf.csv` | SetUserFTA `del .pdf` - Rueckgaengig nach PDFXChange |
| `procmon-pdfxchange-2.csv` | PDFXChange Editor - zweiter Aufruf |
| `procmon-pdfxchange-1-admin.csv` | PDFXChange Editor - erster Aufruf mit Admin-Bestaetigung (57 MB!) |
| `procmon-setuserfta-set-1-broken.csv` | SetUserFTA `set` - Capture unvollstaendig |
| `procmon-setuserfta-set-2-broken.csv` | SetUserFTA `set` - Capture unvollstaendig |

**Hinweis:** Die pdfxchange-1 und pdfxchange-2 Logs gehoeren zusammen (erneuter Aufruf mit Admin-Bestaetigung).

## WARNUNG

| Datei | Beschreibung |
|-------|--------------|
| `regini-NICHT-VERWENDEN.ini` | **GEFAEHRLICH!** Hat Profil zerstoert. Nur zur Dokumentation. |

## Verwendung

### ACL pruefen
```powershell
.\check-acl-detailed.ps1
```

### DENY-ACL entfernen (vorsichtig!)

1. Erst im WhatIf-Modus testen:
```powershell
.\remove-deny-acl.ps1 -WhatIf
```

2. Dann mit Bestaetigung ausfuehren:
```powershell
.\remove-deny-acl.ps1
```

3. Oder ohne Bestaetigung (nur wenn du weisst was du tust!):
```powershell
.\remove-deny-acl.ps1 -Force
```

### Bei Problemen - Backup wiederherstellen
```cmd
reg import backup-pdf-userchoice.reg
```

## Siehe auch

- `../DENY-ACL-Research.md` - Ausfuehrliche Dokumentation der Forschung

# Design-Prinzipien für FTA-Manager

## Leitprinzipien

### 1. Vollständigkeit vor Kürze (Default = Alles zeigen)

**Grundregel**: Zeige standardmäßig ALLE Informationen. Kürzungen nur auf explizite Anfrage.

```powershell
# ❌ FALSCH - Automatisches Kürzen
function Get-FTA {
    # Zeigt nur erste 10 Einträge
    return $results | Select-Object -First 10
}

# ✅ RICHTIG - Default = vollständig
function Get-FTA {
    param([int]$Limit = 0)
    if ($Limit -gt 0) {
        return $results | Select-Object -First $Limit
    }
    return $results
}
```

**Warum?**
- Informationsverlust vermeiden (kritisch für Debugging)
- Principle of Least Surprise (User erwartet zu sehen, was er schreibt)
- Sichere Defaults (keine versteckten Datenverluste)

### 2. Opt-in statt Opt-out für Einschränkungen

**Regel**: Wer Einschränkungen will, muss sie EXPLIZIT aktivieren.

```powershell
# ❌ FALSCH - Opt-out
Set-FTA "ProgId" ".ext" -ShowFullOutput

# ✅ RICHTIG - Opt-in
Set-FTA "ProgId" ".ext" -Quiet
```

### 3. Transparenz bei Modifikationen

**Regel**: Wenn Daten gekürzt/gefiltert/transformiert werden, MUSS das sichtbar sein.

```powershell
# ❌ FALSCH - Versteckte Kürzung
Write-Host "Setze .pdf -> Chrome..."  # Was fehlt?

# ✅ RICHTIG - Transparente Information
Write-Verbose "Verwende regini.exe für UCPD-geschützte Extension .pdf"
Write-Warning "regini.exe fehlgeschlagen, verwende Standard-Methode..."
```

### 4. Explizit vor Implizit

**Regel**: Keine versteckten Defaults, die Daten verändern.

```powershell
# ❌ FALSCH - Implizite Transformation
function Set-FTA($progId, $ext) {
    # Macht automatisch lowercase ohne es zu sagen
    $ext = $ext.ToLower()
}

# ✅ RICHTIG - Explizite Kontrolle oder dokumentiertes Verhalten
function Set-FTA($progId, $ext) {
    # Extension wird normalisiert (dokumentiert im Help)
    if (-not $ext.StartsWith(".")) {
        $ext = ".$ext"
    }
}
```

### 5. Sichere Defaults

**Regel**: Default-Verhalten sollte keine Datenverluste oder unerwartete Einschränkungen haben.

**Sichere Defaults in FTA-Manager:**
- ✅ Vollständige Rückgabe-Objekte (Extension, ProgId, Hash, Success, Method)
- ✅ Verbose-Output für wichtige Operationen
- ✅ Automatischer Fallback mit Warning bei Fehlern
- ✅ Verifikation nach Set-Operationen

**Vermiedene unsichere Defaults:**
- ❌ Keine automatische Ausgabe-Kürzung
- ❌ Keine versteckten Fehler (immer Exception oder Warning)
- ❌ Keine automatische Löschung von Daten

## Projekt-spezifische Entscheidungen

### Auto-Erkennung für UCPD-Bypass

**Entscheidung**: Automatisch die regini.exe-Methode für UCPD-geschützte Extensions verwenden.

```powershell
# ❌ FALSCH - User muss Method wählen
Set-FTA "ChromePDF" ".pdf" -Method Regini

# ✅ RICHTIG - Automatische Erkennung
Set-FTA "ChromePDF" ".pdf"
# → Erkennt .pdf als UCPD-geschützt
# → Versucht automatisch regini.exe
# → Fallback auf Registry-Methode mit Warning
```

**Warum?**
- Benutzerfreundlich: "Es funktioniert einfach"
- Transparent: Verbose zeigt was passiert
- Sicher: Fallback verhindert komplettes Scheitern

### Fallback mit Meldung

**Entscheidung**: Bei Fehlern Fallback versuchen, aber immer informieren.

```powershell
# Ablauf bei UCPD-geschützter Extension:
# 1. Write-Verbose "Verwende regini.exe für UCPD-geschützte Extension .pdf"
# 2. Versuche regini.exe
# 3. Bei Erfolg: Return mit Method = 'Regini'
# 4. Bei Fehler: Write-Warning "regini.exe fehlgeschlagen, verwende Standard-Methode..."
# 5. Versuche Registry-Methode
# 6. Return mit Method = 'Registry'
```

**Warum?**
- User wird nicht im Dunkeln gelassen
- Debugging möglich (Verbose zeigt alles)
- Graceful Degradation (versucht alles bevor es aufgibt)

### Rückgabe-Objekte statt nur True/False

**Entscheidung**: Immer vollständige Objekte zurückgeben.

```powershell
# ❌ FALSCH - Nur Erfolg/Misserfolg
Set-FTA "ProgId" ".ext"  # Returns: $true

# ✅ RICHTIG - Vollständiges Objekt
Set-FTA "ProgId" ".ext"
# Returns:
# @{
#     Extension = ".ext"
#     ProgId    = "ProgId"
#     Hash      = "abc123="
#     Success   = $true
#     Method    = "Regini"
# }
```

**Warum?**
- Vollständige Information für Debugging
- Pipe-freundlich für Weiterverarbeitung
- Method zeigt welche Technik verwendet wurde

### Lokalisierung: Deutsch + Englisch

**Entscheidung**: Alle Meldungen zweisprachig.

```powershell
$script:Messages = @{
    'de' = @{
        ReginiSuccess = "Verwende regini.exe für UCPD-geschützte Extension {0}"
        ReginiFallback = "regini.exe fehlgeschlagen, verwende Standard-Methode..."
    }
    'en' = @{
        ReginiSuccess = "Using regini.exe for UCPD-protected extension {0}"
        ReginiFallback = "regini.exe failed, falling back to standard method..."
    }
}
```

**Warum?**
- Deutschsprachige Benutzer als Hauptzielgruppe
- Internationale Verwendbarkeit
- Konsistente Erfahrung

## Test-Kriterium

**Frage**: "Wird ein Entwickler überrascht sein?"

- Wenn JA → Design ändern
- Wenn NEIN → Design ist gut

**Beispiele:**
- "Set-FTA gibt nur true zurück" → Überraschend! → Vollständiges Objekt zurückgeben
- "Set-FTA versucht automatisch regini bei .pdf" → Nicht überraschend wenn dokumentiert → OK
- "Set-FTA schlägt still fehl" → Überraschend! → Immer Error/Warning

## Merksatz

> **"Der Default ist die Wahrheit, Einschränkungen sind explizit."**

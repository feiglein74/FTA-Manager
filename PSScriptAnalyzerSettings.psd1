@{
    # PSScriptAnalyzer-Konfiguration fuer FTA-Manager
    #
    # Aufruf (wie in CLAUDE.md): Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
    #
    # Nur Error und Warning sind "gate"-relevant. Information-Regeln (z.B.
    # PSUseOutputTypeCorrectly) sind rein beratend und blockieren keinen Commit.
    Severity = @('Error', 'Warning')

    # Projektweite, bewusste Design-Entscheidungen. Lokale Ausnahmen (einzelne
    # Funktionen) stehen als [SuppressMessageAttribute] direkt im Code.
    ExcludeRules = @(
        # Interaktive Installations- und Diagnose-Skripte (tools/, Install-*, check-acl*)
        # schreiben bewusst auf die Host-Konsole. Das ist hier die gewuenschte UX,
        # kein Pipeline-Output.
        'PSAvoidUsingWriteHost'

        # Oeffentliche API-Namen wie Get-AllFTA, Get-AllPTA und *-DefaultAssociations
        # sind Teil der stabilen Schnittstelle (Logon-Scripts). Ein Umbenennen auf
        # Singular waere ein Breaking Change.
        'PSUseSingularNouns'
    )
}

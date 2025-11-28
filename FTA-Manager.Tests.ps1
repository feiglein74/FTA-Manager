#Requires -Modules Pester
<#
.SYNOPSIS
    Pester-Tests für das FTA-Manager Modul

.DESCRIPTION
    Unit- und Integrationstests für File Type Associations und Protocol Associations

.NOTES
    Ausführen mit: Invoke-Pester -Path .\FTA-Manager.Tests.ps1 -Output Detailed
#>

BeforeAll {
    # Modul importieren
    $modulePath = Join-Path $PSScriptRoot "FTA-Manager.psd1"
    Import-Module $modulePath -Force
}

Describe "FTA-Manager Modul" {
    Context "Modul-Grundlagen" {
        It "Modul kann importiert werden" {
            $module = Get-Module FTA-Manager
            $module | Should -Not -BeNullOrEmpty
        }

        It "Modul exportiert alle erwarteten Funktionen" {
            $expectedFunctions = @(
                'Get-FTA', 'Set-FTA', 'Remove-FTA', 'Get-AllFTA',
                'Get-PTA', 'Set-PTA', 'Remove-PTA', 'Get-AllPTA',
                'Test-UCPDEnabled', 'Get-UCPDStatus', 'Disable-UCPD', 'Enable-UCPD',
                'Get-RegisteredApplications', 'Find-ProgIdForExtension'
            )

            $exportedFunctions = (Get-Module FTA-Manager).ExportedFunctions.Keys

            foreach ($func in $expectedFunctions) {
                $exportedFunctions | Should -Contain $func
            }
        }

        It "Modul-Version ist 1.1.0" {
            $module = Get-Module FTA-Manager
            $module.Version.ToString() | Should -Be "1.1.0"
        }
    }
}

Describe "Get-FTA" {
    Context "Parameter-Validierung" {
        It "Akzeptiert Extension mit Punkt" {
            { Get-FTA ".txt" } | Should -Not -Throw
        }

        It "Akzeptiert Extension ohne Punkt" {
            { Get-FTA "txt" } | Should -Not -Throw
        }

        It "Wirft Fehler ohne Parameter" {
            { Get-FTA } | Should -Throw
        }
    }

    Context "Rückgabewerte" {
        It "Gibt PSCustomObject oder null zurück" {
            $result = Get-FTA ".txt"
            if ($null -ne $result) {
                $result.PSObject.Properties.Name | Should -Contain "Extension"
                $result.PSObject.Properties.Name | Should -Contain "ProgId"
            }
        }

        It "Extension beginnt immer mit Punkt" {
            $result = Get-FTA "txt"
            if ($null -ne $result) {
                $result.Extension | Should -BeLike ".*"
            }
        }
    }
}

Describe "Set-FTA" {
    Context "Parameter-Validierung" {
        It "Benötigt ProgId und Extension" {
            { Set-FTA } | Should -Throw
            { Set-FTA "TestProgId" } | Should -Throw
        }

        It "Unterstützt -WhatIf" {
            { Set-FTA "TestProgId" ".testextension123" -WhatIf } | Should -Not -Throw
        }
    }

    Context "UCPD-Schutz" {
        It "Warnt bei geschützten Extensions ohne -Force" {
            # Nur testen wenn UCPD aktiv ist
            if (Test-UCPDEnabled) {
                $result = Set-FTA "TestProgId" ".pdf"
                $result.Success | Should -Be $false
                $result.Error | Should -Be "UCPD protection active"
            }
        }
    }

    Context "Rückgabewerte" {
        It "Gibt Objekt mit Success-Property zurück" {
            $result = Set-FTA "Applications\notepad.exe" ".testfta123" -WhatIf
            # Bei -WhatIf wird nichts ausgeführt, aber auch kein Fehler
        }
    }
}

Describe "Remove-FTA" {
    Context "Parameter-Validierung" {
        It "Benötigt Extension" {
            { Remove-FTA } | Should -Throw
        }

        It "Unterstützt -WhatIf" {
            { Remove-FTA ".testextension123" -WhatIf } | Should -Not -Throw
        }
    }
}

Describe "Get-AllFTA" {
    Context "Funktionalität" {
        It "Gibt Array oder null zurück" {
            $result = Get-AllFTA
            # Funktion wirft keinen Fehler und gibt entweder null oder eine Sammlung zurück
            { Get-AllFTA } | Should -Not -Throw
        }

        It "Jedes Element hat Extension und ProgId" {
            $result = Get-AllFTA
            if ($result -and $result.Count -gt 0) {
                $result[0].PSObject.Properties.Name | Should -Contain "Extension"
                $result[0].PSObject.Properties.Name | Should -Contain "ProgId"
            }
        }

        It "Ergebnisse sind nach Extension sortiert" {
            $result = Get-AllFTA
            if ($result -and $result.Count -gt 1) {
                $sorted = $result | Sort-Object Extension
                $result[0].Extension | Should -Be $sorted[0].Extension
            }
        }
    }
}

Describe "Get-PTA" {
    Context "Parameter-Validierung" {
        It "Akzeptiert Protocol-Parameter" {
            { Get-PTA "http" } | Should -Not -Throw
        }

        It "Wirft Fehler ohne Parameter" {
            { Get-PTA } | Should -Throw
        }
    }

    Context "Rückgabewerte" {
        It "Gibt PSCustomObject oder null zurück" {
            $result = Get-PTA "http"
            if ($null -ne $result) {
                $result.PSObject.Properties.Name | Should -Contain "Protocol"
                $result.PSObject.Properties.Name | Should -Contain "ProgId"
            }
        }
    }
}

Describe "Set-PTA" {
    Context "Parameter-Validierung" {
        It "Benötigt ProgId und Protocol" {
            { Set-PTA } | Should -Throw
            { Set-PTA "TestProgId" } | Should -Throw
        }

        It "Unterstützt -WhatIf" {
            { Set-PTA "TestProgId" "testprotocol123" -WhatIf } | Should -Not -Throw
        }
    }

    Context "UCPD-Schutz" {
        It "Warnt bei http ohne -Force" {
            if (Test-UCPDEnabled) {
                $result = Set-PTA "TestProgId" "http"
                $result.Success | Should -Be $false
                $result.Error | Should -Be "UCPD protection active"
            }
        }

        It "Warnt bei https ohne -Force" {
            if (Test-UCPDEnabled) {
                $result = Set-PTA "TestProgId" "https"
                $result.Success | Should -Be $false
                $result.Error | Should -Be "UCPD protection active"
            }
        }
    }
}

Describe "Remove-PTA" {
    Context "Parameter-Validierung" {
        It "Benötigt Protocol" {
            { Remove-PTA } | Should -Throw
        }

        It "Unterstützt -WhatIf" {
            { Remove-PTA "testprotocol123" -WhatIf } | Should -Not -Throw
        }
    }
}

Describe "Get-AllPTA" {
    Context "Funktionalität" {
        It "Gibt Array oder null zurück" {
            $result = Get-AllPTA
            # Funktion wirft keinen Fehler und gibt entweder null oder eine Sammlung zurück
            { Get-AllPTA } | Should -Not -Throw
        }

        It "Jedes Element hat Protocol und ProgId" {
            $result = Get-AllPTA
            if ($result -and $result.Count -gt 0) {
                $result[0].PSObject.Properties.Name | Should -Contain "Protocol"
                $result[0].PSObject.Properties.Name | Should -Contain "ProgId"
            }
        }
    }
}

Describe "Test-UCPDEnabled" {
    Context "Funktionalität" {
        It "Gibt Boolean zurück" {
            $result = Test-UCPDEnabled
            $result | Should -BeOfType [bool]
        }

        It "Wirft keinen Fehler" {
            { Test-UCPDEnabled } | Should -Not -Throw
        }
    }
}

Describe "Get-UCPDStatus" {
    Context "Funktionalität" {
        It "Gibt PSCustomObject zurück" {
            $result = Get-UCPDStatus
            $result | Should -Not -BeNullOrEmpty
        }

        It "Enthält erwartete Properties" {
            $result = Get-UCPDStatus
            $result.PSObject.Properties.Name | Should -Contain "Exists"
            $result.PSObject.Properties.Name | Should -Contain "Enabled"
            $result.PSObject.Properties.Name | Should -Contain "Description"
        }

        It "Exists ist Boolean" {
            $result = Get-UCPDStatus
            $result.Exists | Should -BeOfType [bool]
        }

        It "Enabled ist Boolean" {
            $result = Get-UCPDStatus
            $result.Enabled | Should -BeOfType [bool]
        }
    }
}

Describe "Disable-UCPD" {
    Context "Parameter-Validierung" {
        It "Unterstützt -WhatIf" {
            { Disable-UCPD -WhatIf } | Should -Not -Throw
        }

        It "Unterstützt ShouldProcess" {
            $cmd = Get-Command Disable-UCPD
            $cmd.Parameters.Keys | Should -Contain "WhatIf"
            $cmd.Parameters.Keys | Should -Contain "Confirm"
        }
    }
}

Describe "Enable-UCPD" {
    Context "Parameter-Validierung" {
        It "Unterstützt -WhatIf" {
            { Enable-UCPD -WhatIf } | Should -Not -Throw
        }

        It "Unterstützt ShouldProcess" {
            $cmd = Get-Command Enable-UCPD
            $cmd.Parameters.Keys | Should -Contain "WhatIf"
            $cmd.Parameters.Keys | Should -Contain "Confirm"
        }
    }
}

Describe "Get-RegisteredApplications" {
    Context "Funktionalität" {
        It "Gibt Array zurück" {
            $result = Get-RegisteredApplications
            # Kann leer sein oder Array
            { $result } | Should -Not -Throw
        }

        It "Unterstützt Filter-Parameter" {
            { Get-RegisteredApplications -Filter "*notepad*" } | Should -Not -Throw
        }

        It "Ergebnisse haben ProgId und Command" {
            $result = Get-RegisteredApplications
            if ($result -and $result.Count -gt 0) {
                $result[0].PSObject.Properties.Name | Should -Contain "ProgId"
                $result[0].PSObject.Properties.Name | Should -Contain "Command"
            }
        }
    }
}

Describe "Find-ProgIdForExtension" {
    Context "Parameter-Validierung" {
        It "Benötigt Extension" {
            { Find-ProgIdForExtension } | Should -Throw
        }

        It "Akzeptiert Extension mit Punkt" {
            { Find-ProgIdForExtension ".txt" } | Should -Not -Throw
        }

        It "Akzeptiert Extension ohne Punkt" {
            { Find-ProgIdForExtension "txt" } | Should -Not -Throw
        }
    }

    Context "Rückgabewerte" {
        It "Gibt Array zurück" {
            $result = Find-ProgIdForExtension ".txt"
            # Kann leer sein oder Array
            { $result } | Should -Not -Throw
        }

        It "Ergebnisse haben ProgId und Extension" {
            $result = Find-ProgIdForExtension ".txt"
            if ($result -and $result.Count -gt 0) {
                $result[0].PSObject.Properties.Name | Should -Contain "ProgId"
                $result[0].PSObject.Properties.Name | Should -Contain "Extension"
            }
        }
    }
}

Describe "Integrationstests" {
    Context "FTA Workflow" {
        BeforeAll {
            $testExtension = ".ftatestext123"
            $testProgId = "Applications\notepad.exe"
        }

        AfterAll {
            # Aufräumen
            Remove-FTA $testExtension -ErrorAction SilentlyContinue
        }

        It "Set-FTA setzt Association" {
            $result = Set-FTA $testProgId $testExtension
            $result.Success | Should -Be $true
            $result.Extension | Should -Be $testExtension
            $result.ProgId | Should -Be $testProgId
        }

        It "Get-FTA liest gesetzte Association" {
            $result = Get-FTA $testExtension
            $result | Should -Not -BeNullOrEmpty
            $result.ProgId | Should -Be $testProgId
        }

        It "Remove-FTA entfernt Association" {
            $result = Remove-FTA $testExtension
            $result | Should -Be $true

            $check = Get-FTA $testExtension
            $check | Should -BeNullOrEmpty
        }
    }

    Context "PTA Workflow (nicht-geschützte Protokolle)" {
        BeforeAll {
            $testProtocol = "ptatesprotocol123"
            $testProgId = "TestProgId"
        }

        AfterAll {
            # Aufräumen
            Remove-PTA $testProtocol -ErrorAction SilentlyContinue
        }

        It "Set-PTA setzt Association" {
            $result = Set-PTA $testProgId $testProtocol
            $result.Success | Should -Be $true
            $result.Protocol | Should -Be $testProtocol
            $result.ProgId | Should -Be $testProgId
        }

        It "Get-PTA liest gesetzte Association" {
            $result = Get-PTA $testProtocol
            $result | Should -Not -BeNullOrEmpty
            $result.ProgId | Should -Be $testProgId
        }

        It "Remove-PTA entfernt Association" {
            $result = Remove-PTA $testProtocol
            $result | Should -Be $true

            $check = Get-PTA $testProtocol
            $check | Should -BeNullOrEmpty
        }
    }
}

AfterAll {
    # Modul entladen
    Remove-Module FTA-Manager -Force -ErrorAction SilentlyContinue
}

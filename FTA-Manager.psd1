@{
    # Module manifest for FTA-Manager

    # Script module or binary module file associated with this manifest
    RootModule        = 'FTA-Manager.psm1'

    # Version number of this module
    ModuleVersion     = '1.1.0'

    # ID used to uniquely identify this module
    GUID              = 'f8a7c3e1-5b2d-4a6f-9c8e-1d3b5a7f9e2c'

    # Author of this module
    Author            = 'FTA-Manager Project'

    # Company or vendor of this module
    CompanyName       = ''

    # Copyright statement for this module
    Copyright         = '(c) 2024. MIT License.'

    # Description of the functionality provided by this module
    Description       = 'Manage Windows File Type Associations (FTA) and Protocol Associations (PTA) by computing the correct UserChoice hash. Supports Windows 10/11 including UCPD protection detection.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        # File Type Associations
        'Get-FTA',
        'Set-FTA',
        'Remove-FTA',
        'Get-AllFTA',
        # Protocol Associations
        'Get-PTA',
        'Set-PTA',
        'Remove-PTA',
        'Get-AllPTA',
        # UCPD Management
        'Test-UCPDEnabled',
        'Get-UCPDStatus',
        'Disable-UCPD',
        'Enable-UCPD',
        # UCPD Scheduled Task Management
        'Get-UCPDScheduledTask',
        'Disable-UCPDScheduledTask',
        'Enable-UCPDScheduledTask',
        # Enterprise UCPD Safe Management
        'Disable-UCPDSafely',
        'Enable-UCPDSafely',
        # Enterprise Deployment (DISM)
        'Export-DefaultAssociations',
        'Import-DefaultAssociations',
        'Remove-DefaultAssociations',
        # Utility & Detection
        'Get-RegisteredApplications',
        'Find-ProgIdForExtension',
        'Test-IsWindowsServer',
        'Open-DefaultAppsSettings',
        'Get-EDRStatus'
    )

    # Cmdlets to export from this module
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport   = @()

    # Private data to pass to the module specified in RootModule
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module
            Tags         = @('FileTypeAssociation', 'FTA', 'ProtocolAssociation', 'Windows', 'Registry', 'UserChoice')

            # A URL to the license for this module
            LicenseUri   = ''

            # A URL to the main website for this project
            ProjectUri   = ''

            # Release notes for this module
            ReleaseNotes = @'
v1.1.0 - Enterprise Features & UCPD Safe Management
- NEW: Test-IsWindowsServer - Detect Windows Server (no UCPD)
- NEW: Get-UCPDScheduledTask / Disable-UCPDScheduledTask / Enable-UCPDScheduledTask
- NEW: Open-DefaultAppsSettings - Open Windows Settings for manual change
- NEW: Get-EDRStatus - Detect installed EDR/XDR solutions
- NEW: Disable-UCPDSafely / Enable-UCPDSafely - Enterprise UCPD management with EDR check and logging
- NEW: Export-DefaultAssociations / Import-DefaultAssociations / Remove-DefaultAssociations - DISM deployment
- FIXED: Set-FTA/Set-PTA now correctly report failure when UCPD blocks changes
- Enhanced error messages with UCPD detection and recommendations

v1.0.0 - Initial release
- Set/Get/Remove File Type Associations (FTA)
- Set/Get/Remove Protocol Associations (PTA)
- UCPD (User Choice Protection Driver) detection and management
- Find ProgIds for extensions
- List all registered applications
'@
        }
    }
}

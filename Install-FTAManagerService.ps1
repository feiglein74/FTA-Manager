#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the FTA-Manager-Service Scheduled Task

.DESCRIPTION
    This script installs the FTA-Manager-Service which processes FTA change requests
    from user registry queues. It:
    1. Creates the installation directory (C:\Program Files\FTA-Manager)
    2. Copies FTA-Manager-Service.ps1 to the installation directory
    3. Registers the EventLog source
    4. Creates a Scheduled Task that runs at user logon with SYSTEM privileges

.PARAMETER InstallPath
    Installation directory. Default: C:\Program Files\FTA-Manager

.PARAMETER Uninstall
    Remove the service (delete task, keep files)

.PARAMETER Force
    Overwrite existing installation without prompting

.EXAMPLE
    # Install with default settings
    .\Install-FTAManagerService.ps1

.EXAMPLE
    # Uninstall
    .\Install-FTAManagerService.ps1 -Uninstall

.EXAMPLE
    # Force reinstall
    .\Install-FTAManagerService.ps1 -Force

.NOTES
    Author: FTA-Manager Project
    License: MIT
    Requires: Administrator privileges
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [string]$InstallPath = 'C:\Program Files\FTA-Manager',

    [Parameter(ParameterSetName = 'Uninstall')]
    [switch]$Uninstall,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$Force
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$script:Config = @{
    TaskName         = 'FTA-Manager-Service'
    TaskPath         = '\FTA-Manager\'
    TaskDescription  = 'Processes File Type Association change requests from user registry queues'
    EventLogSource   = 'FTA-Manager'
    EventLogName     = 'Application'
    ServiceScript    = 'FTA-Manager-Service.ps1'
    LogonDelay       = 'PT30S'  # 30 seconds delay after logon
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Status {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )

    $prefix = switch ($Type) {
        'Info'    { '[*]' }
        'Success' { '[+]' }
        'Warning' { '[!]' }
        'Error'   { '[-]' }
    }

    $color = switch ($Type) {
        'Info'    { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }

    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Test-TaskExists {
    param([string]$TaskName, [string]$TaskPath)

    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    return ($null -ne $task)
}

# ============================================================================
# UNINSTALL
# ============================================================================

function Uninstall-FTAManagerService {
    Write-Status "Uninstalling FTA-Manager-Service..." -Type Info

    # Remove Scheduled Task
    if (Test-TaskExists -TaskName $script:Config.TaskName -TaskPath $script:Config.TaskPath) {
        if ($PSCmdlet.ShouldProcess($script:Config.TaskName, "Remove Scheduled Task")) {
            try {
                Unregister-ScheduledTask -TaskName $script:Config.TaskName `
                                         -TaskPath $script:Config.TaskPath `
                                         -Confirm:$false
                Write-Status "Scheduled Task removed" -Type Success
            }
            catch {
                Write-Status "Failed to remove Scheduled Task: $($_.Exception.Message)" -Type Error
                return $false
            }
        }
    }
    else {
        Write-Status "Scheduled Task not found (already removed?)" -Type Warning
    }

    # Note: We don't remove files or EventLog source - admin may want to keep logs
    Write-Status "Uninstall complete. Files in '$InstallPath' were kept." -Type Info
    Write-Status "To fully remove, delete: $InstallPath" -Type Info

    return $true
}

# ============================================================================
# INSTALL
# ============================================================================

function Install-FTAManagerService {
    Write-Status "Installing FTA-Manager-Service..." -Type Info

    # Locate source script
    $sourceScript = Join-Path $PSScriptRoot $script:Config.ServiceScript
    if (-not (Test-Path $sourceScript)) {
        Write-Status "Source script not found: $sourceScript" -Type Error
        return $false
    }

    # Check existing installation
    $targetScript = Join-Path $InstallPath $script:Config.ServiceScript
    $taskExists = Test-TaskExists -TaskName $script:Config.TaskName -TaskPath $script:Config.TaskPath

    if ((Test-Path $targetScript) -or $taskExists) {
        if (-not $Force) {
            Write-Status "FTA-Manager-Service is already installed. Use -Force to reinstall." -Type Warning
            return $false
        }
        Write-Status "Existing installation found, reinstalling..." -Type Warning

        # Remove existing task
        if ($taskExists) {
            Unregister-ScheduledTask -TaskName $script:Config.TaskName `
                                     -TaskPath $script:Config.TaskPath `
                                     -Confirm:$false -ErrorAction SilentlyContinue
        }
    }

    # Step 1: Create installation directory
    if (-not (Test-Path $InstallPath)) {
        if ($PSCmdlet.ShouldProcess($InstallPath, "Create Directory")) {
            try {
                New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
                Write-Status "Created directory: $InstallPath" -Type Success
            }
            catch {
                Write-Status "Failed to create directory: $($_.Exception.Message)" -Type Error
                return $false
            }
        }
    }

    # Step 2: Copy service script
    if ($PSCmdlet.ShouldProcess($targetScript, "Copy Service Script")) {
        try {
            Copy-Item -Path $sourceScript -Destination $targetScript -Force
            Write-Status "Copied service script to: $targetScript" -Type Success
        }
        catch {
            Write-Status "Failed to copy script: $($_.Exception.Message)" -Type Error
            return $false
        }
    }

    # Step 3: Register EventLog source
    if ($PSCmdlet.ShouldProcess($script:Config.EventLogSource, "Register EventLog Source")) {
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($script:Config.EventLogSource)) {
                [System.Diagnostics.EventLog]::CreateEventSource(
                    $script:Config.EventLogSource,
                    $script:Config.EventLogName
                )
                Write-Status "Registered EventLog source: $($script:Config.EventLogSource)" -Type Success
            }
            else {
                Write-Status "EventLog source already exists" -Type Info
            }
        }
        catch {
            Write-Status "Failed to register EventLog source: $($_.Exception.Message)" -Type Warning
            # Continue anyway - service can still work without EventLog
        }
    }

    # Step 4: Create Scheduled Task
    if ($PSCmdlet.ShouldProcess($script:Config.TaskName, "Create Scheduled Task")) {
        try {
            # Task Action
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
                -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$targetScript`""

            # Task Trigger: At logon of any user, with 30 second delay
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            $trigger.Delay = $script:Config.LogonDelay

            # Task Principal: Run as SYSTEM with highest privileges
            $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
                                                     -LogonType ServiceAccount `
                                                     -RunLevel Highest

            # Task Settings
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                                                      -DontStopIfGoingOnBatteries `
                                                      -StartWhenAvailable `
                                                      -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
                                                      -MultipleInstances IgnoreNew

            # Register the task
            Register-ScheduledTask -TaskName $script:Config.TaskName `
                                   -TaskPath $script:Config.TaskPath `
                                   -Action $action `
                                   -Trigger $trigger `
                                   -Principal $principal `
                                   -Settings $settings `
                                   -Description $script:Config.TaskDescription `
                                   -Force | Out-Null

            Write-Status "Created Scheduled Task: $($script:Config.TaskPath)$($script:Config.TaskName)" -Type Success
        }
        catch {
            Write-Status "Failed to create Scheduled Task: $($_.Exception.Message)" -Type Error
            return $false
        }
    }

    # Success summary
    Write-Host ""
    Write-Status "Installation complete!" -Type Success
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor White
    Write-Host "  Install Path:    $InstallPath"
    Write-Host "  Service Script:  $targetScript"
    Write-Host "  Task Name:       $($script:Config.TaskPath)$($script:Config.TaskName)"
    Write-Host "  Trigger:         At user logon + 30 seconds delay"
    Write-Host "  Run As:          NT AUTHORITY\SYSTEM"
    Write-Host "  EventLog:        Application / $($script:Config.EventLogSource)"
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor White
    Write-Host "  Users can request FTA changes by writing to:"
    Write-Host "    HKCU:\Software\FTA-Manager\Requests\"
    Write-Host ""
    Write-Host "  Example (in Logon Script or GPO):"
    Write-Host '    $path = "HKCU:\Software\FTA-Manager\Requests"'
    Write-Host '    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }'
    Write-Host '    Set-ItemProperty -Path $path -Name ".pdf" -Value "ChromePDF"'
    Write-Host ""
    Write-Host "Testing:" -ForegroundColor White
    Write-Host "  # Run service manually (as Admin):"
    Write-Host "  & `"$targetScript`" -Verbose"
    Write-Host ""
    Write-Host "  # Check EventLog:"
    Write-Host "  Get-EventLog -LogName Application -Source FTA-Manager -Newest 10"
    Write-Host ""

    return $true
}

# ============================================================================
# MAIN
# ============================================================================

if ($Uninstall) {
    $result = Uninstall-FTAManagerService
}
else {
    $result = Install-FTAManagerService
}

exit $(if ($result) { 0 } else { 1 })

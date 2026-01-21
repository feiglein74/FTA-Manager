# ACL als SDDL speichern (fuer Wiederherstellung)
$keyPath = 'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice'
$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
    $keyPath,
    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
    [System.Security.AccessControl.RegistryRights]::ReadPermissions
)
if ($key) {
    $acl = $key.GetAccessControl()
    $sddl = $acl.Sddl
    Write-Host "=== SDDL (Security Descriptor) ===" -ForegroundColor Yellow
    Write-Host $sddl
    Write-Host ""

    # In Datei speichern
    $sddl | Out-File "C:\temp\userchoice-acl-sddl.txt" -Encoding UTF8
    Write-Host "Gespeichert in: C:\temp\userchoice-acl-sddl.txt" -ForegroundColor Green

    $key.Close()
}

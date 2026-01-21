$keyPath = 'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice'
$key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
    $keyPath,
    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
    [System.Security.AccessControl.RegistryRights]::ReadPermissions
)
if ($key) {
    $acl = $key.GetAccessControl()
    Write-Host "=== Detaillierte ACL fuer .pdf UserChoice ===" -ForegroundColor Yellow
    Write-Host ""
    foreach ($ace in $acl.Access) {
        Write-Host "$($ace.IdentityReference)" -ForegroundColor Cyan
        Write-Host "  Type:      $($ace.AccessControlType)"
        Write-Host "  Rights:    $($ace.RegistryRights)"
        Write-Host "  Inherited: $($ace.IsInherited)"
        Write-Host ""
    }
    $key.Close()
} else {
    Write-Host "Key konnte nicht geoeffnet werden" -ForegroundColor Red
}

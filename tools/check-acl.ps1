$keyPath = 'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice'
try {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        $keyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
        [System.Security.AccessControl.RegistryRights]::ReadPermissions
    )
    if ($key) {
        $acl = $key.GetAccessControl()
        Write-Host "=== ACL fuer UserChoice ===" -ForegroundColor Yellow
        $acl.Access | Format-Table IdentityReference, AccessControlType, RegistryRights -AutoSize
        $key.Close()
    } else {
        Write-Host "Key konnte nicht geoeffnet werden"
    }
} catch {
    Write-Host "Fehler: $_"
}

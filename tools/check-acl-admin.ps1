# Als Admin versuchen, die UserChoice ACL zu lesen
$keyPath = 'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice'

Write-Host "=== Versuche UserChoice ACL zu lesen ===" -ForegroundColor Yellow

# Methode 1: Ueber Registry Provider mit TakeOwnership
try {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        $keyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::TakeOwnership -bor [System.Security.AccessControl.RegistryRights]::ReadPermissions
    )
    if ($key) {
        $acl = $key.GetAccessControl()
        Write-Host "`nACL Eintraege:" -ForegroundColor Green
        foreach ($ace in $acl.Access) {
            Write-Host "  $($ace.IdentityReference): $($ace.AccessControlType) - $($ace.RegistryRights)"
        }
        $key.Close()
    } else {
        Write-Host "Key konnte nicht geoeffnet werden"
    }
} catch {
    Write-Host "Fehler: $_" -ForegroundColor Red
}

# Methode 2: Probiere mit reg.exe Berechtigungen
Write-Host "`n=== reg.exe Versuch ===" -ForegroundColor Yellow
$result = & reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice" /z 2>&1
Write-Host $result

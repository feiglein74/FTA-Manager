# Muss als Admin ausgefuehrt werden!
$taskName = "FixUserChoice"

# Task erstellen der als SYSTEM laeuft
$action = New-ScheduledTaskAction -Execute "reg.exe" -Argument 'delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice" /f'
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force
Write-Host "Task erstellt, starte..."

Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3

# Ergebnis pruefen
$result = Get-ScheduledTaskInfo -TaskName $taskName
Write-Host "Task Result: $($result.LastTaskResult)"

# Aufraeumen
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
Write-Host "Task entfernt"

# Pruefen ob Key weg ist
$exists = Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice"
Write-Host "UserChoice existiert noch: $exists"

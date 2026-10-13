[CmdletBinding()]
param(
    [string]$DomainName = 'sp2.lan',
    [string]$DnsServer = '192.168.0.143',
    [string]$DomainController = 'szkolaak.sp2.lan',
    [string]$RecoveryLocalAccount = 'SP2',
    [ValidateRange(5, 1440)]
    [int]$IntervalMinutes = 30
)

$ErrorActionPreference = 'Stop'
$Target = 'C:\Program Files\SP2 Agent\DomainHealer'
$ScriptSource = Join-Path $PSScriptRoot 'SP2-Domain-Healer.ps1'
$ScriptTarget = Join-Path $Target 'SP2-Domain-Healer.ps1'
$TaskName = 'SP2 Domain Healer'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Uruchom PowerShell jako administrator.'
}

if (-not (Test-Path $ScriptSource)) {
    throw "Brak pliku $ScriptSource"
}

New-Item -ItemType Directory -Path $Target -Force | Out-Null
Copy-Item $ScriptSource $ScriptTarget -Force

$arguments = @(
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-File', ('"{0}"' -f $ScriptTarget),
    '-Mode', 'Auto',
    '-DomainName', $DomainName,
    '-DnsServer', $DnsServer,
    '-DomainController', $DomainController,
    '-RecoveryLocalAccount', $RecoveryLocalAccount,
    '-Quiet'
) -join ' '

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$triggerStartup = New-ScheduledTaskTrigger -AtStartup
$triggerRepeat = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$principalTask = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger @($triggerStartup, $triggerRepeat) `
    -Principal $principalTask `
    -Settings $settings `
    -Description 'SP2: automatyczna diagnostyka i bezpieczna naprawa DNS/Netlogon/czasu oraz wykrywanie uszkodzonego secure channel.' | Out-Null

Start-ScheduledTask -TaskName $TaskName

Write-Host 'SP2 Domain Healer został zainstalowany.'
Write-Host "Skrypt: $ScriptTarget"
Write-Host "Zadanie: $TaskName (co $IntervalMinutes min + przy starcie)"
Write-Host 'Raport: C:\ProgramData\SP2-Agent\DomainHealer\last-report.json'
Write-Host 'Log: C:\ProgramData\SP2-Agent\DomainHealer\domain-healer.log'

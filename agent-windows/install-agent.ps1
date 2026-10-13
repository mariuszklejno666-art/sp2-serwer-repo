[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https?://')]
    [string]$ServerUrl,

    [string]$Room = "",

    [ValidateRange(30, 3600)]
    [int]$IntervalSeconds = 60,

    [switch]$DisableTlsVerification
)

$ErrorActionPreference = "Stop"
$Target = "C:\Program Files\SP2 Agent"
$ConfigPath = Join-Path $Target "agent-config.json"
$Python = Join-Path $Target "venv\Scripts\python.exe"
$Script = Join-Path $Target "sp2_agent.py"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Uruchom PowerShell jako administrator."
}

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Nie znaleziono Python Launcher (py.exe). Zainstaluj Python 3.11 lub nowszy."
}

if ($ServerUrl.StartsWith("http://")) {
    Write-Warning "Połączenie HTTP nie szyfruje tokenu. W środowisku produkcyjnym użyj HTTPS."
}

$secureToken = Read-Host "Wklej SP2_API_TOKEN z serwera" -AsSecureString
$token = [System.Net.NetworkCredential]::new("", $secureToken).Password
if ([string]::IsNullOrWhiteSpace($token)) {
    throw "Token nie może być pusty."
}

New-Item -ItemType Directory -Force -Path $Target | Out-Null
Copy-Item (Join-Path $PSScriptRoot "sp2_agent.py") $Target -Force

if (-not (Test-Path $Python)) {
    py -3 -m venv (Join-Path $Target "venv")
}

& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $PSScriptRoot "requirements.txt")

$config = [ordered]@{
    server_url = $ServerUrl.TrimEnd("/")
    token = $token
    room = $Room.Trim()
    interval_seconds = $IntervalSeconds
    verify_tls = -not $DisableTlsVerification.IsPresent
}
$config | ConvertTo-Json -Depth 3 | Set-Content -Path $ConfigPath -Encoding UTF8

# Token może odczytać wyłącznie SYSTEM i lokalni administratorzy.
& icacls.exe $ConfigPath /inheritance:r /grant:r '*S-1-5-18:(R)' '*S-1-5-32-544:(R)' | Out-Null
$token = $null
$secureToken = $null

$existingService = Get-Service -Name "SP2Agent" -ErrorAction SilentlyContinue
if ($existingService) {
    if ($existingService.Status -ne "Stopped") {
        Stop-Service -Name "SP2Agent" -Force
        $existingService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete "SP2Agent" | Out-Null
    Start-Sleep -Seconds 2
}

& $Python $Script --startup auto install
& $Python $Script start

Write-Host "SP2 Agent został zainstalowany i uruchomiony."
Write-Host "Konfiguracja: $ConfigPath"
Write-Host "Log: C:\ProgramData\SP2-Agent\agent.log"

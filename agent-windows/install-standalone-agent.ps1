[CmdletBinding()]
param(
    [ValidatePattern('^$|^https?://')]
    [string]$ServerUrl = "",

    [string]$EnrollmentCode = "",

    [string]$EnrollmentToken = "",

    # Zgodność ze starszym wywołaniem instalatora.
    [string]$ApiToken = "",

    [string]$Room = "",

    [ValidateRange(30, 3600)]
    [int]$IntervalSeconds = 60,

    [string]$AgentExe = "",

    [string]$DeploymentConfig = "",

    [string]$CaCertificate = "",

    [switch]$DisableTlsVerification
)

$ErrorActionPreference = "Stop"
$Target = "C:\Program Files\SP2 Agent"
$ConfigPath = Join-Path $Target "agent-config.json"
$InstalledExe = Join-Path $Target "SP2Agent.exe"
$TaskName = "SP2Agent"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Uruchom PowerShell jako administrator."
}

if (-not $AgentExe) {
    $AgentExe = Join-Path $PSScriptRoot "SP2Agent.exe"
}
if (-not (Test-Path $AgentExe)) {
    throw "Brak SP2Agent.exe: $AgentExe"
}

# Dla wdrożeń masowych instalator automatycznie czyta deployment.json
# znajdujący się obok instalatora. Dzięki temu na stacji nie trzeba nic wpisywać.
if (-not $DeploymentConfig) {
    $candidate = Join-Path $PSScriptRoot "deployment.json"
    if (Test-Path $candidate) {
        $DeploymentConfig = $candidate
    }
}

if ($DeploymentConfig) {
    if (-not (Test-Path $DeploymentConfig)) {
        throw "Nie znaleziono pliku wdrożeniowego: $DeploymentConfig"
    }
    $deployment = Get-Content $DeploymentConfig -Raw | ConvertFrom-Json
    if (-not $ServerUrl -and $deployment.server_url) {
        $ServerUrl = [string]$deployment.server_url
    }
    if (-not $EnrollmentCode -and $deployment.enrollment_code) {
        $EnrollmentCode = [string]$deployment.enrollment_code
    }
    if (-not $EnrollmentToken -and $deployment.enrollment_token) {
        # Okres przejściowy dla starszych paczek. Nowy kreator zapisuje wyłącznie kod jednorazowy.
        $EnrollmentToken = [string]$deployment.enrollment_token
    }
    if (-not $Room -and $deployment.room) {
        $Room = [string]$deployment.room
    }
    if ($deployment.interval_seconds) {
        $IntervalSeconds = [int]$deployment.interval_seconds
    }
    if (-not $CaCertificate -and $deployment.ca_certificate) {
        $CaCertificate = [string]$deployment.ca_certificate
        if (-not [System.IO.Path]::IsPathRooted($CaCertificate)) {
            $CaCertificate = Join-Path (Split-Path -Parent $DeploymentConfig) $CaCertificate
        }
    }
}

if (-not $EnrollmentCode -and $env:SP2_ENROLLMENT_CODE) {
    $EnrollmentCode = $env:SP2_ENROLLMENT_CODE
}
if (-not $EnrollmentToken -and $ApiToken) {
    $EnrollmentToken = $ApiToken
}
if (-not $EnrollmentToken -and $env:SP2_ENROLLMENT_TOKEN) {
    $EnrollmentToken = $env:SP2_ENROLLMENT_TOKEN
}

if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
    throw "Brak ServerUrl. Podaj -ServerUrl albo umieść server_url w deployment.json."
}
$ServerUrl = $ServerUrl.TrimEnd("/")
$uri = $null
if (-not [System.Uri]::TryCreate($ServerUrl, [System.UriKind]::Absolute, [ref]$uri) -or
    $uri.Scheme -notin @("http", "https")) {
    throw "Nieprawidłowy ServerUrl: $ServerUrl"
}

$BootstrapCredential = $EnrollmentCode
if ([string]::IsNullOrWhiteSpace($BootstrapCredential)) {
    $BootstrapCredential = $EnrollmentToken
}
if ([string]::IsNullOrWhiteSpace($BootstrapCredential)) {
    $secureCode = Read-Host "Wklej kod wdrożeniowy z SP2 ADMIN" -AsSecureString
    $BootstrapCredential = [System.Net.NetworkCredential]::new("", $secureCode).Password
}
if ([string]::IsNullOrWhiteSpace($BootstrapCredential)) {
    throw "Kod wdrożeniowy nie może być pusty."
}

if ($ServerUrl.StartsWith("http://")) {
    Write-Warning "Połączenie HTTP nie szyfruje kodu wdrożeniowego. W środowisku produkcyjnym użyj HTTPS."
}

Write-Host "[1/9] Przygotowanie bezpiecznej aktualizacji..."
New-Item -ItemType Directory -Force -Path $Target | Out-Null

$InstalledCa = ""
if ($CaCertificate) {
    if (-not (Test-Path $CaCertificate)) {
        throw "Brak certyfikatu CA: $CaCertificate"
    }
    Write-Host "[2/9] Instalowanie certyfikatu CA SP2..."
    $InstalledCa = Join-Path $Target "sp2-internal-ca.crt"
    Copy-Item $CaCertificate $InstalledCa -Force
    & certutil.exe -f -addstore Root $InstalledCa | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Nie udało się dodać certyfikatu CA do zaufanych głównych urzędów."
    }
}

# Zatrzymaj poprzednią instancję PRZED rotacją tokenu. Dzięki temu stary agent
# nie wysyła heartbeatów z tokenem, który za chwilę zostanie unieważniony.
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
$oldService = Get-Service -Name "SP2Agent" -ErrorAction SilentlyContinue
if ($oldService -and $oldService.Status -ne "Stopped") {
    Stop-Service -Name "SP2Agent" -Force -ErrorAction SilentlyContinue
}

# Starszy instalator celowo pozostawiał konfigurację tylko do odczytu dla
# Administratorów i SYSTEM. Przy aktualizacji musimy tymczasowo przywrócić
# lokalnym Administratorom pełne prawa, zanim serwer wyda nowy token.
if (Test-Path $ConfigPath) {
    & icacls.exe $ConfigPath /grant:r '*S-1-5-32-544:(F)' | Out-Null
}

# Preflight zapisu: jeśli Program Files/ACL blokują aktualizację, zatrzymujemy
# się jeszcze PRZED rejestracją i rotacją indywidualnego tokenu urządzenia.
$probe = Join-Path $Target ".sp2-write-test.tmp"
try {
    [System.IO.File]::WriteAllText($probe, "ok", [System.Text.UTF8Encoding]::new($false))
    Remove-Item $probe -Force
}
catch {
    throw "Brak prawa zapisu do $Target. Nie wykonano rejestracji ani rotacji tokenu. $($_.Exception.Message)"
}

Write-Host "[3/9] Rejestracja komputera w SP2 ADMIN..."
$headers = @{ Authorization = "Bearer $BootstrapCredential" }
$registerPayload = [ordered]@{
    hostname = $env:COMPUTERNAME.ToUpperInvariant()
    room = $Room.Trim()
    os_name = "Windows"
    os_version = [Environment]::OSVersion.VersionString
    agent_version = "standalone-enrollment"
}

# Windows PowerShell 5.1 nie ma -SkipCertificateCheck. Opcja jest przeznaczona
# wyłącznie do krótkich testów w odizolowanej sieci.
$oldCertCallback = $null
if ($DisableTlsVerification.IsPresent -and $ServerUrl.StartsWith("https://")) {
    $oldCertCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}
try {
    $registration = Invoke-RestMethod `
        -Method Post `
        -Uri "$ServerUrl/api/v1/agent/register" `
        -Headers $headers `
        -ContentType "application/json; charset=utf-8" `
        -Body ($registerPayload | ConvertTo-Json -Depth 3) `
        -TimeoutSec 30
}
finally {
    if ($DisableTlsVerification.IsPresent -and $ServerUrl.StartsWith("https://")) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCertCallback
    }
}

$DeviceToken = [string]$registration.token
if ([string]::IsNullOrWhiteSpace($DeviceToken)) {
    throw "Serwer nie zwrócił indywidualnego tokenu urządzenia."
}
Write-Host "Komputer $($registration.hostname) zarejestrowany. Otrzymano indywidualny token urządzenia."

Write-Host "[4/9] Kopiowanie samodzielnego agenta..."
Copy-Item $AgentExe $InstalledExe -Force

Write-Host "[5/9] Zapisywanie konfiguracji UTF-8 bez BOM..."
$config = [ordered]@{
    server_url = $ServerUrl
    token = $DeviceToken
    room = $Room.Trim()
    interval_seconds = $IntervalSeconds
    verify_tls = -not $DisableTlsVerification.IsPresent
    ca_bundle = $InstalledCa
}
$json = $config | ConvertTo-Json -Depth 3
$tempConfig = Join-Path $Target "agent-config.json.new"
[System.IO.File]::WriteAllText(
    $tempConfig,
    $json,
    [System.Text.UTF8Encoding]::new($false)
)
Move-Item -Path $tempConfig -Destination $ConfigPath -Force

# Konfigurację może czytać wyłącznie SYSTEM i lokalni administratorzy.
# Administratorzy dostają odczyt; kolejny reinstall sam tymczasowo podniesie ACL.
& icacls.exe $ConfigPath /inheritance:r /grant:r '*S-1-5-18:(R)' '*S-1-5-32-544:(R)' | Out-Null

Write-Host "[6/9] Usuwanie starej usługi/zadania..."
if ($oldService) {
    & sc.exe delete "SP2Agent" | Out-Null
    Start-Sleep -Seconds 2
}
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "[7/9] Tworzenie automatycznego zadania SYSTEM..."
$action = New-ScheduledTaskAction -Execute $InstalledExe
$trigger = New-ScheduledTaskTrigger -AtStartup
$principalTask = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 10 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principalTask `
    -Settings $settings `
    -Description "SP2 ADMIN Agent - inwentaryzacja i zdalne polecenia" `
    -Force | Out-Null

Write-Host "[8/9] Uruchamianie agenta..."
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 6

Write-Host "[9/9] Weryfikacja instalacji..."
$task = Get-ScheduledTask -TaskName $TaskName
$info = Get-ScheduledTaskInfo -TaskName $TaskName
$logPath = "C:\ProgramData\SP2-Agent\agent.log"
$heartbeatOk = $false
if (Test-Path $logPath) {
    $recentLog = Get-Content $logPath -Tail 30 -ErrorAction SilentlyContinue
    $heartbeatOk = [bool]($recentLog | Select-String -SimpleMatch "Heartbeat wysłany poprawnie")
}

Write-Host "SP2 Agent zainstalowany bez instalowania Pythona na stacji."
Write-Host "Plik: $InstalledExe"
Write-Host "Konfiguracja: $ConfigPath"
Write-Host "Zadanie: $TaskName / stan=$($task.State) / kod=$($info.LastTaskResult)"
Write-Host "Log: $logPath"
if ($heartbeatOk) {
    Write-Host "Heartbeat: OK"
}
else {
    Write-Warning "Nie potwierdzono jeszcze poprawnego heartbeat. Sprawdź log po 60 sekundach."
}

$EnrollmentToken = $null
$ApiToken = $null
$DeviceToken = $null
$secureToken = $null

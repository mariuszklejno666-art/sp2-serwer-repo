#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-/home/baraqda/sp2-admin-6.0.0-commit-0003}"
SOURCE_DIR="${SP2_AGENT_SOURCE:-/var/lib/samba/sysvol/sp2.lan/scripts/SP2-Agent}"
MIGRATION_SCRIPT="${SP2_MIGRATION_SCRIPT:-$ROOT/agent-windows/migrate-entra-to-samba.ps1}"
EMERGENCY_LEAVE_SCRIPT="${SP2_EMERGENCY_LEAVE_SCRIPT:-$ROOT/agent-windows/emergency-leave-samba.ps1}"
INSTALLER_SCRIPT="${SP2_AGENT_INSTALLER_SCRIPT:-$ROOT/agent-windows/install-standalone-agent.ps1}"
ENROLLMENT_CODE="${SP2_AGENT_ENROLLMENT_CODE:-}"
OUTPUT_DIR="${SP2_AGENT_USB_OUTPUT:-/tmp/SP2-Agent-USB}"
SERVER_URL="${SP2_AGENT_SERVER_URL:-https://dc.sp2.lan}"
CA_SOURCE="${SP2_AGENT_CA_SOURCE:-/home/baraqda/sp2-internal-ca.crt}"

if [[ ! -f "$SOURCE_DIR/SP2Agent.exe" ]]; then
  echo "Brak SP2Agent.exe w $SOURCE_DIR" >&2
  exit 1
fi
if [[ ! -f "$INSTALLER_SCRIPT" ]]; then
  echo "Brak instalatora agenta: $INSTALLER_SCRIPT" >&2
  exit 1
fi
if [[ ! -f "$MIGRATION_SCRIPT" ]]; then
  echo "Brak skryptu migracji: $MIGRATION_SCRIPT" >&2
  exit 1
fi
if [[ ! -f "$EMERGENCY_LEAVE_SCRIPT" ]]; then
  echo "Brak skryptu awaryjnego odłączenia: $EMERGENCY_LEAVE_SCRIPT" >&2
  exit 1
fi
if [[ ! -f "$CA_SOURCE" ]]; then
  echo "Brak certyfikatu CA: $CA_SOURCE" >&2
  exit 1
fi

if [[ -z "$ENROLLMENT_CODE" ]]; then
  echo "Brak SP2_AGENT_ENROLLMENT_CODE. Wygeneruj kod wdrożeniowy w SP2 ADMIN i przekaż go tylko do procesu budowania." >&2
  exit 1
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

cp "$SOURCE_DIR/SP2Agent.exe" "$OUTPUT_DIR/SP2Agent.exe"
cp "$INSTALLER_SCRIPT" "$OUTPUT_DIR/install-agent.ps1"
cp "$MIGRATION_SCRIPT" "$OUTPUT_DIR/migrate-entra-to-samba.ps1"
cp "$EMERGENCY_LEAVE_SCRIPT" "$OUTPUT_DIR/emergency-leave-samba.ps1"
cp "$CA_SOURCE" "$OUTPUT_DIR/sp2-internal-ca.crt"

cat > "$OUTPUT_DIR/deployment.json" <<EOF
{
  "server_url": "$SERVER_URL",
  "enrollment_code": "$ENROLLMENT_CODE",
  "room": "",
  "interval_seconds": 60,
  "ca_certificate": "sp2-internal-ca.crt"
}
EOF

cat > "$OUTPUT_DIR/INSTALUJ.ps1" <<'EOF'
[CmdletBinding()]
param(
    [ValidateSet('','Sala11','Sala32','Sala4','Sala7','Nauczyciel','Administracja')]
    [string]$Profile = '',
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Select-DeploymentProfile {
    Write-Host ''
    Write-Host 'Wybierz przeznaczenie komputera:'
    Write-Host '  1. Sala 11'
    Write-Host '  2. Sala 32'
    Write-Host '  3. Sala 4'
    Write-Host '  4. Sala 7'
    Write-Host '  5. Nauczyciel'
    Write-Host '  6. Administracja'
    do {
        $choice = Read-Host 'Wybierz numer 1-6'
        switch ($choice) {
            '1' { return 'Sala11' }
            '2' { return 'Sala32' }
            '3' { return 'Sala4' }
            '4' { return 'Sala7' }
            '5' { return 'Nauczyciel' }
            '6' { return 'Administracja' }
            default { Write-Warning 'Nieprawidlowy wybor. Wpisz liczbe od 1 do 6.' }
        }
    } while ($true)
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Uruchom INSTALUJ-AGENTA.cmd jako administrator.'
}
if (-not $Profile) {
    $Profile = Select-DeploymentProfile
}

$deployment = Get-Content (Join-Path $Root 'deployment.json') -Raw | ConvertFrom-Json
Write-Host "Profil instalacji: $Profile"

$existingTask = Get-ScheduledTask -TaskName 'SP2Agent' -ErrorAction SilentlyContinue
if ($existingTask) {
    Stop-ScheduledTask -TaskName 'SP2Agent' -ErrorAction SilentlyContinue
}
Get-Process -Name 'SP2Agent' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

$installedExe = 'C:\Program Files\SP2 Agent\SP2Agent.exe'
if (Test-Path $installedExe) {
    $unlocked = $false
    for ($i = 0; $i -lt 20; $i++) {
        try {
            $stream = [System.IO.File]::Open($installedExe, 'Open', 'ReadWrite', 'None')
            $stream.Close()
            $unlocked = $true
            break
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $unlocked) {
        throw "Nie mozna odblokowac pliku $installedExe. Zrestartuj komputer i uruchom instalator ponownie."
    }
}

& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'install-agent.ps1')
if ($LASTEXITCODE -ne 0) {
    throw "Instalator SP2 Agent zakonczyl sie kodem $LASTEXITCODE"
}

$agentConfigPath = 'C:\Program Files\SP2 Agent\agent-config.json'
if (-not (Test-Path $agentConfigPath)) {
    throw "Brak konfiguracji z indywidualnym tokenem urządzenia: $agentConfigPath"
}
$agentConfig = Get-Content $agentConfigPath -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace([string]$agentConfig.token)) {
    throw 'Instalator nie zapisał indywidualnego tokenu urządzenia.'
}
$headers = @{ Authorization = "Bearer $($agentConfig.token)" }
$body = @{
    hostname = $env:COMPUTERNAME.ToUpperInvariant()
    profile = $Profile
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod `
        -Method Post `
        -Uri (([string]$deployment.server_url).TrimEnd('/') + '/api/v1/agent/profile/assign') `
        -Headers $headers `
        -ContentType 'application/json; charset=utf-8' `
        -Body $body `
        -TimeoutSec 30

    if ($response.status -eq 'assigned') {
        Write-Host "Profil przypisany automatycznie: $Profile"
        Write-Host "OU: $($response.target_ou)"
    }
    else {
        Write-Warning "Agent zainstalowany. Przypisanie profilu oczekuje: $($response.message)"
    }
}
catch {
    Write-Warning "Agent zainstalowany, ale przypisanie profilu nie powiodlo sie: $($_.Exception.Message)"
}

Write-Host "Gotowe. Komputer: $env:COMPUTERNAME / profil: $Profile"
if (-not $NonInteractive) {
    Read-Host 'Nacisnij Enter, aby zamknac'
}
EOF

cat > "$OUTPUT_DIR/START-MIGRACJA.cmd" <<'EOF'
@echo off
cd /d "%~dp0"
certutil.exe -f -addstore Root "%~dp0sp2-internal-ca.crt" >nul
if errorlevel 1 (
  echo BLAD: Nie udalo sie zainstalowac certyfikatu CA SP2.
  pause
  exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0migrate-entra-to-samba.ps1" -AgentInstaller "%~dp0INSTALUJ.ps1"
pause
EOF

cat > "$OUTPUT_DIR/INSTALUJ-AGENTA.cmd" <<'EOF'
@echo off
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0INSTALUJ.ps1"
pause
EOF

cat > "$OUTPUT_DIR/TRYB-AWARYJNY-ODLACZ.cmd" <<'EOF'
@echo off
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0emergency-leave-samba.ps1"
pause
EOF

cat > "$OUTPUT_DIR/README.txt" <<'EOF'
SP2 Agent - jedna uniwersalna paczka USB

MIGRACJA Z MICROSOFT ENTRA DO SAMBA AD:
Uruchom START-MIGRACJA.cmd jako administrator.
Program poprosi o wybor sali, nauczyciela albo administracji.
Dla sal pobierze z SP2 ADMIN liste wolnych numerow i zaproponuje pierwszy wolny.
Po restarcie wdrozenie wznowi sie automatycznie jako SYSTEM: sprawdzi DNS, domene
i secure channel, a nastepnie zainstaluje agenta pod docelowa nazwa oraz przypisze OU.
Nie trzeba drugi raz uruchamiac instalatora agenta.

KOMPUTER JUZ W DOMENIE:
Uruchom INSTALUJ-AGENTA.cmd jako administrator i wybierz profil.

AWARYJNE ODLACZENIE OD DOMENY:
Uruchom TRYB-AWARYJNY-ODLACZ.cmd jako administrator tylko wtedy, gdy komputer
nalezy do sp2.lan i trzeba go kontrolowanie przeniesc do WORKGROUP.
Kreator sprawdzi lokalne konto .\SP2, zapisze obecny DNS, poprosi o jawne
potwierdzenie ODLACZ i po restarcie opcjonalnie przywroci wczesniejszy DNS.

UWAGA:
Hasla administratorow nie sa zapisane w paczce.
deployment.json zawiera czasowy kod wdrożeniowy ważny 8 godzin, domyślnie do 100 komputerów.
Każdy komputer otrzymuje własny indywidualny token urządzenia zapisywany
w chronionej konfiguracji C:\Program Files\SP2 Agent\agent-config.json.
Paczka laczy sie bezpiecznie z https://dc.sp2.lan i instaluje certyfikat CA SP2.
EOF

# Windows PowerShell 5.1 requires UTF-8 BOM for reliable non-ASCII parsing.
python3 - "$OUTPUT_DIR" <<'PY'
from pathlib import Path
import sys

utf8_bom = b"\xef\xbb\xbf"
package_dir = Path(sys.argv[1])

for script in package_dir.rglob("*.ps1"):
    content = script.read_bytes()
    if content.startswith(utf8_bom):
        content = content[len(utf8_bom):]
    text = content.decode("utf-8")
    script.write_bytes(utf8_bom + text.encode("utf-8"))
PY

chmod -R go-rwx "$OUTPUT_DIR"
echo "Gotowe: $OUTPUT_DIR"
find "$OUTPUT_DIR" -maxdepth 1 -type f -printf '%P\n' | sort

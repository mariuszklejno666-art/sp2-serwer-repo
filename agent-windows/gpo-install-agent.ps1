[CmdletBinding()]
param(
    [string]$PackageRoot = "\\szkolaak.sp2.lan\SYSVOL\sp2.lan\scripts\SP2-Agent",
    [string]$LocalCache = "C:\ProgramData\SP2-Agent-Deploy",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$LogDir = "C:\ProgramData\SP2-Agent"
$DeployLog = Join-Path $LogDir "gpo-deploy.log"
$Marker = Join-Path $LocalCache "package.sha256"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $LocalCache | Out-Null

function Write-DeployLog {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $DeployLog -Value $line -Encoding UTF8
}

try {
    Write-DeployLog "START package=$PackageRoot"

    $required = @("SP2Agent.exe", "install-agent.ps1", "deployment.json")
    foreach ($name in $required) {
        $source = Join-Path $PackageRoot $name
        if (-not (Test-Path $source)) {
            throw "Missing deployment file: $source"
        }
    }

    $hashInput = @()
    foreach ($name in $required) {
        $source = Join-Path $PackageRoot $name
        $hashInput += (Get-FileHash -Algorithm SHA256 -Path $source).Hash
    }
    $packageHash = ($hashInput -join "|")

    $installedExe = "C:\Program Files\SP2 Agent\SP2Agent.exe"
    $taskExists = Get-ScheduledTask -TaskName "SP2Agent" -ErrorAction SilentlyContinue
    $previousHash = if (Test-Path $Marker) { (Get-Content $Marker -Raw).Trim() } else { "" }

    if (-not $Force -and $taskExists -and (Test-Path $installedExe) -and $previousHash -eq $packageHash) {
        Write-DeployLog "SKIP agent already installed and package unchanged"
        exit 0
    }

    foreach ($name in $required) {
        Copy-Item (Join-Path $PackageRoot $name) (Join-Path $LocalCache $name) -Force
    }

    # Stop the scheduled task, then force-stop any remaining SP2Agent process.
    if ($taskExists) {
        Stop-ScheduledTask -TaskName "SP2Agent" -ErrorAction SilentlyContinue
    }
    Stop-Process -Name "SP2Agent" -Force -ErrorAction SilentlyContinue

    $deadline = (Get-Date).AddSeconds(20)
    do {
        $running = Get-Process -Name "SP2Agent" -ErrorAction SilentlyContinue
        if ($running) {
            Stop-Process -Name "SP2Agent" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
        }
    } while ($running -and (Get-Date) -lt $deadline)

    if (Get-Process -Name "SP2Agent" -ErrorAction SilentlyContinue) {
        throw "SP2Agent.exe is still running and cannot be upgraded"
    }

    # Make sure the binary is no longer locked before invoking the installer.
    if (Test-Path $installedExe) {
        $lockDeadline = (Get-Date).AddSeconds(10)
        do {
            $locked = $false
            try {
                $stream = [System.IO.File]::Open($installedExe, 'Open', 'ReadWrite', 'None')
                $stream.Close()
            }
            catch {
                $locked = $true
                Start-Sleep -Milliseconds 500
            }
        } while ($locked -and (Get-Date) -lt $lockDeadline)
        if ($locked) {
            throw "SP2Agent.exe file lock did not clear"
        }
    }

    $installer = Join-Path $LocalCache "install-agent.ps1"
    & powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $installer
    if ($LASTEXITCODE -ne 0) {
        throw "Installer failed with exit code $LASTEXITCODE"
    }

    [System.IO.File]::WriteAllText($Marker, $packageHash, [System.Text.UTF8Encoding]::new($false))
    Write-DeployLog "SUCCESS package applied"
    exit 0
}
catch {
    Write-DeployLog ("ERROR " + $_.Exception.Message)
    exit 1
}

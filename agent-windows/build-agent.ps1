param(
    [string]$Python = "py",
    [string]$OutputDir = "dist"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw "Nie znaleziono Pythona do kompilacji. Ten skrypt uruchamiasz tylko na komputerze deweloperskim/buildowym."
}

& $Python -3 -m pip install --upgrade pip
& $Python -3 -m pip install -r requirements.txt pyinstaller

$dist = Join-Path $Root $OutputDir
$work = Join-Path $Root "build"
$spec = Join-Path $Root "SP2Agent.spec"
$source = Join-Path $Root "sp2_agent.py"
$buildSource = Join-Path $Root "sp2_agent_build.py"

Remove-Item $dist -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $spec -Force -ErrorAction SilentlyContinue
Remove-Item $buildSource -Force -ErrorAction SilentlyContinue

# PyInstaller --onefile uruchamia kod z katalogu tymczasowego. Oryginalny
# agent wylicza CONFIG względem __file__, więc EXE szukał agent-config.json
# w katalogu _MEI zamiast obok zainstalowanego SP2Agent.exe. Do buildu
# tworzymy tymczasową kopię źródła, która w trybie frozen używa katalogu
# sys.executable. Źródłowy sp2_agent.py pozostaje bez zmian.
$text = [System.IO.File]::ReadAllText($source)
$old = @'
BASE_DIR = Path(__file__).resolve().parent
CONFIG = BASE_DIR / "agent-config.json"
'@
$new = @'
BASE_DIR = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent
)
CONFIG = BASE_DIR / "agent-config.json"
'@
if (-not $text.Contains($old)) {
    throw "Nie znaleziono oczekiwanego fragmentu BASE_DIR/CONFIG w sp2_agent.py."
}
$text = $text.Replace($old, $new)
[System.IO.File]::WriteAllText($buildSource, $text, [System.Text.UTF8Encoding]::new($false))

try {
    & $Python -3 -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --name SP2Agent `
        --hidden-import win32timezone `
        --hidden-import servicemanager `
        --hidden-import win32service `
        --hidden-import win32serviceutil `
        --hidden-import win32event `
        sp2_agent_build.py
}
finally {
    Remove-Item $buildSource -Force -ErrorAction SilentlyContinue
}

Write-Host "Gotowe: $dist\SP2Agent.exe"

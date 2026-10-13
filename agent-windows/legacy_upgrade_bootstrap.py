from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

TASK_NAME = "SP2Agent"
SERVICE_NAME = "SP2Agent"
DEFAULT_TARGET = Path(r"C:\Program Files\SP2 Agent\SP2Agent.exe")
DATA_ROOT = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SP2-Agent"
UPGRADE_ROOT = DATA_ROOT / "legacy-upgrade"


def _payload_path() -> Path:
    root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return root / "payload" / "SP2Agent.exe"


def _scheduled_task_target() -> Path | None:
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "$t=Get-ScheduledTask -TaskName 'SP2Agent' -ErrorAction SilentlyContinue;"
            "if($t){[string]$t.Actions[0].Execute}"
        ),
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = (result.stdout or "").strip().strip('"')
    if not value:
        return None
    path = Path(value)
    if path.name.casefold() != "sp2agent.exe":
        return None
    return path


def resolve_target() -> Path:
    candidate = _scheduled_task_target()
    if candidate and candidate.is_file():
        return candidate
    return DEFAULT_TARGET


def build_helper_script(target: Path, staged: Path, log_path: Path) -> str:
    backup = target.with_suffix(target.suffix + ".pre-2.8.0.bak")
    replacement = target.with_suffix(target.suffix + ".new")
    return (
        "@echo off\r\n"
        "setlocal\r\n"
        f'set "LOG={log_path}"\r\n'
        f'echo [%date% %time%] Legacy upgrade helper started>>"%LOG%"\r\n'
        "timeout /t 10 /nobreak >nul\r\n"
        f'schtasks.exe /End /TN "{TASK_NAME}" >nul 2>&1\r\n'
        f'sc.exe stop "{SERVICE_NAME}" >nul 2>&1\r\n'
        'taskkill.exe /F /IM "SP2Agent.exe" >nul 2>&1\r\n'
        "timeout /t 3 /nobreak >nul\r\n"
        f'copy /y "{staged}" "{replacement}" >nul\r\n'
        "if errorlevel 1 goto failed\r\n"
        f'if exist "{target}" copy /y "{target}" "{backup}" >nul\r\n'
        f'move /y "{replacement}" "{target}" >nul\r\n'
        "if errorlevel 1 goto rollback\r\n"
        f'schtasks.exe /Run /TN "{TASK_NAME}" >nul 2>&1\r\n'
        "if not errorlevel 1 goto success\r\n"
        f'sc.exe start "{SERVICE_NAME}" >nul 2>&1\r\n'
        "if errorlevel 1 goto failed\r\n"
        ":success\r\n"
        'echo [%date% %time%] SP2 Agent 2.8.0 installed>>"%LOG%"\r\n'
        f'del /q "{staged}" >nul 2>&1\r\n'
        'del /q "%~f0" >nul 2>&1\r\n'
        "exit /b 0\r\n"
        ":rollback\r\n"
        f'if exist "{backup}" copy /y "{backup}" "{target}" >nul\r\n'
        ":failed\r\n"
        'echo [%date% %time%] Legacy upgrade FAILED>>"%LOG%"\r\n'
        'del /q "%~f0" >nul 2>&1\r\n'
        "exit /b 1\r\n"
    )


def stage_upgrade() -> tuple[Path, Path, str]:
    payload = _payload_path()
    if not payload.is_file():
        raise RuntimeError("Brak osadzonego SP2Agent.exe.")
    if payload.read_bytes()[:2] != b"MZ":
        raise RuntimeError("Osadzony agent nie jest poprawnym EXE.")

    target = resolve_target()
    config = target.parent / "agent-config.json"
    if not target.is_file():
        raise RuntimeError(f"Nie znaleziono zainstalowanego agenta: {target}")
    if not config.is_file():
        raise RuntimeError(
            f"Brak istniejącej konfiguracji agenta: {config}. "
            "Bootstrap nie będzie wykonywał ponownego enrollment."
        )

    UPGRADE_ROOT.mkdir(parents=True, exist_ok=True)
    staged = UPGRADE_ROOT / "SP2Agent-2.8.0.exe"
    helper = UPGRADE_ROOT / "apply-2.8.0.cmd"
    log_path = DATA_ROOT / "legacy-upgrade.log"

    digest = hashlib.sha256()
    with payload.open("rb") as source, staged.open("wb") as output:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
            output.write(block)

    helper.write_text(
        build_helper_script(target, staged, log_path),
        encoding="utf-8",
        newline="",
    )
    return target, helper, digest.hexdigest()


def launch_helper(helper: Path) -> None:
    subprocess.Popen(
        ["cmd.exe", "/c", str(helper)],
        creationflags=(
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        ),
        close_fds=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="Zaplanuj aktualizację")
    args = parser.parse_args()
    if not args.apply:
        parser.error("Wymagany parametr --apply")

    target, helper, digest = stage_upgrade()
    launch_helper(helper)
    print(f"Przygotowano aktualizację SP2 Agent 2.8.0: {target}")
    print(f"SHA256: {digest}")
    print("Podmiana rozpocznie się po zapisaniu wyniku zadania przez stary agent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

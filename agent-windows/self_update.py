from __future__ import annotations

import ntpath


def build_self_update_script(
    *, new_exe_path: str, installed_exe_path: str, task_name: str = "SP2Agent"
) -> str:
    """Buduje skrypt .cmd, który bezpiecznie podmienia działającego agenta.

    Windows nie pozwala nadpisać pliku EXE, który jest aktualnie
    wykonywany — dlatego bieżący proces agenta uruchamia ten skrypt jako
    ODŁĄCZONY proces potomny i kończy działanie. Skrypt czeka, aż stary
    proces faktycznie się zakończy, dopiero wtedy podmienia plik i
    ponownie uruchamia zaplanowane zadanie. Na końcu usuwa samego siebie.
    """
    exe_name = ntpath.basename(installed_exe_path) or "SP2Agent.exe"
    return (
        "@echo off\r\n"
        f'taskkill /F /IM "{exe_name}" >nul 2>&1\r\n'
        "timeout /t 3 /nobreak >nul\r\n"
        f'move /y "{new_exe_path}" "{installed_exe_path}" >nul\r\n'
        f'schtasks /Run /TN "{task_name}" >nul\r\n'
        'del "%~f0"\r\n'
    )

from __future__ import annotations

import getpass
import hashlib
import os
import json
import logging
import platform
import shutil
import socket
import subprocess
import sys
import threading
import tempfile
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import psutil
import requests

from console_session import parse_query_user_output
from self_update import build_self_update_script
from software_bundle import extract_bundle
from web_filter_hosts import apply_web_filter_hosts

VERSION = "2.8.0"
BASE_DIR = Path(__file__).resolve().parent
CONFIG = BASE_DIR / "agent-config.json"
DATA_DIR = Path(r"C:\ProgramData\SP2-Agent")
LOG_FILE = DATA_DIR / "agent.log"
DOWNLOAD_DIR = DATA_DIR / "downloads"


def configure_logging() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if sys.stdout and sys.stdout.isatty():
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)


def load_config() -> dict[str, Any]:
    if not CONFIG.exists():
        raise FileNotFoundError(
            f"Brak pliku konfiguracji: {CONFIG}. "
            "Skopiuj agent-config.example.json jako agent-config.json."
        )

    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    required = ("server_url", "token")
    missing = [key for key in required if not cfg.get(key)]
    if missing:
        raise ValueError(
            "Brak wymaganych ustawień: " + ", ".join(missing)
        )
    return cfg


def run_powershell_json(script: str, timeout: int = 20) -> Any:
    command = [
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    output = result.stdout.strip()
    return json.loads(output) if output else None


def collect_hardware() -> dict[str, Any]:
    script = r"""
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os = Get-CimInstance Win32_OperatingSystem
[PSCustomObject]@{
    manufacturer = $cs.Manufacturer
    model = $cs.Model
    serial_number = $bios.SerialNumber
    windows_caption = $os.Caption
    windows_build = $os.BuildNumber
    domain = $cs.Domain
    part_of_domain = [bool]$cs.PartOfDomain
} | ConvertTo-Json -Compress
"""
    try:
        data = run_powershell_json(script)
        return data if isinstance(data, dict) else {}
    except Exception:
        logging.exception("Nie udało się pobrać danych CIM")
        return {}


def collect_console_session() -> dict[str, Any] | None:
    """Zwraca aktywną sesję konsoli (do RDP Shadow), jeśli ktoś jest zalogowany.

    `query.exe` bywa zwraca kod wyjścia != 0 mimo poprawnego wyniku, więc
    celowo nie sprawdzamy returncode — tylko parsujemy stdout.
    """
    try:
        completed = subprocess.run(
            ["query", "user"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_query_user_output(completed.stdout or "")


def collect_mac_addresses() -> list[str]:
    macs: set[str] = set()
    for values in psutil.net_if_addrs().values():
        for addr in values:
            family_name = str(addr.family)
            if "AF_LINK" in family_name or "AF_PACKET" in family_name:
                value = (addr.address or "").strip().upper()
                if value and value != "00:00:00:00:00:00":
                    macs.add(value.replace("-", ":"))
    return sorted(macs)


def collect() -> dict[str, Any]:
    ips: set[str] = set()
    for values in psutil.net_if_addrs().values():
        for addr in values:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ips.add(addr.address)

    disks: list[dict[str, Any]] = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append(
                {
                    "mount": part.mountpoint,
                    "filesystem": part.fstype,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent_used": usage.percent,
                }
            )
        except (OSError, PermissionError):
            logging.debug("Pominięto dysk %s", part.mountpoint)

    data: dict[str, Any] = {
        "hostname": socket.gethostname().upper(),
        "fqdn": socket.getfqdn(),
        "os_name": platform.system(),
        "os_version": platform.platform(),
        "username": getpass.getuser(),
        "ip_addresses": sorted(ips),
        "mac_addresses": collect_mac_addresses(),
        "cpu": platform.processor() or platform.machine(),
        "cpu_logical_count": psutil.cpu_count(logical=True),
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "ram_bytes": psutil.virtual_memory().total,
        "memory_percent": psutil.virtual_memory().percent,
        "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
        "disks": disks,
        "console_session": collect_console_session(),
        "boot_time": datetime.fromtimestamp(
            psutil.boot_time(), timezone.utc
        ).isoformat(),
        "agent_version": VERSION,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
    data.update(collect_hardware())
    return data


def create_session(cfg: dict[str, Any]) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": "Bearer " + str(cfg["token"]),
            "User-Agent": f"SP2-Agent/{VERSION}",
        }
    )
    ca_bundle = str(cfg.get("ca_bundle", "")).strip()
    if ca_bundle:
        ca_path = Path(ca_bundle)
        if not ca_path.is_absolute():
            ca_path = BASE_DIR / ca_path
        ca_path = ca_path.resolve()
        if not ca_path.is_file():
            raise FileNotFoundError(
                f"Brak certyfikatu CA do weryfikacji HTTPS: {ca_path}"
            )
        session.verify = str(ca_path)
    else:
        session.verify = bool(cfg.get("verify_tls", True))
    return session


def heartbeat(
    session: requests.Session,
    cfg: dict[str, Any],
) -> None:
    url = str(cfg["server_url"]).rstrip("/") + "/api/v1/agent/heartbeat"
    payload = collect()
    room = str(cfg.get("room", "")).strip()
    if room:
        payload["room"] = room
    response = session.post(url, json=payload, timeout=30)
    response.raise_for_status()
    logging.info("Heartbeat wysłany poprawnie")


def schedule_self_update(new_exe_path: Path) -> None:
    """Zleca bezpieczną podmianę działającego agenta i restart zadania.

    Uruchamia skrypt pomocniczy jako ODŁĄCZONY proces potomny (przeżywa
    zakończenie tego procesu) — sam agent nie może nadpisać własnego,
    aktualnie wykonywanego pliku EXE.
    """
    installed_exe = (
        Path(sys.executable).resolve()
        if getattr(sys, "frozen", False)
        else BASE_DIR / "SP2Agent.exe"
    )
    script = build_self_update_script(
        new_exe_path=str(new_exe_path.resolve()),
        installed_exe_path=str(installed_exe),
    )
    helper_script = DATA_DIR / "self-update.cmd"
    helper_script.parent.mkdir(parents=True, exist_ok=True)
    helper_script.write_text(script, encoding="utf-8")
    subprocess.Popen(
        ["cmd.exe", "/c", str(helper_script)],
        creationflags=(
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        ),
        close_fds=True,
    )


def execute_command(
    command: dict[str, Any],
    session: requests.Session,
    cfg: dict[str, Any],
) -> tuple[str, str, str]:
    command_type = command.get("type")
    payload = command.get("payload") or {}

    if command_type == "inventory":
        return "success", json.dumps(collect(), ensure_ascii=False), ""

    if command_type == "message":
        message = str(payload.get("message", "")).strip()[:500]
        if not message:
            return "failed", "", "Pusta wiadomość."
        subprocess.run(
            ["msg", "*", message],
            check=True,
            timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return "success", "Wiadomość została wyświetlona.", ""

    if command_type == "shutdown":
        delay = int(payload.get("delay_seconds", 30))
        delay = min(max(delay, 15), 3600)
        subprocess.Popen(
            [
                "shutdown", "/s", "/t", str(delay), "/c",
                "Wyłączenie zlecone przez SP2 ADMIN",
            ],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return "success", f"Wyłączenie zaplanowane za {delay} sekund.", ""

    if command_type == "restart":
        delay = int(payload.get("delay_seconds", 30))
        delay = min(max(delay, 15), 3600)
        subprocess.Popen(
            [
                "shutdown",
                "/r",
                "/t",
                str(delay),
                "/c",
                "Restart zlecony przez SP2 ADMIN",
            ],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return "success", f"Restart zaplanowany za {delay} sekund.", ""

    safe_commands = {
        "hostname": (["hostname"], 20),
        "ipconfig": (["ipconfig", "/all"], 60),
        "systeminfo": (["systeminfo"], 120),
        "gpupdate": (["gpupdate", "/force"], 300),
    }
    if command_type in safe_commands:
        args, timeout = safe_commands[command_type]
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = (completed.stdout or "").strip()
        error = (completed.stderr or "").strip()
        if completed.returncode == 0:
            return "success", output[:12000], ""
        return "failed", output[:12000], (
            error or f"Kod zakończenia: {completed.returncode}"
        )[:4000]

    if command_type == "list_services":
        script = r"""
Get-CimInstance Win32_Service |
  Sort-Object Name |
  Select-Object -First 300 Name, DisplayName, State, StartMode |
  ConvertTo-Json -Compress
"""
        data = run_powershell_json(script, timeout=60)
        return "success", json.dumps(data, ensure_ascii=False, indent=2)[:12000], ""

    if command_type == "list_processes":
        processes = []
        for proc in psutil.process_iter(["pid", "name", "username", "memory_info"]):
            try:
                info = proc.info
                memory = info.get("memory_info")
                processes.append(
                    {
                        "pid": info.get("pid"),
                        "name": info.get("name"),
                        "username": info.get("username"),
                        "memory_bytes": getattr(memory, "rss", None),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        processes.sort(key=lambda item: (item.get("name") or "").lower())
        return "success", json.dumps(
            processes[:300], ensure_ascii=False, indent=2
        )[:12000], ""


    if command_type == "install_software":
        package_id = str(payload.get("package_id", "")).strip()
        filename = str(payload.get("filename", "")).strip()
        expected_sha256 = str(payload.get("sha256", "")).strip().lower()
        installer_type = str(payload.get("installer_type", "")).strip().lower()
        arguments = payload.get("arguments", [])
        download_path = str(payload.get("download_path", "")).strip()
        expected_size = int(payload.get("size", 0) or 0)
        files = payload.get("files")

        if (
            not package_id
            or not filename
            or "/" in filename
            or "\\" in filename
            or installer_type not in {"exe", "msi", "zip"}
        ):
            return "failed", "", "Nieprawidłowe dane pakietu."
        if len(expected_sha256) != 64:
            return "failed", "", "Brak prawidłowej sumy SHA-256."
        if not isinstance(arguments, list) or not all(isinstance(v, str) for v in arguments):
            return "failed", "", "Nieprawidłowe argumenty instalatora."
        if not download_path.startswith("/api/v1/agent/software/"):
            return "failed", "", "Nieprawidłowa ścieżka pobierania."
        if files is not None and not isinstance(files, list):
            return "failed", "", "Nieprawidłowa lista plików pakietu."

        DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

        if files:
            if len(files) > 128:
                return "failed", "", "Pakiet zawiera zbyt wiele plików."

            package_key = hashlib.sha256(package_id.encode("utf-8")).hexdigest()[:20]
            package_dir = DOWNLOAD_DIR / f"package-{package_key}"
            temporary_dir = DOWNLOAD_DIR / f"package-{package_key}.part"
            shutil.rmtree(temporary_dir, ignore_errors=True)
            temporary_dir.mkdir(parents=True, exist_ok=False)

            total_downloaded = 0
            seen_names: set[str] = set()
            installer_seen = False
            try:
                for index, entry in enumerate(files):
                    if not isinstance(entry, dict):
                        raise TypeError("Nieprawidłowy wpis pliku pakietu.")
                    item_name = str(entry.get("filename", "")).strip()
                    item_sha256 = str(entry.get("sha256", "")).strip().lower()
                    item_size = int(entry.get("size", 0) or 0)
                    if (
                        not item_name
                        or len(item_name) > 240
                        or "/" in item_name
                        or "\\" in item_name
                        or item_name in {".", ".."}
                    ):
                        raise ValueError("Nieprawidłowa nazwa pliku w pakiecie.")
                    name_key = item_name.casefold()
                    if name_key in seen_names:
                        raise ValueError(f"Powtórzona nazwa pliku: {item_name}.")
                    seen_names.add(name_key)
                    if len(item_sha256) != 64 or item_size < 0:
                        raise ValueError(f"Nieprawidłowe metadane pliku {item_name}.")

                    item_path = temporary_dir / item_name
                    item_url = (
                        str(cfg["server_url"]).rstrip("/")
                        + f"/api/v1/agent/software/{package_id}/files/{index}/download"
                    )
                    digest = hashlib.sha256()
                    downloaded = 0
                    with session.get(item_url, stream=True, timeout=(20, 600)) as response:
                        response.raise_for_status()
                        with item_path.open("wb") as handle:
                            for data in response.iter_content(chunk_size=1024 * 1024):
                                if not data:
                                    continue
                                downloaded += len(data)
                                total_downloaded += len(data)
                                if total_downloaded > 4 * 1024 * 1024 * 1024:
                                    raise ValueError("Pakiet przekracza limit 4 GB.")
                                digest.update(data)
                                handle.write(data)

                    if item_size and downloaded != item_size:
                        raise ValueError(
                            f"Nieprawidłowy rozmiar pliku {item_name}: "
                            f"{downloaded}, oczekiwano {item_size}."
                        )
                    if digest.hexdigest().lower() != item_sha256:
                        raise ValueError(
                            f"Suma SHA-256 pliku {item_name} jest nieprawidłowa."
                        )
                    if name_key == filename.casefold():
                        installer_seen = True
                        if item_sha256 != expected_sha256:
                            raise ValueError(
                                "Suma głównego instalatora nie zgadza się z manifestem."
                            )

                if not installer_seen:
                    raise ValueError("W pobranym pakiecie brakuje głównego instalatora.")
                if expected_size and total_downloaded != expected_size:
                    raise ValueError(
                        f"Nieprawidłowy rozmiar całego pakietu: {total_downloaded}, "
                        f"oczekiwano {expected_size}."
                    )

                shutil.rmtree(package_dir, ignore_errors=True)
                os.replace(temporary_dir, package_dir)
            except (OSError, TypeError, ValueError, requests.RequestException) as exc:
                shutil.rmtree(temporary_dir, ignore_errors=True)
                return "failed", "", f"Nie udało się pobrać pełnego pakietu: {exc}"

            destination = package_dir / filename
        else:
            # Zgodność ze starszym serwerem: pojedynczy EXE/MSI.
            destination = DOWNLOAD_DIR / Path(filename).name
            temporary = destination.with_suffix(destination.suffix + ".part")
            temporary.unlink(missing_ok=True)

            url = str(cfg["server_url"]).rstrip("/") + download_path
            digest = hashlib.sha256()
            downloaded = 0
            with session.get(url, stream=True, timeout=(20, 600)) as response:
                response.raise_for_status()
                with temporary.open("wb") as handle:
                    for data in response.iter_content(chunk_size=1024 * 1024):
                        if not data:
                            continue
                        downloaded += len(data)
                        if downloaded > 4 * 1024 * 1024 * 1024:
                            raise ValueError("Pakiet przekracza limit 4 GB.")
                        digest.update(data)
                        handle.write(data)

            if expected_size and downloaded != expected_size:
                temporary.unlink(missing_ok=True)
                return "failed", "", (
                    f"Nieprawidłowy rozmiar pliku: {downloaded}, oczekiwano {expected_size}."
                )
            actual_sha256 = digest.hexdigest().lower()
            if actual_sha256 != expected_sha256:
                temporary.unlink(missing_ok=True)
                return "failed", "", "Suma SHA-256 pobranego pliku jest nieprawidłowa."

            os.replace(temporary, destination)

        def run_installer(path: Path, kind: str):
            if kind == "msi":
                command_line = ["msiexec.exe", "/i", str(path), *arguments]
            else:
                command_line = [str(path), *arguments]
            return subprocess.run(
                command_line,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=3600,
                check=False,
                cwd=str(path.parent),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

        if installer_type == "zip":
            with tempfile.TemporaryDirectory(
                prefix="install-", dir=DOWNLOAD_DIR
            ) as unpacked:
                unpacked_installer = extract_bundle(destination, Path(unpacked))
                completed = run_installer(
                    unpacked_installer,
                    unpacked_installer.suffix.lower().lstrip("."),
                )
        else:
            completed = run_installer(destination, installer_type)
        output = (completed.stdout or "").strip()
        error = (completed.stderr or "").strip()
        if completed.returncode in {0, 1641, 3010}:
            restart_note = (
                " Wymagany restart komputera."
                if completed.returncode in {1641, 3010}
                else ""
            )
            return (
                "success",
                f"Zainstalowano {payload.get('name', package_id)}. "
                f"Kod: {completed.returncode}.{restart_note}\n{output}"[:12000],
                "",
            )
        return (
            "failed",
            output[:12000],
            (error or f"Instalator zakończył się kodem {completed.returncode}.")[:4000],
        )

    if command_type == "self_update":
        filename = Path(str(payload.get("filename", ""))).name
        expected_sha256 = str(payload.get("sha256", "")).strip().lower()
        download_path = str(payload.get("download_path", "")).strip()
        expected_size = int(payload.get("size", 0) or 0)

        if not filename:
            return "failed", "", "Nieprawidłowe dane pakietu."
        if len(expected_sha256) != 64:
            return "failed", "", "Brak prawidłowej sumy SHA-256."
        if not download_path.startswith("/api/v1/agent/software/"):
            return "failed", "", "Nieprawidłowa ścieżka pobierania."

        DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
        destination = DOWNLOAD_DIR / f"update-{filename}"
        temporary = destination.with_suffix(destination.suffix + ".part")
        temporary.unlink(missing_ok=True)

        url = str(cfg["server_url"]).rstrip("/") + download_path
        digest = hashlib.sha256()
        downloaded = 0
        with session.get(url, stream=True, timeout=(20, 300)) as response:
            response.raise_for_status()
            with temporary.open("wb") as handle:
                for block in response.iter_content(chunk_size=1024 * 1024):
                    if not block:
                        continue
                    downloaded += len(block)
                    if downloaded > 200 * 1024 * 1024:
                        raise ValueError("Nowy agent przekracza limit 200 MB.")
                    digest.update(block)
                    handle.write(block)

        if expected_size and downloaded != expected_size:
            temporary.unlink(missing_ok=True)
            return "failed", "", (
                f"Nieprawidłowy rozmiar pliku: {downloaded}, oczekiwano {expected_size}."
            )
        actual_sha256 = digest.hexdigest().lower()
        if actual_sha256 != expected_sha256:
            temporary.unlink(missing_ok=True)
            return "failed", "", "Suma SHA-256 pobranego pliku jest nieprawidłowa."

        os.replace(temporary, destination)
        try:
            schedule_self_update(destination)
        except OSError as exc:
            return "failed", "", f"Nie udało się zaplanować aktualizacji: {exc}"

        version = str(payload.get("version", "")).strip() or "?"
        return (
            "success",
            f"Aktualizacja do wersji {version} zaplanowana — agent zaraz się zrestartuje.",
            "",
        )

    if command_type == "apply_web_filter":
        hostnames = payload.get("hostnames", [])
        if not isinstance(hostnames, list) or not all(isinstance(h, str) for h in hostnames):
            return "failed", "", "Nieprawidłowa lista domen."
        try:
            applied = apply_web_filter_hosts(hostnames)
        except OSError as exc:
            return "failed", "", f"Nie udało się zapisać pliku hosts: {exc}"
        return "success", f"Zablokowano {applied} domen w pliku hosts.", ""

    return "failed", "", f"Nieobsługiwane polecenie: {command_type}"


def process_next_command(
    session: requests.Session,
    cfg: dict[str, Any],
) -> None:
    base = str(cfg["server_url"]).rstrip("/") + "/api/v1/agent"
    hostname = socket.gethostname().upper()

    response = session.post(
        base + "/commands/next",
        json={"hostname": hostname},
        timeout=20,
    )
    response.raise_for_status()
    command = response.json().get("command")

    if not command:
        return

    command_id = command.get("id")
    command_type = command.get("type")
    logging.info(
        "Odebrano polecenie id=%s typ=%s",
        command_id,
        command_type,
    )

    try:
        status, result, error = execute_command(command, session, cfg)
    except Exception as exc:
        logging.exception("Błąd wykonania polecenia id=%s", command_id)
        status, result, error = "failed", "", str(exc)

    result_response = session.post(
        base + f"/commands/{command_id}/result",
        json={
            "hostname": hostname,
            "status": status,
            "result": result,
            "error": error,
        },
        timeout=20,
    )
    result_response.raise_for_status()
    logging.info(
        "Wysłano wynik polecenia id=%s status=%s",
        command_id,
        status,
    )


def run_agent(stop_event: threading.Event | None = None) -> None:
    configure_logging()
    cfg = load_config()
    interval = max(30, int(cfg.get("interval_seconds", 60)))
    session = create_session(cfg)

    logging.info(
        "Uruchomiono SP2 Agent %s; serwer=%s; interwał=%ss",
        VERSION,
        cfg["server_url"],
        interval,
    )

    while stop_event is None or not stop_event.is_set():
        try:
            heartbeat(session, cfg)
            process_next_command(session, cfg)
        except requests.RequestException:
            logging.exception("Błąd komunikacji z serwerem")
        except Exception:
            logging.exception("Nieoczekiwany błąd agenta")

        if stop_event is None:
            time.sleep(interval)
        else:
            stop_event.wait(interval)

    logging.info("SP2 Agent został zatrzymany")


# Obsługa usługi Windows przez pywin32.
try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class SP2AgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "SP2Agent"
        _svc_display_name_ = "SP2 ADMIN Agent"
        _svc_description_ = (
            "Agent inwentaryzacji i bezpiecznych zdalnych poleceń SP2 ADMIN."
        )

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            self.stop_event = threading.Event()
            self.service_stop_event = win32event.CreateEvent(
                None, 0, 0, None
            )

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()
            win32event.SetEvent(self.service_stop_event)

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg("SP2Agent uruchomiony")
            run_agent(self.stop_event)

except ImportError:
    SP2AgentService = None  # type: ignore[assignment]


def main() -> None:
    service_commands = {
        "install",
        "update",
        "remove",
        "start",
        "stop",
        "restart",
        "debug",
    }

    if len(sys.argv) > 1 and any(arg.lower() in service_commands for arg in sys.argv[1:]):
        if SP2AgentService is None:
            raise RuntimeError(
                "Brak pywin32. Zainstaluj: py -m pip install pywin32"
            )
        win32serviceutil.HandleCommandLine(SP2AgentService)
        return

    run_agent()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generuje bezpieczne raporty diagnostyczne dla konta codex-audit.

Skrypt celowo nie zapisuje surowych komunikatów dziennika ani pełnego
wyjścia narzędzi testowych. Do raportu trafiają wyłącznie dozwolone pola,
liczniki zdarzeń i zbiorczy wynik kontroli.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


DEFAULT_APP_DIR = Path("/home/baraqda/sp2-admin-6.0.0-commit-0003")
DEFAULT_REPORT_DIR = Path("/var/lib/sp2-admin-audit")
SERVICE_NAME = "sp2-admin.service"

SERVICE_FIELDS = (
    "ActiveState",
    "SubState",
    "MainPID",
    "NRestarts",
    "ExecMainStatus",
)

EVENT_PATTERNS = {
    "warnings": re.compile(r"\bwarning\b", re.IGNORECASE),
    "errors": re.compile(
        r"\b(error|critical|traceback|exception|failed)\b",
        re.IGNORECASE,
    ),
    "http_5xx": re.compile(r'"\s5\d{2}(?:\s|$)'),
    "auth_failures": re.compile(r'"\s(?:401|403)(?:\s|$)'),
}

PYTEST_COUNT_PATTERN = re.compile(
    r"(?P<count>\d+)\s+"
    r"(?P<label>passed|failed|errors?|skipped|warnings?|xfailed|xpassed)\b",
    re.IGNORECASE,
)

SAFE_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


def timestamp() -> str:
    """Zwraca lokalny czas w jednoznacznym formacie ISO."""

    return datetime.now().astimezone().isoformat(timespec="seconds")


def parse_properties(output: str) -> dict[str, str]:
    """Odczytuje wyłącznie dozwolone właściwości systemd."""

    allowed = set(SERVICE_FIELDS)
    properties: dict[str, str] = {}

    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in allowed:
            properties[key] = value.strip()

    return properties


def safe_health_payload(payload: Any) -> dict[str, str]:
    """Usuwa z odpowiedzi health wszystkie pola poza status i version."""

    if not isinstance(payload, dict):
        return {"status": "invalid", "version": "unknown"}

    result: dict[str, str] = {}
    for key in ("status", "version"):
        value = payload.get(key)
        if isinstance(value, str) and SAFE_VALUE_PATTERN.fullmatch(value):
            result[key] = value
        else:
            result[key] = "unknown"

    return result


def summarize_journal(output: str) -> dict[str, int]:
    """Zlicza zdarzenia bez zachowywania treści wpisów dziennika."""

    lines = [line for line in output.splitlines() if line.strip()]
    summary = {"entries": len(lines)}

    for name, pattern in EVENT_PATTERNS.items():
        summary[name] = sum(bool(pattern.search(line)) for line in lines)

    return summary


def parse_pytest_counts(output: str) -> dict[str, int]:
    """Wyciąga z wyniku pytest tylko liczniki kategorii."""

    counts: dict[str, int] = {}
    aliases = {
        "error": "errors",
        "warning": "warnings",
    }

    for match in PYTEST_COUNT_PATTERN.finditer(output):
        label = match.group("label").lower()
        label = aliases.get(label, label)
        counts[label] = max(
            counts.get(label, 0),
            int(match.group("count")),
        )

    return counts


def render_runtime_report(
    *,
    generated_at: str,
    service: dict[str, str],
    health: dict[str, str],
    disk_total: int,
    disk_used: int,
    disk_free: int,
    journal: dict[str, int],
) -> str:
    """Buduje raport, korzystając wyłącznie z bezpiecznych wartości."""

    gib = 1024**3
    return "\n".join(
        [
            "SP2 ADMIN - BEZPIECZNY RAPORT DIAGNOSTYCZNY",
            f"Wygenerowano: {generated_at}",
            "",
            "USŁUGA",
            (f"Stan: {service.get('ActiveState', 'unknown')}/{service.get('SubState', 'unknown')}"),
            f"PID: {service.get('MainPID', '0')}",
            f"Restarty: {service.get('NRestarts', '0')}",
            f"Kod procesu: {service.get('ExecMainStatus', 'unknown')}",
            "",
            "APLIKACJA",
            f"Health: {health.get('status', 'unknown')}",
            f"Wersja: {health.get('version', 'unknown')}",
            "",
            "DYSK /",
            f"Rozmiar: {disk_total / gib:.1f} GiB",
            f"Użyte: {disk_used / gib:.1f} GiB",
            f"Wolne: {disk_free / gib:.1f} GiB",
            "",
            "DZIENNIK - OSTATNIE 500 WPISÓW",
            f"Wpisy: {journal.get('entries', 0)}",
            f"Ostrzeżenia: {journal.get('warnings', 0)}",
            f"Błędy: {journal.get('errors', 0)}",
            f"HTTP 5xx: {journal.get('http_5xx', 0)}",
            f"HTTP 401/403: {journal.get('auth_failures', 0)}",
            "",
            "Surowe wiadomości dziennika są celowo ukryte.",
            "",
        ]
    )


def render_tests_report(
    *,
    generated_at: str,
    pytest_returncode: int,
    pytest_counts: dict[str, int],
    pytest_seconds: float,
    ruff_returncode: int,
    ruff_seconds: float,
) -> str:
    """Buduje raport testów bez nazw testów, ścieżek i treści błędów."""

    pytest_status = "OK" if pytest_returncode == 0 else "BŁĄD"
    ruff_status = "OK" if ruff_returncode == 0 else "BŁĄD"
    count_order = (
        "passed",
        "failed",
        "errors",
        "skipped",
        "warnings",
        "xfailed",
        "xpassed",
    )
    count_parts = [
        f"{label}={pytest_counts[label]}" for label in count_order if label in pytest_counts
    ]
    count_text = ", ".join(count_parts) or "brak podsumowania"

    return "\n".join(
        [
            "SP2 ADMIN - BEZPIECZNY RAPORT TESTÓW",
            f"Wygenerowano: {generated_at}",
            "",
            f"pytest: {pytest_status} ({count_text})",
            f"Czas pytest: {pytest_seconds:.1f} s",
            f"ruff: {ruff_status}",
            f"Czas ruff: {ruff_seconds:.1f} s",
            "",
            "Nazwy testów, ścieżki i szczegóły błędów są celowo ukryte.",
            "",
        ]
    )


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Uruchamia polecenie i przechowuje wyjście wyłącznie w pamięci."""

    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def collect_health(
    health_url: str = "http://127.0.0.1/health",
    health_host: str = "dc.sp2.lan",
) -> dict[str, str]:
    """Pobiera endpoint health i zachowuje tylko status oraz wersję."""

    request = Request(
        health_url,
        headers={"Host": health_host},
    )

    try:
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read(4096).decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {"status": "unavailable", "version": "unknown"}

    return safe_health_payload(payload)


def atomic_write(
    path: Path,
    content: str,
    *,
    group_name: str,
) -> None:
    """Zapisuje raport atomowo z uprawnieniami 0640."""

    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    temporary_path = Path(temporary_name)

    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

        os.chmod(temporary_path, 0o640)
        if os.name != "nt":
            import grp

            group_id = grp.getgrnam(group_name).gr_gid
            os.chown(temporary_path, os.geteuid(), group_id)
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def runtime_report(
    report_dir: Path,
    report_group: str,
    health_url: str,
    health_host: str,
) -> int:
    """Tworzy bezpieczny raport działania aplikacji."""

    service_result = run_command(
        [
            "systemctl",
            "show",
            SERVICE_NAME,
            "--no-pager",
            *[f"--property={field}" for field in SERVICE_FIELDS],
        ],
        timeout=10,
    )
    service = parse_properties(service_result.stdout)
    health = collect_health(health_url, health_host)

    journal_result = run_command(
        [
            "journalctl",
            "-u",
            SERVICE_NAME,
            "--no-pager",
            "-n",
            "500",
            "-o",
            "cat",
        ],
        timeout=15,
    )
    journal = summarize_journal(journal_result.stdout if journal_result.returncode == 0 else "")
    disk = shutil.disk_usage("/")

    content = render_runtime_report(
        generated_at=timestamp(),
        service=service,
        health=health,
        disk_total=disk.total,
        disk_used=disk.used,
        disk_free=disk.free,
        journal=journal,
    )
    atomic_write(
        report_dir / "logs.txt",
        content,
        group_name=report_group,
    )

    service_ok = (
        service_result.returncode == 0
        and service.get("ActiveState") == "active"
        and service.get("SubState") == "running"
    )
    return 0 if service_ok and health.get("status") == "ok" else 1


def tests_report(
    *,
    report_dir: Path,
    report_group: str,
    app_dir: Path,
    python_executable: Path,
) -> int:
    """Uruchamia testy i publikuje wyłącznie ich zbiorczy wynik."""

    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
        }
    )
    base_temp = Path(tempfile.gettempdir()) / f"sp2-audit-pytest-{os.getpid()}"

    pytest_started = time.monotonic()
    try:
        pytest_result = run_command(
            [
                str(python_executable),
                "-m",
                "pytest",
                "-q",
                "--disable-warnings",
                "-p",
                "no:cacheprovider",
                "--basetemp",
                str(base_temp),
            ],
            cwd=app_dir,
            timeout=300,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        pytest_result = subprocess.CompletedProcess([], 124, "", "")
    finally:
        if base_temp.parent == Path(tempfile.gettempdir()) and base_temp.name.startswith(
            "sp2-audit-pytest-"
        ):
            shutil.rmtree(base_temp, ignore_errors=True)
    pytest_seconds = time.monotonic() - pytest_started

    ruff_started = time.monotonic()
    try:
        ruff_result = run_command(
            [
                str(python_executable),
                "-m",
                "ruff",
                "check",
                "app",
                "tests",
                "--no-cache",
            ],
            cwd=app_dir,
            timeout=120,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        ruff_result = subprocess.CompletedProcess([], 124, "", "")
    ruff_seconds = time.monotonic() - ruff_started

    content = render_tests_report(
        generated_at=timestamp(),
        pytest_returncode=pytest_result.returncode,
        pytest_counts=parse_pytest_counts(pytest_result.stdout + "\n" + pytest_result.stderr),
        pytest_seconds=pytest_seconds,
        ruff_returncode=ruff_result.returncode,
        ruff_seconds=ruff_seconds,
    )
    atomic_write(
        report_dir / "checks.txt",
        content,
        group_name=report_group,
    )

    return 0 if pytest_result.returncode == 0 and ruff_result.returncode == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bezpieczne raporty diagnostyczne SP2 ADMIN",
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    runtime_parser = subparsers.add_parser("runtime")
    runtime_parser.add_argument(
        "--report-dir",
        type=Path,
        default=DEFAULT_REPORT_DIR,
    )
    runtime_parser.add_argument(
        "--report-group",
        default="codex-audit",
    )
    runtime_parser.add_argument(
        "--health-url",
        default="http://127.0.0.1/health",
    )
    runtime_parser.add_argument(
        "--health-host",
        default="dc.sp2.lan",
    )

    tests_parser = subparsers.add_parser("tests")
    tests_parser.add_argument(
        "--report-dir",
        type=Path,
        default=DEFAULT_REPORT_DIR,
    )
    tests_parser.add_argument(
        "--report-group",
        default="codex-audit",
    )
    tests_parser.add_argument(
        "--app-dir",
        type=Path,
        default=DEFAULT_APP_DIR,
    )
    tests_parser.add_argument(
        "--python",
        type=Path,
        default=DEFAULT_APP_DIR / ".venv/bin/python",
    )

    return parser


def main() -> int:
    arguments = build_parser().parse_args()

    if arguments.mode == "runtime":
        return runtime_report(
            arguments.report_dir,
            arguments.report_group,
            arguments.health_url,
            arguments.health_host,
        )

    return tests_report(
        report_dir=arguments.report_dir,
        report_group=arguments.report_group,
        app_dir=arguments.app_dir,
        python_executable=arguments.python,
    )


if __name__ == "__main__":
    raise SystemExit(main())

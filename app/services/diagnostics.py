from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from flask import current_app

from app.extensions import db


DiagnosticStatus = Literal["info", "ok", "warning"]


@dataclass(frozen=True, slots=True)
class HealthCheck:
    """Pojedynczy wynik wspólnej diagnostyki aplikacji."""

    name: str
    status: DiagnosticStatus
    message: str


class DiagnosticsError(RuntimeError):
    """Błąd uniemożliwiający ukończenie diagnostyki."""


def run_health_checks() -> Iterator[HealthCheck]:
    """Uruchom diagnostykę katalogu instance, bazy danych i LDAP.

    Wyniki są zwracane kolejno, dzięki czemu CLI zachowuje dotychczasową
    kolejność komunikatów również wtedy, gdy późniejszy test zakończy się
    błędem. Ten sam strumień wyników może zostać użyty przez panel WWW.
    """
    instance_dir = Path(current_app.instance_path)

    yield HealthCheck(
        name="application",
        status="info",
        message=(
            f"Aplikacja: {current_app.config['APP_NAME']} "
            f"{current_app.config['APP_VERSION']}"
        ),
    )
    yield HealthCheck(
        name="instance_path",
        status="info",
        message=f"Instance: {instance_dir}",
    )
    yield HealthCheck(
        name="database_uri",
        status="info",
        message=f"Baza: {current_app.config['SQLALCHEMY_DATABASE_URI']}",
    )

    try:
        instance_dir.mkdir(parents=True, exist_ok=True)
        probe = instance_dir / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        raise DiagnosticsError(
            f"Katalog instance nie jest zapisywalny: {exc}"
        ) from exc

    yield HealthCheck(
        name="instance_writable",
        status="ok",
        message="[OK] Katalog instance jest zapisywalny.",
    )

    try:
        db.create_all()
        db.session.execute(db.text("SELECT 1"))
    except Exception as exc:
        raise DiagnosticsError(f"Baza danych nie działa: {exc}") from exc

    yield HealthCheck(
        name="database",
        status="ok",
        message="[OK] Baza danych działa.",
    )

    required = (
        "LDAP_URI",
        "LDAP_BIND_DN",
        "LDAP_BIND_PASSWORD",
        "LDAP_BASE_DN",
    )
    missing = [key for key in required if not current_app.config.get(key)]

    if current_app.config.get("PREVIEW_DEMO_DATA"):
        yield HealthCheck(
            name="ldap_config",
            status="info",
            message="[DEMO] Katalog LDAP jest odłączony; dane są przykładowe.",
        )
    elif missing:
        yield HealthCheck(
            name="ldap_config",
            status="warning",
            message="[UWAGA] Brak ustawień LDAP: " + ", ".join(missing),
        )
    else:
        yield HealthCheck(
            name="ldap_config",
            status="ok",
            message="[OK] Podstawowa konfiguracja LDAP jest ustawiona.",
        )

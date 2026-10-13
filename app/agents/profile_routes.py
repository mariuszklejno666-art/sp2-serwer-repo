from __future__ import annotations

import subprocess

from flask import current_app, jsonify, request

from app.directory.service import DirectoryError, DirectoryService, computer_name
from app.domain_naming import (
    ComputerNameError,
    admin_computer_name,
    computer_name_exists,
    room_computer_name,
    teacher_computer_name,
)
from app.extensions import csrf, db
from app.models import AgentComputer, DomainRecovery

from . import api_bp
from .routes import _enrollment_authorized

PROFILE_TARGETS = {
    "Sala11": "OU=Sala11,OU=Komputery,DC=sp2,DC=lan",
    "Sala32": "OU=Sala32,OU=Komputery,DC=sp2,DC=lan",
    "Sala4": "OU=Sala4,OU=Komputery,DC=sp2,DC=lan",
    "Sala7": "OU=Sala7,OU=Komputery,DC=sp2,DC=lan",
    "Nauczyciel": "OU=Nauczyciele,OU=Komputery,DC=sp2,DC=lan",
    "Administracja": "OU=Administracja,OU=Komputery,DC=sp2,DC=lan",
}
PROFILE_HELPER = "/usr/local/sbin/sp2-agent-profile-assign"


def _normalize_hostname(value: object) -> str:
    hostname = str(value or "").strip().upper().rstrip("$")
    if not hostname or len(hostname) > 63:
        raise ValueError("Nieprawidłowa nazwa komputera.")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    if any(char not in allowed for char in hostname):
        raise ValueError("Nazwa komputera zawiera niedozwolone znaki.")
    return hostname


@api_bp.post("/domain/name-preview")
@csrf.exempt
def domain_name_preview():
    """Wyznacza nazwę komputera dla paczki USB.

    Endpoint akceptuje wyłącznie token rejestracyjny agenta, zamkniętą listę
    profili i nie udostępnia innych danych katalogowych.
    """
    if not _enrollment_authorized():
        return jsonify(error="unauthorized"), 401

    payload = request.get_json(silent=True) or {}
    profile = str(payload.get("profile") or "").strip()
    target_ou = PROFILE_TARGETS.get(profile)
    if target_ou is None:
        return jsonify(error="Nieobsługiwany profil instalacyjny."), 400

    try:
        existing_names = [
            computer_name(item)
            for item in DirectoryService().computers(limit=0)
        ]
        existing_names.extend(db.session.scalars(
            db.select(DomainRecovery.reserved_name).where(
                DomainRecovery.reserved_name.is_not(None)
            )
        ).all())
        available_numbers: list[int] | None = None
        station_number: int | None = None
        if profile.startswith("Sala"):
            requested_number = str(payload.get("station_number") or "").strip()
            if requested_number:
                candidate = room_computer_name(profile, requested_number)
                available = not computer_name_exists(candidate, existing_names)
            else:
                available_numbers = [
                    number
                    for number in range(1, 100)
                    if not computer_name_exists(
                        room_computer_name(profile, number),
                        existing_names,
                    )
                ]
                if not available_numbers:
                    raise ComputerNameError(
                        f"Brak wolnych nazw komputerów w {profile}."
                    )
                station_number = available_numbers[0]
                candidate = room_computer_name(profile, station_number)
                available = True
        elif profile == "Nauczyciel":
            candidate = teacher_computer_name(
                existing_names=existing_names,
            )
            available = True
        else:
            candidate = admin_computer_name(existing_names)
            available = True
    except ComputerNameError as exc:
        return jsonify(error=str(exc)), 400
    except DirectoryError as exc:
        return jsonify(error=str(exc)), 503

    response = {
        "status": "available" if available else "conflict",
        "computer_name": candidate,
        "available": available,
        "profile": profile,
        "target_ou": target_ou,
    }
    if available_numbers is not None:
        response["available_numbers"] = available_numbers
        response["station_number"] = station_number
    return jsonify(response), 200


@api_bp.post("/profile/assign")
@csrf.exempt
def assign_profile():
    """Przypisuje komputer do profilu/OU podczas instalacji z paczki USB.

    Endpoint używa wyłącznie tokenu enrollment i akceptuje zamkniętą listę profili.
    Właściwa operacja AD wykonywana jest przez minimalny helper sudo z allowlistą.
    """
    if not _enrollment_authorized():
        return jsonify(error="unauthorized"), 401

    payload = request.get_json(silent=True) or {}
    try:
        hostname = _normalize_hostname(payload.get("hostname"))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    profile = str(payload.get("profile") or payload.get("room") or "").strip()
    target_ou = PROFILE_TARGETS.get(profile)
    if target_ou is None:
        return jsonify(error="Nieobsługiwany profil instalacyjny."), 400

    completed = subprocess.run(
        ["sudo", "-n", PROFILE_HELPER, hostname, profile],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    output = ((completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")).strip()
    if completed.returncode != 0:
        # Agent może być instalowany chwilę przed utworzeniem/przeniesieniem obiektu AD.
        # Nie unieważniamy rejestracji; klient może ponowić przypisanie tą samą paczką.
        return jsonify(
            status="pending",
            hostname=hostname,
            profile=profile,
            target_ou=target_ou,
            message=output or "Nie udało się jeszcze przenieść komputera w AD.",
        ), 202

    agent = db.session.scalar(
        db.select(AgentComputer).where(AgentComputer.hostname == hostname)
    )
    if agent is not None:
        agent.room = profile
        agent.ou = target_ou
        db.session.commit()

    return jsonify(
        status="assigned",
        hostname=hostname,
        profile=profile,
        target_ou=target_ou,
        message=output,
    ), 200


@api_bp.post("/domain/join-credential")
@csrf.exempt
def domain_join_credential():
    """Zwraca dane logowania konta serwisowego do dolaczania komputerow.

    Chronione tym samym jednorazowym enrollment_code co /domain/name-preview.
    Haslo nigdy nie jest zapisywane na USB - agent pobiera je tuz przed
    Add-Computer i trzyma tylko w pamieci procesu.
    """
    if not _enrollment_authorized():
        return jsonify(error="unauthorized"), 401

    return service_join_credential()


def service_join_credential():
    """Called only after the caller has authorized a specific enrollment/plan."""

    user = str(current_app.config.get("AD_JOIN_SERVICE_USER", "")).strip()
    password = str(current_app.config.get("AD_JOIN_SERVICE_PASSWORD", "")).strip()
    if not user or not password:
        return jsonify(error="Konto serwisowe nie jest skonfigurowane."), 503

    response = jsonify(username=user, password=password)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response

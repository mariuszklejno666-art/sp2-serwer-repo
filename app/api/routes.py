from __future__ import annotations

import hmac
from datetime import datetime, timezone
from typing import Any

from flask import abort, current_app, jsonify, request

from app.extensions import csrf, db
from app.models import AgentComputer, DomainRecovery
from app.directory.service import (
    DirectoryError,
    DirectoryService,
    account_enabled,
    computer_name,
    first_value,
    ou_path,
)
from app.domain_naming import (
    ComputerNameError,
    WINDOWS_COMPUTER_NAME_MAX_LENGTH,
    admin_computer_name,
    computer_name_exists,
    distinguished_name_within,
    naming_mode_for_ou,
    ou_name_from_dn,
    room_computer_name,
    teacher_computer_name,
)

from . import bp


def _authorized() -> bool:
    expected_tokens = (
        str(current_app.config.get("SP2_API_TOKEN", "")).strip(),
        str(current_app.config.get("SP2_API_TOKEN_PREVIOUS", "")).strip(),
    )
    supplied = request.headers.get("Authorization", "").strip()
    if supplied.lower().startswith("bearer "):
        supplied = supplied[7:].strip()
    if not supplied:
        return False
    return any(
        token and hmac.compare_digest(token, supplied)
        for token in expected_tokens
    )


def _enrollment_authorized() -> bool:
    supplied = request.headers.get("Authorization", "").strip()
    if supplied.lower().startswith("bearer "):
        supplied = supplied[7:].strip()

    if not supplied:
        return False

    enrollment_token = str(
        current_app.config.get("AGENT_ENROLLMENT_TOKEN", "")
    ).strip()

    return bool(
        enrollment_token
        and hmac.compare_digest(enrollment_token, supplied)
    )


def _require_token() -> None:
    if not _authorized():
        abort(401)


def _text(value: Any, default: str = "") -> str:
    if isinstance(value, list):
        value = value[0] if value else default
    return default if value in (None, "") else str(value)


def _user_payload(item: dict[str, Any]) -> dict[str, Any]:
    username = first_value(item, "sAMAccountName", "")
    return {
        "username": username,
        "display_name": first_value(item, "displayName", username),
        "email": first_value(item, "mail", ""),
        "enabled": account_enabled(item),
        "distinguished_name": first_value(item, "distinguishedName", ""),
    }


def _computer_payload(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": first_value(item, "name", first_value(item, "sAMAccountName", "")).rstrip("$"),
        "dns_hostname": first_value(item, "dNSHostName", ""),
        "operating_system": first_value(item, "operatingSystem", ""),
        "operating_system_version": first_value(item, "operatingSystemVersion", ""),
        "enabled": account_enabled(item),
        "distinguished_name": first_value(item, "distinguishedName", ""),
    }


def _join_settings() -> tuple[str, str, tuple[str, ...], tuple[str, ...], str]:
    return (
        str(current_app.config.get("AD_DOMAIN_FQDN", "")).strip(),
        str(current_app.config.get("AD_DOMAIN_NETBIOS", "")).strip(),
        tuple(current_app.config.get("AD_DNS_SERVERS", ())),
        tuple(current_app.config.get("AD_JOIN_ALLOWED_OU_BASES", ())),
        str(current_app.config.get("LDAP_BASE_DN", "")).strip(),
    )


@bp.before_request
def authenticate_api() -> None:
    enrollment_paths = {
        "/api/v1/domain/join-options",
        "/api/v1/domain/name-preview",
    }

    if request.path in enrollment_paths and _enrollment_authorized():
        return

    _require_token()


@bp.get("/health")
@csrf.exempt
def health():
    return jsonify(
        status="ok",
        api_version="v1",
        app_version=current_app.config.get("APP_VERSION", "unknown"),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@bp.get("/dashboard")
@csrf.exempt
def dashboard():
    service = DirectoryService()
    try:
        users = service.users()
        groups = service.groups()
        computers = service.computers()
    except DirectoryError as exc:
        return jsonify(error=str(exc)), 503

    threshold = current_app.config["AGENT_OFFLINE_AFTER_SECONDS"]
    agents = db.session.scalars(db.select(AgentComputer)).all()
    online = sum(1 for agent in agents if agent.is_online(threshold))
    return jsonify(
        users=len(users),
        groups=len(groups),
        computers=len(computers),
        agents_total=len(agents),
        agents_online=online,
        agents_offline=max(0, len(agents) - online),
    )


@bp.get("/users")
@csrf.exempt
def users():
    query = request.args.get("q", "").strip()
    limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
    try:
        records = DirectoryService().users(query=query)
    except DirectoryError as exc:
        return jsonify(error=str(exc)), 503
    payload = [_user_payload(item) for item in records[:limit]]
    return jsonify(items=payload, count=len(payload), total=len(records))


@bp.get("/users/<username>")
@csrf.exempt
def user_details(username: str):
    try:
        item = DirectoryService().user(username)
    except DirectoryError as exc:
        return jsonify(error=str(exc)), 503
    if item is None:
        return jsonify(error="Nie znaleziono użytkownika."), 404
    payload = _user_payload(item)
    payload.update(
        {
            "telephone": first_value(item, "telephoneNumber", ""),
            "description": first_value(item, "description", ""),
            "groups": item.get("memberOf", []) if isinstance(item.get("memberOf", []), list) else [item.get("memberOf")],
            "created_at": _text(item.get("whenCreated")),
            "password_last_set": _text(item.get("pwdLastSet")),
            "last_logon": _text(item.get("lastLogonTimestamp")),
        }
    )
    return jsonify(payload)


@bp.get("/groups")
@csrf.exempt
def groups():
    query = request.args.get("q", "").strip()
    limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
    try:
        records = DirectoryService().groups(query=query)
    except DirectoryError as exc:
        return jsonify(error=str(exc)), 503
    items = [
        {
            "name": first_value(item, "name", first_value(item, "sAMAccountName", "")),
            "description": first_value(item, "description", ""),
            "distinguished_name": first_value(item, "distinguishedName", ""),
        }
        for item in records[:limit]
    ]
    return jsonify(items=items, count=len(items), total=len(records))


@bp.get("/computers")
@csrf.exempt
def computers():
    query = request.args.get("q", "").strip()
    limit = min(max(request.args.get("limit", 100, type=int), 1), 500)
    try:
        records = DirectoryService().computers(query=query)
    except DirectoryError as exc:
        return jsonify(error=str(exc)), 503
    items = [_computer_payload(item) for item in records[:limit]]
    return jsonify(items=items, count=len(items), total=len(records))


@bp.get("/domain/join-options")
@csrf.exempt
def domain_join_options():
    (
        domain_fqdn,
        domain_netbios,
        dns_servers,
        allowed_bases,
        ldap_base,
    ) = _join_settings()

    missing = [
        name
        for name, value in {
            "AD_DOMAIN_FQDN": domain_fqdn,
            "AD_DOMAIN_NETBIOS": domain_netbios,
            "AD_DNS_SERVERS": dns_servers,
            "AD_JOIN_ALLOWED_OU_BASES": allowed_bases,
            "LDAP_BASE_DN": ldap_base,
        }.items()
        if not value
    ]
    if missing:
        return jsonify(
            error="Kreator domeny nie jest skonfigurowany.",
            missing=missing,
        ), 503

    invalid_bases = [
        base
        for base in allowed_bases
        if not distinguished_name_within(base, ldap_base)
    ]
    if invalid_bases:
        return jsonify(
            error="Dozwolona jednostka OU znajduje się poza domeną.",
        ), 503

    try:
        records = DirectoryService().organizational_units()
    except DirectoryError as exc:
        return jsonify(error=str(exc)), 503

    organizational_units = []
    for record in records:
        dn = first_value(
            record,
            "distinguishedName",
            str(record.get("dn", "")),
        )
        if not dn or not any(
            distinguished_name_within(dn, base)
            for base in allowed_bases
        ):
            continue
        organizational_units.append(
            {
                "name": first_value(record, "ou", ou_path(dn)),
                "path": ou_path(dn),
                "distinguished_name": dn,
                "naming_mode": naming_mode_for_ou(dn),
            }
        )

    return jsonify(
        schema_version=1,
        read_only=True,
        operations={"join": False, "unjoin": False},
        domain={
            "fqdn": domain_fqdn,
            "netbios": domain_netbios,
            "dns_servers": list(dns_servers),
        },
        naming={
            "max_length": WINDOWS_COMPUTER_NAME_MAX_LENGTH,
            "room_pattern": "S{NUMER_SALI}-{NUMER_KOMPUTERA:02d}",
            "teacher_pattern": "NAU-{NUMER:03d}",
            "teacher_range": [1, 199],
            "admin_pattern": "ADM-{NUMER:03d}",
        },
        organizational_units=organizational_units,
    )


@bp.post("/domain/name-preview")
@csrf.exempt
def domain_name_preview():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Oczekiwano obiektu JSON."), 400

    mode = str(payload.get("mode", "")).strip().casefold()
    target_ou = str(payload.get("organizational_unit", "")).strip()
    _, _, _, allowed_bases, ldap_base = _join_settings()

    if not ldap_base or not allowed_bases:
        return jsonify(error="Kreator domeny nie jest skonfigurowany."), 503
    if any(
        not distinguished_name_within(base, ldap_base)
        for base in allowed_bases
    ):
        return jsonify(error="Konfiguracja dozwolonych OU jest nieprawidłowa."), 503
    if not target_ou or not any(
        distinguished_name_within(target_ou, base)
        for base in allowed_bases
    ):
        return jsonify(error="Wybrana jednostka OU nie jest dozwolona."), 400
    if mode != naming_mode_for_ou(target_ou):
        return jsonify(error="Wybrana jednostka OU nie pasuje do trybu nazwy."), 400
    teacher_computer_ou = str(
        current_app.config.get("AD_TEACHER_COMPUTER_OU", "")
    ).strip()
    if (
        mode == "teacher"
        and teacher_computer_ou
        and target_ou.casefold() != teacher_computer_ou.casefold()
    ):
        return jsonify(error="Wybrano nieprawidłową OU komputerów nauczycieli."), 400

    try:
        service = DirectoryService()
        organizational_units = service.organizational_units()
        known_ous = {
            first_value(
                item,
                "distinguishedName",
                str(item.get("dn", "")),
            ).casefold()
            for item in organizational_units
            if first_value(
                item,
                "distinguishedName",
                str(item.get("dn", "")),
            )
        }
        if target_ou.casefold() not in known_ous:
            return jsonify(error="Wybrana jednostka OU nie istnieje."), 400

        existing_names = [
            computer_name(item)
            for item in service.computers(limit=0)
        ]
        existing_names.extend(db.session.scalars(
            db.select(DomainRecovery.reserved_name).where(
                DomainRecovery.reserved_name.is_not(None)
            )
        ).all())
        if mode == "room":
            room = ou_name_from_dn(target_ou)
            candidate = room_computer_name(room, payload.get("number"))
            available = not computer_name_exists(candidate, existing_names)
        elif mode == "teacher":
            candidate = teacher_computer_name(
                payload.get("given_name"),
                payload.get("surname"),
                existing_names,
            )
            available = True
        elif mode == "admin":
            candidate = admin_computer_name(existing_names)
            available = True
        else:
            return jsonify(error="Nieznany tryb nazewnictwa."), 400
    except ComputerNameError as exc:
        return jsonify(error=str(exc)), 400
    except DirectoryError as exc:
        return jsonify(error=str(exc)), 503

    return jsonify(
        read_only=True,
        mode=mode,
        computer_name=candidate,
        available=available,
        organizational_unit=target_ou,
        operations={"join": False, "unjoin": False},
    )

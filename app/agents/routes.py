from __future__ import annotations

import hmac
import time
from datetime import datetime, timedelta, timezone

from flask import (
    Response,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import or_

from app.extensions import csrf, db
from app.models import (
    AgentArchive,
    AgentComputer,
    AgentEnrollmentCode,
    AgentEnrollmentUse,
    AgentJob,
    AgentRegistration,
    AuditLog,
)
from app.permissions import is_school_management
from app.remote_desktop import (
    build_rdp_file,
    build_shadow_command,
    rdp_target_address,
    safe_rdp_filename,
)
from app.room_assignment import effective_room

from . import api_bp, bp
from .silent_profiles import (
    PROFILES,
    require_agent_package,
    require_silent_package,
    resolve_profile,
)
from .software_catalog import (
    CatalogError,
    add_package,
    agent_supports_legacy_bundle,
    agent_supports_multifile,
    available_packages,
    delete_package,
    get_installable_package,
    get_package_file_by_index,
    load_catalog,
    packages_dir,
    remove_package_files,
    save_catalog,
    save_package_uploads,
    toggle_package,
)

ALLOWED_ACTIONS = {
    "inventory",
    "message",
    "restart",
    "shutdown",
    "hostname",
    "ipconfig",
    "systeminfo",
    "gpupdate",
    "list_services",
    "list_processes",
    "install_software",
    "install_software_interactive",
    "self_update",
}


def _supplied_token() -> str:
    supplied = request.headers.get("Authorization", "").strip()
    if supplied.lower().startswith("bearer "):
        supplied = supplied[7:].strip()
    return supplied


def _shared_authorized() -> bool:
    supplied = _supplied_token()
    if not supplied:
        return False
    expected_tokens = (
        str(
            current_app.config.get("SP2_API_TOKEN")
            or current_app.config.get("AGENT_API_TOKEN")
            or ""
        ).strip(),
        str(current_app.config.get("SP2_API_TOKEN_PREVIOUS", "")).strip(),
    )
    return any(
        token and hmac.compare_digest(token, supplied)
        for token in expected_tokens
    )


def _enrollment_credential() -> tuple[str, AgentEnrollmentCode | None] | None:
    supplied = _supplied_token()
    if not supplied:
        return None

    enrollment_token = str(
        current_app.config.get("AGENT_ENROLLMENT_TOKEN") or ""
    ).strip()
    if enrollment_token and hmac.compare_digest(enrollment_token, supplied):
        return ("legacy", None)
    if _shared_authorized():
        return ("legacy", None)

    code = db.session.scalar(
        db.select(AgentEnrollmentCode).where(
            AgentEnrollmentCode.code_hash == AgentEnrollmentCode.hash_code(supplied),
        )
    )
    if code is None:
        return None
    expires_at = code.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        return None

    return ("multi-use", code)


def _consume_enrollment_code(code: AgentEnrollmentCode, hostname: str) -> bool:
    """Reserve one workstation slot for a reusable USB enrollment code."""
    normalized = hostname.strip().upper()
    existing = db.session.scalar(
        db.select(AgentEnrollmentUse).where(
            AgentEnrollmentUse.enrollment_code_id == code.id,
            AgentEnrollmentUse.hostname == normalized,
        )
    )
    if existing is not None:
        return True

    max_uses = max(1, int(current_app.config.get("AGENT_ENROLLMENT_MAX_USES", 100)))
    use_count = db.session.scalar(
        db.select(db.func.count(AgentEnrollmentUse.id)).where(
            AgentEnrollmentUse.enrollment_code_id == code.id
        )
    ) or 0
    if use_count >= max_uses:
        return False

    if code.used_at is None:
        code.used_at = datetime.now(timezone.utc)
    db.session.add(
        AgentEnrollmentUse(
            enrollment_code_id=code.id,
            hostname=normalized,
        )
    )
    return True


def _enrollment_authorized() -> bool:
    # Zgodność dla endpointów kreatora, które tylko sprawdzają poświadczenie.
    # Kod jest zużywany wyłącznie przez /register.
    return _enrollment_credential() is not None


def _registered_agent_for_token() -> AgentComputer | None:
    supplied = _supplied_token()
    if not supplied:
        return None
    token_hash = AgentRegistration.hash_token(supplied)
    registration = db.session.scalar(
        db.select(AgentRegistration).where(
            AgentRegistration.token_hash == token_hash
        )
    )
    return registration.computer if registration is not None else None


def _authorized(hostname: str | None = None) -> bool:
    # Wspólny token pozostaje obsługiwany dla zgodności ze starszymi agentami.
    if _shared_authorized():
        return True
    agent = _registered_agent_for_token()
    if agent is None:
        return False
    return hostname is None or hmac.compare_digest(agent.hostname, hostname)


def _administrator_required() -> None:
    if not current_user.is_authenticated or current_user.role != "administrator":
        abort(403)


def _audit(action: str, result: str, details: str) -> None:
    db.session.add(
        AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action=action,
            result=result,
            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
            details=details[:500],
        )
    )


def _normalize_hostname(payload: dict) -> str:
    hostname = str(payload.get("hostname", "")).strip().upper()
    if not hostname or len(hostname) > 255:
        raise ValueError("Nieprawidłowa nazwa komputera.")
    return hostname


def _update_agent(agent: AgentComputer, payload: dict) -> None:
    text_fields = (
        "fqdn", "ou", "room", "os_name", "os_version", "username",
        "serial_number", "manufacturer", "model", "cpu", "agent_version",
    )
    for field in text_fields:
        value = payload.get(field)
        if value is not None:
            limit = 512 if field == "ou" else 255
            setattr(agent, field, str(value).strip()[:limit])

    # Starsze paczki nie zawsze przesyłały pole room po restarcie. Nazwa
    # S11-/S32-/S4-/S7- jest jednak jednoznaczna i nie powinna pozostawiać
    # komputera poza widokiem sal.
    agent.room = effective_room(agent.room, agent.hostname)

    for field in ("ip_addresses", "mac_addresses", "disks"):
        value = payload.get(field)
        if isinstance(value, list):
            setattr(agent, field, value)

    ram = payload.get("ram_bytes")
    if isinstance(ram, (int, float)) and ram >= 0:
        agent.ram_bytes = int(ram)

    cpu_percent = payload.get("cpu_percent")
    if isinstance(cpu_percent, (int, float)) and 0 <= cpu_percent <= 100:
        agent.cpu_percent = round(float(cpu_percent), 1)

    memory_percent = payload.get("memory_percent")
    if isinstance(memory_percent, (int, float)) and 0 <= memory_percent <= 100:
        agent.memory_percent = round(float(memory_percent), 1)

    uptime_seconds = payload.get("uptime_seconds")
    if isinstance(uptime_seconds, (int, float)) and uptime_seconds >= 0:
        agent.uptime_seconds = int(uptime_seconds)

    if "console_session" in payload:
        console_session = payload.get("console_session")
        if console_session is None:
            agent.console_session = None
        elif (
            isinstance(console_session, dict)
            and isinstance(console_session.get("session_id"), int)
            and isinstance(console_session.get("username"), str)
        ):
            agent.console_session = {
                "username": str(console_session["username"])[:255],
                "session_id": int(console_session["session_id"]),
                "session_name": str(console_session.get("session_name", ""))[:64],
                **(
                    {
                        "sid": str(console_session.get("sid", ""))[:200],
                        "logon_id": str(console_session.get("logon_id", ""))[:100],
                        "interactive_ready": console_session.get("interactive_ready") is True,
                    }
                    if "interactive_ready" in console_session
                    else {}
                ),
            }

    collected_at = payload.get("collected_at")
    if collected_at:
        try:
            agent.metrics_collected_at = datetime.fromisoformat(
                str(collected_at).replace("Z", "+00:00")
            )
        except ValueError:
            pass

    boot = payload.get("boot_time")
    if boot:
        try:
            agent.boot_time = datetime.fromisoformat(str(boot).replace("Z", "+00:00"))
        except ValueError:
            pass
    agent.last_seen = datetime.now(timezone.utc)


def _save_agent(payload: dict) -> tuple[AgentComputer, bool]:
    hostname = _normalize_hostname(payload)
    agent = db.session.scalar(db.select(AgentComputer).where(AgentComputer.hostname == hostname))
    created = agent is None
    if agent is None:
        agent = AgentComputer(hostname=hostname)
        db.session.add(agent)
    _update_agent(agent, payload)
    if agent.id is not None:
        archive = db.session.scalar(
            db.select(AgentArchive).where(
                AgentArchive.computer_id == agent.id
            )
        )
        if archive is not None:
            # Jeżeli stary agent ponownie się odezwie, automatycznie wraca
            # na listę. Chroni to przed ukryciem nadal używanego komputera.
            db.session.delete(archive)
    db.session.commit()
    return agent, created


def _legacy_agent_candidates(
    agents: list[AgentComputer],
    threshold_seconds: int,
) -> list[dict[str, object]]:
    legacy_prefixes = ("DESKTOP-", "LAPTOP-")
    ignored_serials = {
        "", "NONE", "UNKNOWN", "DEFAULT STRING", "TO BE FILLED BY O.E.M.",
    }
    candidates: list[dict[str, object]] = []

    for old_agent in agents:
        if not old_agent.hostname.startswith(legacy_prefixes):
            continue
        if old_agent.is_online(threshold_seconds):
            continue

        old_serial = str(old_agent.serial_number or "").strip().upper()
        old_macs = {
            str(value).strip().upper()
            for value in (old_agent.mac_addresses or [])
            if str(value).strip()
        }
        matches: list[tuple[AgentComputer, str]] = []
        for current_agent in agents:
            if current_agent.id == old_agent.id:
                continue
            if current_agent.hostname.startswith(legacy_prefixes):
                continue

            current_serial = str(current_agent.serial_number or "").strip().upper()
            current_macs = {
                str(value).strip().upper()
                for value in (current_agent.mac_addresses or [])
                if str(value).strip()
            }
            if (
                old_serial not in ignored_serials
                and current_serial == old_serial
            ):
                matches.append((current_agent, "numer seryjny"))
            elif old_macs and old_macs.intersection(current_macs):
                matches.append((current_agent, "adres MAC"))

        matches.sort(
            key=lambda item: item[0].last_seen.timestamp() if item[0].last_seen else 0,
            reverse=True,
        )
        successor, reason = matches[0] if matches else (None, None)
        candidates.append({
            "legacy": old_agent,
            "successor": successor,
            "reason": reason,
        })

    return candidates


@bp.get("/cleanup")
@login_required
def cleanup_preview():
    _administrator_required()
    threshold = current_app.config["AGENT_OFFLINE_AFTER_SECONDS"]
    archived_ids = db.select(AgentArchive.computer_id)
    agents = db.session.scalars(
        db.select(AgentComputer)
        .where(AgentComputer.id.not_in(archived_ids))
        .order_by(AgentComputer.hostname)
    ).all()
    candidates = _legacy_agent_candidates(agents, threshold)
    matched_count = sum(item["successor"] is not None for item in candidates)

    archive_rows = db.session.scalars(
        db.select(AgentArchive).order_by(AgentArchive.archived_at.desc())
    ).all()
    archived = [{
        "archive": row,
        "legacy": db.session.get(AgentComputer, row.computer_id),
        "successor": db.session.get(AgentComputer, row.successor_id)
        if row.successor_id else None,
    } for row in archive_rows]

    return render_template(
        "agents/cleanup.html",
        candidates=candidates,
        archived=archived,
        matched_count=matched_count,
        unmatched_count=len(candidates) - matched_count,
    )


@bp.post("/cleanup/<int:agent_id>/archive")
@login_required
def archive_agent(agent_id: int):
    _administrator_required()
    if request.form.get("confirm") != "archive":
        flash("Archiwizacja wymaga jawnego potwierdzenia.", "danger")
        return redirect(url_for("agents.cleanup_preview"))

    if db.session.scalar(
        db.select(AgentArchive).where(AgentArchive.computer_id == agent_id)
    ):
        flash("Ten rekord jest już zarchiwizowany.", "warning")
        return redirect(url_for("agents.cleanup_preview"))

    threshold = current_app.config["AGENT_OFFLINE_AFTER_SECONDS"]
    archived_ids = db.select(AgentArchive.computer_id)
    agents = db.session.scalars(
        db.select(AgentComputer).where(AgentComputer.id.not_in(archived_ids))
    ).all()
    candidate = next(
        (
            item for item in _legacy_agent_candidates(agents, threshold)
            if item["legacy"].id == agent_id and item["successor"] is not None
        ),
        None,
    )
    if candidate is None:
        flash(
            "Rekord nie ma obecnie jednoznacznie dopasowanego następcy.",
            "danger",
        )
        return redirect(url_for("agents.cleanup_preview"))

    successor = candidate["successor"]
    submitted_successor_id = request.form.get("successor_id", type=int)
    if submitted_successor_id != successor.id:
        flash("Dopasowanie zmieniło się. Odśwież ekran i sprawdź ponownie.", "danger")
        return redirect(url_for("agents.cleanup_preview"))

    legacy = candidate["legacy"]
    archive = AgentArchive(
        computer_id=legacy.id,
        successor_id=successor.id,
        reason=str(candidate["reason"]),
        archived_by=current_user.username,
    )
    db.session.add(archive)
    _audit(
        "AGENT_ARCHIVE",
        "SUCCESS",
        f"legacy={legacy.hostname}; successor={successor.hostname}; "
        f"reason={candidate['reason']}",
    )
    db.session.commit()
    flash(
        f"Zarchiwizowano stary rekord {legacy.hostname}. "
        "Historia została zachowana.",
        "success",
    )
    return redirect(url_for("agents.cleanup_preview"))


@bp.post("/cleanup/archive/<int:archive_id>/restore")
@login_required
def restore_agent(archive_id: int):
    _administrator_required()
    if request.form.get("confirm") != "restore":
        flash("Przywrócenie wymaga jawnego potwierdzenia.", "danger")
        return redirect(url_for("agents.cleanup_preview"))

    archive = db.get_or_404(AgentArchive, archive_id)
    legacy = db.session.get(AgentComputer, archive.computer_id)
    legacy_name = legacy.hostname if legacy else f"ID {archive.computer_id}"
    _audit(
        "AGENT_ARCHIVE_RESTORE",
        "SUCCESS",
        f"legacy={legacy_name}; archive_id={archive.id}",
    )
    db.session.delete(archive)
    db.session.commit()
    flash(f"Przywrócono rekord {legacy_name} do listy agentów.", "success")
    return redirect(url_for("agents.cleanup_preview"))


@bp.get("")
@login_required
def index():
    query = request.args.get("q", "").strip()
    room = request.args.get("room", "").strip()
    status = request.args.get("status", "").strip().lower()
    threshold = current_app.config["AGENT_OFFLINE_AFTER_SECONDS"]

    archived_ids = db.select(AgentArchive.computer_id)
    statement = db.select(AgentComputer).where(
        AgentComputer.id.not_in(archived_ids)
    )
    if query:
        pattern = f"%{query}%"
        statement = statement.where(or_(
            AgentComputer.hostname.ilike(pattern),
            AgentComputer.fqdn.ilike(pattern),
            AgentComputer.username.ilike(pattern),
            AgentComputer.serial_number.ilike(pattern),
        ))
    if room:
        statement = statement.where(AgentComputer.room == room)

    agents = db.session.scalars(statement.order_by(AgentComputer.hostname)).all()
    if status == "online":
        agents = [agent for agent in agents if agent.is_online(threshold)]
    elif status == "offline":
        agents = [agent for agent in agents if not agent.is_online(threshold)]

    rooms = db.session.scalars(
        db.select(AgentComputer.room)
        .where(
            AgentComputer.id.not_in(archived_ids),
            AgentComputer.room.is_not(None),
            AgentComputer.room != "",
        )
        .distinct().order_by(AgentComputer.room)
    ).all()
    online_count = sum(agent.is_online(threshold) for agent in agents)
    return render_template(
        "agents/index.html", agents=agents, threshold=threshold, rooms=rooms,
        query=query, selected_room=room, selected_status=status,
        online_count=online_count, offline_count=len(agents) - online_count,
    )


@bp.get("/<int:agent_id>")
@login_required
def details(agent_id: int):
    agent = db.get_or_404(AgentComputer, agent_id)
    jobs = db.session.scalars(
        db.select(AgentJob).where(AgentJob.computer_id == agent.id)
        .order_by(AgentJob.created_at.desc()).limit(50)
    ).all()
    try:
        packages = available_packages()
        catalog_error = None
    except CatalogError as exc:
        packages, catalog_error = [], str(exc)

    shadow_commands = None
    if is_school_management() and agent.console_session:
        session_id = agent.console_session.get("session_id")
        address = rdp_target_address(agent)
        if address and isinstance(session_id, int):
            shadow_commands = {
                "view": build_shadow_command(address=address, session_id=session_id, control=False),
                "control": build_shadow_command(address=address, session_id=session_id, control=True),
            }
            _audit(
                "AGENT_SHADOW_VIEW",
                "SUCCESS",
                f"hostname={agent.hostname}; session_id={session_id}",
            )
            db.session.commit()

    return render_template(
        "agents/details.html", agent=agent, jobs=jobs,
        threshold=current_app.config["AGENT_OFFLINE_AFTER_SECONDS"],
        can_manage=current_user.role == "administrator",
        software_packages=packages, catalog_error=catalog_error,
        shadow_commands=shadow_commands,
    )


@bp.get("/<int:agent_id>/rdp")
@login_required
def remote_desktop_file(agent_id: int):
    _administrator_required()
    agent = db.get_or_404(AgentComputer, agent_id)
    address = rdp_target_address(agent)
    if not address:
        flash("Brak adresu (FQDN/IP/hostname) do połączenia RDP z tym komputerem.", "danger")
        return redirect(url_for("agents.details", agent_id=agent.id))

    content = build_rdp_file(
        address=address,
        domain=current_app.config.get("AD_DOMAIN_NETBIOS", ""),
    )
    _audit("AGENT_RDP_DOWNLOAD", "SUCCESS", f"hostname={agent.hostname}; address={address}")
    db.session.commit()
    return Response(
        content,
        mimetype="application/x-rdp",
        headers={
            "Content-Disposition": f"attachment; filename={safe_rdp_filename(agent.hostname)}"
        },
    )


@bp.get("/software")
@login_required
def software_catalog_page():
    _administrator_required()
    try:
        packages = available_packages()
        catalog_error = None
    except CatalogError as exc:
        packages, catalog_error = [], str(exc)
    return render_template(
        "agents/software.html",
        packages=packages,
        catalog_error=catalog_error,
        profiles=PROFILES,
    )


@bp.post("/software")
@login_required
def upload_software_package():
    _administrator_required()
    upload = request.files.get("installer_file")
    support_uploads = [
        item
        for item in request.files.getlist("support_files")
        if item is not None and item.filename
    ]
    package_id = str(request.form.get("package_id", "")).strip().lower()
    name = str(request.form.get("name", "")).strip()
    version = str(request.form.get("version", "")).strip()
    description = str(request.form.get("description", "")).strip()
    arguments = [
        line.strip()
        for line in str(request.form.get("arguments", "")).splitlines()
        if line.strip()
    ]

    if upload is None or not upload.filename:
        flash("Wybierz główny instalator (.exe lub .msi).", "danger")
        return redirect(url_for("agents.software_catalog_page"))
    if not package_id:
        flash("Podaj identyfikator pakietu.", "danger")
        return redirect(url_for("agents.software_catalog_page"))
    if package_id in load_catalog():
        flash(f"Pakiet o identyfikatorze „{package_id}” już istnieje.", "danger")
        return redirect(url_for("agents.software_catalog_page"))

    try:
        (
            storage_dir,
            installer_filename,
            installer_type,
            size,
            sha256,
            files,
        ) = save_package_uploads(package_id, upload, support_uploads)
    except CatalogError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("agents.software_catalog_page"))

    try:
        profile = str(request.form.get("silent_profile", "auto")).strip() or "auto"
        installer_path = packages_dir() / storage_dir / installer_filename
        arguments = resolve_profile(
            profile,
            installer_type,
            installer_filename,
            arguments,
            installer_path,
        )
        add_package(
            package_id=package_id,
            name=name,
            version=version,
            description=description,
            filename=installer_filename,
            installer_type=installer_type,
            arguments=arguments,
            sha256=sha256,
            storage_dir=storage_dir,
            files=files,
            purpose="agent" if profile == "agent" else "software",
            silent_profile=profile,
            source_filename=installer_filename,
            source_type=installer_type,
            file_names=[entry["filename"] for entry in files],
        )
    except CatalogError as exc:
        remove_package_files(
            {"storage_dir": storage_dir, "filename": installer_filename}
        )
        flash(str(exc), "danger")
        return redirect(url_for("agents.software_catalog_page"))

    _audit(
        "SOFTWARE_PACKAGE_UPLOAD",
        "SUCCESS",
        (
            f"id={package_id}; name={name}; type={installer_type}; "
            f"files={len(files)}; size={size}"
        ),
    )
    db.session.commit()
    flash(
        f"Pakiet „{name or package_id}” został dodany: "
        f"{len(files)} plik(ów), {size // (1024 * 1024)} MB.",
        "success",
    )
    return redirect(url_for("agents.software_catalog_page"))


@bp.post("/software/<package_id>/toggle")
@login_required
def toggle_software_package(package_id: str):
    _administrator_required()
    try:
        package = toggle_package(package_id)
    except CatalogError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("agents.software_catalog_page"))
    _audit(
        "SOFTWARE_PACKAGE_TOGGLE",
        "SUCCESS",
        f"id={package_id}; enabled={package['enabled']}",
    )
    db.session.commit()
    flash("Stan pakietu został zmieniony.", "success")
    return redirect(url_for("agents.software_catalog_page"))


@bp.post("/software/<package_id>/delete")
@login_required
def delete_software_package(package_id: str):
    _administrator_required()
    try:
        package = delete_package(package_id)
    except CatalogError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("agents.software_catalog_page"))
    remove_package_files(package)
    _audit("SOFTWARE_PACKAGE_DELETE", "SUCCESS", f"id={package_id}; name={package['name']}")
    db.session.commit()
    flash("Pakiet został usunięty.", "success")
    return redirect(url_for("agents.software_catalog_page"))


@bp.post("/software/<package_id>/deploy-agent-update")
@login_required
def deploy_agent_update(package_id: str):
    _administrator_required()
    if request.form.get("confirm") != "yes":
        flash("Potwierdź aktualizację agenta na wszystkich komputerach.", "danger")
        return redirect(url_for("agents.software_catalog_page"))
    try:
        package = require_agent_package(get_installable_package(package_id))
    except CatalogError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("agents.software_catalog_page"))

    payload = {
        "package_id": package["id"], "name": package["name"],
        "version": package["version"], "filename": package["filename"],
        "sha256": package["sha256"], "size": package["size"],
        "download_path": f"/api/v1/agent/software/{package['id']}/download",
    }

    agents = db.session.scalars(
        db.select(AgentComputer).where(
            AgentComputer.id.not_in(db.select(AgentArchive.computer_id))
        )
    ).all()
    queued = 0
    for agent in agents:
        # Pomiń komputery już na docelowej wersji — nie ma sensu ponownie
        # kolejkować pobrania i restartu agenta, który już ją ma.
        if package["version"] and agent.agent_version == package["version"]:
            continue
        db.session.add(
            AgentJob(computer=agent, action="self_update", payload=dict(payload), status="pending")
        )
        queued += 1

    _audit(
        "AGENT_FLEET_SELF_UPDATE",
        "SUCCESS",
        f"package={package['id']}; version={package['version']}; computers={queued}",
    )
    db.session.commit()
    if queued:
        flash(f"Zlecono aktualizację agenta na {queued} komputerach.", "success")
    else:
        flash("Wszystkie komputery są już na tej wersji agenta.", "info")
    return redirect(url_for("agents.software_catalog_page"))


@bp.post("/software/<package_id>/deploy-all")
@login_required
def deploy_software_to_all(package_id: str):
    _administrator_required()
    if request.form.get("confirm") != "yes":
        flash("Potwierdź instalację na wszystkich komputerach.", "danger")
        return redirect(url_for("agents.software_catalog_page"))
    try:
        package = require_silent_package(get_installable_package(package_id))
    except CatalogError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("agents.software_catalog_page"))

    agents = db.session.scalars(
        db.select(AgentComputer).where(
            AgentComputer.id.not_in(db.select(AgentArchive.computer_id))
        )
    ).all()
    if package["is_multifile"]:
        if package.get("legacy_bundle"):
            incompatible = [
                agent
                for agent in agents
                if not agent_supports_legacy_bundle(agent.agent_version)
            ]
            required_version = "2.7.1"
        else:
            incompatible = [
                agent
                for agent in agents
                if not agent_supports_multifile(agent.agent_version)
            ]
            required_version = "2.8.0"
        if incompatible:
            flash(
                "Ten pakiet zawiera wiele plików. Najpierw zaktualizuj SP2 Agent "
                f"do wersji {required_version} lub nowszej na "
                f"{len(incompatible)} komputerach.",
                "danger",
            )
            return redirect(url_for("agents.software_catalog_page"))

    payload = {
        "package_id": package["id"], "name": package["name"],
        "version": package["version"], "filename": package["filename"],
        "sha256": package["sha256"], "size": package["size"],
        "installer_type": package["installer_type"],
        "arguments": package["arguments"],
        "files": [] if package.get("legacy_bundle") else package["files"],
        "download_path": f"/api/v1/agent/software/{package['id']}/download",
    }

    for index, agent in enumerate(agents):
        scheduled_payload = dict(payload)
        scheduled_payload["not_before"] = (
            datetime.now(timezone.utc) + timedelta(seconds=(index // 10) * 120)
        ).isoformat()
        db.session.add(
            AgentJob(
                computer=agent,
                action="install_software",
                payload=scheduled_payload,
                status="pending",
            )
        )

    _audit(
        "AGENT_FLEET_INSTALL_SOFTWARE",
        "SUCCESS",
        f"package={package['id']}; version={package['version']}; computers={len(agents)}",
    )
    db.session.commit()
    if agents:
        flash(f"Zlecono instalację „{package['name']}” na {len(agents)} komputerach.", "success")
    else:
        flash("Brak zarejestrowanych komputerów.", "warning")
    return redirect(url_for("agents.software_catalog_page"))


@bp.post("/<int:agent_id>/commands")
@login_required
def create_command(agent_id: int):
    _administrator_required()
    agent = db.get_or_404(AgentComputer, agent_id)
    action = str(request.form.get("action") or request.form.get("command_type") or "").strip().lower()
    if action not in ALLOWED_ACTIONS:
        flash("Nieobsługiwane polecenie.", "danger")
        return redirect(url_for("agents.details", agent_id=agent.id))

    payload: dict[str, object] = {}
    if action == "message":
        message = request.form.get("message", "").strip()
        if not message or len(message) > 500:
            flash("Wiadomość musi mieć od 1 do 500 znaków.", "danger")
            return redirect(url_for("agents.details", agent_id=agent.id))
        payload["message"] = message
    elif action in {"restart", "shutdown"}:
        if request.form.get("confirm") != "yes":
            flash("Potwierdź wykonanie operacji zasilania.", "danger")
            return redirect(url_for("agents.details", agent_id=agent.id))
        payload["delay_seconds"] = 30
    elif action == "install_software":
        if request.form.get("confirm") != "yes":
            flash("Potwierdź instalację oprogramowania.", "danger")
            return redirect(url_for("agents.details", agent_id=agent.id))
        try:
            package = require_silent_package(
                get_installable_package(request.form.get("package_id", ""))
            )
        except CatalogError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("agents.details", agent_id=agent.id))
        if package["is_multifile"]:
            compatible = (
                agent_supports_legacy_bundle(agent.agent_version)
                if package.get("legacy_bundle")
                else agent_supports_multifile(agent.agent_version)
            )
            if not compatible:
                required_version = "2.7.1" if package.get("legacy_bundle") else "2.8.0"
                flash(
                    "Ten pakiet zawiera wiele plików. Najpierw zaktualizuj SP2 Agent "
                    f"na tym komputerze do wersji {required_version} lub nowszej.",
                    "danger",
                )
                return redirect(url_for("agents.details", agent_id=agent.id))
        payload = {
            "package_id": package["id"], "name": package["name"],
            "version": package["version"], "filename": package["filename"],
            "sha256": package["sha256"], "size": package["size"],
            "installer_type": package["installer_type"],
            "arguments": package["arguments"],
            "files": [] if package.get("legacy_bundle") else package["files"],
            "download_path": f"/api/v1/agent/software/{package['id']}/download",
        }
    elif action == "install_software_interactive":
        if request.form.get("confirm") != "yes":
            abort(400)
        identity = agent.console_session or {}
        if (
            not identity.get("interactive_ready")
            or not identity.get("sid")
            or not identity.get("logon_id")
            or not agent.is_online(current_app.config["AGENT_OFFLINE_AFTER_SECONDS"])
        ):
            flash(
                "Brak zalogowanego użytkownika przy komputerze lub usługi "
                "instalacji z oknem.",
                "danger",
            )
            return redirect(url_for("agents.details", agent_id=agent.id))
        try:
            package = get_installable_package(request.form.get("package_id", ""))
            if package.get("purpose") == "agent":
                raise CatalogError(
                    "Plik agenta aktualizuj przez wdrożenie agenta."
                )
            if package["is_multifile"]:
                raise CatalogError(
                    "Pakiet wieloplikowy uruchom w trybie instalacji cichej."
                )
        except CatalogError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("agents.details", agent_id=agent.id))
        payload = {
            "package_id": package["id"],
            "name": package["name"],
            "filename": package["filename"],
            "sha256": package["sha256"],
            "size": package["size"],
            "installer_type": package["installer_type"],
            "arguments": [],
            "download_path": f"/api/v1/agent/software/{package['id']}/download",
            "interactive_session": dict(identity),
            "interactive_expires": time.time() + 300,
        }
    elif action == "self_update":
        if request.form.get("confirm") != "yes":
            flash("Potwierdź aktualizację agenta.", "danger")
            return redirect(url_for("agents.details", agent_id=agent.id))
        try:
            package = require_agent_package(
                get_installable_package(request.form.get("package_id", ""))
            )
        except CatalogError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("agents.details", agent_id=agent.id))
        payload = {
            "package_id": package["id"], "name": package["name"],
            "version": package["version"], "filename": package["filename"],
            "sha256": package["sha256"], "size": package["size"],
            "download_path": f"/api/v1/agent/software/{package['id']}/download",
        }

    job = AgentJob(computer=agent, action=action, payload=payload, status="pending")
    db.session.add(job)
    _audit("AGENT_JOB_CREATE", "SUCCESS", f"hostname={agent.hostname}; action={action}")
    db.session.commit()
    flash(f"Polecenie „{action}” zostało dodane do kolejki.", "success")
    return redirect(url_for("agents.details", agent_id=agent.id))


@api_bp.get("/software/<package_id>/download")
@csrf.exempt
def software_download(package_id: str):
    if not _authorized():
        abort(401)
    try:
        package = get_installable_package(package_id)
    except CatalogError:
        abort(404)
    return send_file(package["path"], as_attachment=True,
                     download_name=package["filename"], conditional=True, max_age=0)


@api_bp.get("/software/<package_id>/files/<int:file_index>/download")
@csrf.exempt
def software_file_download(package_id: str, file_index: int):
    if not _authorized():
        abort(401)
    try:
        file_path, entry = get_package_file_by_index(package_id, file_index)
    except CatalogError:
        abort(404)
    return send_file(
        file_path,
        as_attachment=True,
        download_name=entry["filename"],
        conditional=True,
        max_age=0,
    )


@api_bp.post("/domain-repair/diagnose")
@csrf.exempt
def domain_repair_diagnose():
    """Return an authoritative Samba AD diagnosis for the local workstation.

    Authentication deliberately reuses the existing SP2 agent/enrollment
    credentials.  No domain-administrator password is accepted by this API.
    """
    from .recovery_routes import diagnose_request, guarded
    return guarded(diagnose_request)()


@api_bp.post("/register")
@csrf.exempt
def register():
    # Rejestracja akceptuje czasowy kod wdrożeniowy do wielu komputerów
    # albo starszy wspólny token wdrożeniowy.
    # W odpowiedzi agent otrzymuje osobny sekret przypisany do komputera.
    credential = _enrollment_credential()
    if credential is None:
        abort(401)
    payload = request.get_json(silent=True) or {}
    try:
        hostname = _normalize_hostname(payload)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    credential_type, enrollment_code = credential
    if credential_type == "multi-use":
        if enrollment_code is None or not _consume_enrollment_code(enrollment_code, hostname):
            db.session.rollback()
            abort(401)

    agent, created = _save_agent(payload)
    registration, raw_token = AgentRegistration.issue(agent)
    db.session.add(registration)
    db.session.commit()
    return jsonify(
        status="registered",
        id=agent.id,
        hostname=agent.hostname,
        token=raw_token,
    ), 201 if created else 200


@api_bp.post("/heartbeat")
@csrf.exempt
def heartbeat():
    payload = request.get_json(silent=True) or {}
    try:
        hostname = _normalize_hostname(payload)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    if not _authorized(hostname):
        abort(401)
    agent, _ = _save_agent(payload)
    return jsonify(status="ok", id=agent.id, hostname=agent.hostname), 200


@api_bp.get("/status")
@csrf.exempt
def status():
    if not _authorized():
        abort(401)
    threshold = current_app.config["AGENT_OFFLINE_AFTER_SECONDS"]
    archived_ids = db.select(AgentArchive.computer_id)
    agents = db.session.scalars(
        db.select(AgentComputer).where(
            AgentComputer.id.not_in(archived_ids)
        )
    ).all()
    online = sum(agent.is_online(threshold) for agent in agents)
    return jsonify(total=len(agents), online=online, offline=len(agents) - online), 200


@api_bp.post("/commands/next")
@csrf.exempt
def next_command():
    payload = request.get_json(silent=True) or {}
    try:
        hostname = _normalize_hostname(payload)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    if not _authorized(hostname):
        abort(401)
    agent = db.session.scalar(db.select(AgentComputer).where(AgentComputer.hostname == hostname))
    if agent is None:
        return jsonify(command=None), 200
    if db.session.scalar(
        db.select(AgentJob.id)
        .where(
            AgentJob.computer_id == agent.id,
            AgentJob.status == "running",
        )
        .limit(1)
    ):
        return jsonify(command=None), 200
    jobs = db.session.scalars(
        db.select(AgentJob)
        .where(
            AgentJob.computer_id == agent.id,
            AgentJob.status == "pending",
        )
        .order_by(AgentJob.created_at, AgentJob.id)
    ).all()
    now = datetime.now(timezone.utc)
    job = None
    for candidate in jobs:
        when = (candidate.payload or {}).get("not_before")
        if when:
            try:
                scheduled = datetime.fromisoformat(str(when).replace("Z", "+00:00"))
                if scheduled.tzinfo is None:
                    scheduled = scheduled.replace(tzinfo=timezone.utc)
                if scheduled > now:
                    continue
            except ValueError:
                continue
        job = candidate
        break
    if job is None:
        return jsonify(command=None), 200
    claimed = db.session.execute(
        db.update(AgentJob)
        .where(AgentJob.id == job.id, AgentJob.status == "pending")
        .values(status="running", claimed_at=now)
    )
    if claimed.rowcount != 1:
        db.session.rollback()
        return jsonify(command=None), 200
    db.session.commit()
    return jsonify(command=job.as_agent_payload()), 200


@api_bp.post("/commands/<int:job_id>/result")
@csrf.exempt
def command_result(job_id: int):
    payload = request.get_json(silent=True) or {}
    try:
        hostname = _normalize_hostname(payload)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    if not _authorized(hostname):
        abort(401)
    job = db.session.get(AgentJob, job_id)
    if job is None:
        return jsonify(error="Nie znaleziono zadania."), 404
    if job.computer.hostname != hostname:
        return jsonify(error="Zadanie nie należy do tego komputera."), 403
    status_value = str(payload.get("status", "")).strip().lower()
    if status_value not in {"success", "failed"}:
        return jsonify(error="Nieprawidłowy status wyniku."), 400
    if job.status in {"success", "failed"}:
        if job.status != status_value:
            return jsonify(error="Zadanie ma już inny wynik końcowy."), 409
        return jsonify(status="saved", id=job.id, job_status=job.status), 200
    if job.status != "running":
        return jsonify(error="Zadanie nie zostało pobrane."), 409
    job.status, job.finished_at = status_value, datetime.now(timezone.utc)
    result, error = payload.get("result"), payload.get("error")
    job.result = {"output": str(result)[:12000]} if result not in (None, "") else None
    job.error_message = str(error)[:4000] if error not in (None, "") else None
    db.session.commit()
    return jsonify(status="saved", id=job.id, job_status=job.status), 200



@bp.post("/software/<package_id>/profile")
@login_required
def edit_software_profile(package_id: str):
    _administrator_required()
    try:
        catalog = load_catalog()
        if package_id not in catalog:
            abort(404)
        package = catalog[package_id]
        profile = str(request.form.get("silent_profile", "custom")).strip()
        arguments = [
            line.strip()
            for line in request.form.get("arguments", "").splitlines()
            if line.strip()
        ]
        if profile == "agent" and package["installer_type"] == "zip":
            raise CatalogError("Pakiet z plikami BIN nie jest aktualizacją agenta.")
        installer_path = (
            packages_dir() / package["storage_dir"] / package["filename"]
            if package.get("storage_dir")
            else packages_dir() / package["filename"]
        )
        package["arguments"] = resolve_profile(
            profile,
            package.get("source_type", package["installer_type"]),
            package.get("source_filename", package["filename"]),
            arguments,
            installer_path,
        )
        package["silent_profile"] = profile
        package["purpose"] = "agent" if profile == "agent" else "software"
        save_catalog(catalog)
        _audit(
            "AGENT_SOFTWARE_PROFILE",
            "SUCCESS",
            f"package={package_id}; profile={profile}",
        )
        db.session.commit()
        flash("Zapisano profil instalacji.", "success")
    except CatalogError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("agents.software_catalog_page"))

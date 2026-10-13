from flask import abort, current_app, render_template
from flask_login import login_required

from app.directory.service import DirectoryError, DirectoryService
from app.disk_alerts import low_disk_volumes
from app.extensions import db
from app.models import AgentComputer, AgentJob
from app.permissions import is_administrator
from app.services.diagnostics import DiagnosticsError, run_health_checks

from . import bp


@bp.get("/")
@login_required
def index():
    ldap_error = None
    try:
        stats = DirectoryService().stats()
        cards = [
            {"label": "Użytkownicy AD", "value": stats.users, "description": "Konta odczytane z Samba AD", "endpoint": "directory.users"},
            {"label": "Grupy AD", "value": stats.groups, "description": "Grupy odczytane z Samba AD", "endpoint": "directory.groups"},
            {"label": "Komputery AD", "value": stats.computers, "description": "Konta komputerów w domenie", "endpoint": "directory.computers"},
        ]
        checked_at = stats.checked_at
    except DirectoryError as exc:
        ldap_error = str(exc)
        checked_at = None
        cards = [
            {"label": "Użytkownicy AD", "value": "—", "description": "Sprawdź konfigurację LDAP", "endpoint": "directory.users"},
            {"label": "Grupy AD", "value": "—", "description": "Sprawdź konfigurację LDAP", "endpoint": "directory.groups"},
            {"label": "Komputery AD", "value": "—", "description": "Sprawdź konfigurację LDAP", "endpoint": "directory.computers"},
        ]

    threshold = current_app.config["AGENT_OFFLINE_AFTER_SECONDS"]
    agents = db.session.scalars(db.select(AgentComputer)).all()
    online = sum(agent.is_online(threshold) for agent in agents)
    rooms_count = db.session.scalar(
        db.select(db.func.count(db.distinct(AgentComputer.room))).where(
            AgentComputer.room.is_not(None), AgentComputer.room != ""
        )
    ) or 0
    pending_jobs = db.session.scalar(
        db.select(db.func.count(AgentJob.id)).where(AgentJob.status.in_(["pending", "running"]))
    ) or 0
    failed_jobs = db.session.scalar(
        db.select(db.func.count(AgentJob.id)).where(AgentJob.status == "failed")
    ) or 0

    disk_threshold = current_app.config["AGENT_DISK_WARNING_PERCENT_USED"]
    low_disks = low_disk_volumes(agents, disk_threshold)

    agent_cards = [
        {"label": "Agenci online", "value": online, "description": f"Offline: {len(agents) - online}", "endpoint": "agents.index"},
        {"label": "Sale", "value": rooms_count, "description": "Sale z przypisanymi agentami", "endpoint": "rooms.index"},
        {"label": "Zadania w toku", "value": pending_jobs, "description": "Oczekujące i wykonywane", "endpoint": "agents.index"},
        {"label": "Błędy zadań", "value": failed_jobs, "description": "Wymagają sprawdzenia", "endpoint": "agents.index"},
        {
            "label": "Mało miejsca na dysku",
            "value": len(low_disks),
            "description": f"Próg zajętości: {disk_threshold:g}%",
            "endpoint": "agents.index",
        },
    ]

    diagnostic_summary = None
    diagnostics_error = None
    if is_administrator():
        try:
            health_checks = list(run_health_checks())
        except DiagnosticsError as exc:
            diagnostics_error = str(exc)
        else:
            diagnostic_summary = {
                "ok": sum(
                    check.status == "ok" for check in health_checks
                ),
                "warnings": sum(
                    check.status == "warning" for check in health_checks
                ),
            }

    return render_template(
        "dashboard/index.html",
        cards=cards,
        agent_cards=agent_cards,
        low_disks=low_disks[:10],
        diagnostic_summary=diagnostic_summary,
        diagnostics_error=diagnostics_error,
        ldap_error=ldap_error,
        checked_at=checked_at,
        app_name=current_app.config["APP_NAME"],
        app_version=current_app.config["APP_VERSION"],
        app_author=current_app.config["APP_AUTHOR"],
    )


@bp.get("/system/diagnostyka")
@login_required
def diagnostics():
    """Wyświetl wspólne wyniki diagnostyki administratorowi."""
    if not is_administrator():
        abort(403)

    checks = []
    error = None
    try:
        checks.extend(run_health_checks())
    except DiagnosticsError as exc:
        error = str(exc)

    return render_template(
        "dashboard/diagnostics.html",
        checks=checks,
        error=error,
    )

from __future__ import annotations

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.agents.silent_profiles import require_agent_package, require_silent_package
from app.agents.software_catalog import (
    CatalogError,
    agent_supports_legacy_bundle,
    agent_supports_multifile,
    available_packages,
    get_installable_package,
)
from app.extensions import db
from app.models import AgentComputer, AgentJob, AuditLog
from app.room_assignment import effective_room

from . import bp

ALLOWED_ROOM_ACTIONS = {
    "inventory",
    "gpupdate",
    "message",
    "restart",
    "shutdown",
    "install_software",
    "self_update",
}


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


def _room_agents(room_name: str) -> list[AgentComputer]:
    agents = db.session.scalars(
        db.select(AgentComputer).order_by(AgentComputer.hostname)
    ).all()
    return [agent for agent in agents if effective_room(agent.room, agent.hostname) == room_name]


@bp.get("")
@login_required
def index():
    threshold = current_app.config["AGENT_OFFLINE_AFTER_SECONDS"]
    agents = db.session.scalars(
        db.select(AgentComputer).order_by(AgentComputer.hostname)
    ).all()

    grouped: dict[str, list[AgentComputer]] = {}
    for agent in agents:
        room_name = effective_room(agent.room, agent.hostname)
        if room_name:
            grouped.setdefault(room_name, []).append(agent)

    rooms = []
    for name, room_agents in grouped.items():
        online = sum(agent.is_online(threshold) for agent in room_agents)
        rooms.append(
            {
                "name": name,
                "agents": room_agents,
                "total": len(room_agents),
                "online": online,
                "offline": len(room_agents) - online,
            }
        )

    unassigned = sum(
        effective_room(agent.room, agent.hostname) is None for agent in agents
    )

    return render_template("rooms/index.html", rooms=rooms, unassigned=unassigned)


@bp.get("/<path:room_name>")
@login_required
def details(room_name: str):
    agents = _room_agents(room_name)
    if not agents:
        abort(404)

    threshold = current_app.config["AGENT_OFFLINE_AFTER_SECONDS"]
    online_count = sum(agent.is_online(threshold) for agent in agents)
    try:
        packages = available_packages()
        catalog_error = None
    except CatalogError as exc:
        packages, catalog_error = [], str(exc)

    agent_ids = [agent.id for agent in agents]
    recent_jobs = db.session.scalars(
        db.select(AgentJob)
        .where(AgentJob.computer_id.in_(agent_ids))
        .order_by(AgentJob.created_at.desc())
        .limit(100)
    ).all()

    return render_template(
        "rooms/details.html",
        room_name=room_name,
        agents=agents,
        online_count=online_count,
        offline_count=len(agents) - online_count,
        threshold=threshold,
        software_packages=packages,
        catalog_error=catalog_error,
        recent_jobs=recent_jobs,
        can_manage=current_user.role == "administrator",
    )


@bp.post("/<path:room_name>/commands")
@login_required
def create_commands(room_name: str):
    _administrator_required()
    agents = _room_agents(room_name)
    if not agents:
        abort(404)

    action = str(request.form.get("action", "")).strip().lower()
    if action not in ALLOWED_ROOM_ACTIONS:
        flash("Nieobsługiwane polecenie grupowe.", "danger")
        return redirect(url_for("rooms.details", room_name=room_name))

    selected_ids = request.form.getlist("agent_ids")
    if selected_ids:
        selected = {int(value) for value in selected_ids if value.isdigit()}
        agents = [agent for agent in agents if agent.id in selected]
    if not agents:
        flash("Nie wybrano żadnego komputera.", "warning")
        return redirect(url_for("rooms.details", room_name=room_name))

    payload: dict[str, object] = {}
    if action == "message":
        message = request.form.get("message", "").strip()
        if not message or len(message) > 500:
            flash("Wiadomość musi mieć od 1 do 500 znaków.", "danger")
            return redirect(url_for("rooms.details", room_name=room_name))
        payload["message"] = message
    elif action in {"restart", "shutdown"}:
        if request.form.get("confirm") != "yes":
            flash("Potwierdź operację zasilania.", "danger")
            return redirect(url_for("rooms.details", room_name=room_name))
        payload["delay_seconds"] = 30
    elif action == "install_software":
        if request.form.get("confirm") != "yes":
            flash("Potwierdź instalację oprogramowania.", "danger")
            return redirect(url_for("rooms.details", room_name=room_name))
        try:
            package = require_silent_package(
                get_installable_package(request.form.get("package_id", ""))
            )
        except CatalogError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("rooms.details", room_name=room_name))
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
                    f"{len(incompatible)} komputerach w tej sali.",
                    "danger",
                )
                return redirect(url_for("rooms.details", room_name=room_name))
        payload = {
            "package_id": package["id"],
            "name": package["name"],
            "version": package["version"],
            "filename": package["filename"],
            "sha256": package["sha256"],
            "size": package["size"],
            "installer_type": package["installer_type"],
            "arguments": package["arguments"],
            "files": [] if package.get("legacy_bundle") else package["files"],
            "download_path": f"/api/v1/agent/software/{package['id']}/download",
        }
    elif action == "self_update":
        if request.form.get("confirm") != "yes":
            flash("Potwierdź aktualizację agenta.", "danger")
            return redirect(url_for("rooms.details", room_name=room_name))
        try:
            package = require_agent_package(
                get_installable_package(request.form.get("package_id", ""))
            )
        except CatalogError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("rooms.details", room_name=room_name))
        payload = {
            "package_id": package["id"],
            "name": package["name"],
            "version": package["version"],
            "filename": package["filename"],
            "sha256": package["sha256"],
            "size": package["size"],
            "download_path": f"/api/v1/agent/software/{package['id']}/download",
        }

    for agent in agents:
        db.session.add(AgentJob(computer=agent, action=action, payload=dict(payload), status="pending"))

    _audit(
        "ROOM_JOB_CREATE",
        "SUCCESS",
        f"room={room_name}; action={action}; computers={len(agents)}",
    )
    db.session.commit()
    flash(
        f"Dodano polecenie „{action}” do kolejki dla {len(agents)} komputerów.",
        "success",
    )
    return redirect(url_for("rooms.details", room_name=room_name))

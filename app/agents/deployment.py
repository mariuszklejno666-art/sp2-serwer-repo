from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import AgentComputer, AgentEnrollmentCode

from . import bp

ROOMS = ("Sala11", "Sala32", "Sala4", "Sala7")
DOMAIN_DN = "DC=sp2,DC=lan"
SYNC_TIMER = "sp2-agent-group-sync.timer"
SYNC_SERVICE = "sp2-agent-group-sync.service"
GROUP_HELPER = "/usr/local/sbin/sp2-agent-group-members"
ROOM_HELPER = "/usr/local/sbin/sp2-agent-room-computers"
LOG_HELPER = "/usr/local/sbin/sp2-agent-group-sync-log"
TOGGLE_HELPER = "/usr/local/sbin/sp2-agent-room-toggle"
STATE_FILE = Path("/etc/sp2-admin/agent-deployment-rooms.conf")


def _run(command: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    output = result.stdout or ""
    if result.stderr:
        output += ("\n" if output else "") + result.stderr
    return result.returncode, output.strip()


def _systemctl_properties(unit: str) -> dict[str, str]:
    code, output = _run([
        "systemctl", "show", unit,
        "--property=ActiveState,SubState,LastTriggerUSec,NextElapseUSecRealtime",
    ])
    if code != 0:
        return {"ActiveState": "unknown", "SubState": output or "error"}
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def _helper_members(helper: str, value: str) -> tuple[list[str], str | None]:
    code, output = _run(["sudo", "-n", helper, value])
    if code != 0:
        return [], output or "Nie udało się odczytać danych."
    members = sorted({line.strip() for line in output.splitlines() if line.strip()}, key=str.casefold)
    return members, None


def _group_members(group: str) -> tuple[list[str], str | None]:
    return _helper_members(GROUP_HELPER, group)


def _room_computers(room: str) -> tuple[list[str], str | None]:
    return _helper_members(ROOM_HELPER, room)


def _sync_log() -> str:
    code, output = _run(["sudo", "-n", LOG_HELPER], timeout=20)
    if code != 0:
        return output or "Brak dostępu do logu synchronizacji."
    return output


def _enabled_rooms() -> set[str]:
    if not STATE_FILE.exists():
        return set(ROOMS)
    enabled: set[str] = set()
    try:
        lines = STATE_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set(ROOMS)
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        room, value = line.split("=", 1)
        room = room.strip()
        if room in ROOMS and value.strip().lower() in {"1", "true", "yes", "on", "enabled"}:
            enabled.add(room)
    return enabled


def _reconcile_agent_location(agent: AgentComputer, room: str) -> bool:
    changed = False
    expected_ou = f"OU={room},OU=Komputery,{DOMAIN_DN}"
    if agent.room != room:
        agent.room = room
        changed = True
    if agent.ou != expected_ou:
        agent.ou = expected_ou
        changed = True
    return changed


def _room_snapshot(room: str, by_hostname: dict[str, AgentComputer], threshold: int) -> tuple[dict, list[str]]:
    group = f"SP2-Agent-{room}"
    members, group_error = _group_members(group)
    ou_members, ou_error = _room_computers(room)
    errors: list[str] = []
    if group_error:
        errors.append(f"{group}: {group_error}")
    if ou_error:
        errors.append(f"{room}: {ou_error}")

    group_computers = [item for item in members if item.endswith("$")]
    ou_computers = [item for item in ou_members if item.endswith("$")]
    group_set = {item.upper() for item in group_computers}

    reporting = 0
    online = 0
    offline = 0
    reporting_names: list[str] = []
    waiting_names: list[str] = []
    computers: list[dict] = []
    location_changed = False

    for member in ou_computers:
        hostname = member[:-1].upper()
        agent = by_hostname.get(hostname)
        in_group = member.upper() in group_set
        if agent is None:
            waiting_names.append(hostname)
            computers.append({
                "hostname": hostname,
                "in_group": in_group,
                "agent": None,
                "status": "waiting",
            })
            continue

        if _reconcile_agent_location(agent, room):
            location_changed = True

        reporting += 1
        reporting_names.append(hostname)
        is_online = agent.is_online(threshold)
        if is_online:
            online += 1
            status = "online"
        else:
            offline += 1
            status = "offline"
        computers.append({
            "hostname": hostname,
            "in_group": in_group,
            "agent": agent,
            "status": status,
        })

    if location_changed:
        db.session.commit()

    ou_count = len(ou_computers)
    progress = round((reporting / ou_count) * 100) if ou_count else 0
    group_missing = [item[:-1] for item in ou_computers if item.upper() not in group_set]

    return ({
        "room": room,
        "group": group,
        "members": group_computers,
        "ou_members": ou_computers,
        "ou_count": ou_count,
        "count": len(group_computers),
        "reporting": reporting,
        "reporting_names": reporting_names,
        "online": online,
        "offline": offline,
        "waiting": len(waiting_names),
        "waiting_names": waiting_names,
        "group_missing": group_missing,
        "progress": progress,
        "computers": computers,
    }, errors)


@bp.get("/deployment")
@login_required
def deployment():
    timer = _systemctl_properties(SYNC_TIMER)
    service = _systemctl_properties(SYNC_SERVICE)
    threshold = current_app.config["AGENT_OFFLINE_AFTER_SECONDS"]
    enabled_rooms = _enabled_rooms()

    all_agents = db.session.scalars(db.select(AgentComputer)).all()
    by_hostname = {agent.hostname.upper(): agent for agent in all_agents}

    room_rows = []
    errors: list[str] = []
    totals = {"ou": 0, "group": 0, "reporting": 0, "online": 0, "waiting": 0}

    for room in ROOMS:
        row, row_errors = _room_snapshot(room, by_hostname, threshold)
        row["enabled"] = room in enabled_rooms
        room_rows.append(row)
        errors.extend(row_errors)
        totals["ou"] += row["ou_count"]
        totals["group"] += row["count"]
        totals["reporting"] += row["reporting"]
        totals["online"] += row["online"]
        totals["waiting"] += row["waiting"]

    totals["progress"] = round((totals["reporting"] / totals["ou"]) * 100) if totals["ou"] else 0

    deployment_members, deployment_error = _group_members("SP2-Agent-Deployment")
    if deployment_error:
        errors.append(f"SP2-Agent-Deployment: {deployment_error}")

    return render_template(
        "agents/deployment.html",
        timer=timer,
        service=service,
        rooms=room_rows,
        totals=totals,
        deployment_members=deployment_members,
        sync_log=_sync_log(),
        errors=errors,
        now=datetime.now(UTC),
    )


@bp.post("/deployment/enrollment-code")
@login_required
def deployment_enrollment_code():
    if current_user.role != "administrator":
        abort(403)
    expires_at = datetime.now(UTC) + timedelta(hours=24)
    enrollment, raw_code = AgentEnrollmentCode.issue(
        created_by=current_user.username,
        expires_at=expires_at,
    )
    db.session.add(enrollment)
    db.session.commit()
    max_uses = max(1, int(current_app.config.get("AGENT_ENROLLMENT_MAX_USES", 100)))
    flash(
        (
            f"Kod wdrożeniowy do {max_uses} komputerów "
            f"(ważny do {expires_at.strftime('%H:%M:%S')}): {raw_code}"
        ),
        "success",
    )
    return redirect(url_for("agents.deployment"))


@bp.get("/deployment/room/<room>")
@login_required
def deployment_room(room: str):
    if room not in ROOMS:
        abort(404)
    threshold = current_app.config["AGENT_OFFLINE_AFTER_SECONDS"]
    enabled_rooms = _enabled_rooms()
    all_agents = db.session.scalars(db.select(AgentComputer)).all()
    by_hostname = {agent.hostname.upper(): agent for agent in all_agents}
    row, errors = _room_snapshot(room, by_hostname, threshold)
    row["enabled"] = room in enabled_rooms
    return render_template(
        "agents/deployment_room.html",
        row=row,
        errors=errors,
        threshold=threshold,
        now=datetime.now(UTC),
    )


@bp.post("/deployment/sync")
@login_required
def deployment_sync_now():
    if current_user.role != "administrator":
        abort(403)
    code, output = _run(["sudo", "-n", "systemctl", "start", SYNC_SERVICE], timeout=30)
    if code == 0:
        flash("Synchronizacja grup wdrożeniowych została wykonana.", "success")
    else:
        flash("Nie udało się uruchomić synchronizacji: " + (output or "nieznany błąd"), "danger")
    return redirect(url_for("agents.deployment"))


@bp.post("/deployment/room/<room>/toggle")
@login_required
def deployment_toggle_room(room: str):
    if current_user.role != "administrator":
        abort(403)
    if room not in ROOMS:
        abort(404)
    action = str(request.form.get("action", "")).strip().lower()
    if action not in {"enable", "disable"}:
        abort(400)
    code, output = _run(["sudo", "-n", TOGGLE_HELPER, room, action], timeout=30)
    if code == 0:
        flash(
            f"Wdrożenie dla {room} zostało {'włączone' if action == 'enable' else 'wyłączone'}.",
            "success",
        )
    else:
        flash("Nie udało się zmienić wdrożenia: " + (output or "nieznany błąd"), "danger")
    return redirect(url_for("agents.deployment"))

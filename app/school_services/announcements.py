from __future__ import annotations

from datetime import datetime, timezone

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Announcement, AuditLog
from app.permissions import is_administrator, is_school_management

from . import bp

PRIORITIES = {"informational", "organizational", "urgent", "alarm"}
AUDIENCES = {"all", "staff", "teachers", "students", "administration"}


def _management_required() -> None:
    if not is_school_management():
        abort(403)


def _administrator_required() -> None:
    if not is_administrator():
        abort(403)


def _parse_datetime(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _audit(action: str, details: str) -> None:
    db.session.add(
        AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action=action,
            result="SUCCESS",
            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
            details=details[:500],
        )
    )


def _active_announcements(now: datetime) -> list[Announcement]:
    items = db.session.scalars(
        db.select(Announcement).order_by(
            Announcement.pinned.desc(),
            Announcement.priority.desc(),
            Announcement.created_at.desc(),
        )
    ).all()
    return [item for item in items if item.is_active_at(now)]


@bp.get("/announcements")
@login_required
def announcements_board():
    _management_required()
    now = datetime.now(timezone.utc)
    active = _active_announcements(now)
    _audit("ANNOUNCEMENT_BOARD_OPEN", f"active={len(active)}")
    db.session.commit()
    return render_template("school_services/announcements_board.html", announcements=active, now=now)


@bp.get("/announcements/display")
@login_required
def announcements_display():
    _management_required()
    now = datetime.now(timezone.utc)
    active = _active_announcements(now)
    alarms = [item for item in active if item.priority == "alarm"]
    _audit("ANNOUNCEMENT_DISPLAY_OPEN", f"active={len(active)}; alarms={len(alarms)}")
    db.session.commit()
    response = render_template(
        "school_services/announcements_display.html",
        announcements=active,
        alarms=alarms,
        now=now,
    )
    return response, 200, {"Cache-Control": "no-store, private"}


@bp.route("/announcements/manage", methods=["GET", "POST"])
@login_required
def announcements_manage():
    _administrator_required()
    if request.method == "POST":
        title = str(request.form.get("title", "")).strip()
        body = str(request.form.get("body", "")).strip()
        priority = str(request.form.get("priority", "informational")).strip()
        audience = str(request.form.get("audience", "all")).strip()
        try:
            starts_at = _parse_datetime(str(request.form.get("starts_at", "")))
            ends_at = _parse_datetime(str(request.form.get("ends_at", "")))
        except ValueError:
            flash("Nieprawidłowa data publikacji.", "danger")
            return redirect(url_for("school_services.announcements_manage"))

        if not title or len(title) > 160 or not body or len(body) > 5000:
            flash("Podaj tytuł i treść ogłoszenia.", "danger")
            return redirect(url_for("school_services.announcements_manage"))
        if priority not in PRIORITIES or audience not in AUDIENCES:
            abort(400)
        if starts_at and ends_at and ends_at <= starts_at:
            flash("Data zakończenia musi być późniejsza niż data rozpoczęcia.", "danger")
            return redirect(url_for("school_services.announcements_manage"))

        item = Announcement(
            title=title,
            body=body,
            priority=priority,
            audience=audience,
            starts_at=starts_at,
            ends_at=ends_at,
            enabled=False,
            pinned=bool(request.form.get("pinned")),
            created_by=current_user.username,
        )
        db.session.add(item)
        _audit("ANNOUNCEMENT_CREATE", f"title={title}; priority={priority}; audience={audience}; enabled=false")
        db.session.commit()
        flash("Ogłoszenie zapisano jako wyłączone. Możesz je sprawdzić przed publikacją.", "success")
        return redirect(url_for("school_services.announcements_manage"))

    items = db.session.scalars(
        db.select(Announcement).order_by(Announcement.created_at.desc())
    ).all()
    return render_template(
        "school_services/announcements_manage.html",
        announcements=items,
        priorities=sorted(PRIORITIES),
        audiences=sorted(AUDIENCES),
    )


@bp.post("/announcements/<int:item_id>/toggle")
@login_required
def announcement_toggle(item_id: int):
    _administrator_required()
    item = db.get_or_404(Announcement, item_id)
    item.enabled = not item.enabled
    _audit("ANNOUNCEMENT_TOGGLE", f"id={item.id}; enabled={item.enabled}")
    db.session.commit()
    flash("Stan publikacji został zmieniony.", "success")
    return redirect(url_for("school_services.announcements_manage"))

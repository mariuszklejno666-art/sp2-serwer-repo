from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import db
from app.models import AuditLog, User

from . import bp
from .forms import LoginForm


def _safe_next_url(target: str | None) -> bool:
    if not target:
        return False
    base = urlparse(request.host_url)
    candidate = urlparse(urljoin(request.host_url, target))
    return candidate.scheme in {"http", "https"} and base.netloc == candidate.netloc


def _record_login(user: User | None, result: str, details: str | None = None) -> None:
    db.session.add(
        AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else request.form.get("username", "")[:64],
            action="LOGIN",
            result=result,
            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
            details=details,
        )
    )
    db.session.commit()


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        user = db.session.scalar(db.select(User).where(User.username == username))

        if user and user.is_active and user.check_password(form.password.data):
            user.last_login_at = datetime.now(timezone.utc)
            login_user(user, remember=False)
            _record_login(user, "SUCCESS")
            flash("Zalogowano poprawnie.", "success")
            next_url = request.args.get("next")
            return redirect(next_url if _safe_next_url(next_url) else url_for("dashboard.index"))

        _record_login(user, "FAILURE", "Nieprawidłowy login, hasło lub konto nieaktywne")
        flash("Nieprawidłowy login lub hasło.", "danger")

    return render_template("auth/login.html", form=form)


@bp.post("/logout")
@login_required
def logout():
    username = current_user.username if current_user.is_authenticated else None
    user_id = current_user.id if current_user.is_authenticated else None
    logout_user()
    db.session.add(
        AuditLog(
            user_id=user_id,
            username=username,
            action="LOGOUT",
            result="SUCCESS",
            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
        )
    )
    db.session.commit()
    flash("Wylogowano.", "info")
    return redirect(url_for("auth.login"))

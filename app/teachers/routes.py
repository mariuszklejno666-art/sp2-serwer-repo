from __future__ import annotations

from flask import current_app, render_template, request
from flask_login import login_required

from app.directory.service import (
    DirectoryError,
    DirectoryService,
    account_enabled,
    first_value,
)
from app.domain_naming import distinguished_name_within

from . import bp


@bp.get("")
@login_required
def index():
    query = request.args.get("q", "").strip()
    teacher_ou = str(current_app.config.get("AD_TEACHER_USER_OU", "")).strip()
    try:
        records = DirectoryService().users(query=query, limit=0)
        records = [
            item
            for item in records
            if distinguished_name_within(
                first_value(
                    item,
                    "distinguishedName",
                    str(item.get("dn", "")),
                ),
                teacher_ou,
            )
        ]
        records.sort(
            key=lambda item: first_value(
                item,
                "displayName",
                first_value(item, "sAMAccountName", ""),
            ).casefold()
        )
        error = None
    except DirectoryError as exc:
        records = []
        error = str(exc)

    enabled = sum(account_enabled(item) for item in records)
    return render_template(
        "teachers/index.html",
        records=records,
        error=error,
        query=query,
        teacher_ou=teacher_ou,
        enabled=enabled,
        disabled=len(records) - enabled,
        first_value=first_value,
        account_enabled=account_enabled,
    )

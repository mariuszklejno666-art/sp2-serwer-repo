from __future__ import annotations

import csv
import io

from flask import Response, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import AuditLog
from app.domain_naming import (
    ComputerNameError,
    admin_computer_name,
    computer_name_exists,
    distinguished_name_within,
    naming_mode_for_ou,
    ou_name_from_dn,
    room_computer_name,
    teacher_computer_name,
)

from . import bp
from .forms import (
    AccountActionForm,
    BulkUserActionForm,
    CreateUserForm,
    DeleteUserForm,
    GroupMembershipForm,
    MoveUserForm,
    RenameUserForm,
    ResetPasswordForm,
)
from .service import (
    DirectoryError,
    DirectoryService,
    account_enabled,
    computer_name,
    dn_common_name,
    dn_organizational_path,
    first_value,
    format_ad_datetime,
    ou_path,
    sid_value,
)


def _safe_load(loader):
    try:
        return loader(), None
    except DirectoryError as exc:
        return [], str(exc)


def _is_administrator() -> bool:
    return bool(current_user.is_authenticated and current_user.role == "administrator")


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
    db.session.commit()


@bp.get("/")
@login_required
def index():
    return redirect(url_for("directory.users"))


@bp.get("/users")
@login_required
def users():
    query = request.args.get("q", "").strip()
    records, error = _safe_load(lambda: DirectoryService().users(query=query))
    return render_template(
        "directory/users.html",
        records=records,
        query=query,
        error=error,
        first_value=first_value,
        account_enabled=account_enabled,
        bulk_form=BulkUserActionForm(),
        can_write=_is_administrator(),
        write_configured=bool(
            current_app.config.get("LDAP_WRITE_BIND_DN")
            and current_app.config.get("LDAP_WRITE_BIND_PASSWORD")
        ),
    )


@bp.get("/users/<username>")
@login_required
def user_details(username: str):
    try:
        user = DirectoryService().user(username)
    except DirectoryError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("directory.users"))

    if user is None:
        flash(f"Nie znaleziono użytkownika: {username}", "warning")
        return redirect(url_for("directory.users"))

    groups = user.get("memberOf", [])
    if not isinstance(groups, list):
        groups = [groups] if groups else []

    service = DirectoryService()
    all_groups, groups_error = _safe_load(lambda: service.groups(limit=0))
    all_ous, ous_error = _safe_load(lambda: service.organizational_units(limit=0))
    group_form = GroupMembershipForm()
    group_form.group_dn.choices = sorted(
        [
            (first_value(item, "distinguishedName", item.get("dn", "")), first_value(item, "sAMAccountName"))
            for item in all_groups
        ],
        key=lambda choice: choice[1].casefold(),
    )
    move_form = MoveUserForm()
    move_form.target_ou_dn.choices = sorted(
        [
            (first_value(item, "distinguishedName", item.get("dn", "")), ou_path(first_value(item, "distinguishedName", item.get("dn", ""))))
            for item in all_ous
        ],
        key=lambda choice: choice[1].casefold(),
    )

    return render_template(
        "directory/user_details.html",
        user=user,
        groups=groups,
        reset_form=ResetPasswordForm(),
        account_action_form=AccountActionForm(),
        group_form=group_form,
        move_form=move_form,
        rename_form=RenameUserForm(),
        delete_form=DeleteUserForm(),
        directory_options_error=groups_error or ous_error,
        can_write=_is_administrator(),
        write_configured=bool(
            current_app.config.get("LDAP_WRITE_BIND_DN")
            and current_app.config.get("LDAP_WRITE_BIND_PASSWORD")
        ),
        first_value=first_value,
        account_enabled=account_enabled,
        dn_common_name=dn_common_name,
        format_ad_datetime=format_ad_datetime,
    )


def _ou_choices(service: DirectoryService) -> tuple[list[tuple[str, str]], str | None]:
    records, error = _safe_load(lambda: service.organizational_units(limit=0))
    choices = sorted(
        [
            (
                first_value(item, "distinguishedName", item.get("dn", "")),
                ou_path(first_value(item, "distinguishedName", item.get("dn", ""))),
            )
            for item in records
        ],
        key=lambda choice: choice[1].casefold(),
    )
    return choices, error


def _group_choices(service: DirectoryService) -> tuple[list[tuple[str, str]], str | None]:
    records, error = _safe_load(lambda: service.groups(limit=0))
    choices = sorted(
        [
            (
                first_value(item, "distinguishedName", item.get("dn", "")),
                first_value(item, "sAMAccountName"),
            )
            for item in records
        ],
        key=lambda choice: choice[1].casefold(),
    )
    return choices, error


@bp.get("/users/new")
@login_required
def new_user():
    if not _is_administrator():
        abort(403)
    service = DirectoryService()
    ou_choices, ous_error = _ou_choices(service)
    group_choices, groups_error = _group_choices(service)
    form = CreateUserForm()
    form.organizational_unit.choices = ou_choices
    form.groups.choices = group_choices
    return render_template(
        "directory/user_new.html",
        form=form,
        directory_options_error=ous_error or groups_error,
        write_configured=bool(
            current_app.config.get("LDAP_WRITE_BIND_DN")
            and current_app.config.get("LDAP_WRITE_BIND_PASSWORD")
        ),
    )


@bp.post("/users/new")
@login_required
def create_user():
    if not _is_administrator():
        abort(403)
    service = DirectoryService()
    ou_choices, ous_error = _ou_choices(service)
    group_choices, groups_error = _group_choices(service)
    form = CreateUserForm()
    form.organizational_unit.choices = ou_choices
    form.groups.choices = group_choices

    if not form.validate_on_submit():
        flash("Sprawdź formularz tworzenia użytkownika.", "danger")
        return render_template(
            "directory/user_new.html",
            form=form,
            directory_options_error=ous_error or groups_error,
            write_configured=bool(
                current_app.config.get("LDAP_WRITE_BIND_DN")
                and current_app.config.get("LDAP_WRITE_BIND_PASSWORD")
            ),
        ), 400

    min_length = current_app.config["AD_NEW_USER_PASSWORD_MIN_LENGTH"]
    if len(form.password.data) < min_length:
        flash(f"Hasło musi mieć co najmniej {min_length} znaków.", "danger")
        return redirect(url_for("directory.new_user"))

    username = form.username.data.strip()
    try:
        service.create_user(
            username=username,
            given_name=form.given_name.data.strip(),
            surname=form.surname.data.strip(),
            display_name=(form.display_name.data or "").strip() or None,
            mail=(form.mail.data or "").strip() or None,
            password=form.password.data,
            ou_dn=form.organizational_unit.data,
            group_dns=form.groups.data,
        )
        _audit(
            "AD_USER_CREATE",
            "SUCCESS",
            f"target={username}; ou={form.organizational_unit.data}",
        )
        flash(f"Użytkownik {username} został utworzony.", "success")
        return redirect(url_for("directory.user_details", username=username))
    except DirectoryError as exc:
        _audit("AD_USER_CREATE", "FAILURE", f"target={username}; error={exc}")
        flash(str(exc), "danger")
        return redirect(url_for("directory.new_user"))


@bp.post("/users/<username>/rename")
@login_required
def rename_user(username: str):
    if not _is_administrator():
        abort(403)
    form = RenameUserForm()
    if not form.validate_on_submit():
        flash("Sprawdź formularz zmiany nazwy użytkownika.", "danger")
        return redirect(url_for("directory.user_details", username=username))

    new_username = form.new_username.data.strip()
    try:
        DirectoryService().rename_user(username, new_username)
        _audit("AD_USER_RENAME", "SUCCESS", f"target={username}; new_username={new_username}")
        flash(f"Nazwa użytkownika została zmieniona na {new_username}.", "success")
        return redirect(url_for("directory.user_details", username=new_username))
    except DirectoryError as exc:
        _audit("AD_USER_RENAME", "FAILURE", f"target={username}; new_username={new_username}; error={exc}")
        flash(str(exc), "danger")
        return redirect(url_for("directory.user_details", username=username))


@bp.post("/users/<username>/delete")
@login_required
def delete_user(username: str):
    if not _is_administrator():
        abort(403)
    form = DeleteUserForm()
    if not form.validate_on_submit():
        flash("Sprawdź formularz usuwania użytkownika.", "danger")
        return redirect(url_for("directory.user_details", username=username))

    if form.confirm_username.data.strip().casefold() != username.strip().casefold():
        flash("Wpisana nazwa użytkownika nie zgadza się z usuwanym kontem.", "danger")
        return redirect(url_for("directory.user_details", username=username))

    try:
        DirectoryService().delete_user(username)
        _audit("AD_USER_DELETE", "SUCCESS", f"target={username}")
        flash(f"Użytkownik {username} został usunięty.", "success")
        return redirect(url_for("directory.users"))
    except DirectoryError as exc:
        _audit("AD_USER_DELETE", "FAILURE", f"target={username}; error={exc}")
        flash(str(exc), "danger")
        return redirect(url_for("directory.user_details", username=username))


@bp.post("/users/<username>/reset-password")
@login_required
def reset_password(username: str):
    if not _is_administrator():
        abort(403)

    form = ResetPasswordForm()
    if not form.validate_on_submit():
        flash("Sprawdź formularz resetowania hasła.", "danger")
        return redirect(url_for("directory.user_details", username=username))

    min_length = current_app.config["AD_PASSWORD_MIN_LENGTH"]
    if len(form.new_password.data) < min_length:
        flash(f"Hasło musi mieć co najmniej {min_length} znaków.", "danger")
        return redirect(url_for("directory.user_details", username=username))

    try:
        DirectoryService().reset_password(
            username,
            form.new_password.data,
            force_change=bool(form.force_change.data),
        )
        _audit(
            "AD_PASSWORD_RESET",
            "SUCCESS",
            f"target={username}; force_change={bool(form.force_change.data)}",
        )
        flash(f"Hasło użytkownika {username} zostało zresetowane.", "success")
    except DirectoryError as exc:
        _audit("AD_PASSWORD_RESET", "FAILURE", f"target={username}; error={exc}")
        flash(str(exc), "danger")

    return redirect(url_for("directory.user_details", username=username))


@bp.post("/users/<username>/account/<action>")
@login_required
def account_action(username: str, action: str):
    if not _is_administrator():
        abort(403)
    form = AccountActionForm()
    if not form.validate_on_submit():
        flash("Nieprawidłowe żądanie zmiany konta.", "danger")
        return redirect(url_for("directory.user_details", username=username))

    service = DirectoryService()
    try:
        if action == "enable":
            service.set_account_enabled(username, enabled=True)
            audit_action, message = "AD_ACCOUNT_ENABLE", "Konto zostało włączone."
        elif action == "disable":
            service.set_account_enabled(username, enabled=False)
            audit_action, message = "AD_ACCOUNT_DISABLE", "Konto zostało wyłączone."
        elif action == "unlock":
            service.unlock_account(username)
            audit_action, message = "AD_ACCOUNT_UNLOCK", "Konto zostało odblokowane."
        else:
            abort(404)
        _audit(audit_action, "SUCCESS", f"target={username}")
        flash(message, "success")
    except DirectoryError as exc:
        _audit(f"AD_ACCOUNT_{action.upper()}", "FAILURE", f"target={username}; error={exc}")
        flash(str(exc), "danger")
    return redirect(url_for("directory.user_details", username=username))


@bp.get("/groups")
@login_required
def groups():
    query = request.args.get("q", "").strip()
    records, error = _safe_load(lambda: DirectoryService().groups(query=query))
    return render_template(
        "directory/groups.html",
        records=records,
        query=query,
        error=error,
        first_value=first_value,
    )


@bp.get("/ous")
@login_required
def organizational_units():
    query = request.args.get("q", "").strip()
    records, error = _safe_load(lambda: DirectoryService().organizational_units(query=query))
    return render_template(
        "directory/ous.html",
        records=records,
        query=query,
        error=error,
        first_value=first_value,
        ou_path=ou_path,
        format_ad_datetime=format_ad_datetime,
    )


@bp.get("/computers")
@login_required
def computers():
    query = request.args.get("q", "").strip()
    records, error = _safe_load(lambda: DirectoryService().computers(query=query))
    return render_template(
        "directory/computers.html",
        records=records,
        query=query,
        error=error,
        first_value=first_value,
        computer_name=computer_name,
        dn_organizational_path=dn_organizational_path,
        format_ad_datetime=format_ad_datetime,
    )


@bp.get("/domain-enrollment")
@login_required
def domain_enrollment():
    service = DirectoryService()
    error = None
    try:
        ou_records = service.organizational_units(limit=0)
        computer_records = service.computers(limit=0)
        user_records = service.users(limit=0)
    except DirectoryError as exc:
        ou_records = []
        computer_records = []
        user_records = []
        error = str(exc)

    allowed_bases = tuple(
        current_app.config.get("AD_JOIN_ALLOWED_OU_BASES", ())
    )
    teacher_computer_ou = str(
        current_app.config.get("AD_TEACHER_COMPUTER_OU", "")
    ).strip()
    ou_options = []
    for item in ou_records:
        dn = first_value(
            item,
            "distinguishedName",
            str(item.get("dn", "")),
        )
        mode = naming_mode_for_ou(dn)
        if not mode or not any(
            distinguished_name_within(dn, base)
            for base in allowed_bases
        ):
            continue
        if (
            mode == "teacher"
            and teacher_computer_ou
            and dn.casefold() != teacher_computer_ou.casefold()
        ):
            continue
        ou_options.append(
            {
                "name": first_value(item, "ou", ou_name_from_dn(dn)),
                "path": ou_path(dn),
                "distinguished_name": dn,
                "mode": mode,
            }
        )
    ou_options.sort(key=lambda item: item["path"].casefold())

    teacher_user_ou = str(
        current_app.config.get("AD_TEACHER_USER_OU", "")
    ).strip()
    teachers = [
        item
        for item in user_records
        if distinguished_name_within(
            first_value(
                item,
                "distinguishedName",
                str(item.get("dn", "")),
            ),
            teacher_user_ou,
        )
        and account_enabled(item)
    ]
    teachers.sort(
        key=lambda item: first_value(
            item,
            "displayName",
            first_value(item, "sAMAccountName", ""),
        ).casefold()
    )

    mode = request.args.get("mode", "").strip().casefold()
    selected_ou = request.args.get("organizational_unit", "").strip()
    selected_teacher = request.args.get("teacher", "").strip()
    number = request.args.get("number", "").strip()
    preview = None
    preview_error = None

    if mode:
        selected_option = next(
            (
                item
                for item in ou_options
                if item["distinguished_name"].casefold()
                == selected_ou.casefold()
                and item["mode"] == mode
            ),
            None,
        )
        try:
            if selected_option is None:
                raise ComputerNameError(
                    "Wybierz jednostkę OU pasującą do rodzaju komputera."
                )

            existing_names = [
                computer_name(item)
                for item in computer_records
            ]
            free_numbers: list[int] | None = None
            if mode == "room":
                room_name = ou_name_from_dn(selected_ou)
                free_numbers = [
                    value
                    for value in range(1, 100)
                    if not computer_name_exists(
                        room_computer_name(room_name, value),
                        existing_names,
                    )
                ]
                candidate = room_computer_name(room_name, number)
                available = not computer_name_exists(
                    candidate,
                    existing_names,
                )
            elif mode == "teacher":
                teacher = next(
                    (
                        item
                        for item in teachers
                        if first_value(
                            item,
                            "sAMAccountName",
                            "",
                        ).casefold()
                        == selected_teacher.casefold()
                    ),
                    None,
                )
                if teacher is None:
                    raise ComputerNameError("Wybierz nauczyciela.")
                candidate = teacher_computer_name(
                    first_value(teacher, "givenName", ""),
                    first_value(teacher, "sn", ""),
                    existing_names,
                )
                available = True
            elif mode == "admin":
                candidate = admin_computer_name(existing_names)
                available = True
            else:
                raise ComputerNameError("Nieznany rodzaj komputera.")

            preview = {
                "computer_name": candidate,
                "available": available,
                "organizational_unit": selected_option,
                "free_numbers": free_numbers,
            }
        except ComputerNameError as exc:
            preview_error = str(exc)

    return render_template(
        "directory/domain_enrollment.html",
        error=error,
        ou_options=ou_options,
        teachers=teachers,
        mode=mode or "room",
        selected_ou=selected_ou,
        selected_teacher=selected_teacher,
        number=number,
        preview=preview,
        preview_error=preview_error,
        dns_servers=tuple(current_app.config.get("AD_DNS_SERVERS", ())),
        first_value=first_value,
    )


@bp.get("/computers/export.csv")
@login_required
def computers_export():
    query = request.args.get("q", "").strip()
    try:
        records = DirectoryService().computers(query=query, limit=0)
    except DirectoryError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("directory.computers", q=query))

    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";")
    writer.writerow(["Nazwa", "DNS", "System", "Wersja", "OU", "Ostatnie logowanie", "Opis"])
    for item in records:
        writer.writerow([
            computer_name(item),
            first_value(item, "dNSHostName", ""),
            first_value(item, "operatingSystem", ""),
            first_value(item, "operatingSystemVersion", ""),
            dn_organizational_path(item.get("dn", "")),
            format_ad_datetime(item.get("lastLogonTimestamp")),
            first_value(item, "description", ""),
        ])
    payload = "\ufeff" + stream.getvalue()
    return Response(
        payload,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=komputery-ad.csv"},
    )


@bp.get("/computers/<computer>")
@login_required
def computer_details(computer: str):
    try:
        item = DirectoryService().computer(computer)
    except DirectoryError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("directory.computers"))
    if item is None:
        abort(404)

    groups = item.get("memberOf", [])
    if not isinstance(groups, list):
        groups = [groups] if groups else []

    return render_template(
        "directory/computer_details.html",
        item=item,
        groups=groups,
        first_value=first_value,
        computer_name=computer_name,
        dn_common_name=dn_common_name,
        dn_organizational_path=dn_organizational_path,
        format_ad_datetime=format_ad_datetime,
        sid_value=sid_value,
    )


@bp.post("/users/<username>/groups/add")
@login_required
def add_to_group(username: str):
    if not _is_administrator():
        abort(403)
    service = DirectoryService()
    records, _ = _safe_load(lambda: service.groups(limit=0))
    form = GroupMembershipForm()
    form.group_dn.choices = [
        (first_value(item, "distinguishedName", item.get("dn", "")), first_value(item, "sAMAccountName"))
        for item in records
    ]
    if not form.validate_on_submit():
        flash("Wybierz prawidłową grupę.", "danger")
        return redirect(url_for("directory.user_details", username=username))
    try:
        service.add_user_to_group(username, form.group_dn.data)
        _audit("AD_GROUP_ADD", "SUCCESS", f"target={username}; group={form.group_dn.data}")
        flash("Użytkownik został dodany do grupy.", "success")
    except DirectoryError as exc:
        _audit("AD_GROUP_ADD", "FAILURE", f"target={username}; group={form.group_dn.data}; error={exc}")
        flash(str(exc), "danger")
    return redirect(url_for("directory.user_details", username=username))


@bp.post("/users/<username>/groups/remove")
@login_required
def remove_from_group(username: str):
    if not _is_administrator():
        abort(403)
    group_dn = request.form.get("group_dn", "").strip()
    if not group_dn:
        flash("Nie wskazano grupy.", "danger")
        return redirect(url_for("directory.user_details", username=username))
    try:
        DirectoryService().remove_user_from_group(username, group_dn)
        _audit("AD_GROUP_REMOVE", "SUCCESS", f"target={username}; group={group_dn}")
        flash("Użytkownik został usunięty z grupy.", "success")
    except DirectoryError as exc:
        _audit("AD_GROUP_REMOVE", "FAILURE", f"target={username}; group={group_dn}; error={exc}")
        flash(str(exc), "danger")
    return redirect(url_for("directory.user_details", username=username))


@bp.post("/users/<username>/move")
@login_required
def move_user(username: str):
    if not _is_administrator():
        abort(403)
    service = DirectoryService()
    records, _ = _safe_load(lambda: service.organizational_units(limit=0))
    form = MoveUserForm()
    form.target_ou_dn.choices = [
        (first_value(item, "distinguishedName", item.get("dn", "")), ou_path(first_value(item, "distinguishedName", item.get("dn", ""))))
        for item in records
    ]
    if not form.validate_on_submit():
        flash("Wybierz prawidłową jednostkę OU.", "danger")
        return redirect(url_for("directory.user_details", username=username))
    try:
        service.move_user(username, form.target_ou_dn.data)
        _audit("AD_USER_MOVE", "SUCCESS", f"target={username}; ou={form.target_ou_dn.data}")
        flash("Użytkownik został przeniesiony.", "success")
    except DirectoryError as exc:
        _audit("AD_USER_MOVE", "FAILURE", f"target={username}; ou={form.target_ou_dn.data}; error={exc}")
        flash(str(exc), "danger")
    return redirect(url_for("directory.user_details", username=username))


@bp.post("/users/bulk-action")
@login_required
def bulk_user_action():
    if not _is_administrator():
        abort(403)
    form = BulkUserActionForm()
    usernames = list(dict.fromkeys(request.form.getlist("usernames")))[:200]
    if not form.validate_on_submit() or not usernames:
        flash("Zaznacz użytkowników i wybierz operację.", "danger")
        return redirect(url_for("directory.users"))

    service = DirectoryService()
    succeeded = 0
    failures: list[str] = []
    for username in usernames:
        try:
            if form.action.data == "enable":
                service.set_account_enabled(username, enabled=True)
            elif form.action.data == "disable":
                service.set_account_enabled(username, enabled=False)
            elif form.action.data == "unlock":
                service.unlock_account(username)
            else:
                abort(400)
            succeeded += 1
        except DirectoryError as exc:
            failures.append(f"{username}: {exc}")

    result = "SUCCESS" if not failures else ("FAILURE" if not succeeded else "PARTIAL")
    _audit(
        f"AD_BULK_{form.action.data.upper()}",
        result,
        f"targets={','.join(usernames)}; succeeded={succeeded}; failed={len(failures)}",
    )
    if succeeded:
        flash(f"Operację wykonano dla {succeeded} kont.", "success")
    if failures:
        flash(f"Niepowodzenia: {len(failures)}. Pierwszy błąd: {failures[0]}", "warning")
    return redirect(url_for("directory.users"))


@bp.post("/test")
@login_required
def test_connection():
    try:
        result = DirectoryService().test_connection()
        if result["status"] == "demo":
            flash("Aktywne są wyłącznie dane demonstracyjne. Połączenie LDAP jest wyłączone.", "info")
        else:
            flash(
                f"Połączenie LDAP działa: {result['server']} / {result['base_dn']}",
                "success",
            )
    except DirectoryError as exc:
        flash(str(exc), "danger")
    return redirect(request.referrer or url_for("directory.users"))

from __future__ import annotations

from flask_login import current_user


ADMIN_ROLE = "administrator"
SCHOOL_MANAGEMENT_ROLES = frozenset(
    {
        ADMIN_ROLE,
        "dyrektor",
        "wicedyrektor",
    }
)


def has_role(*roles: str) -> bool:
    return bool(
        current_user.is_authenticated
        and str(current_user.role).strip().lower() in roles
    )


def is_administrator() -> bool:
    return has_role(ADMIN_ROLE)


def is_school_management() -> bool:
    return has_role(*SCHOOL_MANAGEMENT_ROLES)

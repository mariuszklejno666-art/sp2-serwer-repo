from flask import Blueprint


bp = Blueprint("school_services", __name__, url_prefix="/school-services")

from . import announcements, routes  # noqa: E402, F401

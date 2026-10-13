from flask import Blueprint

bp = Blueprint("rooms", __name__, url_prefix="/rooms")

from . import routes  # noqa: E402, F401

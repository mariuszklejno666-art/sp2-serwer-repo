from flask import Blueprint

bp = Blueprint("teachers", __name__, url_prefix="/teachers")

from . import routes  # noqa: E402, F401

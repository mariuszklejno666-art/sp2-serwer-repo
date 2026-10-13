from flask import Blueprint

bp = Blueprint("directory", __name__, url_prefix="/directory")

from . import routes  # noqa: E402, F401

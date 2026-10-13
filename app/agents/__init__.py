from flask import Blueprint

bp = Blueprint("agents", __name__, url_prefix="/agents")
api_bp = Blueprint("agent_api", __name__, url_prefix="/api/v1/agent")

from . import routes  # noqa: E402,F401
from . import deployment  # noqa: E402,F401
from . import profile_routes  # noqa: E402,F401
from . import recovery_routes  # noqa: E402,F401
from . import recovery_pairing  # noqa: E402,F401

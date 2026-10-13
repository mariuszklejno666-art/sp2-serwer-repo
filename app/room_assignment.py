from __future__ import annotations

import re


ROOM_HOSTNAME_PATTERN = re.compile(r"^S(11|32|4|7)-(?:0*[1-9]\d*)$", re.IGNORECASE)


def room_from_hostname(hostname: object) -> str | None:
    """Return the canonical room profile encoded in an SP2 hostname."""
    match = ROOM_HOSTNAME_PATTERN.fullmatch(str(hostname or "").strip())
    return f"Sala{match.group(1)}" if match else None


def effective_room(room: object, hostname: object) -> str | None:
    explicit = str(room or "").strip()
    return explicit or room_from_hostname(hostname)

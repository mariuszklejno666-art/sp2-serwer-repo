from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RadioSource:
    key: str
    name: str
    kind: str
    public_url: str
    status: str
    description: str
    school_broadcast_allowed: bool


RADIO_SOURCES = (
    RadioSource(
        key="radio-zet",
        name="Radio ZET",
        kind="radio",
        public_url="https://player.radiozet.pl/",
        status="Oficjalny odtwarzacz",
        description="Otwiera oficjalny serwis Radia ZET w nowej karcie.",
        school_broadcast_allowed=False,
    ),
    RadioSource(
        key="rmf-fm",
        name="RMF FM",
        kind="radio",
        public_url="https://www.rmfon.pl/play,5",
        status="Oficjalny odtwarzacz",
        description="Otwiera oficjalny serwis RMF ON w nowej karcie.",
        school_broadcast_allowed=False,
    ),
)

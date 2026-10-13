from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class LowDiskVolume:
    """Wolumin lokalny przekraczający próg zajętości."""

    agent_id: int
    hostname: str
    room: str | None
    mount: str
    percent_used: float
    free_bytes: int
    total_bytes: int


def low_disk_volumes(agents: Iterable[Any], threshold_percent: float) -> list[LowDiskVolume]:
    """Zwraca dyski lokalne komputerów z agentem, których zajętość
    przekracza próg, posortowane od najbardziej zapełnionych."""
    results: list[LowDiskVolume] = []
    for agent in agents:
        for disk in agent.disks or []:
            percent_used = disk.get("percent_used")
            if not isinstance(percent_used, (int, float)):
                continue
            if percent_used < threshold_percent:
                continue
            results.append(
                LowDiskVolume(
                    agent_id=agent.id,
                    hostname=agent.hostname,
                    room=agent.room,
                    mount=str(disk.get("mount") or "—"),
                    percent_used=float(percent_used),
                    free_bytes=int(disk.get("free_bytes") or 0),
                    total_bytes=int(disk.get("total_bytes") or 0),
                )
            )
    return sorted(results, key=lambda item: item.percent_used, reverse=True)

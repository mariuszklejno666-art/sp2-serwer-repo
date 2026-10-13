from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class BellPreview:
    schedule: str
    label: str
    due_at: datetime


@dataclass(frozen=True)
class DueBell:
    event_id: int
    schedule: str
    label: str
    due_at: datetime
    track: object

    @property
    def execution_key(self) -> str:
        return f"{self.due_at.isoformat(timespec='minutes')}:{self.event_id}"


def next_bell(now: datetime, school_day: object, schedules: Iterable[object]) -> BellPreview | None:
    """Return the next configured bell without causing any playback side effect."""
    if not school_day.bells:
        return None

    active = next(
        (
            schedule
            for schedule in schedules
            if schedule.enabled and schedule.name == school_day.schedule
        ),
        None,
    )
    if active is None:
        return None

    for event in active.events:
        if not event.enabled:
            continue
        due_at = datetime.combine(now.date(), event.time_of_day, tzinfo=now.tzinfo)
        if due_at >= now:
            return BellPreview(active.name, event.label, due_at)
    return None


def due_bells(now: datetime, school_day: object, schedules: Iterable[object]) -> list[DueBell]:
    """Return enabled, audio-assigned bells due in the current local minute."""
    if not school_day.bells:
        return []
    active = next(
        (schedule for schedule in schedules if schedule.enabled and schedule.name == school_day.schedule),
        None,
    )
    if active is None:
        return []

    result: list[DueBell] = []
    for event in active.events:
        assignment = getattr(event, "audio_assignment", None)
        track = getattr(assignment, "track", None)
        if not event.enabled or track is None or not track.enabled:
            continue
        due_at = datetime.combine(now.date(), event.time_of_day, tzinfo=now.tzinfo)
        if due_at.replace(second=0, microsecond=0) == now.replace(second=0, microsecond=0):
            result.append(DueBell(event.id, active.name, event.label, due_at, track))
    return result


def was_executed(state_path: Path, execution_key: str) -> bool:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return False
    return state.get("last_execution_key") == execution_key


def mark_executed(state_path: Path, execution_key: str) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_path.write_text(
        json.dumps({"last_execution_key": execution_key}, ensure_ascii=False),
        encoding="utf-8",
    )
    state_path.chmod(0o600)

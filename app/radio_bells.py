from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import Flask

from app.extensions import db
from app.models import BellSchedule, SchoolCalendarException
from app.radio_calendar import classify_school_day
from app.radio_player import PlaybackError, start_playlist
from app.radio_scheduler import due_bells, mark_executed, was_executed


logger = logging.getLogger(__name__)


def run_bell_tick(app: Flask, now: datetime | None = None) -> str:
    """Play the bell due in the current Warsaw minute, at most once."""
    if not app.config["RADIO_PLAYBACK_ENABLED"]:
        return "Odtwarzanie radiowęzła jest wyłączone."
    if not app.config["RADIO_BELL_AUTOMATION_ENABLED"]:
        return "Automatyczne dzwonki są wyłączone."

    local_now = now or datetime.now(ZoneInfo("Europe/Warsaw"))
    exceptions = db.session.scalars(
        db.select(SchoolCalendarException).where(SchoolCalendarException.enabled.is_(True))
    ).all()
    school_day = classify_school_day(local_now.date(), exceptions)
    schedules = db.session.scalars(
        db.select(BellSchedule).where(BellSchedule.enabled.is_(True))
    ).unique().all()
    due = due_bells(local_now, school_day, schedules)
    if not due:
        return "Brak dzwonka w bieżącej minucie."

    bell = due[0]
    state_dir = Path(app.instance_path) / "radio_player"
    execution_state = Path(app.instance_path) / "radio_bells" / "last_execution.json"
    if was_executed(execution_state, bell.execution_key):
        return "Dzwonek został już wykonany."

    upload_dir = Path(app.instance_path) / "radio_uploads"
    try:
        start_playlist(
            playlist_name=f"Dzwonek: {bell.label}",
            tracks=[upload_dir / bell.track.stored_filename],
            upload_dir=upload_dir,
            state_dir=state_dir,
            binary=app.config["RADIO_PLAYER_BINARY"],
            audio_device=app.config["RADIO_AUDIO_DEVICE"],
        )
    except PlaybackError as exc:
        logger.warning("Pominięto automatyczny dzwonek %s: %s", bell.execution_key, exc)
        return f"Dzwonek pominięty: {exc}"

    mark_executed(execution_state, bell.execution_key)
    logger.info("Uruchomiono automatyczny dzwonek %s (%s)", bell.label, bell.execution_key)
    return f"Uruchomiono dzwonek: {bell.label}."

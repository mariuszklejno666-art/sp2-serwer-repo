from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


class WebBlockRule(db.Model):
    __tablename__ = "web_block_rules"

    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(120), nullable=False)
    source_url = db.Column(db.String(500), nullable=False)
    hostname = db.Column(db.String(253), nullable=False, index=True)
    rooms = db.Column(db.String(32), nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    @property
    def room_list(self) -> tuple[str, ...]:
        return tuple(value for value in self.rooms.split(",") if value)


class SchoolCalendarException(db.Model):
    __tablename__ = "school_calendar_exceptions"

    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(160), nullable=False)
    starts_on = db.Column(db.Date, nullable=False, index=True)
    ends_on = db.Column(db.Date, nullable=False, index=True)
    kind = db.Column(db.String(32), nullable=False, default="break")
    lessons = db.Column(db.Boolean, nullable=False, default=False)
    bells = db.Column(db.Boolean, nullable=False, default=False)
    schedule = db.Column(db.String(64), nullable=False, default="brak")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class BellSchedule(db.Model):
    __tablename__ = "bell_schedules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True, index=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    events = db.relationship(
        "BellEvent",
        back_populates="schedule",
        cascade="all, delete-orphan",
        order_by="BellEvent.time_of_day",
    )


class BellEvent(db.Model):
    __tablename__ = "bell_events"

    id = db.Column(db.Integer, primary_key=True)
    schedule_id = db.Column(
        db.Integer,
        db.ForeignKey("bell_schedules.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    label = db.Column(db.String(120), nullable=False)
    time_of_day = db.Column(db.Time, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    schedule = db.relationship("BellSchedule", back_populates="events")
    audio_assignment = db.relationship(
        "BellEventAudio",
        back_populates="event",
        cascade="all, delete-orphan",
        uselist=False,
    )

    __table_args__ = (
        db.UniqueConstraint("schedule_id", "time_of_day", name="uq_bell_event_schedule_time"),
    )


class BellEventAudio(db.Model):
    __tablename__ = "bell_event_audio"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(
        db.Integer,
        db.ForeignKey("bell_events.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    track_id = db.Column(
        db.Integer,
        db.ForeignKey("audio_tracks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    event = db.relationship("BellEvent", back_populates="audio_assignment")
    track = db.relationship("AudioTrack")



class AudioTrack(db.Model):
    __tablename__ = "audio_tracks"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    media_type = db.Column(db.String(16), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    playlist_entries = db.relationship(
        "AudioPlaylistEntry",
        back_populates="track",
        cascade="all, delete-orphan",
    )


class AudioPlaylist(db.Model):
    __tablename__ = "audio_playlists"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True, index=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_by = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    entries = db.relationship(
        "AudioPlaylistEntry",
        back_populates="playlist",
        cascade="all, delete-orphan",
        order_by="AudioPlaylistEntry.position",
    )


class AudioPlaylistEntry(db.Model):
    __tablename__ = "audio_playlist_entries"

    id = db.Column(db.Integer, primary_key=True)
    playlist_id = db.Column(
        db.Integer,
        db.ForeignKey("audio_playlists.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    track_id = db.Column(
        db.Integer,
        db.ForeignKey("audio_tracks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    position = db.Column(db.Integer, nullable=False)
    created_by = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    playlist = db.relationship("AudioPlaylist", back_populates="entries")
    track = db.relationship("AudioTrack", back_populates="playlist_entries")

    __table_args__ = (
        db.UniqueConstraint(
            "playlist_id",
            "track_id",
            name="uq_audio_playlist_track",
        ),
        db.UniqueConstraint(
            "playlist_id",
            "position",
            name="uq_audio_playlist_position",
        ),
    )

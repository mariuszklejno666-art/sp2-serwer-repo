from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


class Announcement(db.Model):
    __tablename__ = "announcements"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    body = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(24), nullable=False, default="informational", index=True)
    audience = db.Column(db.String(80), nullable=False, default="all")
    starts_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    ends_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    enabled = db.Column(db.Boolean, nullable=False, default=False, index=True)
    pinned = db.Column(db.Boolean, nullable=False, default=False)
    created_by = db.Column(db.String(64), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def is_active_at(self, moment: datetime) -> bool:
        if not self.enabled:
            return False
        moment_utc = self._as_utc(moment)
        starts_at = self._as_utc(self.starts_at)
        ends_at = self._as_utc(self.ends_at)
        if starts_at is not None and moment_utc < starts_at:
            return False
        if ends_at is not None and moment_utc >= ends_at:
            return False
        return True

    @staticmethod
    def _as_utc(value: datetime | None) -> datetime | None:
        """Normalize SQLite-naive and timezone-aware values to UTC."""
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

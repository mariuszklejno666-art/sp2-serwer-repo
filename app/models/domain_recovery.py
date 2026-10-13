"""Additive schema: created by the repository's init-db/create_all convention."""

import uuid

from app.extensions import db
from .agent import utcnow


class RecoveryPairing(db.Model):
    __tablename__ = "domain_recovery_pairings"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    secret_hash = db.Column(db.String(64), nullable=False)
    hostname = db.Column(db.String(15), nullable=False)
    device_id = db.Column(db.String(36), nullable=False)
    address = db.Column(db.String(64), nullable=False)
    approved_by = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    consumed = db.Column(db.Boolean, nullable=False, default=False)
    replace_existing = db.Column(db.Boolean, nullable=False, default=False)


class DomainRecovery(db.Model):
    __tablename__ = "domain_recoveries"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    computer_id = db.Column(
        db.Integer, db.ForeignKey("agent_computers.id"), nullable=False, index=True
    )
    request_id = db.Column(db.String(36), nullable=False)
    device_id = db.Column(db.String(36), nullable=False)
    source_name = db.Column(db.String(15), nullable=False)
    target_name = db.Column(db.String(15), nullable=False)
    target_ou = db.Column(db.String(512), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    source_sid = db.Column(db.String(184), nullable=False, default="")
    state = db.Column(db.String(32), nullable=False, default="ready")
    action = db.Column(db.String(32), nullable=False, default="diagnose")
    version = db.Column(db.Integer, nullable=False, default=1)
    # Nullable unique reservations serialize competing plans even on SQLite.
    active_computer = db.Column(db.Integer, unique=True, nullable=True)
    reserved_name = db.Column(db.String(15), unique=True, nullable=True)
    diagnosis = db.Column(db.JSON, nullable=False, default=dict)
    history = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (db.UniqueConstraint("computer_id", "request_id"),)

    def payload(self):
        result = {
            key: getattr(self, key)
            for key in (
                "id",
                "device_id",
                "source_name",
                "target_name",
                "target_ou",
                "domain",
                "source_sid",
                "state",
                "action",
                "version",
                "diagnosis",
                "history",
            )
        }
        result["server_time_utc"] = utcnow().isoformat()
        return result

from __future__ import annotations

import hashlib
import ipaddress
import secrets
from datetime import datetime, timezone

from app.extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AgentComputer(db.Model):
    __tablename__ = "agent_computers"

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False, index=True)
    fqdn = db.Column(db.String(255), nullable=True)
    os_name = db.Column(db.String(255), nullable=True)
    os_version = db.Column(db.String(128), nullable=True)
    username = db.Column(db.String(255), nullable=True)
    ou = db.Column(db.String(512), nullable=True)
    room = db.Column(db.String(128), nullable=True, index=True)
    ip_addresses = db.Column(db.JSON, nullable=False, default=list)
    mac_addresses = db.Column(db.JSON, nullable=False, default=list)
    serial_number = db.Column(db.String(255), nullable=True)
    manufacturer = db.Column(db.String(255), nullable=True)
    model = db.Column(db.String(255), nullable=True)
    cpu = db.Column(db.String(255), nullable=True)
    ram_bytes = db.Column(db.BigInteger, nullable=True)
    cpu_percent = db.Column(db.Float, nullable=True)
    memory_percent = db.Column(db.Float, nullable=True)
    uptime_seconds = db.Column(db.BigInteger, nullable=True)
    metrics_collected_at = db.Column(db.DateTime(timezone=True), nullable=True)
    disks = db.Column(db.JSON, nullable=False, default=list)
    # {"username": str, "session_id": int, "session_name": str} albo None,
    # gdy nikt nie jest aktualnie zalogowany. Do generowania komendy
    # RDP Shadow (mstsc /shadow) — patrz app/remote_desktop.py.
    console_session = db.Column(db.JSON, nullable=True)
    boot_time = db.Column(db.DateTime(timezone=True), nullable=True)
    last_seen = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    agent_version = db.Column(db.String(32), nullable=True)
    registered_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    registration = db.relationship(
        "AgentRegistration", back_populates="computer", uselist=False, cascade="all, delete-orphan"
    )
    jobs = db.relationship(
        "AgentJob", back_populates="computer", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def primary_ip(self) -> str:
        addresses = [str(value).strip() for value in (self.ip_addresses or []) if str(value).strip()]
        parsed: list[tuple[str, ipaddress._BaseAddress]] = []
        for value in addresses:
            try:
                parsed.append((value, ipaddress.ip_address(value)))
            except ValueError:
                continue

        # Prefer a normal private IPv4 LAN address. Link-local 169.254/16 is
        # deliberately rejected because Windows often reports virtual adapters first.
        for value, address in parsed:
            if address.version == 4 and address.is_private and not address.is_link_local and not address.is_loopback:
                return value
        for value, address in parsed:
            if address.version == 4 and not address.is_link_local and not address.is_loopback and not address.is_unspecified:
                return value
        for value, address in parsed:
            if not address.is_link_local and not address.is_loopback and not address.is_unspecified:
                return value
        return addresses[0] if addresses else "—"

    def is_online(self, threshold_seconds: int = 180) -> bool:
        seen = self.last_seen
        if seen is None:
            return False
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        return (utcnow() - seen).total_seconds() <= threshold_seconds


class AgentArchive(db.Model):
    __tablename__ = "agent_archives"

    id = db.Column(db.Integer, primary_key=True)
    computer_id = db.Column(
        db.Integer,
        db.ForeignKey("agent_computers.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    successor_id = db.Column(
        db.Integer,
        db.ForeignKey("agent_computers.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    reason = db.Column(db.String(128), nullable=False)
    archived_by = db.Column(db.String(255), nullable=False)
    archived_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )


class AgentRegistration(db.Model):
    __tablename__ = "agent_registrations"

    id = db.Column(db.Integer, primary_key=True)
    computer_id = db.Column(
        db.Integer, db.ForeignKey("agent_computers.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    rotated_at = db.Column(db.DateTime(timezone=True), nullable=True)

    computer = db.relationship("AgentComputer", back_populates="registration")

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @classmethod
    def issue(cls, computer: AgentComputer) -> tuple["AgentRegistration", str]:
        raw_token = secrets.token_urlsafe(40)
        registration = computer.registration
        if registration is None:
            registration = cls(computer=computer, token_hash=cls.hash_token(raw_token))
        else:
            registration.token_hash = cls.hash_token(raw_token)
            registration.rotated_at = utcnow()
        return registration, raw_token


class AgentEnrollmentCode(db.Model):
    __tablename__ = "agent_enrollment_codes"

    id = db.Column(db.Integer, primary_key=True)
    code_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    created_by = db.Column(db.String(255), nullable=False)

    @staticmethod
    def hash_code(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    @classmethod
    def issue(cls, created_by: str, expires_at: datetime) -> tuple["AgentEnrollmentCode", str]:
        raw_code = secrets.token_urlsafe(32)
        return cls(
            code_hash=cls.hash_code(raw_code),
            expires_at=expires_at,
            created_by=created_by,
        ), raw_code


class AgentEnrollmentUse(db.Model):
    __tablename__ = "agent_enrollment_uses"

    id = db.Column(db.Integer, primary_key=True)
    enrollment_code_id = db.Column(
        db.Integer,
        db.ForeignKey("agent_enrollment_codes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    hostname = db.Column(db.String(255), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    __table_args__ = (
        db.UniqueConstraint(
            "enrollment_code_id",
            "hostname",
            name="uq_agent_enrollment_use_code_hostname",
        ),
    )


class AgentJob(db.Model):
    __tablename__ = "agent_jobs"

    id = db.Column(db.Integer, primary_key=True)
    computer_id = db.Column(
        db.Integer, db.ForeignKey("agent_computers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action = db.Column(db.String(64), nullable=False)
    payload = db.Column(db.JSON, nullable=False, default=dict)
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    claimed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)
    result = db.Column(db.JSON, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    computer = db.relationship("AgentComputer", back_populates="jobs")

    def as_agent_payload(self) -> dict[str, object]:
        return {"id": self.id, "type": self.action, "payload": self.payload or {}}

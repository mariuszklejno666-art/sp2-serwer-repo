"""Additive hardware identity and recovery-only credentials."""
from app.extensions import db
from .agent import utcnow


class RecoveryDevice(db.Model):
    __tablename__ = "recovery_devices"
    device_id = db.Column(db.String(36), primary_key=True)
    computer_id = db.Column(db.Integer, db.ForeignKey("agent_computers.id"), unique=True, nullable=False)
    hardware_uuid = db.Column(db.String(36), nullable=False, default="", index=True)
    mac_addresses = db.Column(db.JSON, nullable=False, default=list)
    current_hostname = db.Column(db.String(15), nullable=False)
    owned_source_sid = db.Column(db.String(184), nullable=False, default="")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class RecoveryDeviceToken(db.Model):
    __tablename__ = "recovery_device_tokens"
    token_hash = db.Column(db.String(64), primary_key=True)
    device_id = db.Column(db.String(36), db.ForeignKey("recovery_devices.device_id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class RecoveryPairingHardware(db.Model):
    __tablename__ = "recovery_pairing_hardware"
    pair_id = db.Column(db.String(36), db.ForeignKey("domain_recovery_pairings.id"), primary_key=True)
    hardware = db.Column(db.JSON, nullable=False)


class RecoveryHardwareKey(db.Model):
    """Additive unique UUID/MAC claims serialize duplicate registration."""
    __tablename__ = "recovery_hardware_keys"
    key = db.Column(db.String(64), primary_key=True)
    device_id = db.Column(db.String(36), db.ForeignKey("recovery_devices.device_id"),
                          nullable=False, index=True)


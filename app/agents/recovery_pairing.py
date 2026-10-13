"""Browser approval uses SP2 ADMIN login; no domain passwords in the API."""

import hmac
import secrets
from datetime import timedelta, timezone

from flask import abort, jsonify, render_template, request
from flask_login import current_user, login_required

from app.extensions import csrf, db
from app.models import AgentComputer, AgentRegistration, AuditLog, RecoveryPairing, DomainRecovery
from app.models.agent import utcnow
from app.models.recovery_device import RecoveryDevice, RecoveryDeviceToken, RecoveryPairingHardware
from .recovery_devices import hardware_value, find_device, legacy_agent, profile, claim_hardware
from .domain_repair import computer_state
from . import api_bp, bp
from .domain_repair import valid_name
from .recovery_routes import body, guarded, uuid_value


def pairing_record(pair_id):
    item = db.session.get(RecoveryPairing, pair_id)
    if not item:
        abort(404)
    expires = (
        item.expires_at.replace(tzinfo=timezone.utc)
        if item.expires_at.tzinfo is None
        else item.expires_at
    )
    if expires <= utcnow() or item.consumed:
        abort(410)
    return item


@api_bp.post("/domain-repair/pair")
@csrf.exempt
@guarded
def recovery_pair():
    data = body({"hostname", "device_id", "hardware"})
    name, device = valid_name(data.get("hostname")), uuid_value(data.get("device_id"))
    address = (request.remote_addr or "unknown")[:64]
    count = db.session.scalar(
        db.select(db.func.count(RecoveryPairing.id)).where(
            RecoveryPairing.address == address,
            RecoveryPairing.created_at > utcnow() - timedelta(minutes=10),
        )
    )
    if count >= 10:
        abort(429)
    secret = secrets.token_urlsafe(40)
    item = RecoveryPairing(
        hostname=name,
        device_id=device,
        address=address,
        secret_hash=AgentRegistration.hash_token(secret),
        expires_at=utcnow() + timedelta(minutes=10),
    )
    db.session.add(item)
    if "hardware" in data:
        db.session.flush()
        hardware = hardware_value(data["hardware"])
        find_device(device, hardware)  # reject ambiguous/copied identities before approval
        db.session.add(RecoveryPairingHardware(pair_id=item.id, hardware=hardware))
    db.session.commit()
    return jsonify(
        id=item.id, claim_secret=secret, approval_path="/agents/domain-repair/approve/" + item.id
    ), 201


@bp.route("/domain-repair/approve/<pair_id>", methods=["GET", "POST"])
@login_required
def recovery_approve(pair_id):
    if current_user.role != "administrator":
        abort(403)
    item = pairing_record(pair_id)
    snapshot = db.session.get(RecoveryPairingHardware, pair_id)
    known_device = find_device(item.device_id, snapshot.hardware) if snapshot else None
    known_agent = (db.session.get(AgentComputer, known_device.computer_id) if known_device else legacy_agent(item.device_id, snapshot.hardware)) if snapshot else None
    existing = db.session.scalar(
        db.select(AgentComputer.id).where(AgentComputer.hostname == item.hostname)
    )
    if snapshot:
        existing = None  # recovery-only token issuance never rotates the Windows agent token
    if request.method == "POST":
        if request.form.get("confirm") != "yes" or (
            existing and request.form.get("replace_existing") != "yes"
        ):
            abort(400)
        item.approved_by = current_user.username
        item.replace_existing = bool(existing)
        db.session.add(
            AuditLog(
                user_id=current_user.id,
                username=current_user.username,
                action="DOMAIN_RECOVERY_APPROVE",
                result="SUCCESS",
                ip_address=request.remote_addr,
                details=f"{item.id} {item.hostname} {item.device_id}",
            )
        )
        db.session.commit()
    return render_template("agents/recovery_approve.html", pairing=item, existing=bool(existing),
        hardware=snapshot.hardware if snapshot else None,
        registered_name=known_agent.hostname if known_agent else None)


@api_bp.post("/domain-repair/pair/<pair_id>/claim")
@csrf.exempt
@guarded
def recovery_claim(pair_id):
    data = body({"claim_secret"})
    secret = data.get("claim_secret")
    if not isinstance(secret, str) or len(secret) > 128:
        abort(401)
    item = pairing_record(pair_id)
    if not hmac.compare_digest(item.secret_hash, AgentRegistration.hash_token(secret)):
        abort(401)
    if not item.approved_by:
        return jsonify(error="Zaloguj sie do panelu i zatwierdz ten komputer."), 409
    snapshot = db.session.get(RecoveryPairingHardware, pair_id)
    if snapshot:
        return claim_device(item, snapshot.hardware)
    # A transaction claims once before issuing/rotating an agent token.
    changed = db.session.execute(
        db.update(RecoveryPairing)
        .where(RecoveryPairing.id == item.id, RecoveryPairing.consumed.is_(False))
        .values(consumed=True)
    ).rowcount
    if changed != 1:
        db.session.rollback()
        abort(409)
    agent = db.session.scalar(
        db.select(AgentComputer).where(AgentComputer.hostname == item.hostname)
    )
    if agent is not None and not item.replace_existing:
        db.session.rollback()
        abort(409)
    if agent is None:
        agent = AgentComputer(hostname=item.hostname)
    registration, token = AgentRegistration.issue(agent)
    db.session.add_all([agent, registration])
    db.session.commit()
    response = jsonify(token=token)
    response.headers["Cache-Control"] = "no-store"
    return response


def claim_device(item, hardware):
    changed = db.session.execute(db.update(RecoveryPairing).where(
        RecoveryPairing.id == item.id, RecoveryPairing.consumed.is_(False)
    ).values(consumed=True)).rowcount
    if changed != 1:
        db.session.rollback()
        abort(409)
    device = find_device(item.device_id, hardware)
    if not device:
        agent = legacy_agent(item.device_id, hardware)
        owned_sid = ""
        if agent:
            plan = db.session.scalar(db.select(DomainRecovery).where(
                DomainRecovery.computer_id == agent.id, DomainRecovery.device_id == item.device_id
            ).order_by(DomainRecovery.created_at.desc()))
            owned_sid = plan.source_sid if plan else computer_state(item.hostname).object_sid
        else:
            occupied = db.session.scalar(db.select(AgentComputer.id).where(AgentComputer.hostname == item.hostname))
            name = "RECOVERY-" + item.device_id if occupied else item.hostname
            agent = AgentComputer(hostname=name, mac_addresses=hardware["mac_addresses"])
            db.session.add(agent)
            db.session.flush()
        device = RecoveryDevice(device_id=item.device_id, computer_id=agent.id,
            hardware_uuid=hardware["uuid"], mac_addresses=hardware["mac_addresses"],
            current_hostname=item.hostname, owned_source_sid=owned_sid)
        db.session.add(device)
        db.session.flush()
    else:
        device.current_hostname = item.hostname
        device.mac_addresses = sorted(set(device.mac_addresses) | set(hardware["mac_addresses"]))
    # Revoke only prior recovery credentials for this physical device.
    claim_hardware(device)
    db.session.execute(db.delete(RecoveryDeviceToken).where(RecoveryDeviceToken.device_id == device.device_id))
    token = secrets.token_urlsafe(40)
    db.session.add(RecoveryDeviceToken(token_hash=AgentRegistration.hash_token(token), device_id=device.device_id))
    db.session.commit()
    response = jsonify(token=token, **profile(device))
    response.headers["Cache-Control"] = "no-store"
    return response


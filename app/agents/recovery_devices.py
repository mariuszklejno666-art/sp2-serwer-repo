"""Hardware observations identify records; tokens and browser approval authorize access."""
import re
from uuid import UUID
from flask import request, abort
from app.extensions import db
from app.models import AgentComputer, AgentRegistration, DomainRecovery
from app.models.recovery_device import RecoveryDevice, RecoveryDeviceToken, RecoveryHardwareKey


def hardware_value(value):
    if not isinstance(value, dict) or set(value) - {"uuid", "mac_addresses"}:
        raise ValueError("Nieprawidlowe dane sprzetowe.")
    raw = value.get("uuid", "")
    try:
        uid = str(UUID(raw)) if raw else ""
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Nieprawidlowy UUID sprzetu.") from None
    if uid in {str(UUID(int=0)), str(UUID(int=(1 << 128) - 1))}:
        uid = ""
    macs = value.get("mac_addresses", [])
    if not isinstance(macs, list) or len(macs) > 16:
        raise ValueError("Nieprawidlowe adresy MAC.")
    result = set()
    for mac in macs:
        if type(mac) is not str:
            raise ValueError("Nieprawidlowy adres MAC.")
        normalized = re.sub(r"[:-]", "", mac).upper()
        if not re.fullmatch(r"[0-9A-F]{12}", normalized) or normalized == "000000000000" or int(normalized[:2], 16) & 1:
            raise ValueError("Nieprawidlowy adres MAC.")
        result.add(normalized)
    if not uid and not result:
        raise ValueError("Nie mozna potwierdzic identyfikacji sprzetu.")
    return {"uuid": uid, "mac_addresses": sorted(result)}


def find_device(device_id, hardware):
    direct = db.session.get(RecoveryDevice, device_id)
    devices = db.session.scalars(db.select(RecoveryDevice)).all()
    matches = []
    macs = set(hardware["mac_addresses"])
    for device in devices:
        uuid_match = bool(hardware["uuid"] and device.hardware_uuid == hardware["uuid"])
        mac_match = bool(macs & set(device.mac_addresses))
        if device is direct:
            if hardware["uuid"] and device.hardware_uuid and hardware["uuid"] != device.hardware_uuid:
                abort(409, description="Identyfikator lokalny nalezy do innego sprzetu.")
            # A copied recovery folder with a cloned UUID and another NIC cannot take over a plan.
            if macs and device.mac_addresses and not mac_match:
                abort(409, description="Identyfikator lokalny nie zgadza sie z adresami MAC.")
            matches.append(device)
        elif uuid_match or mac_match:
            if uuid_match and macs and device.mac_addresses and not mac_match:
                abort(409, description="UUID powtarza sie na innym sprzecie. Wymagana kontrola.")
            if mac_match and hardware["uuid"] and device.hardware_uuid and not uuid_match:
                abort(409, description="MAC nalezy do urzadzenia z innym UUID. Wymagana kontrola.")
            matches.append(device)
    if len(matches) > 1:
        abort(409, description="Niejednoznaczna identyfikacja sprzetu.")
    return matches[0] if matches else None


def claim_hardware(device):
    """Called within the device/token transaction; uniqueness closes concurrent races."""
    keys = ["mac:" + m for m in device.mac_addresses]
    if device.hardware_uuid:
        keys.append("uuid:" + device.hardware_uuid)
    for key in keys:
        existing = db.session.get(RecoveryHardwareKey, key)
        if existing and existing.device_id != device.device_id:
            abort(409, description="Sprzet jest juz przypisany do innego urzadzenia.")
        if not existing:
            db.session.add(RecoveryHardwareKey(key=key, device_id=device.device_id))
    db.session.flush()


def legacy_agent(device_id, hardware):
    # Never match an old record solely by its hostname.
    plans = db.session.scalars(db.select(DomainRecovery).where(DomainRecovery.device_id == device_id)).all()
    # Old clients used the firmware UUID. A copied pending.json is not proof.
    ids = {p.computer_id for p in plans} if device_id == hardware["uuid"] else set()
    if hardware["mac_addresses"]:
        for agent in db.session.scalars(db.select(AgentComputer)).all():
            known = {re.sub(r"[:-]", "", str(m)).upper() for m in (agent.mac_addresses or [])}
            if known & set(hardware["mac_addresses"]):
                ids.add(agent.id)
    if len(ids) > 1:
        abort(409, description="Sprzet pasuje do kilku rejestracji.")
    if not ids:
        return None
    agent = db.session.get(AgentComputer, ids.pop())
    bound = db.session.scalar(db.select(RecoveryDevice).where(RecoveryDevice.computer_id == agent.id))
    if bound:
        return None
    known = {re.sub(r"[:-]", "", str(m)).upper() for m in (agent.mac_addresses or [])}
    if known and hardware["mac_addresses"] and not known & set(hardware["mac_addresses"]):
        return None
    return agent


def device_for_token():
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    entry = db.session.get(RecoveryDeviceToken, AgentRegistration.hash_token(token)) if token else None
    return db.session.get(RecoveryDevice, entry.device_id) if entry else None


def profile(device):
    agent = db.session.get(AgentComputer, device.computer_id)
    plan = db.session.scalar(db.select(DomainRecovery).where(DomainRecovery.active_computer == agent.id, DomainRecovery.device_id == device.device_id))
    return {"device_id": device.device_id, "known": True, "registered_name": agent.hostname,
                "observed_name": device.current_hostname, "room": agent.room or "", "ou": agent.ou or "",
                "plan": plan.payload() if plan else None}


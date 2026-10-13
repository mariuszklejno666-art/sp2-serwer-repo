"""Durable, agent-scoped recovery. Never accept arbitrary logs or credentials."""

import re
from functools import wraps
from datetime import datetime, timedelta
from uuid import UUID

from flask import abort, current_app, jsonify, request
from sqlalchemy.exc import IntegrityError

from app.directory.service import DirectoryError, DirectoryService, first_value
from app.domain_naming import distinguished_name_within
from app.extensions import csrf, db
from app.models import AgentComputer, AgentRegistration, DomainRecovery, RecoveryPairing
from app.models.recovery_device import RecoveryDevice
from .recovery_devices import (
    device_for_token, hardware_value, find_device, legacy_agent, profile, claim_hardware,
)
from app.models.agent import utcnow
from . import api_bp
from .domain_repair import (
    ad_timestamp, build_diagnosis, computer_state, valid_name, validate_local, normalize_macs,
)
from .routes import _registered_agent_for_token, _enrollment_credential, _consume_enrollment_code


def guarded(fn):
    @wraps(fn)
    def run(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ValueError as exc:
            db.session.rollback()
            return jsonify(error=str(exc)), 400
        except DirectoryError:
            db.session.rollback()
            return jsonify(error="Nie mozna potwierdzic stanu AD. Operacja zablokowana."), 503
        except IntegrityError:
            db.session.rollback()
            return jsonify(error="Komputer lub nazwa ma juz aktywny plan."), 409

    return run


def body(keys):
    if request.content_length and request.content_length > 8192:
        abort(413)
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - set(keys):
        raise ValueError("Nieobslugiwane pola. API nie przyjmuje hasel ani logow.")
    return data


def uuid_value(value):
    try:
        result = str(UUID(value))
        if int(UUID(result)) == 0:
            raise ValueError()
        return result
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Wymagany niezerowy UUID.") from None


def available_candidates(requested):
    student = re.fullmatch(r"(S[0-9]{1,3}-)([0-9]{2})", str(requested or ""))
    teacher = re.fullmatch(r"((?:BR|PL)-S[0-9]{1,3})(?:-([0-9]{2}))?", str(requested or ""))
    if student and 1 <= int(student[2]) <= 99:
        first = int(student[2])
        return [student[1] + f"{n:02d}" for n in list(range(first, 100)) + list(range(1, first))]
    if teacher and (teacher[2] is None or 1 <= int(teacher[2]) <= 99):
        first = int(teacher[2] or 0)
        return [teacher[1] if n == 0 else teacher[1] + f"-{n:02d}"
                for n in list(range(first, 100)) + list(range(1, first))]
    raise ValueError("Nieprawidlowy format automatycznej nazwy komputera.")


def agent_required():
    device = device_for_token()
    if device:
        return db.session.get(AgentComputer, device.computer_id)
    agent = _registered_agent_for_token()
    if agent is None:
        abort(401)
    return agent


def owned_plan(plan_id):
    agent = agent_required()
    plan = db.session.get(DomainRecovery, plan_id)
    if plan is None or plan.computer_id != agent.id:
        abort(404)
    device = device_for_token()
    if device and plan.device_id != device.device_id:
        abort(403)
    return agent, plan


# Any of these in a plan's history means Windows or AD may have been changed.
PLAN_STARTED_EVENTS = frozenset({"begin", "credential_issued", "approve_ad", "retry", "failed"})
CANCEL_REASONS = frozenset({
    "operator_rejected_target_name",
    "operator_changed_target_name",
    "operator_cancelled_wrong_name",
})


def machine_recovery_attempts(plan):
    return [h for h in plan.history
            if h.get("action") == "machine_account_recovery"
            and h.get("event") in {"begin", "credential_issued"}]


def local_resolution_blockers(agent, plan, data, local):
    """Why a stuck machine_account_recovery may NOT be closed as repaired locally.

    The operator repaired the existing account's trust (Test-ComputerSecureChannel
    -Repair) instead of rebuilding it under a new name. Accept that only when:
    the same authenticated hardware reports a healthy channel under the plan's
    source name, AD shows that account enabled in an allowed OU with its machine
    password reset AFTER the last recovery attempt, and the abandoned target
    name left no account behind. Nothing in AD is changed here.
    """
    blockers = []
    attempts = machine_recovery_attempts(plan)
    if data.get("approved") is not True:
        blockers.append("not_approved")
    if plan.state != "manual_review":
        blockers.append("plan_not_in_review")
    if not attempts:
        blockers.append("no_recovery_attempt")
    if (local.get("part_of_domain") is not True or local.get("secure_channel") is not True
            or local.get("domain", "").lower() != plan.domain):
        blockers.append("windows_channel_not_healthy")
    if local.get("hostname", "").upper() != plan.source_name:
        blockers.append("windows_name_changed")
    if not local.get("boot_id"):
        blockers.append("missing_boot_id")
    source = computer_state(plan.source_name)
    if not source.exists or not source.enabled or not source.object_sid:
        blockers.append("source_account_invalid")
    parent = source.dn.partition(",")[2]
    if not parent or not any(distinguished_name_within(parent, base)
                             for base in current_app.config.get("AD_JOIN_ALLOWED_OU_BASES", [])):
        blockers.append("source_ou_not_allowed")
    device = db.session.scalar(db.select(RecoveryDevice).where(RecoveryDevice.device_id == plan.device_id))
    pinned = {sid for sid in (plan.source_sid, device.owned_source_sid if device else "") if sid}
    if source.object_sid and pinned and pinned != {source.object_sid}:
        blockers.append("source_identity_changed")
    reset_at = ad_timestamp(source.password_last_set)
    attempt_at = max((datetime.fromisoformat(h["at"]) for h in attempts if h.get("at")), default=None)
    if reset_at is None or attempt_at is None or reset_at <= attempt_at:
        blockers.append("password_not_reset_after_attempt")
    if plan.target_name != plan.source_name and computer_state(plan.target_name).exists:
        blockers.append("target_account_exists")
    return blockers, source, device


def last_begin(plan):
    return next((h for h in reversed(plan.history) if h.get("event") == "begin"), {})


def durable_history(history, entry):
    combined = history + [entry]
    if len(combined) <= 100:
        return combined
    # Polling must never erase the write-ahead or credential-delivery checkpoints.
    checkpoints = [h for h in combined if h.get("event") in {"begin", "credential_issued"}]
    recent = [h for h in combined if h.get("event") not in {"begin", "credential_issued"}]
    return checkpoints + recent[-(100 - len(checkpoints)):]


def recovery_identity(agent, device_id, local, plan=None):
    """UUID is bound by browser approval; MAC/IP come from registered inventory."""
    reported = set(normalize_macs(local.get("mac_addresses")))
    if plan:
        identity = plan.diagnosis.get("recovery_identity", {})
        if not identity or not reported.intersection(identity.get("mac_addresses", [])):
            abort(403)
        if identity.get("hardware_uuid") and local.get("hardware_uuid", "").lower() != identity["hardware_uuid"]:
            abort(403)
        return identity
    device = device_for_token()
    if device:
        if device.device_id != device_id or device.computer_id != agent.id:
            abort(403)
        if device.hardware_uuid and local.get("hardware_uuid", "").lower() != device.hardware_uuid:
            abort(403)
        if not reported.intersection(normalize_macs(device.mac_addresses)):
            abort(403)
    # RecoveryDevice is the authoritative hardware binding for a recovery
    # token. AgentComputer inventory can be stale after a NIC replacement or
    # before the regular agent has reported again, so do not require the same
    # MAC to exist in both tables for a hardware-bound recovery session.
    stored = set(normalize_macs(device.mac_addresses if device else agent.mac_addresses))
    if not reported.intersection(stored):
        abort(403)
    # Legacy agent tokens still require a previously registered IP address.
    if not device and not agent.ip_addresses:
        abort(403)
    approved = db.session.scalar(db.select(RecoveryPairing.id).where(
        RecoveryPairing.device_id == device_id,
        RecoveryPairing.hostname == agent.hostname,
        RecoveryPairing.consumed.is_(True),
        RecoveryPairing.approved_by.is_not(None),
    ))
    if not approved and not device:
        abort(403)
    return {"device_id": device_id, "hardware_uuid": device.hardware_uuid if device else "", "mac_addresses": sorted(stored),
            "ip_addresses": list(agent.ip_addresses)}


def diagnosis(data, agent, plan=None):
    local = validate_local(data.get("local"))
    source = valid_name(local["hostname"])
    if plan:
        if uuid_value(data.get("device_id")) != plan.device_id or source not in {
            plan.source_name,
            plan.target_name,
        }:
            abort(403)
        sid = plan.source_sid
        # A completed join may have created a new SID. Only adopt after an issued
        # join, a new boot, and a healthy domain channel; never before the join.
        if (
            plan.state in {"pending", "manual_review"}
            and plan.action in {"join", "machine_account_recovery"}
            and source == plan.target_name
            and local.get("part_of_domain") is True
            and local.get("secure_channel") is True
        ):
            if local.get("boot_id") and local["boot_id"] != last_begin(plan).get("boot_id"):
                if not sid:
                    sid = computer_state(source).object_sid
        target, ou = plan.target_name, plan.target_ou
        if plan.domain != current_app.config.get("AD_DOMAIN_FQDN", "").lower():
            raise ValueError("Konfiguracja domeny zmienila sie podczas recovery.")
    else:
        device = device_for_token()
        if source != (device.current_hostname if device else agent.hostname.upper()):
            abort(403)
        # Registration authenticates the source name, but an outside-domain
        # machine must never reuse an existing AD account automatically.
        sid = (device.owned_source_sid if device else computer_state(source).object_sid) if local["part_of_domain"] else ""
        target, ou = data.get("target_name"), data.get("target_ou")
    result = build_diagnosis(
        {"local": local, "target_name": target, "target_ou": ou}, owned_sid=sid
    )
    unowned_source_retarget = (
        device_for_token()
        and local["part_of_domain"]
        and local.get("secure_channel") is False
        and result["source_ad"]["exists"]
        and not sid
        and result["target_name"] != source
        and not result["target_conflict"]
        and current_app.config.get("MACHINE_ACCOUNT_RECOVERY_ENABLED")
    )
    if not plan and device_for_token() and local["part_of_domain"] and result["source_ad"]["exists"] and not sid:
        if unowned_source_retarget:
            result.update(
                status="SOURCE_OWNERSHIP_UNCONFIRMED_RETARGET",
                recommended_action="machine_account_recovery",
            )
        else:
            result.update(status="SOURCE_OWNERSHIP_UNCONFIRMED", recommended_action="blocked")
    if (
        plan
        and plan.action == "machine_account_recovery"
        and plan.diagnosis.get("status") == "SOURCE_OWNERSHIP_UNCONFIRMED_RETARGET"
        and source == plan.source_name
        and unowned_source_retarget
    ):
        result.update(
            status="SOURCE_OWNERSHIP_UNCONFIRMED_RETARGET",
            recommended_action="machine_account_recovery",
        )
    if plan and "recovery_identity" in plan.diagnosis:
        identity = recovery_identity(agent, plan.device_id, local, plan)
        result["recovery_identity"] = identity
        addresses = set(result["checks"].get("dns_addresses", []))
        expected = set(identity["ip_addresses"])
        if source == plan.target_name and expected and (
            not addresses or not addresses.issubset(expected)
        ):
            result.update(status="RECOVERY_DNS_IDENTITY_MISMATCH", recommended_action="blocked")
        if not local["part_of_domain"]:
            result.update(status="RECOVERY_MEMBERSHIP_CHANGED", recommended_action="blocked")
        if result["recommended_action"] == "none" and (
            not any(h.get("event") == "credential_issued" for h in plan.history)
            or not last_begin(plan)
            or not local.get("boot_id")
            or local["boot_id"] == last_begin(plan).get("boot_id")
        ):
            result.update(status="RECOVERY_JOIN_NOT_ISSUED", recommended_action="blocked")
    if plan and plan.source_sid and result["source_ad"]["exists"]:
        if result["source_ad"]["object_sid"] != plan.source_sid:
            result.update(status="SOURCE_IDENTITY_CHANGED", recommended_action="blocked")
    other = db.session.scalar(
        db.select(AgentComputer).where(
            AgentComputer.hostname == result["target_name"], AgentComputer.id != agent.id
        )
    )
    result["target_agent_online"] = other.is_online() if other else None
    if other:
        result.update(
            status="TARGET_AGENT_CONFLICT",
            recommended_action="blocked_conflict",
            target_conflict=True,
        )
    source_ad = result["source_ad"]
    if (sid and source_ad["exists"] and source_ad["dn"] and source_ad["object_sid"] == sid
        and source_ad["dn"].partition(",")[0].upper() != "CN=" + source
        and result["recommended_action"] in {"repair_secure_channel", "rename_domain", "none"}):
        result.update(status="AD_CN_MISMATCH", recommended_action="repair_ad_cn")
    if plan:
        for key in ("requested_target_name", "auto_name"):
            if key in plan.diagnosis:
                result[key] = plan.diagnosis[key]
    return result


def diagnose_request():
    agent = agent_required()
    data = body({"local", "target_name", "target_ou"})
    result = diagnosis(data, agent)
    result["server_time_utc"] = utcnow().isoformat()
    return jsonify(result)


@api_bp.get("/domain-repair/capabilities")
def recovery_capabilities():
    # Public discovery advertises the protocol, never credentials or AD data.
    response = jsonify(service="sp2-admin-domain-repair", protocol=2, pairing=True, hardware_identity=True)
    response.headers["Cache-Control"] = "no-store"
    return response


@api_bp.post("/domain-repair/identify")
@csrf.exempt
@guarded
def recovery_identify():
    data = body({"device_id", "hostname", "hardware"})
    device_id = uuid_value(data.get("device_id"))
    name = valid_name(data.get("hostname"))
    hardware = hardware_value(data.get("hardware"))
    device = find_device(device_id, hardware)
    token_device = device_for_token()
    if token_device:
        if not device or device.device_id != token_device.device_id:
            return jsonify(error_code="IDENTITY_PAIRING_REQUIRED"), 403
    else:
        agent = agent_required()
        if device:
            if device.computer_id != agent.id:
                return jsonify(error_code="IDENTITY_PAIRING_REQUIRED"), 403
        else:
            match = legacy_agent(device_id, hardware)
            if not match or match.id != agent.id:
                return jsonify(error_code="IDENTITY_PAIRING_REQUIRED"), 403
            plan = db.session.scalar(db.select(DomainRecovery).where(DomainRecovery.computer_id == agent.id, DomainRecovery.device_id == device_id).order_by(DomainRecovery.created_at.desc()))
            device = RecoveryDevice(device_id=device_id, computer_id=agent.id,
                hardware_uuid=hardware["uuid"], mac_addresses=hardware["mac_addresses"],
                current_hostname=name, owned_source_sid=plan.source_sid if plan else computer_state(name).object_sid)
            db.session.add(device)
    device.current_hostname = name
    # Accumulate only observations already matching the authenticated device.
    device.mac_addresses = sorted(set(device.mac_addresses) | set(hardware["mac_addresses"]))
    claim_hardware(device)
    db.session.commit()
    response = jsonify(profile(device))
    response.headers["Cache-Control"] = "no-store"
    return response


@api_bp.get("/domain-repair/config")
@csrf.exempt
@guarded
def recovery_config():
    agent_required()
    bases = current_app.config.get("AD_JOIN_ALLOWED_OU_BASES", [])
    ous = [
        first_value(item, "distinguishedName", first_value(item, "dn", ""))
        for item in DirectoryService().organizational_units(limit=0)
    ]
    return jsonify(
        domain=current_app.config.get("AD_DOMAIN_FQDN", ""),
        teacher_ou=current_app.config.get("AD_TEACHER_COMPUTER_OU", ""),
        ous=[ou for ou in ous if any(distinguished_name_within(ou, base) for base in bases)],
    )


@api_bp.post("/domain-repair/enroll")
@csrf.exempt
@guarded
def recovery_enroll():
    credential = _enrollment_credential()
    if credential is None:
        abort(401)
    data = body({"hostname"})
    name = valid_name(data.get("hostname"))
    # Unlike the legacy register route, this cannot rotate another agent's token.
    if db.session.scalar(db.select(AgentComputer.id).where(AgentComputer.hostname == name)):
        return jsonify(
            error="Komputer zarejestrowany. Uzyj jego indywidualnego tokenu agenta."
        ), 409
    if credential[1] is not None and not _consume_enrollment_code(credential[1], name):
        db.session.rollback()
        abort(401)
    agent = AgentComputer(hostname=name)
    registration, token = AgentRegistration.issue(agent)
    db.session.add_all([agent, registration])
    db.session.commit()
    return jsonify(token=token), 201


@api_bp.post("/domain-repair/plan")
@csrf.exempt
@guarded
def recovery_plan():
    agent = agent_required()
    data = body({"request_id", "device_id", "local", "target_name", "target_ou", "auto_name"})
    if "auto_name" in data and type(data["auto_name"]) is not bool:
        raise ValueError("auto_name musi byc wartoscia logiczna.")
    request_id, device_id = uuid_value(data.get("request_id")), uuid_value(data.get("device_id"))
    device = device_for_token()
    if device and device.device_id != device_id:
        abort(403)
    existing = db.session.scalar(
        db.select(DomainRecovery).where(
            DomainRecovery.computer_id == agent.id, DomainRecovery.request_id == request_id
        )
    )
    if existing:
        if (
            existing.device_id != device_id
            or (existing.diagnosis.get("requested_target_name", existing.target_name) != data.get("target_name"))
            or existing.diagnosis.get("auto_name", False) != data.get("auto_name", False)
            or existing.target_ou != data.get("target_ou")
        ):
            abort(409)
        return jsonify(existing.payload())
    requested_name = data.get("target_name")
    if data.get("auto_name"):
        result = None
        for candidate in available_candidates(requested_name):
            # Neither an AD account (including the current account), another
            # agent nor an active recovery reservation counts as a free name.
            if computer_state(candidate).exists:
                continue
            if db.session.scalar(db.select(AgentComputer.id).where(AgentComputer.hostname == candidate)):
                continue
            if db.session.scalar(db.select(DomainRecovery.id).where(DomainRecovery.reserved_name == candidate)):
                continue
            probe = diagnosis({**data, "target_name": candidate}, agent)
            if probe.get("target_conflict"):
                continue
            result = probe
            break
        if result is None:
            return jsonify(error_code="NO_FREE_NAME", error="Brak wolnej nazwy w tej sali."), 409
    else:
        result = diagnosis(data, agent)
    result.update(requested_target_name=requested_name, auto_name=data.get("auto_name", False))
    if result["recommended_action"] in {"blocked", "blocked_conflict", "diagnose"}:
        if result.get("target_conflict"):
            return jsonify(error_code="NAME_TAKEN", error="Nazwa jest zajeta.", diagnosis=result), 409
        return jsonify(error="Plan zablokowany.", diagnosis=result), 409
    if result["recommended_action"] == "machine_account_recovery":
        result["recovery_identity"] = recovery_identity(agent, device_id, data["local"])
    plan = DomainRecovery(
        computer_id=agent.id,
        request_id=request_id,
        device_id=device_id,
        source_name=result["source_name"],
        target_name=result["target_name"],
        target_ou=result["target_ou"],
        domain=result["domain"],
        source_sid=(device.owned_source_sid if device else result["source_ad"]["object_sid"]) if data["local"]["part_of_domain"] else "",
        action=result["recommended_action"],
        diagnosis=result,
        active_computer=agent.id,
        reserved_name=result["target_name"],
    )
    db.session.add(plan)
    db.session.commit()
    return jsonify(plan.payload()), 201


@api_bp.get("/domain-repair/status")
@csrf.exempt
def recovery_pending():
    agent = agent_required()
    plan = db.session.scalar(
        db.select(DomainRecovery).where(DomainRecovery.active_computer == agent.id)
    )
    device = device_for_token()
    if device and plan and plan.device_id != device.device_id:
        return jsonify(error_code="DEVICE_PLAN_MISMATCH"), 403
    return jsonify(plan=plan.payload() if plan else None)


@api_bp.get("/domain-repair/status/<plan_id>")
@csrf.exempt
def recovery_status(plan_id):
    _, plan = owned_plan(plan_id)
    return jsonify(plan.payload())


@api_bp.post("/domain-repair/approve-ad/<plan_id>")
@csrf.exempt
@guarded
def recovery_approve_ad(plan_id):
    from ldap3 import BASE
    from ldap3.core.exceptions import LDAPNoSuchObjectResult, LDAPException
    agent, plan = owned_plan(plan_id)
    data = body({"version", "device_id", "local", "approved"})
    if data.get("approved") is not True or type(data.get("version")) is not int or data["version"] != plan.version:
        abort(409)
    result = diagnosis(data, agent, plan)
    if (plan.state not in {"ready", "manual_review"} or plan.action != "repair_ad_cn"
        or result["recommended_action"] != "repair_ad_cn" or not plan.source_sid):
        abort(409)
    state = result["source_ad"]
    old = state["dn"]
    rdn = "CN=" + result["source_name"]
    new = rdn + "," + old.partition(",")[2]
    # Commit write-ahead state before making a directory change.
    history = (plan.history + [{"event": "approve_ad", "action": "repair_ad_cn", "at": utcnow().isoformat()}])[-100:]
    changed = db.session.execute(db.update(DomainRecovery).where(
        DomainRecovery.id == plan.id, DomainRecovery.version == data["version"]
    ).values(state="pending", history=history, version=plan.version + 1, updated_at=utcnow())).rowcount
    if changed != 1:
        abort(409)
    db.session.commit()
    service = DirectoryService()
    connection = service._connection(write=True)
    try:
        # Recheck immutable SID immediately before the write.
        if computer_state(result["source_name"]).object_sid != plan.source_sid:
            raise DirectoryError("Tozsamosc obiektu zmienila sie.")
        try:
            connection.search(new, "(objectClass=*)", search_scope=BASE, attributes=["objectGUID"])
        except LDAPNoSuchObjectResult:
            pass
        if connection.result.get("result") != 32 or connection.entries:
            raise DirectoryError("Docelowy CN nie jest wolny.")
        if not connection.modify_dn(old, rdn, delete_old_dn=True):
            raise DirectoryError("Korekta CN odrzucona.")
    except LDAPException:
        raise DirectoryError("Korekta CN nie zostala potwierdzona.") from None
    finally:
        connection.unbind()
    after = computer_state(result["source_name"])
    if after.object_sid != plan.source_sid or after.dn.casefold() != new.casefold():
        raise DirectoryError("Nie potwierdzono korekty CN.")
    db.session.refresh(plan)
    return jsonify(plan.payload())


@api_bp.post("/domain-repair/progress/<plan_id>")
@csrf.exempt
@guarded
def recovery_progress(plan_id):
    agent, plan = owned_plan(plan_id)
    data = body({"version", "event", "device_id", "local", "approved", "reason"})
    if "reason" in data and (data.get("event") != "cancel" or data["reason"] not in CANCEL_REASONS):
        raise ValueError("Nieobslugiwany powod anulowania.")
    if type(data.get("version")) is not int or data["version"] != plan.version:
        return jsonify(error_code="STALE_PLAN_VERSION", error="Plan zmienil sie. Pobierz aktualny stan."), 409
    if uuid_value(data.get("device_id")) != plan.device_id:
        abort(403)
    event = data.get("event")
    if event not in {"observe", "begin", "failed", "cancel", "retry", "resolve"}:
        raise ValueError("Nieznany etap recovery.")
    if plan.state in {"complete", "cancelled"}:
        abort(409)
    updates = {"version": plan.version + 1, "updated_at": utcnow()}
    entry = {"event": event, "at": utcnow().isoformat(), "action": plan.action}
    if event == "cancel":
        if plan.state == "pending":
            abort(409)  # first reconcile potentially completed local changes
        if plan.action == "join" and any(h.get("event") == "begin" for h in plan.history):
            # A previously started join is ambiguous. The operator may release
            # its reservation only after a new Windows boot, with the original
            # hardware still authenticated and BOTH AD + Windows confirming
            # that no join was completed. Never delete or reuse an AD account.
            local = validate_local(data.get("local"))
            result = diagnosis(data, agent, plan)
            last = last_begin(plan)
            if (
                data.get("approved") is not True
                or plan.state != "manual_review"
                or local.get("part_of_domain") is not False
                or local.get("secure_channel") is not None
                or local.get("hostname", "").upper() != plan.source_name
                or not local.get("boot_id")
                or local["boot_id"] == last.get("boot_id")
                or result["recommended_action"] != "join"
                or result["target_ad"]["exists"]
                or result["target_conflict"]
                or result["checks"].get("dns_spn_conflict")
                or any(h.get("event") == "credential_issued" for h in plan.history)
            ):
                return jsonify(
                    error_code="JOIN_CANCEL_NOT_VERIFIED",
                    error="Nie potwierdzono bezpiecznego wycofania planu join.",
                ), 409
            updates["diagnosis"] = result
            entry.update(approved=True, boot_id=local["boot_id"], reconciled=True)
        else:
            # Operator rejected the reserved name (wrong room/number) before
            # anything ran. Only a plan without any write-ahead or directory
            # checkpoint may be cancelled: then Windows and AD are untouched and
            # the reservation is the only state to release.
            if any(h.get("event") in PLAN_STARTED_EVENTS for h in plan.history):
                return jsonify(
                    error_code="PLAN_ALREADY_STARTED",
                    error="Plan zostal juz rozpoczety. Anulowanie niedozwolone.",
                ), 409
            local = validate_local(data.get("local"))
            if "recovery_identity" in plan.diagnosis:
                recovery_identity(agent, plan.device_id, local, plan)
            if (
                data.get("approved") is not True
                or plan.state not in {"ready", "manual_review"}
                or local.get("hostname", "").upper() != plan.source_name
            ):
                return jsonify(
                    error_code="CANCEL_NOT_ALLOWED",
                    error="Nie potwierdzono warunkow anulowania planu.",
                ), 409
            entry.update(approved=True, before_start=True, boot_id=local.get("boot_id", ""))
        if "reason" in data:
            entry["reason"] = data["reason"]
        updates.update(state="cancelled", active_computer=None, reserved_name=None)
    elif event == "resolve":
        local = validate_local(data.get("local"))
        if "recovery_identity" in plan.diagnosis:
            recovery_identity(agent, plan.device_id, local, plan)
        blockers, source, device = local_resolution_blockers(agent, plan, data, local)
        if blockers:
            return jsonify(
                error_code="LOCAL_REPAIR_NOT_VERIFIED",
                error="Serwer nie potwierdzil lokalnej naprawy zaufania. Plan zachowany.",
                blockers=blockers,
            ), 409
        entry.update(approved=True, resolved_locally=True, boot_id=local["boot_id"],
                     source_sid=source.object_sid, password_last_set=source.password_last_set)
        updates.update(
            state="cancelled", active_computer=None, reserved_name=None,
            diagnosis={**plan.diagnosis, "status": "RESOLVED_LOCALLY", "recommended_action": "none",
                       "source_ad": source.payload()},
        )
        if device:
            # Hardware-bound device proved it holds the account's new machine
            # password: future repairs keep this account instead of a new name.
            device.current_hostname = plan.source_name
            device.owned_source_sid = source.object_sid
    elif event == "failed":
        updates.update(state="manual_review")  # keep reservation until resolved
    else:
        local = validate_local(data.get("local"))
        result = diagnosis(data, agent, plan)
        action = result["recommended_action"]
        updates.update(diagnosis=result)
        if event == "retry":
            # Explicit approval permits a fresh channel repair, or a fresh
            # machine-account recovery only when the previous attempt failed
            # before any join authorization/credential checkpoint existed.
            machine_preflight_retry = (
                data.get("approved") is True
                and plan.state == "manual_review"
                and plan.action == "machine_account_recovery"
                and action == "machine_account_recovery"
                and local.get("boot_id")
                and result["source_name"] == plan.source_name
                and local.get("part_of_domain") is True
                and local.get("secure_channel") is False
                and not any(h.get("event") == "credential_issued" for h in plan.history)
                and any(
                    h.get("event") == "begin"
                    and h.get("action") == "machine_account_recovery"
                    for h in plan.history
                )
            )
            channel_retry = (
                data.get("approved") is True
                and plan.state in {"ready", "manual_review"}
                and plan.action == "repair_secure_channel"
                and action == "repair_secure_channel"
                and plan.source_sid
                and result["source_ad"]["object_sid"] == plan.source_sid
                and local.get("boot_id")
                and any(h.get("event") == "begin" and h.get("action") == action for h in plan.history)
            )
            if not (machine_preflight_retry or channel_retry):
                return jsonify(error_code="RETRY_NOT_ALLOWED", error="Nie mozna zatwierdzic ponowienia tej operacji."), 409
            entry.update(approved=True, boot_id=local["boot_id"])
            if machine_preflight_retry:
                entry["preflight_only"] = True
            updates.update(state="ready")
        elif event == "begin":
            if (
                plan.state != "ready"
                or action != plan.action
                or action
                not in {"join", "rename_domain", "repair_secure_channel", "machine_account_recovery"}
            ):
                abort(409)
            if not local.get("boot_id"):
                raise ValueError("Brak identyfikatora uruchomienia Windows.")
            previous = [h for h in plan.history if h.get("action") == action]
            if any(h.get("event") == "begin" for h in previous):
                retry = previous[-1] if previous else {}
                safe_machine_retry = (
                    action == "machine_account_recovery"
                    and not any(h.get("event") == "credential_issued" for h in plan.history)
                    and any(
                        h.get("event") == "retry"
                        and h.get("approved") is True
                        and h.get("preflight_only") is True
                        and h.get("boot_id") == local["boot_id"]
                        for h in reversed(plan.history)
                    )
                )
                safe_channel_retry = (
                    action == "repair_secure_channel"
                    and retry.get("event") == "retry"
                    and retry.get("approved") is True
                    and retry.get("boot_id") == local["boot_id"]
                    and plan.source_sid
                    and result["source_ad"]["object_sid"] == plan.source_sid
                )
                if not (safe_machine_retry or safe_channel_retry):
                    return jsonify(error_code="PREVIOUS_OPERATION_UNCONFIRMED", error="Poprzednia operacja zostala rozpoczeta. Wymagane sprawdzenie wyniku lub zatwierdzenie ponowienia naprawy zaufania."), 409
            entry["boot_id"] = local["boot_id"]
            updates.update(state="pending")
        else:
            if plan.state == "pending":
                if plan.action in {"join", "rename_domain", "machine_account_recovery"}:
                    if not local.get("boot_id") or local["boot_id"] == last_begin(plan).get(
                        "boot_id"
                    ):
                        return jsonify(error="Wymagany restart przed wznowieniem."), 409
                if action == plan.action:
                    updates.update(state="manual_review")
                else:
                    updates.update(state="ready", action=action)
            elif action == plan.action and (
                plan.state == "manual_review"
                or any(h.get("event") == "begin" and h.get("action") == action for h in plan.history)
            ):
                updates.update(state="manual_review")
            else:
                updates.update(state="ready", action=action)
                if "recovery_identity" in plan.diagnosis and last_begin(plan) and action != "none":
                    updates.update(state="manual_review")
            if action in {"blocked", "blocked_conflict", "diagnose"}:
                updates.update(state="manual_review", action=action)
            elif action == "none":
                updates.update(
                    state="complete", action="none", active_computer=None, reserved_name=None
                )
            if (result["source_ad"]["object_sid"] and result["source_name"] == plan.target_name
                    and ("recovery_identity" not in plan.diagnosis or (
                        local.get("secure_channel") is True
                        and local.get("boot_id")
                        and local["boot_id"] != last_begin(plan).get("boot_id")
                        and any(h.get("event") == "credential_issued" for h in plan.history)
                    )) and not plan.source_sid):
                updates["source_sid"] = result["source_ad"]["object_sid"]
    updates["history"] = durable_history(plan.history, entry)
    changed = db.session.execute(
        db.update(DomainRecovery)
        .where(DomainRecovery.id == plan.id, DomainRecovery.version == data["version"])
        .values(**updates)
    ).rowcount
    if changed != 1:
        db.session.rollback()
        abort(409)
    if updates.get("state") == "complete":
        agent.hostname = plan.target_name
        agent.ou = plan.target_ou
        device = db.session.scalar(db.select(RecoveryDevice).where(RecoveryDevice.computer_id == agent.id))
        if device:
            device.current_hostname = plan.target_name
            device.owned_source_sid = updates.get("source_sid", plan.source_sid)
    db.session.commit()
    db.session.refresh(plan)
    return jsonify(plan.payload())


def _validate_recovery_join(plan_id):
    agent, plan = owned_plan(plan_id)
    data = body({"version", "device_id", "local"})
    if not current_app.config.get("MACHINE_ACCOUNT_RECOVERY_ENABLED"):
        abort(409)
    if (type(data.get("version")) is not int or data["version"] != plan.version
            or plan.state != "pending" or plan.action != "machine_account_recovery"):
        abort(409)
    if uuid_value(data.get("device_id")) != plan.device_id:
        abort(403)
    local = validate_local(data.get("local"))
    begin = last_begin(plan)
    if not begin or local.get("boot_id") != begin.get("boot_id"):
        abort(409)
    if datetime.fromisoformat(begin["at"]) < utcnow() - timedelta(minutes=5):
        abort(409)
    if any(h.get("event") == "credential_issued" for h in plan.history):
        abort(409)
    result = diagnosis(data, agent, plan)
    if result["recommended_action"] != "machine_account_recovery":
        abort(409)
    return plan, data


def _commit_recovery_join_authorization(plan, data):
    entry = {"event": "credential_issued", "at": utcnow().isoformat(),
             "action": plan.action}
    changed = db.session.execute(db.update(DomainRecovery).where(
        DomainRecovery.id == plan.id, DomainRecovery.version == data["version"],
        DomainRecovery.state == "pending",
    ).values(version=plan.version + 1, updated_at=utcnow(),
             history=durable_history(plan.history, entry))).rowcount
    if changed != 1:
        db.session.rollback()
        abort(409)
    db.session.commit()


@api_bp.post("/domain-repair/join-credential/<plan_id>")
@csrf.exempt
@guarded
def recovery_join_credential(plan_id):
    """Legacy one-shot credential delivery for older recovery clients."""
    from .profile_routes import service_join_credential

    plan, data = _validate_recovery_join(plan_id)
    response = service_join_credential()
    if isinstance(response, tuple):
        return response
    _commit_recovery_join_authorization(plan, data)
    return response


@api_bp.post("/domain-repair/join-authorize/<plan_id>")
@csrf.exempt
@guarded
def recovery_join_authorize(plan_id):
    """Authorize a local-credential machine-account recovery without returning secrets."""
    plan, data = _validate_recovery_join(plan_id)
    _commit_recovery_join_authorization(plan, data)
    response = jsonify(authorized=True)
    response.headers["Cache-Control"] = "no-store"
    return response

from uuid import uuid4

import pytest
from flask import Flask
from app import create_app
from app.extensions import db
from app.models import AgentComputer, AgentRegistration, DomainRecovery, RecoveryPairing
from app.models.agent import utcnow
from datetime import timedelta
from app.agents.domain_repair import ComputerState

OU = "OU=Nauczyciele,OU=Komputery,DC=sp2,DC=lan"
DEVICE = "6a7289cd-0c71-4773-8a9d-debe56de38f1"
MAC = "02:00:00:00:00:01"


def test_public_capabilities_contains_no_credentials(repair_env):
    _, client, _, _, _ = repair_env
    response = client.get("/api/v1/agent/domain-repair/capabilities")
    assert response.status_code == 200
    assert response.json == {"service": "sp2-admin-domain-repair", "protocol": 2, "pairing": True, "hardware_identity": True}
    assert response.headers["Cache-Control"] == "no-store"


@pytest.fixture
def repair_env(monkeypatch):
    # Render the approval screen within the real navigation and branding layout.
    app = create_app("testing")
    app.config.update(
        TESTING=True,
        STAGING_READ_ONLY=False,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        WTF_CSRF_ENABLED=False,
        AD_DOMAIN_FQDN="sp2.lan",
        AD_JOIN_ALLOWED_OU_BASES=[OU],
        AGENT_ENROLLMENT_TOKEN="enroll",
        MACHINE_ACCOUNT_RECOVERY_ENABLED=True,
        AD_JOIN_SERVICE_USER="joiner@sp2.lan",
        AD_JOIN_SERVICE_PASSWORD="test-only-password",
    )
    states = {}
    monkeypatch.setattr(
        "app.agents.domain_repair.computer_state",
        lambda name: states.get(name, ComputerState(False, name=name)),
    )
    monkeypatch.setattr(
        "app.agents.recovery_routes.computer_state",
        lambda name: states.get(name, ComputerState(False, name=name)),
    )
    monkeypatch.setattr(
        "app.agents.domain_repair.directory_checks",
        lambda *args: {"ou_exists": True, "dns_spn_conflict": False, "dns_resolves": True,
                       "dns_addresses": ["192.0.2.10"]},
    )
    with app.app_context():
        db.create_all()
        a = AgentComputer(hostname="NAU-010", mac_addresses=[MAC], ip_addresses=["192.0.2.10"])
        b = AgentComputer(hostname="NAU-011", mac_addresses=[MAC], ip_addresses=["192.0.2.10"])
        ra, ta = AgentRegistration.issue(a)
        rb, tb = AgentRegistration.issue(b)
        db.session.add_all([a, b, ra, rb])
        for name in ("NAU-010", "NAU-011"):
            db.session.add(RecoveryPairing(hostname=name, device_id=DEVICE,
                address="192.0.2.10", secret_hash="test", approved_by="admin", consumed=True,
                expires_at=utcnow() + timedelta(minutes=10)))
        db.session.commit()
    yield app, app.test_client(), states, ta, tb


def payload(**changes):
    result = {
        "request_id": str(uuid4()),
        "device_id": DEVICE,
        "target_name": "BR-S30",
        "target_ou": OU,
        "local": {
            "hostname": "NAU-010",
            "part_of_domain": True,
            "secure_channel": False,
            "domain": "sp2.lan",
            "boot_id": "boot1",
            "mac_addresses": [MAC],
        },
    }
    result.update(changes)
    return result


def post(client, path, token, data):
    return client.post(
        "/api/v1/agent/domain-repair/" + path,
        headers={"Authorization": "Bearer " + token},
        json=data,
    )


def progress(client, token, plan, p, event, **local):
    return post(
        client,
        "progress/" + plan["id"],
        token,
        {
            "version": plan["version"],
            "device_id": p["device_id"],
            "event": event,
            "local": {**p["local"], **local},
        },
    )


def test_plan_idempotent_owner_and_name_reservation(repair_env):
    app, client, states, a, b = repair_env
    p = payload()
    response = post(client, "plan", a, p)
    assert response.status_code == 201
    plan = response.json
    assert post(client, "plan", a, p).json["id"] == plan["id"]
    assert (
        client.get(
            "/api/v1/agent/domain-repair/status/" + plan["id"],
            headers={"Authorization": "Bearer " + b},
        ).status_code
        == 404
    )
    other = payload(local={**p["local"], "hostname": "NAU-011"})
    assert post(client, "plan", b, other).status_code == 409
    assert post(client, "plan", a, payload()).status_code == 409
    with app.app_context():
        db.session.remove()
        assert db.session.get(DomainRecovery, plan["id"]).state == "ready"


def test_recovery_payload_carries_pinned_sid_only_to_owner(repair_env):
    app, client, states, a, b = repair_env
    pinned_sid = "S-1-5-21-101-202-303-444"
    states["NAU-010"] = ComputerState(
        True, "NAU-010", "CN=NAU-010," + OU,
        "nau-010.sp2.lan", True, pinned_sid,
        ["HOST/NAU-010", "HOST/nau-010.sp2.lan"],
    )
    p = payload()
    response = post(client, "plan", a, p)
    assert response.status_code == 201
    plan = response.json
    assert plan["source_sid"] == pinned_sid
    own = client.get(
        "/api/v1/agent/domain-repair/status/" + plan["id"],
        headers={"Authorization": "Bearer " + a},
    )
    assert own.status_code == 200
    assert own.json["source_sid"] == pinned_sid
    other = client.get(
        "/api/v1/agent/domain-repair/status/" + plan["id"],
        headers={"Authorization": "Bearer " + b},
    )
    assert other.status_code == 404


def test_machine_recovery_across_reboot_without_unjoin(repair_env):
    app, client, states, a, _ = repair_env
    p = payload()
    plan = post(client, "plan", a, p).json
    plan = progress(client, a, plan, p, "begin").json
    assert plan["state"] == "pending"
    assert progress(client, a, plan, p, "observe").status_code == 409
    assert plan["action"] == "machine_account_recovery"
    delivered = post(client, "join-credential/" + plan["id"], a, {
        "version": plan["version"], "device_id": p["device_id"], "local": p["local"],
    })
    assert delivered.status_code == 200
    assert delivered.headers["Cache-Control"] == "no-store"
    plan = client.get("/api/v1/agent/domain-repair/status/" + plan["id"],
                      headers={"Authorization": "Bearer " + a}).json
    states["BR-S30"] = ComputerState(
        True,
        "BR-S30",
        "CN=BR-S30," + OU,
        "br-s30.sp2.lan",
        True,
        "SID-new",
        ["HOST/BR-S30", "HOST/br-s30.sp2.lan"],
    )
    plan = progress(
        client,
        a,
        plan,
        p,
        "observe",
        hostname="BR-S30",
        part_of_domain=True,
        domain="sp2.lan",
        secure_channel=True,
        boot_id="boot3",
    ).json
    assert plan["state"] == "complete"
    with app.app_context():
        saved = db.session.get(DomainRecovery, plan["id"])
        assert saved.reserved_name is None
        assert db.session.get(AgentComputer, saved.computer_id).hostname == "BR-S30"


def test_stale_version_device_mismatch_and_no_blind_retry(repair_env):
    _, client, _, a, _ = repair_env
    p = payload()
    plan = post(client, "plan", a, p).json
    assert progress(client, a, plan, {**p, "device_id": str(uuid4())}, "begin").status_code == 403
    begun = progress(client, a, plan, p, "begin").json
    assert progress(client, a, plan, p, "begin").status_code == 409
    observed = progress(client, a, begun, p, "observe", boot_id="boot2").json
    assert observed["state"] == "manual_review"
    assert progress(client, a, observed, p, "begin").status_code == 409


@pytest.mark.parametrize(
    "bad",
    [
        {"password": "secret"},
        {"local": {"password": "secret"}},
        {"local": {"hostname": "NAU-010", "part_of_domain": "false"}},
        {"device_id": "bad"},
    ],
)
def test_rejects_credentials_and_malformed_input(repair_env, bad):
    _, client, _, a, _ = repair_env
    assert post(client, "plan", a, payload(**bad)).status_code == 400


def test_enrollment_does_not_rotate_existing_agent(repair_env):
    _, client, _, a, _ = repair_env
    assert post(client, "enroll", "enroll", {"hostname": "NAU-010"}).status_code == 409
    assert post(client, "plan", "enroll", payload()).status_code == 401
    assert post(client, "plan", "invalid", payload()).status_code == 401
    result = post(client, "enroll", "enroll", {"hostname": "NEW-01"})
    assert result.status_code == 201
    assert result.json["token"] != a


def test_conflict_rechecked_before_begin(repair_env):
    _, client, states, a, _ = repair_env
    p = payload()
    plan = post(client, "plan", a, p).json
    states["BR-S30"] = ComputerState(True, name="BR-S30", object_sid="other")
    assert progress(client, a, plan, p, "begin").status_code == 409


def test_ldap_failure_is_not_absence(repair_env, monkeypatch):
    from app.directory.service import DirectoryError

    _, client, _, a, _ = repair_env

    def unavailable(*args):
        raise DirectoryError("sensitive connection detail")

    monkeypatch.setattr("app.agents.domain_repair.directory_checks", unavailable)
    result = post(client, "plan", a, payload())
    assert result.status_code == 503
    assert b"sensitive" not in result.data


def test_additive_schema_and_persistence_after_restart(tmp_path):
    uri = "sqlite:///" + str(tmp_path / "recovery.sqlite")
    first = Flask("before")
    first.config["SQLALCHEMY_DATABASE_URI"] = uri
    db.init_app(first)
    with first.app_context():
        AgentComputer.__table__.create(db.engine)
        db.session.add(AgentComputer(hostname="OLD-PC"))
        db.session.commit()
        db.create_all()
        db.create_all()
        plan = DomainRecovery(
            computer_id=1,
            request_id=str(uuid4()),
            device_id=str(uuid4()),
            source_name="OLD-PC",
            target_name="BR-S30",
            target_ou=OU,
            domain="sp2.lan",
            state="pending",
            action="join",
            active_computer=1,
            reserved_name="BR-S30",
        )
        db.session.add(plan)
        db.session.commit()
        plan_id = plan.id
        db.session.remove()
        db.engine.dispose()
    second = Flask("after")
    second.config["SQLALCHEMY_DATABASE_URI"] = uri
    db.init_app(second)
    with second.app_context():
        db.create_all()
        assert db.session.get(AgentComputer, 1).hostname == "OLD-PC"
        assert db.session.get(DomainRecovery, plan_id).state == "pending"


def test_config_requires_agent_and_filters_ous(repair_env, monkeypatch):
    app, client, _, a, _ = repair_env
    monkeypatch.setattr("app.agents.recovery_routes.DirectoryService.__init__", lambda self: None)
    monkeypatch.setattr(
        "app.agents.recovery_routes.DirectoryService.organizational_units",
        lambda self, **kwargs: [{"dn": OU}, {"dn": "OU=Forbidden,DC=sp2,DC=lan"}],
    )
    assert client.get("/api/v1/agent/domain-repair/config").status_code == 401
    response = client.get(
        "/api/v1/agent/domain-repair/config", headers={"Authorization": "Bearer " + a}
    )
    assert response.status_code == 200
    assert response.json["ous"] == [OU]


def credential_request(client, token, plan, p):
    return post(client, "join-credential/" + plan["id"], token, {
        "version": plan["version"], "device_id": p["device_id"], "local": p["local"],
    })


def test_credential_scoped_one_delivery_and_no_secret_persistence(repair_env):
    app, client, _, a, b = repair_env
    p = payload()
    plan = post(client, "plan", a, p).json
    assert credential_request(client, a, plan, p).status_code == 409
    plan = progress(client, a, plan, p, "begin").json
    assert credential_request(client, b, plan, p).status_code == 404
    assert credential_request(client, a, plan, {**p, "device_id": str(uuid4())}).status_code == 403
    issued = credential_request(client, a, plan, p)
    assert issued.status_code == 200
    assert issued.json["username"] == "joiner@sp2.lan"
    assert credential_request(client, a, plan, p).status_code == 409
    with app.app_context():
        saved = db.session.get(DomainRecovery, plan["id"])
        assert "test-only-password" not in str(saved.payload())
        assert "joiner@sp2.lan" not in str(saved.payload())
        plan = saved.payload()
    assert credential_request(client, a, plan, p).status_code == 409


def test_recovery_identity_requires_approved_uuid_and_matching_inventory(repair_env):
    _, client, _, a, _ = repair_env
    assert post(client, "plan", a, payload(device_id=str(uuid4()))).status_code == 403
    p = payload()
    p["local"]["mac_addresses"] = ["02:00:00:00:00:02"]
    assert post(client, "plan", a, p).status_code == 403


def test_recovery_remains_disabled_by_default_and_never_unjoins(repair_env):
    app, client, _, a, _ = repair_env
    app.config["MACHINE_ACCOUNT_RECOVERY_ENABLED"] = False
    response = post(client, "plan", a, payload())
    assert response.status_code == 409
    assert response.json["diagnosis"]["recommended_action"] == "blocked"


def test_unconfirmed_workgroup_join_cancel_after_new_boot_and_ad_absence(repair_env):
    app, client, states, token, _ = repair_env
    p = payload()
    p["local"].update(part_of_domain=False, secure_channel=None, domain="WORKGROUP")
    plan = post(client, "plan", token, p).json
    assert plan["action"] == "join"
    plan = progress(client, token, plan, p, "begin").json
    data = {
        "version": plan["version"], "device_id": p["device_id"],
        "event": "cancel", "approved": True,
        "local": {**p["local"], "boot_id": "new-boot"},
    }
    assert post(client, "progress/" + plan["id"], token, data).status_code == 409
    assert progress(client, token, plan, p, "observe").status_code == 409
    plan = progress(client, token, plan, p, "observe", boot_id="new-boot").json
    assert plan["state"] == "manual_review"
    data["version"] = plan["version"]
    no_approval = dict(data, approved=False)
    assert post(client, "progress/" + plan["id"], token, no_approval).status_code == 409
    bad_boot = dict(data, local={**p["local"], "boot_id": "boot1"})
    assert post(client, "progress/" + plan["id"], token, bad_boot).status_code == 409
    states["BR-S30"] = ComputerState(True, "BR-S30", enabled=True, object_sid="other-device")
    assert post(client, "progress/" + plan["id"], token, data).status_code == 409
    states.pop("BR-S30")
    cancelled = post(client, "progress/" + plan["id"], token, data)
    assert cancelled.status_code == 200
    assert cancelled.json["state"] == "cancelled"
    assert any(h.get("event") == "cancel" and h.get("reconciled") is True
               for h in cancelled.json["history"])
    with app.app_context():
        saved = db.session.get(DomainRecovery, plan["id"])
        assert saved.reserved_name is None and saved.active_computer is None
    new_plan = post(client, "plan", token, payload(local=p["local"])).json
    assert new_plan["id"] != plan["id"]
    assert new_plan["target_name"] == plan["target_name"]


def test_machine_recovery_failed_join_keeps_reservation_and_cannot_retry(repair_env):
    app, client, _, a, _ = repair_env
    p = payload()
    plan = post(client, "plan", a, p).json
    plan = progress(client, a, plan, p, "begin").json
    plan = progress(client, a, plan, p, "failed").json
    plan = progress(client, a, plan, p, "observe", boot_id="boot2").json
    assert plan["state"] == "manual_review"
    assert progress(client, a, plan, p, "begin").status_code == 409
    with app.app_context():
        saved = db.session.get(DomainRecovery, plan["id"])
        assert saved.reserved_name == p["target_name"]
    assert post(client, "plan", a, payload()).status_code == 409


@pytest.mark.parametrize("bad", ["ou", "dns", "spn", "disabled", "no_sid", "wrong_ip"])
def test_machine_recovery_cannot_complete_with_bad_directory_metadata(repair_env, bad, monkeypatch):
    _, client, states, a, _ = repair_env
    p = payload()
    plan = post(client, "plan", a, p).json
    plan = progress(client, a, plan, p, "begin").json
    assert credential_request(client, a, plan, p).status_code == 200
    plan = client.get("/api/v1/agent/domain-repair/status/" + plan["id"],
                      headers={"Authorization": "Bearer " + a}).json
    state = ComputerState(True, "BR-S30", "CN=BR-S30," + OU, "br-s30.sp2.lan",
                          True, "SID-new", ["HOST/BR-S30", "HOST/br-s30.sp2.lan"])
    if bad == "ou":
        state.dn = "CN=BR-S30,OU=Other,DC=sp2,DC=lan"
    elif bad == "dns":
        state.dns_hostname = "wrong.sp2.lan"
    elif bad == "spn":
        state.spns = []
    elif bad == "disabled":
        state.enabled = False
    elif bad == "no_sid":
        state.object_sid = ""
    elif bad == "wrong_ip":
        monkeypatch.setattr("app.agents.domain_repair.directory_checks", lambda *args: {
            "ou_exists": True, "dns_spn_conflict": False, "dns_resolves": True,
            "dns_addresses": ["192.0.2.99"],
        })
    states["BR-S30"] = state
    response = progress(client, a, plan, p, "observe", hostname="BR-S30",
                        boot_id="boot2", secure_channel=True)
    assert response.status_code == 200
    assert response.json["state"] == "manual_review"


def test_reconcile_failed_report_can_complete_but_pinned_sid_cannot_change(repair_env):
    app, client, states, a, _ = repair_env
    p = payload()
    plan = post(client, "plan", a, p).json
    plan = progress(client, a, plan, p, "begin").json
    assert credential_request(client, a, plan, p).status_code == 200
    plan = client.get("/api/v1/agent/domain-repair/status/" + plan["id"],
                      headers={"Authorization": "Bearer " + a}).json
    plan = progress(client, a, plan, p, "failed").json
    state = ComputerState(True, "BR-S30", "CN=BR-S30," + OU, "br-s30.sp2.lan",
                          True, "SID-first", [])
    states["BR-S30"] = state
    plan = progress(client, a, plan, p, "observe", hostname="BR-S30",
                    boot_id="boot2", secure_channel=True).json
    assert plan["state"] == "manual_review"
    with app.app_context():
        assert db.session.get(DomainRecovery, plan["id"]).source_sid == "SID-first"
    state.object_sid = "SID-replacement"
    state.spns = ["HOST/BR-S30", "HOST/br-s30.sp2.lan"]
    plan = progress(client, a, plan, p, "observe", hostname="BR-S30",
                    boot_id="boot2", secure_channel=True).json
    assert plan["state"] == "manual_review"
    assert plan["diagnosis"]["status"] == "SOURCE_IDENTITY_CHANGED"
    state.object_sid = "SID-first"
    plan = progress(client, a, plan, p, "observe", hostname="BR-S30",
                    boot_id="boot2", secure_channel=True).json
    assert plan["state"] == "complete"


def test_reconcile_never_accepts_workgroup_or_unknown_channel(repair_env):
    _, client, _, a, _ = repair_env
    p = payload()
    plan = post(client, "plan", a, p).json
    plan = progress(client, a, plan, p, "begin").json
    assert credential_request(client, a, plan, p).status_code == 200
    plan = client.get("/api/v1/agent/domain-repair/status/" + plan["id"],
                      headers={"Authorization": "Bearer " + a}).json
    plan = progress(client, a, plan, p, "observe", boot_id="boot2",
                    part_of_domain=False, domain="WORKGROUP", secure_channel=None).json
    assert plan["state"] == "manual_review"
    assert plan["action"] == "blocked"
    assert plan["diagnosis"]["status"] == "RECOVERY_MEMBERSHIP_CHANGED"


def test_observation_history_never_erases_one_shot_join_checkpoints():
    from app.agents.recovery_routes import durable_history

    history = [{"event": "begin", "action": "machine_account_recovery", "boot_id": "boot1"},
               {"event": "credential_issued", "action": "machine_account_recovery"}]
    for _ in range(150):
        history = durable_history(history, {"event": "observe"})
    assert len(history) == 100
    assert sum(h["event"] == "begin" for h in history) == 1
    assert sum(h["event"] == "credential_issued" for h in history) == 1

def test_review_stays_blocked_and_explicit_channel_retry(repair_env):
    _, client, states, token, _ = repair_env
    states["NAU-010"] = ComputerState(True, "NAU-010", enabled=True, object_sid="own")
    p = payload()
    plan = post(client, "plan", token, p).json
    plan = progress(client, token, plan, p, "begin").json
    plan = progress(client, token, plan, p, "observe").json
    assert plan["state"] == "manual_review"
    plan = progress(client, token, plan, p, "observe").json
    assert plan["state"] == "manual_review"
    data = {"version": plan["version"], "device_id": p["device_id"], "event": "retry", "local": p["local"]}
    assert post(client, "progress/" + plan["id"], token, data).status_code == 409
    data["approved"] = True
    plan = post(client, "progress/" + plan["id"], token, data).json
    assert plan["state"] == "ready"
    plan = progress(client, token, plan, p, "begin").json
    assert plan["state"] == "pending"
    assert sum(h["event"] == "begin" for h in plan["history"]) == 2
    assert progress(client, token, plan, p, "begin").status_code == 409
    plan = progress(client, token, plan, p, "observe", secure_channel=True).json
    assert plan["state"] == "ready" and plan["action"] == "rename_domain"


def test_machine_retry_without_failed_marker_allowed_before_authorization(repair_env):
    _, client, states, token, _ = repair_env
    p = payload()
    plan = post(client, "plan", token, p).json
    plan = progress(client, token, plan, p, "begin").json
    plan = progress(client, token, plan, p, "observe", boot_id="boot2").json
    assert plan["state"] == "manual_review"
    data = {"version": plan["version"], "device_id": p["device_id"], "event": "retry", "approved": True, "local": {**p["local"], "boot_id": "boot2"}}
    retry = post(client, "progress/" + plan["id"], token, data)
    assert retry.status_code == 200
    assert retry.json["state"] == "ready"
    assert any(h.get("event") == "retry" and h.get("preflight_only") is True for h in retry.json["history"])


def test_automatic_student_name_skips_ad_agents_reservations_and_is_idempotent(repair_env):
    app, client, states, token, _ = repair_env
    states["S11-10"] = ComputerState(True, "S11-10", object_sid="occupied")
    with app.app_context():
        db.session.add(AgentComputer(hostname="S11-11"))
        db.session.add(DomainRecovery(computer_id=2, request_id=str(uuid4()), device_id=str(uuid4()), source_name="NAU-011", target_name="S11-12", target_ou=OU, domain="sp2.lan", action="join", reserved_name="S11-12", active_computer=2))
        db.session.commit()
    p = payload(target_name="S11-10", auto_name=True)
    response = post(client, "plan", token, p)
    assert response.status_code == 201
    assert response.json["target_name"] == "S11-13"
    assert post(client, "plan", token, p).json["id"] == response.json["id"]
    observed = progress(client, token, response.json, p, "observe")
    assert observed.status_code == 200
    assert post(client, "plan", token, p).json["id"] == response.json["id"]


def test_channel_retry_rejects_changed_sid(repair_env):
    _, client, states, token, _ = repair_env
    states["NAU-010"] = ComputerState(True, "NAU-010", enabled=True, object_sid="own")
    p = payload()
    plan = post(client, "plan", token, p).json
    plan = progress(client, token, plan, p, "begin").json
    plan = progress(client, token, plan, p, "observe").json
    states["NAU-010"].object_sid = "replacement"
    data = {"version": plan["version"], "device_id": p["device_id"], "event": "retry", "approved": True, "local": p["local"]}
    response = post(client, "progress/" + plan["id"], token, data)
    assert response.status_code == 409 and response.json["error_code"] == "RETRY_NOT_ALLOWED"



def test_newly_paired_device_can_plan_without_ip_inventory(repair_env, monkeypatch):
    app, client, states, _, _ = repair_env
    from app.models.recovery_device import RecoveryDevice, RecoveryDeviceToken
    from app.models import AgentRegistration

    token = "fresh-device-token"
    device_id = str(uuid4())
    with app.app_context():
        agent = AgentComputer(hostname="RECOVERY-" + device_id, mac_addresses=[MAC], ip_addresses=[])
        db.session.add(agent)
        db.session.flush()
        device = RecoveryDevice(
            device_id=device_id,
            computer_id=agent.id,
            hardware_uuid=device_id,
            mac_addresses=[MAC.replace(":", "")],
            current_hostname="S11-08",
            owned_source_sid="",
        )
        db.session.add(device)
        db.session.add(RecoveryDeviceToken(
            token_hash=AgentRegistration.hash_token(token),
            device_id=device_id,
        ))
        db.session.commit()

    p = payload(
        device_id=device_id,
        target_name="S11-10",
        auto_name=True,
        local={
            "hostname": "S11-08",
            "part_of_domain": True,
            "secure_channel": False,
            "domain": "sp2.lan",
            "boot_id": "boot1",
            "mac_addresses": [MAC],
            "hardware_uuid": device_id,
        },
    )
    response = post(client, "plan", token, p)
    assert response.status_code == 201
    assert response.json["source_name"] == "S11-08"
    assert response.json["target_name"].startswith("S11-")
    assert response.json["diagnosis"]["recovery_identity"]["ip_addresses"] == []


def test_device_token_uses_recovery_device_mac_when_agent_inventory_is_stale(repair_env):
    app, client, _, _, _ = repair_env
    from app.models.recovery_device import RecoveryDevice, RecoveryDeviceToken
    from app.models import AgentRegistration

    token = "rotated-nic-recovery-token"
    device_id = str(uuid4())
    old_mac = "02:00:00:00:00:09"
    new_mac = "02:00:00:00:00:0A"
    with app.app_context():
        agent = AgentComputer(
            hostname="RECOVERY-" + device_id,
            mac_addresses=[old_mac],
            ip_addresses=[],
        )
        db.session.add(agent)
        db.session.flush()
        db.session.add(
            RecoveryDevice(
                device_id=device_id,
                computer_id=agent.id,
                hardware_uuid=device_id,
                mac_addresses=[new_mac.replace(":", "")],
                current_hostname="S11-08",
                owned_source_sid="",
            )
        )
        db.session.add(
            RecoveryDeviceToken(
                token_hash=AgentRegistration.hash_token(token),
                device_id=device_id,
            )
        )
        db.session.commit()

    p = payload(
        device_id=device_id,
        target_name="S11-10",
        auto_name=True,
        local={
            "hostname": "S11-08",
            "part_of_domain": True,
            "secure_channel": False,
            "domain": "sp2.lan",
            "boot_id": "boot1",
            "mac_addresses": [new_mac],
            "hardware_uuid": device_id,
        },
    )
    response = post(client, "plan", token, p)
    assert response.status_code == 201
    assert response.json["source_name"] == "S11-08"
    assert response.json["diagnosis"]["recovery_identity"]["mac_addresses"] == [new_mac]


def test_join_authorize_returns_no_credentials(repair_env):
    _, client, _, token, _ = repair_env
    p = payload()
    plan = post(client, "plan", token, p).json
    plan = progress(client, token, plan, p, "begin").json
    response = post(client, "join-authorize/" + plan["id"], token, {
        "version": plan["version"],
        "device_id": p["device_id"],
        "local": p["local"],
    })
    assert response.status_code == 200
    assert response.json == {"authorized": True}
    assert response.headers["Cache-Control"] == "no-store"
    assert "username" not in response.json
    assert "password" not in response.json


def test_machine_recovery_requires_explicit_retry_if_begin_happened_but_no_credential_was_issued(repair_env):
    _, client, _, token, _ = repair_env
    p = payload()
    plan = post(client, "plan", token, p).json
    plan = progress(client, token, plan, p, "begin").json
    plan = progress(client, token, plan, p, "failed").json
    assert plan["state"] == "manual_review"

    plan = progress(client, token, plan, p, "observe").json
    assert plan["state"] == "manual_review"

    retry = post(client, "progress/" + plan["id"], token, {
        "version": plan["version"],
        "device_id": p["device_id"],
        "event": "retry",
        "approved": True,
        "local": p["local"],
    })
    assert retry.status_code == 200
    plan = retry.json
    assert plan["state"] == "ready"

    retried = progress(client, token, plan, p, "begin")
    assert retried.status_code == 200
    assert retried.json["state"] == "pending"


def test_machine_recovery_manual_review_can_retry_after_reboot_before_authorization(repair_env):
    _, client, _, token, _ = repair_env
    p = payload()
    plan = post(client, "plan", token, p).json
    plan = progress(client, token, plan, p, "begin").json
    assert plan["state"] == "pending"
    plan = progress(client, token, plan, p, "failed").json
    assert plan["state"] == "manual_review"

    # A reboot alone must not silently reopen a destructive operation.
    plan = progress(client, token, plan, p, "observe", boot_id="boot-after-restart").json
    assert plan["state"] == "manual_review"

    retry = post(client, "progress/" + plan["id"], token, {
        "version": plan["version"],
        "device_id": p["device_id"],
        "event": "retry",
        "approved": True,
        "local": {**p["local"], "boot_id": "boot-after-restart"},
    })
    assert retry.status_code == 200
    plan = retry.json
    assert plan["state"] == "ready"
    assert any(
        h.get("event") == "retry"
        and h.get("approved") is True
        and h.get("preflight_only") is True
        and h.get("boot_id") == "boot-after-restart"
        for h in plan["history"]
    )

    begun = progress(
        client, token, plan, p, "begin", boot_id="boot-after-restart"
    )
    assert begun.status_code == 200
    assert begun.json["state"] == "pending"


def test_machine_recovery_retry_rejected_after_authorization(repair_env):
    _, client, _, token, _ = repair_env
    p = payload()
    plan = post(client, "plan", token, p).json
    plan = progress(client, token, plan, p, "begin").json
    assert credential_request(client, token, plan, p).status_code == 200
    plan = client.get(
        "/api/v1/agent/domain-repair/status/" + plan["id"],
        headers={"Authorization": "Bearer " + token},
    ).json
    plan = progress(client, token, plan, p, "failed").json
    plan = progress(client, token, plan, p, "observe", boot_id="boot-after-restart").json
    retry = post(client, "progress/" + plan["id"], token, {
        "version": plan["version"],
        "device_id": p["device_id"],
        "event": "retry",
        "approved": True,
        "local": {**p["local"], "boot_id": "boot-after-restart"},
    })
    assert retry.status_code == 409
    assert retry.json["error_code"] == "RETRY_NOT_ALLOWED"


def cancel_request(client, token, plan, p, **changes):
    data = {
        "version": plan["version"], "device_id": p["device_id"], "event": "cancel",
        "approved": True, "local": p["local"], "reason": "operator_rejected_target_name",
    }
    data.update(changes)
    return post(client, "progress/" + plan["id"], token, data)


def workgroup_payload(**changes):
    p = payload(**changes)
    p["local"].update(part_of_domain=False, secure_channel=None, domain="WORKGROUP")
    return p


def test_wrong_name_plan_cancel_before_begin_releases_reservation(repair_env):
    app, client, _, token, _ = repair_env
    p = workgroup_payload()
    plan = post(client, "plan", token, p).json
    assert plan["state"] == "ready" and plan["action"] == "join"
    cancelled = cancel_request(client, token, plan, p)
    assert cancelled.status_code == 200
    assert cancelled.json["state"] == "cancelled"
    entry = cancelled.json["history"][-1]
    assert entry["event"] == "cancel" and entry["before_start"] is True
    assert entry["reason"] == "operator_rejected_target_name"
    with app.app_context():
        saved = db.session.get(DomainRecovery, plan["id"])
        assert saved.reserved_name is None and saved.active_computer is None
    # The released name and a corrected name can both be reserved again.
    corrected = post(client, "plan", token, workgroup_payload(target_name="BR-S30-02"))
    assert corrected.status_code == 201
    assert corrected.json["target_name"] == "BR-S30-02"


def test_cancel_before_begin_requires_approval_and_same_windows_name(repair_env):
    _, client, _, token, _ = repair_env
    p = workgroup_payload()
    plan = post(client, "plan", token, p).json
    denied = cancel_request(client, token, plan, p, approved=False)
    assert denied.status_code == 409 and denied.json["error_code"] == "CANCEL_NOT_ALLOWED"
    renamed = cancel_request(client, token, plan, p, local={**p["local"], "hostname": "BR-S30"})
    assert renamed.status_code in {403, 409}
    bad_reason = cancel_request(client, token, plan, p, reason="anything")
    assert bad_reason.status_code == 400
    assert progress(client, token, plan, p, "observe").json["state"] == "ready"


def test_cancel_rejected_after_begin_without_reboot_reconcile(repair_env):
    _, client, _, token, _ = repair_env
    p = workgroup_payload()
    plan = post(client, "plan", token, p).json
    plan = progress(client, token, plan, p, "begin").json
    plan = progress(client, token, plan, p, "failed").json
    plan = progress(client, token, plan, p, "observe", boot_id="boot2").json
    assert plan["state"] == "manual_review"
    # Same boot as begin: the existing reconcile path still refuses.
    response = cancel_request(client, token, plan, p)
    assert response.status_code == 409
    assert response.json["error_code"] == "JOIN_CANCEL_NOT_VERIFIED"


def test_cancel_rejected_for_started_machine_account_recovery(repair_env):
    _, client, _, token, _ = repair_env
    p = payload()
    plan = post(client, "plan", token, p).json
    assert plan["action"] == "machine_account_recovery"
    plan = progress(client, token, plan, p, "begin").json
    assert credential_request(client, token, plan, p).status_code == 200
    plan = client.get(
        "/api/v1/agent/domain-repair/status/" + plan["id"],
        headers={"Authorization": "Bearer " + token},
    ).json
    plan = progress(client, token, plan, p, "failed").json
    response = cancel_request(client, token, plan, p)
    assert response.status_code == 409
    assert response.json["error_code"] == "PLAN_ALREADY_STARTED"


def test_exact_name_taken_returns_name_taken(repair_env):
    _, client, states, token, _ = repair_env
    states["BR-S30"] = ComputerState(True, "BR-S30", enabled=True, object_sid="other-device")
    response = post(client, "plan", token, workgroup_payload(auto_name=False))
    assert response.status_code == 409
    assert response.json["error_code"] == "NAME_TAKEN"


# --- Stuck machine_account_recovery closed after a local trust repair -------

def resolve_request(client, token, plan, p, **local):
    return post(client, "progress/" + plan["id"], token, {
        "version": plan["version"], "device_id": p["device_id"], "event": "resolve",
        "approved": True, "local": {**p["local"], **local},
    })


def authorized_failed_recovery(client, token, p):
    """Plan state seen on S11-15: join authorized, Windows join failed."""
    plan = post(client, "plan", token, p).json
    plan = progress(client, token, plan, p, "begin").json
    assert credential_request(client, token, plan, p).status_code == 200
    plan = client.get("/api/v1/agent/domain-repair/status/" + plan["id"],
                      headers={"Authorization": "Bearer " + token}).json
    plan = progress(client, token, plan, p, "failed").json
    assert plan["state"] == "manual_review"
    return plan


def repaired_account(name="NAU-010", minutes=1, **changes):
    values = {"dn": f"CN={name},{OU}", "enabled": True, "object_sid": "S-1-5-21-1-2-3-1110",
                  "password_last_set": (utcnow() + timedelta(minutes=minutes)).isoformat()}
    values.update(changes)
    return ComputerState(True, name=name, **values)


def test_locally_repaired_trust_closes_authorized_recovery_and_releases_name(repair_env):
    app, client, states, token, _ = repair_env
    p = payload()
    plan = authorized_failed_recovery(client, token, p)
    target = plan["target_name"]
    # Operator ran Test-ComputerSecureChannel -Repair: same account, new password.
    states["NAU-010"] = repaired_account()
    response = resolve_request(client, token, plan, p, secure_channel=True)
    assert response.status_code == 200, response.json
    plan = response.json
    assert plan["state"] == "cancelled"
    assert plan["diagnosis"]["status"] == "RESOLVED_LOCALLY"
    last = plan["history"][-1]
    assert last["event"] == "resolve" and last["resolved_locally"] is True
    assert last["source_sid"] == "S-1-5-21-1-2-3-1110"
    with app.app_context():
        stored = db.session.get(DomainRecovery, plan["id"])
        assert stored.reserved_name is None and stored.active_computer is None
    # The abandoned name is free again and no further progress is accepted.
    assert resolve_request(client, token, plan, p, secure_channel=True).status_code == 409
    assert target


@pytest.mark.parametrize("case,expected", [
    ({"secure_channel": False}, "windows_channel_not_healthy"),
    ({"part_of_domain": False, "secure_channel": None}, "windows_channel_not_healthy"),
    ({"hostname": "NAU-011"}, None),  # foreign name never reaches the check
])
def test_resolve_requires_healthy_channel_under_source_name(repair_env, case, expected):
    _, client, states, token, _ = repair_env
    p = payload()
    plan = authorized_failed_recovery(client, token, p)
    states["NAU-010"] = repaired_account()
    response = resolve_request(client, token, plan, p, **{"secure_channel": True, **case})
    assert response.status_code in {403, 409}
    if expected:
        assert expected in response.json["blockers"]


@pytest.mark.parametrize("account,expected", [
    ({"minutes": -60}, "password_not_reset_after_attempt"),
    ({"password_last_set": ""}, "password_not_reset_after_attempt"),
    ({"enabled": False}, "source_account_invalid"),
    ({"dn": "CN=NAU-010,OU=Obce,DC=sp2,DC=lan"}, "source_ou_not_allowed"),
])
def test_resolve_fails_closed_on_unproven_ad_state(repair_env, account, expected):
    _, client, states, token, _ = repair_env
    p = payload()
    plan = authorized_failed_recovery(client, token, p)
    states["NAU-010"] = repaired_account(**account)
    response = resolve_request(client, token, plan, p, secure_channel=True)
    assert response.status_code == 409
    assert response.json["error_code"] == "LOCAL_REPAIR_NOT_VERIFIED"
    assert expected in response.json["blockers"]


def test_resolve_blocked_when_abandoned_target_left_an_account(repair_env):
    _, client, states, token, _ = repair_env
    p = payload()
    plan = authorized_failed_recovery(client, token, p)
    states["NAU-010"] = repaired_account()
    states[plan["target_name"]] = repaired_account(plan["target_name"], object_sid="S-1-5-21-1-2-3-9999")
    response = resolve_request(client, token, plan, p, secure_channel=True)
    assert response.status_code == 409
    assert "target_account_exists" in response.json["blockers"]


def test_resolve_requires_a_recovery_attempt(repair_env):
    _, client, states, token, _ = repair_env
    p = payload()
    plan = post(client, "plan", token, p).json
    states["NAU-010"] = repaired_account()
    response = resolve_request(client, token, plan, p, secure_channel=True)
    assert response.status_code == 409
    assert {"plan_not_in_review", "no_recovery_attempt"} <= set(response.json["blockers"])


def test_resolve_requires_explicit_approval(repair_env):
    _, client, states, token, _ = repair_env
    p = payload()
    plan = authorized_failed_recovery(client, token, p)
    states["NAU-010"] = repaired_account()
    response = post(client, "progress/" + plan["id"], token, {
        "version": plan["version"], "device_id": DEVICE, "event": "resolve",
        "local": {**p["local"], "secure_channel": True}})
    assert response.status_code == 409
    assert "not_approved" in response.json["blockers"]


def test_pwd_last_set_parsing_matches_samba_filetime():
    from datetime import datetime, timezone
    from app.agents.domain_repair import ad_timestamp
    # Real value read on S11-15 after Test-ComputerSecureChannel -Repair.
    parsed = ad_timestamp("134363585174747321")
    assert parsed.replace(microsecond=0) == datetime(2026, 10, 13, 9, 48, 37, tzinfo=timezone.utc)
    assert ad_timestamp(parsed.isoformat()) == parsed
    assert ad_timestamp([datetime(2026, 1, 1)]).tzinfo is not None
    for unset in ("0", 0, "", None, [], "garbage", datetime(1601, 1, 1)):
        assert ad_timestamp(unset) is None

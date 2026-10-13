from uuid import uuid4

import pytest

from app.extensions import db
from app.models import AgentComputer, DomainRecovery, RecoveryPairing
from app.models.recovery_device import RecoveryDevice
from app.agents.domain_repair import ComputerState
from test_recovery_api import repair_env as recovery_fixture, payload, post, progress, OU

repair_env = recovery_fixture


def test_teacher_names_advance_after_occupied_base(repair_env):
    _, client, states, token, _ = repair_env
    states["BR-S30"] = ComputerState(True, "BR-S30", object_sid="occupied")
    states["BR-S30-01"] = ComputerState(True, "BR-S30-01", object_sid="occupied2")
    result = post(client, "plan", token, payload(target_name="BR-S30", auto_name=True))
    assert result.status_code == 201 and result.json["target_name"] == "BR-S30-02"


def hardware(mac="02:11:22:33:44:10", uid=None):
    return {"uuid": uid or str(uuid4()), "mac_addresses": [mac]}


def approve(app, client, name, hw, device_id=None):
    device_id = device_id or str(uuid4())
    response = post(client, "pair", "", {"hostname": name, "device_id": device_id, "hardware": hw})
    assert response.status_code == 201, response.data
    pair = response.json
    with app.app_context():
        db.session.get(RecoveryPairing, pair["id"]).approved_by = "operator"
        db.session.commit()
    response = post(client, "pair/" + pair["id"] + "/claim", "", {"claim_secret": pair["claim_secret"]})
    assert response.status_code == 200, response.data
    return response.json


def plan_request(device, name="S11-10"):
    return payload(device_id=device["device_id"], target_name="S11-10", auto_name=True,
        local={"hostname": name, "part_of_domain": False, "domain": "WORKGROUP", "secure_channel": None, "boot_id": "boot1"})


def test_same_hostname_two_devices_reserve_different_names_and_keep_tokens(repair_env):
    app, client, states, old_token, _ = repair_env
    first = approve(app, client, "S11-10", hardware())
    one = post(client, "plan", first["token"], plan_request(first))
    assert one.status_code == 201
    assert one.json["target_name"] == "S11-11"  # registered S11-10 is occupied
    second = approve(app, client, "S11-10", hardware("02:11:22:33:44:20"))
    two = post(client, "plan", second["token"], plan_request(second))
    assert two.status_code == 201 and two.json["target_name"] == "S11-12"
    assert two.json["id"] != one.json["id"]
    for device, plan in [(first, one.json), (second, two.json)]:
        response = client.get("/api/v1/agent/domain-repair/status", headers={"Authorization": "Bearer " + device["token"]})
        assert response.json["plan"]["id"] == plan["id"]
    assert client.get("/api/v1/agent/domain-repair/status/" + one.json["id"], headers={"Authorization": "Bearer " + second["token"]}).status_code == 404
    assert client.get("/api/v1/agent/domain-repair/status", headers={"Authorization": "Bearer " + old_token}).status_code == 200
    with app.app_context():
        assert db.session.get(DomainRecovery, one.json["id"]).version == 1
        assert db.session.query(RecoveryDevice).count() == 2


def test_known_hardware_restores_canonical_id_plan_after_name_change(repair_env):
    app, client, _, _, _ = repair_env
    hw = hardware()
    first = approve(app, client, "S11-10", hw)
    request = plan_request(first)
    plan = post(client, "plan", first["token"], request).json
    assert post(client, "plan", first["token"], request).json["id"] == plan["id"]
    again = approve(app, client, "S11-11", hw, str(uuid4()))
    assert again["device_id"] == first["device_id"]
    assert again["plan"]["id"] == plan["id"]
    assert again["observed_name"] == "S11-11"
    assert client.get("/api/v1/agent/domain-repair/status", headers={"Authorization": "Bearer " + first["token"]}).status_code == 401


def test_copied_local_id_cannot_take_over_other_hardware(repair_env):
    app, client, _, _, _ = repair_env
    hw = hardware()
    first = approve(app, client, "S11-10", hw)
    plan = post(client, "plan", first["token"], plan_request(first)).json
    for other in [hardware(), hardware("02:11:22:33:44:20", hw["uuid"])]:
        response = post(client, "identify", first["token"], {"hostname": "S11-10", "device_id": first["device_id"], "hardware": other})
        assert response.status_code == 409
        response = post(client, "pair", "", {"hostname": "S11-10", "device_id": first["device_id"], "hardware": other})
        assert response.status_code == 409
    with app.app_context():
        assert db.session.get(DomainRecovery, plan["id"]).version == 1


def test_legacy_token_requires_matching_hardware_not_hostname(repair_env):
    app, client, _, token, _ = repair_env
    hw = hardware()
    response = post(client, "identify", token, {"hostname": "NAU-010", "device_id": str(uuid4()), "hardware": hw})
    assert response.status_code == 403
    with app.app_context():
        agent = db.session.scalar(db.select(AgentComputer).where(AgentComputer.hostname == "NAU-010"))
        agent.mac_addresses = hw["mac_addresses"]
        db.session.commit()
    response = post(client, "identify", token, {"hostname": "NAU-010", "device_id": str(uuid4()), "hardware": hw})
    assert response.status_code == 200
    other = approve(app, client, "NAU-010", hardware("02:11:22:33:44:20"))
    assert other["device_id"] != response.json["device_id"]
    assert other["plan"] is None


def test_existing_firmware_plan_migrates_without_rotating_agent_token(repair_env):
    app, client, states, token, _ = repair_env
    hw = hardware("02:00:00:00:00:01")
    with app.app_context():
        other = db.session.scalar(db.select(AgentComputer).where(AgentComputer.hostname == "NAU-011"))
        other.mac_addresses = ["02:00:00:00:00:02"]
        db.session.commit()
    states["NAU-010"] = ComputerState(True, "NAU-010", enabled=True, object_sid="own")
    p = payload(device_id=hw["uuid"])
    plan = post(client, "plan", token, p).json
    device = approve(app, client, "NAU-010", hw, hw["uuid"])
    assert device["plan"]["id"] == plan["id"]
    with app.app_context():
        assert db.session.get(RecoveryDevice, device["device_id"]).owned_source_sid == "own"
    assert client.get("/api/v1/agent/domain-repair/status", headers={"Authorization": "Bearer " + token}).status_code == 200


def test_new_device_retargets_without_adopting_other_devices_ad_sid(repair_env):
    app, client, states, _, _ = repair_env
    states["S11-10"] = ComputerState(True, "S11-10", enabled=True, object_sid="somebody-else")
    hw = hardware()
    device = approve(app, client, "S11-10", hw)
    p = plan_request(device)
    p["local"].update(
        part_of_domain=True,
        domain="sp2.lan",
        secure_channel=False,
        mac_addresses=hw["mac_addresses"],
        hardware_uuid=hw["uuid"],
    )
    result = post(client, "plan", device["token"], p)
    assert result.status_code == 201
    plan = result.json
    assert plan["target_name"] != "S11-10"
    assert plan["action"] == "machine_account_recovery"
    assert plan["diagnosis"]["status"] == "SOURCE_OWNERSHIP_UNCONFIRMED_RETARGET"
    plan = progress(client, device["token"], plan, p, "begin").json
    authorized = post(client, "join-authorize/" + plan["id"], device["token"], {
        "version": plan["version"],
        "device_id": p["device_id"],
        "local": p["local"],
    })
    assert authorized.status_code == 200
    assert authorized.json == {"authorized": True}
    with app.app_context():
        saved = db.session.get(RecoveryDevice, device["device_id"])
        assert saved.owned_source_sid == ""
        recovery = db.session.get(DomainRecovery, plan["id"])
        assert recovery.source_sid == ""


def test_new_device_cannot_recover_into_unowned_source_name(repair_env):
    app, client, states, _, _ = repair_env
    states["S11-10"] = ComputerState(True, "S11-10", enabled=True, object_sid="somebody-else")
    hw = hardware()
    device = approve(app, client, "S11-10", hw)
    p = plan_request(device)
    p["auto_name"] = False
    p["target_name"] = "S11-10"
    p["local"].update(
        part_of_domain=True,
        domain="sp2.lan",
        secure_channel=False,
        mac_addresses=hw["mac_addresses"],
        hardware_uuid=hw["uuid"],
    )
    result = post(client, "plan", device["token"], p)
    assert result.status_code == 409
    assert result.json["diagnosis"]["status"] == "SOURCE_OWNERSHIP_UNCONFIRMED"


def test_device_completion_remembers_new_name_and_issued_join_sid(repair_env):
    app, client, states, _, _ = repair_env
    device = approve(app, client, "S11-10", hardware())
    p = plan_request(device)
    plan = post(client, "plan", device["token"], p).json
    plan = progress(client, device["token"], plan, p, "begin").json
    target = plan["target_name"]
    states[target] = ComputerState(True, target, "CN=" + target + "," + OU,
        target.lower() + ".sp2.lan", True, "new-own-sid", ["HOST/" + target, "HOST/" + target.lower() + ".sp2.lan"])
    response = progress(client, device["token"], plan, p, "observe", hostname=target,
        part_of_domain=True, domain="sp2.lan", secure_channel=True, boot_id="boot2")
    assert response.status_code == 200 and response.json["state"] == "complete"
    with app.app_context():
        saved = db.session.get(RecoveryDevice, device["device_id"])
        assert saved.current_hostname == target and saved.owned_source_sid == "new-own-sid"
        assert db.session.get(AgentComputer, saved.computer_id).hostname == target


@pytest.mark.parametrize("bad", [{}, {"uuid": "bad", "mac_addresses": []}, {"mac_addresses": ["FF:FF:FF:FF:FF:FF"]}, {"mac_addresses": ["00:00:00:00:00:00"]}])
def test_missing_invalid_hardware_does_not_create_pairing(repair_env, bad):
    app, client, _, _, _ = repair_env
    with app.app_context():
        before = db.session.query(RecoveryPairing).count()
    result = post(client, "pair", "", {"hostname": "S11-10", "device_id": str(uuid4()), "hardware": bad})
    assert result.status_code == 400
    with app.app_context():
        assert db.session.query(RecoveryPairing).count() == before


@pytest.mark.parametrize("collision", ["uuid", "mac"])
def test_duplicate_hardware_with_new_local_id_is_blocked(repair_env, collision):
    app, client, _, _, _ = repair_env
    original = hardware()
    approve(app, client, "S11-10", original)
    duplicate = hardware("02:11:22:33:44:20", original["uuid"]) if collision == "uuid" else hardware(original["mac_addresses"][0])
    response = post(client, "pair", "", {"hostname": "S11-20", "device_id": str(uuid4()), "hardware": duplicate})
    assert response.status_code == 409
    with app.app_context():
        assert db.session.query(RecoveryDevice).count() == 1


def test_owned_cn_mismatch_is_resolved_once_without_changing_sid(repair_env, monkeypatch):
    app, client, states, token, _ = repair_env
    states["NAU-010"] = ComputerState(True, "NAU-010", "CN=Old," + OU, enabled=True, object_sid="own")
    p = payload()
    plan = post(client, "plan", token, p).json
    assert plan["action"] == "repair_ad_cn"

    class Connection:
        result = {"result": 32}
        entries = []
        def search(self, *args, **kwargs):
            return False
        def modify_dn(self, old, rdn, **kwargs):
            saved = db.session.get(DomainRecovery, plan["id"])
            assert saved.state == "pending" and saved.version == plan["version"] + 1
            assert old == "CN=Old," + OU and rdn == "CN=NAU-010"
            states["NAU-010"].dn = rdn + "," + OU
            return True
        def unbind(self):
            pass

    monkeypatch.setattr("app.agents.recovery_routes.DirectoryService.__init__", lambda self: None)
    monkeypatch.setattr("app.agents.recovery_routes.DirectoryService._connection", lambda self, **kwargs: Connection())
    data = {"version": plan["version"], "device_id": p["device_id"], "local": p["local"], "approved": True}
    response = post(client, "approve-ad/" + plan["id"], token, data)
    assert response.status_code == 200
    with app.app_context():
        assert db.session.get(DomainRecovery, plan["id"]).source_sid == "own"
    assert post(client, "approve-ad/" + plan["id"], token, data).status_code == 409
    result = progress(client, token, response.json, p, "observe")
    assert result.json["action"] == "repair_secure_channel"


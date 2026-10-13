import pytest
from flask import Flask

from app.agents.domain_repair import ComputerState, build_diagnosis, computer_state
from app.directory.service import DirectoryError

OU = "OU=Nauczyciele,OU=Komputery,DC=sp2,DC=lan"


@pytest.fixture
def diagnosis_env(monkeypatch):
    app = Flask(__name__)
    app.config.update(AD_DOMAIN_FQDN="sp2.lan", AD_JOIN_ALLOWED_OU_BASES=[OU])
    states = {}
    monkeypatch.setattr(
        "app.agents.domain_repair.computer_state",
        lambda name: states.get(name, ComputerState(False, name)),
    )
    monkeypatch.setattr(
        "app.agents.domain_repair.directory_checks",
        lambda *args: {"ou_exists": True, "dns_spn_conflict": False, "dns_resolves": True},
    )
    with app.app_context():
        yield states


def diagnose(member=True, secure=False, source="NAU-010", sid=""):
    return build_diagnosis(
        {
            "local": {
                "hostname": source,
                "part_of_domain": member,
                "secure_channel": secure,
                "domain": "sp2.lan",
            },
            "target_name": "BR-S30",
            "target_ou": OU,
        },
        owned_sid=sid,
    )


def test_domain_repair_missing_source_account_fails_closed_without_ntlm(diagnosis_env):
    result = diagnose()
    assert result["status"] == "TRUST_BROKEN_AD_MISSING_NTLM_SAFE_STOP"
    assert result["recommended_action"] == "blocked"


def test_machine_recovery_requires_explicit_enable_and_known_broken_channel(diagnosis_env):
    from flask import current_app

    current_app.config["MACHINE_ACCOUNT_RECOVERY_ENABLED"] = True
    assert diagnose()["recommended_action"] == "machine_account_recovery"
    assert diagnose(secure=None)["recommended_action"] == "blocked"
    assert diagnose(secure=True)["recommended_action"] == "blocked"
    diagnosis_env["BR-S30"] = ComputerState(True, "BR-S30", enabled=True, object_sid="foreign")
    assert diagnose()["recommended_action"] == "blocked_conflict"




def test_missing_source_never_returns_recovery_to_workgroup(diagnosis_env):
    for secure in (False, None):
        result = diagnose(secure=secure)
        assert result["recommended_action"] == "blocked"
        assert result["recommended_action"] != "recovery_to_workgroup"


def test_domain_repair_target_conflict_is_blocked(diagnosis_env):
    diagnosis_env["BR-S30"] = ComputerState(True, "BR-S30", enabled=True, object_sid="other")
    assert diagnose()["status"] == "TARGET_CONFLICT"


def test_same_name_outside_domain_does_not_reuse_account(diagnosis_env):
    diagnosis_env["BR-S30"] = ComputerState(True, "BR-S30", enabled=True, object_sid="other")
    assert diagnose(member=False, source="BR-S30")["status"] == "TARGET_CONFLICT"


def test_repair_existing_source_then_rename(diagnosis_env):
    diagnosis_env["NAU-010"] = ComputerState(True, "NAU-010", enabled=True, object_sid="own")
    assert diagnose(sid="own")["recommended_action"] == "repair_secure_channel"
    assert diagnose(secure=True, sid="own")["recommended_action"] == "rename_domain"


def test_unknown_and_inconsistent_states_stop(diagnosis_env):
    assert diagnose(secure=None)["recommended_action"] == "blocked"
    assert diagnose(secure=True)["status"] == "INCONSISTENT_AD_STATE"
    diagnosis_env["NAU-010"] = ComputerState(True, "NAU-010", enabled=True, object_sid="own")
    assert diagnose(secure=None, sid="own")["recommended_action"] == "diagnose"


def test_ou_dns_spn_required_for_completion(diagnosis_env):
    state = ComputerState(
        True,
        "BR-S30",
        "CN=BR-S30," + OU,
        "br-s30.sp2.lan",
        True,
        "own",
        ["HOST/BR-S30", "HOST/br-s30.sp2.lan"],
    )
    diagnosis_env["BR-S30"] = state
    assert diagnose(secure=True, source="BR-S30", sid="own")["status"] == "OK"
    state.spns = []
    assert diagnose(secure=True, source="BR-S30", sid="own")["status"] == "AD_METADATA_REVIEW"


def test_spn_conflict_on_noncomputer_object_blocks(diagnosis_env, monkeypatch):
    monkeypatch.setattr(
        "app.agents.domain_repair.directory_checks",
        lambda *args: {"ou_exists": True, "dns_spn_conflict": True},
    )
    assert diagnose()["status"] == "TARGET_CONFLICT"


def test_actual_record_parser(monkeypatch):
    class Service:
        COMPUTER_ATTRIBUTES = []

        def _search(self, query, attrs, **kwargs):
            assert "sAMAccountName=NAU-010$" in query
            assert "servicePrincipalName" in attrs
            return [
                {
                    "userAccountControl": [4096],
                    "objectSid": ["SID"],
                    "dn": "CN=NAU-010," + OU,
                    "servicePrincipalName": ["HOST/NAU-010"],
                    "lastLogonTimestamp": ["2026-09-30"],
                }
            ]

    monkeypatch.setattr("app.agents.domain_repair.DirectoryService", Service)
    state = computer_state("NAU-010")
    assert state.enabled and state.object_sid == "SID" and state.spns == ["HOST/NAU-010"]
    assert state.activity == "unknown"


def test_ambiguous_lookup_fails_closed(monkeypatch):
    class Service:
        COMPUTER_ATTRIBUTES = []

        def _search(self, *args, **kwargs):
            return [{}, {}]

    monkeypatch.setattr("app.agents.domain_repair.DirectoryService", Service)
    with pytest.raises(DirectoryError):
        computer_state("BR-S30")


def test_dns_timeout_is_not_a_free_name(monkeypatch):
    import socket
    from app.agents.domain_repair import dns_addresses

    def fail(*args):
        raise socket.gaierror(socket.EAI_AGAIN, "temporary failure")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(DirectoryError):
        dns_addresses("BR-S30", "sp2.lan")


def test_dns_absence_and_resolution(monkeypatch):
    import socket
    from app.agents.domain_repair import dns_addresses

    def absent(*args):
        raise socket.gaierror(socket.EAI_NONAME, "not found")

    monkeypatch.setattr(socket, "getaddrinfo", absent)
    assert dns_addresses("BR-S30", "sp2.lan") == []
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args: [(None, None, None, None, ("192.0.2.3", 0))]
    )
    assert dns_addresses("BR-S30", "sp2.lan") == ["192.0.2.3"]

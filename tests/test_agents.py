from datetime import datetime, timedelta, timezone

from app import create_app
from app.extensions import db
from app.models import (
    AgentArchive,
    AgentComputer,
    AgentEnrollmentCode,
    AgentEnrollmentUse,
    User,
)


def test_agent_heartbeat_requires_token():
    app = create_app("testing")
    response = app.test_client().post("/api/v1/agent/heartbeat", json={"hostname": "PC-01"})
    assert response.status_code == 401


def test_agent_register_and_heartbeat_save_inventory():
    app = create_app("testing")
    app.config["AGENT_API_TOKEN"] = "test-token"
    client = app.test_client()
    payload = {
        "hostname": "pc-01",
        "os_name": "Windows 11 Pro",
        "ram_bytes": 8589934592,
        "ip_addresses": ["10.0.0.10"],
        "mac_addresses": ["AA-BB-CC-DD-EE-FF"],
        "room": "Sala32",
        "serial_number": "ABC123",
    }
    response = client.post("/api/v1/agent/register", headers={"Authorization": "Bearer test-token"}, json=payload)
    assert response.status_code == 201
    response = client.post("/api/v1/agent/heartbeat", headers={"Authorization": "Bearer test-token"}, json=payload)
    assert response.status_code == 200
    with app.app_context():
        agent = db.session.scalar(db.select(AgentComputer).where(AgentComputer.hostname == "PC-01"))
        assert agent is not None
        assert agent.room == "Sala32"
        assert agent.serial_number == "ABC123"


def test_heartbeat_stores_console_session():
    app = create_app("testing")
    app.config["AGENT_API_TOKEN"] = "test-token"
    client = app.test_client()
    payload = {
        "hostname": "pc-session",
        "console_session": {"username": "uczen01", "session_id": 1, "session_name": "console"},
    }
    client.post("/api/v1/agent/register", headers={"Authorization": "Bearer test-token"}, json=payload)
    response = client.post("/api/v1/agent/heartbeat", headers={"Authorization": "Bearer test-token"}, json=payload)

    assert response.status_code == 200
    with app.app_context():
        agent = db.session.scalar(
            db.select(AgentComputer).where(AgentComputer.hostname == "PC-SESSION")
        )
        assert agent.console_session == {
            "username": "uczen01", "session_id": 1, "session_name": "console",
        }


def test_heartbeat_clears_console_session_when_nobody_logged_in():
    app = create_app("testing")
    app.config["AGENT_API_TOKEN"] = "test-token"
    client = app.test_client()
    with_session = {
        "hostname": "pc-session2",
        "console_session": {"username": "uczen02", "session_id": 1, "session_name": "console"},
    }
    client.post("/api/v1/agent/register", headers={"Authorization": "Bearer test-token"}, json=with_session)
    client.post("/api/v1/agent/heartbeat", headers={"Authorization": "Bearer test-token"}, json=with_session)

    without_session = {"hostname": "pc-session2", "console_session": None}
    response = client.post(
        "/api/v1/agent/heartbeat", headers={"Authorization": "Bearer test-token"}, json=without_session
    )

    assert response.status_code == 200
    with app.app_context():
        agent = db.session.scalar(
            db.select(AgentComputer).where(AgentComputer.hostname == "PC-SESSION2")
        )
        assert agent.console_session is None


def test_agent_list_and_details_require_login():
    app = create_app("testing")
    client = app.test_client()
    assert client.get("/agents").status_code == 302
    assert client.get("/agents/1").status_code == 302


def test_agent_details_page():
    app = create_app("testing")
    with app.app_context():
        user = User(username="adminagent", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        agent = AgentComputer(hostname="PC-32-01", room="Sala32", os_name="Windows 11")
        db.session.add_all([user, agent])
        db.session.commit()
        agent_id = agent.id
    client = app.test_client()
    client.post("/login", data={"username": "adminagent", "password": "secret123"})
    response = client.get(f"/agents/{agent_id}")
    assert response.status_code == 200
    assert b"PC-32-01" in response.data


def test_remote_desktop_download_requires_login():
    app = create_app("testing")
    client = app.test_client()
    assert client.get("/agents/1/rdp").status_code == 302


def test_remote_desktop_download_requires_administrator():
    app = create_app("testing")
    with app.app_context():
        user = User(username="viewer-rdp", full_name="Viewer", role="viewer")
        user.set_password("secret123")
        agent = AgentComputer(hostname="PC-RDP-01", fqdn="pc-rdp-01.sp2.local")
        db.session.add_all([user, agent])
        db.session.commit()
        agent_id = agent.id
    client = app.test_client()
    client.post("/login", data={"username": "viewer-rdp", "password": "secret123"})
    assert client.get(f"/agents/{agent_id}/rdp").status_code == 403


def test_remote_desktop_download_returns_rdp_file():
    app = create_app("testing")
    app.config.update(AD_DOMAIN_NETBIOS="SP2")
    with app.app_context():
        user = User(username="admin-rdp", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        agent = AgentComputer(hostname="PC-RDP-02", fqdn="pc-rdp-02.sp2.local")
        db.session.add_all([user, agent])
        db.session.commit()
        agent_id = agent.id
    client = app.test_client()
    client.post("/login", data={"username": "admin-rdp", "password": "secret123"})
    response = client.get(f"/agents/{agent_id}/rdp")

    assert response.status_code == 200
    assert response.mimetype == "application/x-rdp"
    assert "PC-RDP-02.rdp" in response.headers["Content-Disposition"]
    body = response.get_data(as_text=True)
    assert "full address:s:pc-rdp-02.sp2.local" in body
    assert "domain:s:SP2" in body
    assert "password" not in body.lower()

    with app.app_context():
        from app.models import AuditLog

        audit = db.session.scalar(
            db.select(AuditLog).where(AuditLog.action == "AGENT_RDP_DOWNLOAD")
        )
        assert audit is not None
        assert audit.result == "SUCCESS"


def test_agent_details_page_shows_remote_desktop_button_for_administrator():
    app = create_app("testing")
    with app.app_context():
        user = User(username="admin-rdp-btn", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        agent = AgentComputer(hostname="PC-RDP-03")
        db.session.add_all([user, agent])
        db.session.commit()
        agent_id = agent.id
    client = app.test_client()
    client.post("/login", data={"username": "admin-rdp-btn", "password": "secret123"})
    response = client.get(f"/agents/{agent_id}")

    assert response.status_code == 200
    assert f"/agents/{agent_id}/rdp".encode() in response.data


def test_agent_details_page_shows_shadow_commands_for_school_management():
    from app.models import AuditLog

    app = create_app("testing")
    with app.app_context():
        user = User(username="dyrektor-shadow", full_name="Dyrektor", role="dyrektor")
        user.set_password("secret123")
        agent = AgentComputer(
            hostname="PC-SHADOW-01",
            fqdn="pc-shadow-01.sp2.local",
            console_session={"username": "uczen01", "session_id": 2, "session_name": "console"},
        )
        db.session.add_all([user, agent])
        db.session.commit()
        agent_id = agent.id
    client = app.test_client()
    client.post("/login", data={"username": "dyrektor-shadow", "password": "secret123"})
    response = client.get(f"/agents/{agent_id}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "mstsc /shadow:2 /v:pc-shadow-01.sp2.local /noConsentPrompt" in body
    assert "mstsc /shadow:2 /v:pc-shadow-01.sp2.local /control /noConsentPrompt" in body
    assert "uczen01" in body
    with app.app_context():
        audit = db.session.scalar(
            db.select(AuditLog).where(AuditLog.action == "AGENT_SHADOW_VIEW")
        )
        assert audit is not None


def test_agent_details_page_hides_shadow_commands_for_viewer_role():
    app = create_app("testing")
    with app.app_context():
        user = User(username="viewer-shadow", full_name="Viewer", role="viewer")
        user.set_password("secret123")
        agent = AgentComputer(
            hostname="PC-SHADOW-02",
            console_session={"username": "uczen02", "session_id": 3, "session_name": "console"},
        )
        db.session.add_all([user, agent])
        db.session.commit()
        agent_id = agent.id
    client = app.test_client()
    client.post("/login", data={"username": "viewer-shadow", "password": "secret123"})
    response = client.get(f"/agents/{agent_id}")

    assert response.status_code == 200
    assert b"mstsc /shadow" not in response.data


def test_agent_details_page_hides_shadow_commands_without_active_session():
    app = create_app("testing")
    with app.app_context():
        user = User(username="admin-noshadow", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        agent = AgentComputer(hostname="PC-SHADOW-03", console_session=None)
        db.session.add_all([user, agent])
        db.session.commit()
        agent_id = agent.id
    client = app.test_client()
    client.post("/login", data={"username": "admin-noshadow", "password": "secret123"})
    response = client.get(f"/agents/{agent_id}")

    assert response.status_code == 200
    assert b"mstsc /shadow" not in response.data


def test_agent_job_payload_uses_type_key():
    from app.models import AgentJob
    job = AgentJob(id=7, computer_id=1, action="inventory", payload={})
    assert job.as_agent_payload() == {"id": 7, "type": "inventory", "payload": {}}


def test_admin_can_create_and_agent_can_receive_job():
    from app.models import AgentJob
    app = create_app("testing")
    app.config["SP2_API_TOKEN"] = "test-token"
    app.config["AGENT_API_TOKEN"] = "test-token"
    with app.app_context():
        user = User(username="jobadmin", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        agent = AgentComputer(hostname="PC-JOB-01")
        db.session.add_all([user, agent])
        db.session.commit()
        agent_id = agent.id

    client = app.test_client()
    client.post("/login", data={"username": "jobadmin", "password": "secret123"})
    response = client.post(f"/agents/{agent_id}/commands", data={"action": "inventory"})
    assert response.status_code == 302

    response = client.post(
        "/api/v1/agent/commands/next",
        headers={"Authorization": "Bearer test-token"},
        json={"hostname": "PC-JOB-01"},
    )
    assert response.status_code == 200
    command = response.get_json()["command"]
    assert command["type"] == "inventory"
    assert "action" not in command

    with app.app_context():
        job = db.session.scalar(db.select(AgentJob))
        assert job.status == "running"


def test_agent_result_is_saved():
    from app.models import AgentJob
    app = create_app("testing")
    app.config["SP2_API_TOKEN"] = "test-token"
    app.config["AGENT_API_TOKEN"] = "test-token"
    with app.app_context():
        agent = AgentComputer(hostname="PC-RESULT-01")
        job = AgentJob(computer=agent, action="inventory", payload={}, status="running")
        db.session.add_all([agent, job])
        db.session.commit()
        job_id = job.id

    response = app.test_client().post(
        f"/api/v1/agent/commands/{job_id}/result",
        headers={"Authorization": "Bearer test-token"},
        json={"hostname": "PC-RESULT-01", "status": "success", "result": "OK"},
    )
    assert response.status_code == 200
    with app.app_context():
        job = db.session.get(AgentJob, job_id)
        assert job.status == "success"
        assert job.result == {"output": "OK"}

def test_agent_accepts_previous_token_during_rollover():
    app = create_app("testing")
    app.config["SP2_API_TOKEN"] = "new-token"
    app.config["AGENT_API_TOKEN"] = "new-token"
    app.config["SP2_API_TOKEN_PREVIOUS"] = "old-token"

    response = app.test_client().post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": "Bearer old-token"},
        json={"hostname": "PC-ROLLOVER-01"},
    )

    assert response.status_code == 200


def test_usb_name_preview_requires_enrollment_token(client):
    response = client.post(
        "/api/v1/agent/domain/name-preview",
        json={"profile": "Nauczyciel"},
    )
    assert response.status_code == 401


def test_usb_name_preview_detects_room_conflict(
    app,
    client,
    monkeypatch,
):
    app.config["AGENT_ENROLLMENT_TOKEN"] = "usb-token"
    monkeypatch.setattr(
        "app.agents.profile_routes.DirectoryService.computers",
        lambda self, limit=500: [
            {"sAMAccountName": ["S11-01$"]},
        ],
    )

    response = client.post(
        "/api/v1/agent/domain/name-preview",
        headers={"Authorization": "Bearer usb-token"},
        json={"profile": "Sala11", "station_number": 1},
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "conflict",
        "computer_name": "S11-01",
        "available": False,
        "profile": "Sala11",
        "target_ou": "OU=Sala11,OU=Komputery,DC=sp2,DC=lan",
    }


def test_usb_name_preview_selects_first_free_teacher_name(
    app,
    client,
    monkeypatch,
):
    app.config["AGENT_ENROLLMENT_TOKEN"] = "usb-token"
    monkeypatch.setattr(
        "app.agents.profile_routes.DirectoryService.computers",
        lambda self, limit=500: [
            {"sAMAccountName": ["NAU-001$"]},
            {"sAMAccountName": ["nau-002"]},
        ],
    )

    response = client.post(
        "/api/v1/agent/domain/name-preview",
        headers={"Authorization": "Bearer usb-token"},
        json={"profile": "Nauczyciel"},
    )

    assert response.status_code == 200
    assert response.get_json()["computer_name"] == "NAU-003"
    assert response.get_json()["available"] is True


def test_usb_name_preview_selects_first_free_admin_name(
    app,
    client,
    monkeypatch,
):
    app.config["AGENT_ENROLLMENT_TOKEN"] = "usb-token"
    monkeypatch.setattr(
        "app.agents.profile_routes.DirectoryService.computers",
        lambda self, limit=500: [],
    )

    response = client.post(
        "/api/v1/agent/domain/name-preview",
        headers={"Authorization": "Bearer usb-token"},
        json={"profile": "Administracja"},
    )

    assert response.status_code == 200
    assert response.get_json()["computer_name"] == "ADM-001"


def test_usb_name_preview_lists_free_room_numbers(
    app,
    client,
    monkeypatch,
):
    app.config["AGENT_ENROLLMENT_TOKEN"] = "usb-token"
    monkeypatch.setattr(
        "app.agents.profile_routes.DirectoryService.computers",
        lambda self, limit=500: [
            {"sAMAccountName": ["S11-01$"]},
            {"sAMAccountName": ["s11-03"]},
        ],
    )

    response = client.post(
        "/api/v1/agent/domain/name-preview",
        headers={"Authorization": "Bearer usb-token"},
        json={"profile": "Sala11"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["computer_name"] == "S11-02"
    assert payload["station_number"] == 2
    assert payload["available_numbers"][:3] == [2, 4, 5]
    assert 1 not in payload["available_numbers"]
    assert 3 not in payload["available_numbers"]


def test_agent_cleanup_preview_matches_legacy_record_by_serial_number():
    app = create_app("testing")
    with app.app_context():
        user = User(username="cleanupadmin", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        old = AgentComputer(
            hostname="DESKTOP-OLD123",
            serial_number="SERIAL-001",
            mac_addresses=["AA-BB-CC-DD-EE-FF"],
            last_seen=datetime.now(timezone.utc) - timedelta(days=10),
        )
        current = AgentComputer(
            hostname="S11-10",
            room="Sala11",
            serial_number="SERIAL-001",
            mac_addresses=["AA-BB-CC-DD-EE-FF"],
        )
        db.session.add_all([user, old, current])
        db.session.commit()

    client = app.test_client()
    client.post("/login", data={"username": "cleanupadmin", "password": "secret123"})
    response = client.get("/agents/cleanup")

    assert response.status_code == 200
    assert b"DESKTOP-OLD123" in response.data
    assert b"S11-10" in response.data
    assert "numer seryjny".encode() in response.data


def test_agent_cleanup_preview_does_not_flag_online_legacy_agent():
    app = create_app("testing")
    with app.app_context():
        user = User(username="cleanupadmin2", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        online_old_name = AgentComputer(
            hostname="LAPTOP-STILL-USED",
            last_seen=datetime.now(timezone.utc),
        )
        db.session.add_all([user, online_old_name])
        db.session.commit()

    client = app.test_client()
    client.post("/login", data={"username": "cleanupadmin2", "password": "secret123"})
    response = client.get("/agents/cleanup")

    assert response.status_code == 200
    assert b"LAPTOP-STILL-USED" not in response.data


def test_admin_can_archive_and_restore_matched_legacy_agent():
    app = create_app("testing")
    with app.app_context():
        user = User(username="archiveadmin", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        old = AgentComputer(
            hostname="DESKTOP-ARCHIVE",
            serial_number="SERIAL-ARCHIVE",
            last_seen=datetime.now(timezone.utc) - timedelta(days=10),
        )
        current = AgentComputer(
            hostname="S11-12",
            room="Sala11",
            serial_number="SERIAL-ARCHIVE",
        )
        db.session.add_all([user, old, current])
        db.session.commit()
        old_id, current_id = old.id, current.id

    client = app.test_client()
    client.post("/login", data={"username": "archiveadmin", "password": "secret123"})
    response = client.post(
        f"/agents/cleanup/{old_id}/archive",
        data={
            "confirm": "archive",
            "successor_id": current_id,
        },
    )
    assert response.status_code == 302

    with app.app_context():
        archive = db.session.scalar(
            db.select(AgentArchive).where(AgentArchive.computer_id == old_id)
        )
        assert archive is not None
        assert archive.successor_id == current_id
        archive_id = archive.id

    response = client.get("/agents")
    # Komunikat flash celowo zawiera starą nazwę. Sprawdzamy więc,
    # czy z tabeli zniknął link do szczegółów starego rekordu.
    assert f'href="/agents/{old_id}"'.encode() not in response.data
    assert f'href="/agents/{current_id}"'.encode() in response.data

    response = client.post(
        f"/agents/cleanup/archive/{archive_id}/restore",
        data={"confirm": "restore"},
    )
    assert response.status_code == 302

    with app.app_context():
        assert db.session.get(AgentArchive, archive_id) is None

    response = client.get("/agents")
    assert b"DESKTOP-ARCHIVE" in response.data


def test_unmatched_legacy_agent_cannot_be_archived():
    app = create_app("testing")
    with app.app_context():
        user = User(username="archiveadmin2", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        old = AgentComputer(
            hostname="LAPTOP-UNMATCHED",
            serial_number="ONLY-OLD",
            last_seen=datetime.now(timezone.utc) - timedelta(days=10),
        )
        db.session.add_all([user, old])
        db.session.commit()
        old_id = old.id

    client = app.test_client()
    client.post("/login", data={"username": "archiveadmin2", "password": "secret123"})
    response = client.post(
        f"/agents/cleanup/{old_id}/archive",
        data={"confirm": "archive", "successor_id": 999},
    )
    assert response.status_code == 302

    with app.app_context():
        assert db.session.scalar(db.select(AgentArchive)) is None


def test_archived_agent_is_restored_automatically_on_heartbeat():
    app = create_app("testing")
    app.config["SP2_API_TOKEN"] = "test-token"
    app.config["AGENT_API_TOKEN"] = "test-token"
    with app.app_context():
        old = AgentComputer(hostname="DESKTOP-RETURNED")
        current = AgentComputer(hostname="S11-13")
        db.session.add_all([old, current])
        db.session.flush()
        archive = AgentArchive(
            computer_id=old.id,
            successor_id=current.id,
            reason="numer seryjny",
            archived_by="admin",
        )
        db.session.add(archive)
        db.session.commit()
        old_id = old.id

    response = app.test_client().post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": "Bearer test-token"},
        json={"hostname": "DESKTOP-RETURNED"},
    )
    assert response.status_code == 200

    with app.app_context():
        assert db.session.scalar(
            db.select(AgentArchive).where(AgentArchive.computer_id == old_id)
        ) is None


def test_enrollment_code_registers_multiple_workstations_up_to_limit():
    app = create_app("testing")
    app.config["AGENT_ENROLLMENT_MAX_USES"] = 2
    with app.app_context():
        code, raw_code = AgentEnrollmentCode.issue(
            created_by="admin",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db.session.add(code)
        db.session.commit()
        code_id = code.id

    client = app.test_client()
    headers = {"Authorization": f"Bearer {raw_code}"}

    first = client.post(
        "/api/v1/agent/register",
        headers=headers,
        json={"hostname": "PC-BATCH-01"},
    )
    assert first.status_code == 201
    assert first.get_json()["token"]

    second = client.post(
        "/api/v1/agent/register",
        headers=headers,
        json={"hostname": "PC-BATCH-02"},
    )
    assert second.status_code == 201
    assert second.get_json()["token"]

    third = client.post(
        "/api/v1/agent/register",
        headers=headers,
        json={"hostname": "PC-BATCH-03"},
    )
    assert third.status_code == 401

    with app.app_context():
        uses = db.session.scalar(
            db.select(db.func.count(AgentEnrollmentUse.id)).where(
                AgentEnrollmentUse.enrollment_code_id == code_id
            )
        )
        code = db.session.get(AgentEnrollmentCode, code_id)
        assert uses == 2
        assert code.used_at is not None


def test_enrollment_code_retry_for_same_hostname_does_not_consume_extra_slot():
    app = create_app("testing")
    app.config["AGENT_ENROLLMENT_MAX_USES"] = 1
    with app.app_context():
        code, raw_code = AgentEnrollmentCode.issue(
            created_by="admin",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        db.session.add(code)
        db.session.commit()

    client = app.test_client()
    headers = {"Authorization": f"Bearer {raw_code}"}
    assert client.post(
        "/api/v1/agent/register", headers=headers, json={"hostname": "PC-RETRY-01"}
    ).status_code == 201
    assert client.post(
        "/api/v1/agent/register", headers=headers, json={"hostname": "PC-RETRY-01"}
    ).status_code == 200


def test_expired_enrollment_code_is_rejected():
    app = create_app("testing")
    with app.app_context():
        code, raw_code = AgentEnrollmentCode.issue(
            created_by="admin",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        db.session.add(code)
        db.session.commit()

    response = app.test_client().post(
        "/api/v1/agent/register",
        headers={"Authorization": f"Bearer {raw_code}"},
        json={"hostname": "PC-EXPIRED-01"},
    )
    assert response.status_code == 401


def test_administrator_can_generate_enrollment_code():
    app = create_app("testing")
    with app.app_context():
        user = User(username="codeadmin", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        db.session.add(user)
        db.session.commit()

    client = app.test_client()
    client.post("/login", data={"username": "codeadmin", "password": "secret123"})
    response = client.post("/agents/deployment/enrollment-code")
    assert response.status_code == 302
    with app.app_context():
        code = db.session.scalar(db.select(AgentEnrollmentCode))
        assert code is not None
        assert code.created_by == "codeadmin"
        assert code.used_at is None

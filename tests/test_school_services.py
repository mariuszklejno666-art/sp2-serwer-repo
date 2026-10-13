from datetime import date, datetime, time
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from app.extensions import db
from app.network_drives import (
    NasEndpoint,
    ShareGroupMapping,
    audit_share_group_mappings,
    parse_nas_endpoints,
    parse_share_group_mappings,
)
from app.models import (
    AgentComputer,
    AgentJob,
    AudioTrack,
    AuditLog,
    BellEvent,
    BellEventAudio,
    BellSchedule,
    SchoolCalendarException,
    User,
    WebBlockRule,
)
from app.radio_calendar import classify_school_day
from app.radio_scheduler import due_bells, mark_executed, next_bell, was_executed


def _login_as(app, client, username: str, role: str):
    with app.app_context():
        user = User(
            username=username,
            full_name=f"Użytkownik {role}",
            role=role,
        )
        user.set_password("Test-password-123!")
        db.session.add(user)
        db.session.commit()

    response = client.post(
        "/login",
        data={
            "username": username,
            "password": "Test-password-123!",
        },
    )
    assert response.status_code == 302


def test_services_dashboard_requires_login(client):
    response = client.get("/school-services")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_administrator_can_add_web_filter_rule(app, authenticated_client):
    response = authenticated_client.post(
        "/school-services/web-filter",
        data={
            "label": "Gry online",
            "address": "https://games.example.pl/play",
            "rooms": ["4", "7", "11", "32"],
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "games.example.pl" in response.get_data(as_text=True)
    with app.app_context():
        rule = db.session.scalar(db.select(WebBlockRule))
        assert rule is not None
        assert rule.hostname == "games.example.pl"
        assert rule.room_list == ("4", "7", "11", "32")
        audit = db.session.scalar(
            db.select(AuditLog).where(
                AuditLog.action == "WEB_FILTER_RULE_CREATE"
            )
        )
        assert audit is not None


def test_apply_web_filter_requires_enforcement_flag(app, authenticated_client):
    app.config.update(WEB_FILTER_ENFORCEMENT_ENABLED=False)

    response = authenticated_client.post(
        "/school-services/web-filter/apply", follow_redirects=True
    )

    assert response.status_code == 200
    assert "WEB_FILTER_ENFORCEMENT_ENABLED" in response.get_data(as_text=True)
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count(AgentJob.id))) == 0


def test_apply_web_filter_queues_jobs_for_matching_rooms(app, authenticated_client):
    app.config.update(WEB_FILTER_ENFORCEMENT_ENABLED=True)
    with app.app_context():
        db.session.add(
            WebBlockRule(
                label="Gry",
                source_url="https://gry.pl",
                hostname="gry.pl",
                rooms="4",
                enabled=True,
                created_by="test-admin",
            )
        )
        db.session.add(AgentComputer(hostname="PC-SALA4-01", room="Sala4"))
        db.session.add(AgentComputer(hostname="PC-SALA7-01", room="Sala7"))
        db.session.commit()

    response = authenticated_client.post(
        "/school-services/web-filter/apply", follow_redirects=True
    )

    assert response.status_code == 200
    with app.app_context():
        jobs = db.session.scalars(
            db.select(AgentJob).where(AgentJob.action == "apply_web_filter")
        ).all()
        by_hostname = {job.computer.hostname: job for job in jobs}
        assert by_hostname["PC-SALA4-01"].payload["hostnames"] == ["gry.pl"]
        assert by_hostname["PC-SALA7-01"].payload["hostnames"] == []
        audit = db.session.scalar(
            db.select(AuditLog).where(AuditLog.action == "WEB_FILTER_APPLY")
        )
        assert audit is not None


def test_apply_web_filter_rejects_non_administrator(app, client):
    app.config.update(WEB_FILTER_ENFORCEMENT_ENABLED=True)
    _login_as(app, client, "viewer-webfilter", "viewer")

    response = client.post("/school-services/web-filter/apply")

    assert response.status_code == 403


def test_viewer_cannot_open_restricted_service_panels(app, client):
    _login_as(app, client, "viewer-services", "viewer")

    assert client.get("/school-services/web-filter").status_code == 403
    assert client.get("/school-services/monitoring").status_code == 403
    assert client.get("/school-services/radio").status_code == 403
    assert client.get("/school-services/network-drives").status_code == 403


def test_school_management_can_open_monitoring_but_not_filter(app, client):
    _login_as(app, client, "school-director", "dyrektor")

    assert client.get("/school-services/monitoring").status_code == 200
    assert client.get("/school-services/radio").status_code == 200
    assert client.get("/school-services/network-drives").status_code == 200
    assert client.get("/school-services/web-filter").status_code == 403


def test_qnap_endpoint_configuration_is_parsed():
    endpoints = parse_nas_endpoints((
        "QNAP-A=192.168.0.188",
        "QNAP-B=192.168.0.203",
        "invalid",
    ))
    assert endpoints == (
        NasEndpoint("QNAP-A", "192.168.0.188"),
        NasEndpoint("QNAP-B", "192.168.0.203"),
    )


def test_share_group_mapping_configuration_is_parsed():
    mappings = parse_share_group_mappings((
        "Nauczyciele=G-Nauczyciele",
        "Uczniowie=G-Uczniowie",
        "invalid",
    ))
    assert mappings == (
        ShareGroupMapping("Nauczyciele", "G-Nauczyciele"),
        ShareGroupMapping("Uczniowie", "G-Uczniowie"),
    )


def test_audit_share_group_mappings_flags_missing_group():
    mappings = parse_share_group_mappings((
        "Nauczyciele=G-Nauczyciele",
        "Uczniowie=G-Uczniowie",
    ))
    ad_groups = [
        {"sAMAccountName": ["G-Nauczyciele"], "member": ["u1", "u2", "u3"]},
    ]

    result = audit_share_group_mappings(mappings, ad_groups)

    assert result == [
        {"share": "Nauczyciele", "group": "G-Nauczyciele", "found": True, "member_count": 3},
        {"share": "Uczniowie", "group": "G-Uczniowie", "found": False, "member_count": 0},
    ]


def test_network_drives_route_shows_share_audit(app, authenticated_client, monkeypatch):
    app.config.update(NETWORK_DRIVE_SHARE_GROUPS=("Nauczyciele=G-Nauczyciele",))
    monkeypatch.setattr(
        "app.school_services.routes.DirectoryService.groups",
        lambda self, limit=500: [
            {"sAMAccountName": ["G-Nauczyciele"], "member": ["u1", "u2"]}
        ],
    )

    response = authenticated_client.get("/school-services/network-drives")

    assert response.status_code == 200
    assert "Grupa istnieje" in response.get_data(as_text=True)
    assert "Członków grupy: 2" in response.get_data(as_text=True)


def test_monitoring_route_shows_nvr_reachability(app, authenticated_client, monkeypatch):
    app.config.update(MONITORING_NVR_ENDPOINTS=("Sekretariat=192.168.0.227",))
    monkeypatch.setattr(
        "app.school_services.routes.check_nvr",
        lambda endpoint, timeout: {
            "name": endpoint.name,
            "host": endpoint.host,
            "port": endpoint.port,
            "reachable": True,
            "message": "Panel odpowiada na porcie 80",
            "panel_url": "http://192.168.0.227:80/",
        },
    )

    response = authenticated_client.get("/school-services/monitoring")

    assert response.status_code == 200
    assert "Sekretariat" in response.get_data(as_text=True)
    assert "Panel online" in response.get_data(as_text=True)


def test_monitoring_open_panel_redirects_and_audits(app, authenticated_client):
    app.config.update(MONITORING_NVR_ENDPOINTS=("Sekretariat=192.168.0.227",))

    response = authenticated_client.get(
        "/school-services/monitoring/open/Sekretariat", follow_redirects=False
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "http://192.168.0.227:80/"
    with app.app_context():
        audit = db.session.scalar(
            db.select(AuditLog).where(AuditLog.action == "MONITORING_PANEL_OPEN")
        )
        assert audit is not None
        assert "Sekretariat" in audit.details


def test_monitoring_open_panel_rejects_unknown_name(app, authenticated_client):
    app.config.update(MONITORING_NVR_ENDPOINTS=("Sekretariat=192.168.0.227",))

    response = authenticated_client.get("/school-services/monitoring/open/Nieznany")

    assert response.status_code == 404


def test_monitoring_snapshot_requires_matching_pilot_name(app, authenticated_client):
    app.config.update(
        MONITORING_NVR_ENDPOINTS=("Portiernia=192.168.0.75",),
        MONITORING_SNAPSHOT_NVR_NAME="Portiernia",
        MONITORING_SNAPSHOT_USERNAME="viewer",
        MONITORING_SNAPSHOT_PASSWORD="secret",
    )

    response = authenticated_client.get("/school-services/monitoring/snapshot/Sekretariat")

    assert response.status_code == 404


def test_monitoring_snapshot_returns_image_when_configured(app, authenticated_client, monkeypatch):
    app.config.update(
        MONITORING_NVR_ENDPOINTS=("Portiernia=192.168.0.75",),
        MONITORING_SNAPSHOT_NVR_NAME="Portiernia",
        MONITORING_SNAPSHOT_USERNAME="viewer",
        MONITORING_SNAPSHOT_PASSWORD="secret",
    )
    monkeypatch.setattr(
        "app.school_services.routes.fetch_snapshot",
        lambda **kwargs: (b"fake-jpeg-bytes", "image/jpeg"),
    )

    response = authenticated_client.get("/school-services/monitoring/snapshot/Portiernia")

    assert response.status_code == 200
    assert response.mimetype == "image/jpeg"
    assert response.data == b"fake-jpeg-bytes"
    with app.app_context():
        audit = db.session.scalar(
            db.select(AuditLog).where(AuditLog.action == "MONITORING_SNAPSHOT_FETCH")
        )
        assert audit is not None
        assert audit.result == "SUCCESS"


def test_monitoring_snapshot_returns_502_on_fetch_error(app, authenticated_client, monkeypatch):
    from app.monitoring_nvr import SnapshotError

    app.config.update(
        MONITORING_NVR_ENDPOINTS=("Portiernia=192.168.0.75",),
        MONITORING_SNAPSHOT_NVR_NAME="Portiernia",
        MONITORING_SNAPSHOT_USERNAME="viewer",
        MONITORING_SNAPSHOT_PASSWORD="secret",
    )

    def _boom(**kwargs):
        raise SnapshotError("timed out")

    monkeypatch.setattr("app.school_services.routes.fetch_snapshot", _boom)

    response = authenticated_client.get("/school-services/monitoring/snapshot/Portiernia")

    assert response.status_code == 502


def test_monitoring_snapshot_disabled_without_credentials(app, authenticated_client):
    app.config.update(
        MONITORING_NVR_ENDPOINTS=("Portiernia=192.168.0.75",),
        MONITORING_SNAPSHOT_NVR_NAME="Portiernia",
        MONITORING_SNAPSHOT_USERNAME="",
        MONITORING_SNAPSHOT_PASSWORD="",
    )

    response = authenticated_client.get("/school-services/monitoring/snapshot/Portiernia")

    assert response.status_code == 404


def test_network_drives_route_shows_volume_usage(app, authenticated_client, monkeypatch):
    from app.nas_snmp import VolumeUsage

    app.config.update(
        NETWORK_DRIVE_SNMP_HOST="192.168.0.203",
        NETWORK_DRIVE_SNMP_COMMUNITY="public",
    )
    monkeypatch.setattr(
        "app.school_services.routes.fetch_storage_usage",
        lambda host, community, port, timeout: [
            VolumeUsage(
                label="/share/CACHEDEV1_DATA",
                total_bytes=1000 * 1073741824,
                used_bytes=920 * 1073741824,
                percent_used=92.0,
            )
        ],
    )

    response = authenticated_client.get("/school-services/network-drives")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "92.0% zapełnione" in body
    assert "/share/CACHEDEV1_DATA" in body


def test_network_drives_route_shows_snmp_error(app, authenticated_client, monkeypatch):
    from app.nas_snmp import SnmpError

    app.config.update(
        NETWORK_DRIVE_SNMP_HOST="192.168.0.203",
        NETWORK_DRIVE_SNMP_COMMUNITY="public",
    )

    def _boom(host, community, port, timeout):
        raise SnmpError("timed out")

    monkeypatch.setattr("app.school_services.routes.fetch_storage_usage", _boom)

    response = authenticated_client.get("/school-services/network-drives")

    assert response.status_code == 200
    assert "timed out" in response.get_data(as_text=True)


def test_network_drives_route_hides_volume_section_without_snmp_config(
    app, authenticated_client
):
    app.config.update(NETWORK_DRIVE_SNMP_HOST="", NETWORK_DRIVE_SNMP_COMMUNITY="")

    response = authenticated_client.get("/school-services/network-drives")

    assert response.status_code == 200
    assert "Zapełnienie woluminów (SNMP)" not in response.get_data(as_text=True)


def test_network_drives_route_without_mappings_shows_hint(app, authenticated_client):
    app.config.update(NETWORK_DRIVE_SHARE_GROUPS=())

    response = authenticated_client.get("/school-services/network-drives")

    assert response.status_code == 200
    assert "NETWORK_DRIVE_SHARE_GROUPS" in response.get_data(as_text=True)


def test_school_management_can_add_radio_calendar_exception(app, client):
    _login_as(app, client, "radio-director", "dyrektor")
    response = client.post(
        "/school-services/radio/calendar-exceptions",
        data={
            "label": "Dzień dyrektorski",
            "starts_on": "2026-10-14",
            "ends_on": "2026-10-14",
            "kind": "break",
            "schedule": "brak",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Dzień dyrektorski" in response.get_data(as_text=True)
    with app.app_context():
        item = db.session.scalar(db.select(SchoolCalendarException))
        assert item is not None
        assert item.bells is False
        assert item.lessons is False


def test_school_management_can_create_bell_plan_and_event(app, client):
    _login_as(app, client, "bell-director", "dyrektor")
    response = client.post(
        "/school-services/radio/bell-schedules",
        data={"name": "standardowy"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "standardowy" in response.get_data(as_text=True)

    with app.app_context():
        schedule = db.session.scalar(db.select(BellSchedule))
        assert schedule is not None
        schedule_id = schedule.id

    response = client.post(
        f"/school-services/radio/bell-schedules/{schedule_id}/events",
        data={"time_of_day": "08:00", "label": "Początek pierwszej lekcji"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "08:00" in response.get_data(as_text=True)
    with app.app_context():
        event = db.session.scalar(db.select(BellEvent))
        assert event is not None
        assert event.time_of_day == time(8, 0)
        assert db.session.scalar(
            db.select(AuditLog).where(AuditLog.action == "RADIO_BELL_EVENT_CREATE")
        )


def test_bell_preview_selects_schedule_without_playback():
    now = datetime(2026, 9, 1, 7, 30, tzinfo=ZoneInfo("Europe/Warsaw"))
    day = classify_school_day(date(2026, 9, 1))
    event = SimpleNamespace(
        enabled=True,
        label="Pierwsza lekcja",
        time_of_day=time(8, 0),
    )
    schedule = SimpleNamespace(enabled=True, name="standardowy", events=[event])

    preview = next_bell(now, day, [schedule])

    assert preview is not None
    assert preview.label == "Pierwsza lekcja"
    assert preview.due_at.hour == 8


def test_bell_preview_is_silent_on_day_off():
    now = datetime(2026, 9, 5, 7, 30, tzinfo=ZoneInfo("Europe/Warsaw"))
    day = classify_school_day(date(2026, 9, 5))
    schedule = SimpleNamespace(enabled=True, name="standardowy", events=[])

    assert next_bell(now, day, [schedule]) is None


def test_due_bells_requires_enabled_audio_assignment():
    now = datetime(2026, 9, 1, 8, 0, 32, tzinfo=ZoneInfo("Europe/Warsaw"))
    day = classify_school_day(now.date())
    track = SimpleNamespace(enabled=True, stored_filename="bell.mp3")
    event = SimpleNamespace(
        id=7,
        enabled=True,
        label="Pierwsza lekcja",
        time_of_day=time(8, 0),
        audio_assignment=SimpleNamespace(track=track),
    )
    schedule = SimpleNamespace(enabled=True, name="standardowy", events=[event])

    due = due_bells(now, day, [schedule])

    assert len(due) == 1
    assert due[0].track is track
    assert due[0].execution_key.endswith(":7")


def test_due_bells_is_empty_without_assignment():
    now = datetime(2026, 9, 1, 8, 0, tzinfo=ZoneInfo("Europe/Warsaw"))
    day = classify_school_day(now.date())
    event = SimpleNamespace(
        id=8,
        enabled=True,
        label="Pierwsza lekcja",
        time_of_day=time(8, 0),
        audio_assignment=None,
    )
    schedule = SimpleNamespace(enabled=True, name="standardowy", events=[event])
    assert due_bells(now, day, [schedule]) == []


def test_bell_execution_state_prevents_duplicate(tmp_path):
    state_path = tmp_path / "last_execution.json"
    assert not was_executed(state_path, "2026-09-01T08:00+02:00:1")
    mark_executed(state_path, "2026-09-01T08:00+02:00:1")
    assert was_executed(state_path, "2026-09-01T08:00+02:00:1")


def test_school_management_can_assign_audio_to_bell(app, client):
    _login_as(app, client, "bell-audio-director", "dyrektor")
    with app.app_context():
        schedule = BellSchedule(name="standardowy", created_by="test")
        event = BellEvent(
            schedule=schedule,
            label="Dzwonek",
            time_of_day=time(8, 0),
            created_by="test",
        )
        track = AudioTrack(
            title="Dzwonek klasyczny",
            original_filename="bell.mp3",
            stored_filename="bell-123.mp3",
            media_type="mp3",
            size_bytes=100,
            created_by="test",
        )
        db.session.add_all([schedule, event, track])
        db.session.commit()
        event_id, track_id = event.id, track.id

    response = client.post(
        f"/school-services/radio/bell-events/{event_id}/audio",
        data={"track_id": track_id},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Dźwięk został przypisany" in response.get_data(as_text=True)
    with app.app_context():
        assignment = db.session.scalar(db.select(BellEventAudio))
        assert assignment is not None
        assert assignment.track_id == track_id

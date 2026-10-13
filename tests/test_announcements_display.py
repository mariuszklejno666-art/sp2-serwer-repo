from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import Announcement, AuditLog


def _announcement(*, priority: str = "informational", enabled: bool = True) -> Announcement:
    now = datetime.now(timezone.utc)
    return Announcement(
        title="Testowe ogłoszenie",
        body="Treść dla szkolnego ekranu",
        priority=priority,
        audience="all",
        starts_at=now - timedelta(minutes=5),
        ends_at=now + timedelta(hours=1),
        enabled=enabled,
        pinned=False,
        created_by="administrator",
    )


def test_fullscreen_display_requires_login(client):
    response = client.get("/school-services/announcements/display")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_fullscreen_display_shows_active_announcement(app, authenticated_client):
    with app.app_context():
        db.session.add(_announcement())
        db.session.commit()

    response = authenticated_client.get("/school-services/announcements/display")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "CENTRUM INFORMACYJNE" in body
    assert "Testowe ogłoszenie" in body
    assert response.headers["Cache-Control"] == "no-store, private"

    with app.app_context():
        audit = db.session.scalar(
            db.select(AuditLog).where(AuditLog.action == "ANNOUNCEMENT_DISPLAY_OPEN")
        )
        assert audit is not None


def test_alarm_replaces_normal_fullscreen_layout(app, authenticated_client):
    with app.app_context():
        db.session.add(_announcement(priority="alarm"))
        db.session.commit()

    response = authenticated_client.get("/school-services/announcements/display")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "alarm-overlay" in body
    assert ">ALARM<" in body
    assert "Treść dla szkolnego ekranu" in body

from app import create_app
from app.extensions import db
from app.models import AuditLog, User


def _create_user(app, username="admin", password="VeryStrong123!"):
    with app.app_context():
        user = User(username=username, full_name="Administrator SP2", role="administrator")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()


def test_anonymous_user_is_redirected_to_login():
    app = create_app("testing")
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_and_audit():
    app = create_app("testing")
    _create_user(app)
    client = app.test_client()

    response = client.post(
        "/login",
        data={"username": "admin", "password": "VeryStrong123!"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Administrator SP2" in response.data
    with app.app_context():
        audit = db.session.scalar(db.select(AuditLog).where(AuditLog.action == "LOGIN"))
        assert audit is not None
        assert audit.result == "SUCCESS"


def test_failed_login_is_audited():
    app = create_app("testing")
    _create_user(app)
    client = app.test_client()
    response = client.post("/login", data={"username": "admin", "password": "bad"})
    assert response.status_code == 200
    with app.app_context():
        audit = db.session.scalar(db.select(AuditLog).where(AuditLog.result == "FAILURE"))
        assert audit is not None


def test_health_endpoint():
    app = create_app("testing")
    client = app.test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"

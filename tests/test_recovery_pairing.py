from datetime import timedelta
from uuid import uuid4

from app.extensions import db
from app.models import RecoveryPairing, User
from app.models.agent import utcnow
from test_recovery_api import repair_env as recovery_fixture, post

repair_env = recovery_fixture


def pair(client, name="NEW-PC"):
    return post(client, "pair", "", {"hostname": name, "device_id": str(uuid4())})


def login(app, client, role="administrator"):
    with app.app_context():
        user = User(username="operator", full_name="Operator", role=role)
        user.set_password("not-a-domain-password")
        db.session.add(user)
        db.session.commit()
        user_id = user.id
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True


def test_browser_approval_and_single_claim(repair_env):
    app, client, _, _, _ = repair_env
    p = pair(client).json
    claim = "pair/" + p["id"] + "/claim"
    assert post(client, claim, "", {"claim_secret": p["claim_secret"]}).status_code == 409
    anonymous = client.get(p["approval_path"])
    assert anonymous.status_code == 302
    assert "/login" in anonymous.headers["Location"]
    login(app, client)
    app.config["PREVIEW_THEME"] = True
    approval = client.get(p["approval_path"])
    assert approval.status_code == 200
    page = approval.get_data(as_text=True)
    assert "matrix-server-loop.mp4" in page
    assert "sp2-logo.png" in page
    assert 'name="csrf_token"' in page
    assert 'name="confirm"' in page
    assert client.post(p["approval_path"], data={"confirm": "yes"}).status_code == 200
    assert post(client, claim, "", {"claim_secret": "wrong"}).status_code == 401
    token = post(client, claim, "", {"claim_secret": p["claim_secret"]})
    assert token.status_code == 200 and token.json["token"]
    assert token.headers["Cache-Control"] == "no-store"
    assert post(client, claim, "", {"claim_secret": p["claim_secret"]}).status_code == 410


def test_existing_agent_needs_explicit_rotation_approval(repair_env):
    app, client, _, _, _ = repair_env
    p = pair(client, "NAU-010").json
    login(app, client)
    assert client.post(p["approval_path"], data={"confirm": "yes"}).status_code == 400
    assert (
        client.post(
            p["approval_path"], data={"confirm": "yes", "replace_existing": "yes"}
        ).status_code
        == 200
    )


def test_approval_requires_admin_and_csrf(repair_env):
    app, client, _, _, _ = repair_env
    p = pair(client).json
    login(app, client, "teacher")
    assert client.post(p["approval_path"], data={"confirm": "yes"}).status_code == 403
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post(p["approval_path"], data={"confirm": "yes"}).status_code == 400


def test_expired_pairing_and_rate_limit(repair_env):
    app, client, _, _, _ = repair_env
    p = pair(client).json
    with app.app_context():
        db.session.get(RecoveryPairing, p["id"]).expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
    assert (
        post(
            client, "pair/" + p["id"] + "/claim", "", {"claim_secret": p["claim_secret"]}
        ).status_code
        == 410
    )
    for _ in range(9):
        assert pair(client).status_code == 201
    assert pair(client).status_code == 429

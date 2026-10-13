from app.extensions import db
from app.models import AgentComputer


def test_rooms_requires_login(client):
    response = client.get("/rooms")
    assert response.status_code in {302, 401}


def test_rooms_list_for_logged_user(app, authenticated_client):
    with app.app_context():
        db.session.add(AgentComputer(hostname="SALA32-01", room="Sala 32"))
        db.session.commit()
    response = authenticated_client.get("/rooms")
    assert response.status_code == 200
    assert b"Sala 32" in response.data


def test_rooms_infers_room_from_sp2_hostname(app, authenticated_client):
    with app.app_context():
        db.session.add_all([
            AgentComputer(hostname="S32-01", room=None),
            AgentComputer(hostname="S32-02", room=""),
            AgentComputer(hostname="NAU-001", room=None),
        ])
        db.session.commit()

    response = authenticated_client.get("/rooms")
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Sala32" in text
    assert "2 komputerów" in text
    assert "Bez przypisanej sali: 1" in text

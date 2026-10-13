from __future__ import annotations

import pytest

from app import create_app


@pytest.fixture
def app():
    application = create_app("testing")
    application.config.update(TESTING=True)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def authenticated_client(app, client):
    """Klient testowy zalogowany jako administrator."""
    from app.extensions import db
    from app.models import User

    with app.app_context():
        user = User(
            username="test-admin",
            full_name="Administrator testowy",
            role="administrator",
        )
        user.set_password("Test-password-123!")
        db.session.add(user)
        db.session.commit()

    response = client.post(
        "/login",
        data={
            "username": "test-admin",
            "password": "Test-password-123!",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    return client

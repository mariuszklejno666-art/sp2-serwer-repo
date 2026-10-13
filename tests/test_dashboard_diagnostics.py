from app.extensions import db
from app.models import AgentComputer, User


def test_diagnostics_requires_login(client):
    response = client.get("/system/diagnostyka")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_diagnostics_is_available_to_administrator(
    app,
    authenticated_client,
):
    app.config.update(
        LDAP_URI="ldap://127.0.0.1",
        LDAP_BIND_DN="CN=test",
        LDAP_BIND_PASSWORD="test-password",
        LDAP_BASE_DN="DC=sp2,DC=lan",
    )

    response = authenticated_client.get("/system/diagnostyka")

    assert response.status_code == 200
    assert "Diagnostyka SP2 ADMIN" in response.text
    assert "Katalog instance jest zapisywalny" in response.text
    assert "Baza danych działa" in response.text
    assert "Podstawowa konfiguracja LDAP jest ustawiona" in response.text


def test_dashboard_shows_diagnostics_summary(
    authenticated_client,
    monkeypatch,
):
    from app.dashboard import routes
    from app.services.diagnostics import HealthCheck

    def dashboard_checks():
        yield HealthCheck("database", "ok", "Baza działa")
        yield HealthCheck("ldap_config", "warning", "Brak LDAP")

    monkeypatch.setattr(routes, "run_health_checks", dashboard_checks)

    response = authenticated_client.get("/")

    assert response.status_code == 200
    assert "Stan systemu" in response.text
    assert "Kontrole poprawne: 1" in response.text
    assert "Ostrzeżenia: 1" in response.text
    assert 'href="/system/diagnostyka"' in response.text


def test_dashboard_survives_diagnostics_failure(
    authenticated_client,
    monkeypatch,
):
    from app.dashboard import routes
    from app.services.diagnostics import DiagnosticsError

    def failing_dashboard_checks():
        if False:
            yield
        raise DiagnosticsError("Kontrolowany błąd dashboardu")

    monkeypatch.setattr(
        routes,
        "run_health_checks",
        failing_dashboard_checks,
    )

    response = authenticated_client.get("/")

    assert response.status_code == 200
    assert "Stan systemu" in response.text
    assert "Kontrolowany błąd dashboardu" in response.text


def test_dashboard_shows_low_disk_space_alert(app, authenticated_client):
    with app.app_context():
        db.session.add(
            AgentComputer(
                hostname="PC-PELNY-01",
                room="Sala11",
                disks=[
                    {
                        "mount": "C:\\",
                        "percent_used": 96.4,
                        "free_bytes": 2 * 1024**3,
                        "total_bytes": 100 * 1024**3,
                    }
                ],
            )
        )
        db.session.add(
            AgentComputer(
                hostname="PC-OK-01",
                room="Sala11",
                disks=[{"mount": "C:\\", "percent_used": 30.0}],
            )
        )
        db.session.commit()

    response = authenticated_client.get("/")

    assert response.status_code == 200
    assert "Mało miejsca na dysku" in response.text
    assert "PC-PELNY-01" in response.text
    assert "PC-OK-01" not in response.text


def test_dashboard_hides_low_disk_section_when_all_healthy(app, authenticated_client):
    with app.app_context():
        db.session.add(
            AgentComputer(
                hostname="PC-OK-02",
                disks=[{"mount": "C:\\", "percent_used": 10.0}],
            )
        )
        db.session.commit()

    response = authenticated_client.get("/")

    assert response.status_code == 200
    # Kafelek statystyk zawsze pokazuje etykietę (z wartością 0); tabela ze
    # szczegółami renderuje się tylko, gdy jest co wypisać.
    assert "Wolne / Razem" not in response.text


def test_diagnostics_rejects_non_administrator(app, client):
    with app.app_context():
        user = User(
            username="diagnostics-viewer",
            full_name="Użytkownik testowy",
            role="viewer",
        )
        user.set_password("Test-password-123!")
        db.session.add(user)
        db.session.commit()

    client.post(
        "/login",
        data={
            "username": "diagnostics-viewer",
            "password": "Test-password-123!",
        },
    )

    response = client.get("/system/diagnostyka")

    assert response.status_code == 403


def test_diagnostics_shows_shared_check_failure(
    authenticated_client,
    monkeypatch,
):
    from app.dashboard import routes
    from app.services.diagnostics import DiagnosticsError, HealthCheck

    def failing_checks():
        yield HealthCheck("application", "info", "Aplikacja testowa")
        raise DiagnosticsError("Kontrolowany błąd testowy")

    monkeypatch.setattr(routes, "run_health_checks", failing_checks)

    response = authenticated_client.get("/system/diagnostyka")

    assert response.status_code == 200

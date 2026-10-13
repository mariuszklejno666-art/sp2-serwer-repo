from __future__ import annotations

from app.directory.service import DirectoryError, DirectoryService
from app.directory.preview_data import seed_agents
from app.extensions import db
from app.models import AgentComputer


def test_demo_directory_never_opens_ldap(app, authenticated_client):
    app.config.update(
        STAGING_READ_ONLY=True,
        PREVIEW_DEMO_DATA=True,
        AD_JOIN_ALLOWED_OU_BASES=("OU=Komputery,DC=sp2,DC=test",),
        AD_TEACHER_USER_OU="OU=Nauczyciele,OU=Uzytkownicy,DC=sp2,DC=test",
        AD_TEACHER_COMPUTER_OU="OU=Nauczyciele,OU=Komputery,DC=sp2,DC=test",
    )

    with app.app_context():
        service = DirectoryService()
        assert service.stats().users == 3
        assert service.stats().computers == 3
        assert len(service.users("testowa")) == 1
        assert service.user("anna.testowa")["displayName"].endswith("(demo)")
        assert service.computer("DEMO-S11-01")["dNSHostName"].endswith(".test")
        assert service.organizational_units("Sala11")[0]["counts"]["computers"] == 2
        assert service.test_connection()["status"] == "demo"
        try:
            service._connection()
        except DirectoryError as exc:
            assert "nie łączy się z LDAP" in str(exc)
        else:
            raise AssertionError("Demo must never connect to LDAP")

    for path in (
        "/",
        "/directory/users",
        "/directory/users/anna.testowa",
        "/directory/groups",
        "/directory/ous",
        "/directory/computers",
        "/directory/computers/DEMO-S11-01",
        "/directory/domain-enrollment",
    ):
        response = authenticated_client.get(path)
        assert response.status_code == 200, path
        assert "DANE DEMONSTRACYJNE" in response.get_data(as_text=True)

    dashboard = authenticated_client.get("/").get_data(as_text=True)
    assert "LDAP niedostępny" not in dashboard
    assert "Dane demonstracyjne" in dashboard
    assert "Symulacja:" in authenticated_client.get(
        "/directory/domain-enrollment"
    ).get_data(as_text=True)


def test_agents_seed_is_idempotent_in_separate_test_database(app):
    with app.app_context():
        assert seed_agents() == 3
        assert seed_agents() == 0
        agents = db.session.scalars(db.select(AgentComputer)).all()
        assert {agent.room for agent in agents} == {"Sala11", "Sala32"}
        assert all(agent.hostname.startswith("DEMO-") for agent in agents)
        assert all(agent.fqdn.endswith(".test") for agent in agents)


def test_seed_command_refuses_any_other_database(app):
    app.config.update(STAGING_READ_ONLY=True, PREVIEW_DEMO_DATA=True)
    result = app.test_cli_runner().invoke(args=["seed-preview-demo"])
    assert result.exit_code != 0
    assert "oddzielnej bazy podglądu" in result.output

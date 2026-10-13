from __future__ import annotations


def test_api_requires_token(app, client):
    app.config["SP2_API_TOKEN"] = "secret-token"
    response = client.get("/api/v1/health")
    assert response.status_code == 401


def test_api_health_with_token(app, client):
    app.config["SP2_API_TOKEN"] = "secret-token"
    response = client.get(
        "/api/v1/health",
        headers={"Authorization": "Bearer secret-token"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["api_version"] == "v1"


def test_api_rejects_wrong_token(app, client):
    app.config["SP2_API_TOKEN"] = "secret-token"
    response = client.get(
        "/api/v1/health",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401

def test_api_accepts_previous_token_during_rollover(app, client):
    app.config["SP2_API_TOKEN"] = "new-token"
    app.config["SP2_API_TOKEN_PREVIOUS"] = "old-token"

    response = client.get(
        "/api/v1/health",
        headers={"Authorization": "Bearer old-token"},
    )

    assert response.status_code == 200


def test_api_rejects_previous_token_after_rollover(app, client):
    app.config["SP2_API_TOKEN"] = "new-token"
    app.config["SP2_API_TOKEN_PREVIOUS"] = ""

    response = client.get(
        "/api/v1/health",
        headers={"Authorization": "Bearer old-token"},
    )

    assert response.status_code == 401


def test_domain_join_options_require_configuration(app, client):
    app.config.update(
        AD_DOMAIN_FQDN="",
        AD_DOMAIN_NETBIOS="",
        AD_DNS_SERVERS=(),
        AD_JOIN_ALLOWED_OU_BASES=(),
    )

    response = client.get(
        "/api/v1/domain/join-options",
        headers={"Authorization": "Bearer test-token"},
    )

    assert response.status_code == 503
    assert response.get_json()["error"] == "Kreator domeny nie jest skonfigurowany."


def test_domain_join_options_return_only_allowed_ous(app, client, monkeypatch):
    app.config.update(
        LDAP_BASE_DN="DC=sp2,DC=lan",
        AD_DOMAIN_FQDN="sp2.lan",
        AD_DOMAIN_NETBIOS="SP2",
        AD_DNS_SERVERS=("192.168.0.143",),
        AD_JOIN_ALLOWED_OU_BASES=("OU=Komputery,DC=sp2,DC=lan",),
    )
    monkeypatch.setattr(
        "app.api.routes.DirectoryService.organizational_units",
        lambda self: [
            {
                "ou": ["Sala 1"],
                "distinguishedName": [
                    "OU=Sala 1,OU=Komputery,DC=sp2,DC=lan"
                ],
            },
            {
                "ou": ["Uczniowie"],
                "distinguishedName": ["OU=Uczniowie,DC=sp2,DC=lan"],
            },
        ],
    )

    response = client.get(
        "/api/v1/domain/join-options",
        headers={"Authorization": "Bearer test-token"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["read_only"] is True
    assert payload["operations"] == {"join": False, "unjoin": False}
    assert payload["domain"] == {
        "fqdn": "sp2.lan",
        "netbios": "SP2",
        "dns_servers": ["192.168.0.143"],
    }
    assert payload["naming"]["max_length"] == 15
    assert payload["naming"]["teacher_pattern"] == "NAU-{NUMER:03d}"
    assert [item["name"] for item in payload["organizational_units"]] == [
        "Sala 1"
    ]


def test_domain_name_preview_returns_room_name_and_detects_conflict(
    app,
    client,
    monkeypatch,
):
    room_dn = "OU=Sala11,OU=Komputery,DC=sp2,DC=lan"
    app.config.update(
        LDAP_BASE_DN="DC=sp2,DC=lan",
        AD_JOIN_ALLOWED_OU_BASES=("OU=Komputery,DC=sp2,DC=lan",),
    )
    monkeypatch.setattr(
        "app.api.routes.DirectoryService.organizational_units",
        lambda self: [
            {
                "ou": ["Sala11"],
                "distinguishedName": [room_dn],
            }
        ],
    )
    monkeypatch.setattr(
        "app.api.routes.DirectoryService.computers",
        lambda self, limit=500: [{"sAMAccountName": ["S11-01$"]}],
    )

    response = client.post(
        "/api/v1/domain/name-preview",
        headers={"Authorization": "Bearer test-token"},
        json={
            "mode": "room",
            "organizational_unit": room_dn,
            "number": 1,
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["computer_name"] == "S11-01"
    assert payload["available"] is False
    assert payload["read_only"] is True
    assert payload["operations"] == {"join": False, "unjoin": False}


def test_domain_name_preview_adds_teacher_conflict_suffix(
    app,
    client,
    monkeypatch,
):
    teacher_ou = "OU=Nauczyciele,OU=Komputery,DC=sp2,DC=lan"
    app.config.update(
        LDAP_BASE_DN="DC=sp2,DC=lan",
        AD_JOIN_ALLOWED_OU_BASES=("OU=Komputery,DC=sp2,DC=lan",),
    )
    monkeypatch.setattr(
        "app.api.routes.DirectoryService.organizational_units",
        lambda self: [
            {
                "ou": ["Nauczyciele"],
                "distinguishedName": [teacher_ou],
            }
        ],
    )
    monkeypatch.setattr(
        "app.api.routes.DirectoryService.computers",
        lambda self, limit=500: [{"sAMAccountName": ["NAU-001$"]}],
    )

    response = client.post(
        "/api/v1/domain/name-preview",
        headers={"Authorization": "Bearer test-token"},
        json={
            "mode": "teacher",
            "organizational_unit": teacher_ou,
            "given_name": "Joanna",
            "surname": "Zalewska",
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["computer_name"] == "NAU-002"
    assert payload["available"] is True


def test_domain_name_preview_rejects_ou_outside_allowed_root(app, client):
    app.config.update(
        LDAP_BASE_DN="DC=sp2,DC=lan",
        AD_JOIN_ALLOWED_OU_BASES=("OU=Komputery,DC=sp2,DC=lan",),
    )

    response = client.post(
        "/api/v1/domain/name-preview",
        headers={"Authorization": "Bearer test-token"},
        json={
            "mode": "room",
            "organizational_unit": "OU=Nauczyciele,OU=Uzytkownicy,DC=sp2,DC=lan",
            "number": 1,
        },
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Wybrana jednostka OU nie jest dozwolona."

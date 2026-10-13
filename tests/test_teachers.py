from __future__ import annotations


def test_teachers_page_lists_only_accounts_from_teacher_ou(
    app,
    authenticated_client,
    monkeypatch,
):
    teacher_dn = "OU=Nauczyciele,OU=Uzytkownicy,DC=sp2,DC=lan"
    app.config["AD_TEACHER_USER_OU"] = teacher_dn
    monkeypatch.setattr(
        "app.teachers.routes.DirectoryService.users",
        lambda self, query="", limit=500: [
            {
                "sAMAccountName": ["jan.kowalski"],
                "displayName": ["Jan Kowalski"],
                "mail": ["jan.kowalski@sp2.lan"],
                "userAccountControl": ["512"],
                "distinguishedName": [
                    f"CN=Jan Kowalski,{teacher_dn}"
                ],
            },
            {
                "sAMAccountName": ["uczen.test"],
                "displayName": ["Uczeń Testowy"],
                "userAccountControl": ["512"],
                "distinguishedName": [
                    "CN=Uczeń Testowy,OU=Uczniowie,DC=sp2,DC=lan"
                ],
            },
        ],
    )

    response = authenticated_client.get("/teachers")

    assert response.status_code == 200
    assert b"jan.kowalski" in response.data
    assert "Jan Kowalski".encode() in response.data
    assert b"uczen.test" not in response.data


def test_teachers_page_requires_login(client):
    response = client.get("/teachers")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

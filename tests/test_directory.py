from app.directory.service import _escape_filter, account_enabled, first_value


def test_escape_filter_blocks_wildcard_injection():
    assert _escape_filter("jan*(test)") == r"jan\2a\28test\29"


def _stub_directory_choices(monkeypatch):
    monkeypatch.setattr(
        "app.directory.routes.DirectoryService.organizational_units",
        lambda self, limit=500: [
            {"ou": ["Uczniowie"], "distinguishedName": ["OU=Uczniowie,DC=sp2,DC=lan"]}
        ],
    )
    monkeypatch.setattr(
        "app.directory.routes.DirectoryService.groups",
        lambda self, limit=500: [
            {"sAMAccountName": ["Klasa1A"], "distinguishedName": ["CN=Klasa1A,DC=sp2,DC=lan"]}
        ],
    )


def test_new_user_route_requires_login(client):
    response = client.get("/directory/users/new")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_new_user_route_requires_administrator(app, client):
    from app.extensions import db
    from app.models import User

    with app.app_context():
        user = User(username="viewer-new", full_name="Viewer", role="viewer")
        user.set_password("very-secure-password")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "viewer-new", "password": "very-secure-password"})
    response = client.get("/directory/users/new")
    assert response.status_code == 403


def test_new_user_route_renders_form(app, authenticated_client, monkeypatch):
    app.config.update(
        LDAP_WRITE_BIND_DN="CN=svc-write,DC=sp2,DC=lan",
        LDAP_WRITE_BIND_PASSWORD="write-secret",
    )
    _stub_directory_choices(monkeypatch)
    response = authenticated_client.get("/directory/users/new")
    assert response.status_code == 200
    assert "Nowy użytkownik".encode() in response.data


def test_create_user_requires_administrator(client):
    response = client.post("/directory/users/new", data={})
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_create_user_rejects_short_password(app, authenticated_client, monkeypatch):
    _stub_directory_choices(monkeypatch)

    def _unexpected_call(self, **kwargs):
        raise AssertionError("create_user nie powinien zostać wywołany dla za krótkiego hasła")

    monkeypatch.setattr("app.directory.routes.DirectoryService.create_user", _unexpected_call)

    response = authenticated_client.post(
        "/directory/users/new",
        data={
            "username": "jkowalski",
            "given_name": "Jan",
            "surname": "Kowalski",
            "password": "abc12",
            "confirm_password": "abc12",
            "organizational_unit": "OU=Uczniowie,DC=sp2,DC=lan",
        },
    )
    assert response.status_code == 400


def test_create_user_route_creates_account_and_redirects(app, authenticated_client, monkeypatch):
    _stub_directory_choices(monkeypatch)
    calls = []

    def _fake_create_user(self, **kwargs):
        calls.append(kwargs)
        return "CN=Jan Kowalski,OU=Uczniowie,DC=sp2,DC=lan"

    monkeypatch.setattr("app.directory.routes.DirectoryService.create_user", _fake_create_user)

    response = authenticated_client.post(
        "/directory/users/new",
        data={
            "username": "jkowalski",
            "given_name": "Jan",
            "surname": "Kowalski",
            "password": "haslo1",
            "confirm_password": "haslo1",
            "organizational_unit": "OU=Uczniowie,DC=sp2,DC=lan",
            "groups": ["CN=Klasa1A,DC=sp2,DC=lan"],
        },
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/directory/users/jkowalski")
    assert len(calls) == 1
    assert calls[0]["username"] == "jkowalski"
    assert calls[0]["group_dns"] == ["CN=Klasa1A,DC=sp2,DC=lan"]


def test_rename_user_requires_administrator(client):
    response = client.post("/directory/users/jkowalski/rename", data={"new_username": "jnowak"})
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_rename_user_route_renames_and_redirects(app, authenticated_client, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.directory.routes.DirectoryService.rename_user",
        lambda self, username, new_username: calls.append((username, new_username)) or "CN=X,DC=sp2,DC=lan",
    )
    response = authenticated_client.post(
        "/directory/users/jkowalski/rename", data={"new_username": "jnowak"}
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/directory/users/jnowak")
    assert calls == [("jkowalski", "jnowak")]


def test_delete_user_requires_administrator(client):
    response = client.post(
        "/directory/users/jkowalski/delete", data={"confirm_username": "jkowalski"}
    )
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_delete_user_requires_matching_confirmation(app, authenticated_client, monkeypatch):
    def _unexpected_call(self, username):
        raise AssertionError("delete_user nie powinien zostać wywołany bez poprawnego potwierdzenia")

    monkeypatch.setattr("app.directory.routes.DirectoryService.delete_user", _unexpected_call)

    response = authenticated_client.post(
        "/directory/users/jkowalski/delete", data={"confirm_username": "not-jkowalski"}
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/directory/users/jkowalski")


def test_delete_user_route_deletes_and_redirects(app, authenticated_client, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.directory.routes.DirectoryService.delete_user",
        lambda self, username: calls.append(username) or "CN=X,DC=sp2,DC=lan",
    )
    response = authenticated_client.post(
        "/directory/users/jkowalski/delete", data={"confirm_username": "jkowalski"}
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/directory/users")
    assert calls == ["jkowalski"]


def test_user_details_renders_rename_and_delete_forms(app, authenticated_client, monkeypatch):
    app.config.update(
        LDAP_WRITE_BIND_DN="CN=svc-write,DC=sp2,DC=lan",
        LDAP_WRITE_BIND_PASSWORD="write-secret",
    )
    monkeypatch.setattr(
        "app.directory.routes.DirectoryService.user",
        lambda self, username: {
            "sAMAccountName": ["jkowalski"],
            "displayName": ["Jan Kowalski"],
            "distinguishedName": ["CN=Jan Kowalski,OU=Uczniowie,DC=sp2,DC=lan"],
        },
    )
    _stub_directory_choices(monkeypatch)
    response = authenticated_client.get("/directory/users/jkowalski")
    assert response.status_code == 200
    assert "Zmiana nazwy i usunięcie konta".encode() in response.data
    assert b"Usu\xc5\x84 u\xc5\xbcytkownika" in response.data


def test_add_user_to_groups_is_idempotent(app, monkeypatch):
    from app.directory.service import DirectoryService

    class _FakeConnection:
        def __init__(self, existing_members):
            self.existing_members = existing_members
            self.result = {}
            self.calls = []

        def modify(self, dn, changes):
            self.calls.append((dn, changes))
            user_dn = changes["member"][0][1][0]
            members = self.existing_members.setdefault(dn, set())
            if user_dn in members:
                self.result = {"description": "attributeOrValueExists"}
                return False
            members.add(user_dn)
            self.result = {"description": "success"}
            return True

        def unbind(self):
            pass

    with app.app_context():
        service = DirectoryService.__new__(DirectoryService)
        service.base_dn = "DC=sp2,DC=lan"
        user_dn = "CN=Jan Kowalski,OU=Uczniowie,DC=sp2,DC=lan"
        monkeypatch.setattr(service, "_user_dn", lambda username: user_dn)
        fake = _FakeConnection({"CN=Klasa1A,DC=sp2,DC=lan": {user_dn}})
        monkeypatch.setattr(service, "_connection", lambda write=False: fake)

        result = service.add_user_to_groups(
            "jkowalski",
            [
                "CN=Klasa1A,DC=sp2,DC=lan",
                "CN=Klasa1A,DC=sp2,DC=lan",
                "CN=Basen,DC=sp2,DC=lan",
            ],
        )

        assert result == [
            "CN=Klasa1A,DC=sp2,DC=lan",
            "CN=Klasa1A,DC=sp2,DC=lan",
            "CN=Basen,DC=sp2,DC=lan",
        ]
        assert len(fake.calls) == 3


def test_add_user_to_group_is_idempotent_on_samba_entry_already_exists(app, monkeypatch):
    # Samba AD zwraca "entryAlreadyExists" (kod 68) zamiast standardowego dla
    # LDAP "attributeOrValueExists" (kod 20), gdy użytkownik jest już
    # członkiem grupy — wykryte na produkcyjnym serwerze Samba.
    from app.directory.service import DirectoryService

    class _FakeConnection:
        def __init__(self):
            self.result = {"description": "entryAlreadyExists"}

        def modify(self, dn, changes):
            return False

        def unbind(self):
            pass

    with app.app_context():
        service = DirectoryService.__new__(DirectoryService)
        service.base_dn = "DC=sp2,DC=lan"
        user_dn = "CN=Anna Nowak,OU=Nauczyciele,DC=sp2,DC=lan"
        monkeypatch.setattr(service, "_user_dn", lambda username: user_dn)
        monkeypatch.setattr(service, "_connection", lambda write=False: _FakeConnection())

        result = service.add_user_to_group("anna.nowak", "CN=Nauczyciele,DC=sp2,DC=lan")

        assert result == "CN=Nauczyciele,DC=sp2,DC=lan"


def test_helpers_normalize_ldap_values():
    item = {"sAMAccountName": ["jkowalski"], "userAccountControl": ["514"]}
    assert first_value(item, "sAMAccountName") == "jkowalski"
    assert account_enabled(item) is False


def test_directory_routes_require_login():
    from app import create_app

    client = create_app("testing").test_client()
    response = client.get("/directory/users")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_reset_password_requires_login():
    from app import create_app

    client = create_app("testing").test_client()
    response = client.post("/directory/users/test/reset-password")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_reset_password_requires_administrator():
    from app import create_app
    from app.extensions import db
    from app.models import User

    app = create_app("testing")
    with app.app_context():
        user = User(username="viewer", full_name="Viewer", role="viewer")
        user.set_password("very-secure-password")
        db.session.add(user)
        db.session.commit()

    client = app.test_client()
    client.post("/login", data={"username": "viewer", "password": "very-secure-password"})
    response = client.post(
        "/directory/users/test/reset-password",
        data={
            "new_password": "Another-secure-Password1!",
            "confirm_password": "Another-secure-Password1!",
        },
    )
    assert response.status_code == 403


def test_account_action_requires_login():
    from app import create_app

    client = create_app("testing").test_client()
    response = client.post("/directory/users/test/account/unlock")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_account_action_rejects_unknown_action_for_admin():
    from app import create_app
    from app.extensions import db
    from app.models import User

    app = create_app("testing")
    with app.app_context():
        user = User(username="admin2", full_name="Admin 2", role="administrator")
        user.set_password("very-secure-password")
        db.session.add(user)
        db.session.commit()

    client = app.test_client()
    client.post("/login", data={"username": "admin2", "password": "very-secure-password"})
    response = client.post("/directory/users/test/account/not-valid", data={})
    assert response.status_code in {302, 400, 404}


def test_computer_helpers():
    from app.directory.service import computer_name, dn_organizational_path

    assert computer_name({"sAMAccountName": ["PC-01$"]}) == "PC-01"
    assert dn_organizational_path("CN=PC-01,OU=Sala 12,OU=Komputery,DC=sp2,DC=local") == "Komputery / Sala 12"
    assert dn_organizational_path("CN=PC-01,CN=Computers,DC=sp2,DC=local") == "Kontener domyślny"


def test_computer_detail_route(monkeypatch):
    from app import create_app
    from app.extensions import db
    from app.models import User

    app = create_app("testing")
    with app.app_context():
        user = User(username="adminpc", full_name="Administrator", role="administrator")
        user.set_password("secret123")
        db.session.add(user)
        db.session.commit()

    monkeypatch.setattr(
        "app.directory.routes.DirectoryService.computer",
        lambda self, computer: {
            "sAMAccountName": ["PC-01$"],
            "dNSHostName": ["pc-01.sp2.local"],
            "operatingSystem": ["Windows 11 Pro"],
            "memberOf": ["CN=Pracownia 1,DC=sp2,DC=local"],
            "dn": "CN=PC-01,OU=Pracownia 1,DC=sp2,DC=local",
        },
    )
    client = app.test_client()
    client.post("/login", data={"username": "adminpc", "password": "secret123"})
    response = client.get("/directory/computers/PC-01")
    assert response.status_code == 200
    assert b"PC-01" in response.data
    assert b"Windows 11 Pro" in response.data
    assert b"Pracownia 1" in response.data


def test_ou_path_helper():
    from app.directory.service import ou_path

    assert ou_path("OU=Klasa 1A,OU=Uczniowie,DC=sp2,DC=local") == "Uczniowie / Klasa 1A"
    assert ou_path("DC=sp2,DC=local") == "—"


def test_organizational_units_route(monkeypatch):
    from app import create_app
    from app.extensions import db
    from app.models import User

    app = create_app("testing")
    with app.app_context():
        user = User(username="adminou", full_name="Administrator OU", role="administrator")
        user.set_password("secret123")
        db.session.add(user)
        db.session.commit()

    monkeypatch.setattr(
        "app.directory.routes.DirectoryService.organizational_units",
        lambda self, query="": [
            {
                "ou": ["Klasa 1A"],
                "description": ["Uczniowie klasy 1A"],
                "distinguishedName": ["OU=Klasa 1A,OU=Uczniowie,DC=sp2,DC=local"],
                "counts": {"users": 24, "computers": 0, "ous": 0},
            }
        ],
    )
    client = app.test_client()
    client.post("/login", data={"username": "adminou", "password": "secret123"})
    response = client.get("/directory/ous")
    assert response.status_code == 200
    assert b"Klasa 1A" in response.data
    assert b"24" in response.data


def test_group_action_requires_administrator():
    from app import create_app
    from app.extensions import db
    from app.models import User

    app = create_app("testing")
    with app.app_context():
        user = User(username="viewer-groups", full_name="Viewer", role="viewer")
        user.set_password("very-secure-password")
        db.session.add(user)
        db.session.commit()
    client = app.test_client()
    client.post("/login", data={"username": "viewer-groups", "password": "very-secure-password"})
    response = client.post("/directory/users/test/groups/remove", data={"group_dn": "CN=X,DC=sp2,DC=lan"})
    assert response.status_code == 403


def test_bulk_action_requires_selected_users():
    from app import create_app
    from app.extensions import db
    from app.models import User

    app = create_app("testing")
    with app.app_context():
        user = User(username="admin-bulk", full_name="Admin", role="administrator")
        user.set_password("very-secure-password")
        db.session.add(user)
        db.session.commit()
    client = app.test_client()
    client.post("/login", data={"username": "admin-bulk", "password": "very-secure-password"})
    response = client.post("/directory/users/bulk-action", data={"action": "unlock"})
    assert response.status_code == 302


def test_domain_enrollment_page_previews_room_name(
    app,
    authenticated_client,
    monkeypatch,
):
    room_dn = "OU=Sala11,OU=Komputery,DC=sp2,DC=lan"
    app.config.update(
        AD_JOIN_ALLOWED_OU_BASES=("OU=Komputery,DC=sp2,DC=lan",),
        AD_TEACHER_USER_OU=(
            "OU=Nauczyciele,OU=Uzytkownicy,DC=sp2,DC=lan"
        ),
    )
    monkeypatch.setattr(
        "app.directory.routes.DirectoryService.organizational_units",
        lambda self, limit=500: [
            {
                "ou": ["Sala11"],
                "distinguishedName": [room_dn],
            }
        ],
    )
    monkeypatch.setattr(
        "app.directory.routes.DirectoryService.computers",
        lambda self, limit=500: [],
    )
    monkeypatch.setattr(
        "app.directory.routes.DirectoryService.users",
        lambda self, limit=500: [],
    )

    response = authenticated_client.get(
        "/directory/domain-enrollment",
        query_string={
            "mode": "room",
            "organizational_unit": room_dn,
            "number": "1",
        },
    )

    assert response.status_code == 200
    assert b"S11-01" in response.data
    assert "Nazwa jest wolna".encode() in response.data
    assert "Kreator 2.0".encode() in response.data
    assert b"START-MIGRACJA.cmd" in response.data
    assert "Wolne numery w wybranej sali".encode() in response.data

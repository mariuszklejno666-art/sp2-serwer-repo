from __future__ import annotations

import io

from app.agents.software_catalog import (
    CatalogError,
    add_package,
    delete_package,
    agent_supports_multifile,
    get_installable_package,
    load_catalog,
    save_installer_upload,
    save_package_uploads,
    toggle_package,
)
from app.extensions import db
from app.models import AuditLog, User


def _login_admin(app, client, username="pkg-admin"):
    with app.app_context():
        user = User(username=username, full_name="Administrator", role="administrator")
        user.set_password("Test-password-123!")
        db.session.add(user)
        db.session.commit()
    response = client.post(
        "/login", data={"username": username, "password": "Test-password-123!"}
    )
    assert response.status_code == 302


class _FakeUpload:
    def __init__(self, filename: str, content: bytes):
        self.filename = filename
        self.stream = io.BytesIO(content)


def test_save_installer_upload_accepts_valid_exe(app, tmp_path):
    app.instance_path = str(tmp_path)
    with app.app_context():
        content = b"MZ" + b"\x00" * 100
        stored_filename, installer_type, size, sha256 = save_installer_upload(
            _FakeUpload("setup.exe", content)
        )
        assert installer_type == "exe"
        assert size == len(content)
        assert len(sha256) == 64
        assert (tmp_path / "software-packages" / stored_filename).is_file()


def test_save_installer_upload_rejects_bad_signature(app, tmp_path):
    app.instance_path = str(tmp_path)
    with app.app_context():
        try:
            save_installer_upload(_FakeUpload("setup.exe", b"not-a-real-exe"))
            assert False, "expected CatalogError"
        except CatalogError:
            pass
        assert list((tmp_path / "software-packages").glob("*")) == []


def test_save_installer_upload_rejects_disallowed_extension(app, tmp_path):
    app.instance_path = str(tmp_path)
    with app.app_context():
        try:
            save_installer_upload(_FakeUpload("setup.zip", b"PK\x03\x04"))
            assert False, "expected CatalogError"
        except CatalogError:
            pass


def test_save_installer_upload_enforces_size_limit(app, tmp_path):
    app.instance_path = str(tmp_path)
    with app.app_context():
        content = b"MZ" + b"\x00" * 1000
        try:
            save_installer_upload(_FakeUpload("setup.exe", content), max_bytes=10)
            assert False, "expected CatalogError"
        except CatalogError:
            pass


def test_add_toggle_delete_package_roundtrip(app, tmp_path):
    app.instance_path = str(tmp_path)
    with app.app_context():
        add_package(
            package_id="firefox-esr",
            name="Firefox ESR",
            version="128.1.0",
            description="Przeglądarka",
            filename="firefox.exe",
            installer_type="exe",
            arguments=["/S"],
            sha256="a" * 64,
        )
        assert "firefox-esr" in load_catalog()

        try:
            add_package(
                package_id="firefox-esr",
                name="dup",
                version="",
                description="",
                filename="x.exe",
                installer_type="exe",
                arguments=[],
                sha256="b" * 64,
            )
            assert False, "expected CatalogError for duplicate id"
        except CatalogError:
            pass

        package = toggle_package("firefox-esr")
        assert package["enabled"] is False
        assert load_catalog()["firefox-esr"]["enabled"] is False

        removed = delete_package("firefox-esr")
        assert removed["id"] == "firefox-esr"
        assert "firefox-esr" not in load_catalog()

        try:
            toggle_package("firefox-esr")
            assert False, "expected CatalogError for missing package"
        except CatalogError:
            pass


def test_upload_route_requires_administrator(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    with app.app_context():
        user = User(username="viewer-pkg", full_name="Viewer", role="viewer")
        user.set_password("Test-password-123!")
        db.session.add(user)
        db.session.commit()
    client.post(
        "/login", data={"username": "viewer-pkg", "password": "Test-password-123!"}
    )

    response = client.get("/agents/software")
    assert response.status_code == 403


def test_upload_route_creates_package_and_audits(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client)

    data = {
        "package_id": "firefox-esr",
        "name": "Firefox ESR",
        "version": "128.1.0",
        "description": "Przeglądarka",
        "arguments": "/S\n/norestart",
        "installer_file": (io.BytesIO(b"MZ" + b"\x00" * 50), "firefox.exe"),
    }
    response = client.post(
        "/agents/software", data=data, content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Firefox ESR" in response.get_data(as_text=True)
    with app.app_context():
        assert "firefox-esr" in load_catalog()
        audit = db.session.scalar(
            db.select(AuditLog).where(AuditLog.action == "SOFTWARE_PACKAGE_UPLOAD")
        )
        assert audit is not None


def test_upload_route_rejects_duplicate_id(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client)
    with app.app_context():
        add_package(
            package_id="firefox-esr", name="Firefox", version="", description="",
            filename="existing.exe", installer_type="exe", arguments=[], sha256="a" * 64,
        )

    data = {
        "package_id": "firefox-esr",
        "name": "Duplikat",
        "version": "",
        "description": "",
        "arguments": "",
        "installer_file": (io.BytesIO(b"MZ" + b"\x00" * 50), "setup.exe"),
    }
    response = client.post(
        "/agents/software", data=data, content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "już istnieje" in response.get_data(as_text=True)


def test_toggle_and_delete_routes(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client)
    with app.app_context():
        add_package(
            package_id="firefox-esr", name="Firefox", version="", description="",
            filename="firefox.exe", installer_type="exe", arguments=[], sha256="a" * 64,
        )
        (tmp_path / "software-packages").mkdir(parents=True, exist_ok=True)
        (tmp_path / "software-packages" / "firefox.exe").write_bytes(b"MZ")

    toggle_response = client.post(
        "/agents/software/firefox-esr/toggle", follow_redirects=True
    )
    assert toggle_response.status_code == 200
    with app.app_context():
        assert load_catalog()["firefox-esr"]["enabled"] is False

    delete_response = client.post(
        "/agents/software/firefox-esr/delete", follow_redirects=True
    )
    assert delete_response.status_code == 200
    with app.app_context():
        assert "firefox-esr" not in load_catalog()
    assert not (tmp_path / "software-packages" / "firefox.exe").exists()



def test_save_package_uploads_keeps_companion_files_together(app, tmp_path):
    app.instance_path = str(tmp_path)
    with app.app_context():
        (
            storage_dir,
            installer_filename,
            installer_type,
            total_size,
            installer_sha,
            files,
        ) = save_package_uploads(
            "infkl1",
            _FakeUpload("setup.exe", b"MZ" + b"\x00" * 20),
            [
                _FakeUpload("data1.bin", b"BIN-DATA-1"),
                _FakeUpload("data2.cab", b"CAB-DATA-2"),
            ],
        )
        add_package(
            package_id="infkl1",
            name="INF KL 1",
            version="1.0",
            description="Pakiet wieloplikowy",
            filename=installer_filename,
            installer_type=installer_type,
            arguments=["/S"],
            sha256=installer_sha,
            storage_dir=storage_dir,
            files=files,
        )

        package = get_installable_package("infkl1")
        assert package["is_multifile"] is True
        assert package["file_count"] == 3
        assert package["size"] == total_size
        assert {item["filename"] for item in package["files"]} == {
            "setup.exe",
            "data1.bin",
            "data2.cab",
        }
        package_dir = tmp_path / "software-packages" / storage_dir
        assert (package_dir / "setup.exe").is_file()
        assert (package_dir / "data1.bin").is_file()
        assert (package_dir / "data2.cab").is_file()


def test_upload_route_accepts_installer_with_companion_files(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client, username="pkg-multi-admin")

    response = client.post(
        "/agents/software",
        data={
            "package_id": "infkl2",
            "name": "INF KL 2",
            "version": "2.0",
            "description": "Pełny pakiet",
            "arguments": "/S",
            "installer_file": (io.BytesIO(b"MZ" + b"\x00" * 50), "setup.exe"),
            "support_files": [
                (io.BytesIO(b"payload-1"), "install-1.bin"),
                (io.BytesIO(b"payload-2"), "install-2.bin"),
            ],
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "INF KL 2" in body
    assert "Kompletny pakiet" in body
    assert "3 plik" in body
    with app.app_context():
        package = load_catalog()["infkl2"]
        assert len(package["files"]) == 3
        assert package["storage_dir"]


def test_multifile_agent_version_gate():
    assert agent_supports_multifile("2.8.0") is True
    assert agent_supports_multifile("2.8.1") is True
    assert agent_supports_multifile("3.0.0") is True
    assert agent_supports_multifile("2.7.9") is False
    assert agent_supports_multifile(None) is False

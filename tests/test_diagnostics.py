from __future__ import annotations


def test_doctor_preserves_success_output(app):
    app.config.update(
        LDAP_URI="ldap://127.0.0.1",
        LDAP_BIND_DN="CN=reader,DC=sp2,DC=lan",
        LDAP_BIND_PASSWORD="test-password",
        LDAP_BASE_DN="DC=sp2,DC=lan",
    )

    result = app.test_cli_runner().invoke(args=["doctor"])

    assert result.exit_code == 0
    assert result.output.splitlines() == [
        f"Aplikacja: {app.config['APP_NAME']} {app.config['APP_VERSION']}",
        f"Instance: {app.instance_path}",
        f"Baza: {app.config['SQLALCHEMY_DATABASE_URI']}",
        "[OK] Katalog instance jest zapisywalny.",
        "[OK] Baza danych działa.",
        "[OK] Podstawowa konfiguracja LDAP jest ustawiona.",
    ]


def test_doctor_preserves_missing_ldap_warning(app):
    app.config.update(
        LDAP_URI="",
        LDAP_BIND_DN="",
        LDAP_BIND_PASSWORD="",
        LDAP_BASE_DN="",
    )

    result = app.test_cli_runner().invoke(args=["doctor"])

    assert result.exit_code == 0
    assert (
        "[UWAGA] Brak ustawień LDAP: "
        "LDAP_URI, LDAP_BIND_DN, LDAP_BIND_PASSWORD, LDAP_BASE_DN"
    ) in result.output

from __future__ import annotations

from ops.sp2_audit_report import (
    parse_properties,
    parse_pytest_counts,
    render_runtime_report,
    render_tests_report,
    safe_health_payload,
    summarize_journal,
)


def test_parse_properties_allows_only_safe_systemd_fields():
    result = parse_properties(
        "ActiveState=active\n"
        "SubState=running\n"
        "MainPID=123\n"
        "Environment=SECRET_KEY=do-not-export"
    )

    assert result == {
        "ActiveState": "active",
        "SubState": "running",
        "MainPID": "123",
    }


def test_safe_health_payload_drops_unknown_fields_and_control_characters():
    assert safe_health_payload(
        {
            "status": "ok",
            "version": "7.1.0-dev.1",
            "token": "secret-token",
        }
    ) == {
        "status": "ok",
        "version": "7.1.0-dev.1",
    }

    assert safe_health_payload({"status": "ok\nsecret", "version": object()}) == {
        "status": "unknown",
        "version": "unknown",
    }


def test_journal_summary_returns_counts_without_messages():
    secret = "Bearer super-secret-token"
    summary = summarize_journal(
        "\n".join(
            [
                "INFO request completed",
                "WARNING retry requested",
                f"ERROR request failed {secret}",
                'GET / HTTP/1.1" 503 10',
                'POST /login HTTP/1.1" 403 20',
            ]
        )
    )

    assert summary == {
        "entries": 5,
        "warnings": 1,
        "errors": 1,
        "http_5xx": 1,
        "auth_failures": 1,
    }
    assert secret not in repr(summary)


def test_parse_pytest_counts_keeps_only_numeric_summary():
    result = parse_pytest_counts(
        "tests/test_secret.py::test_token FAILED\n2 failed, 48 passed, 3 warnings in 1.23s"
    )

    assert result == {
        "failed": 2,
        "passed": 48,
        "warnings": 3,
    }


def test_runtime_report_does_not_receive_raw_journal_messages():
    report = render_runtime_report(
        generated_at="2026-07-23T15:00:00+02:00",
        service={
            "ActiveState": "active",
            "SubState": "running",
            "MainPID": "123",
            "NRestarts": "0",
            "ExecMainStatus": "0",
        },
        health={"status": "ok", "version": "7.1.0-dev.1"},
        disk_total=100 * 1024**3,
        disk_used=10 * 1024**3,
        disk_free=90 * 1024**3,
        journal={
            "entries": 12,
            "warnings": 1,
            "errors": 0,
            "http_5xx": 0,
            "auth_failures": 2,
        },
    )

    assert "active/running" in report
    assert "7.1.0-dev.1" in report
    assert "Bearer" not in report
    assert "LDAP_BIND_PASSWORD" not in report


def test_tests_report_hides_failure_details():
    report = render_tests_report(
        generated_at="2026-07-23T15:00:00+02:00",
        pytest_returncode=1,
        pytest_counts={"failed": 1, "passed": 49},
        pytest_seconds=3.2,
        ruff_returncode=0,
        ruff_seconds=0.4,
    )

    assert "pytest: BŁĄD" in report
    assert "failed=1" in report
    assert "ruff: OK" in report
    assert "test_secret" not in report

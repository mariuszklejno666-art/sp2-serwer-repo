from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_usb_builder_embeds_only_one_time_enrollment_code():
    script = (ROOT / "scripts" / "build-agent-usb-packages.sh").read_text(encoding="utf-8")

    assert "SP2_AGENT_ENROLLMENT_CODE" in script
    assert '"enrollment_code": "$ENROLLMENT_CODE"' in script
    assert "AGENT_ENROLLMENT_TOKEN" not in script
    assert '"enrollment_token"' not in script


def test_installer_exchanges_bootstrap_code_for_device_token():
    installer = (ROOT / "agent-windows" / "install-standalone-agent.ps1").read_text(
        encoding="utf-8"
    )

    assert "$deployment.enrollment_code" in installer
    assert 'Authorization = "Bearer $BootstrapCredential"' in installer
    assert "$DeviceToken = [string]$registration.token" in installer
    assert "token = $DeviceToken" in installer


def test_usb_profile_assignment_uses_device_token_not_bootstrap_code():
    script = (ROOT / "scripts" / "build-agent-usb-packages.sh").read_text(encoding="utf-8")

    assert "$agentConfig.token" in script
    assert 'Authorization = "Bearer $($agentConfig.token)"' in script
    assert 'Authorization = "Bearer $($deployment.enrollment_code)"' not in script


def test_migration_preview_accepts_one_time_enrollment_code():
    migration = (ROOT / "agent-windows" / "migrate-entra-to-samba.ps1").read_text(
        encoding="utf-8"
    )

    assert "$deployment.enrollment_code" in migration
    assert 'Authorization = "Bearer $bootstrapCredential"' in migration

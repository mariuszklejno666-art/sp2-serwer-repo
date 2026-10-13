from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "agent-windows" / "emergency-leave-samba.ps1"


def test_emergency_leave_requires_local_recovery_admin_and_explicit_confirmation():
    source = SCRIPT.read_text(encoding="utf-8")

    assert "Assert-LocalRecoveryAdmin $LocalAdminName" in source
    assert "wpisz dokładnie ODLACZ" in source
    assert "$confirmation -cne 'ODLACZ'" in source


def test_emergency_leave_keeps_credentials_only_in_memory():
    source = SCRIPT.read_text(encoding="utf-8")

    assert "Read-Host" in source
    assert "-AsSecureString" in source
    assert "[pscredential]::new" in source
    assert "domain_password" not in source.lower()
    assert "$domainCredential = $null" in source


def test_emergency_leave_saves_and_optionally_restores_dns_after_restart():
    source = SCRIPT.read_text(encoding="utf-8")

    assert "Get-ActiveDnsSnapshot" in source
    assert "Restore-DnsSnapshot" in source
    assert "Set-DnsClientServerAddress" in source
    assert "'unjoined_pending_restart'" in source
    assert "SP2EmergencyLeaveResume" in source


def test_emergency_leave_is_separate_from_normal_migration():
    migration = (ROOT / "agent-windows" / "migrate-entra-to-samba.ps1").read_text(
        encoding="utf-8"
    )
    builder = (ROOT / "scripts" / "build-agent-usb-packages.sh").read_text(
        encoding="utf-8"
    )

    assert "emergency-leave-samba.ps1" not in migration
    assert "TRYB-AWARYJNY-ODLACZ.cmd" in builder
    assert 'cp "$EMERGENCY_LEAVE_SCRIPT"' in builder

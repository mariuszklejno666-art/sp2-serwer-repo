from pathlib import Path


MIGRATION_SCRIPT = (
    Path(__file__).parents[1] / "agent-windows" / "migrate-entra-to-samba.ps1"
)


def read_script() -> str:
    return MIGRATION_SCRIPT.read_text(encoding="utf-8-sig")


def test_entra_detach_reboots_before_domain_join():
    script = read_script()
    detach_start = script.index("if ($state.AzureAdJoined)")
    detach_end = script.index("else {", detach_start)
    detach_block = script[detach_start:detach_end]

    assert "dsregcmd.exe /leave" in detach_block
    assert "Save-DeploymentState $Profile $newComputerName 'entra_detached_pending_restart'" in detach_block
    assert "Install-PreJoinResumeTask $LocalAdminName" in detach_block
    assert "Restart-Computer -Force" in detach_block
    assert "exit" in detach_block
    assert "Add-Computer" not in detach_block


def test_pre_join_continuation_reapplies_dns_and_requires_fresh_credentials():
    script = read_script()

    assert "[switch]$ContinueAfterEntra" in script
    assert "Set-DomainDns $DnsServer" in script
    assert 'Read-Host "Podaj haslo administratora domeny $DomainAdmin" -AsSecureString' in script
    assert "domain_password" not in script.lower()
    assert "Install-PreJoinResumeTask" in script
    assert "-LogonType Interactive -RunLevel Highest" in script


def test_post_join_resume_accepts_only_completed_domain_join_phase():
    script = read_script()

    assert "'domain_joined_pending_restart'" in script
    assert "Nieprawidlowy etap wznowienia" in script
    assert "SUKCES: DNS, domena, secure channel i agent zostaly zweryfikowane." in script

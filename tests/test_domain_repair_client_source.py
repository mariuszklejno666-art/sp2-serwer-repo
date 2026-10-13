from pathlib import Path


SCRIPT = Path("agent-windows/domain-repair/SP2-Serwis-Domeny.ps1")


def source():
    return SCRIPT.read_text(encoding="utf-8")


def test_broken_trust_local_admin_check_does_not_enumerate_domain_members():
    text = source()
    assert "Get-LocalAdministratorMembership" in text
    assert "Get-LocalGroupMember" not in text
    assert "Win32_GroupUser" in text


def test_authentication_save_has_replace_fallback():
    text = source()
    assert "[IO.File]::Replace($temp,$path,$null)" in text
    assert "Move-Item -LiteralPath $temp -Destination $path -Force" in text


def test_ntlm_disabled_unjoin_is_fail_closed():
    text = source()
    assert "$plan.action -eq 'recovery_to_workgroup'" in text
    assert "$errorText -match 'NTLM|uwierzytelnianie NTLM'" in text
    assert "Program nie wlacza NTLM" in text
    assert "Set-Progress 'failed'" in text


def test_wrong_name_plan_can_be_cancelled_before_start():
    text = source()
    assert "ANULUJ PLAN (bledna nazwa)" in text
    assert "ZMIEN NAZWE" in text
    assert "function Cancel-PlanBeforeStart" in text
    # Started plans keep their reservation; client never cancels them itself.
    assert "$script:PlanStartedEvents = @('begin','credential_issued','retry','failed','approve_ad','ad_approved')" in text
    assert "'YesNoCancel'" in text
    # Operator confirms the exact name before the server reserves it.
    assert "SP2 - potwierdzenie nazwy" in text


def test_stuck_machine_recovery_self_heals_existing_account_trust():
    text = source()
    # Local repair keeps the SAME account (name/OU/SID) and targets the school DC.
    assert "Test-ComputerSecureChannel -Server $script:DomainControllerFqdn -Repair" in text
    assert "$script:DomainControllerFqdn = 'szkolaak.sp2.lan'" in text
    # Server closes the plan only via an explicit, server-verified resolve event.
    assert "Set-Progress 'resolve' $true" in text
    assert "$Event -in @('retry','cancel','resolve')" in text
    assert "$resolved=Resolve-StuckMachineRecovery $plan" in text
    # A queued rename from the failed join is undone before the next reboot.
    assert "function Assert-NoStagedRename" in text
    # Unsynced clock (Samba without signed NTP) is pointed at the school DC.
    assert "Local CMOS Clock" in text
    # Broken trust is repaired locally BEFORE the server reserves a new name.
    assert text.index("$repair=Invoke-LocalSecureChannelRepair") < text.index(
        "Write-UiLog 'Serwer sprawdza dostepnosc nazwy")
    # The authorized-join guard itself is unchanged: no join retry.
    assert "Nie wolno powtarzac operacji bez sprawdzenia wyniku Windows i AD" in text

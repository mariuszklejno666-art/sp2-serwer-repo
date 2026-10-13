from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "agent-windows" / "migrate-entra-to-samba.ps1"


def test_dns_preflight_uses_ad_service_records_and_configured_server():
    script = SCRIPT.read_text(encoding="utf-8-sig")

    assert '$domainLookup = Resolve-DnsName $DomainName' not in script
    assert (
        '$preflightLdapSrv = Resolve-DnsName "_ldap._tcp.dc._msdcs.$DomainName" '
        '-Type SRV -Server $DnsServer -ErrorAction Stop'
    ) in script
    assert (
        '$preflightKerbSrv = Resolve-DnsName "_kerberos._tcp.dc._msdcs.$DomainName" '
        '-Type SRV -Server $DnsServer -ErrorAction Stop'
    ) in script


def test_dns_preflight_runs_before_workstation_changes_and_credentials():
    script = SCRIPT.read_text(encoding="utf-8-sig")
    main = script[script.index("\nAssert-Administrator\n") + 1 :]

    preflight = main.index("[0/7] Kontrola polaczenia")
    credentials = main.index("Read-Host")
    local_admin = main.index("Ensure-LocalAdmin")
    dns_change = main.index("Set-DomainDns")

    assert preflight < local_admin < dns_change < credentials


def test_dns_preflight_reports_safe_stop_and_site_to_site_hint():
    script = SCRIPT.read_text(encoding="utf-8-sig")

    assert "Kontrola wstepna nie powiodla sie" in script
    assert "Nie zmieniono konta lokalnego, DNS ani czlonkostwa komputera" in script
    assert "Site Magic/VPN" in script
    assert "port 53 UDP/TCP" in script


def test_system_dns_is_verified_after_configuration():
    script = SCRIPT.read_text(encoding="utf-8-sig")
    main = script[script.index("\nAssert-Administrator\n") + 1 :]

    dns_change = main.index("Set-DomainDns $DnsServer")
    system_validation = main.index("[3/7] Weryfikacja DNS systemowego")

    assert dns_change < system_validation
    assert (
        '$ldapSrv = Resolve-DnsName "_ldap._tcp.dc._msdcs.$DomainName" '
        '-Type SRV -ErrorAction Stop'
    ) in main

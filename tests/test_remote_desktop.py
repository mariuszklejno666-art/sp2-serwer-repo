from types import SimpleNamespace

from app.remote_desktop import (
    build_rdp_file,
    build_shadow_command,
    rdp_target_address,
    safe_rdp_filename,
)


def test_build_rdp_file_never_embeds_credentials():
    content = build_rdp_file(address="PC-01.sp2.local", domain="SP2")

    assert "full address:s:PC-01.sp2.local" in content
    assert "domain:s:SP2" in content
    assert "prompt for credentials:i:1" in content
    assert "username" not in content.lower()
    assert "password" not in content.lower()


def test_build_rdp_file_omits_domain_when_blank():
    content = build_rdp_file(address="192.168.1.50", domain="")

    assert "domain:s:" not in content


def test_build_rdp_file_strips_newlines_to_prevent_property_injection():
    # Bez usuwania \r\n ten wpis stworzyłby DRUGĄ, niezależną linię
    # "full address:s:evil.example.com", którą mstsc potraktowałby jako
    # nadpisanie właściwego adresu docelowego.
    malicious = "PC-01\r\nfull address:s:evil.example.com"

    content = build_rdp_file(address=malicious)
    lines = content.split("\r\n")

    address_lines = [line for line in lines if line.startswith("full address:s:")]
    assert len(address_lines) == 1


def test_rdp_target_address_prefers_fqdn_then_ip_then_hostname():
    with_fqdn = SimpleNamespace(fqdn="pc-01.sp2.local", primary_ip="10.0.0.5", hostname="PC-01")
    assert rdp_target_address(with_fqdn) == "pc-01.sp2.local"

    with_ip_only = SimpleNamespace(fqdn="", primary_ip="10.0.0.5", hostname="PC-01")
    assert rdp_target_address(with_ip_only) == "10.0.0.5"

    hostname_only = SimpleNamespace(fqdn="", primary_ip="—", hostname="PC-01")
    assert rdp_target_address(hostname_only) == "PC-01"


def test_safe_rdp_filename_strips_unsafe_characters():
    assert safe_rdp_filename("PC-01") == "PC-01.rdp"
    assert safe_rdp_filename("PC 01; rm -rf") == "PC01rm-rf.rdp"
    assert safe_rdp_filename("") == "komputer.rdp"


def test_build_shadow_command_view_only():
    command = build_shadow_command(address="pc-01.sp2.local", session_id=1, control=False)

    assert command == "mstsc /shadow:1 /v:pc-01.sp2.local /noConsentPrompt"
    assert "/control" not in command


def test_build_shadow_command_with_control():
    command = build_shadow_command(address="pc-01.sp2.local", session_id=2, control=True)

    assert command == "mstsc /shadow:2 /v:pc-01.sp2.local /control /noConsentPrompt"


def test_build_shadow_command_strips_newlines_from_address():
    command = build_shadow_command(
        address="pc-01\r\nevil.example.com", session_id=1, control=False
    )

    assert "\n" not in command
    assert "\r" not in command

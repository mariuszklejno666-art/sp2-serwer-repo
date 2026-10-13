from __future__ import annotations

from typing import Any


def _clean(value: str) -> str:
    """Usuwa znaki końca linii, aby uniemożliwić wstrzyknięcie dodatkowych
    właściwości do pliku .rdp przez zmanipulowaną nazwę/adres komputera."""
    return value.replace("\r", "").replace("\n", "").strip()


def rdp_target_address(agent: Any) -> str:
    """Wybiera najlepszy dostępny adres do połączenia RDP z komputerem."""
    fqdn = _clean(str(getattr(agent, "fqdn", "") or ""))
    if fqdn:
        return fqdn
    primary_ip = _clean(str(getattr(agent, "primary_ip", "") or ""))
    if primary_ip and primary_ip != "—":
        return primary_ip
    return _clean(str(getattr(agent, "hostname", "") or ""))


def build_rdp_file(*, address: str, domain: str = "") -> str:
    """Buduje minimalny plik .rdp do pobrania przez administratora.

    Plik celowo nigdy nie zawiera loginu ani hasła — klient RDP (mstsc)
    zawsze poprosi o poświadczenia domenowe przy nawiązywaniu połączenia.
    """
    address = _clean(address)
    lines = [
        f"full address:s:{address}",
        "prompt for credentials:i:1",
        "authentication level:i:2",
        "administrative session:i:0",
        "session bpp:i:32",
        "audiomode:i:0",
        "redirectprinters:i:0",
        "redirectclipboard:i:1",
    ]
    domain = _clean(domain)
    if domain:
        lines.append(f"domain:s:{domain}")
    return "\r\n".join(lines) + "\r\n"


def safe_rdp_filename(hostname: str) -> str:
    """Nazwa pliku ograniczona do bezpiecznego zestawu znaków."""
    cleaned = "".join(ch for ch in _clean(hostname) if ch.isalnum() or ch in "-_")
    return f"{cleaned or 'komputer'}.rdp"


def build_shadow_command(*, address: str, session_id: int, control: bool) -> str:
    """Buduje komendę `mstsc /shadow` do uruchomienia na WŁASNYM komputerze
    administratora — SP2 ADMIN działa na Ubuntu i nie może jej wykonać za
    Ciebie. Wymaga wcześniej ustawionej Zasady Grupy zezwalającej na zdalne
    sterowanie sesją bez potwierdzenia użytkownika (inaczej Windows i tak
    wyświetli monit o zgodę na komputerze docelowym).
    """
    address = _clean(address)
    flags = ["/control", "/noConsentPrompt"] if control else ["/noConsentPrompt"]
    return f"mstsc /shadow:{int(session_id)} /v:{address} " + " ".join(flags)

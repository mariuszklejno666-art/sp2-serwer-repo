from __future__ import annotations

from pathlib import Path

# Znaczniki wyznaczające zarządzany blok wpisów w pliku hosts. Wszystko
# pomiędzy nimi jest w całości zastępowane przy każdym zastosowaniu reguł,
# więc usunięcie/wyłączenie reguły w SP2 ADMIN faktycznie odblokowuje
# domenę przy kolejnej synchronizacji — nie tylko dopisuje kolejne wpisy.
WEB_FILTER_START = "# SP2-ADMIN-WEBFILTER-START"
WEB_FILTER_END = "# SP2-ADMIN-WEBFILTER-END"

DEFAULT_HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")


def apply_web_filter_hosts(hostnames: list[str], hosts_path: Path | None = None) -> int:
    """Nadpisuje zarządzany blok w pliku hosts listą zablokowanych domen.

    Przekierowuje każdą domenę na 127.0.0.1, blokując zarówno HTTP jak
    i HTTPS bez rozwiązywania i śledzenia zmieniających się adresów IP.
    Zwraca liczbę zastosowanych domen.
    """
    path = hosts_path or DEFAULT_HOSTS_PATH
    existing = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""

    cleaned: list[str] = []
    inside_block = False
    for line in existing.splitlines():
        stripped = line.strip()
        if stripped == WEB_FILTER_START:
            inside_block = True
            continue
        if stripped == WEB_FILTER_END:
            inside_block = False
            continue
        if inside_block:
            continue
        cleaned.append(line)

    while cleaned and not cleaned[-1].strip():
        cleaned.pop()

    valid_hostnames = sorted({str(h).strip().lower() for h in hostnames if str(h).strip()})
    if valid_hostnames:
        cleaned.append("")
        cleaned.append(WEB_FILTER_START)
        for hostname in valid_hostnames:
            cleaned.append(f"127.0.0.1 {hostname}")
        cleaned.append(WEB_FILTER_END)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(cleaned) + "\n", encoding="utf-8")
    return len(valid_hostnames)

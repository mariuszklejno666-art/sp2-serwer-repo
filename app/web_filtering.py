from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


FILTERED_ROOMS = ("4", "7", "11", "32")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class WebFilterValidationError(ValueError):
    pass


def normalize_blocked_address(value: str) -> tuple[str, str]:
    raw = str(value or "").strip()
    if not raw:
        raise WebFilterValidationError("Wklej adres strony.")
    if len(raw) > 500:
        raise WebFilterValidationError("Adres może mieć najwyżej 500 znaków.")

    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise WebFilterValidationError("Dozwolone są wyłącznie adresy HTTP i HTTPS.")
    if parsed.username or parsed.password:
        raise WebFilterValidationError("Adres nie może zawierać loginu ani hasła.")

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise WebFilterValidationError("Nie udało się odczytać nazwy domeny.")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise WebFilterValidationError("Nazwa domeny jest nieprawidłowa.") from exc
        labels = ascii_host.split(".")
        if len(labels) < 2 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise WebFilterValidationError("Podaj pełną nazwę domeny, np. gry.example.pl.")
        host = ascii_host
    else:
        raise WebFilterValidationError("Podaj domenę strony, a nie adres IP.")

    return candidate, host


def normalize_rooms(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    selected = tuple(room for room in FILTERED_ROOMS if room in set(values))
    if not selected:
        raise WebFilterValidationError("Wybierz co najmniej jedną salę.")
    return selected


def room_to_agent_room(room_number: str) -> str:
    return f"Sala{room_number}"


def build_room_hostname_map(rules) -> dict[str, list[str]]:
    """Buduje mapę sala_agenta -> posortowana lista domen z włączonych reguł.

    Zawsze zwraca wpis dla każdej znanej sali (FILTERED_ROOMS), nawet z
    pustą listą — dzięki temu wyłączenie ostatniej reguły dla sali dalej
    generuje zadanie, które faktycznie czyści wcześniej zastosowany blok
    w pliku hosts, a nie tylko pomija tę salę.
    """
    mapping: dict[str, set[str]] = {room: set() for room in FILTERED_ROOMS}
    for rule in rules:
        if not rule.enabled:
            continue
        for room in rule.room_list:
            if room in mapping:
                mapping[room].add(rule.hostname)
    return {
        room_to_agent_room(room): sorted(hosts) for room, hosts in mapping.items()
    }

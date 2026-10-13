from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable


WINDOWS_COMPUTER_NAME_MAX_LENGTH = 15
TEACHER_COMPUTER_PREFIX = "NAU"
ADMIN_COMPUTER_PREFIX = "ADM"


class ComputerNameError(ValueError):
    """Nieprawidłowe dane użyte do utworzenia nazwy komputera."""


def _ascii_component(value: object) -> str:
    text = str(value or "").strip().translate(
        str.maketrans({"Ł": "L", "ł": "l"})
    )
    text = (
        unicodedata.normalize("NFKD", text)
        .encode("ascii", "ignore")
        .decode("ascii")
        .upper()
    )
    return re.sub(r"[^A-Z0-9]+", "-", text).strip("-")


def _known_names(values: Iterable[str]) -> set[str]:
    return {
        str(value).strip().rstrip("$").casefold()
        for value in values
        if str(value).strip()
    }


def computer_name_exists(name: str, existing_names: Iterable[str]) -> bool:
    return name.casefold() in _known_names(existing_names)


def distinguished_name_within(value: str, base: str) -> bool:
    normalized = str(value or "").strip().casefold()
    normalized_base = str(base or "").strip().casefold()
    return bool(
        normalized
        and normalized_base
        and (
            normalized == normalized_base
            or normalized.endswith("," + normalized_base)
        )
    )


def ou_name_from_dn(value: str) -> str:
    first_rdn = str(value or "").strip().split(",", 1)[0]
    key, separator, name = first_rdn.partition("=")
    if not separator or key.strip().casefold() != "ou":
        return ""
    return name.replace(r"\,", ",").strip()


def naming_mode_for_ou(value: str) -> str:
    ou_name = ou_name_from_dn(value).casefold()
    if ou_name == "nauczyciele":
        return "teacher"
    if ou_name == "administracja":
        return "admin"
    if ou_name.startswith("sala"):
        return "room"
    return ""


def room_computer_name(room: object, number: object) -> str:
    room_part = _ascii_component(room)
    if not room_part:
        raise ComputerNameError("Nie wybrano sali.")

    # OU może nazywać się Sala11, S11 albo 11. Wynik jest zawsze S11-01.
    if room_part.startswith("SALA"):
        room_part = room_part[4:]
    elif room_part.startswith("S") and room_part[1:].isdigit():
        room_part = room_part[1:]
    if not room_part or not room_part.isdigit():
        raise ComputerNameError(
            "Nazwa OU sali musi mieć format Sala11, S11 albo 11."
        )

    number_text = str(number or "").strip()
    if not number_text.isdigit():
        raise ComputerNameError("Numer komputera musi być liczbą od 1 do 99.")
    number_value = int(number_text)
    if not 1 <= number_value <= 99:
        raise ComputerNameError("Numer komputera musi być liczbą od 1 do 99.")

    name = f"S{int(room_part)}-{number_value:02d}"
    if len(name) > WINDOWS_COMPUTER_NAME_MAX_LENGTH:
        raise ComputerNameError(
            "Numer sali jest zbyt długi dla nazwy komputera Windows."
        )
    return name


def _next_sequential_name(
    prefix: str,
    existing_names: Iterable[str] = (),
    *,
    first: int = 1,
    last: int = 999,
) -> str:
    normalized_prefix = _ascii_component(prefix)
    if not normalized_prefix:
        raise ComputerNameError("Nie podano prefiksu nazwy komputera.")
    known = _known_names(existing_names)
    for sequence in range(first, last + 1):
        candidate = f"{normalized_prefix}-{sequence:03d}"
        if len(candidate) > WINDOWS_COMPUTER_NAME_MAX_LENGTH:
            raise ComputerNameError(
                "Prefiks jest zbyt długi dla nazwy komputera Windows."
            )
        if candidate.casefold() not in known:
            return candidate
    raise ComputerNameError(
        f"Brak wolnych nazw w zakresie {normalized_prefix}-{first:03d}–"
        f"{normalized_prefix}-{last:03d}."
    )


def teacher_computer_name(
    given_name: object = "",
    surname: object = "",
    existing_names: Iterable[str] = (),
) -> str:
    """Zwraca pierwszą wolną nazwę laptopa nauczyciela: NAU-001…NAU-199.

    Imię i nazwisko pozostają w sygnaturze dla zgodności ze starszym
    kreatorem, lecz konto imie.nazwisko nie wpływa na nazwę urządzenia.
    """
    return _next_sequential_name(
        TEACHER_COMPUTER_PREFIX,
        existing_names,
        last=199,
    )


def admin_computer_name(existing_names: Iterable[str] = ()) -> str:
    """Zwraca pierwszą wolną nazwę komputera administracji: ADM-001…ADM-999."""
    return _next_sequential_name(ADMIN_COMPUTER_PREFIX, existing_names)

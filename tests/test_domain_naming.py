from __future__ import annotations

import pytest

from app.domain_naming import (
    ComputerNameError,
    admin_computer_name,
    computer_name_exists,
    distinguished_name_within,
    naming_mode_for_ou,
    room_computer_name,
    teacher_computer_name,
)


def test_room_name_uses_common_short_format():
    assert room_computer_name("Sala11", 1) == "S11-01"
    assert room_computer_name("S11", "9") == "S11-09"
    assert room_computer_name("11", 10) == "S11-10"


@pytest.mark.parametrize("number", ["", "abc", 0, 100])
def test_room_name_rejects_invalid_number(number):
    with pytest.raises(ComputerNameError):
        room_computer_name("Sala11", number)


def test_room_name_rejects_non_numeric_room():
    with pytest.raises(ComputerNameError):
        room_computer_name("Biblioteka", 1)


def test_teacher_name_uses_first_free_sequential_number():
    existing = ["NAU-001$", "nau-002"]
    assert teacher_computer_name("Jan", "Kowalski", existing) == "NAU-003"


def test_teacher_name_stops_at_199():
    existing = [f"NAU-{number:03d}" for number in range(1, 200)]
    with pytest.raises(ComputerNameError, match="Brak wolnych nazw"):
        teacher_computer_name(existing_names=existing)


def test_admin_name_uses_first_free_sequential_number():
    assert admin_computer_name(["ADM-001$"]) == "ADM-002"


def test_existing_name_comparison_ignores_case_and_computer_dollar():
    assert computer_name_exists("S11-01", ["s11-01$"]) is True


def test_ou_helpers_restrict_targets_and_detect_naming_mode():
    root = "OU=Komputery,DC=sp2,DC=lan"
    assert distinguished_name_within(
        "OU=Sala11,OU=Komputery,DC=sp2,DC=lan",
        root,
    )
    assert not distinguished_name_within(
        "OU=Nauczyciele,OU=Uzytkownicy,DC=sp2,DC=lan",
        root,
    )
    assert naming_mode_for_ou(
        "OU=Sala11,OU=Komputery,DC=sp2,DC=lan"
    ) == "room"
    assert naming_mode_for_ou(
        "OU=Nauczyciele,OU=Komputery,DC=sp2,DC=lan"
    ) == "teacher"
    assert naming_mode_for_ou(
        "OU=Administracja,OU=Komputery,DC=sp2,DC=lan"
    ) == "admin"

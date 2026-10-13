from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Iterable


@dataclass(frozen=True)
class SchoolDay:
    day: date
    kind: str
    label: str
    lessons: bool
    bells: bool
    schedule: str


DAY_STYLES = {
    "school": "success",
    "weekend": "secondary",
    "holiday": "danger",
    "break": "danger",
    "special": "warning",
}


def easter_sunday(year: int) -> date:
    a = year % 19
    b, c = divmod(year, 100)
    d, e = divmod(b, 4)
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = divmod(c, 4)
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = ((h + l - 7 * m + 114) % 31) + 1
    return date(year, month, day)


def polish_public_holidays(year: int) -> dict[date, str]:
    easter = easter_sunday(year)
    return {
        date(year, 1, 1): "Nowy Rok",
        date(year, 1, 6): "Święto Trzech Króli",
        easter: "Wielkanoc",
        easter + timedelta(days=1): "Poniedziałek Wielkanocny",
        date(year, 5, 1): "Święto Pracy",
        date(year, 5, 3): "Święto Konstytucji 3 Maja",
        easter + timedelta(days=49): "Zielone Świątki",
        easter + timedelta(days=60): "Boże Ciało",
        date(year, 8, 15): "Wniebowzięcie NMP",
        date(year, 11, 1): "Wszystkich Świętych",
        date(year, 11, 11): "Narodowe Święto Niepodległości",
        date(year, 12, 24): "Wigilia Bożego Narodzenia",
        date(year, 12, 25): "Boże Narodzenie",
        date(year, 12, 26): "Drugi dzień Bożego Narodzenia",
    }


def school_break_for(day: date) -> str | None:
    if (day.month == 6 and day.day >= 27) or day.month in {7, 8}:
        return "Wakacje letnie"
    if day.month == 12 and day.day >= 23:
        return "Zimowa przerwa świąteczna"
    return None


def classify_school_day(day: date, exceptions: Iterable[object] = ()) -> SchoolDay:
    for item in exceptions:
        if item.enabled and item.starts_on <= day <= item.ends_on:
            return SchoolDay(day, item.kind, item.label, item.lessons, item.bells, item.schedule)

    holiday = polish_public_holidays(day.year).get(day)
    if holiday:
        return SchoolDay(day, "holiday", holiday, False, False, "brak")

    school_break = school_break_for(day)
    if school_break:
        return SchoolDay(day, "break", school_break, False, False, "brak")

    if day.weekday() >= 5:
        return SchoolDay(day, "weekend", "Weekend", False, False, "brak")

    return SchoolDay(day, "school", "Dzień nauki", True, True, "standardowy")


def month_calendar(year: int, month: int, exceptions: Iterable[object] = ()):
    items = tuple(exceptions)
    return [
        [classify_school_day(day, items) if day.month == month else None for day in week]
        for week in calendar.Calendar(firstweekday=0).monthdatescalendar(year, month)
    ]

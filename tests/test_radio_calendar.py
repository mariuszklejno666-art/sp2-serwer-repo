from datetime import date

from app.radio_calendar import classify_school_day, easter_sunday, month_calendar


def test_weekday_enables_standard_bells():
    result = classify_school_day(date(2026, 9, 1))
    assert result.kind == "school"
    assert result.lessons is True
    assert result.bells is True
    assert result.schedule == "standardowy"


def test_weekend_and_public_holiday_disable_bells():
    weekend = classify_school_day(date(2026, 9, 5))
    holiday = classify_school_day(date(2026, 11, 11))
    assert weekend.bells is False
    assert holiday.label == "Narodowe Święto Niepodległości"
    assert holiday.bells is False


def test_summer_break_disables_bells():
    result = classify_school_day(date(2026, 7, 15))
    assert result.label == "Wakacje letnie"
    assert result.bells is False


def test_easter_and_month_layout():
    assert easter_sunday(2026) == date(2026, 4, 5)
    weeks = month_calendar(2026, 9)
    assert all(len(week) == 7 for week in weeks)
    assert any(day and day.day == date(2026, 9, 1) for week in weeks for day in week)

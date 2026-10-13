import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "agent-windows"))

from console_session import parse_query_user_output


def test_parses_real_query_user_output_with_active_console():
    # Przechwycone na żywo z `query user` na Windows.
    output = (
        " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n"
        ">sp2                   console             1  Active      none   21.08.2026 08:29"
    )

    result = parse_query_user_output(output)

    assert result == {"username": "sp2", "session_id": 1, "session_name": "console"}


def test_returns_none_when_nobody_logged_in():
    output = " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME"

    assert parse_query_user_output(output) is None


def test_returns_none_for_empty_output():
    assert parse_query_user_output("") is None
    assert parse_query_user_output("   \n  ") is None


def test_picks_active_session_among_multiple_users():
    output = (
        " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n"
        " jkowalski             rdp-tcp#3           2  Disc        1:15   21.08.2026 07:10\n"
        ">anowak                console             1  Active      none   21.08.2026 08:29"
    )

    result = parse_query_user_output(output)

    assert result == {"username": "anowak", "session_id": 1, "session_name": "console"}


def test_ignores_header_only_variations_gracefully():
    assert parse_query_user_output("just one line") is None

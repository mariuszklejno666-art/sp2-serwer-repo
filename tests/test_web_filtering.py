from types import SimpleNamespace

from app.web_filtering import build_room_hostname_map, room_to_agent_room


def _rule(hostname, rooms, enabled=True):
    room_list = tuple(rooms)
    return SimpleNamespace(hostname=hostname, room_list=room_list, enabled=enabled)


def test_room_to_agent_room_matches_agent_naming():
    assert room_to_agent_room("4") == "Sala4"
    assert room_to_agent_room("32") == "Sala32"


def test_build_room_hostname_map_includes_every_filtered_room():
    result = build_room_hostname_map([])

    assert set(result.keys()) == {"Sala4", "Sala7", "Sala11", "Sala32"}
    assert all(hosts == [] for hosts in result.values())


def test_build_room_hostname_map_groups_by_room_and_sorts():
    rules = [
        _rule("gry.pl", ["4", "7"]),
        _rule("social.com", ["4"]),
    ]

    result = build_room_hostname_map(rules)

    assert result["Sala4"] == ["gry.pl", "social.com"]
    assert result["Sala7"] == ["gry.pl"]
    assert result["Sala11"] == []
    assert result["Sala32"] == []


def test_build_room_hostname_map_ignores_disabled_rules():
    rules = [_rule("gry.pl", ["4"], enabled=False)]

    result = build_room_hostname_map(rules)

    assert result["Sala4"] == []


def test_build_room_hostname_map_deduplicates_hostnames():
    rules = [
        _rule("gry.pl", ["4"]),
        _rule("gry.pl", ["4"]),
    ]

    result = build_room_hostname_map(rules)

    assert result["Sala4"] == ["gry.pl"]

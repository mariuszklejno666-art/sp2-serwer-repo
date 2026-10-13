from types import SimpleNamespace

from app.disk_alerts import low_disk_volumes


def _agent(agent_id, hostname, room, disks):
    return SimpleNamespace(id=agent_id, hostname=hostname, room=room, disks=disks)


def test_low_disk_volumes_filters_by_threshold():
    agents = [
        _agent(
            1,
            "PC-01",
            "Sala11",
            [{"mount": "C:\\", "percent_used": 95.0, "free_bytes": 10, "total_bytes": 200}],
        ),
        _agent(
            2,
            "PC-02",
            "Sala11",
            [{"mount": "C:\\", "percent_used": 40.0, "free_bytes": 100, "total_bytes": 200}],
        ),
    ]

    result = low_disk_volumes(agents, threshold_percent=90)

    assert [item.hostname for item in result] == ["PC-01"]
    assert result[0].mount == "C:\\"
    assert result[0].percent_used == 95.0


def test_low_disk_volumes_sorts_most_full_first():
    agents = [
        _agent(1, "PC-01", None, [{"mount": "C:\\", "percent_used": 91.0}]),
        _agent(2, "PC-02", None, [{"mount": "C:\\", "percent_used": 99.0}]),
    ]

    result = low_disk_volumes(agents, threshold_percent=90)

    assert [item.hostname for item in result] == ["PC-02", "PC-01"]


def test_low_disk_volumes_ignores_missing_or_invalid_usage():
    agents = [
        _agent(1, "PC-01", None, [{"mount": "C:\\"}]),
        _agent(2, "PC-02", None, [{"mount": "D:\\", "percent_used": "n/a"}]),
        _agent(3, "PC-03", None, None),
    ]

    assert low_disk_volumes(agents, threshold_percent=90) == []


def test_low_disk_volumes_reports_multiple_disks_per_computer():
    agents = [
        _agent(
            1,
            "PC-01",
            "Sala7",
            [
                {"mount": "C:\\", "percent_used": 92.0},
                {"mount": "D:\\", "percent_used": 20.0},
            ],
        ),
    ]

    result = low_disk_volumes(agents, threshold_percent=90)

    assert [item.mount for item in result] == ["C:\\"]

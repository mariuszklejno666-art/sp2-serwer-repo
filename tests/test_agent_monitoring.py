from app.extensions import db
from app.models import AgentComputer


def test_heartbeat_saves_monitoring_metrics(client, app):
    with app.app_context():
        app.config["AGENT_API_TOKEN"] = "test-token"

    response = client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": "Bearer test-token"},
        json={
            "hostname": "SALA32-PC01",
            "cpu_percent": 37.4,
            "memory_percent": 62.1,
            "uptime_seconds": 98765,
            "collected_at": "2026-07-23T06:00:00+00:00",
            "disks": [{"mount": "C:\\", "total_bytes": 1000, "free_bytes": 400, "percent_used": 60.0}],
        },
    )
    assert response.status_code == 200

    with app.app_context():
        computer = db.session.scalar(
            db.select(AgentComputer).where(AgentComputer.hostname == "SALA32-PC01")
        )
        assert computer is not None
        assert computer.cpu_percent == 37.4
        assert computer.memory_percent == 62.1
        assert computer.uptime_seconds == 98765
        assert computer.metrics_collected_at is not None

from __future__ import annotations

import hashlib


from app.agents.software_catalog import add_package
from app.extensions import db
from app.models import AgentComputer, AgentJob, AuditLog, User


def _login_admin(app, client, username="selfupdate-admin"):
    with app.app_context():
        user = User(username=username, full_name="Administrator", role="administrator")
        user.set_password("Test-password-123!")
        db.session.add(user)
        db.session.commit()
    response = client.post(
        "/login", data={"username": username, "password": "Test-password-123!"}
    )
    assert response.status_code == 302


def _seed_agent_package(app, tmp_path, *, package_id="sp2-agent", version="2.7.0"):
    content = b"MZ" + b"fake-agent-exe-content"
    sha256 = hashlib.sha256(content).hexdigest()
    with app.app_context():
        is_agent = package_id in {"agent", "sp2-agent"}
        add_package(
            package_id=package_id,
            name="SP2 Agent" if is_agent else package_id,
            version=version,
            description="",
            filename="SP2Agent.exe",
            installer_type="exe",
            arguments=[] if is_agent else ["/S"],
            sha256=sha256,
            purpose="agent" if is_agent else "software",
            silent_profile="agent" if is_agent else "custom",
        )
    packages_dir = tmp_path / "software-packages"
    packages_dir.mkdir(parents=True, exist_ok=True)
    (packages_dir / "SP2Agent.exe").write_bytes(content)
    return sha256


def _seed_multifile_package(app, tmp_path, *, package_id="infkl3"):
    installer = b"MZ" + b"full-installer"
    companion = b"required-bin-data"
    installer_sha = hashlib.sha256(installer).hexdigest()
    companion_sha = hashlib.sha256(companion).hexdigest()
    storage_dir = f"{package_id}-files"
    package_dir = tmp_path / "software-packages" / storage_dir
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "setup.exe").write_bytes(installer)
    (package_dir / "payload.bin").write_bytes(companion)
    with app.app_context():
        add_package(
            package_id=package_id,
            name="INF KL 3",
            version="1.0",
            description="",
            filename="setup.exe",
            installer_type="exe",
            arguments=["/S"],
            sha256=installer_sha,
            storage_dir=storage_dir,
            files=[
                {
                    "filename": "setup.exe",
                    "sha256": installer_sha,
                    "size": len(installer),
                },
                {
                    "filename": "payload.bin",
                    "sha256": companion_sha,
                    "size": len(companion),
                },
            ],
        )


def test_single_computer_self_update_queues_job(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client)
    sha256 = _seed_agent_package(app, tmp_path)
    with app.app_context():
        agent = AgentComputer(hostname="PC-SELFUPDATE-01")
        db.session.add(agent)
        db.session.commit()
        agent_id = agent.id

    response = client.post(
        f"/agents/{agent_id}/commands",
        data={"action": "self_update", "package_id": "sp2-agent", "confirm": "yes"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    with app.app_context():
        job = db.session.scalar(
            db.select(AgentJob).where(AgentJob.computer_id == agent_id)
        )
        assert job is not None
        assert job.action == "self_update"
        assert job.payload["sha256"] == sha256
        assert job.payload["download_path"] == "/api/v1/agent/software/sp2-agent/download"
        assert "installer_type" not in job.payload


def test_single_computer_self_update_requires_confirmation(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client)
    _seed_agent_package(app, tmp_path)
    with app.app_context():
        agent = AgentComputer(hostname="PC-SELFUPDATE-02")
        db.session.add(agent)
        db.session.commit()
        agent_id = agent.id

    response = client.post(
        f"/agents/{agent_id}/commands",
        data={"action": "self_update", "package_id": "sp2-agent"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count(AgentJob.id))) == 0


def test_room_bulk_self_update_queues_job_per_agent(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client)
    _seed_agent_package(app, tmp_path)
    with app.app_context():
        db.session.add_all([
            AgentComputer(hostname="PC-SALA11-01", room="Sala11"),
            AgentComputer(hostname="PC-SALA11-02", room="Sala11"),
        ])
        db.session.commit()

    response = client.post(
        "/rooms/Sala11/commands",
        data={"action": "self_update", "package_id": "sp2-agent", "confirm": "yes"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    with app.app_context():
        jobs = db.session.scalars(
            db.select(AgentJob).where(AgentJob.action == "self_update")
        ).all()
        assert len(jobs) == 2


def test_deploy_agent_update_skips_computers_already_on_target_version(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client)
    _seed_agent_package(app, tmp_path, version="2.7.0")
    with app.app_context():
        db.session.add_all([
            AgentComputer(hostname="PC-OLD-01", agent_version="2.6.0"),
            AgentComputer(hostname="PC-CURRENT-01", agent_version="2.7.0"),
        ])
        db.session.commit()

    response = client.post(
        "/agents/software/sp2-agent/deploy-agent-update",
        data={"confirm": "yes"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "1 komputer" in body
    with app.app_context():
        jobs = db.session.scalars(
            db.select(AgentJob).where(AgentJob.action == "self_update")
        ).all()
        assert len(jobs) == 1
        assert jobs[0].computer.hostname == "PC-OLD-01"
        audit = db.session.scalar(
            db.select(AuditLog).where(AuditLog.action == "AGENT_FLEET_SELF_UPDATE")
        )
        assert audit is not None


def test_deploy_software_to_all_queues_job_per_agent(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client)
    _seed_agent_package(app, tmp_path, package_id="vlc", version="3.0.23")
    with app.app_context():
        db.session.add_all([
            AgentComputer(hostname="PC-FLEET-01"),
            AgentComputer(hostname="PC-FLEET-02"),
        ])
        db.session.commit()

    response = client.post(
        "/agents/software/vlc/deploy-all",
        data={"confirm": "yes"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "2 komputerach" in body
    with app.app_context():
        jobs = db.session.scalars(
            db.select(AgentJob).where(AgentJob.action == "install_software")
        ).all()
        assert len(jobs) == 2
        assert all(job.payload["package_id"] == "vlc" for job in jobs)
        audit = db.session.scalar(
            db.select(AuditLog).where(AuditLog.action == "AGENT_FLEET_INSTALL_SOFTWARE")
        )
        assert audit is not None


def test_deploy_software_to_all_requires_confirmation(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client)
    _seed_agent_package(app, tmp_path, package_id="vlc", version="3.0.23")
    with app.app_context():
        db.session.add(AgentComputer(hostname="PC-FLEET-03"))
        db.session.commit()

    response = client.post("/agents/software/vlc/deploy-all", follow_redirects=True)

    assert response.status_code == 200
    with app.app_context():
        assert db.session.scalar(db.select(db.func.count(AgentJob.id))) == 0


def test_deploy_software_to_all_requires_administrator(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _seed_agent_package(app, tmp_path, package_id="vlc", version="3.0.23")
    with app.app_context():
        user = User(username="viewer-deployall", full_name="Viewer", role="viewer")
        user.set_password("Test-password-123!")
        db.session.add(user)
        db.session.commit()
    client.post(
        "/login", data={"username": "viewer-deployall", "password": "Test-password-123!"}
    )

    response = client.post("/agents/software/vlc/deploy-all", data={"confirm": "yes"})

    assert response.status_code == 403


def test_deploy_agent_update_requires_administrator(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _seed_agent_package(app, tmp_path)
    with app.app_context():
        user = User(username="viewer-selfupdate", full_name="Viewer", role="viewer")
        user.set_password("Test-password-123!")
        db.session.add(user)
        db.session.commit()
    client.post(
        "/login",
        data={"username": "viewer-selfupdate", "password": "Test-password-123!"},
    )

    response = client.post(
        "/agents/software/sp2-agent/deploy-agent-update", data={"confirm": "yes"}
    )

    assert response.status_code == 403



def test_multifile_deploy_requires_agent_2_8(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client, username="multifile-old-agent-admin")
    _seed_multifile_package(app, tmp_path)
    with app.app_context():
        db.session.add(AgentComputer(hostname="PC-OLD-MULTI", agent_version="2.7.0"))
        db.session.commit()

    response = client.post(
        "/agents/software/infkl3/deploy-all",
        data={"confirm": "yes"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "2.8.0" in response.get_data(as_text=True)
    with app.app_context():
        jobs = db.session.scalars(
            db.select(AgentJob).where(AgentJob.action == "install_software")
        ).all()
        assert jobs == []


def test_multifile_deploy_includes_manifest_for_agent_2_8(app, client, tmp_path):
    app.instance_path = str(tmp_path)
    _login_admin(app, client, username="multifile-new-agent-admin")
    _seed_multifile_package(app, tmp_path)
    with app.app_context():
        db.session.add(AgentComputer(hostname="PC-NEW-MULTI", agent_version="2.8.0"))
        db.session.commit()

    response = client.post(
        "/agents/software/infkl3/deploy-all",
        data={"confirm": "yes"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    with app.app_context():
        job = db.session.scalar(
            db.select(AgentJob).where(AgentJob.action == "install_software")
        )
        assert job is not None
        assert len(job.payload["files"]) == 2
        assert job.payload["filename"] == "setup.exe"
        assert job.payload["files"][1]["filename"] == "payload.bin"

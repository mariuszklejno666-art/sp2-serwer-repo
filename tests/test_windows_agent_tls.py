import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import ModuleType

import pytest


class FakeSession:
    def __init__(self):
        self.headers = {}
        self.verify = True


def load_windows_agent(monkeypatch):
    fake_requests = ModuleType("requests")
    fake_requests.Session = FakeSession
    monkeypatch.setitem(sys.modules, "requests", fake_requests)
    monkeypatch.setitem(sys.modules, "psutil", ModuleType("psutil"))
    path = Path(__file__).parents[1] / "agent-windows" / "sp2_agent.py"
    spec = spec_from_file_location("sp2_agent_windows", path)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_agent_session_uses_relative_ca_bundle(monkeypatch, tmp_path):
    agent = load_windows_agent(monkeypatch)
    ca = tmp_path / "sp2-internal-ca.crt"
    ca.write_text("test-ca", encoding="utf-8")
    monkeypatch.setattr(agent, "BASE_DIR", tmp_path)

    session = agent.create_session(
        {
            "token": "device-token",
            "ca_bundle": "sp2-internal-ca.crt",
            "verify_tls": False,
        }
    )

    assert session.verify == str(ca.resolve())
    assert session.headers["Authorization"] == "Bearer device-token"


def test_agent_session_rejects_missing_ca_bundle(monkeypatch, tmp_path):
    agent = load_windows_agent(monkeypatch)
    monkeypatch.setattr(agent, "BASE_DIR", tmp_path)

    with pytest.raises(FileNotFoundError, match="Brak certyfikatu CA"):
        agent.create_session(
            {
                "token": "device-token",
                "ca_bundle": "missing-ca.crt",
            }
        )

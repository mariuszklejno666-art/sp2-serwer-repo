from __future__ import annotations

import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "agent-windows" / "legacy_upgrade_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("legacy_upgrade_bootstrap", MODULE_PATH)
assert SPEC and SPEC.loader
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


def test_helper_script_preserves_config_and_restarts_agent():
    target = Path(r"C:\Program Files\SP2 Agent\SP2Agent.exe")
    staged = Path(r"C:\ProgramData\SP2-Agent\legacy-upgrade\SP2Agent-2.8.0.exe")
    log_path = Path(r"C:\ProgramData\SP2-Agent\legacy-upgrade.log")

    script = bootstrap.build_helper_script(target, staged, log_path)

    assert "agent-config.json" not in script
    assert 'taskkill.exe /F /IM "SP2Agent.exe"' in script
    assert 'schtasks.exe /Run /TN "SP2Agent"' in script
    assert 'sc.exe start "SP2Agent"' in script
    assert ".pre-2.8.0.bak" in script
    assert "timeout /t 10" in script


def test_default_target_is_standard_install_path():
    assert str(bootstrap.DEFAULT_TARGET).endswith(
        r"Program Files\SP2 Agent\SP2Agent.exe"
    )



def test_scheduled_task_timeout_falls_back(monkeypatch):
    def boom(*args, **kwargs):
        raise bootstrap.subprocess.TimeoutExpired(cmd="powershell.exe", timeout=20)

    monkeypatch.setattr(bootstrap.subprocess, "run", boom)
    assert bootstrap._scheduled_task_target() is None

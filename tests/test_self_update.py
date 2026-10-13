import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "agent-windows"))

from self_update import build_self_update_script


def test_build_self_update_script_kills_old_process_before_swap():
    script = build_self_update_script(
        new_exe_path=r"C:\ProgramData\SP2-Agent\downloads\SP2Agent.exe",
        installed_exe_path=r"C:\Program Files\SP2 Agent\SP2Agent.exe",
    )

    kill_index = script.index("taskkill")
    move_index = script.index("move /y")
    assert kill_index < move_index, "stary proces musi zostać ubity przed podmianą pliku"


def test_build_self_update_script_restarts_task_after_swap():
    script = build_self_update_script(
        new_exe_path="new.exe", installed_exe_path="old.exe", task_name="SP2Agent"
    )

    move_index = script.index("move /y")
    run_index = script.index("schtasks /Run")
    assert move_index < run_index, "zadanie musi wystartować dopiero po podmianie pliku"
    assert '/TN "SP2Agent"' in script


def test_build_self_update_script_deletes_itself_last():
    script = build_self_update_script(new_exe_path="new.exe", installed_exe_path="old.exe")

    lines = [line for line in script.splitlines() if line.strip()]
    assert lines[-1].startswith('del "%~f0"')


def test_build_self_update_script_uses_provided_paths():
    script = build_self_update_script(
        new_exe_path=r"C:\temp\SP2Agent.new.exe",
        installed_exe_path=r"C:\Program Files\SP2 Agent\SP2Agent.exe",
    )

    assert r"C:\temp\SP2Agent.new.exe" in script
    assert r"C:\Program Files\SP2 Agent\SP2Agent.exe" in script


def test_build_self_update_script_respects_custom_task_name():
    script = build_self_update_script(
        new_exe_path="new.exe",
        installed_exe_path=r"C:\Program Files\SP2 Agent\SP2Agent.exe",
        task_name="CustomTask",
    )

    assert 'taskkill /F /IM "SP2Agent.exe"' in script
    assert 'schtasks /Run /TN "CustomTask"' in script

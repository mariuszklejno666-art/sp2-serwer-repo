from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from app.radio_speech import (
    SpeechError,
    build_speech_command,
    generate_speech,
    validate_announcement,
)


def test_announcement_is_normalized_and_limited():
    assert validate_announcement("  Uwaga!\n  Prosimy do sekretariatu. ") == (
        "Uwaga! Prosimy do sekretariatu."
    )
    with pytest.raises(SpeechError, match="Wpisz"):
        validate_announcement("   ")
    with pytest.raises(SpeechError, match="500"):
        validate_announcement("a" * 501)


def test_speech_command_does_not_use_shell(tmp_path):
    output = tmp_path / "announcement.wav"
    command = build_speech_command("/usr/bin/espeak-ng", output, "pl", 165)

    assert command == [
        "/usr/bin/espeak-ng",
        "-v",
        "pl",
        "-s",
        "165",
        "-w",
        str(output),
    ]
    with pytest.raises(SpeechError, match="80"):
        build_speech_command("/usr/bin/espeak-ng", output, "pl", 10)


def test_generate_speech_passes_text_over_stdin(monkeypatch, tmp_path):
    monkeypatch.setattr("app.radio_speech.shutil.which", lambda _binary: "/usr/bin/espeak-ng")

    def fake_run(command, **kwargs):
        Path(command[-1]).write_bytes(b"RIFFgenerated-wave")
        assert kwargs["input"] == "Uwaga! Próba mikrofonu."
        assert kwargs["text"] is True
        assert "shell" not in kwargs
        return Mock(returncode=0)

    monkeypatch.setattr("app.radio_speech.subprocess.run", fake_run)

    result = generate_speech(
        " Uwaga!   Próba mikrofonu. ",
        tmp_path / "speech",
    )

    assert result == tmp_path / "speech" / "announcement.wav"
    assert result.read_bytes() == b"RIFFgenerated-wave"
    if os.name == "posix":
        # os.chmod na Windows nie odwzorowuje bitów uprawnień POSIX (brak
        # pojęcia owner/group/other na NTFS), więc ta asercja ma sens
        # wyłącznie na docelowej platformie serwera (Ubuntu).
        assert result.stat().st_mode & 0o777 == 0o600


def test_generate_speech_requires_installed_binary(monkeypatch, tmp_path):
    monkeypatch.setattr("app.radio_speech.shutil.which", lambda _binary: None)

    with pytest.raises(SpeechError, match="Zainstaluj pakiet espeak-ng"):
        generate_speech("Komunikat", tmp_path)


def test_management_can_play_spoken_announcement(
    app,
    authenticated_client,
    monkeypatch,
    tmp_path,
):
    app.instance_path = str(tmp_path)
    app.config["RADIO_PLAYBACK_ENABLED"] = True
    calls = {}

    def fake_generate(text, output_dir, **options):
        calls["text"] = text
        calls["speech_options"] = options
        output_dir.mkdir(parents=True)
        output = output_dir / "announcement.wav"
        output.write_bytes(b"RIFFwave")
        return output

    def fake_start(**options):
        calls["player_options"] = options

    monkeypatch.setattr("app.school_services.routes.generate_speech", fake_generate)
    monkeypatch.setattr("app.school_services.routes.start_local_playlist", fake_start)

    response = authenticated_client.post(
        "/school-services/radio/announcements/play",
        data={"announcement": "Uwaga! Próba komunikatu."},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Komunikat jest odtwarzany" in response.get_data(as_text=True)
    assert calls["text"] == "Uwaga! Próba komunikatu."
    assert calls["speech_options"]["voice"] == "pl"
    assert calls["player_options"]["playlist_name"] == "Komunikat głosowy"
    assert calls["player_options"]["audio_device"] == "auto"


def test_announcement_playback_stays_disabled_by_default(
    app,
    authenticated_client,
    monkeypatch,
):
    app.config["RADIO_PLAYBACK_ENABLED"] = False
    generator = Mock()
    monkeypatch.setattr("app.school_services.routes.generate_speech", generator)

    response = authenticated_client.post(
        "/school-services/radio/announcements/play",
        data={"announcement": "Test"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "wyłączone w konfiguracji" in response.get_data(as_text=True)
    generator.assert_not_called()

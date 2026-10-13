from __future__ import annotations

import pytest

from app.radio_player import PlaybackError, _validated_tracks, build_player_command


def test_player_command_uses_local_audio_without_shell(tmp_path):
    playlist = tmp_path / "current.m3u8"

    command = build_player_command("/usr/bin/mpv", playlist, "auto")

    assert command[0] == "/usr/bin/mpv"
    assert "--no-video" in command
    assert "--no-terminal" in command
    assert "--audio-device=auto" in command
    assert f"--playlist={playlist}" in command


def test_player_only_accepts_private_uploaded_tracks(tmp_path):
    upload_dir = tmp_path / "radio_uploads"
    upload_dir.mkdir()
    allowed = upload_dir / "track.mp3"
    allowed.write_bytes(b"ID3audio")
    outside = tmp_path / "outside.mp3"
    outside.write_bytes(b"ID3audio")

    assert _validated_tracks([allowed], upload_dir) == [allowed.resolve()]
    with pytest.raises(PlaybackError, match="niedostępny"):
        _validated_tracks([outside], upload_dir)


def test_player_rejects_empty_playlist(tmp_path):
    upload_dir = tmp_path / "radio_uploads"
    upload_dir.mkdir()

    with pytest.raises(PlaybackError, match="nie zawiera"):
        _validated_tracks([], upload_dir)

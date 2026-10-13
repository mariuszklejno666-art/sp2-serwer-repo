from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

import fcntl


class PlaybackError(RuntimeError):
    """Bezpieczny komunikat błędu lokalnego odtwarzacza."""


@dataclass(frozen=True)
class PlaybackStatus:
    running: bool
    pid: int | None = None
    playlist_name: str | None = None
    message: str = "Odtwarzanie zatrzymane."


def _state_path(state_dir: Path) -> Path:
    return state_dir / "playback.json"


@contextmanager
def _locked(state_dir: Path) -> Iterator[None]:
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = state_dir / "playback.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield


def _read_state(state_dir: Path) -> dict[str, object]:
    try:
        return json.loads(_state_path(state_dir).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _process_matches(pid: int, playlist_path: Path) -> bool:
    if pid <= 1:
        return False
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(
            "utf-8", errors="replace"
        )
    except OSError:
        return False
    return "mpv" in command and str(playlist_path) in command


def _status_unlocked(state_dir: Path) -> PlaybackStatus:
    state = _read_state(state_dir)
    try:
        pid = int(state["pid"])
        playlist_path = Path(str(state["playlist_path"]))
    except (KeyError, TypeError, ValueError):
        return PlaybackStatus(running=False)
    if not _process_matches(pid, playlist_path):
        _state_path(state_dir).unlink(missing_ok=True)
        return PlaybackStatus(running=False)
    return PlaybackStatus(
        running=True,
        pid=pid,
        playlist_name=str(state.get("playlist_name") or "Playlista"),
        message="Odtwarzanie przez lokalne wyjście audio jest aktywne.",
    )


def playback_status(state_dir: Path) -> PlaybackStatus:
    with _locked(state_dir):
        return _status_unlocked(state_dir)


def _resolve_player(binary: str) -> str:
    candidate = shutil.which(binary)
    if not candidate:
        raise PlaybackError(
            f"Nie znaleziono odtwarzacza {binary}. Zainstaluj pakiet mpv na serwerze."
        )
    return candidate


def _validated_tracks(tracks: Sequence[Path], upload_dir: Path) -> list[Path]:
    root = upload_dir.resolve()
    validated: list[Path] = []
    for track in tracks:
        resolved = track.resolve()
        if root not in resolved.parents or not resolved.is_file():
            raise PlaybackError("Jeden z plików playlisty jest niedostępny.")
        validated.append(resolved)
    if not validated:
        raise PlaybackError("Playlista nie zawiera żadnych utworów.")
    return validated


def build_player_command(
    executable: str,
    playlist_path: Path,
    audio_device: str,
) -> list[str]:
    return [
        executable,
        "--no-video",
        "--no-terminal",
        "--input-terminal=no",
        "--really-quiet",
        f"--audio-device={audio_device}",
        f"--playlist={playlist_path}",
    ]


def start_playlist(
    *,
    playlist_name: str,
    tracks: Sequence[Path],
    upload_dir: Path,
    state_dir: Path,
    binary: str = "mpv",
    audio_device: str = "auto",
) -> PlaybackStatus:
    executable = _resolve_player(binary)
    validated = _validated_tracks(tracks, upload_dir)

    with _locked(state_dir):
        current = _status_unlocked(state_dir)
        if current.running:
            raise PlaybackError(
                f"Najpierw zatrzymaj playlistę „{current.playlist_name}”."
            )

        playlist_path = state_dir / "current.m3u8"
        playlist_path.write_text(
            "#EXTM3U\n" + "\n".join(str(path) for path in validated) + "\n",
            encoding="utf-8",
        )
        os.chmod(playlist_path, 0o600)
        log_path = state_dir / "player.log"
        with log_path.open("ab") as log:
            process = subprocess.Popen(
                build_player_command(executable, playlist_path, audio_device),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
        state = {
            "pid": process.pid,
            "playlist_name": playlist_name,
            "playlist_path": str(playlist_path),
        }
        _state_path(state_dir).write_text(
            json.dumps(state, ensure_ascii=False),
            encoding="utf-8",
        )
        os.chmod(_state_path(state_dir), 0o600)
        return PlaybackStatus(
            running=True,
            pid=process.pid,
            playlist_name=playlist_name,
            message="Odtwarzanie przez lokalne wyjście audio zostało uruchomione.",
        )


def stop_playback(state_dir: Path) -> bool:
    with _locked(state_dir):
        state = _read_state(state_dir)
        try:
            pid = int(state["pid"])
            playlist_path = Path(str(state["playlist_path"]))
        except (KeyError, TypeError, ValueError):
            _state_path(state_dir).unlink(missing_ok=True)
            return False

        if not _process_matches(pid, playlist_path):
            _state_path(state_dir).unlink(missing_ok=True)
            return False

        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        _state_path(state_dir).unlink(missing_ok=True)
        return True

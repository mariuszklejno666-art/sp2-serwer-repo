from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from uuid import uuid4


class SpeechError(RuntimeError):
    """Bezpieczny komunikat błędu syntezatora mowy."""


def validate_announcement(text: str, max_length: int = 500) -> str:
    normalized = " ".join(str(text).split())
    if not normalized:
        raise SpeechError("Wpisz treść komunikatu.")
    if len(normalized) > max_length:
        raise SpeechError(f"Komunikat może mieć najwyżej {max_length} znaków.")
    return normalized


def build_speech_command(
    executable: str,
    output_path: Path,
    voice: str,
    speed: int,
) -> list[str]:
    if not 80 <= speed <= 450:
        raise SpeechError("Prędkość mowy musi mieścić się w zakresie 80–450.")
    return [
        executable,
        "-v",
        voice,
        "-s",
        str(speed),
        "-w",
        str(output_path),
    ]


def generate_speech(
    text: str,
    output_dir: Path,
    *,
    binary: str = "espeak-ng",
    voice: str = "pl",
    speed: int = 165,
) -> Path:
    announcement = validate_announcement(text)
    executable = shutil.which(binary)
    if not executable:
        raise SpeechError(
            f"Nie znaleziono syntezatora {binary}. Zainstaluj pakiet espeak-ng na serwerze."
        )

    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = output_dir / f"announcement-{uuid4().hex}.wav"
    destination = output_dir / "announcement.wav"
    command = build_speech_command(executable, temporary, voice, speed)

    try:
        subprocess.run(
            command,
            input=announcement,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
        )
        if not temporary.is_file() or temporary.stat().st_size == 0:
            raise SpeechError("Syntezator nie utworzył pliku dźwiękowego.")
        temporary.replace(destination)
        os.chmod(destination, 0o600)
    except subprocess.TimeoutExpired as exc:
        temporary.unlink(missing_ok=True)
        raise SpeechError("Przekroczono czas generowania komunikatu.") from exc
    except subprocess.CalledProcessError as exc:
        temporary.unlink(missing_ok=True)
        raise SpeechError("Nie udało się wygenerować komunikatu głosowego.") from exc
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise SpeechError("Nie udało się zapisać komunikatu głosowego.") from exc

    return destination

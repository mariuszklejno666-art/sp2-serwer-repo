from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename


ALLOWED_AUDIO_EXTENSIONS = {".mp3": "mp3", ".wav": "wav"}


class AudioUploadError(ValueError):
    pass


@dataclass(frozen=True)
class SavedAudio:
    original_filename: str
    stored_filename: str
    media_type: str
    size_bytes: int


def _valid_signature(media_type: str, header: bytes) -> bool:
    if media_type == "wav":
        return len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WAVE"
    if media_type == "mp3":
        return header.startswith(b"ID3") or (
            len(header) >= 2 and header[0] == 0xFF and (header[1] & 0xE0) == 0xE0
        )
    return False


def save_audio_upload(
    upload: FileStorage,
    destination: Path,
    max_bytes: int,
) -> SavedAudio:
    original_filename = secure_filename(upload.filename or "")
    suffix = Path(original_filename).suffix.lower()
    media_type = ALLOWED_AUDIO_EXTENSIONS.get(suffix)
    if not original_filename or media_type is None:
        raise AudioUploadError("Dozwolone są wyłącznie pliki MP3 i WAV.")
    if max_bytes <= 0:
        raise AudioUploadError("Limit rozmiaru pliku jest nieprawidłowy.")

    destination.mkdir(parents=True, exist_ok=True)
    stored_filename = f"{secrets.token_hex(16)}{suffix}"
    target = destination / stored_filename
    size_bytes = 0
    header = b""

    try:
        with target.open("xb") as output:
            while True:
                chunk = upload.stream.read(1024 * 1024)
                if not chunk:
                    break
                size_bytes += len(chunk)
                if size_bytes > max_bytes:
                    raise AudioUploadError(
                        f"Plik przekracza limit {max_bytes // (1024 * 1024)} MB."
                    )
                if len(header) < 12:
                    header = (header + chunk)[:12]
                output.write(chunk)

        if size_bytes == 0:
            raise AudioUploadError("Nie można wgrać pustego pliku.")
        if not _valid_signature(media_type, header):
            raise AudioUploadError("Zawartość pliku nie odpowiada formatowi MP3/WAV.")
    except Exception:
        target.unlink(missing_ok=True)
        raise

    return SavedAudio(
        original_filename=original_filename,
        stored_filename=stored_filename,
        media_type=media_type,
        size_bytes=size_bytes,
    )

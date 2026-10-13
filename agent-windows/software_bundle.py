"""Validate and unpack SP2 installer bundles without executing archive content."""
from __future__ import annotations

import re
import stat
import zipfile
from pathlib import Path

MAX_BYTES = 4 * 1024 * 1024 * 1024


def extract_bundle(archive_path: Path, destination: Path) -> Path:
    with zipfile.ZipFile(archive_path) as archive:
        files = archive.infolist()
        if not 2 <= len(files) <= 32:
            raise ValueError('Pakiet musi zawierać instalator i pliki BIN (maksymalnie 32 pliki).')
        seen = set()
        installers = []
        total = 0
        for item in files:
            name = item.filename
            if (not name or len(name) > 180 or name in {'.', '..'}
                    or re.search(r'[\x00-\x1f<>:"/\\|?*]', name)
                    or name.endswith((' ', '.'))
                    or name.split('.')[0].upper() in {
                        'CON', 'PRN', 'AUX', 'NUL',
                        *(f'COM{i}' for i in range(1, 10)),
                        *(f'LPT{i}' for i in range(1, 10)),
                    }
                    or name.casefold() in seen
                    or item.is_dir() or stat.S_ISLNK(item.external_attr >> 16)
                    or item.flag_bits & 1 or item.compress_type != zipfile.ZIP_STORED):
                raise ValueError('Nieprawidłowy plik w pakiecie instalacyjnym.')
            seen.add(name.casefold())
            suffix = Path(name).suffix.lower()
            if suffix not in {'.exe', '.msi', '.bin'}:
                raise ValueError('Nieobsługiwany plik w pakiecie.')
            if suffix != '.bin':
                installers.append(name)
            total += item.file_size
            if item.file_size <= 0 or total > MAX_BYTES:
                raise ValueError('Nieprawidłowy rozmiar pakietu.')
        if len(installers) != 1:
            raise ValueError('Pakiet musi zawierać dokładnie jeden instalator.')

        written = 0
        for item in files:
            with archive.open(item) as source, (destination / item.filename).open('xb') as target:
                while block := source.read(1024 * 1024):
                    written += len(block)
                    if written > MAX_BYTES:
                        raise ValueError('Przekroczono limit rozpakowanego pakietu.')
                    target.write(block)

    installer = destination / installers[0]
    with installer.open('rb') as handle:
        header = handle.read(8)
    if (installer.suffix.lower() == '.exe' and not header.startswith(b'MZ')) or (
        installer.suffix.lower() == '.msi' and header != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    ):
        raise ValueError('Nieprawidłowa sygnatura instalatora w pakiecie.')
    return installer

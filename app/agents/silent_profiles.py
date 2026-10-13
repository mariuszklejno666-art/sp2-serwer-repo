"""Profile dobierane raz przez administratora; zadania nie uruchamiają kreatorów."""
import re
import zipfile
from pathlib import Path
from .software_catalog import CatalogError, packages_dir

PROFILES = {
    'auto': ('Automatycznie: MSI / Inno Setup / znany instalator', None),
    '7zip': ('7-Zip EXE', ['/S']),
    'vlc': ('VLC EXE', ['/S']),
    'firefox': ('Firefox — pełny instalator EXE', ['/S']),
    'nsis': ('NSIS — potwierdzony typ instalatora', ['/S']),
    'inno': ('Inno Setup — potwierdzony typ instalatora', ['/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-']),
    'custom': ('Własne parametry producenta', None),
    'agent': ('SP2Agent.exe — aktualizacja agenta', []),
}


def _installer_header(path):
    if path is None:
        return b''
    path = Path(path)
    try:
        if path.suffix.lower() == '.zip':
            with zipfile.ZipFile(path) as archive:
                entries = [i for i in archive.infolist() if Path(i.filename).suffix.lower() in {'.exe', '.msi'}]
                if len(entries) != 1:
                    raise CatalogError('Pakiet musi zawierać jeden instalator.')
                with archive.open(entries[0]) as handle:
                    return handle.read(8 * 1024 * 1024)
        with path.open('rb') as handle:
            return handle.read(8 * 1024 * 1024)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise CatalogError('Nie można odczytać instalatora do rozpoznania profilu.') from exc


def resolve_profile(profile, installer_type, filename, arguments, installer_path=None):
    if profile not in PROFILES:
        raise CatalogError('Nieznany profil instalatora.')
    if not isinstance(arguments, list) or not all(isinstance(a, str) and '\x00' not in a for a in arguments):
        raise CatalogError('Nieprawidłowe parametry instalatora.')
    if len(arguments) > 20 or any(len(a) > 2000 for a in arguments):
        raise CatalogError('Zbyt wiele lub zbyt długie parametry instalatora.')
    if profile == 'agent':
        if installer_type != 'exe':
            raise CatalogError('Aktualizacja agenta wymaga pliku EXE.')
        return []
    if installer_type == 'msi':
        return [a for a in arguments if a.lower() not in {'/qn','/quiet','/norestart','reboot=reallysuppress'}] + ['/qn','/norestart','REBOOT=ReallySuppress']
    if profile == 'auto' and not arguments:
        header = _installer_header(installer_path)
        if header.startswith(b'MZ') and b'Inno Setup Setup Data (' in header:
            return list(PROFILES['inno'][1])
        name = filename.lower()
        if re.fullmatch(r'7z[0-9]+(?:[-_]?x64|[-_]?arm64)?\.exe', name) or re.fullmatch(r'vlc-[0-9.]+-win(?:32|64)\.exe', name):
            return ['/S']
        if re.fullmatch(r'firefox setup [0-9][^/\\]*\.exe', name):
            return ['/S']
        return []  # Pakiet zapisany jako niegotowy; administrator wybiera profil.
    preset = PROFILES[profile][1]
    return list(preset) if preset is not None else arguments


def require_silent_package(package):
    if package.get('purpose') == 'agent':
        raise CatalogError('To plik agenta. Użyj aktualizacji agenta zamiast instalacji programu.')
    source_type = package.get('source_type', package['installer_type'])
    if package.get('silent_profile', 'auto') == 'auto' and not package.get('arguments'):
        package['arguments'] = resolve_profile(
            'auto', source_type, package.get('source_filename', package['filename']), [],
            package.get('path') or packages_dir() / package['filename'],
        )
    if source_type == 'exe' and not package.get('arguments'):
        raise CatalogError('Pakiet EXE nie ma profilu instalacji cichej. Ustaw profil w Pakietach oprogramowania; nie uruchomiono niczego na stacjach.')
    if source_type == 'msi':
        package['arguments'] = resolve_profile('auto', 'msi', package['filename'], package.get('arguments', []))
    return package


def require_agent_package(package):
    if package.get('purpose') != 'agent' or package['installer_type'] != 'exe':
        raise CatalogError('Do aktualizacji wybierz pakiet z profilem SP2Agent.exe.')
    return package

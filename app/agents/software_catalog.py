from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import tempfile
from pathlib import Path
from typing import Any

from flask import current_app
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

PACKAGE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ALLOWED_INSTALLER_TYPES = {"exe", "msi", "zip"}
ALLOWED_UPLOAD_EXTENSIONS = {".exe": "exe", ".msi": "msi"}
MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024
MAX_PACKAGE_FILES = 128
MULTIFILE_AGENT_VERSION = (2, 8, 0)


class CatalogError(ValueError):
    pass


def catalog_path() -> Path:
    return Path(current_app.instance_path) / "software-catalog.json"


def packages_dir() -> Path:
    path = Path(current_app.instance_path) / "software-packages"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_filename(value: str) -> str:
    name = Path(value).name
    if name != value or not name:
        raise CatalogError("Nieprawidłowa nazwa pliku pakietu.")
    return name


def _safe_upload_filename(value: str) -> str:
    """Zachowuje oryginalną nazwę wymaganą przez instalator, blokując traversal."""
    name = str(value or "").strip()
    if (
        not name
        or len(name) > 240
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or any(ord(ch) < 32 for ch in name)
        or any(ch in '<>:"|?*' for ch in name)
        or name.endswith((" ", "."))
    ):
        raise CatalogError(f"Nieprawidłowa nazwa pliku pakietu: {name or '(pusta)'}.")
    return name


def _valid_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[a-f0-9]{64}", value))


def _normalize_file_entries(raw_files: Any) -> list[dict[str, Any]]:
    if raw_files in (None, []):
        return []
    if not isinstance(raw_files, list) or len(raw_files) > MAX_PACKAGE_FILES:
        raise CatalogError("Nieprawidłowa lista plików pakietu.")

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in raw_files:
        if not isinstance(raw, dict):
            raise CatalogError("Nieprawidłowy wpis pliku pakietu.")
        filename = _safe_upload_filename(str(raw.get("filename", "")))
        key = filename.casefold()
        if key in seen:
            raise CatalogError(f"Powtórzona nazwa pliku w pakiecie: {filename}.")
        seen.add(key)

        sha256 = str(raw.get("sha256", "")).strip().lower()
        if not _valid_sha256(sha256):
            raise CatalogError(f"Nieprawidłowa suma SHA-256 pliku {filename}.")
        try:
            size = int(raw.get("size", 0))
        except (TypeError, ValueError) as exc:
            raise CatalogError(f"Nieprawidłowy rozmiar pliku {filename}.") from exc
        if size < 0 or size > MAX_PACKAGE_BYTES:
            raise CatalogError(f"Nieprawidłowy rozmiar pliku {filename}.")

        normalized.append({"filename": filename, "sha256": sha256, "size": size})
    return normalized


def load_catalog() -> dict[str, dict[str, Any]]:
    path = catalog_path()
    if not path.exists():
        return {}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"Nie można odczytać katalogu oprogramowania: {exc}") from exc

    items = raw.get("packages", []) if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise CatalogError("Pole packages musi być listą.")

    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        package_id = str(item.get("id", "")).strip().lower()
        if not PACKAGE_ID_RE.fullmatch(package_id):
            continue
        try:
            filename = _safe_upload_filename(str(item.get("filename", "")).strip())
            files = _normalize_file_entries(item.get("files", []))
        except CatalogError:
            continue

        installer_type = str(item.get("installer_type", "")).strip().lower()
        if installer_type not in ALLOWED_INSTALLER_TYPES:
            continue
        arguments = item.get("arguments", [])
        if not isinstance(arguments, list) or not all(isinstance(v, str) for v in arguments):
            continue
        sha256 = str(item.get("sha256", "")).strip().lower()
        if not _valid_sha256(sha256):
            continue

        storage_dir = str(item.get("storage_dir", "")).strip()
        if storage_dir:
            try:
                storage_dir = _safe_upload_filename(storage_dir)
            except CatalogError:
                continue
        if files:
            installer = next(
                (entry for entry in files if entry["filename"].casefold() == filename.casefold()),
                None,
            )
            if installer is None or installer["sha256"] != sha256 or not storage_dir:
                continue

        result[package_id] = {
            "id": package_id,
            "purpose": item.get(
                "purpose",
                "agent" if package_id in {"agent", "sp2-agent"} else "software",
            ),
            "silent_profile": item.get(
                "silent_profile", "custom" if arguments else "auto"
            ),
            "name": str(item.get("name", package_id)).strip()[:120],
            "version": str(item.get("version", "")).strip()[:60],
            "description": str(item.get("description", "")).strip()[:300],
            "filename": filename,
            "source_filename": str(item.get("source_filename", filename)),
            "source_type": str(item.get("source_type", installer_type)),
            "file_names": item.get("file_names", []),
            "installer_type": installer_type,
            "arguments": arguments[:20],
            "sha256": sha256,
            "enabled": bool(item.get("enabled", True)),
            "storage_dir": storage_dir,
            "files": files,
        }
    return result


def _package_file_entries(package: dict[str, Any]) -> list[dict[str, Any]]:
    files = list(package.get("files") or [])
    if files:
        return files
    # Starszy katalog przechowywał tylko instalator. Rozmiar jest ustalany z dysku.
    file_path = packages_dir() / package["filename"]
    size = file_path.stat().st_size if file_path.is_file() else 0
    return [{
        "filename": package["filename"],
        "sha256": package["sha256"],
        "size": size,
    }]


def _package_file_path(package: dict[str, Any], filename: str) -> Path:
    safe_name = _safe_upload_filename(filename)
    storage_dir = str(package.get("storage_dir") or "")
    if storage_dir:
        return packages_dir() / storage_dir / safe_name
    if safe_name.casefold() != str(package["filename"]).casefold():
        raise CatalogError("Starszy pakiet nie zawiera wskazanego pliku.")
    return packages_dir() / package["filename"]


def available_packages() -> list[dict[str, Any]]:
    packages = []
    for item in load_catalog().values():
        entries = _package_file_entries(item)
        paths = [_package_file_path(item, entry["filename"]) for entry in entries]
        all_present = bool(paths) and all(path.is_file() for path in paths)
        copy = dict(item)
        copy["file_exists"] = all_present
        copy["path"] = _package_file_path(item, item["filename"])
        legacy_bundle = item["installer_type"] == "zip"
        copy["legacy_bundle"] = legacy_bundle
        copy["file_count"] = (
            max(len(entries), len(item.get("file_names") or []))
            if legacy_bundle
            else len(entries)
        )
        copy["is_multifile"] = len(entries) > 1 or legacy_bundle
        copy["file_size"] = (
            sum(path.stat().st_size for path in paths) if all_present else None
        )
        from .silent_profiles import require_silent_package
        try:
            require_silent_package(copy)
            copy["silent_ready"] = True
        except CatalogError:
            copy["silent_ready"] = False
        packages.append(copy)
    return sorted(packages, key=lambda p: p["name"].lower())


def get_installable_package(package_id: str) -> dict[str, Any]:
    package_id = package_id.strip().lower()
    package = load_catalog().get(package_id)
    if not package or not package["enabled"]:
        raise CatalogError("Pakiet nie istnieje albo jest wyłączony.")

    entries = _package_file_entries(package)
    total_size = 0
    resolved: list[dict[str, Any]] = []
    installer_path: Path | None = None

    for entry in entries:
        file_path = _package_file_path(package, entry["filename"])
        if not file_path.is_file():
            raise CatalogError(f"Brak wymaganego pliku pakietu: {entry['filename']}.")
        size = file_path.stat().st_size
        if size < 0:
            raise CatalogError("Nieprawidłowy rozmiar pakietu.")
        total_size += size
        if total_size > MAX_PACKAGE_BYTES:
            raise CatalogError("Pakiet przekracza limit 4 GB.")

        expected_size = int(entry.get("size", 0) or 0)
        if expected_size and size != expected_size:
            raise CatalogError(f"Rozmiar pliku {entry['filename']} nie zgadza się z katalogiem.")

        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest().lower() != entry["sha256"]:
            raise CatalogError(f"Suma SHA-256 pliku {entry['filename']} nie zgadza się z katalogiem.")

        resolved_entry = {
            "filename": entry["filename"],
            "sha256": entry["sha256"],
            "size": size,
        }
        resolved.append(resolved_entry)
        if entry["filename"].casefold() == package["filename"].casefold():
            installer_path = file_path

    if installer_path is None:
        raise CatalogError("W pakiecie brakuje głównego instalatora.")

    copy = dict(package)
    copy["path"] = installer_path
    copy["size"] = total_size
    copy["files"] = resolved
    copy["legacy_bundle"] = package["installer_type"] == "zip"
    copy["file_count"] = (
        max(len(resolved), len(package.get("file_names") or []))
        if copy["legacy_bundle"]
        else len(resolved)
    )
    copy["is_multifile"] = len(resolved) > 1 or copy["legacy_bundle"]
    return copy


def get_package_file_by_index(package_id: str, file_index: int) -> tuple[Path, dict[str, Any]]:
    package_id = package_id.strip().lower()
    package = load_catalog().get(package_id)
    if not package or not package["enabled"]:
        raise CatalogError("Pakiet nie istnieje albo jest wyłączony.")

    entries = _package_file_entries(package)
    if file_index < 0 or file_index >= len(entries):
        raise CatalogError("Plik pakietu nie istnieje.")
    entry = entries[file_index]
    file_path = _package_file_path(package, entry["filename"])
    if not file_path.is_file():
        raise CatalogError("Plik pakietu nie istnieje.")
    size = file_path.stat().st_size
    expected_size = int(entry.get("size", 0) or 0)
    if expected_size and size != expected_size:
        raise CatalogError("Rozmiar pliku pakietu nie zgadza się z katalogiem.")
    return file_path, {**entry, "size": size}


def save_catalog(packages: dict[str, dict[str, Any]]) -> None:
    payload = {"packages": list(packages.values())}
    path = catalog_path()
    fd, name = tempfile.mkstemp(prefix=".catalog-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def add_package(
    *,
    package_id: str,
    name: str,
    version: str,
    description: str,
    filename: str,
    installer_type: str,
    arguments: list[str],
    sha256: str,
    storage_dir: str = "",
    files: list[dict[str, Any]] | None = None,
    purpose: str = "software",
    silent_profile: str = "custom",
    source_filename: str = "",
    source_type: str = "",
    file_names: list[str] | None = None,
) -> None:
    package_id = package_id.strip().lower()
    if not PACKAGE_ID_RE.fullmatch(package_id):
        raise CatalogError(
            "Identyfikator pakietu: małe litery, cyfry, kropki, myślniki, "
            "podkreślenia (do 64 znaków)."
        )
    filename = _safe_upload_filename(filename)
    if installer_type not in ALLOWED_INSTALLER_TYPES:
        raise CatalogError("Nieobsługiwany typ instalatora.")
    sha256 = sha256.strip().lower()
    if not _valid_sha256(sha256):
        raise CatalogError("Nieprawidłowa suma SHA-256.")

    normalized_files = _normalize_file_entries(files or [])
    storage_dir = str(storage_dir or "").strip()
    if normalized_files:
        storage_dir = _safe_upload_filename(storage_dir)
        installer = next(
            (entry for entry in normalized_files if entry["filename"].casefold() == filename.casefold()),
            None,
        )
        if installer is None:
            raise CatalogError("Lista plików nie zawiera głównego instalatora.")
        if installer["sha256"] != sha256:
            raise CatalogError("Suma głównego instalatora nie zgadza się z listą plików.")
    elif storage_dir:
        raise CatalogError("Katalog pakietu wymaga listy plików.")

    packages = load_catalog()
    if package_id in packages:
        raise CatalogError(f"Pakiet o identyfikatorze „{package_id}” już istnieje.")

    packages[package_id] = {
        "id": package_id,
        "purpose": (
            "agent"
            if purpose == "agent" or package_id in {"agent", "sp2-agent"}
            else "software"
        ),
        "silent_profile": silent_profile,
        "name": name.strip()[:120] or package_id,
        "version": version.strip()[:60],
        "description": description.strip()[:300],
        "filename": filename,
        "source_filename": source_filename or filename,
        "source_type": source_type or installer_type,
        "file_names": file_names or [entry["filename"] for entry in normalized_files],
        "installer_type": installer_type,
        "arguments": arguments[:20],
        "sha256": sha256,
        "enabled": True,
        "storage_dir": storage_dir,
        "files": normalized_files,
    }
    save_catalog(packages)


def toggle_package(package_id: str) -> dict[str, Any]:
    packages = load_catalog()
    package = packages.get(package_id.strip().lower())
    if package is None:
        raise CatalogError("Pakiet nie istnieje.")
    package["enabled"] = not package["enabled"]
    save_catalog(packages)
    return package


def delete_package(package_id: str) -> dict[str, Any]:
    packages = load_catalog()
    package = packages.pop(package_id.strip().lower(), None)
    if package is None:
        raise CatalogError("Pakiet nie istnieje.")
    save_catalog(packages)
    return package


def remove_package_files(package: dict[str, Any]) -> None:
    storage_dir = str(package.get("storage_dir") or "")
    if storage_dir:
        shutil.rmtree(packages_dir() / storage_dir, ignore_errors=True)
    else:
        (packages_dir() / package["filename"]).unlink(missing_ok=True)


def _valid_installer_signature(installer_type: str, header: bytes) -> bool:
    if installer_type == "exe":
        return len(header) >= 2 and header[:2] == b"MZ"
    if installer_type == "msi":
        return len(header) >= 8 and header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    return False


def _save_upload_stream(
    upload: FileStorage,
    target: Path,
    *,
    max_bytes: int,
    capture_header: bool = False,
) -> tuple[int, str, bytes]:
    digest = hashlib.sha256()
    size_bytes = 0
    header = b""
    with target.open("xb") as output:
        while True:
            chunk = upload.stream.read(1024 * 1024)
            if not chunk:
                break
            size_bytes += len(chunk)
            if size_bytes > max_bytes:
                raise CatalogError("Pakiet przekracza limit 4 GB.")
            if capture_header and len(header) < 8:
                header = (header + chunk)[:8]
            digest.update(chunk)
            output.write(chunk)
    return size_bytes, digest.hexdigest(), header


def save_package_uploads(
    package_id: str,
    installer_upload: FileStorage,
    support_uploads: list[FileStorage],
    max_bytes: int = MAX_PACKAGE_BYTES,
) -> tuple[str, str, str, int, str, list[dict[str, Any]]]:
    """Zapisuje pełny pakiet instalacyjny w osobnym katalogu.

    Główny EXE/MSI oraz wszystkie pliki towarzyszące są zachowywane pod
    oryginalnymi nazwami, aby instalator mógł znaleźć BIN/CAB/DAT/DLL obok siebie.
    """
    package_id = package_id.strip().lower()
    if not PACKAGE_ID_RE.fullmatch(package_id):
        raise CatalogError("Nieprawidłowy identyfikator pakietu.")
    if max_bytes <= 0:
        raise CatalogError("Limit rozmiaru pakietu jest nieprawidłowy.")

    installer_filename = _safe_upload_filename(installer_upload.filename or "")
    installer_type = ALLOWED_UPLOAD_EXTENSIONS.get(Path(installer_filename).suffix.lower())
    if installer_type is None:
        raise CatalogError("Główny instalator musi być plikiem EXE albo MSI.")

    uploads = [installer_upload] + [
        upload for upload in support_uploads if upload is not None and upload.filename
    ]
    if len(uploads) > MAX_PACKAGE_FILES:
        raise CatalogError(f"Pakiet może zawierać maksymalnie {MAX_PACKAGE_FILES} plików.")

    names: list[str] = []
    seen: set[str] = set()
    for upload in uploads:
        filename = _safe_upload_filename(upload.filename or "")
        key = filename.casefold()
        if key in seen:
            raise CatalogError(f"Powtórzona nazwa pliku: {filename}.")
        seen.add(key)
        names.append(filename)

    storage_dir = f"{package_id}-{secrets.token_hex(8)}"
    target_dir = packages_dir() / storage_dir
    target_dir.mkdir(parents=False, exist_ok=False)

    entries: list[dict[str, Any]] = []
    total_size = 0
    installer_sha = ""
    try:
        for index, (upload, filename) in enumerate(zip(uploads, names)):
            remaining = max_bytes - total_size
            if remaining <= 0:
                raise CatalogError("Pakiet przekracza limit 4 GB.")
            size, sha256, header = _save_upload_stream(
                upload,
                target_dir / filename,
                max_bytes=remaining,
                capture_header=index == 0,
            )
            if index == 0:
                if size <= 0:
                    raise CatalogError("Nie można wgrać pustego instalatora.")
                if not _valid_installer_signature(installer_type, header):
                    raise CatalogError("Zawartość głównego pliku nie odpowiada formatowi EXE/MSI.")
                installer_sha = sha256
            total_size += size
            entries.append({"filename": filename, "sha256": sha256, "size": size})
    except Exception:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise

    return (
        storage_dir,
        installer_filename,
        installer_type,
        total_size,
        installer_sha,
        entries,
    )


def save_installer_upload(
    upload: FileStorage,
    max_bytes: int = MAX_PACKAGE_BYTES,
) -> tuple[str, str, int, str]:
    """Wstecznie zgodny zapis pojedynczego instalatora."""
    original_filename = secure_filename(upload.filename or "")
    suffix = Path(original_filename).suffix.lower()
    installer_type = ALLOWED_UPLOAD_EXTENSIONS.get(suffix)
    if not original_filename or installer_type is None:
        raise CatalogError("Dozwolone są wyłącznie pliki EXE i MSI.")
    if max_bytes <= 0:
        raise CatalogError("Limit rozmiaru pakietu jest nieprawidłowy.")

    stored_filename = f"{secrets.token_hex(16)}{suffix}"
    target = packages_dir() / stored_filename
    try:
        size_bytes, sha256, header = _save_upload_stream(
            upload, target, max_bytes=max_bytes, capture_header=True
        )
        if size_bytes == 0:
            raise CatalogError("Nie można wgrać pustego pliku.")
        if not _valid_installer_signature(installer_type, header):
            raise CatalogError("Zawartość pliku nie odpowiada formatowi EXE/MSI.")
    except Exception:
        target.unlink(missing_ok=True)
        raise

    return stored_filename, installer_type, size_bytes, sha256


def _agent_version(version: str | None) -> tuple[int, int, int] | None:
    match = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)", str(version or ""))
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def agent_supports_multifile(version: str | None) -> bool:
    parsed = _agent_version(version)
    return parsed is not None and parsed >= MULTIFILE_AGENT_VERSION


def agent_supports_legacy_bundle(version: str | None) -> bool:
    parsed = _agent_version(version)
    return parsed is not None and parsed >= (2, 7, 1)

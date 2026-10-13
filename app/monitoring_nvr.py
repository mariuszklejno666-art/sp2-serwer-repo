from __future__ import annotations

import socket
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class NvrEndpoint:
    """Rejestrator NVR/DVR dostępny we własnym panelu webowym urządzenia."""

    name: str
    host: str
    port: int = 80


def parse_nvr_endpoints(values: tuple[str, ...]) -> tuple[NvrEndpoint, ...]:
    """Parsuje wpisy "Nazwa=host" lub "Nazwa=host:port" (domyślnie port 80)."""
    endpoints: list[NvrEndpoint] = []
    for value in values:
        name, separator, target = value.partition("=")
        name, target = name.strip(), target.strip()
        if not (separator and name and target):
            continue
        host, _, port_text = target.partition(":")
        host = host.strip()
        if not host:
            continue
        port = 80
        if port_text:
            try:
                port = int(port_text)
            except ValueError:
                continue
        endpoints.append(NvrEndpoint(name=name[:80], host=host[:255], port=port))
    return tuple(endpoints)


def panel_url(endpoint: NvrEndpoint) -> str:
    scheme = "https" if endpoint.port == 443 else "http"
    return f"{scheme}://{endpoint.host}:{endpoint.port}/"


def check_nvr(endpoint: NvrEndpoint, timeout: float = 1.5) -> dict[str, object]:
    """Sprawdza wyłącznie dostępność portu panelu webowego rejestratora.

    Nie loguje się do urządzenia i nie pobiera obrazu — to tylko test
    osiągalności, analogiczny do sprawdzenia SMB dla dysków sieciowych.
    """
    try:
        with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout):
            reachable, message = True, f"Panel odpowiada na porcie {endpoint.port}"
    except OSError as exc:
        reachable, message = False, f"Brak połączenia z panelem: {exc}"
    return {
        "name": endpoint.name,
        "host": endpoint.host,
        "port": endpoint.port,
        "reachable": reachable,
        "message": message,
        "panel_url": panel_url(endpoint),
    }


class SnapshotError(RuntimeError):
    """Pobranie migawki z rejestratora nie powiodło się."""


def fetch_snapshot(
    *,
    endpoint: NvrEndpoint,
    username: str,
    password: str,
    channel: int = 1,
    timeout: float = 5.0,
) -> tuple[bytes, str]:
    """Pobiera pojedynczą migawkę JPEG z kanału Hikvision przez ISAPI.

    Poświadczenia (konto tylko-do-podglądu, nie administracyjne) są znane
    wyłącznie serwerowi — obraz trafia do przeglądarki jako zwykłe bajty,
    hasło nigdy jej nie dociera.
    """
    scheme = "https" if endpoint.port == 443 else "http"
    url = f"{scheme}://{endpoint.host}:{endpoint.port}/ISAPI/Streaming/channels/{channel}01/picture"

    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, url, username, password)
    opener = urllib.request.build_opener(
        urllib.request.HTTPDigestAuthHandler(password_manager),
        urllib.request.HTTPBasicAuthHandler(password_manager),
    )
    try:
        with opener.open(url, timeout=timeout) as response:
            content_type = response.headers.get("Content-Type", "image/jpeg")
            data = response.read()
    except (urllib.error.URLError, OSError) as exc:
        raise SnapshotError(f"Nie udało się pobrać migawki: {exc}") from exc

    if not data:
        raise SnapshotError("Rejestrator zwrócił pustą odpowiedź.")
    return data, content_type

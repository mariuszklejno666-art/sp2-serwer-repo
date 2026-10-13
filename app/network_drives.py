from __future__ import annotations

import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class NasEndpoint:
    name: str
    host: str


def parse_nas_endpoints(values: tuple[str, ...]) -> tuple[NasEndpoint, ...]:
    endpoints: list[NasEndpoint] = []
    for value in values:
        name, separator, host = value.partition("=")
        name, host = name.strip(), host.strip()
        if separator and name and host:
            endpoints.append(NasEndpoint(name=name[:80], host=host[:255]))
    return tuple(endpoints)


def check_smb(endpoint: NasEndpoint, timeout: float = 1.5) -> dict[str, object]:
    try:
        with socket.create_connection((endpoint.host, 445), timeout=timeout):
            reachable, message = True, "SMB odpowiada na porcie 445"
    except OSError as exc:
        reachable, message = False, f"Brak połączenia SMB: {exc}"
    return {
        "name": endpoint.name,
        "host": endpoint.host,
        "reachable": reachable,
        "message": message,
    }


@dataclass(frozen=True)
class ShareGroupMapping:
    """Oczekiwane powiązanie udziału sieciowego z grupą AD."""

    share: str
    group: str


def parse_share_group_mappings(values: tuple[str, ...]) -> tuple[ShareGroupMapping, ...]:
    mappings: list[ShareGroupMapping] = []
    for value in values:
        share, separator, group = value.partition("=")
        share, group = share.strip(), group.strip()
        if separator and share and group:
            mappings.append(ShareGroupMapping(share=share[:80], group=group[:255]))
    return tuple(mappings)


def _group_sam_account_name(group: dict[str, object]) -> str:
    value = group.get("sAMAccountName")
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value) if value else ""


def _group_member_count(group: dict[str, object]) -> int:
    members = group.get("member", [])
    if not isinstance(members, list):
        members = [members] if members else []
    return len(members)


def audit_share_group_mappings(
    mappings: tuple[ShareGroupMapping, ...],
    ad_groups: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Sprawdza w danych już pobranych z AD, czy oczekiwane grupy istnieją.

    To wyłącznie audyt spójności katalogu (grupa istnieje i ma członków) —
    nie sprawdza faktycznych uprawnień do udziału na serwerze NAS, bo panel
    nie ma do tego osobnych poświadczeń administracyjnych.
    """
    by_name = {_group_sam_account_name(item).casefold(): item for item in ad_groups}
    results: list[dict[str, object]] = []
    for mapping in mappings:
        group = by_name.get(mapping.group.casefold())
        results.append(
            {
                "share": mapping.share,
                "group": mapping.group,
                "found": group is not None,
                "member_count": _group_member_count(group) if group else 0,
            }
        )
    return results

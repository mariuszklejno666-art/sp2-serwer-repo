from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

# HOST-RESOURCES-MIB::hrStorageTable — standardowe OID-y wspierane przez QNAP
# i praktycznie każdy NAS/serwer z włączonym SNMP.
HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
HR_STORAGE_ALLOCATION_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"
# hrStorageFixedDisk — samo to nie wystarcza jako filtr: na QNAP obejmuje
# też wewnętrzne punkty montowania systemu (/tmp, /usr, /home...) oraz
# osobny wpis dla KAŻDEJ migawki (/mnt/snapshot/1/100xx — to ten sam
# wolumin widziany wielokrotnie). Zweryfikowane na żywo na 192.168.0.203.
HR_STORAGE_FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"
# Prawdziwe, przyrostowe woluminy danych na QNAP mają zawsze tę postać.
QNAP_DATA_VOLUME_RE = re.compile(r"^/share/CACHEDEV\d+_DATA$")


class SnmpError(RuntimeError):
    """Odczyt SNMP z rejestratora/NAS nie powiódł się."""


@dataclass(frozen=True)
class VolumeUsage:
    """Zapełnienie pojedynczego woluminu dyskowego (nie pojedynczego udziału —
    wiele udziałów SMB może leżeć na tym samym woluminie i dzielić ten sam
    wynik)."""

    label: str
    total_bytes: int
    used_bytes: int
    percent_used: float


def aggregate_storage_columns(
    *,
    types: dict[str, object],
    descrs: dict[str, object],
    units: dict[str, object],
    sizes: dict[str, object],
    useds: dict[str, object],
) -> list[VolumeUsage]:
    """Łączy kolumny hrStorageTable pobrane przez SNMP w listę woluminów.

    Czysta funkcja bez I/O — łatwa do przetestowania niezależnie od
    faktycznego pobierania danych przez SNMP.
    """
    volumes: list[VolumeUsage] = []
    for index, storage_type in types.items():
        if str(storage_type) != HR_STORAGE_FIXED_DISK:
            continue
        if not QNAP_DATA_VOLUME_RE.match(str(descrs.get(index, ""))):
            continue
        try:
            alloc_units = int(units[index])
            size = int(sizes[index])
            used = int(useds[index])
        except (KeyError, ValueError, TypeError):
            continue
        if size <= 0 or alloc_units <= 0:
            continue

        total_bytes = size * alloc_units
        used_bytes = used * alloc_units
        volumes.append(
            VolumeUsage(
                label=str(descrs.get(index, index)),
                total_bytes=total_bytes,
                used_bytes=used_bytes,
                percent_used=round(used_bytes / total_bytes * 100, 1),
            )
        )
    return sorted(volumes, key=lambda item: item.label)


async def _walk_column(engine, community, target, oid: str) -> dict[str, object]:
    from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, bulk_walk_cmd

    result: dict[str, object] = {}
    async for error_indication, error_status, _error_index, var_binds in bulk_walk_cmd(
        engine,
        community,
        target,
        ContextData(),
        0,
        25,
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False,
    ):
        if error_indication:
            raise SnmpError(str(error_indication))
        if error_status and int(error_status) != 0:
            raise SnmpError(f"Błąd SNMP: {error_status.prettyPrint()}")
        for name, value in var_binds:
            name_str = str(name)
            if not name_str.startswith(oid + "."):
                continue
            result[name_str[len(oid) + 1 :]] = value
    return result


async def _fetch_storage_columns(
    host: str, community: str, port: int, timeout: float
) -> tuple[dict, dict, dict, dict, dict]:
    from pysnmp.hlapi.v3arch.asyncio import CommunityData, SnmpEngine, UdpTransportTarget

    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=1)  # SNMPv2c
    target = await UdpTransportTarget.create((host, port), timeout=timeout, retries=1)

    types = await _walk_column(engine, auth, target, HR_STORAGE_TYPE)
    descrs = await _walk_column(engine, auth, target, HR_STORAGE_DESCR)
    units = await _walk_column(engine, auth, target, HR_STORAGE_ALLOCATION_UNITS)
    sizes = await _walk_column(engine, auth, target, HR_STORAGE_SIZE)
    useds = await _walk_column(engine, auth, target, HR_STORAGE_USED)
    return types, descrs, units, sizes, useds


def fetch_storage_usage(
    host: str, community: str, port: int = 161, timeout: float = 3.0
) -> list[VolumeUsage]:
    """Odczytuje zapełnienie woluminów NAS przez SNMP tylko-do-odczytu.

    Wymaga wyłącznie community string do odczytu statystyk — to nie jest
    hasło do panelu administracyjnego NAS-a.
    """
    try:
        types, descrs, units, sizes, useds = asyncio.run(
            _fetch_storage_columns(host, community, port, timeout)
        )
    except SnmpError:
        raise
    except Exception as exc:
        raise SnmpError(f"Odczyt SNMP z {host} nie powiódł się: {exc}") from exc

    return aggregate_storage_columns(
        types=types, descrs=descrs, units=units, sizes=sizes, useds=useds
    )

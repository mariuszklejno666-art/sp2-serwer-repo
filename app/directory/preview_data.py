"""Synthetic directory records for an isolated, read-only SP2 preview."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import AgentComputer


DOMAIN = "DC=sp2,DC=test"
USER_OU = f"OU=Nauczyciele,OU=Uzytkownicy,{DOMAIN}"
COMPUTER_OU = f"OU=Komputery,{DOMAIN}"
GROUP_OU = f"OU=Grupy,{DOMAIN}"


def _record(dn: str, **attributes: object) -> dict[str, object]:
    return {"dn": dn, "distinguishedName": dn, **attributes}


_USERS = [
    _record(
        f"CN=Anna Testowa,{USER_OU}",
        sAMAccountName="anna.testowa",
        displayName="Anna Testowa (demo)",
        givenName="Anna",
        sn="Testowa",
        mail="anna.testowa@example.invalid",
        department="Nauczyciele",
        title="Nauczyciel",
        userAccountControl=512,
        memberOf=[f"CN=GRP-Nauczyciele,{GROUP_OU}"],
        lastLogonTimestamp="2026-09-21 08:10:00",
    ),
    _record(
        f"CN=Piotr Przykladowy,{USER_OU}",
        sAMAccountName="piotr.przykladowy",
        displayName="Piotr Przykładowy (demo)",
        givenName="Piotr",
        sn="Przykładowy",
        mail="piotr.przykladowy@example.invalid",
        department="Nauczyciele",
        title="Nauczyciel",
        userAccountControl=512,
        memberOf=[f"CN=GRP-Nauczyciele,{GROUP_OU}"],
    ),
    _record(
        f"CN=Konto Pokazowe,OU=Uzytkownicy,{DOMAIN}",
        sAMAccountName="konto.pokazowe",
        displayName="Konto Pokazowe (demo)",
        userAccountControl=514,
        memberOf=[],
    ),
]

_GROUPS = [
    _record(
        f"CN=GRP-Nauczyciele,{GROUP_OU}",
        sAMAccountName="GRP-Nauczyciele",
        description="Przykładowa grupa nauczycieli",
        member=[_USERS[0]["dn"], _USERS[1]["dn"]],
    ),
    _record(
        f"CN=GRP-Pracownie,{GROUP_OU}",
        sAMAccountName="GRP-Pracownie",
        description="Przykładowa grupa sal komputerowych",
        member=[],
    ),
]

_OUS = [
    _record(f"OU=Uzytkownicy,{DOMAIN}", ou="Uzytkownicy"),
    _record(USER_OU, ou="Nauczyciele"),
    _record(COMPUTER_OU, ou="Komputery"),
    _record(f"OU=Sala11,{COMPUTER_OU}", ou="Sala11"),
    _record(f"OU=Sala32,{COMPUTER_OU}", ou="Sala32"),
    _record(f"OU=Nauczyciele,{COMPUTER_OU}", ou="Nauczyciele"),
    _record(f"OU=Administracja,{COMPUTER_OU}", ou="Administracja"),
    _record(GROUP_OU, ou="Grupy"),
]

_COMPUTERS = [
    _record(
        f"CN=DEMO-S11-01,OU=Sala11,{COMPUTER_OU}",
        sAMAccountName="DEMO-S11-01$",
        dNSHostName="demo-s11-01.sp2.test",
        operatingSystem="Windows 11 Pro",
        operatingSystemVersion="23H2",
        description="Stanowisko pokazowe, bez połączenia z domeną",
        userAccountControl=4096,
        memberOf=[],
        lastLogonTimestamp="2026-09-21 08:00:00",
    ),
    _record(
        f"CN=DEMO-S11-02,OU=Sala11,{COMPUTER_OU}",
        sAMAccountName="DEMO-S11-02$",
        dNSHostName="demo-s11-02.sp2.test",
        operatingSystem="Windows 10 Pro",
        description="Przykład stacji offline",
        userAccountControl=4096,
        memberOf=[],
    ),
    _record(
        f"CN=DEMO-S32-01,OU=Sala32,{COMPUTER_OU}",
        sAMAccountName="DEMO-S32-01$",
        dNSHostName="demo-s32-01.sp2.test",
        operatingSystem="Windows 11 Pro",
        userAccountControl=4096,
        memberOf=[],
    ),
]


def _filter(records: list[dict[str, object]], query: str, fields: tuple[str, ...], limit: int) -> list[dict[str, object]]:
    needle = query.strip().casefold()
    matching = [
        deepcopy(item)
        for item in records
        if not needle or any(needle in str(item.get(field, "")).casefold() for field in fields)
    ]
    return matching[:limit] if limit > 0 else matching


def users(query: str = "", limit: int = 500) -> list[dict[str, object]]:
    return _filter(_USERS, query, ("sAMAccountName", "displayName", "mail"), limit)


def groups(query: str = "", limit: int = 500) -> list[dict[str, object]]:
    return _filter(_GROUPS, query, ("sAMAccountName",), limit)


def computers(query: str = "", limit: int = 500) -> list[dict[str, object]]:
    return _filter(_COMPUTERS, query, ("sAMAccountName", "dNSHostName"), limit)


def organizational_units(query: str = "", limit: int = 500) -> list[dict[str, object]]:
    records = _filter(_OUS, query, ("ou",), limit)
    for item in records:
        dn = str(item["dn"]).casefold()
        item["counts"] = {
            "users": sum(str(user["dn"]).split(",", 1)[1].casefold() == dn for user in _USERS),
            "computers": sum(str(pc["dn"]).split(",", 1)[1].casefold() == dn for pc in _COMPUTERS),
            "ous": sum(str(ou["dn"]).split(",", 1)[1].casefold() == dn for ou in _OUS),
        }
    return records


def seed_agents() -> int:
    """Insert idempotent example agents into the separately guarded preview DB."""
    now = datetime.now(timezone.utc)
    examples = (
        ("DEMO-S11-01", "Sala11", 0, 64),
        ("DEMO-S11-02", "Sala11", 1800, 95),
        ("DEMO-S32-01", "Sala32", 0, 37),
    )
    created = 0
    for hostname, room, age_seconds, disk_used in examples:
        existing = db.session.scalar(
            db.select(AgentComputer).where(AgentComputer.hostname == hostname)
        )
        if existing is not None:
            continue
        db.session.add(
            AgentComputer(
                hostname=hostname,
                fqdn=f"{hostname.lower()}.sp2.test",
                room=room,
                ou=f"OU={room},{COMPUTER_OU}",
                os_name="Windows 11 Pro",
                agent_version="demo",
                ip_addresses=["192.0.2.11"],
                disks=[{"mount": "C:", "percent_used": disk_used, "total_bytes": 256 * 1073741824, "free_bytes": int(256 * 1073741824 * (100 - disk_used) / 100)}],
                last_seen=now - timedelta(seconds=age_seconds),
            )
        )
        created += 1
    db.session.commit()
    return created

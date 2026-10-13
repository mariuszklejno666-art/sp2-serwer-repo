from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import ldb
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB


DOMAIN_DN = "DC=sp2,DC=lan"
DEPLOYMENT_GROUP = "SP2-Agent-Deployment"
ROOMS = ("Sala11", "Sala32", "Sala4", "Sala7")
STATE_FILE = Path("/etc/sp2-admin/agent-deployment-rooms.conf")


@dataclass(frozen=True)
class RoomPlan:
    room: str
    ou_dn: str
    group: str
    computers: tuple[str, ...]


def samdb_local() -> SamDB:
    lp = LoadParm()
    lp.load_default()
    samdb_url = lp.private_path("sam.ldb")
    return SamDB(url=samdb_url, session_info=system_session(), lp=lp)


def load_enabled_rooms() -> set[str]:
    if not STATE_FILE.exists():
        return set(ROOMS)
    enabled: set[str] = set()
    for raw in STATE_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        room, value = line.split("=", 1)
        room = room.strip()
        value = value.strip().lower()
        if room in ROOMS and value in {"1", "true", "yes", "on", "enabled"}:
            enabled.add(room)
    return enabled


def computers_in_ou(samdb: SamDB, ou_dn: str) -> tuple[str, ...]:
    rows = samdb.search(base=ou_dn, scope=ldb.SCOPE_SUBTREE, expression="(objectClass=computer)", attrs=["sAMAccountName"])
    result: set[str] = set()
    for row in rows:
        if "sAMAccountName" not in row:
            continue
        value = str(row["sAMAccountName"][0]).strip()
        if value:
            result.add(value)
    return tuple(sorted(result, key=str.casefold))


def group_members(group: str) -> set[str]:
    completed = subprocess.run(["samba-tool", "group", "listmembers", group], check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(f"Nie można odczytać grupy {group}: {(completed.stderr or completed.stdout).strip()}")
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def ensure_group(group: str, *, dry_run: bool) -> None:
    completed = subprocess.run(["samba-tool", "group", "show", group], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if completed.returncode == 0:
        return
    if dry_run:
        print(f"DRY-RUN create group: {group}")
        return
    subprocess.run(["samba-tool", "group", "add", group], check=True)


def add_members(group: str, members: list[str], *, dry_run: bool) -> None:
    if not members:
        return
    if dry_run:
        print(f"DRY-RUN add to {group}: {', '.join(members)}")
        return
    subprocess.run(["samba-tool", "group", "addmembers", group, ",".join(members)], check=True)


def remove_members(group: str, members: list[str], *, dry_run: bool) -> None:
    if not members:
        return
    if dry_run:
        print(f"DRY-RUN remove from {group}: {', '.join(members)}")
        return
    subprocess.run(["samba-tool", "group", "removemembers", group, ",".join(members)], check=True)


def build_plan(samdb: SamDB, rooms: tuple[str, ...]) -> list[RoomPlan]:
    return [
        RoomPlan(
            room=room,
            ou_dn=f"OU={room},OU=Komputery,{DOMAIN_DN}",
            group=f"SP2-Agent-{room}",
            computers=computers_in_ou(samdb, f"OU={room},OU=Komputery,{DOMAIN_DN}"),
        )
        for room in rooms
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronizuje grupy wdrożeniowe SP2 Agent z OU sal.")
    parser.add_argument("--dry-run", action="store_true", help="Pokaż zmiany bez modyfikowania Active Directory.")
    parser.add_argument("--prune", action="store_true", help="Usuń z grup salowych komputery, które nie znajdują się już w odpowiadającym im OU.")
    parser.add_argument("--rooms", nargs="+", default=list(ROOMS), help="Nazwy OU sal, domyślnie: " + ", ".join(ROOMS))
    args = parser.parse_args()

    if not args.dry_run and hasattr(sys, "geteuid") and sys.geteuid() != 0:
        print("Uruchom przez sudo albo użyj --dry-run.", file=sys.stderr)
        return 2

    rooms = tuple(dict.fromkeys(str(room).strip() for room in args.rooms if str(room).strip()))
    if not rooms:
        print("Brak sal do synchronizacji.", file=sys.stderr)
        return 2

    enabled_rooms = load_enabled_rooms()
    samdb = samdb_local()
    plans = build_plan(samdb, rooms)
    ensure_group(DEPLOYMENT_GROUP, dry_run=args.dry_run)
    deployment_members = set() if args.dry_run else group_members(DEPLOYMENT_GROUP)

    print("SP2 Agent - synchronizacja grup wdrożeniowych")
    print(f"Tryb: {'DRY-RUN' if args.dry_run else 'APPLY'}")
    print("Włączone sale: " + (", ".join(sorted(enabled_rooms)) if enabled_rooms else "brak"))

    for plan in plans:
        ensure_group(plan.group, dry_run=args.dry_run)
        current = set() if args.dry_run else group_members(plan.group)
        desired = set(plan.computers)
        missing = sorted(desired - current, key=str.casefold)
        stale = sorted(current - desired, key=str.casefold) if args.prune else []

        print(f"\n[{plan.room}]")
        print(f"OU: {plan.ou_dn}")
        print(f"Grupa: {plan.group}")
        print(f"Wdrożenie: {'WŁĄCZONE' if plan.room in enabled_rooms else 'WYŁĄCZONE'}")
        print(f"Komputery w OU: {len(desired)}")
        if desired:
            print("  " + ", ".join(sorted(desired, key=str.casefold)))
        print(f"Do dodania: {len(missing)}")
        print(f"Do usunięcia: {len(stale)}" if args.prune else "Prune: wyłączony")

        add_members(plan.group, missing, dry_run=args.dry_run)
        remove_members(plan.group, stale, dry_run=args.dry_run)

        should_be_linked = plan.room in enabled_rooms
        is_linked = plan.group in deployment_members
        if should_be_linked and not is_linked:
            add_members(DEPLOYMENT_GROUP, [plan.group], dry_run=args.dry_run)
            deployment_members.add(plan.group)
        elif not should_be_linked and is_linked:
            remove_members(DEPLOYMENT_GROUP, [plan.group], dry_run=args.dry_run)
            deployment_members.discard(plan.group)

    print("\nGotowe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

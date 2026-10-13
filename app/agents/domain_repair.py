"""Read-only Samba diagnosis. Unknown directory state always fails closed."""

from __future__ import annotations

import re
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from flask import current_app
from ldap3 import BASE
from ldap3.core.exceptions import LDAPException

from app.directory.service import DirectoryError, DirectoryService, first_value, _escape_filter
from app.domain_naming import distinguished_name_within


def valid_name(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?", value)
        or value.isdigit()
    ):
        raise ValueError("Nieprawidlowa nazwa komputera (1-15 znakow).")
    return value.upper()


def validate_local(local):
    if not isinstance(local, dict) or set(local) - {
        "hostname",
        "part_of_domain",
        "secure_channel",
        "domain",
        "boot_id",
        "mac_addresses",
        "hardware_uuid",
    }:
        raise ValueError("Nieprawidlowy raport lokalny.")
    valid_name(local.get("hostname"))
    if type(local.get("part_of_domain")) is not bool:
        raise ValueError("Wymagany logiczny stan domeny.")
    if local.get("secure_channel") is not None and type(local["secure_channel"]) is not bool:
        raise ValueError("Nieprawidlowy secure_channel.")
    for key, limit in (("domain", 255), ("boot_id", 80)):
        if not isinstance(local.get(key, ""), str) or len(local.get(key, "")) > limit:
            raise ValueError("Nieprawidlowy raport lokalny.")
    if "mac_addresses" in local:
        normalize_macs(local["mac_addresses"])
    if "hardware_uuid" in local and not isinstance(local["hardware_uuid"], str):
        raise ValueError("Nieprawidlowy UUID sprzetu.")
    return local


def normalize_macs(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 32:
        raise ValueError("Wymagane adresy MAC urzadzenia.")
    result = set()
    for value in values:
        if not isinstance(value, str) or not re.fullmatch(
            r"(?:[0-9A-Fa-f]{12}|[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", value
        ):
            raise ValueError("Nieprawidlowy adres MAC.")
        compact = value.replace("-", "").replace(":", "").upper()
        normalized = ":".join(compact[i:i + 2] for i in range(0, 12, 2))
        if normalized in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
            raise ValueError("Nieprawidlowy adres MAC.")
        if int(compact[:2], 16) & 1:
            raise ValueError("Nieprawidlowy adres MAC.")
        result.add(normalized)
    return sorted(result)


def validate_target(name, ou):
    name = valid_name(name)
    if not re.fullmatch(r"(?:(?:BR|PL)-S[0-9]{2,3}(?:-[0-9]{2})?|S[0-9]{2,3}-[0-9]{2})", name):
        raise ValueError("Uzyj BR-Sxx/PL-Sxx[-yy] lub Sxx-yy.")
    allowed = current_app.config.get("AD_JOIN_ALLOWED_OU_BASES", [])
    if (
        not isinstance(ou, str)
        or len(ou) > 512
        or not any(distinguished_name_within(ou, base) for base in allowed)
    ):
        raise ValueError("OU poza dozwolonym zakresem serwera.")
    return name


@dataclass(slots=True)
class ComputerState:
    exists: bool
    name: str = ""
    dn: str = ""
    dns_hostname: str = ""
    enabled: bool = False
    object_sid: str = ""
    spns: list[str] = field(default_factory=list)
    last_logon: str = ""
    activity: str = "unknown"
    password_last_set: str = ""

    def payload(self):
        return asdict(self)


def ad_timestamp(value):
    """pwdLastSet as aware UTC datetime; None when unset/unknown (fail closed)."""
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, str) and value and not value.isdigit():
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if isinstance(value, datetime):
        result = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    else:
        try:
            ticks = int(str(value))
        except (TypeError, ValueError):
            return None
        if ticks <= 0:
            return None
        result = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
    if result.year <= 1601:
        return None
    return result.astimezone(timezone.utc)


def computer_state(name):
    normalized = valid_name(name)
    service = DirectoryService()
    records = service._search(
        f"(&(objectCategory=computer)(sAMAccountName={_escape_filter(normalized)}$))",
        service.COMPUTER_ATTRIBUTES + ["servicePrincipalName", "pwdLastSet"],
        size_limit=2,
    )
    if len(records) > 1:
        raise DirectoryError("Niejednoznaczne konto komputera.")
    if not records:
        return ComputerState(False, name=normalized)
    record = records[0]
    try:
        enabled = not bool(int(first_value(record, "userAccountControl", "2")) & 2)
    except ValueError:
        enabled = False
    spns = record.get("servicePrincipalName", [])
    if isinstance(spns, str):
        spns = [spns]
    return ComputerState(
        True,
        normalized,
        first_value(record, "distinguishedName", first_value(record, "dn", "")),
        first_value(record, "dNSHostName", ""),
        enabled,
        first_value(record, "objectSid", ""),
        [str(x) for x in spns],
        first_value(record, "lastLogonTimestamp", ""),
        password_last_set=_iso(ad_timestamp(record.get("pwdLastSet"))),
    )


def _iso(value):
    return value.isoformat() if value else ""


def directory_checks(target, ou, domain, owned_sid):
    service = DirectoryService()
    connection = service._connection()
    try:
        connection.search(
            ou,
            "(objectClass=organizationalUnit)",
            search_scope=BASE,
            attributes=["distinguishedName"],
        )
        if connection.result.get("description") != "success" or len(connection.entries) != 1:
            raise DirectoryError("Nie potwierdzono docelowego OU.")
    except LDAPException as exc:
        raise DirectoryError("Nie potwierdzono docelowego OU.") from exc
    finally:
        connection.unbind()
    short = _escape_filter(target)
    fqdn = _escape_filter(f"{target}.{domain}")
    records = service._search(
        f"(|(dNSHostName={fqdn})(servicePrincipalName=*/{short})(servicePrincipalName=*/{fqdn}))",
        ["objectSid", "dNSHostName", "servicePrincipalName"],
        size_limit=2,
    )
    conflict = any(not owned_sid or first_value(r, "objectSid", "") != owned_sid for r in records)
    addresses = dns_addresses(target, domain)
    # A DNS-only leftover cannot be assumed to belong to this workstation.
    conflict = conflict or bool(addresses and not records)
    return {
        "ou_exists": True,
        "dns_spn_conflict": conflict,
        "dns_addresses": addresses,
        "dns_resolves": bool(addresses),
    }


def dns_addresses(name, domain):
    try:
        return sorted({record[4][0] for record in socket.getaddrinfo(f"{name}.{domain}", None)})
    except socket.gaierror as exc:
        if exc.errno in {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}:
            return []
        raise DirectoryError("Nie mozna potwierdzic stanu DNS.") from exc


def build_diagnosis(payload, *, owned_sid=""):
    local = validate_local(payload.get("local"))
    source = valid_name(local["hostname"])
    target = validate_target(payload.get("target_name"), payload.get("target_ou"))
    ou = payload["target_ou"]
    domain = current_app.config.get("AD_DOMAIN_FQDN", "").lower()
    if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", domain):
        raise ValueError("Brak poprawnej domeny AD_DOMAIN_FQDN na serwerze.")
    source_ad = computer_state(source)
    target_ad = source_ad if source == target else computer_state(target)
    member = local["part_of_domain"]
    secure = local.get("secure_channel")
    # owned_sid comes only from authenticated registration/plan, never client JSON.
    conflict = target_ad.exists and (not owned_sid or target_ad.object_sid != owned_sid)
    checks = directory_checks(target, ou, domain, owned_sid)
    conflict = conflict or checks["dns_spn_conflict"]
    expected_dns = f"{target}.{domain}".lower()
    spns = {s.lower() for s in target_ad.spns}
    checks.update(
        ou_matches=target_ad.dn.partition(",")[2].casefold() == ou.casefold(),
        dns_matches=target_ad.dns_hostname.lower() == expected_dns
        and checks.get("dns_resolves", False),
        spn_matches={f"host/{target.lower()}", f"host/{expected_dns}"}.issubset(spns),
    )
    if conflict:
        status, action = "TARGET_CONFLICT", "blocked_conflict"
    elif member and local.get("domain", "").lower() != domain:
        status, action = "FOREIGN_DOMAIN", "blocked"
    elif member and secure is True and not source_ad.exists:
        status, action = "INCONSISTENT_AD_STATE", "blocked"
    elif source_ad.exists and member and (not source_ad.enabled or not source_ad.object_sid):
        status, action = "AD_ACCOUNT_INVALID", "blocked"
    elif member and not source_ad.exists and secure is not True:
        status, action = "TRUST_BROKEN_AD_MISSING_NTLM_SAFE_STOP", "blocked"
        if secure is False and current_app.config.get("MACHINE_ACCOUNT_RECOVERY_ENABLED"):
            status, action = "TRUST_BROKEN_AD_MISSING", "machine_account_recovery"
    elif member and secure is False:
        status, action = "TRUST_BROKEN_AD_EXISTS", "repair_secure_channel"
    elif member and secure is True and source != target:
        status, action = "DOMAIN_OK_RENAME_REQUIRED", "rename_domain"
    elif member and secure is True:
        status, action = (
            ("OK", "none")
            if all(checks[k] for k in ("ou_matches", "dns_matches", "spn_matches"))
            else ("AD_METADATA_REVIEW", "blocked")
        )
    elif not member:
        status, action = "OUTSIDE_DOMAIN", "join"
    else:
        status, action = "UNKNOWN", "diagnose"
    return {
        "status": status,
        "recommended_action": action,
        "source_name": source,
        "target_name": target,
        "target_ou": ou,
        "domain": domain,
        "source_ad": source_ad.payload(),
        "target_ad": target_ad.payload(),
        "target_conflict": bool(conflict),
        "target_active": "unknown",
        "checks": checks,
    }


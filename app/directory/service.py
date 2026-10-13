from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from flask import current_app
from ldap3 import (
    ALL,
    BASE,
    LEVEL,
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
    SUBTREE,
    Connection,
    Server,
)
from ldap3.core.exceptions import LDAPException


class DirectoryError(RuntimeError):
    """Błąd połączenia lub zapytania do katalogu LDAP."""


NEW_USER_MIN_PASSWORD_LENGTH = 6


@dataclass(frozen=True, slots=True)
class DirectoryStats:
    users: int
    groups: int
    computers: int
    checked_at: datetime


class DirectoryService:
    """Warstwa odczytu Samba AD przez LDAP.

    Moduł celowo nie udostępnia operacji zapisu. W Sprint 1 katalog jest tylko do odczytu.
    """

    USER_ATTRIBUTES = [
        "sAMAccountName",
        "userPrincipalName",
        "displayName",
        "givenName",
        "sn",
        "mail",
        "telephoneNumber",
        "department",
        "title",
        "userAccountControl",
        "distinguishedName",
        "memberOf",
        "pwdLastSet",
        "lastLogonTimestamp",
        "lockoutTime",
    ]
    GROUP_ATTRIBUTES = ["sAMAccountName", "description", "member", "distinguishedName"]
    OU_ATTRIBUTES = ["ou", "description", "distinguishedName", "whenCreated"]
    COMPUTER_ATTRIBUTES = [
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
        "lastLogonTimestamp",
        "distinguishedName",
        "description",
        "whenCreated",
        "objectSid",
        "memberOf",
        "userAccountControl",
    ]

    def __init__(self) -> None:
        self.uri = current_app.config["LDAP_URI"]
        self.bind_dn = current_app.config["LDAP_BIND_DN"]
        self.password = current_app.config["LDAP_BIND_PASSWORD"]
        self.base_dn = current_app.config["LDAP_BASE_DN"]
        self.connect_timeout = current_app.config["LDAP_CONNECT_TIMEOUT"]
        self.receive_timeout = current_app.config["LDAP_RECEIVE_TIMEOUT"]
        self.use_ssl = current_app.config["LDAP_USE_SSL"]

    def _validate_configuration(self) -> None:
        missing = [
            key
            for key, value in {
                "LDAP_URI": self.uri,
                "LDAP_BIND_DN": self.bind_dn,
                "LDAP_BIND_PASSWORD": self.password,
                "LDAP_BASE_DN": self.base_dn,
            }.items()
            if not value
        ]
        if missing:
            raise DirectoryError("Brak konfiguracji: " + ", ".join(missing))

    def _connection(self, *, write: bool = False) -> Connection:
        if current_app.config.get("PREVIEW_DEMO_DATA"):
            raise DirectoryError("Podgląd demo nie łączy się z LDAP.")
        self._validate_configuration()
        bind_dn = self.bind_dn
        password = self.password
        if write:
            bind_dn = current_app.config.get("LDAP_WRITE_BIND_DN", "")
            password = current_app.config.get("LDAP_WRITE_BIND_PASSWORD", "")
            if not bind_dn or not password:
                raise DirectoryError(
                    "Operacje zapisu są wyłączone. Ustaw LDAP_WRITE_BIND_DN i "
                    "LDAP_WRITE_BIND_PASSWORD."
                )

        server = Server(
            self.uri,
            get_info=ALL,
            connect_timeout=self.connect_timeout,
            use_ssl=self.use_ssl,
        )
        try:
            return Connection(
                server,
                user=bind_dn,
                password=password,
                auto_bind=True,
                receive_timeout=self.receive_timeout,
                raise_exceptions=True,
            )
        except LDAPException as exc:
            raise DirectoryError(f"Nie udało się połączyć z LDAP: {exc}") from exc

    @staticmethod
    def _entry_to_dict(entry: Any) -> dict[str, Any]:
        values = entry.entry_attributes_as_dict
        values["dn"] = entry.entry_dn
        return values

    def _search(
        self,
        search_filter: str,
        attributes: list[str],
        *,
        size_limit: int = 0,
    ) -> list[dict[str, Any]]:
        connection = self._connection()
        try:
            ok = connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                size_limit=size_limit,
                paged_size=current_app.config["LDAP_PAGE_SIZE"],
            )
            if not ok and connection.result.get("description") not in {"success", "sizeLimitExceeded"}:
                raise DirectoryError(
                    f"LDAP zwrócił błąd: {connection.result.get('message') or connection.result}"
                )
            return [self._entry_to_dict(entry) for entry in connection.entries]
        except LDAPException as exc:
            raise DirectoryError(f"Błąd zapytania LDAP: {exc}") from exc
        finally:
            connection.unbind()

    def test_connection(self) -> dict[str, str]:
        if current_app.config.get("PREVIEW_DEMO_DATA"):
            return {"status": "demo", "server": "brak połączenia", "base_dn": "DC=sp2,DC=test"}
        connection = self._connection()
        try:
            connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["distinguishedName"],
                size_limit=1,
            )
            return {
                "status": "ok",
                "server": self.uri,
                "base_dn": self.base_dn,
            }
        except LDAPException as exc:
            raise DirectoryError(f"Test LDAP nie powiódł się: {exc}") from exc
        finally:
            connection.unbind()

    def users(self, query: str = "", limit: int = 500) -> list[dict[str, Any]]:
        if current_app.config.get("PREVIEW_DEMO_DATA"):
            from .preview_data import users

            return users(query, limit)
        escaped = _escape_filter(query.strip())
        query_filter = (
            f"(|(sAMAccountName=*{escaped}*)(displayName=*{escaped}*)(mail=*{escaped}*))"
            if escaped
            else "(sAMAccountName=*)"
        )
        ldap_filter = f"(&(objectCategory=person)(objectClass=user){query_filter})"
        return self._search(ldap_filter, self.USER_ATTRIBUTES, size_limit=limit)

    def user(self, username: str) -> dict[str, Any] | None:
        """Zwraca pojedynczego użytkownika AD po nazwie sAMAccountName."""
        if current_app.config.get("PREVIEW_DEMO_DATA"):
            return next(
                (item for item in self.users(limit=0) if first_value(item, "sAMAccountName").casefold() == username.strip().casefold()),
                None,
            )
        escaped = _escape_filter(username.strip())
        if not escaped:
            return None
        records = self._search(
            f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={escaped}))",
            self.USER_ATTRIBUTES,
            size_limit=1,
        )
        return records[0] if records else None

    def reset_password(
        self,
        username: str,
        new_password: str,
        *,
        force_change: bool = True,
    ) -> str:
        """Resetuje hasło konta AD przez szyfrowane połączenie LDAP."""
        if not self.use_ssl:
            raise DirectoryError("Reset hasła wymaga połączenia LDAPS.")

        user = self.user(username)
        if user is None:
            raise DirectoryError(f"Nie znaleziono użytkownika: {username}")
        user_dn = first_value(user, "distinguishedName", "")
        if not user_dn:
            raise DirectoryError("Konto użytkownika nie ma distinguishedName.")

        connection = self._connection(write=True)
        try:
            ok = connection.extend.microsoft.modify_password(user_dn, new_password)
            if not ok:
                raise DirectoryError(
                    "Kontroler domeny odrzucił reset hasła: "
                    f"{connection.result.get('message') or connection.result}"
                )
            if force_change:
                changed = connection.modify(
                    user_dn,
                    {"pwdLastSet": [(MODIFY_REPLACE, [0])]},
                )
                if not changed:
                    raise DirectoryError(
                        "Hasło zmieniono, ale nie udało się wymusić zmiany przy "
                        "następnym logowaniu: "
                        f"{connection.result.get('message') or connection.result}"
                    )
            return user_dn
        except LDAPException as exc:
            raise DirectoryError(f"Reset hasła nie powiódł się: {exc}") from exc
        finally:
            connection.unbind()

    def set_account_enabled(self, username: str, *, enabled: bool) -> str:
        """Włącza lub wyłącza konto, zachowując pozostałe flagi userAccountControl."""
        user = self.user(username)
        if user is None:
            raise DirectoryError(f"Nie znaleziono użytkownika: {username}")
        user_dn = first_value(user, "distinguishedName", "")
        if not user_dn:
            raise DirectoryError("Konto użytkownika nie ma distinguishedName.")

        try:
            current_uac = int(first_value(user, "userAccountControl", "0"))
        except ValueError as exc:
            raise DirectoryError("Nieprawidłowa wartość userAccountControl.") from exc
        new_uac = current_uac & ~2 if enabled else current_uac | 2

        connection = self._connection(write=True)
        try:
            ok = connection.modify(
                user_dn,
                {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]},
            )
            if not ok:
                raise DirectoryError(
                    "Kontroler domeny odrzucił zmianę statusu konta: "
                    f"{connection.result.get('message') or connection.result}"
                )
            return user_dn
        except LDAPException as exc:
            raise DirectoryError(f"Zmiana statusu konta nie powiodła się: {exc}") from exc
        finally:
            connection.unbind()

    def unlock_account(self, username: str) -> str:
        """Odblokowuje konto przez wyzerowanie atrybutu lockoutTime."""
        user = self.user(username)
        if user is None:
            raise DirectoryError(f"Nie znaleziono użytkownika: {username}")
        user_dn = first_value(user, "distinguishedName", "")
        if not user_dn:
            raise DirectoryError("Konto użytkownika nie ma distinguishedName.")

        connection = self._connection(write=True)
        try:
            ok = connection.modify(
                user_dn,
                {"lockoutTime": [(MODIFY_REPLACE, [0])]},
            )
            if not ok:
                raise DirectoryError(
                    "Kontroler domeny odrzucił odblokowanie konta: "
                    f"{connection.result.get('message') or connection.result}"
                )
            return user_dn
        except LDAPException as exc:
            raise DirectoryError(f"Odblokowanie konta nie powiodło się: {exc}") from exc
        finally:
            connection.unbind()



    def create_user(
        self,
        *,
        username: str,
        given_name: str,
        surname: str,
        password: str,
        ou_dn: str,
        display_name: str | None = None,
        mail: str | None = None,
        group_dns: list[str] | None = None,
    ) -> str:
        """Tworzy nowe konto użytkownika AD i opcjonalnie dodaje je do grup."""
        if not self.use_ssl:
            raise DirectoryError("Tworzenie użytkownika wymaga połączenia LDAPS.")

        normalized_username = username.strip()
        if not normalized_username:
            raise DirectoryError("Nie podano nazwy użytkownika.")
        if len(password) < NEW_USER_MIN_PASSWORD_LENGTH:
            raise DirectoryError(
                f"Hasło musi mieć co najmniej {NEW_USER_MIN_PASSWORD_LENGTH} znaków."
            )
        if self.user(normalized_username) is not None:
            raise DirectoryError(f"Użytkownik {normalized_username} już istnieje.")

        ou_dn = self._validated_dn(ou_dn, object_name="OU")
        display = (display_name or f"{given_name} {surname}").strip()
        user_dn = f"CN={_escape_dn_value(display)},{ou_dn}"

        connection = self._connection(write=True)
        try:
            attributes = {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "sAMAccountName": normalized_username,
                "userPrincipalName": f"{normalized_username}@{self._upn_suffix()}",
                "givenName": given_name,
                "sn": surname,
                "displayName": display,
                # Konto tymczasowo wyłączone i bez wymaganego hasła — AD nie
                # pozwala włączyć konta zanim hasło nie zostanie ustawione.
                "userAccountControl": 546,
            }
            if mail:
                attributes["mail"] = mail
            ok = connection.add(user_dn, attributes=attributes)
            if not ok:
                raise DirectoryError(
                    "Nie udało się utworzyć użytkownika: "
                    f"{connection.result.get('message') or connection.result}"
                )
        except LDAPException as exc:
            raise DirectoryError(f"Tworzenie użytkownika nie powiodło się: {exc}") from exc
        finally:
            connection.unbind()

        try:
            self.reset_password(normalized_username, password, force_change=True)
            self.set_account_enabled(normalized_username, enabled=True)
            for group_dn in group_dns or []:
                self.add_user_to_group(normalized_username, group_dn)
        except DirectoryError:
            try:
                self.delete_user(normalized_username)
            except DirectoryError:
                pass
            raise

        return user_dn

    def delete_user(self, username: str) -> str:
        """Usuwa konto użytkownika z katalogu AD."""
        user_dn = self._user_dn(username)
        connection = self._connection(write=True)
        try:
            ok = connection.delete(user_dn)
            if not ok:
                raise DirectoryError(
                    "Nie udało się usunąć użytkownika: "
                    f"{connection.result.get('message') or connection.result}"
                )
            return user_dn
        except LDAPException as exc:
            raise DirectoryError(f"Usuwanie użytkownika nie powiodło się: {exc}") from exc
        finally:
            connection.unbind()

    def rename_user(self, username: str, new_username: str) -> str:
        """Zmienia nazwę logowania (sAMAccountName) użytkownika."""
        normalized_new = new_username.strip()
        if not normalized_new:
            raise DirectoryError("Nie podano nowej nazwy użytkownika.")
        if normalized_new.casefold() == username.strip().casefold():
            return self._user_dn(username)
        if self.user(normalized_new) is not None:
            raise DirectoryError(f"Użytkownik {normalized_new} już istnieje.")

        user = self.user(username)
        if user is None:
            raise DirectoryError(f"Nie znaleziono użytkownika: {username}")
        user_dn = first_value(user, "distinguishedName", "")
        if not user_dn:
            raise DirectoryError("Konto użytkownika nie ma distinguishedName.")

        changes: dict[str, list[tuple[Any, list[Any]]]] = {
            "sAMAccountName": [(MODIFY_REPLACE, [normalized_new])],
        }
        old_upn = first_value(user, "userPrincipalName", "")
        if old_upn and "@" in old_upn:
            suffix = old_upn.split("@", 1)[1]
            changes["userPrincipalName"] = [(MODIFY_REPLACE, [f"{normalized_new}@{suffix}"])]

        connection = self._connection(write=True)
        try:
            ok = connection.modify(user_dn, changes)
            if not ok:
                raise DirectoryError(
                    "Nie udało się zmienić nazwy użytkownika: "
                    f"{connection.result.get('message') or connection.result}"
                )
            return user_dn
        except LDAPException as exc:
            raise DirectoryError(f"Zmiana nazwy użytkownika nie powiodła się: {exc}") from exc
        finally:
            connection.unbind()

    def add_user_to_group(self, username: str, group_dn: str) -> str:
        """Dodaje użytkownika do grupy AD wskazanej pełnym DN."""
        user_dn = self._user_dn(username)
        group_dn = self._validated_dn(group_dn, object_name="grupy")
        connection = self._connection(write=True)
        try:
            ok = connection.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
            if not ok:
                description = connection.result.get("description")
                # Samba AD zgłasza duplikat wartości atrybutu member jako
                # "entryAlreadyExists" (kod 68), a nie standardowe dla LDAP
                # "attributeOrValueExists" (kod 20) — akceptujemy oba, żeby
                # dodanie do grupy pozostało idempotentne na Samba AD.
                if description in ("attributeOrValueExists", "entryAlreadyExists"):
                    return group_dn
                raise DirectoryError(
                    "Nie udało się dodać użytkownika do grupy: "
                    f"{connection.result.get('message') or connection.result}"
                )
            return group_dn
        except LDAPException as exc:
            raise DirectoryError(f"Dodawanie do grupy nie powiodło się: {exc}") from exc
        finally:
            connection.unbind()

    def remove_user_from_group(self, username: str, group_dn: str) -> str:
        """Usuwa użytkownika z grupy AD wskazanej pełnym DN."""
        user_dn = self._user_dn(username)
        group_dn = self._validated_dn(group_dn, object_name="grupy")
        connection = self._connection(write=True)
        try:
            ok = connection.modify(group_dn, {"member": [(MODIFY_DELETE, [user_dn])]})
            if not ok:
                description = connection.result.get("description")
                if description == "noSuchAttribute":
                    return group_dn
                raise DirectoryError(
                    "Nie udało się usunąć użytkownika z grupy: "
                    f"{connection.result.get('message') or connection.result}"
                )
            return group_dn
        except LDAPException as exc:
            raise DirectoryError(f"Usuwanie z grupy nie powiodło się: {exc}") from exc
        finally:
            connection.unbind()

    def add_user_to_groups(self, username: str, group_dns: list[str]) -> list[str]:
        """Dodaje użytkownika do wielu grup naraz.

        Operacja jest idempotentna: powtórne dodanie do tej samej grupy albo
        wielokrotne wystąpienie tej samej grupy na liście nie kończy się błędem.
        """
        return [self.add_user_to_group(username, group_dn) for group_dn in group_dns]

    def move_user(self, username: str, target_ou_dn: str) -> str:
        """Przenosi użytkownika do wybranej jednostki organizacyjnej."""
        user_dn = self._user_dn(username)
        target_ou_dn = self._validated_dn(target_ou_dn, object_name="OU")
        rdn = user_dn.split(",", 1)[0]
        connection = self._connection(write=True)
        try:
            ok = connection.modify_dn(user_dn, rdn, new_superior=target_ou_dn)
            if not ok:
                raise DirectoryError(
                    "Nie udało się przenieść użytkownika: "
                    f"{connection.result.get('message') or connection.result}"
                )
            return f"{rdn},{target_ou_dn}"
        except LDAPException as exc:
            raise DirectoryError(f"Przenoszenie użytkownika nie powiodło się: {exc}") from exc
        finally:
            connection.unbind()

    def _user_dn(self, username: str) -> str:
        user = self.user(username)
        if user is None:
            raise DirectoryError(f"Nie znaleziono użytkownika: {username}")
        user_dn = first_value(user, "distinguishedName", "")
        if not user_dn:
            raise DirectoryError("Konto użytkownika nie ma distinguishedName.")
        return user_dn

    def _upn_suffix(self) -> str:
        """Wyprowadza sufiks UPN (np. sp2.local) z LDAP_BASE_DN."""
        parts = [
            chunk.split("=", 1)[1]
            for chunk in self.base_dn.split(",")
            if chunk.strip().upper().startswith("DC=")
        ]
        return ".".join(parts) if parts else self.base_dn

    def _validated_dn(self, dn: str, *, object_name: str) -> str:
        normalized = (dn or "").strip()
        if not normalized:
            raise DirectoryError(f"Nie wybrano {object_name}.")
        if not normalized.casefold().endswith(self.base_dn.casefold()):
            raise DirectoryError(f"Wybrany DN {object_name} znajduje się poza domeną.")
        return normalized

    def groups(self, query: str = "", limit: int = 500) -> list[dict[str, Any]]:
        if current_app.config.get("PREVIEW_DEMO_DATA"):
            from .preview_data import groups

            return groups(query, limit)
        escaped = _escape_filter(query.strip())
        query_filter = f"(sAMAccountName=*{escaped}*)" if escaped else "(sAMAccountName=*)"
        return self._search(
            f"(&(objectCategory=group){query_filter})",
            self.GROUP_ATTRIBUTES,
            size_limit=limit,
        )

    def organizational_units(self, query: str = "", limit: int = 500) -> list[dict[str, Any]]:
        """Zwraca jednostki organizacyjne AD wraz z liczbą bezpośrednich obiektów."""
        if current_app.config.get("PREVIEW_DEMO_DATA"):
            from .preview_data import organizational_units

            return organizational_units(query, limit)
        escaped = _escape_filter(query.strip())
        query_filter = f"(ou=*{escaped}*)" if escaped else "(ou=*)"
        records = self._search(
            f"(&(objectClass=organizationalUnit){query_filter})",
            self.OU_ATTRIBUTES,
            size_limit=limit,
        )
        for record in records:
            dn = first_value(record, "distinguishedName", record.get("dn", ""))
            counts = self._direct_child_counts(dn) if dn else {"users": 0, "computers": 0, "ous": 0}
            record["counts"] = counts
        return sorted(records, key=lambda item: ou_path(first_value(item, "distinguishedName", item.get("dn", ""))).casefold())

    def _direct_child_counts(self, ou_dn: str) -> dict[str, int]:
        connection = self._connection()
        try:
            ok = connection.search(
                search_base=ou_dn,
                search_filter="(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer)(objectClass=organizationalUnit))",
                search_scope=LEVEL,
                attributes=["objectClass", "objectCategory"],
                paged_size=current_app.config["LDAP_PAGE_SIZE"],
            )
            if not ok and connection.result.get("description") not in {"success", "sizeLimitExceeded"}:
                raise DirectoryError(
                    f"LDAP zwrócił błąd podczas liczenia obiektów OU: {connection.result.get('message') or connection.result}"
                )
            counts = {"users": 0, "computers": 0, "ous": 0}
            for entry in connection.entries:
                classes = {str(value).lower() for value in entry.objectClass.values}
                if "organizationalunit" in classes:
                    counts["ous"] += 1
                elif "computer" in classes:
                    counts["computers"] += 1
                elif "user" in classes:
                    counts["users"] += 1
            return counts
        except LDAPException as exc:
            raise DirectoryError(f"Nie udało się policzyć obiektów OU: {exc}") from exc
        finally:
            connection.unbind()

    def computers(self, query: str = "", limit: int = 500) -> list[dict[str, Any]]:
        if current_app.config.get("PREVIEW_DEMO_DATA"):
            from .preview_data import computers

            return computers(query, limit)
        escaped = _escape_filter(query.strip())
        query_filter = (
            f"(|(sAMAccountName=*{escaped}*)(dNSHostName=*{escaped}*))"
            if escaped
            else "(sAMAccountName=*)"
        )
        return self._search(
            f"(&(objectCategory=computer){query_filter})",
            self.COMPUTER_ATTRIBUTES,
            size_limit=limit,
        )

    def computer(self, computer_name: str) -> dict[str, Any] | None:
        """Zwraca pojedynczy komputer AD po nazwie bez lub z końcowym znakiem $."""
        if current_app.config.get("PREVIEW_DEMO_DATA"):
            normalized = computer_name.strip().rstrip("$").casefold()
            return next(
                (item for item in self.computers(limit=0) if first_value(item, "sAMAccountName").rstrip("$").casefold() == normalized),
                None,
            )
        normalized = computer_name.strip().rstrip("$")
        if not normalized:
            return None
        escaped = _escape_filter(normalized)
        records = self._search(
            "(&(objectCategory=computer)"
            f"(|(sAMAccountName={escaped}$)(sAMAccountName={escaped})"
            f"(cn={escaped})(dNSHostName={escaped})))",
            self.COMPUTER_ATTRIBUTES,
            size_limit=1,
        )
        return records[0] if records else None

    def stats(self) -> DirectoryStats:
        return DirectoryStats(
            users=len(self.users(limit=0)),
            groups=len(self.groups(limit=0)),
            computers=len(self.computers(limit=0)),
            checked_at=datetime.now(UTC),
        )


def _escape_filter(value: str) -> str:
    """Minimalne RFC4515 escaping dla danych wpisanych przez użytkownika."""
    return (
        value.replace("\\", r"\5c")
        .replace("*", r"\2a")
        .replace("(", r"\28")
        .replace(")", r"\29")
        .replace("\x00", r"\00")
    )


def _escape_dn_value(value: str) -> str:
    """Minimalne RFC4514 escaping wartości używanej w DN (np. CN)."""
    escaped = value.strip()
    for char in ("\\", ",", "+", '"', "<", ">", ";"):
        escaped = escaped.replace(char, f"\\{char}")
    if escaped.startswith(("#", " ")):
        escaped = "\\" + escaped
    if escaped.endswith(" ") and not escaped.endswith("\\ "):
        escaped = escaped[:-1] + "\\ "
    return escaped


def first_value(item: dict[str, Any], key: str, default: str = "—") -> str:
    value = item.get(key)
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value) if value not in (None, "") else default


def account_enabled(item: dict[str, Any]) -> bool:
    raw = first_value(item, "userAccountControl", "0")
    try:
        return not bool(int(raw) & 2)
    except ValueError:
        return True


def dn_common_name(value: str) -> str:
    """Wyciąga czytelną nazwę CN z pełnego distinguishedName."""
    if not value:
        return "—"
    first = str(value).split(",", 1)[0]
    return first[3:] if first.upper().startswith("CN=") else str(value)


def format_ad_datetime(value: Any) -> str:
    """Formatuje wartości dat zwracane przez ldap3."""
    if isinstance(value, list):
        value = value[0] if value else None
    if value in (None, "", 0, "0"):
        return "—"
    if isinstance(value, datetime):
        return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def computer_name(item: dict[str, Any]) -> str:
    """Czytelna nazwa komputera bez końcowego znaku dolara."""
    return first_value(item, "sAMAccountName").rstrip("$")


def dn_organizational_path(value: str) -> str:
    """Buduje czytelną ścieżkę OU z distinguishedName."""
    if not value:
        return "—"
    parts = []
    escaped = False
    current = []
    chunks = []
    for char in str(value):
        if char == "," and not escaped:
            chunks.append("".join(current))
            current = []
            continue
        current.append(char)
        escaped = char == "\\" and not escaped
        if char != "\\":
            escaped = False
    chunks.append("".join(current))
    for chunk in chunks:
        key, sep, raw = chunk.partition("=")
        if sep and key.strip().upper() == "OU":
            parts.append(raw.replace("\\,", ",").strip())
    return " / ".join(reversed(parts)) if parts else "Kontener domyślny"


def sid_value(value: Any, default: str = "—") -> str:
    """Normalizuje SID zwracany przez ldap3 do tekstu."""
    if isinstance(value, list):
        value = value[0] if value else None
    if value in (None, ""):
        return default
    return str(value)


def ou_path(value: str) -> str:
    """Czytelna ścieżka OU, łącznie z nazwą bieżącej jednostki."""
    if not value:
        return "—"
    parts: list[str] = []
    for chunk in _split_dn(value):
        key, sep, raw = chunk.partition("=")
        if sep and key.strip().upper() == "OU":
            parts.append(raw.replace(r"\,", ",").strip())
    return " / ".join(reversed(parts)) if parts else "—"


def _split_dn(value: str) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    escaped = False
    for char in str(value):
        if char == "," and not escaped:
            chunks.append("".join(current))
            current = []
            continue
        current.append(char)
        if char == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    chunks.append("".join(current))
    return chunks

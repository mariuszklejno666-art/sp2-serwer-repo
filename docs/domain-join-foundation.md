# Fundament kreatora dołączenia do domeny

Ten etap udostępnia wyłącznie dane potrzebne przyszłemu kreatorowi Windows. Nie zmienia DNS, nazwy komputera ani członkostwa w domenie.

## Konfiguracja

- `AD_DOMAIN_FQDN` — pełna nazwa domeny, np. `example.lan`.
- `AD_DOMAIN_NETBIOS` — krótka nazwa domeny, np. `EXAMPLE`.
- `AD_DNS_SERVERS` — adresy serwerów DNS rozdzielone przecinkami.
- `AD_JOIN_ALLOWED_OU_BASES` — dozwolone korzenie OU rozdzielone znakiem `|`.
- `AD_TEACHER_USER_OU` — OU, z której panel pobiera konta nauczycieli.
- `AD_TEACHER_COMPUTER_OU` — docelowa OU komputerów nauczycieli.

Przykładowy format `AD_JOIN_ALLOWED_OU_BASES`:

```text
OU=Komputery,DC=example,DC=lan|OU=Laptopy,DC=example,DC=lan
```

## API

`GET /api/v1/domain/join-options` wymaga istniejącego tokenu API w nagłówku `Authorization: Bearer ...`.

Odpowiedź zawiera dane domeny i tylko te OU, które należą do skonfigurowanych korzeni. Pola `operations.join` oraz `operations.unjoin` pozostają ustawione na `false`, dopóki operacje zapisu nie zostaną osobno zaprojektowane i przetestowane.

Endpoint nigdy nie zwraca haseł LDAP, tokenów ani danych kont serwisowych.

`POST /api/v1/domain/name-preview` wylicza bezpieczną nazwę komputera i sprawdza
ją względem istniejących kont komputerów. Operacja jest tylko do odczytu:

```json
{
  "mode": "room",
  "organizational_unit": "OU=Sala11,OU=Komputery,DC=sp2,DC=lan",
  "number": 1
}
```

Odpowiedź zawiera `computer_name`, `available` i potwierdzenie, że operacje
`join` oraz `unjoin` są nadal wyłączone. Dla trybu `teacher` żądanie przyjmuje
`given_name` oraz `surname`; przy konflikcie dobierany jest kolejny sufiks.

Zalogowany administrator może użyć tego samego mechanizmu na stronie
`/directory/domain-enrollment`. Strona pokazuje sale i aktywnych nauczycieli,
ale nie wykonuje żadnej operacji zapisu w AD.


## Ustalenia dla środowiska SP2

Kreator może wyświetlać wyłącznie jednostki pod następującym korzeniem:

```text
OU=Komputery,DC=sp2,DC=lan
```

OU serwerów, kontrolerów domeny, drukarek i użytkowników nie są dostępne podczas
dołączania komputerów.

Administrator wybiera OU i podaje numer komputera. Program pokazuje końcową nazwę
przed zastosowaniem zmian, na przykład `SALA11-01`. Nazwa jest sprawdzana pod
kątem ograniczeń Windows oraz konfliktu z istniejącym kontem AD.

## Rejestracja bez ręcznego tokenu

Docelowy kreator nie będzie pytał użytkownika o token API. Zalogowany administrator
pobierze go z panelu wraz z jednorazowym, krótkotrwałym kodem rejestracyjnym.
Kreator wymieni kod przez HTTPS na ograniczony token urządzenia i zabezpieczy go
przez Windows DPAPI lub Menedżer poświadczeń.

Długotrwały token panelu nie będzie zwracany przez endpoint ani zapisywany w pliku,
schowku, argumentach procesu lub logach.

## Operacje docelowe

- dołączenie: zapis DNS, ustawienie DNS domeny, wybór OU i numeru, zmiana nazwy,
  bezpieczne poświadczenia domenowe, dołączenie i restart,
- odłączenie: potwierdzenie lokalnego administratora, bezpieczne poświadczenia,
  przejście do `WORKGROUP`, opcjonalne przywrócenie DNS i restart.

Operacje pozostają wyłączone, dopóki nie będzie dostępnego HTTPS, jednorazowej
rejestracji i oddzielnego komputera lub maszyny wirtualnej do testów.


## Nazewnictwo komputerów nauczycieli

Dla komputerów nauczycieli kreator pobiera osoby z:

```text
OU=Nauczyciele,OU=Uzytkownicy,DC=sp2,DC=lan
```

Interfejs pokazuje pełne `Imię Nazwisko`, ale techniczna nazwa komputera ma
format `I-NAZWISKO`, np. `J-ZALEWSKA`. Polskie znaki są zamieniane na ASCII,
nazwa jest zapisywana wielkimi literami i ograniczona do 15 znaków. Przy konflikcie
kreator dodaje numer, np. `J-ZALEWSKA-2`.

Komputer zostaje umieszczony w:

```text
OU=Nauczyciele,OU=Komputery,DC=sp2,DC=lan
```

Lista nauczycieli będzie dostępna dopiero po wdrożeniu krótkotrwałych, jednorazowych
uprawnień rejestracyjnych. Obecny długotrwały token agenta nie będzie używany do
udostępniania danych osobowych.

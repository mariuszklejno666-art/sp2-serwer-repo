# Równoległa wersja zapasowa SP2 ADMIN

Ta gałąź dodaje wygląd nowego panelu do istniejącej aplikacji Flask. Uruchom ją jako
**oddzielny proces** w szkolnej sieci, z osobnym kontem systemowym, bazą SQLite,
sekretem sesji i adresem HTTPS. Stara usługa `sp2-admin.service` pozostaje bez zmian.

## Granice podglądu

- `SP2_STAGING_READ_ONLY=true` blokuje żądania zmieniające stan z przeglądarki,
  z wyjątkiem logowania, wylogowania i testu połączenia LDAP.
- Pobieranie pliku RDP, migawki kamery i otwarcie panelu monitoringu są blokowane.
- Konto LDAP do odczytu może pokazać rzeczywiste konta i komputery, jeśli administrator
  szkoły skonfiguruje dostęp z serwera. Nie ustawiaj konta LDAP z prawem zapisu.
- Lista agentów, zadania i sale korzystają z **osobnej** bazy SQLite. Pusta baza nie
  pokaże aktualnego stanu agentów. Do prób na danych użyj wyłącznie zanonimizowanej
  kopii, nigdy produkcyjnego pliku bazy.
- Kreator dołączenia i naprawa zaufania pozostają symulacją w osobnym prototypie
  `https://sp2-admin-demo.klaniak1986.chatgpt.site`; ta gałąź nie wykonuje naprawy AD.

### Tryb przykładowych danych

Jeśli nie podłączasz LDAP do kopii zapasowej, ustaw `SP2_PREVIEW_DEMO_DATA=true` obok
`SP2_STAGING_READ_ONLY=true`. Panel pokaże fikcyjne konta, grupy, OU i komputery z
zarezerwowanej domeny `sp2.test`; nigdy nie wywoła LDAP. W katalogu kopii ustaw również:

```dotenv
AD_JOIN_ALLOWED_OU_BASES=OU=Komputery,DC=sp2,DC=test
AD_TEACHER_USER_OU=OU=Nauczyciele,OU=Uzytkownicy,DC=sp2,DC=test
AD_TEACHER_COMPUTER_OU=OU=Nauczyciele,OU=Komputery,DC=sp2,DC=test
```

Do zasilenia sal i agentów użyj `flask --app run.py seed-preview-demo`. Polecenie
odmawia działania poza bazą `instance/preview.sqlite3` i można je powtórzyć bez
powielania rekordów. Wszystkie nazwy agentów mają prefiks `DEMO-`, a adresy IP są
przykładowe. Podgląd pozostaje tylko do odczytu; pełny przepływ dołączenia stacji i
naprawy relacji zaufania sprawdź w osobnym prototypie symulacyjnym.

## Ustawienia instancji

Po pobraniu tej gałęzi do `/opt/sp2-admin-preview`, utworzeniu jej własnego środowiska
Python i konta usługi ustaw plik środowiskowy dostępny tylko temu kontu, np.
`/etc/sp2-admin-preview.env`. Wartości wpisz lokalnie na serwerze; nie zapisuj ich w Git.

```dotenv
FLASK_ENV=production
SP2_STAGING_READ_ONLY=true
SP2_PREVIEW_THEME=true
APP_NAME=SP2 ADMIN · WERSJA ZAPASOWA
SESSION_COOKIE_NAME=sp2_preview_session
SESSION_COOKIE_SECURE=true
DATABASE_URI=sqlite:////var/lib/sp2-admin-preview/preview.sqlite3
SECRET_KEY=<oddzielny-silny-losowy-sekret>
SP2_API_TOKEN=<oddzielny-losowy-token-nieużywany-przez-agentów>
LDAP_URI=ldaps://<wewnętrzny-kontroler-domeny>
LDAP_BASE_DN=<baza-katalogu>
LDAP_BIND_DN=<konto-tylko-do-odczytu>
LDAP_BIND_PASSWORD=<hasło-konta-tylko-do-odczytu>
LDAP_WRITE_BIND_DN=
LDAP_WRITE_BIND_PASSWORD=
AD_JOIN_SERVICE_USER=
AD_JOIN_SERVICE_PASSWORD=
AGENT_ENROLLMENT_TOKEN=<oddzielny-losowy-token-nieużywany-przez-agentów>
WEB_FILTER_ENFORCEMENT_ENABLED=false
RADIO_PLAYBACK_ENABLED=false
RADIO_BELL_AUTOMATION_ENABLED=false
MONITORING_STREAMS_ENABLED=false
```

Przed startem utwórz katalogi `/var/lib/sp2-admin-preview` i
`/opt/sp2-admin-preview/instance`, oba z prawem zapisu tylko dla `sp2-preview`.
W pliku `ops/systemd/sp2-admin-preview.service.example` jest gotowy wzór usługi
wiążącej `gunicorn` tylko z `127.0.0.1:5051`. Po dostosowaniu ścieżek skopiuj go do
`/etc/systemd/system/sp2-admin-preview.service` i uruchom tę usługę oddzielnie.
Proxy HTTPS powinno
udostępniać ją pod nową nazwą hosta dostępną tylko administratorom (VPN / szkolna
sieć / ograniczenie IP). Nie kieruj do niej ruchu produkcyjnego ani agentów Windows.
Następnie załóż **osobne** konto administracyjne w bazie podglądu (`flask --app run.py
create-admin`). Nie kopiuj haseł, tokenów ani całego produkcyjnego `.env`.

## Lista kontroli przed decyzją o przełączeniu

1. Na osobnym adresie sprawdź `/health`, logowanie i wylogowanie oraz rozdzielenie sesji
   od starej aplikacji.
2. Otwórz logo, portret, poster PNG i film MP4; sprawdź ruch tła, tryb ograniczonego
   ruchu, ekran telefonu i ekran komputera.
3. Sprawdź dashboard, LDAP (użytkownicy, grupy, komputery, OU), sale, kreator
   nazw, agentów, usługi i diagnostykę. Zapisz, które widoki korzystają z pustej
   bazy podglądu i gdzie potrzebna jest zanonimizowana kopia danych.
4. Zweryfikuj, że próbne żądanie modyfikacji odpowiada 403 i nie zmienia AD,
   kolejki agentów ani produkcyjnej bazy.
5. Funkcje zapisu i naprawy testuj dopiero w odrębnej domenie testowej / na
   wydzielonej stacji. Nie wyłączaj starej aplikacji podczas tych prób.

## Wycofanie podglądu

Wyłącz tylko usługę i wpis proxy wersji zapasowej. Ruch do starej aplikacji nie jest
zmieniany przez tę gałąź.

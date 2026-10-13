# SP2 Serwis Domeny 2.0.1 — automatyczna autoryzacja

## Poprawka 2.0.1

Pole Token/kod pozostaw puste. Program sprawdza dostępność aktualnego API,
odczytuje zapisaną autoryzację, konfigurację SP2 Agenta i deployment.json.
Nieaktualny token (401), wygasły kod (401) i istniejąca rejestracja przy enrollment
(409) uruchamiają logowanie i zatwierdzenie komputera w przeglądarce. Program sam
odbiera nowy token i zachowuje go w pliku auth.json, szyfrowanym DPAPI oraz chronionym
uprawnieniami katalogu. Kolejne uruchomienia mogą korzystać z tej autoryzacji.
Obsługiwane klucze deployment.json: enrollment_token lub enrollment_code.

Podany adres musi prowadzić do panelu/API SP2 ADMIN. `https://dc.sp2.lan` jest
poprawny tylko wtedy, gdy właśnie tam wystawiono SP2 ADMIN z backendem z PR #52.
Sam kontroler domeny nie wydaje tokenu SP2 ADMIN. Na serwerze z kodem main bez
tej aktualizacji klient zgłosi brak API, zamiast prosić o ręczne podanie tokenu.
Sprawdzenie zgodności: GET /api/v1/agent/domain-repair/capabilities powinno zwrócić
service=sp2-admin-domain-repair, protocol=2, pairing=true. Ten endpoint nie wydaje
tokenów i nie wymaga logowania. Ruch HTTPS nie jest przekierowywany z sekretami.

Ta poprawka jest w PR #52 i pakiecie testowym; nie wykonuje wdrożenia na serwerze.

Uruchamianie: wypakuj cały ZIP do lokalnego folderu, otwórz
`SP2-Serwis-Domeny.exe` i zaakceptuj UAC. To skompilowany launcher Windows x64;
plik `SP2-Serwis-Domeny.ps1` musi pozostać obok EXE. Nie wymaga Pythona.
Wymaga Windows 10/11 Pro/Education/Enterprise, Windows PowerShell 5.1 i .NET 4.x.
EXE nie jest podpisany certyfikatem wydawcy. Respektuje politykę PowerShell
RemoteSigned i certyfikat HTTPS; nie wyłącza weryfikacji TLS. Jeżeli ZIP pochodzi
z internetu, po sprawdzeniu SHA256 odblokuj go we Właściwościach przed rozpakowaniem.
Polityka domenowa AllSigned wymaga podpisania skryptu przez administratora.


## Kontrola nazw Windows przed dolaczeniem do domeny

Przed potwierdzeniem planu `join` klient porownuje nazwe Windows, DNSHostName,
`[System.Net.Dns]::GetHostName()`, nazwe procesu, rejestr ActiveComputerName,
nazwe oczekujaca na restart oraz Tcpip/Parameters Hostname i NV Hostname.
Jesli nazwy sa niespojne (np. `LAPTOP-D9MFLC2P` i `WIN-L5Q9CJACB5B`),
klient pokazuje kazda niespojnosc jako `BLOKADA join`, zachowuje plan w stanie
`ready` i **nie** wysyla `progress begin`, nie uruchamia `Add-Computer`,
nie zmienia rejestru ani nie uruchamia restartu. To zabezpieczenie nie dotyczy
kontrolowanego wycofywania istniejacego `manual_review`: tam nadal obowiazuja
niezalezne warunki serwera i zatwierdzenie operatora.

Naprawa niespojnej nazwy wymaga osobnej, zatwierdzonej procedury Windows,
a potem powtornego odczytu planu. Nie uruchamiaj recznego `Add-Computer`
ani nie usuwaj plikow recovery, aby ominac te kontrole.

## Szkolny certyfikat HTTPS — bezpieczne pierwsze uruchomienie

Przed pierwszym polaczeniem z `https://dc.sp2.lan` program sprawdza szkolne CA:
`CN=SP2 ADMIN Internal CA`. Nazwa nie wystarcza — wymagany jest konkretny,
znany certyfikat o **SHA-256 DER**:
`45581ba7ef494ddce73702c8f7f4174a5f8309ddf342f12b78c7a097f2bbcd33`.
Dodatkowo sprawdzane sa zakres waznosci i BasicConstraints CA. Inny certyfikat,
brak pliku lub odmowa potwierdzenia **nie powoduje zadnego importu**.

Jesli CA jest juz zaufane w `Cert:\\LocalMachine\\Root`, program nie modyfikuje
magazynu. W przeciwnym razie korzysta z publicznego pliku
`sp2-internal-ca.crt` znajdujacego sie **obok EXE i skryptu**. Po weryfikacji
odcisku wyświetla operatorowi ostrzezenie o dodaniu szkolnego CA do calego
magazynu zaufanych glownych urzedow Windows. Import nastepuje tylko za
wyrazna zgoda i z uprawnieniami administratora. Ponowny start jest
idempotentny. Nie wylaczamy walidacji TLS ani sprawdzania CRL/OCSP.

`SP2-Serwis-Domeny-Portable.exe` obsluguje ten sam plik CA obok EXE:
najpierw niezaleznie sprawdza jego SHA-256, a nastepnie przekazuje go do
chronionego folderu roboczego w ProgramData. Dzieki temu na nowych komputerach
wystarczy wspolna paczka bez osobnego uruchamiania polecen `Import-Certificate`.

**Wazne:** artefakt z publicznego GitHub Actions CI nie zawiera szkolnego CA,
poniewaz plik znajduje sie na szkolnym serwerze, a CI nie ma do niego dostepu.
Nalezy zlozyc paczke na serwerze `szkolaak`, gdzie jest dostepny
`/home/baraqda/sp2-internal-ca.crt`:

```bash
python3 scripts/package-domain-repair-with-ca.py \\
  /sciezka/do/SP2-Serwis-Domeny.zip \\
  --ca /home/baraqda/sp2-internal-ca.crt \\
  --output /sciezka/do/SP2-Serwis-Domeny-z-CA.zip
```

Skrypt odrzuca nieznany CA, sprawdza **SHA-256 calego pliku**
`6206e04e6d6a8aef3676b95b2aed61ff55e48f39fc1b42ce6848da6ef7f43c43`,
SHA-256 certyfikatu DER i bezpieczenstwo sciezek ZIP. Kopiuje jedynie publiczny
`.crt` — **nigdy prywatnego klucza**. Wynikowa paczke nalezy wypakowac na
komputerach wraz z certyfikatem w tym samym folderze, nie rozdzielajac plikow.
Po przyznaniu zaufania klient laczy sie normalnym Windows HTTPS i oczekuje
`HTTP 200` z API `capabilities`. Dla innych serwerow niz `dc.sp2.lan:443`
program nie instaluje szkolnego CA.

Przy budowaniu bezposrednio na szkolnym komputerze z Windows mozna tez
utworzyc **naprawde jedno-plikowy Portable EXE** zawierajacy ten sam publiczny
CA jako zasob .NET (sam certyfikat, nigdy klucz prywatny):

```powershell
.\\build.ps1 -SchoolCaFile 'C:\\sp2-internal-ca.crt'
```

Kompilator odrzuca certyfikat o innym SHA-256. Standardowy ZIP nadal moze
uzywac publicznego pliku obok EXE; jest on weryfikowany przed importem.

Komputery juz nalezace do domeny moga otrzymac zaufanie do szkolnego CA
centralnie przez GPO; metoda z paczka jest szczegolnie wazna na stacjach
z WORKGROUP bez GPO. Jesli program wykryje istniejacy plan `pending` lub
`manual_review`, **nie ponawia** Join/Unjoin w ramach poprawki certyfikatu.

## Przygotowanie osobnego serwera testowego

Nie wdrażaj tej gałęzi na produkcyjnym SP2 ADMIN. Użyj kopii serwera/aplikacji,
oddzielnej bazy i najlepiej izolowanej domeny Samba oraz jednego komputera testowego.
Kopia podłączona do produkcyjnego AD nie jest izolowanym testem: klient wykonuje
realne operacje domenowe z uprawnieniami podanymi lokalnie przez operatora.

1. Pobierz gałąź `domain-repair-v2`; zainstaluj `pip install -e '.[dev]'` na Linux.
2. Skonfiguruj HTTPS z certyfikatem zaufanym przez Windows oraz LDAP zgodnie
   z `.env.example`: LDAP_URI, LDAP_BIND_DN, LDAP_BIND_PASSWORD, LDAP_BASE_DN.
   Hasło konta odczytu katalogu pozostaje konfiguracją serwera; klient go nie wysyła.
3. Ustaw AD_DOMAIN_FQDN, AD_JOIN_ALLOWED_OU_BASES (DN rozdzielone `|`) i DNS
   systemu Linux na DNS tej domeny. OU musi już istnieć. Puste allowed OU blokuje plan.
4. Ustaw osobną SQLALCHEMY_DATABASE_URI. Wykonaj backup tej bazy i
   `flask --app run.py init-db`. Repo używa `db.create_all()` również przy starcie;
   aktualizacja dodaje tabele `domain_recoveries` i `domain_recovery_pairings` z indeksami/ograniczeniami,
   bez zmiany starych tabel. Polecenie jest idempotentne. Nie ma Alembic w tym repo.
5. Serwer testu recovery musi dopuszczać POST. Tryb STAGING_READ_ONLY=true blokuje
   te endpointy z założenia; wyłącz go wyłącznie w odizolowanej instancji testowej.
6. Wygeneruj zwykły kod enrollment istniejącym panelem SP2 ADMIN albo użyj
   indywidualnego tokenu agenta testowego. Wspólny token nie otwiera planów recovery.
   Możesz też pozostawić token pusty i zalogować się w przeglądarce do SP2 ADMIN.
   Po zatwierdzeniu nazwy/UUID program pobierze token automatycznie. Żądanie jest
   ważne 10 minut; serwer ogranicza tworzenie żądań do 10 na adres w 10 minut.
   Dla istniejącej rejestracji panel wymaga osobnej zgody na wymianę tokenu.

## Próba na jednym komputerze

1. Zrób migawkę/kopię testowego Windows. Sprawdź logowanie na lokalnego
   administratora i uruchamiaj program z tego konta również po restartach.
2. Uruchom EXE. Podaj adres **testowego** SP2 ADMIN. OU możesz zostawić puste:
   program pobierze OU nauczycieli z konfiguracji serwera lub jednoznaczne OU sali
   uczniów z AD. Jeśli jest kilka pasujących OU, podaj właściwe ręcznie.
   Wybierz Nauczyciel, BR/PL, salę i numer: 0 → BR-S30, 1 → BR-S30-01.
   Dla ucznia sala 4/numer 9 daje S04-09. Nazwy sal są uzupełniane do dwóch cyfr.
3. Jeśli jest zainstalowany SP2 Agent, program automatycznie odczyta token z
   `C:\Program Files\SP2 Agent\agent-config.json`. Pole tokenu zostaw puste.
   Token zostanie użyty tylko przy identycznym adresie serwera. Nie kopiuje
   produkcyjnego tokenu do serwera testowego ani nie wyłącza kontroli certyfikatów.
   Przy nowym agencie wpisz kod enrollment i zaznacz odpowiednie pole; program
   wymieni kod na token. Nie pozwoli podmienić tokenu już zarejestrowanego komputera.
   Alternatywnie połóż obok programu `deployment.json` zgodny z konwencją projektu:
   `{"server_url":"https://TWOJ-SERWER-TESTOWY","enrollment_token":"KOD"}`.
   Program odczyta kod automatycznie. Chroń ten plik jak kod wdrożeniowy i usuń
   go z pendrive'a po zakończeniu/wygaśnięciu kodu. Bez konfiguracji otworzy panel
   logowania do SP2 ADMIN, więc nie musisz kopiować kodu. Login panelu jest odrębny
   od poświadczeń domenowych wpisywanych lokalnie w Get-Credential.
4. Naciśnij NAPRAW TEN KOMPUTER. Sprawdź pokazany plan i potwierdź operację.
   Poświadczenia domenowe wpisz w osobnym oknie Get-Credential. Nigdy nie wpisuj
   hasła administratora w pole tokenu. API odrzuca nieobsługiwane pola/hasła/logi.
5. Po Remove-Computer, Rename-Computer lub Add-Computer potrzebny jest restart.
   Możesz odłożyć restart, ale do tego czasu recovery nie przejdzie dalej.
   Zadanie `SP2-Domain-Recovery` otworzy GUI po zalogowaniu administratora.
   Wybierz WZNÓW RECOVERY. Hasło domenowe trzeba podać ponownie; nie jest zapisywane.
   Przed join/unjoin program zapewnia lokalne konto administratora SP2. Jeśli nie
   istnieje lub nie ma uprawnień, poprosi o ustalone przez Ciebie hasło lokalne,
   utworzy/uzupełni konto i doda je do Administratorów. Sprawnego, aktywnego
   administratora SP2 nie resetuje. Windows przechowuje zwykłe dane logowania
   lokalnego konta; program nie zapisuje jego jawnego hasła.
   Różnica czasu Windows–SP2 ADMIN powyżej 4 minut blokuje operacje. Nie zmienia
   automatycznie zegara ani konfiguracji W32Time. Sprawdź synchronizację z DC.
6. Przy braku konta komputera w AD i nadal aktywnym lokalnym członkostwie domeny
   recovery zatrzymuje się przed unjoin. Nie próbuje automatycznie Remove-Computer,
   nie włącza NTLM, nie wykonuje force-unjoin i nie manipuluje rejestrem. Stan wymaga
   osobnej, zatwierdzonej procedury odzyskania konta maszyny.
   Wariant `machine_account_recovery` jest domyslnie wylaczony; wymagania testu
   Windows/Samba bez NTLM oraz procedura wdrozenia sa opisane w
   [machine-account-recovery](../../docs/machine-account-recovery.md).
7. Wynik COMPLETE wymaga zgodnej nazwy, zdrowego kanału, konta AD, OU, DNS i SPN.
   Błędne OU/DNS/SPN zatrzymuje proces do kontroli administratora; ta wersja
   nie przenosi samodzielnie kont AD ani nie usuwa starych rekordów.

Osobno sprawdź konflikt: utwórz w **testowej** domenie drugie konto docelowe.
Plan musi zostać zablokowany, również dla starego/wyłączonego konta. Usuń konto
testowe ręcznie dopiero po ustaleniu jego właściciela. Sprawdź też utratę połączenia,
ponowne otwarcie GUI, restart przed join i odmowę dostępu tokenem innego agenta.

## Niepotwierdzone dolaczenie WORKGROUP i `manual_review`

Jesli operacja `join` zostala rozpoczęta, ale Windows zgłosił błąd albo
wynik jest niepewny, plan zachowuje rezerwacje i stan `manual_review`.
`OUTSIDE_DOMAIN` jest diagnoza Windows, a nie zezwoleniem na ponowienie.

Po **nowym restarcie Windows** i otwarciu `WZNOW RECOVERY` klient moze
zaproponowac **wycofanie starego niepotwierdzonego planu**, nie nowy join.
Dopiero po wyraznej zgodzie uzytkownika wysyla do serwera
`progress/<id>` z `event=cancel, approved=true`.
Serwer ponownie, niezaleznie od klienta weryfikuje przypisanie UUID/MAC,
poprawny plan i nowy boot_id, brak czlonkostwa Windows, brak docelowego
konta AD i konfliktu DNS/SPN. Jesli jakikolwiek warunek nie jest
potwierdzony, odpowiada HTTP 409 i **zachowuje rezerwacje**.
Klient nigdy sam nie usuwa kont AD, nie zmienia nazwy, nie wykonuje
`Add-Computer` i nie uruchamia nowej proby.

Dopiero po serwerowym `state=cancelled` operator wybiera osobno
`NAPRAW TEN KOMPUTER`, aby uzyskac nowy plan i sprawdzic nazwe oraz OU.
Gdy istnieje konto docelowe AD, urzadzenie jest w domenie albo nie ma
potwierdzonego ponownego uruchomienia, wymagana jest reczna diagnostyka
`C:\\Windows\\Debug\\NetSetup.log` i obiektu AD.

## Bledna nazwa: anulowanie planu przed startem i ZMIEN NAZWE

Pod polami wyboru program pokazuje podglad nazwy (np. `Nazwa: S07-03`).
Przed rezerwacja na serwerze operator potwierdza nazwe i OU w osobnym oknie.

Jesli mimo to zarezerwowano zla nazwe, plan mozna anulowac **tylko dopoki nie
zostal rozpoczety** (brak w historii `begin`, `credential_issued`,
`approve_ad`, `retry`, `failed`) - wtedy Windows i AD nie zostaly zmienione:

- okno *Plan naprawy*: **TAK** wykonuje, **NIE** anuluje plan i zwalnia nazwe,
  **ANULUJ** nic nie zmienia,
- przycisk **ANULUJ PLAN (bledna nazwa)** - to samo z dowolnego momentu,
- **NAPRAW TEN KOMPUTER** z inna sala/OU niz w istniejacym planie pyta, czy
  anulowac stary plan i zarezerwowac nowa nazwe,
- **ZMIEN NAZWE** rezerwuje *dokladnie* nazwe z podgladu (`auto_name=false`);
  zajeta nazwa daje `NAME_TAKEN`. Dla komputera w domenie serwer tworzy plan
  `rename_domain` (zmiana nazwy z kontem domenowym + restart).

Serwer (`progress/<id>`, `event=cancel, approved=true`, opcjonalnie `reason`)
niezaleznie sprawdza historie planu, urzadzenie (UUID/MAC) i nazwe Windows.
Plan rozpoczety odrzuca kodem `PLAN_ALREADY_STARTED`, inne niezgodnosci
kodem `CANCEL_NOT_ALLOWED` - rezerwacja zostaje. Po anulowaniu klient czysci
zapamietana nazwe i `request_id`, wiec `WZNOW RECOVERY` nie zarezerwuje
ponownie blednej nazwy. Plan rozpoczetego join nadal wycofuje sie tylko
sciezka opisana wyzej (nowy restart, brak konta AD).

**Kolejnosc wdrozenia:** najpierw serwer SP2 ADMIN, potem nowy EXE (starszy
serwer odrzuci pole `reason` kodem HTTP 400).

## Recovery, logi i ograniczenia

- Stan serwera: tabela `domain_recoveries`, wersja optymistyczna, historia etapów,
  rezerwacja nazwy i agenta. Nie wygasa automatycznie podczas restartu/offline.
- Stan klienta: `C:\ProgramData\SP2-Domain-Recovery\pending.json`, atomowy zapis,
  ACL tylko Administratorzy/SYSTEM. Token API jest szyfrowany DPAPI komputera;
  nie jest to hasło domenowe. Stan może odczytać lokalny administrator tego samego
  komputera, również SP2 po restarcie. Nie kopiuj recovery na inne komputery.
- Hasło domenowe jest wyłącznie w PSCredential w pamięci; po operacji SecureString
  jest zwalniany. Nie ma hasła w JSON, argumentach procesu, rejestrze ani zadaniu.
- Crash log: `C:\ProgramData\SP2-Domain-Recovery\crash.log` (czas/kod/typ/linia).
  Błąd launchera: `%LOCALAPPDATA%\SP2-Domain-Recovery-launcher.log`.
  Komunikaty wyjątków/odpowiedzi HTTP nie są zapisywane, aby nie ujawnić sekretów.
- Serwer sprawdza LDAP dla obu nazw, SID, OU, dNSHostName, SPN, lastLogonTimestamp;
  DNS rozwiązuje przez konfigurację systemu serwera. Aktywność AD nie jest dowodem
  obecności komputera. Ostatni heartbeat innego agenta jest dodatkową informacją,
  nigdy podstawą automatycznego usunięcia konta.
- Rezerwacje chronią równoległe plany aplikacji; nie blokują administratora
  zmieniającego AD poza aplikacją. AD jest sprawdzane ponownie przed operacją.
- Raport Windows jest raportem uwierzytelnionego agenta, nie sprzętową atestacją.
  Traktuj token jak sekret administratora urządzenia.
- Niepewne lub nieudane operacje nie są wykonywane ponownie automatycznie.
  `manual_review` zachowuje rezerwację. Administrator może po kontroli stanu
  wywołać progress z event=cancel; pending wymaga najpierw observe po restarcie.
- API: POST diagnose, enroll, plan; GET status, status/<id>;
  POST progress/<id> (version, device_id, event, local). Wszystkie pod
  `/api/v1/agent/domain-repair/`, Bearer w nagłówku. Enrollment służy wyłącznie
  wymianie kodu na token nowego agenta. Idempotencja planu: request_id UUID.

## Samodzielna naprawa zaufania zamiast odbudowy konta

Przypadek S11-15 (2026-10-13): komputer w domenie, `secure channel: False`,
konto `S11-15` istnieje w AD, ale urządzenie nie miało przypiętego SID, więc
serwer zaplanował odbudowę konta pod nową nazwą (`S11-16`). Natywny join nie
powiódł się już po wydaniu autoryzacji i plan utknął w `manual_review`
(„serwer wydał już autoryzację joinu”).

Teraz program sam wychodzi z tego stanu, **bez ponawiania joinu**:

1. **Nazwa:** jeśli nieudana próba zaplanowała zmianę nazwy na następny
   rozruch (`ComputerName`/`NV Hostname` = S11-16), program po potwierdzeniu
   cofa ją do bieżącej nazwy. Inaczej restart zerwałby zaufanie ponownie.
2. **Czas:** gdy W32Time nie synchronizuje się z niczym (`Local CMOS Clock`,
   bo Samba bez `ntp_signd` nie podpisuje NTP), ustawia
   `192.168.0.143,0x8`. Działające źródło domenowe/GPO nie jest nadpisywane.
3. **Zaufanie:** `Test-ComputerSecureChannel -Server szkolaak.sp2.lan -Repair`
   resetuje hasło ISTNIEJĄCEGO konta. Nazwa, OU i SID się nie zmieniają.
   Wynik jest weryfikowany drugim, niezależnym odczytem.
4. **Zamknięcie planu:** `progress/<id>` z `event=resolve`, `approved=true`.
   Serwer niczego nie zmienia w AD, tylko sprawdza: ten sam sprzęt (UUID/MAC),
   Windows w domenie z działającym kanałem pod nazwą źródłową, konto włączone
   w dozwolonym OU, `pwdLastSet` **późniejsze** niż ostatnia próba odbudowy
   oraz brak konta pod porzuconą nazwą docelową. Plan dostaje stan `cancelled`
   (historia: `resolved_locally`), rezerwacja jest zwalniana, a urządzenie
   dostaje przypięty SID, więc kolejne awarie zaufania idą ścieżką
   `repair_secure_channel` zamiast nowej nazwy. Każdy niespełniony warunek
   zwraca `LOCAL_REPAIR_NOT_VERIFIED` z listą `blockers`.

Przy nowym obchodzie (`NAPRAW TEN KOMPUTER`) zepsute zaufanie jest naprawiane
lokalnie **przed** poproszeniem serwera o plan. Jeśli nazwa pasuje do
wybranej sali, nie powstaje żaden plan ani rezerwacja. Odbudowa konta pod
nową nazwą zostaje tylko wtedy, gdy konto AD nie istnieje albo lokalna
naprawa się nie udała.

## Budowanie i weryfikacja

`build.ps1` kompiluje Launcher.cs lokalnym kompilatorem .NET Framework i kopiuje
skrypt z UTF-8 BOM. `SP2-Serwis-Domeny.exe --self-test` sprawdza uruchomienie
PowerShell, budowę GUI, DPAPI i nazewnictwo bez kontaktu z AD, zmian komputera,
zapisu recovery i restartu.
Testy Python obejmują API, autoryzację, plan, konflikty i scenariusz dwóch restartów
na kontrolowanych danych. Nie zastępują rzeczywistego testu Windows ↔ Samba.

Ten pakiet jest wydaniem testowym, nie potwierdzoną wersją do 200 stanowisk.
Nie wykonano wdrożenia produkcyjnego ani merge do main.

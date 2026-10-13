# SP2 ADMIN 7.1.0-dev.1

Panel administracyjny dla serwera Ubuntu 24.04 LTS z Samba Active Directory Domain Controller.

## Dostępne moduły

- lokalne logowanie administratorów, role, CSRF i audyt,
- użytkownicy, grupy, komputery i jednostki OU z Samba AD przez LDAP,
- monitoring komputerów i agentów Windows,
- sale komputerowe,
- kolejka ograniczonych poleceń administracyjnych,
- kontrolowana instalacja oprogramowania z weryfikacją SHA-256,
- API v1 chronione wspólnym tokenem,
- testy automatyczne na Pythonie 3.11 i 3.14,
- walidacja agenta i instalatora na środowisku Windows.
- centrum usług szkoły z konfiguracją filtrowania stron oraz bezpiecznymi
  podstawami Radiowęzła, Monitoringu i audytu dysków sieciowych.
- bezpieczne raporty stanu, testów i zagregowanych zdarzeń dla
  ograniczonego konta SSH `codex-audit`.

## Wymagania

- Ubuntu 24.04 LTS,
- Python 3.11–3.14,
- działająca domena Samba AD,
- konto LDAP tylko do odczytu dla operacji katalogowych,
- osobne konto o ograniczonych uprawnieniach dla dozwolonych operacji zapisu,
- HTTPS z poprawnym certyfikatem w środowisku produkcyjnym.

## Instalacja deweloperska

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
cp .env.example .env
flask --app run.py init-db
flask --app run.py create-admin
flask --app run.py run --host 0.0.0.0 --port 5000
```

Nie zapisuj prawdziwych haseł ani tokenów w repozytorium. Plik `.env` jest lokalny i musi pozostać poza Git.


## Radiowęzeł przez wyjście audio 3,5 mm

Odtwarzanie jest ręczne: panel uruchamia wybraną playlistę MP3/WAV na serwerze,
a przycisk **Zatrzymaj odtwarzanie** kończy proces. Aktualizacja aplikacji ani
restart usługi nie uruchamiają muzyki automatycznie.

Na serwerze Ubuntu zainstaluj odtwarzacz i narzędzia audio:

```bash
sudo apt update
sudo apt install -y mpv alsa-utils espeak-ng
sudo usermod -aG audio UZYTKOWNIK_USLUGI_SP2_ADMIN
```

Po ponownym zalogowaniu użytkownika usługi sprawdź wyjście 3,5 mm przy
odłączonym lub ściszonym wzmacniaczu:

```bash
speaker-test -t sine -f 1000 -l 1
```

Następnie ustaw w lokalnym pliku `.env`:

```dotenv
RADIO_PLAYBACK_ENABLED=true
RADIO_PLAYER_BINARY=mpv
RADIO_AUDIO_DEVICE=auto
RADIO_TTS_BINARY=espeak-ng
RADIO_TTS_VOICE=pl
RADIO_TTS_SPEED=165
```

Generator komunikatów działa lokalnie i nie wysyła tekstu do zewnętrznych usług.
Treść (maksymalnie 500 znaków) jest zamieniana na tymczasowy plik WAV przez
`espeak-ng`, a następnie odtwarzana tym samym wyjściem audio co playlisty.

Po zmianie konfiguracji uruchom ponownie usługę `sp2-admin`. Jeśli serwer ma
więcej kart dźwiękowych, właściwą wartość można odczytać poleceniem
`mpv --audio-device=help` i wpisać jako `RADIO_AUDIO_DEVICE`.

## Testy

```bash
ruff check .
pytest
```

GitHub Actions wykonuje te kontrole na Pythonie 3.11 i 3.14. Osobne zadanie Windows sprawdza zależności agenta, kod Pythona oraz składnię instalatora PowerShell.

Raportowanie serwera dla konta tylko do odczytu opisano w
[`docs/audit-reporting.md`](docs/audit-reporting.md).

## Agent Windows

Wspierany agent znajduje się w katalogu [`agent-windows`](agent-windows/README.md). Przed wdrożeniem na stanowiska produkcyjne instalator należy sprawdzić na oddzielnym komputerze testowym lub maszynie wirtualnej.

## Bezpieczeństwo

Przed wdrożeniem produkcyjnym:

- ustaw silny losowy `SECRET_KEY`,
- ustaw silny `SP2_API_TOKEN`,
- używaj LDAPS/HTTPS i poprawnych certyfikatów,
- ustaw `SESSION_COOKIE_SECURE=true`,
- ogranicz uprawnienia kont LDAP,
- wykonaj rotację każdego sekretu, który mógł zostać ujawniony,
- nie dodawaj plików `.env`, kopii zapasowych ani konfiguracji agentów do Git.

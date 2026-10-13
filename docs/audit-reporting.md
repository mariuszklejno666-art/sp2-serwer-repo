# Bezpieczne raportowanie dla konta `codex-audit`

Konto `codex-audit` nie otrzymuje zwykłej powłoki, `sudo`, dostępu do
produkcyjnego pliku `.env`, bazy danych ani surowego dziennika systemowego.
Autoryzowany klucz SSH uruchamia wyłącznie
`/usr/local/bin/sp2-audit-shell`.

## Publikowane raporty

Co pięć minut tworzony jest raport `logs.txt`, zawierający:

- stan usługi `sp2-admin.service`,
- dozwolone pola endpointu `/health`,
- wersję aplikacji,
- wykorzystanie głównego systemu plików,
- liczbę ostrzeżeń, błędów, odpowiedzi HTTP 5xx i 401/403.

Surowe komunikaty dziennika są przetwarzane wyłącznie w pamięci i nigdy
nie trafiają do raportu.

Raz dziennie wykonywane są `pytest` i `ruff`. Plik `checks.txt` zawiera
wyłącznie status kontroli, liczbę testów i czas wykonania. Nazwy testów,
ścieżki, wyjątki i pełne wyjście narzędzi są ukryte.

Testy działają jako `codex-audit` w piaskownicy systemd. Produkcyjny
`.env` jest zastępowany pustym plikiem, a produkcyjny katalog `instance`
pustym katalogiem tylko do odczytu.

## Instalacja

Wymagane jest istniejące, ograniczone konto systemowe `codex-audit`.
Instalator celowo nie tworzy konta, kluczy SSH ani reguł zdalnego
dostępu. Przed instalacją należy potwierdzić, że konto:

- nie należy do grup `sudo`, `adm` ani `systemd-journal`,
- może uruchomić interpreter środowiska aplikacji i odczytać jej kod,
- nie może odczytać produkcyjnego pliku `.env`.

Po wdrożeniu aplikacji:

```bash
cd /home/baraqda/sp2-admin-6.0.0-commit-0003
sudo ./ops/install-audit-report.sh "$PWD"
```

Instalator uruchamia obydwa raporty od razu, a następnie aktywuje timery:

```bash
systemctl list-timers 'sp2-audit-*'
```

Konto audytowe może odczytać raporty przez dozwolone polecenia SSH:

```bash
ssh codex-audit@dc.sp2.lan checks
ssh codex-audit@dc.sp2.lan logs
```

## Ograniczenia bezpieczeństwa

- raport nie zawiera surowych wpisów dziennika,
- raport nie zawiera pełnego wyjścia `pytest` ani `ruff`,
- nie są publikowane zmienne środowiskowe ani konfiguracja systemd,
- prywatny klucz SSH nie może trafić do repozytorium,
- konto `codex-audit` nie może należeć do grup `sudo`, `adm` ani
  `systemd-journal`.


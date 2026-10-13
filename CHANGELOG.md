# Changelog

## 7.1.0-dev.1 — 2026-07-23

- API v1 chronione wspólnym tokenem `SP2_API_TOKEN`,
- rejestracja, heartbeat, pobieranie poleceń i raportowanie wyników agentów,
- kolejka ograniczonych poleceń administracyjnych z kontrolą roli administratora,
- monitoring komputerów, szczegóły agenta i historia zadań,
- moduł sal komputerowych i przypisanie agenta przez pole `room`,
- kontrolowana instalacja pakietów z weryfikacją SHA-256,
- agent Python dla Windows instalowany jako usługa `SP2Agent`,
- automatyczne testy i lint w GitHub Actions dla Pythona 3.11 oraz 3.14.
- centrum „Usługi szkoły” z panelami filtrowania stron, Radiowęzła,
  Monitoringu i audytu dysków sieciowych,
- konfiguracja domen blokowanych dla sal 4, 7, 11 i 32 bez aktywowania
  egzekwowania w środowisku produkcyjnym,
- ograniczenie paneli kierownictwa do ról `administrator`, `dyrektor`
  i `wicedyrektor`.
- automatyczny, bezpieczny raport stanu usługi i zagregowanych zdarzeń
  bez udostępniania surowych logów,
- nocny raport `pytest` i `ruff` bez nazw testów, ścieżek, wyjątków
  ani danych konfiguracyjnych.

## 0.3.0 — Commit 0003

- odczyt użytkowników, grup i komputerów Samba AD przez `ldap3`,
- wyszukiwanie i tabele katalogowe,
- test połączenia LDAP z panelu,
- bezpieczne escapowanie filtrów LDAP i czytelna obsługa błędów konfiguracji.

## 0.2.0 — Commit 0002

- lokalne konta administratorów w SQLite,
- logowanie i wylogowanie,
- hasła hashowane przez Werkzeug,
- ochrona CSRF,
- zabezpieczenie dashboardu przez Flask-Login,
- audyt udanych i nieudanych logowań,
- komendy `init-db` i `create-admin`,
- testy logowania i audytu.

## 0.1.0 — Commit 0001

- inicjalizacja aplikacji Flask,
- dashboard startowy,
- endpoint `/health`,
- logo i podstawowy interfejs.

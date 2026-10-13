# Usługi szkoły

Moduł grupuje cztery planowane integracje. W pierwszym etapie wszystkie
integracje wykonawcze są domyślnie wyłączone.

## Role

- `administrator` — konfiguracja filtrowania stron i dostęp do wszystkich paneli,
- `dyrektor` — Radiowęzeł, Monitoring i audyt dysków,
- `wicedyrektor` — Radiowęzeł, Monitoring i audyt dysków,
- `viewer` — bez dostępu do paneli chronionych.

## Blokowanie stron

Panel zapisuje domenę oraz sale 4, 7, 11 i 32 objęte regułą. Wklejenie
adresu podstrony zapisuje domenę, dzięki czemu reguła obejmie cały serwis.

Samo zapisanie reguły nie zmienia DNS ani ustawień komputerów. Przed
włączeniem egzekwowania trzeba wybrać jeden mechanizm:

1. polityki URL dla Edge/Chrome przypisane do OU sal,
2. filtrowanie DNS z rozpoznawaniem komputerów lub podsieci,
3. kontrolowany serwer proxy.

Nie należy wymuszać blokad przez lokalny plik `hosts`, ponieważ taka metoda
jest trudna do audytu, niespójna i łatwa do obejścia.

## Radiowęzeł

Etap 1 udostępnia:

- kalendarz w strefie Europe/Warsaw,
- klasyfikację dni nauki, weekendów, świąt i przerw,
- własne wyjątki: dni dyrektorskie, dni specjalne i dni nauki,
- jawny podgląd decyzji, czy danego dnia dzwonki mają być aktywne.

Kalendarz nie uruchamia dźwięku. Następne etapy obejmą warianty planu
dzwonków, komunikaty oraz bezpieczną bibliotekę audio.

Przed implementacją odtwarzania trzeba wskazać docelowe urządzenie audio:
kartę dźwiękową serwera, komputer radiowęzła albo głośniki sieciowe.

## Automatyczne dzwonki

Każdej godzinie w planie można przypisać plik MP3/WAV z biblioteki. Wykonawca
respektuje kalendarz szkolny, aktywny plan i dni z wyłączonymi dzwonkami. Nie
przerywa ręcznie uruchomionej playlisty ani komunikatu — w razie zajętego
odtwarzacza zapisuje ostrzeżenie i pomija dzwonek.

Automatyka ma osobny bezpiecznik i domyślnie pozostaje wyłączona:

```env
RADIO_PLAYBACK_ENABLED=true
RADIO_BELL_AUTOMATION_ENABLED=false
```

Po przypisaniu dźwięków i sprawdzeniu planu ustaw
`RADIO_BELL_AUTOMATION_ENABLED=true`, zrestartuj `sp2-admin` i zainstaluj timer:

```bash
cd /sciezka/do/sp2-admin
bash scripts/install-radio-bells-timer.sh "$PWD"
systemctl list-timers sp2-radio-bells.timer --no-pager
```

Próbę bez oczekiwania na timer można wykonać poleceniem:

```bash
.venv/bin/flask --app run.py radio-bells-tick
```

## Monitoring

Obraz będzie dostępny wyłącznie dla administratora, dyrektora
i wicedyrektora. Integracja wymaga:

- modelu rejestratora NVR/DVR,
- protokołu udostępniania obrazu,
- osobnego konta tylko do podglądu,
- HTTPS lub chronionego połączenia wewnętrznego,
- audytu otwarcia panelu i podglądu kamery.

Hasła i pełne adresy strumieni nie mogą trafić do repozytorium.

## Dyski sieciowe

Audyt ma być najpierw wykonywany wyłącznie do odczytu i porównywać:

- członkostwo użytkownika w grupach AD,
- oczekiwane mapowanie dysków,
- prawa udziału Samba,
- prawa systemu plików,
- rzeczywisty dostęp z konta testowego nauczyciela i ucznia.

Zmiany uprawnień mogą być wykonane dopiero po zatwierdzeniu tabeli
„oczekiwany dostęp / rzeczywisty dostęp”.

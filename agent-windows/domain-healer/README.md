# SP2 Domain Healer

Pakiet do cyklicznej diagnostyki i bezpiecznej naprawy typowych problemów komputerów Windows należących do domeny Samba AD `sp2.lan`.

## Co wykrywa

- brak lub nieprawidłowy DNS domenowy,
- brak rekordu SRV `_ldap._tcp.dc._msdcs.sp2.lan`,
- brak wykrywania kontrolera domeny przez `nltest`,
- zatrzymaną usługę Netlogon,
- problemy z synchronizacją czasu,
- uszkodzony secure channel / relację zaufania,
- brak lokalnego awaryjnego konta administratora `SP2` przed procedurą rejoin.

## Co naprawia automatycznie

Tryb `Auto` działa bez hasła administratora domeny i wykonuje wyłącznie bezpieczne operacje lokalne:

- ustawia DNS `192.168.0.143` na aktywnych fizycznych kartach sieciowych,
- czyści cache DNS,
- uruchamia lub restartuje Netlogon,
- wymusza ponowną synchronizację czasu,
- ponownie testuje dostęp do domeny i secure channel,
- zapisuje raport JSON oraz log.

## Uszkodzony secure channel

Jeżeli zwykłe naprawy nie wystarczą, raport otrzymuje status:

- `REJOIN_REQUIRED` — secure channel jest uszkodzony, ale lokalne konto awaryjne `SP2` istnieje, jest aktywne i należy do lokalnych administratorów,
- `REJOIN_BLOCKED_NO_RECOVERY_ADMIN` — nie wolno automatycznie odłączać komputera, bo brak bezpiecznego konta awaryjnego.

Pakiet celowo **nie zapisuje hasła `SP2\\Administrator` na stacjach roboczych** i w wersji v1 nie wykonuje samodzielnie odłączenia/rejoin. Właściwy następny etap to powiązanie z serwerem SP2 ADMIN i jednorazowym, kontrolowanym mechanizmem rejoin.

## Naprawa ręczna z poświadczeniem domenowym

Uruchom PowerShell jako administrator:

```powershell
cd 'C:\Program Files\SP2 Agent\DomainHealer'
.\SP2-Domain-Healer.ps1 -Mode Repair
```

Skrypt poprosi o konto domenowe dopiero wtedy, gdy secure channel jest uszkodzony. Próbuje kolejno `Test-ComputerSecureChannel -Repair` oraz `Reset-ComputerMachinePassword`.

## Instalacja

Z katalogu pakietu uruchom jako administrator:

```powershell
.\install-domain-healer.ps1
```

Instalator tworzy zadanie Harmonogramu zadań `SP2 Domain Healer` działające jako `SYSTEM`, przy starcie systemu i domyślnie co 30 minut.

Można zmienić częstotliwość:

```powershell
.\install-domain-healer.ps1 -IntervalMinutes 15
```

## Pliki robocze

- raport: `C:\ProgramData\SP2-Agent\DomainHealer\last-report.json`
- log: `C:\ProgramData\SP2-Agent\DomainHealer\domain-healer.log`

## Kody wyjścia

- `0` — OK,
- `20` — problem z DNS/DC,
- `30` — komputer nie należy do domeny,
- `40` — wymagany bezpieczny rejoin,
- `41` — rejoin zablokowany, brak lokalnego konta awaryjnego,
- `10` — brak uprawnień administratora.

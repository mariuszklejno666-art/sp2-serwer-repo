# SP2 Agent dla Windows

Zalecany wariant dla nowych komputerów to samodzielny `SP2Agent.exe`. Na stacjach docelowych nie trzeba instalować Pythona, `pip` ani `pywin32`.

## Wariant zalecany: samodzielny EXE

Paczka z GitHub Actions `Build Windows Agent` zawiera:

- `SP2Agent.exe` — gotowy agent z dołączonym runtime,
- `install-agent.ps1` — instalator dla Windows,
- `deployment.example.json` — szablon konfiguracji masowego wdrożenia,
- `README.md`.

### Instalacja pojedynczego komputera

Uruchom PowerShell jako administrator i wykonaj:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-agent.ps1 -ServerUrl "http://192.168.0.143"
```

Jeśli obok instalatora nie ma `deployment.json`, instalator poprosi o kod wdrożeniowy wygenerowany w panelu SP2 ADMIN. Kod jest ważny 8 godzin i domyślnie może zarejestrować do 100 różnych komputerów. Serwer wydaje następnie każdemu komputerowi oddzielny token urządzenia i tylko ten indywidualny token zostaje zapisany lokalnie.

### Instalacja bezobsługowa / GPO

Skopiuj `deployment.example.json` jako `deployment.json` i ustaw:

```json
{
  "server_url": "http://192.168.0.143",
  "enrollment_code": "TUTAJ_KOD_WDROZENIOWY_Z_PANELU",
  "room": "",
  "interval_seconds": 60
}
```

Gdy `deployment.json` znajduje się obok `install-agent.ps1`, instalacja jest bezobsługowa:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-agent.ps1
```

To jest wariant przeznaczony do wdrożenia przez GPO/Samba AD na dużej liczbie komputerów.

## Jak działa rejestracja

1. Instalator kontaktuje się z `/api/v1/agent/register` używając czasowego kodu wdrożeniowego.
2. SP2 ADMIN zapisuje komputer i generuje indywidualny token urządzenia.
3. Instalator zapisuje indywidualny token w `C:\Program Files\SP2 Agent\agent-config.json` jako UTF-8 bez BOM.
4. ACL ogranicza odczyt konfiguracji do SYSTEM i lokalnych administratorów.
5. Agent uruchamia się jako zadanie SYSTEM przy starcie Windows i wysyła heartbeat.

Kod wdrożeniowy może być używany przez kolejne komputery aż do wygaśnięcia lub osiągnięcia limitu. Heartbeaty, przypisanie profilu i polecenia używają wyłącznie indywidualnego tokenu urządzenia.

## Konfiguracja serwera

W `.env` serwera ustaw osobny token rejestracyjny:

```text
AGENT_ENROLLMENT_TOKEN=dlugi-losowy-sekret-do-wdrozen
```

Jeśli zmienna nie jest ustawiona, SP2 ADMIN dla zgodności użyje `SP2_API_TOKEN`. Do środowiska produkcyjnego zalecany jest osobny `AGENT_ENROLLMENT_TOKEN`.

Po zmianie `.env` zrestartuj usługę SP2 ADMIN.

## Awaryjne odłączenie od Samba AD

Skrypt `emergency-leave-samba.ps1` jest oddzielnym trybem serwisowym. Nie uruchamia się podczas normalnej migracji Entra → Samba.

Przed zmianą sprawdza, czy komputer należy do `sp2.lan`, a lokalne konto `.\\SP2` jest włączonym administratorem. Następnie zapisuje DNS aktywnych kart, wymaga wpisania dokładnego potwierdzenia `ODLACZ` i pobiera poświadczenia domenowe wyłącznie do pamięci.

Po kontrolowanym restarcie zadanie SYSTEM:

1. potwierdza brak członkostwa w domenie,
2. sprawdza grupę `WORKGROUP`,
3. opcjonalnie przywraca zapisany DNS,
4. zapisuje raport bez sekretów w `C:\\ProgramData\\SP2-Emergency-Leave\\emergency-leave.log`.

Uruchomienie z paczki USB:

```text
TRYB-AWARYJNY-ODLACZ.cmd
```

## Automatyczny start

Instalator tworzy zadanie Harmonogramu zadań `SP2Agent` uruchamiane jako `SYSTEM` przy starcie komputera. Dzięki temu omijamy problemy z rejestracją usługi `pywin32` na stacjach docelowych.

Weryfikacja:

```powershell
Get-ScheduledTask -TaskName SP2Agent
Get-ScheduledTaskInfo -TaskName SP2Agent
Get-Content "C:\ProgramData\SP2-Agent\agent.log" -Tail 50
```

## Budowanie EXE

Python jest potrzebny wyłącznie na komputerze deweloperskim lub runnerze GitHub Actions:

```powershell
.\build-agent.ps1
```

Wynik:

```text
dist\SP2Agent.exe
```

## Starszy wariant Python

`sp2_agent.py`, `install-agent.ps1` i `requirements.txt` pozostają w repozytorium dla zgodności i diagnostyki. Nie są zalecane do masowego wdrożenia.

## Bezpieczeństwo

- docelowo używaj HTTPS i poprawnego certyfikatu,
- trzymaj `deployment.json` w zasobie wdrożeniowym dostępnym tylko dla administratorów i komputerów domenowych,
- do paczek USB używaj wyłącznie czasowego kodu wdrożeniowego z panelu,
- każdy zarejestrowany komputer otrzymuje własny token urządzenia,
- kod wdrożeniowy wygasa po 8 godzinach i domyślnie obsługuje maksymalnie 100 różnych komputerów.

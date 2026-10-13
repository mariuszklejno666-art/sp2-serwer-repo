# Masowe wdrożenie SP2Agent przez GPO (Samba AD)

## Cel

Automatyczna instalacja/aktualizacja `SP2Agent.exe` przy starcie Windows bez instalowania Pythona i bez ręcznego wpisywania tokenu na każdej stacji.

## Pliki publikowane w SYSVOL

Docelowy katalog:

`\\szkolaak.sp2.lan\SYSVOL\sp2.lan\scripts\SP2-Agent`

Powinien zawierać:

- `SP2Agent.exe`
- `install-agent.ps1`
- `deployment.json`
- `gpo-install-agent.ps1`

`deployment.json` zawiera wyłącznie token wdrożeniowy `AGENT_ENROLLMENT_TOKEN`. Backend po rejestracji wydaje oddzielny token urządzenia, który jest zapisywany lokalnie w `C:\Program Files\SP2 Agent\agent-config.json`.

## Ważne bezpieczeństwo

SYSVOL jest zwykle czytelny dla uwierzytelnionych użytkowników domeny. Token wdrożeniowy nie daje dostępu do poleceń agentów, ale pozwala rejestrować nowe urządzenia. Po zakończeniu masowego wdrożenia zalecana jest rotacja `AGENT_ENROLLMENT_TOKEN` oraz ponowne wygenerowanie `deployment.json` przed kolejną falą instalacji.

Nie umieszczaj `SP2_API_TOKEN` w SYSVOL.

## Konfiguracja GPO

W GPMC utwórz GPO np. `SP2 - Agent Windows` i podlinkuj do OU zawierającej komputery.

Przejdź do:

`Computer Configuration -> Windows Settings -> Scripts (Startup/Shutdown) -> Startup`

Dodaj skrypt PowerShell uruchamiający:

`\\szkolaak.sp2.lan\SYSVOL\sp2.lan\scripts\SP2-Agent\gpo-install-agent.ps1`

Jeżeli edytor GPO wymaga wrappera `.cmd`, użyj:

```cmd
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "\\szkolaak.sp2.lan\SYSVOL\sp2.lan\scripts\SP2-Agent\gpo-install-agent.ps1"
```

## Zachowanie skryptu

Skrypt:

1. sprawdza kompletność paczki w SYSVOL,
2. liczy SHA-256 paczki,
3. pomija komputer, jeśli agent jest zainstalowany i paczka się nie zmieniła,
4. kopiuje paczkę do `C:\ProgramData\SP2-Agent-Deploy`,
5. uruchamia `install-agent.ps1` jako startup/SYSTEM,
6. zapisuje marker wersji paczki,
7. zapisuje log do `C:\ProgramData\SP2-Agent\gpo-deploy.log`.

Aktualizacja paczki w SYSVOL automatycznie powoduje reinstalację/aktualizację przy następnym starcie komputera.

## Test pilotażowy

Najpierw podlinkuj GPO tylko do OU z 1-3 komputerami testowymi. Po restarcie sprawdź:

```powershell
Get-ScheduledTask SP2Agent
Get-Content "C:\ProgramData\SP2-Agent\gpo-deploy.log" -Tail 50
Get-Content "C:\ProgramData\SP2-Agent\agent.log" -Tail 50
```

Dopiero po potwierdzeniu heartbeat i poprawnej inwentaryzacji rozszerz link GPO na pozostałe OU.

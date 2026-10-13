[CmdletBinding()]
param(
    [string]$DomainName = 'sp2.lan',
    [string]$DomainAdmin = 'SP2\Administrator',
    [string]$LocalAdminName = 'SP2',
    [switch]$Resume,
    [switch]$RestoreDns,
    [switch]$NoRestoreDns
)

$ErrorActionPreference = 'Stop'
$Root = Join-Path $env:ProgramData 'SP2-Emergency-Leave'
$StatePath = Join-Path $Root 'state.json'
$ScriptPath = Join-Path $Root 'emergency-leave-samba.ps1'
$LogPath = Join-Path $Root 'emergency-leave.log'
$TaskName = 'SP2EmergencyLeaveResume'

function Write-ServiceLog([string]$Message) {
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $line | Tee-Object -FilePath $LogPath -Append | Write-Host
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Uruchom TRYB-AWARYJNY-ODLACZ.cmd jako administrator.'
    }
}

function Get-ComputerSystem {
    try {
        return Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    }
    catch {
        return Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
    }
}

function Assert-LocalRecoveryAdmin([string]$Name) {
    $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if (-not $user) {
        throw "Brak lokalnego konta awaryjnego .\$Name. Najpierw uruchom normalny kreator migracji, który tworzy to konto."
    }
    if (-not $user.Enabled) {
        throw "Lokalne konto awaryjne .\$Name jest wyłączone. Włącz je przed odłączeniem domeny."
    }

    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    $isMember = @(Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction Stop |
        Where-Object { $_.SID -eq $user.SID }).Count -gt 0
    if (-not $isMember) {
        throw "Lokalne konto .\$Name nie należy do grupy $($adminGroup.Name)."
    }
    Write-Host "Konto awaryjne .\$Name istnieje, jest włączone i ma prawa administratora."
}

function Get-ActiveDnsSnapshot {
    $snapshot = @()
    foreach ($adapter in @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up')) {
        $ipv4 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
        $snapshot += [ordered]@{
            interface_guid = [string]$adapter.InterfaceGuid
            interface_alias = [string]$adapter.Name
            interface_index = [int]$adapter.ifIndex
            server_addresses = @($ipv4.ServerAddresses)
        }
    }
    if ($snapshot.Count -eq 0) {
        throw 'Nie znaleziono aktywnej karty sieciowej do zapisania ustawień DNS.'
    }
    return $snapshot
}

function Save-State([bool]$ShouldRestoreDns, [array]$DnsSnapshot, [string]$Phase) {
    [ordered]@{
        phase = $Phase
        expected_workgroup = 'WORKGROUP'
        previous_domain = $DomainName
        restore_dns = $ShouldRestoreDns
        dns_snapshot = $DnsSnapshot
        created_at = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Depth 6 | Set-Content -Path $StatePath -Encoding UTF8
}

function Install-ResumeTask {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -Resume' -f $ScriptPath
    )
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

function Remove-ResumeArtifacts {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $StatePath -Force -ErrorAction SilentlyContinue
}

function Resolve-SavedAdapter($Saved) {
    $guid = [string]$Saved.interface_guid
    $alias = [string]$Saved.interface_alias
    $adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.InterfaceGuid -eq $guid } |
        Select-Object -First 1
    if (-not $adapter) {
        $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
    }
    return $adapter
}

function Restore-DnsSnapshot([array]$Snapshot) {
    foreach ($saved in $Snapshot) {
        $adapter = Resolve-SavedAdapter $saved
        if (-not $adapter) {
            Write-ServiceLog "Pominięto brakującą kartę: $($saved.interface_alias)."
            continue
        }
        $addresses = @($saved.server_addresses | Where-Object { $_ })
        if ($addresses.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $addresses -ErrorAction Stop
            Write-ServiceLog "Przywrócono DNS na karcie $($adapter.Name): $($addresses -join ', ')."
        }
        else {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction Stop
            Write-ServiceLog "Przywrócono automatyczny DNS na karcie $($adapter.Name)."
        }
    }
    Clear-DnsClientCache
}

function Invoke-Resume {
    if (-not (Test-Path $StatePath)) {
        throw "Brak pliku stanu: $StatePath"
    }
    $state = Get-Content $StatePath -Raw | ConvertFrom-Json
    if ([string]$state.phase -ne 'unjoined_pending_restart') {
        throw "Nieprawidłowy etap wznowienia: $($state.phase)"
    }

    Start-Sleep -Seconds 15
    $computer = Get-ComputerSystem
    if ($computer.PartOfDomain) {
        throw "Komputer nadal należy do domeny $($computer.Domain)."
    }
    if ([string]$computer.Workgroup -ine [string]$state.expected_workgroup) {
        throw "Komputer jest w grupie $($computer.Workgroup), oczekiwano WORKGROUP."
    }

    if ([bool]$state.restore_dns) {
        Restore-DnsSnapshot @($state.dns_snapshot)
    }
    else {
        Write-ServiceLog 'Pozostawiono serwer DNS domeny zgodnie z wyborem administratora.'
    }

    Write-ServiceLog 'SUKCES: komputer odłączony od domeny i zweryfikowany w WORKGROUP. W raporcie nie zapisano poświadczeń.'
    Remove-ResumeArtifacts
}

Assert-Administrator
if ($Resume) {
    Invoke-Resume
    exit
}

$computer = Get-ComputerSystem
if (-not $computer.PartOfDomain -or [string]$computer.Domain -ine $DomainName) {
    throw "Tryb jest przeznaczony wyłącznie dla komputera należącego do domeny $DomainName. Aktualny stan: domena=$($computer.Domain), PartOfDomain=$($computer.PartOfDomain)."
}

Assert-LocalRecoveryAdmin $LocalAdminName
$dnsSnapshot = @(Get-ActiveDnsSnapshot)

$shouldRestoreDns = $false
if ($RestoreDns -and $NoRestoreDns) {
    throw 'Nie można jednocześnie podać -RestoreDns i -NoRestoreDns.'
}
if ($RestoreDns) {
    $shouldRestoreDns = $true
}
elseif (-not $NoRestoreDns) {
    $answer = Read-Host 'Czy po odłączeniu przywrócić zapisane ustawienia DNS? [T/N]'
    $shouldRestoreDns = $answer -match '^(T|TAK|Y|YES)$'
}

Write-Host ''
Write-Warning "Komputer zostanie odłączony od domeny $DomainName i przeniesiony do WORKGROUP."
Write-Host "Konto awaryjne po restarcie: .\$LocalAdminName"
Write-Host "Przywrócenie wcześniejszego DNS: $shouldRestoreDns"
$confirmation = Read-Host 'Aby kontynuować, wpisz dokładnie ODLACZ'
if ($confirmation -cne 'ODLACZ') {
    throw 'Operacja anulowana. Nie wykonano żadnych zmian.'
}

$domainPassword = Read-Host "Podaj hasło administratora domeny $DomainAdmin" -AsSecureString
$domainCredential = [pscredential]::new($DomainAdmin, $domainPassword)

New-Item -ItemType Directory -Path $Root -Force | Out-Null
Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $ScriptPath -Force
Save-State $shouldRestoreDns $dnsSnapshot 'prepared'
Install-ResumeTask

try {
    Write-ServiceLog "Rozpoczęto kontrolowane odłączenie od domeny $DomainName."
    $result = Remove-Computer -UnjoinDomainCredential $domainCredential -WorkgroupName 'WORKGROUP' -Force -PassThru -ErrorAction Stop
    if (-not $result.HasSucceeded) {
        throw "Windows nie potwierdził odłączenia: $($result.Message)"
    }
    Save-State $shouldRestoreDns $dnsSnapshot 'unjoined_pending_restart'
}
catch {
    Remove-ResumeArtifacts
    Write-ServiceLog "BŁĄD: odłączenie nie powiodło się; zadanie wznowienia usunięto. $($_.Exception.Message)"
    throw
}
finally {
    $domainCredential = $null
    $domainPassword = $null
}

Write-Host 'Odłączenie przyjęte. Komputer uruchomi się ponownie za 15 sekund.'
Write-Host "Po restarcie zaloguj się lokalnie jako .\$LocalAdminName."
shutdown.exe /r /t 15 /c "SP2: zakończenie awaryjnego odłączenia od domeny"

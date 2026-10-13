[CmdletBinding()]
param(
    [ValidateSet('','Sala11','Sala32','Sala4','Sala7','Nauczyciel','Administracja')]
    [string]$Profile = '',
    [string]$StationNumber = '',
    [string]$DomainAdmin = 'SP2\Administrator',

    [string]$DomainName = 'sp2.lan',
    [string]$DnsServer = '192.168.0.143',
    [string]$LocalAdminName = 'SP2',
    [securestring]$LocalAdminPassword = $null,
    [string]$AgentInstaller = '',
    [switch]$Resume,
    [switch]$ContinueAfterEntra
)

$ErrorActionPreference = 'Stop'

$DeploymentRoot = Join-Path $env:ProgramData 'SP2-Deployment'
$StatePath = Join-Path $DeploymentRoot 'state.json'
$ResumeScriptPath = Join-Path $DeploymentRoot 'migrate-entra-to-samba.ps1'
$ResumeTaskName = 'SP2DeploymentResume'
$PreJoinTaskName = 'SP2DeploymentPreJoin'
$DeploymentLogPath = Join-Path $DeploymentRoot 'deployment.log'

function Write-DeploymentLog([string]$message) {
    if (-not (Test-Path $DeploymentRoot)) {
        New-Item -ItemType Directory -Path $DeploymentRoot -Force | Out-Null
    }
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $message
    $line | Tee-Object -FilePath $DeploymentLogPath -Append | Write-Host
}

function Save-DeploymentState(
    [string]$profile,
    [string]$computerName,
    [string]$phase,
    [string]$stationNumber = ''
) {
    @{
        profile = $profile
        computer_name = $computerName
        domain_name = $DomainName
        dns_server = $DnsServer
        phase = $phase
        station_number = $stationNumber
    } | ConvertTo-Json | Set-Content -Path $StatePath -Encoding UTF8
}

function Stage-DeploymentFiles([string]$sourceRoot) {
    New-Item -ItemType Directory -Path $DeploymentRoot -Force | Out-Null
    foreach ($name in @(
        'migrate-entra-to-samba.ps1',
        'INSTALUJ.ps1',
        'install-agent.ps1',
        'SP2Agent.exe',
        'deployment.json',
        'sp2-internal-ca.crt'
    )) {
        $source = Join-Path $sourceRoot $name
        if (-not (Test-Path $source)) {
            throw "Brak pliku wymaganego do wznowienia: $source"
        }
        Copy-Item -Path $source -Destination (Join-Path $DeploymentRoot $name) -Force
    }
}

function Install-ResumeTask {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -Resume' -f $ResumeScriptPath
    )
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $ResumeTaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

function Remove-ResumeTask {
    Unregister-ScheduledTask -TaskName $ResumeTaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Install-PreJoinResumeTask([string]$localAdminName) {
    $localUser = '{0}\\{1}' -f $env:COMPUTERNAME, $localAdminName
    $arguments = (
        '/c start "SP2 - kontynuacja migracji" powershell.exe ' +
        '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -ContinueAfterEntra' -f $ResumeScriptPath
    )
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\\System32\\cmd.exe" -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $localUser
    $principal = New-ScheduledTaskPrincipal -UserId $localUser -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $PreJoinTaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

function Remove-PreJoinResumeTask {
    Unregister-ScheduledTask -TaskName $PreJoinTaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Invoke-PostRestartResume {
    Write-DeploymentLog 'Wznowienie wdrozenia po restarcie.'
    if (-not (Test-Path $StatePath)) {
        throw "Brak pliku stanu: $StatePath"
    }
    $state = Get-Content $StatePath -Raw | ConvertFrom-Json
    if ([string]$state.phase -ne 'domain_joined_pending_restart') {
        throw "Nieprawidlowy etap wznowienia: $($state.phase)."
    }
    Start-Sleep -Seconds 20

    Set-DomainDns ([string]$state.dns_server)

    $ready = $false
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        try {
            Resolve-DnsName ([string]$state.domain_name) -ErrorAction Stop | Out-Null
            Resolve-DnsName "_ldap._tcp.dc._msdcs.$($state.domain_name)" -Type SRV -ErrorAction Stop | Out-Null
            $ready = $true
            break
        }
        catch {
            Write-DeploymentLog "Oczekiwanie na siec i DNS: proba $attempt/12."
            Start-Sleep -Seconds 10
        }
    }
    if (-not $ready) {
        throw 'DNS domeny nie jest dostepny po restarcie.'
    }

    $computerSystem = Get-CimInstance Win32_ComputerSystem
    if (-not $computerSystem.PartOfDomain -or $computerSystem.Domain -ine $state.domain_name) {
        throw "Komputer nie nalezy do domeny $($state.domain_name)."
    }
    if ($env:COMPUTERNAME -ine $state.computer_name) {
        throw "Nazwa komputera $env:COMPUTERNAME jest inna niz oczekiwana $($state.computer_name)."
    }
    if (-not (Test-ComputerSecureChannel -ErrorAction Stop)) {
        throw 'Kanal zaufania z domena nie dziala.'
    }

    $installer = Join-Path $DeploymentRoot 'INSTALUJ.ps1'
    Write-DeploymentLog "Instalacja agenta pod nazwa $env:COMPUTERNAME."
    & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $installer -Profile ([string]$state.profile) -NonInteractive
    if ($LASTEXITCODE -ne 0) {
        throw "Instalator agenta zakonczyl sie kodem $LASTEXITCODE."
    }

    $agentTask = Get-ScheduledTask -TaskName 'SP2Agent' -ErrorAction SilentlyContinue
    if (-not $agentTask) {
        throw 'Nie utworzono zadania SP2Agent.'
    }

    Write-DeploymentLog 'SUKCES: DNS, domena, secure channel i agent zostaly zweryfikowane.'
    Remove-ResumeTask
    Remove-Item $StatePath -Force -ErrorAction SilentlyContinue
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Uruchom MIGRUJ.cmd jako administrator.'
    }
}

function Select-DeploymentProfile {
    Write-Host ''
    Write-Host 'Wybierz przeznaczenie komputera:'
    Write-Host '  1. Sala 11'
    Write-Host '  2. Sala 32'
    Write-Host '  3. Sala 4'
    Write-Host '  4. Sala 7'
    Write-Host '  5. Nauczyciel'
    Write-Host '  6. Administracja'
    do {
        $choice = Read-Host 'Wybierz numer 1-6'
        switch ($choice) {
            '1' { return 'Sala11' }
            '2' { return 'Sala32' }
            '3' { return 'Sala4' }
            '4' { return 'Sala7' }
            '5' { return 'Nauczyciel' }
            '6' { return 'Administracja' }
            default { Write-Warning 'Nieprawidlowy wybor. Wpisz liczbe od 1 do 6.' }
        }
    } while ($true)
}

function Get-TargetOu([string]$profile) {
    switch ($profile) {
        'Sala11'        { return 'OU=Sala11,OU=Komputery,DC=sp2,DC=lan' }
        'Sala32'        { return 'OU=Sala32,OU=Komputery,DC=sp2,DC=lan' }
        'Sala4'         { return 'OU=Sala4,OU=Komputery,DC=sp2,DC=lan' }
        'Sala7'         { return 'OU=Sala7,OU=Komputery,DC=sp2,DC=lan' }
        'Nauczyciel'    { return 'OU=Nauczyciele,OU=Komputery,DC=sp2,DC=lan' }
        'Administracja' { return 'OU=Administracja,OU=Komputery,DC=sp2,DC=lan' }
        default          { throw "Nieznany profil: $profile" }
    }
}

function Get-EntraJoinState {
    $raw = (& dsregcmd.exe /status | Out-String)
    return [pscustomobject]@{
        AzureAdJoined = [bool]($raw -match 'AzureAdJoined\s*:\s*YES')
        DomainJoined  = [bool]($raw -match 'DomainJoined\s*:\s*YES')
        Raw           = $raw
    }
}

function Ensure-LocalAdmin([string]$name, [securestring]$password) {
    $existing = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-LocalUser -Name $name -Password $password -PasswordNeverExpires:$true -AccountNeverExpires:$true -Description 'Awaryjne lokalne konto administratora SP2' | Out-Null
        Write-Host "Utworzono lokalne konto .\\$name i ustawiono nowe haslo."
    }
    else {
        # Haslo jest zawsze ustawiane ponownie. Nie trzeba znac poprzedniego hasla.
        Set-LocalUser -Name $name -Password $password -PasswordNeverExpires:$true
        Enable-LocalUser -Name $name
        Write-Host "Konto .\\$name juz istnieje: ustawiono nowe haslo i wlaczono konto."
    }

    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    try {
        Add-LocalGroupMember -Group $adminGroup.Name -Member $name -ErrorAction Stop
        Write-Host "Dodano .\\$name do lokalnej grupy $($adminGroup.Name)."
    }
    catch {
        # Add-LocalGroupMember zglasza MemberExists, gdy konto juz jest administratorem.
        # To jest prawidlowy stan i migracja ma byc kontynuowana.
        if ($_.FullyQualifiedErrorId -like 'MemberExists*') {
            Write-Host "Konto .\\$name juz nalezy do lokalnej grupy $($adminGroup.Name)."
        }
        else {
            throw
        }
    }
}

function Set-DomainDns([string]$server) {
    # Never replace the Internet resolver. Add the Samba resolver as secondary
    # and use NRPT to route only school-domain names to it.
    if ($server -ne '192.168.0.143') { throw 'Nieznany DNS domeny szkolnej.' }
    $direct=@(Resolve-DnsName 'dc.sp2.lan' -Server $server -Type A -DnsOnly -ErrorAction Stop |
        Where-Object Type -eq 'A' | ForEach-Object { [string]$_.IPAddress })
    if ($direct -notcontains $server) { throw 'Szkolny DNS nie potwierdzil kontrolera domeny.' }
    $adapters=@(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq 'Up')
    if ($adapters.Count -lt 1) { throw 'Brak aktywnej karty sieciowej.' }
    foreach ($adapter in $adapters) {
        $old=@((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses |
            Where-Object { $_ })
        if ($old.Count -lt 1) { throw 'Brak podstawowego DNS; nie zmieniono karty.' }
        if ($old -notcontains $server) {
            $desired=@($old[0],$server)
            if ($old.Count -gt 1) { $desired+=@($old | Select-Object -Skip 1) }
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $desired -ErrorAction Stop
        } elseif ($old.Count -gt 1 -and $old[0] -eq $server) {
            $other=@($old | Where-Object { $_ -ne $server })
            if ($other.Count -gt 0) {
                $desired=@($other[0],$server)
                if ($other.Count -gt 1) { $desired+=@($other | Select-Object -Skip 1) }
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $desired -ErrorAction Stop
            }
        }
    }
    $names=@('sp2.lan','.sp2.lan')
    $existing=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | Where-Object {
        @($_.Namespace | Where-Object { $_ -in $names }).Count -gt 0
    })
    $local=@(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {
        @($_.Namespace | Where-Object { $_ -in $names }).Count -gt 0
    })
    if ($existing.Count -gt 0 -or $local.Count -gt 0) {
        foreach ($rule in @($existing)+@($local)) {
            if (@($rule.NameServers) -notcontains $server) {
                throw 'Istniejaca polityka DNS dla sp2.lan wskazuje inny serwer; nie nadpisano jej.'
            }
        }
    } else {
        $normal=@()
        try {
            $normal=@(Resolve-DnsName 'dc.sp2.lan' -Type A -DnsOnly -ErrorAction Stop |
                Where-Object Type -eq 'A' | ForEach-Object { [string]$_.IPAddress })
        } catch { }
        if ($normal -notcontains $server) {
            $rule=Add-DnsClientNrptRule -Namespace $names -NameServers $server -DisplayName 'SP2 - szkolny DNS' -PassThru -ErrorAction Stop
            try {
                Clear-DnsClientCache
                $check=@(Resolve-DnsName 'dc.sp2.lan' -Type A -DnsOnly -ErrorAction Stop |
                    Where-Object Type -eq 'A' | ForEach-Object { [string]$_.IPAddress })
                if ($check -notcontains $server) { throw 'Nie potwierdzono reguly DNS SP2.' }
            } catch {
                Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction SilentlyContinue
                throw
            }
        }
    }
    Clear-DnsClientCache
}

function Install-BundledCa([string]$root) {
    $caPath = Join-Path $root 'sp2-internal-ca.crt'
    if (-not (Test-Path $caPath)) {
        throw "Brak certyfikatu CA wymaganego do HTTPS: $caPath"
    }

    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($caPath)
    $store = [Security.Cryptography.X509Certificates.X509Store]::new(
        [Security.Cryptography.X509Certificates.StoreName]::Root,
        [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        $existing = @($store.Certificates | Where-Object Thumbprint -eq $certificate.Thumbprint)
        if ($existing.Count -eq 0) {
            $store.Add($certificate)
            Write-Host "Dodano szkolny certyfikat CA do zaufanych głównych urzędów: $($certificate.Thumbprint)"
        }
        else {
            Write-Host 'Szkolny certyfikat CA jest już zaufany.'
        }
    }
    finally {
        $store.Close()
        $certificate.Dispose()
    }
}

function Get-ComputerNamePreview(
    [string]$profile,
    [string]$stationNumber,
    [string]$root
) {
    $deploymentPath = Join-Path $root 'deployment.json'
    if (-not (Test-Path $deploymentPath)) {
        throw "Brak pliku deployment.json: $deploymentPath"
    }
    $deployment = Get-Content $deploymentPath -Raw | ConvertFrom-Json
    $serverUrl = ([string]$deployment.server_url).TrimEnd('/')
    $bootstrapCredential = [string]$deployment.enrollment_code
    if (-not $bootstrapCredential) {
        # Zgodność ze starszymi paczkami podczas okresu przejściowego.
        $bootstrapCredential = [string]$deployment.enrollment_token
    }
    if (-not $serverUrl -or -not $bootstrapCredential) {
        throw 'deployment.json nie zawiera server_url lub jednorazowego enrollment_code.'
    }

    $body = @{
        profile = $profile
        station_number = $stationNumber
    } | ConvertTo-Json
    $response = Invoke-RestMethod `
        -Method Post `
        -Uri "$serverUrl/api/v1/agent/domain/name-preview" `
        -Headers @{ Authorization = "Bearer $bootstrapCredential" } `
        -ContentType 'application/json; charset=utf-8' `
        -Body $body `
        -TimeoutSec 30

    if (-not $response.available) {
        throw "Nazwa $($response.computer_name) istnieje już w Active Directory."
    }
    if ([string]$response.target_ou -ne (Get-TargetOu $profile)) {
        throw 'Serwer zwrócił OU niezgodną z wybranym profilem.'
    }
    return $response
}

Assert-Administrator
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Install-BundledCa $root
if ($Resume) {
    Invoke-PostRestartResume
    exit
}
$pendingState = $null
if ($ContinueAfterEntra) {
    if (-not (Test-Path $StatePath)) {
        throw "Brak pliku stanu po odłączeniu Entra: $StatePath"
    }
    $pendingState = Get-Content $StatePath -Raw | ConvertFrom-Json
    if ([string]$pendingState.phase -ne 'entra_detached_pending_restart') {
        throw "Nieprawidlowy etap kontynuacji: $($pendingState.phase)."
    }
    $Profile = [string]$pendingState.profile
    $StationNumber = [string]$pendingState.station_number
    Remove-PreJoinResumeTask
    Write-DeploymentLog 'Kontynuacja migracji po restarcie wymaganym przez odłączenie Entra ID.'
}
elseif (-not $Profile) {
    $Profile = Select-DeploymentProfile
}
$targetOu = Get-TargetOu $Profile
if (-not $AgentInstaller) {
    $AgentInstaller = Join-Path $root 'INSTALUJ.ps1'
}

Write-Host '=== SP2 MIGRACJA ENTRA -> SAMBA AD ==='
Write-Host "Komputer: $env:COMPUTERNAME"
Write-Host "Profil:   $Profile"
Write-Host "OU:       $targetOu"
Write-Host 'Nazwa zostanie pobrana z SP2 ADMIN po sprawdzeniu DNS.'

Write-Host '[0/7] Kontrola polaczenia z DNS Active Directory (bez zmian na komputerze)...'
try {
    $preflightLdapSrv = Resolve-DnsName "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -Server $DnsServer -ErrorAction Stop
    $preflightKerbSrv = Resolve-DnsName "_kerberos._tcp.dc._msdcs.$DomainName" -Type SRV -Server $DnsServer -ErrorAction Stop
}
catch {
    throw "Kontrola wstepna nie powiodla sie. DNS $DnsServer nie zwraca rekordow uslug domeny $DomainName. Nie zmieniono konta lokalnego, DNS ani czlonkostwa komputera. Sprawdz trase miedzy budynkami (Site Magic/VPN), reguly zapory i port 53 UDP/TCP. Szczegoly: $($_.Exception.Message)"
}
Write-Host "Preflight DNS AD: OK / $DnsServer"
Write-Host "Preflight LDAP SRV: OK / $($preflightLdapSrv.NameTarget | Select-Object -First 1)"
Write-Host "Preflight Kerberos SRV: OK / $($preflightKerbSrv.NameTarget | Select-Object -First 1)"

$localPassword = $LocalAdminPassword
if ($null -eq $localPassword) {
    $localCredential = Get-Credential -UserName ($env:COMPUTERNAME + '\' + $LocalAdminName) -Message 'Podaj uzgodnione haslo lokalnego administratora. Nie jest zapisywane.'
    if ($null -eq $localCredential) { throw 'Brak hasla lokalnego administratora.' }
    $localPassword = $localCredential.Password
}
Write-Host '[1/7] Tworzenie/naprawa awaryjnego lokalnego administratora...'
try { Ensure-LocalAdmin $LocalAdminName $localPassword }
finally { if ($null -ne $localPassword) { $localPassword.Dispose() } }

Write-Host '[2/7] Ustawianie DNS domeny...'
Set-DomainDns $DnsServer

Write-Host '[3/7] Weryfikacja DNS systemowego po konfiguracji...'
$ldapSrv = Resolve-DnsName "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -ErrorAction Stop
$kerbSrv = Resolve-DnsName "_kerberos._tcp.dc._msdcs.$DomainName" -Type SRV -ErrorAction Stop
Write-Host "DNS systemowy AD: OK / $DnsServer"
Write-Host "LDAP SRV: OK / $($ldapSrv.NameTarget | Select-Object -First 1)"
Write-Host "Kerberos SRV: OK / $($kerbSrv.NameTarget | Select-Object -First 1)"

$domainPassword = Read-Host "Podaj haslo administratora domeny $DomainAdmin" -AsSecureString
$domainCredential = [pscredential]::new($DomainAdmin, $domainPassword)
if ($pendingState) {
    Write-Host '[3a/7] Przywracanie nazwy wybranej przed odłączeniem Entra ID...'
    $newComputerName = [string]$pendingState.computer_name
}
else {
    Write-Host '[3a/7] Pobieranie wolnych nazw z SP2 ADMIN...'
    $nameResponse = Get-ComputerNamePreview $Profile $StationNumber $root

    if ($Profile -like 'Sala*' -and -not $StationNumber) {
        $freeNumbers = @($nameResponse.available_numbers)
        if ($freeNumbers.Count -eq 0) {
            throw "Brak wolnych numerow komputerow w $Profile."
        }

        Write-Host "Wolne numery w ${Profile}: $($freeNumbers -join ', ')"
        $suggestedNumber = [string]$nameResponse.station_number
        $selectedNumber = Read-Host "Wybierz numer stanowiska [Enter = $suggestedNumber]"
        if (-not $selectedNumber) {
            $selectedNumber = $suggestedNumber
        }
        if ([int]$selectedNumber -notin $freeNumbers) {
            throw "Numer $selectedNumber nie jest wolny w $Profile."
        }

        if ($selectedNumber -ne $suggestedNumber) {
            $nameResponse = Get-ComputerNamePreview $Profile $selectedNumber $root
        }
        $StationNumber = $selectedNumber
    }

    $newComputerName = [string]$nameResponse.computer_name
}
Write-Host "Wybrana nazwa komputera: $newComputerName"

Write-Host '[4/7] Sprawdzanie Microsoft Entra ID...'
$state = Get-EntraJoinState
if ($state.AzureAdJoined) {
    Write-Host 'Urządzenie jest Entra-joined. Odłączanie...'
    & dsregcmd.exe /leave
    if ($LASTEXITCODE -ne 0) {
        throw "dsregcmd /leave zakończył się kodem $LASTEXITCODE"
    }
    Start-Sleep -Seconds 5
    $stateAfter = Get-EntraJoinState
    if ($stateAfter.AzureAdJoined) {
        throw 'Urządzenie nadal jest Entra-joined po dsregcmd /leave. Przerwano przed dołączeniem do domeny.'
    }
    Write-Host 'Entra: odłączono.'

    Write-Host '[5/7] Przygotowanie kontynuacji po restarcie wymaganym przez Entra ID...'
    Stage-DeploymentFiles $root
    Save-DeploymentState $Profile $newComputerName 'entra_detached_pending_restart' $StationNumber
    Install-PreJoinResumeTask $LocalAdminName
    Write-DeploymentLog 'Entra ID odłączona. Zaplanowano kontynuację po zalogowaniu na lokalne konto SP2.'
    Write-Host "Po restarcie zaloguj się na lokalne konto .\\$LocalAdminName."
    Write-Host 'Migracja otworzy się automatycznie i ponownie poprosi o hasło domenowe.'
    Write-Host 'Komputer zostanie uruchomiony ponownie za 15 sekund.'
    Start-Sleep -Seconds 15
    Restart-Computer -Force
    exit
}
else {
    Write-Host 'Entra: urządzenie nie jest Entra-joined.'
}

Write-Host '[5/7] Przygotowanie automatycznego wznowienia po restarcie domenowym...'
Stage-DeploymentFiles $root
Save-DeploymentState $Profile $newComputerName 'domain_join_pending' $StationNumber

Write-Host '[6/7] Dołączanie do Samba AD...'
$computerSystem = Get-CimInstance Win32_ComputerSystem
if ($computerSystem.PartOfDomain -and $computerSystem.Domain -ieq $DomainName) {
    Write-Host "Komputer już należy do $DomainName."
    if ($env:COMPUTERNAME -ine $newComputerName) {
        Rename-Computer -NewName $newComputerName -DomainCredential $domainCredential -Force
    }
}
else {
    Add-Computer -DomainName $DomainName -Credential $domainCredential -OUPath $targetOu -NewName $newComputerName -Force
}

Write-Host '[7/7] Rejestracja automatycznego wznowienia...'
Save-DeploymentState $Profile $newComputerName 'domain_joined_pending_restart' $StationNumber
Install-ResumeTask
Write-Host "Lokalne konto awaryjne: .\$LocalAdminName"
Write-Host "Po restarcie logowanie domenowe: SP2\<login> lub <login>@$DomainName"
Write-Host 'Po restarcie program sam zweryfikuje DNS i domene oraz zainstaluje agenta pod nowa nazwa.'
Write-Host 'Komputer zostanie uruchomiony ponownie za 15 sekund.'
Start-Sleep -Seconds 15
Restart-Computer -Force

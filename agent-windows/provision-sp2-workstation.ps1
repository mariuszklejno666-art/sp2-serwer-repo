[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Sala11','Sala32','Sala4','Sala7','Nauczyciel','Administracja')]
    [string]$Profile,
    [string]$StationNumber = '',
    [string]$DomainName = 'sp2.lan',
    [string]$DomainNetbios = 'SP2',
    [string]$DomainJoinUser = 'SP2\Administrator',
    [string]$DnsServer = '192.168.0.143',
    [string]$LocalAdminName = 'SP2',
    [string]$LocalAdminPassword = 'Klejno1986@',
    [string]$AgentInstaller = ''
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Uruchom skrypt jako administrator.'
    }
}

function Get-RoomCode([string]$profile) {
    switch ($profile) {
        'Sala11' { '11' }
        'Sala32' { '32' }
        'Sala4'  { '4' }
        'Sala7'  { '7' }
        default  { '' }
    }
}

function Get-TargetOu([string]$profile) {
    switch ($profile) {
        'Sala11'        { 'OU=Sala11,OU=Komputery,DC=sp2,DC=lan' }
        'Sala32'        { 'OU=Sala32,OU=Komputery,DC=sp2,DC=lan' }
        'Sala4'         { 'OU=Sala4,OU=Komputery,DC=sp2,DC=lan' }
        'Sala7'         { 'OU=Sala7,OU=Komputery,DC=sp2,DC=lan' }
        'Nauczyciel'    { 'OU=Nauczyciele,OU=Komputery,DC=sp2,DC=lan' }
        'Administracja' { 'OU=Administracja,OU=Komputery,DC=sp2,DC=lan' }
        default          { throw "Nieznany profil: $profile" }
    }
}

function Ensure-LocalAdmin([string]$name, [securestring]$password) {
    $existing = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if ($existing) {
        Set-LocalUser -Name $name -Password $password -PasswordNeverExpires:$true
        Enable-LocalUser -Name $name
    } else {
        New-LocalUser -Name $name -Password $password -PasswordNeverExpires:$true -AccountNeverExpires:$true -Description 'Lokalny administrator SP2' | Out-Null
    }

    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    $localIdentity = "$env:COMPUTERNAME\$name"
    $members = Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction SilentlyContinue
    if (-not ($members | Where-Object { $_.Name -ieq $localIdentity })) {
        Add-LocalGroupMember -Group $adminGroup.Name -Member $localIdentity
    }

    $verified = Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction Stop |
        Where-Object { $_.Name -ieq $localIdentity }
    if (-not $verified) {
        throw "Lokalne konto $localIdentity nie jest członkiem grupy Administratorzy. Przerwano provisioning."
    }
}

function Set-DomainDns([string]$server) {
    $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    if (-not $adapters) { throw 'Brak aktywnej karty sieciowej.' }
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $server
    }
    Clear-DnsClientCache
}

function Get-ComputerNamePreview([string]$profile, [string]$stationNumber, [string]$root) {
    $deploymentPath = Join-Path $root 'deployment.json'
    if (-not (Test-Path $deploymentPath)) {
        throw "Brak pliku deployment.json: $deploymentPath"
    }
    $deployment = Get-Content $deploymentPath -Raw | ConvertFrom-Json
    $body = @{
        profile = $profile
        station_number = $stationNumber
    } | ConvertTo-Json
    $response = Invoke-RestMethod `
        -Method Post `
        -Uri (([string]$deployment.server_url).TrimEnd('/') + '/api/v1/agent/domain/name-preview') `
        -Headers @{ Authorization = "Bearer $([string]$deployment.enrollment_token)" } `
        -ContentType 'application/json; charset=utf-8' `
        -Body $body `
        -TimeoutSec 30
    if (-not $response.available) {
        throw "Nazwa $($response.computer_name) istnieje już w Active Directory."
    }
    if ([string]$response.target_ou -ne (Get-TargetOu $profile)) {
        throw 'Serwer zwrócił OU niezgodną z wybranym profilem.'
    }
    return [string]$response.computer_name
}

function Leave-EntraIfNeeded {
    $raw = (& dsregcmd.exe /status | Out-String)
    if ($raw -match 'AzureAdJoined\s*:\s*YES') {
        Write-Host 'Microsoft Entra: wykryto - odłączanie...'
        & dsregcmd.exe /leave
        if ($LASTEXITCODE -ne 0) { throw "dsregcmd /leave: kod $LASTEXITCODE" }
        Start-Sleep -Seconds 4
    } else {
        Write-Host 'Microsoft Entra: brak aktywnego join.'
    }
}

function Configure-SharedClassroomLogon {
    # Komputer w sali jest stanowiskiem współdzielonym: nie przypisujemy go na stałe
    # do jednego ucznia. Windows ma pamiętać ostatniego użytkownika i jednocześnie
    # udostępniać kafelek "Inny użytkownik" dla nauczyciela lub innego ucznia.
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $userList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'

    New-Item -Path $policy -Force | Out-Null
    New-Item -Path $userList -Force | Out-Null

    # Nie wymuszaj jednego konta domenowego na stanowisku.
    Remove-ItemProperty -Path $winlogon -Name DefaultUserName -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $winlogon -Name AutoAdminLogon -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $policy -Name DontDisplayLastUserName -Value 0 -Type DWord

    # Konta techniczne nie powinny zajmować kafelków logowania, ale nadal można
    # użyć ich przez "Inny użytkownik", np. .\SP2.
    Set-ItemProperty -Path $userList -Name $LocalAdminName -Value 0 -Type DWord
    if (Get-LocalUser -Name 'user' -ErrorAction SilentlyContinue) {
        Set-ItemProperty -Path $userList -Name 'user' -Value 0 -Type DWord
    }
}

Assert-Administrator
$targetOu = Get-TargetOu $Profile
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $AgentInstaller) { $AgentInstaller = Join-Path $root 'INSTALUJ.ps1' }

$newComputerName = ''
if ($Profile -like 'Sala*' -and -not $StationNumber) {
    $StationNumber = Read-Host "Podaj numer stanowiska w $Profile (1-99)"
}

Write-Host '=== SP2 AUTOMATYCZNE PRZYGOTOWANIE STANOWISKA ==='
Write-Host "Profil: $Profile"
Write-Host "OU: $targetOu"
Write-Host 'Nazwa zostanie pobrana z SP2 ADMIN po sprawdzeniu DNS.'

$localSecure = ConvertTo-SecureString $LocalAdminPassword -AsPlainText -Force

Write-Host '[1/8] Lokalne konto administratora...'
Ensure-LocalAdmin $LocalAdminName $localSecure

Write-Host '[2/8] DNS domeny...'
Set-DomainDns $DnsServer
Resolve-DnsName $DomainName -ErrorAction Stop | Out-Null
Resolve-DnsName "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -ErrorAction Stop | Out-Null
Resolve-DnsName "_kerberos._tcp.dc._msdcs.$DomainName" -Type SRV -ErrorAction Stop | Out-Null
$newComputerName = Get-ComputerNamePreview $Profile $StationNumber $root
Write-Host "Nazwa komputera: $newComputerName"

Write-Host '[3/8] Odłączanie Microsoft Entra (jeśli potrzebne)...'
Leave-EntraIfNeeded

Write-Host '[4/8] Instalacja/naprawa SP2 Agent...'
if (Test-Path $AgentInstaller) {
    & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $AgentInstaller
    if ($LASTEXITCODE -ne 0) { throw "Instalator agenta: kod $LASTEXITCODE" }
}

Write-Host '[5/8] Dane dołączenia do domeny...'
$domainPassword = Read-Host "Haslo konta $DomainJoinUser" -AsSecureString
$domainCredential = [pscredential]::new($DomainJoinUser, $domainPassword)

Write-Host '[6/8] Dołączanie do domeny i właściwego OU...'
$computerSystem = Get-CimInstance Win32_ComputerSystem
if (-not ($computerSystem.PartOfDomain -and $computerSystem.Domain -ieq $DomainName)) {
    $params = @{
        DomainName = $DomainName
        Credential = $domainCredential
        OUPath = $targetOu
        Force = $true
        PassThru = $true
    }
    if ($newComputerName) { $params.NewName = $newComputerName }
    Add-Computer @params | Out-Host
} elseif ($newComputerName -and $env:COMPUTERNAME -ne $newComputerName) {
    Rename-Computer -NewName $newComputerName -DomainCredential $domainCredential -Force
}

Write-Host '[7/8] Konfiguracja współdzielonego ekranu logowania...'
Configure-SharedClassroomLogon
Write-Host 'Po restarcie dostępny będzie ostatni użytkownik oraz "Inny użytkownik".'
Write-Host "Administrator awaryjny pozostaje dostępny jako .\$LocalAdminName przez 'Inny użytkownik'."

Write-Host '[8/8] Koniec - restart za 10 sekund...'
Start-Sleep -Seconds 10
Restart-Computer -Force

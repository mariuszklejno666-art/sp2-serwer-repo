[CmdletBinding()]
param(
    [ValidateSet('Diagnose','Repair','Auto')]
    [string]$Mode = 'Diagnose',

    [string]$DomainName = 'sp2.lan',
    [string]$DomainNetBIOS = 'SP2',
    [string]$DnsServer = '192.168.0.143',
    [string]$DomainController = 'szkolaak.sp2.lan',
    [string]$RecoveryLocalAccount = 'SP2',
    [PSCredential]$DomainCredential,
    [switch]$NoDnsRepair,
    [switch]$NoTimeRepair,
    [switch]$NoNetlogonRepair,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$DataRoot = 'C:\ProgramData\SP2-Agent\DomainHealer'
$LogPath = Join-Path $DataRoot 'domain-healer.log'
$ReportPath = Join-Path $DataRoot 'last-report.json'
New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')] [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
    if (-not $Quiet) {
        switch ($Level) {
            'ERROR' { Write-Host $line -ForegroundColor Red }
            'WARN'  { Write-Host $line -ForegroundColor Yellow }
            default { Write-Host $line }
        }
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PhysicalAdapters {
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Up' }
}

function Get-DnsState {
    $items = @()
    foreach ($adapter in (Get-PhysicalAdapters)) {
        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $items += [pscustomobject]@{
            Name = $adapter.Name
            InterfaceIndex = $adapter.ifIndex
            Servers = @($dns.ServerAddresses)
            HasExpectedDns = (@($dns.ServerAddresses) -contains $DnsServer)
        }
    }
    return @($items)
}

function Repair-Dns {
    if ($NoDnsRepair) { return }
    foreach ($adapter in (Get-PhysicalAdapters)) {
        try {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
            $current = @($dns.ServerAddresses | Where-Object { $_ })
            # SP2 policy: keep the existing resolver first for Internet access and
            # add the Samba AD DNS as the SECOND resolver. Never replace the first
            # DNS with 192.168.0.143 during an automatic repair.
            $withoutDomainDns = @($current | Where-Object { $_ -ne $DnsServer })
            if ($withoutDomainDns.Count -gt 0) {
                $desired = @($withoutDomainDns[0], $DnsServer)
                if ($withoutDomainDns.Count -gt 1) { $desired += @($withoutDomainDns | Select-Object -Skip 1) }
            } else {
                # If this adapter only knows the AD DNS, leave it unchanged:
                # inventing a public/Internet DNS would be unsafe.
                $desired = @($current)
            }
            if ($desired.Count -gt 0 -and (($current -join ',') -ne ($desired -join ','))) {
                Write-Log "Ustawiam DNS domeny $DnsServer jako drugi resolver na interfejsie '$($adapter.Name)'." 'WARN'
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $desired -ErrorAction Stop
            } elseif (-not ($current -contains $DnsServer)) {
                Write-Log "Nie dodano DNS domeny na '$($adapter.Name)': brak istniejacego pierwszego resolvera; nie zmieniam konfiguracji automatycznie." 'WARN'
            }
        } catch {
            Write-Log "Nie udało się ustawić DNS na '$($adapter.Name)': $($_.Exception.Message)" 'ERROR'
        }
    }
    try { Clear-DnsClientCache -ErrorAction Stop } catch { Write-Log "Czyszczenie cache DNS nie powiodło się: $($_.Exception.Message)" 'WARN' }
}

function Test-SrvRecord {
    try {
        $r = Resolve-DnsName "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -ErrorAction Stop
        return [pscustomobject]@{ Ok = $true; Target = ($r | Where-Object NameTarget | Select-Object -First 1 -ExpandProperty NameTarget) }
    } catch {
        return [pscustomobject]@{ Ok = $false; Target = $null; Error = $_.Exception.Message }
    }
}

function Test-DcDiscovery {
    $out = & nltest.exe "/dsgetdc:$DomainName" 2>&1
    return [pscustomobject]@{
        Ok = ($LASTEXITCODE -eq 0)
        ExitCode = $LASTEXITCODE
        Output = ($out -join "`n")
    }
}

function Get-DomainMembership {
    $cs = Get-CimInstance Win32_ComputerSystem
    return [pscustomobject]@{
        Name = $cs.Name
        Domain = $cs.Domain
        PartOfDomain = [bool]$cs.PartOfDomain
    }
}

function Test-RecoveryAccount {
    try {
        $user = Get-LocalUser -Name $RecoveryLocalAccount -ErrorAction Stop
        $admins = Get-LocalGroupMember -Group 'Administratorzy' -ErrorAction SilentlyContinue
        if (-not $admins) { $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue }
        $isAdmin = $false
        if ($admins) {
            $isAdmin = [bool]($admins | Where-Object { $_.Name -match "\\$([regex]::Escape($RecoveryLocalAccount))$" })
        }
        return [pscustomobject]@{ Exists = $true; Enabled = [bool]$user.Enabled; IsAdmin = $isAdmin }
    } catch {
        return [pscustomobject]@{ Exists = $false; Enabled = $false; IsAdmin = $false }
    }
}

function Test-SecureChannelState {
    try {
        $ok = Test-ComputerSecureChannel -ErrorAction Stop
        return [pscustomobject]@{ Ok = [bool]$ok; Error = $null }
    } catch {
        return [pscustomobject]@{ Ok = $false; Error = $_.Exception.Message }
    }
}

function Repair-Netlogon {
    if ($NoNetlogonRepair) { return }
    try {
        $svc = Get-Service Netlogon -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            Set-Service Netlogon -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service Netlogon -ErrorAction Stop
            Write-Log 'Uruchomiono usługę Netlogon.'
        } else {
            Restart-Service Netlogon -Force -ErrorAction Stop
            Write-Log 'Zrestartowano usługę Netlogon.'
        }
    } catch {
        Write-Log "Naprawa Netlogon nie powiodła się: $($_.Exception.Message)" 'WARN'
    }
}

function Repair-Time {
    if ($NoTimeRepair) { return }
    try {
        & w32tm.exe /resync /rediscover | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Log 'Synchronizacja czasu zakończona poprawnie.' }
        else { Write-Log "w32tm /resync zwrócił kod $LASTEXITCODE." 'WARN' }
    } catch {
        Write-Log "Synchronizacja czasu nie powiodła się: $($_.Exception.Message)" 'WARN'
    }
}

function Repair-SecureChannelWithCredential {
    param([PSCredential]$Credential)
    if (-not $Credential) { return $false }

    Write-Log 'Próba naprawy secure channel przez Test-ComputerSecureChannel.' 'WARN'
    try {
        $ok = Test-ComputerSecureChannel -Repair -Credential $Credential -ErrorAction Stop
        if ($ok) { return $true }
    } catch {
        Write-Log "Test-ComputerSecureChannel -Repair: $($_.Exception.Message)" 'WARN'
    }

    Write-Log 'Próba resetu hasła konta maszyny.' 'WARN'
    try {
        Reset-ComputerMachinePassword -Server $DomainController -Credential $Credential -ErrorAction Stop
        Start-Sleep -Seconds 2
        return [bool](Test-ComputerSecureChannel -ErrorAction SilentlyContinue)
    } catch {
        Write-Log "Reset-ComputerMachinePassword: $($_.Exception.Message)" 'WARN'
        return $false
    }
}

if (-not (Test-IsAdministrator)) {
    Write-Log 'Skrypt musi działać jako administrator.' 'ERROR'
    exit 10
}

$membership = Get-DomainMembership
$recovery = Test-RecoveryAccount
$dnsBefore = Get-DnsState
$srvBefore = Test-SrvRecord
$dcBefore = Test-DcDiscovery
$secureBefore = if ($membership.PartOfDomain) { Test-SecureChannelState } else { [pscustomobject]@{ Ok = $false; Error = 'Komputer nie należy do domeny.' } }

Write-Log "Start diagnostyki host=$($membership.Name), domain=$($membership.Domain), mode=$Mode."

if ($Mode -in @('Repair','Auto')) {
    Repair-Dns
    Repair-Netlogon
    Repair-Time
    Start-Sleep -Seconds 2
}

$secureAfterSafe = if ($membership.PartOfDomain) { Test-SecureChannelState } else { [pscustomobject]@{ Ok = $false; Error = 'Komputer nie należy do domeny.' } }
$credentialRepairAttempted = $false
$credentialRepairSucceeded = $false

if ($Mode -eq 'Repair' -and $membership.PartOfDomain -and -not $secureAfterSafe.Ok) {
    if (-not $DomainCredential) {
        try { $DomainCredential = Get-Credential -UserName "$DomainNetBIOS\Administrator" -Message 'Podaj konto uprawnione do naprawy relacji zaufania' } catch { }
    }
    if ($DomainCredential) {
        $credentialRepairAttempted = $true
        $credentialRepairSucceeded = Repair-SecureChannelWithCredential -Credential $DomainCredential
    }
}

$dnsAfter = Get-DnsState
$srvAfter = Test-SrvRecord
$dcAfter = Test-DcDiscovery
$secureAfter = if ($membership.PartOfDomain) { Test-SecureChannelState } else { [pscustomobject]@{ Ok = $false; Error = 'Komputer nie należy do domeny.' } }

$status = 'OK'
$exitCode = 0
if (-not $membership.PartOfDomain) {
    $status = 'NOT_IN_DOMAIN'; $exitCode = 30
} elseif (-not $srvAfter.Ok -or -not $dcAfter.Ok) {
    $status = 'DOMAIN_CONNECTIVITY_ERROR'; $exitCode = 20
} elseif (-not $secureAfter.Ok) {
    if ($recovery.Exists -and $recovery.Enabled -and $recovery.IsAdmin) {
        $status = 'REJOIN_REQUIRED'; $exitCode = 40
    } else {
        $status = 'REJOIN_BLOCKED_NO_RECOVERY_ADMIN'; $exitCode = 41
    }
}

$report = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    computer_name = $membership.Name
    domain = $membership.Domain
    expected_domain = $DomainName
    part_of_domain = $membership.PartOfDomain
    mode = $Mode
    status = $status
    dns_server_expected = $DnsServer
    dns_before = @($dnsBefore)
    dns_after = @($dnsAfter)
    srv_before = $srvBefore
    srv_after = $srvAfter
    dc_before = $dcBefore
    dc_after = $dcAfter
    secure_channel_before = $secureBefore
    secure_channel_after_safe_repairs = $secureAfterSafe
    credential_repair_attempted = $credentialRepairAttempted
    credential_repair_succeeded = $credentialRepairSucceeded
    secure_channel_after = $secureAfter
    recovery_account = [ordered]@{
        name = $RecoveryLocalAccount
        exists = $recovery.Exists
        enabled = $recovery.Enabled
        is_local_admin = $recovery.IsAdmin
    }
    rejoin_is_automatic = $false
    note = if ($status -eq 'REJOIN_REQUIRED') {
        'Kanał zaufania nadal uszkodzony. Automatyczny rejoin jest celowo zablokowany bez bezpiecznego mechanizmu poświadczeń z serwera SP2 ADMIN.'
    } else { '' }
}

$report | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8
Write-Log "Koniec diagnostyki. Status=$status, secure_channel=$($secureAfter.Ok), report=$ReportPath."

if (-not $Quiet) {
    Write-Host ''
    Write-Host "SP2 Domain Healer: $status"
    Write-Host "Raport: $ReportPath"
}

exit $exitCode

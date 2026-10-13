# SP2 safe workgroup migration: cloud detach, local recovery account, time and reboot.
# Loaded only by SP2-Serwis-Domeny.ps1. Never store user passwords or secrets.
$script:EntraTransitionPath=Join-Path $script:Root 'entra-transition.json'

function Get-CloudJoinDeviceState {
    # Read-only NetGetAadJoinInformation. Never parse dsregcmd console text:
    # text can differ by Windows language and native output encoding.
    if (-not ('SP2NativeCloudJoin' -as [type])) {
        $dll=Join-Path $PSScriptRoot 'SP2MachineAccountRecovery.dll'
        if (Test-Path -LiteralPath $dll) {
            Add-Type -Path $dll -ErrorAction Stop
        } else {
            $source=Join-Path $PSScriptRoot 'MachineAccountRecovery.cs'
            if (-not (Test-Path -LiteralPath $source)) {
                throw 'Brak biblioteki odczytu rejestracji Microsoft Entra.'
            }
            Add-Type -Path $source -ErrorAction Stop
        }
    }
    return [int]([SP2NativeCloudJoin]::GetDeviceJoinState())
}

function Get-CloudJoinFlag {
    $state=Get-CloudJoinDeviceState
    if ($state -eq 1) { return $true }
    if ($state -eq 0) { return $false }
    throw 'Natywne API Windows nie potwierdzilo stanu Microsoft Entra.'
}

function Invoke-SchoolTimeCommand([string[]]$Arguments) {
    $exe=Join-Path $env:WINDIR 'System32\w32tm.exe'
    $result=@(& $exe @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ('Windows Time: operacja nie powiodla sie; kod=' + [string]$LASTEXITCODE)
    }
    return $result
}

function Assert-SchoolTime([bool]$ConfigureWorkgroup) {
    # Check that the verified school server provides NTP before any change.
    $server=[string]$script:DomainDnsServer
    if ($server -ne '192.168.0.143') { throw 'Nieznane zrodlo czasu SP2.' }
    $before=@(Invoke-SchoolTimeCommand -Arguments @('/stripchart',('/computer:'+$server),'/dataonly','/samples:2'))
    if (-not (@($before | Where-Object { [string]$_ -match '[-+][0-9]+[.,][0-9]+s' }).Count -ge 1)) {
        throw 'Brak potwierdzonej odpowiedzi NTP z 192.168.0.143.'
    }
    if ($ConfigureWorkgroup) {
        # A workgroup client can use Samba NTP; a domain-joined client must
        # not have its domain/group policy source overwritten.
        Set-Service -Name W32Time -StartupType Automatic -ErrorAction Stop
        Start-Service -Name W32Time -ErrorAction SilentlyContinue
        [void](Invoke-SchoolTimeCommand -Arguments @('/config',('/manualpeerlist:'+$server+',0x8'),'/syncfromflags:manual','/update'))
        [void](Invoke-SchoolTimeCommand -Arguments @('/resync','/rediscover'))
        $source=@(Invoke-SchoolTimeCommand -Arguments @('/query','/source'))
        if (-not (([string]::Join(' ',[string[]]$source)) -match [regex]::Escape($server))) {
            throw 'Windows Time nie potwierdzil szkolnego zrodla NTP.'
        }
    }
    $samples=@(Invoke-SchoolTimeCommand -Arguments @('/stripchart',('/computer:'+$server),'/dataonly','/samples:2'))
    $offsets=@()
    foreach ($sample in $samples) {
        if ([string]$sample -match '([-+][0-9]+[.,][0-9]+)s') {
            $invariant=([string]$Matches[1]).Replace(',','.')
            $offsets+= [double]::Parse($invariant,[Globalization.CultureInfo]::InvariantCulture)
        }
    }
    if ($offsets.Count -lt 1) { throw 'Brak odczytu roznicy czasu Windows i serwera SP2.' }
    foreach ($offset in $offsets) {
        if ([Math]::Abs($offset) -gt 120) {
            throw 'Roznica czasu Windows/serwer przekracza 120 sekund. Join zablokowany.'
        }
    }
    Write-UiLog 'Czas SP2: sprawdzono NTP 192.168.0.143 i roznice zegarow (ponizej 120s).'
}

function Test-LocalSP2Login([Security.SecureString]$Password) {
    if (-not ('SP2LocalLogonCheck' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security;
public static class SP2LocalLogonCheck {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LogonUser(string user, string domain, IntPtr password,
                                         int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    public static bool Check(string user, string domain, SecureString password) {
        IntPtr secret = IntPtr.Zero;
        IntPtr token = IntPtr.Zero;
        try {
            secret = Marshal.SecureStringToGlobalAllocUnicode(password);
            return LogonUser(user, domain, secret, 2, 0, out token);
        } finally {
            if (token != IntPtr.Zero) CloseHandle(token);
            if (secret != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(secret);
        }
    }
}
'@ -ErrorAction Stop
    }
    return [SP2LocalLogonCheck]::Check('SP2',$env:COMPUTERNAME,$Password)
}

function Assert-SchoolAdReachability {
    # Read-only prerequisites before detaching Entra or performing a first
    # domain join. HTTPS alone is not enough for Samba AD/Kerberos logon.
    $server=[string]$script:DomainDnsServer
    if ($server -ne '192.168.0.143') { throw 'Nieznany kontroler domeny SP2.' }
    $addresses=@(Resolve-DnsName 'dc.sp2.lan' -Server $server -Type A -DnsOnly -NoHostsFile -ErrorAction Stop |
        Where-Object { $_.Type -eq 'A' -and $_.Section -eq 'Answer' } |
        ForEach-Object { [string]$_.IPAddress })
    if ($addresses -notcontains $server) {
        throw 'Szkolny DNS nie potwierdzil adresu kontrolera domeny.'
    }
    foreach ($srv in @('_ldap._tcp.dc._msdcs.sp2.lan','_kerberos._tcp.dc._msdcs.sp2.lan')) {
        $records=@(Resolve-DnsName -Name $srv -Server $server -Type SRV -DnsOnly -NoHostsFile -ErrorAction Stop |
            Where-Object { $_.Type -eq 'SRV' -and $_.Section -eq 'Answer' -and $_.NameTarget })
        $valid=@($records | Where-Object {
            ([string]$_.NameTarget).TrimEnd('.').ToLowerInvariant().EndsWith('.sp2.lan')
        })
        if ($valid.Count -lt 1) { throw ('Nie potwierdzono rekordu uslugi domeny ' + $srv) }
    }
    foreach ($port in @(88,389,445)) {
        $probe=Test-NetConnection -ComputerName $server -Port $port -InformationLevel Detailed -WarningAction SilentlyContinue
        if ($probe.TcpTestSucceeded -ne $true) {
            throw ('Brak polaczenia TCP ' + $port + ' z kontrolerem AD. Przed migracja sprawdz zapore/VLAN.')
        }
    }
    Write-UiLog 'Siec SP2: potwierdzono DNS A/SRV, Kerberos TCP 88, LDAP 389 i SMB 445.'
}

function Install-LocalSP2ForMigration {
    # The operator enters the agreed password into a masked UI, once per PC.
    # Never embed it in an image, script, log, task, database or URL.
    $credential=Get-Credential -UserName ($env:COMPUTERNAME+'\SP2') -Message 'Podaj uzgodnione haslo lokalnego administratora SP2. Haslo nie zostanie zapisane.'
    if ($null -eq $credential -or $credential.Password.Length -lt 1) {
        throw 'Nie podano hasla lokalnego konta SP2.'
    }
    try {
        $local=Get-LocalUser -Name 'SP2' -ErrorAction SilentlyContinue
        if ($null -eq $local) {
            $local=New-LocalUser -Name 'SP2' -Password $credential.Password -Description 'SP2 - lokalny administrator awaryjny' -ErrorAction Stop
        } else {
            Set-LocalUser -Name 'SP2' -Password $credential.Password -ErrorAction Stop
            Enable-LocalUser -Name 'SP2' -ErrorAction Stop
        }
        $adminGroup=Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        $members=@(Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop)
        if (@($members | Where-Object { $_.SID.Value -eq $local.SID.Value }).Count -eq 0) {
            Add-LocalGroupMember -Group $adminGroup -Member $local -ErrorAction Stop
        }
        $check=Get-LocalUser -Name 'SP2' -ErrorAction Stop
        if (-not $check.Enabled) { throw 'Konto SP2 jest wylaczone.' }
        if (-not (Test-LocalSP2Login $credential.Password)) {
            throw 'Nie mozna zalogowac sie lokalnie na SP2. Nie odlaczono Entra.'
        }
        Write-UiLog 'SP2: lokalny administrator istnieje, jest aktywny i przeszedl test logowania lokalnego.'
    }
    finally {
        $credential.Password.Dispose()
    }
}

function Assert-SelectedSchoolOu([string]$Kind,[int]$Room,[string]$Ou) {
    if ($Kind -ne 'Uczen') { return }
    $match=[regex]::Match($Ou,
        '^OU=Sala0*([0-9]{1,3}),OU=Komputery,DC=sp2,DC=lan$',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success -or [int]$match.Groups[1].Value -ne $Room) {
        throw ('Nieprawidlowe OU dla sali ' + $Room + '. Wybierz OU=Sala' +
            $Room + ',OU=Komputery,DC=sp2,DC=lan (musi istniec w AD).')
    }
}

function Assert-PlanSchoolOu($Plan) {
    $match=[regex]::Match([string]$Plan.target_name,'^S0*([0-9]{1,3})-[0-9]{2}$')
    if ($match.Success) {
        Assert-SelectedSchoolOu 'Uczen' ([int]$match.Groups[1].Value) ([string]$Plan.target_ou)
    }
}

function Save-EntraTransition($Selection, $Local) {
    # No authentication token or password is ever stored in transition file.
    $state=@{
        phase='entra_detach_pending_reboot'
        device_id=(Get-DeviceId)
        hardware_uuid=[string]((Get-HardwareIdentity).uuid)
        hostname=[string]$Local.hostname
        boot_id=[string]$Local.boot_id
        endpoint=[string]$Selection.endpoint
        kind=[string]$Selection.kind
        building=[string]$Selection.building
        room=[int]$Selection.room
        number=[int]$Selection.number
        ou=[string]$Selection.ou
        created_utc=[DateTime]::UtcNow.ToString('o')
    }
    $temp=$script:EntraTransitionPath+'.tmp'
    [IO.File]::WriteAllText($temp,($state | ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $script:EntraTransitionPath) {
        [IO.File]::Replace($temp,$script:EntraTransitionPath,$null)
    } else { [IO.File]::Move($temp,$script:EntraTransitionPath) }
}

function Read-EntraTransition {
    if (-not (Test-Path -LiteralPath $script:EntraTransitionPath)) { return $null }
    $state=Get-Content -LiteralPath $script:EntraTransitionPath -Raw | ConvertFrom-Json
    if ($state.phase -ne 'entra_detach_pending_reboot') { throw 'Nieznany etap migracji Entra.' }
    if ($state.device_id -ne (Get-DeviceId) -or
        $state.hardware_uuid -ine [string]((Get-HardwareIdentity).uuid)) {
        throw 'Migracja Entra jest przypisana do innego urzadzenia.'
    }
    return $state
}

function Assert-EntraTransitionReady($Transition) {
    if ($null -eq $Transition) { return }
    if ($Transition.boot_id -eq (Get-LocalState).boot_id) {
        throw 'Po odlaczeniu Entra wymagany jest restart Windows.'
    }
    if (Get-CloudJoinFlag) {
        throw 'Komputer nadal jest dolaczony do Entra. Nie wykonuj ponownie dsregcmd /leave automatycznie.'
    }
    $local=Get-LocalState
    if ($local.part_of_domain) { throw 'Stan domeny zmienil sie po migracji Entra.' }
    if ($env:USERNAME -ine 'SP2' -or $env:USERDOMAIN -ine $env:COMPUTERNAME) {
        throw 'Aby wznowic migracje, zaloguj sie lokalnie jako .\SP2.'
    }
    if (-not (Get-LocalUser -Name 'SP2' -ErrorAction Stop).Enabled) {
        throw 'Lokalne konto SP2 jest wylaczone.'
    }
}

function Invoke-AutomaticEntraDetach($Selection,$Local) {
    if ($Local.part_of_domain -or -not (Get-CloudJoinFlag)) {
        throw 'Odlaczenie Entra wymaga potwierdzonego stanu AzureAdJoined=YES i WORKGROUP.'
    }
    if ($null -ne (Read-EntraTransition)) {
        throw 'Wykryto juz rozpoczeta migracje Entra. Sprawdz logowanie/restart zamiast powtarzac leave.'
    }
    # Verify AD DNS/SRV, domain ports and NTP BEFORE an irreversible Entra leave.
    Assert-SchoolAdReachability
    Assert-SchoolTime $true
    Install-LocalSP2ForMigration
    $message="Windows jest dolaczony do Microsoft Entra. Po odlaczeniu mozesz utracic dostep do obecnego profilu/logowania chmurowego.`nZapisz dane i potwierdz dostep do lokalnego administratora SP2.`nPo restarcie zaloguj sie jako .\SP2. Program wznowi dolaczenie do domeny szkolnej.`nCzy odlaczyc Entra i przygotowac restart?"
    if ([Windows.Forms.MessageBox]::Show($message,'SP2 - migracja Entra do Samba AD','YesNo','Warning') -ne 'Yes') {
        return 'Migracja Entra nie zostala zatwierdzona.'
    }
    Save-EntraTransition $Selection $Local
    Install-Resume
    $exe=Join-Path $env:WINDIR 'System32\dsregcmd.exe'
    [void](& $exe /leave)
    if ($LASTEXITCODE -ne 0) {
        throw 'dsregcmd /leave nie powiodlo sie. Migracja pozostaje zapisana, ale nie wolno ponawiac automatycznie.'
    }
    Write-UiLog 'Entra: wykonano leave. Wymagany restart i lokalne logowanie .\SP2. Hasla nie zapisano.'
    Restart-Computer -ErrorAction Stop
    return 'Entra: odlaczanie rozpoczete. Po restarcie zaloguj sie jako .\SP2.'
}

function Assert-SafeCloudJoinReplan($Plan,$Local) {
    # The server has already re-diagnosed the target AD account after reboot.
    # A failed native join may only be cancelled when it clearly did not
    # create any computer account or alter Windows domain membership.
    if ($Plan.action -ne 'join' -or $Plan.state -ne 'manual_review' -or
        $Local.part_of_domain -ne $false -or $null -ne $Local.secure_channel -or
        $Local.hostname -ine $Plan.source_name -or $Plan.device_id -ne (Get-DeviceId) -or
        $Plan.diagnosis.recommended_action -ne 'join' -or
        $Plan.diagnosis.target_ad.exists -ne $false -or
        $Plan.diagnosis.target_conflict -ne $false) {
        throw 'Nie potwierdzono, ze poprzedni join nie zmienil domeny lub konta AD. Plan pozostaje zarezerwowany.'
    }
    $begin=@($Plan.history | Where-Object { $_.event -eq 'begin' -and $_.action -eq 'join' } |
        Select-Object -Last 1)
    if ($begin.Count -ne 1 -or -not $Local.boot_id -or $Local.boot_id -eq $begin[0].boot_id) {
        throw 'Wymagany nowy rozruch Windows przed rozliczeniem starej proby join.'
    }
    if (@($Plan.history | Where-Object { $_.event -eq 'credential_issued' }).Count -gt 0) {
        throw 'Wykryto autoryzacje odbudowy konta. Stary plan nie moze byc anulowany automatycznie.'
    }
}

function Reconcile-PreviousCloudJoin {
    $transition=Read-EntraTransition
    if ($null -eq $transition -or $null -eq $script:State.plan) { return }
    Assert-EntraTransitionReady $transition
    $plan=$script:State.plan
    if ($plan.action -ne 'join' -or $plan.state -notin @('pending','manual_review')) {
        throw 'Poprzedni plan domenowy wymaga recznej kontroli i nie moze byc ponawiany.'
    }
    # Observe is safe after a new boot. It never performs a Windows domain join.
    if ($plan.state -eq 'pending') { Set-Progress 'observe' }
    $plan=$script:State.plan
    $local=Get-LocalState
    Assert-SafeCloudJoinReplan $plan $local
    $prompt='Po migracji Entra Windows nadal jest poza domena. Serwer sprawdzil, ze docelowe konto AD nie istnieje, a poprzedni join nie zakonczyl sie sukcesem. Czy zatwierdzasz anulowanie starej rezerwacji i utworzenie NOWEGO planu dla poprawnego OU?'
    if ([Windows.Forms.MessageBox]::Show($prompt,'SP2 - rozliczenie starego join','YesNo','Warning') -ne 'Yes') {
        throw 'Nie zatwierdzono rozliczenia starego planu. Zachowano rezerwacje.'
    }
    Set-Progress 'cancel' $true
    if ($script:State.plan.state -ne 'cancelled') {
        throw 'Serwer nie potwierdzil anulowania starego planu.'
    }
    Write-UiLog 'Stary plan zabezpieczono jako cancelled; jego historia pozostaje na serwerze.'
    $script:State.plan=$null
    Save-State
}

function Complete-EntraTransition {
    if (Test-Path -LiteralPath $script:EntraTransitionPath) {
        Remove-Item -LiteralPath $script:EntraTransitionPath -Force -ErrorAction Stop
    }
}

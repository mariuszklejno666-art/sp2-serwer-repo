$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

# All tests use mock functions and a temporary file. Never change AD, Entra,
# local users, Windows Time, network resolvers or the real ProgramData state.
function Assert-True([bool]$Value,[string]$Message) {
    if (-not $Value) { throw $Message }
}
# Native join state is an integer: 1=device join, 0=not device joined.
# The printed dsregcmd text is no longer a dependency.
$script:MockNativeCloudState=1
function Get-CloudJoinDeviceState { return $script:MockNativeCloudState }
Assert-True (Get-CloudJoinFlag) 'Native device join must be detected'
$script:MockNativeCloudState=0
Assert-True (-not (Get-CloudJoinFlag)) 'Native not-joined state must be detected'
$script:MockNativeCloudState=-1
$failed=$false
try { Get-CloudJoinFlag | Out-Null } catch { $failed=$true }
Assert-True $failed 'Unexpected native cloud join type must fail closed'
$script:MockNativeCloudState=0

Assert-SelectedSchoolOu 'Uczen' 7 'OU=Sala7,OU=Komputery,DC=sp2,DC=lan'
Assert-SelectedSchoolOu 'Uczen' 7 'OU=Sala07,OU=Komputery,DC=sp2,DC=lan'
$failed=$false
try { Assert-SelectedSchoolOu 'Uczen' 7 'OU=Komputery,DC=sp2,DC=lan' } catch { $failed=$true }
Assert-True $failed 'General computers OU must not be accepted for Sala7'
$failed=$false
try { Assert-PlanSchoolOu ([pscustomobject]@{target_name='S07-01';target_ou='OU=Sala11,OU=Komputery,DC=sp2,DC=lan'}) } catch { $failed=$true }
Assert-True $failed 'Wrong room OU must block join'
Assert-PlanSchoolOu ([pscustomobject]@{target_name='S07-01';target_ou='OU=Sala7,OU=Komputery,DC=sp2,DC=lan'})

$script:DomainDnsServer='192.168.0.143'
$script:Offset=0.035
$script:TimeRequests=@()
$script:SetServiceCalls=0
$script:StartServiceCalls=0
function Invoke-SchoolTimeCommand {
    param([string[]]$Arguments)
    $script:TimeRequests+= ,@($Arguments)
    switch ($Arguments[0]) {
        '/stripchart' { return "12:34:56, +$($script:Offset.ToString('F3',[Globalization.CultureInfo]::InvariantCulture))s" }
        '/query' { return '192.168.0.143,0x8' }
        '/config' { return 'OK' }
        '/resync' { return 'OK' }
        default { throw 'Unrecognized test command' }
    }
}
function Set-Service {
    [CmdletBinding()]
    param([string]$Name,[string]$StartupType)
    Assert-True ($Name -eq 'W32Time') 'Only Windows Time service may be configured'
    Assert-True ($StartupType -eq 'Automatic') 'Correct time service mode required'
    $script:SetServiceCalls++
}
function Start-Service {
    [CmdletBinding()]
    param([string]$Name)
    Assert-True ($Name -eq 'W32Time') 'Only Windows Time service may be started'
    $script:StartServiceCalls++
}
Assert-SchoolTime $true
Assert-True ($script:SetServiceCalls -eq 1) 'Workgroup time setup must be requested once'
Assert-True (@($script:TimeRequests | Where-Object { $_[0] -eq '/resync' }).Count -eq 1) 'NTP resync must be requested once'
Assert-SchoolTime $false
Assert-True ($script:SetServiceCalls -eq 1) 'Domain time check must never overwrite time settings'
$script:Offset=130.0
$failed=$false
try { Assert-SchoolTime $false } catch { $failed=$true }
Assert-True $failed 'Excessive time skew must block join'
$script:Offset=0.035

# Preflight must prevent detaching Microsoft Entra when any AD dependency is
# unreachable. These functions are mocks: NO real DNS/network queries occur.
$script:MockBlockedPort=0
$script:MockMissingSrv=''
$script:MockWrongDcIp=$false
$script:MockProbedPorts=@()
function Resolve-DnsName {
    [CmdletBinding()]
    param([string]$Name,[string]$Server,[string]$Type,
        [switch]$DnsOnly,[switch]$NoHostsFile)
    Assert-True ($Server -eq '192.168.0.143') 'Only school DNS may be queried'
    if ($Type -eq 'A' -and $Name -eq 'dc.sp2.lan') {
        $address='192.168.0.143'
        if ($script:MockWrongDcIp) { $address='192.168.0.250' }
        return [pscustomobject]@{Type='A';Section='Answer';IPAddress=$address}
    }
    if ($Type -eq 'SRV' -and $Name -in @(
        '_ldap._tcp.dc._msdcs.sp2.lan',
        '_kerberos._tcp.dc._msdcs.sp2.lan'
    )) {
        if ($script:MockMissingSrv -eq $Name) { return }
        return [pscustomobject]@{
            Type='SRV';Section='Answer';NameTarget='szkolaak.sp2.lan.'
        }
    }
    throw 'Unexpected DNS request'
}
function Test-NetConnection {
    [CmdletBinding()]
    param([string]$ComputerName,[int]$Port,[string]$InformationLevel)
    Assert-True ($ComputerName -eq '192.168.0.143') 'Only school DC ports may be probed'
    $script:MockProbedPorts+= $Port
    return [pscustomobject]@{TcpTestSucceeded=($Port -ne $script:MockBlockedPort)}
}
Assert-SchoolAdReachability
Assert-True (($script:MockProbedPorts -join ',') -eq '88,389,445') 'Preflight must check 88, 389, 445'
$script:MockBlockedPort=445
$blocked=$false
try { Assert-SchoolAdReachability } catch { $blocked=$true }
Assert-True $blocked 'Closed SMB port must block Entra detach'
$script:MockBlockedPort=0
$script:MockMissingSrv='_kerberos._tcp.dc._msdcs.sp2.lan'
$blocked=$false
try { Assert-SchoolAdReachability } catch { $blocked=$true }
Assert-True $blocked 'Missing Kerberos SRV must block Entra detach'
$script:MockMissingSrv=''
$script:MockWrongDcIp=$true
$blocked=$false
try { Assert-SchoolAdReachability } catch { $blocked=$true }
Assert-True $blocked 'Wrong controller DNS address must block Entra detach'
$script:MockWrongDcIp=$false

$root=Join-Path $env:TEMP ('sp2-entra-migration-ci-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$script:EntraTransitionPath=Join-Path $root 'transition.json'
$local=@{hostname='SALA7';boot_id='boot-before-leave'}
$selection=@{endpoint='https://dc.sp2.lan';kind='Uczen';building='BR';room=7;number=1;ou='OU=Sala7,OU=Komputery,DC=sp2,DC=lan'}
function Get-DeviceId { return 'e3b270e3-6c92-4649-a7a9-d87c62fd4d20' }
function Get-HardwareIdentity { return @{uuid='e3b270e3-6c92-4649-a7a9-d87c62fd4d20'} }
try {
    Save-EntraTransition $selection $local
    $state=Read-EntraTransition
    Assert-True ($state.room -eq 7 -and $state.phase -eq 'entra_detach_pending_reboot') 'Transition state must preserve room'
    $raw=Get-Content -LiteralPath $script:EntraTransitionPath -Raw
    Assert-True (-not ($raw -match '(?i)(password|credential|secret|token)')) 'No credential may be stored in transition state'
    function Get-LocalState { return @{boot_id='boot-after-reboot';part_of_domain=$false} }
    function Get-LocalUser {
        [CmdletBinding()]
        param([string]$Name)
        return [pscustomobject]@{Enabled=$true}
    }
    $beforeUser=$env:USERNAME
    $beforeDomain=$env:USERDOMAIN
    try {
        $env:USERNAME='SP2'
        $env:USERDOMAIN=$env:COMPUTERNAME
        $script:MockNativeCloudState=0
        Assert-EntraTransitionReady $state
        $script:MockNativeCloudState=1
        $blocked=$false
        try { Assert-EntraTransitionReady $state } catch { $blocked=$true }
        Assert-True $blocked 'Entra still joined must block resume'
        $script:MockNativeCloudState=0
        $env:USERNAME='OTHERADMIN'
        $blocked=$false
        try { Assert-EntraTransitionReady $state } catch { $blocked=$true }
        Assert-True $blocked 'Resume must require verified local SP2 session'
    } finally {
        $env:USERNAME=$beforeUser
        $env:USERDOMAIN=$beforeDomain
    }
    Complete-EntraTransition
    Assert-True (-not (Test-Path -LiteralPath $script:EntraTransitionPath)) 'Transition file should be cleared only when explicitly completed'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
$cloudLocal=[pscustomobject]@{
    hostname='SALA7';part_of_domain=$false;secure_channel=$null;boot_id='boot-after-reboot'
}
$oldPlan=[pscustomobject]@{
    id='old-join-plan';action='join';state='manual_review';
    source_name='SALA7';target_name='S07-01';
    device_id='e3b270e3-6c92-4649-a7a9-d87c62fd4d20';
    diagnosis=[pscustomobject]@{
        recommended_action='join';target_conflict=$false;
        target_ad=[pscustomobject]@{exists=$false}
    };
    history=@([pscustomobject]@{event='begin';action='join';boot_id='boot-before-leave'})
}
Assert-SafeCloudJoinReplan $oldPlan $cloudLocal
$oldPlan.diagnosis.target_ad.exists=$true
$blocked=$false
try { Assert-SafeCloudJoinReplan $oldPlan $cloudLocal } catch { $blocked=$true }
Assert-True $blocked 'An AD account always blocks old plan cancellation'
$oldPlan.diagnosis.target_ad.exists=$false
$oldPlan.state='pending'
$blocked=$false
try { Assert-SafeCloudJoinReplan $oldPlan $cloudLocal } catch { $blocked=$true }
Assert-True $blocked 'Pending plan is never cancelled without observe reconciliation'
$oldPlan.state='manual_review'
$cloudLocal.boot_id='boot-before-leave'
$blocked=$false
try { Assert-SafeCloudJoinReplan $oldPlan $cloudLocal } catch { $blocked=$true }
Assert-True $blocked 'Same boot must never release the name'
$cloudLocal.boot_id='boot-after-reboot'
$cloudLocal.part_of_domain=$true
$blocked=$false
try { Assert-SafeCloudJoinReplan $oldPlan $cloudLocal } catch { $blocked=$true }
Assert-True $blocked 'Already joined Windows must keep the existing reservation'
$cloudLocal.part_of_domain=$false

Write-Output 'ENTRA TIME MIGRATION TESTS OK; mocked time, Entra, user and isolated state only.'

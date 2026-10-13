$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

# Fake native boundary: these tests never call Windows join or rename APIs.
Add-Type -TypeDefinition @'
using System.Security;
public static class SP2MachineAccountRecovery {
    public static uint Code = 0;
    public static int Calls = 0;
    public static string Name;
    public static uint Join(string name, string domain, string ou, string account, SecureString password) {
        Calls++; Name=name; return Code;
    }
}
'@
function Assert-True([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Get-DeviceId { return '6a7289cd-0c71-4773-8a9d-debe56de38f1' }
function Get-LocalState { return $script:Local }
$script:State=@{device_id=(Get-DeviceId);plan=@{id='test-plan';version=2}}
$script:Local=@{part_of_domain=$true;secure_channel=$false;domain='sp2.lan'}
$plan=[pscustomobject]@{target_name='S11-15';domain='sp2.lan';target_ou='OU=Sala11,OU=Komputery,DC=sp2,DC=lan'}
$credential=[Management.Automation.PSCredential]::new('joiner@sp2.lan',(ConvertTo-SecureString 'test-only' -AsPlainText -Force))
try {
    Invoke-MachineAccountRecovery $plan $credential
    Assert-True ([SP2MachineAccountRecovery]::Calls -eq 1) 'Exactly one native call expected'
    Assert-True ([SP2MachineAccountRecovery]::Name -eq 'S11-15') 'Reserved target required'
    $script:Local.secure_channel=$null
    $failed=$false
    try { Invoke-MachineAccountRecovery $plan $credential } catch { $failed=$true }
    Assert-True $failed 'Unknown channel must stop'
    Assert-True ([SP2MachineAccountRecovery]::Calls -eq 1) 'Unknown state must never join'
    $script:Local.secure_channel=$false
    [SP2MachineAccountRecovery]::Code=5
    $failed=$false
    try { Invoke-MachineAccountRecovery $plan $credential } catch { $failed=$true }
    Assert-True $failed 'Native failure must surface without retry'
    Assert-True ([SP2MachineAccountRecovery]::Calls -eq 2) 'Native failure must not retry'
    $script:Response=[pscustomobject]@{authorized=$true}
    function Invoke-Api($Path,$Data) {
        Assert-True ($Path -eq 'join-authorize/test-plan') 'Authorization must be plan scoped'
        Assert-True ($Data.version -eq 2) 'Write-ahead version required'
        return $script:Response
    }
    Authorize-RecoveryJoin
    Assert-True ($script:Response.authorized -eq $true) 'Authorization response required'
    $preflight=[pscustomobject]@{history=@([pscustomobject]@{
        event='begin';action='machine_account_recovery'
    })}
    Assert-True (-not (Test-JoinAuthorizationRecorded $preflight)) 'Preflight may use guarded retry'
    $authorized=[pscustomobject]@{history=@(
        [pscustomobject]@{event='begin';action='machine_account_recovery'},
        [pscustomobject]@{event='credential_issued';action='machine_account_recovery'}
    )}
    Assert-True (Test-JoinAuthorizationRecorded $authorized) 'Authorized join must not retry'
} finally { $credential.Password.Dispose() }
# Separate script scope keeps mocked NRPT cmdlets isolated from the native join mocks.
& (Join-Path $PSScriptRoot 'test-domain-dns.ps1')
& (Join-Path $PSScriptRoot 'test-school-ca.ps1')
& (Join-Path $PSScriptRoot 'test-workgroup-join-failure.ps1')
& (Join-Path $PSScriptRoot 'test-join-name-preflight.ps1')
& (Join-Path $PSScriptRoot 'test-cim-https-diagnostics.ps1')
& (Join-Path $PSScriptRoot 'test-join-cancel-reconcile.ps1')
& (Join-Path $PSScriptRoot 'test-entra-transition.ps1')
& (Join-Path $PSScriptRoot 'test-postjoin-dns.ps1')
& (Join-Path $PSScriptRoot 'test-auto-recovery.ps1')
Write-Output 'MACHINE RECOVERY UNIT TESTS OK; no network, AD, rename, join or restart operations.'

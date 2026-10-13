$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

# Pure, mock-only Windows DNS and identity tests: no network, AD, adapter or
# domain operations. Ensure the Internet-first DNS order ALWAYS survives.
function Assert-True([bool]$Ok,[string]$Message) {
    if (-not $Ok) { throw $Message }
}
$script:DomainDnsServer='192.168.0.143'
$script:MockSourceIp='192.168.1.163'
$script:MockActualIp=$script:MockSourceIp
$script:MockDnsPresent=$false
$script:MockDnsConflict=$false
$script:MockExternalAnswer=$true
$script:MockRegisterOnlyWithSchoolFirst=$false
$script:MockRefuseRegistration=$false
$script:MockRegisterCalls=0
$script:MockDnsChanges=@()
$script:MockServers=@('198.168.0.143','192.168.0.143')
function Get-DeviceId { return 'e3b270e3-6c92-4649-a7a9-d87c62fd4d20' }
function Get-LocalState { return $script:MockLocal }
function Test-NetConnection {
    [CmdletBinding()]
    param([string]$ComputerName,[int]$Port,[string]$InformationLevel)
    Assert-True ($ComputerName -eq '192.168.0.143' -and $Port -eq 53) 'Unexpected network probe'
    return [pscustomobject]@{
        TcpTestSucceeded=$true
        SourceAddress=[Net.IPAddress]::Parse($script:MockSourceIp)
        InterfaceAlias='Wi-Fi'
    }
}
function Get-NetAdapter {
    [CmdletBinding()]
    param([switch]$Physical)
    return [pscustomobject]@{Name='Wi-Fi';Status='Up';ifIndex=17}
}
function Get-NetIPAddress {
    [CmdletBinding()]
    param([string]$AddressFamily,[int]$InterfaceIndex)
    Assert-True ($AddressFamily -eq 'IPv4' -and $InterfaceIndex -eq 17) 'Wrong adapter/IP'
    return [pscustomobject]@{IPAddress=$script:MockActualIp}
}
function Get-DnsClientServerAddress {
    [CmdletBinding()]
    param([int]$InterfaceIndex,[string]$AddressFamily)
    return [pscustomobject]@{ServerAddresses=@($script:MockServers)}
}
function Set-DnsClientServerAddress {
    [CmdletBinding()]
    param([int]$InterfaceIndex,[string[]]$ServerAddresses)
    Assert-True ($InterfaceIndex -eq 17) 'Attempted change to another adapter'
    $script:MockServers=@($ServerAddresses)
    $script:MockDnsChanges+= ,@($ServerAddresses)
}
function Clear-DnsClientCache { [CmdletBinding()] param() }
function Start-Sleep { param([int]$Seconds) }
function Resolve-DnsName {
    [CmdletBinding()]
    param([string]$Name,[string]$Server,[string]$Type,
          [switch]$DnsOnly,[switch]$NoHostsFile)
    Assert-True ($Server -eq '192.168.0.143') 'Unexpected DNS server'
    if ($Name -eq 'www.microsoft.com') {
        if ($script:MockExternalAnswer) {
            return [pscustomobject]@{Type='A';Section='Answer';IPAddress='13.107.246.50'}
        }
        return
    }
    Assert-True ($Name -eq 's07-01.sp2.lan') 'Unexpected registered hostname'
    # Windows sometimes returns Question entries that LOOK like A records.
    [pscustomobject]@{Type='A';Section='Question';IPAddress=$script:MockSourceIp}
    if ($script:MockDnsConflict) {
        return [pscustomobject]@{Type='A';Section='Answer';IPAddress='192.168.1.250'}
    }
    if ($script:MockDnsPresent) {
        return [pscustomobject]@{Type='A';Section='Answer';IPAddress=$script:MockSourceIp}
    }
}
function Register-DnsClient {
    [CmdletBinding()]
    param()
    $script:MockRegisterCalls++
    if ($script:MockRefuseRegistration) { return }
    if (-not $script:MockRegisterOnlyWithSchoolFirst -or
        $script:MockServers[0] -eq '192.168.0.143') {
        $script:MockDnsPresent=$true
    }
}
function Reset-DnsCase {
    $script:MockDnsPresent=$false
    $script:MockDnsConflict=$false
    $script:MockExternalAnswer=$true
    $script:MockRegisterOnlyWithSchoolFirst=$false
    $script:MockRefuseRegistration=$false
    $script:MockRegisterCalls=0
    $script:MockDnsChanges=@()
    $script:MockServers=@('198.168.0.143','192.168.0.143')
    $script:MockActualIp='192.168.1.163'
}
$script:MockLocal=@{
    hostname='S07-01';domain='sp2.lan';part_of_domain=$true;secure_channel=$true
}
$script:MockPlan=[pscustomobject]@{
    id='plan-s07-01';state='manual_review';action='blocked'
    target_name='S07-01';domain='sp2.lan'
    device_id='e3b270e3-6c92-4649-a7a9-d87c62fd4d20'
    source_sid='SID-1374'
    history=@([pscustomobject]@{event='begin';action='join';boot_id='old-boot'})
    diagnosis=[pscustomobject]@{
        status='AD_METADATA_REVIEW';target_conflict=$false
        target_ad=[pscustomobject]@{
            exists=$true;enabled=$true;object_sid='SID-1374'
        }
        checks=[pscustomobject]@{
            ou_matches=$true;spn_matches=$true
            dns_spn_conflict=$false;dns_resolves=$false
        }
    }
}
Assert-True (Assert-PostJoinDnsIdentity $script:MockPlan $script:MockLocal) 'Valid post-join identity must pass'
# CI426 regression: old server payload omitted source_sid and StrictMode
# threw PropertyNotFoundException. No DNS operation may occur without the
# immutable SID delivered by the authenticated recovery API.
$script:MockPlan.PSObject.Properties.Remove('source_sid')
Reset-DnsCase
Assert-True (-not (Assert-PostJoinDnsIdentity $script:MockPlan $script:MockLocal)) 'Missing pinned SID must fail closed, not crash'
Assert-True (-not (Repair-MissingSchoolDnsA $script:MockPlan $script:MockLocal)) 'Missing SID must not start DNS registration'
Assert-True ($script:MockRegisterCalls -eq 0) 'No DNS registration without pinned SID'
$script:MockPlan | Add-Member -NotePropertyName source_sid -NotePropertyValue ''
Assert-True (-not (Assert-PostJoinDnsIdentity $script:MockPlan $script:MockLocal)) 'Empty pinned SID must fail closed'
$script:MockPlan.source_sid='SID-1374'


Reset-DnsCase
$resolved=@(Get-AuthoritativeSchoolARecords 's07-01.sp2.lan')
Assert-True ($resolved.Count -eq 0) 'Question-section A record must not count'
Assert-True (Repair-MissingSchoolDnsA $script:MockPlan $script:MockLocal) 'Direct secure registration should pass'
Assert-True ($script:MockRegisterCalls -eq 1) 'Direct registration should execute only once'
Assert-True ($script:MockDnsChanges.Count -eq 0) 'Direct registration must not change interface DNS'

Reset-DnsCase
$script:MockRegisterOnlyWithSchoolFirst=$true
Assert-True (Repair-MissingSchoolDnsA $script:MockPlan $script:MockLocal) 'Temporary school-first fallback should work'
Assert-True ($script:MockDnsChanges.Count -eq 2) 'Fallback must set and restore DNS once'
Assert-True (($script:MockServers -join ',') -eq '198.168.0.143,192.168.0.143') 'Original Internet-first DNS must be restored'
Assert-True ($script:MockDnsPresent) 'Record should exist after fallback'

Reset-DnsCase
$script:MockRegisterOnlyWithSchoolFirst=$true
$script:MockExternalAnswer=$false
$blocked=$false
try { Repair-MissingSchoolDnsA $script:MockPlan $script:MockLocal | Out-Null } catch { $blocked=$true }
Assert-True $blocked 'Without safe public DNS fallback must fail closed'
Assert-True ($script:MockDnsChanges.Count -eq 0) 'Must not change DNS without public forwarder'
Assert-True (($script:MockServers -join ',') -eq '198.168.0.143,192.168.0.143') 'Internet-first DNS must remain'

Reset-DnsCase
$script:MockRegisterOnlyWithSchoolFirst=$true
$script:MockRefuseRegistration=$true
$blocked=$false
try { Repair-MissingSchoolDnsA $script:MockPlan $script:MockLocal | Out-Null } catch { $blocked=$true }
Assert-True $blocked 'Failed secure update should stop'
Assert-True (($script:MockServers -join ',') -eq '198.168.0.143,192.168.0.143') 'Restore DNS even if update failed'
Assert-True ($script:MockDnsChanges.Count -eq 2) 'Must restore DNS in finally'

Reset-DnsCase
$script:MockDnsConflict=$true
$blocked=$false
try { Repair-MissingSchoolDnsA $script:MockPlan $script:MockLocal | Out-Null } catch { $blocked=$true }
Assert-True $blocked 'Existing record with different IP must fail closed'
Assert-True ($script:MockRegisterCalls -eq 0) 'Never register over another IP'
Assert-True ($script:MockDnsChanges.Count -eq 0) 'Never change DNS for conflicting A record'

Reset-DnsCase
$script:MockPlan.source_sid='SID-FROM-ANOTHER-COMPUTER'
Assert-True (-not (Repair-MissingSchoolDnsA $script:MockPlan $script:MockLocal)) 'Mismatched SID blocks registration'
Assert-True ($script:MockRegisterCalls -eq 0) 'No registration with mismatched SID'
$script:MockPlan.source_sid='SID-1374'
$script:MockLocal.secure_channel=$false
Assert-True (-not (Repair-MissingSchoolDnsA $script:MockPlan $script:MockLocal)) 'Broken trust blocks registration'
$script:MockLocal.secure_channel=$true
$script:MockActualIp='192.168.1.250'
$blocked=$false
try { Repair-MissingSchoolDnsA $script:MockPlan $script:MockLocal | Out-Null } catch { $blocked=$true }
Assert-True $blocked 'Route source IP must match configured interface IP'
Assert-True ($script:MockRegisterCalls -eq 0) 'Never register unverified interface IP'
Write-Output 'POST-JOIN DNS TESTS OK: mocked secure updates, DNS rollback, SID, IP and internet checks.'

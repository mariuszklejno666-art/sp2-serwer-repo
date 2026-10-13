$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

# Synthetic inputs only: never touch registry, DNS, AD, Windows join, or restart.
function Assert-True([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }

$names=@{
    WindowsName='LAPTOP-D9MFLC2P'
    DnsHostName='LAPTOP-D9MFLC2P'
    SocketHostName='LAPTOP-D9MFLC2P'
    ProcessName='LAPTOP-D9MFLC2P'
    ActiveName='LAPTOP-D9MFLC2P'
    PendingName='LAPTOP-D9MFLC2P'
    TcpHostname='LAPTOP-D9MFLC2P'
    TcpNvHostname='LAPTOP-D9MFLC2P'
}
$issues=@(Get-JoinNameConsistencyIssues $names 'LAPTOP-D9MFLC2P')
Assert-True ($issues.Count -eq 0) 'Consistent names must pass even if server target name differs'

$broken=$names.Clone()
$broken['DnsHostName']='WIN-L5Q9CJACB5B'
$broken['SocketHostName']='WIN-L5Q9CJACB5B'
$broken['TcpHostname']='WIN-L5Q9CJACB5B'
$broken['TcpNvHostname']='WIN-L5Q9CJACB5B'
$issues=@(Get-JoinNameConsistencyIssues $broken 'LAPTOP-D9MFLC2P')
Assert-True ($issues.Count -eq 4) 'Observed SP2 client mismatch must be detected'
Assert-True (@($issues | Where-Object { $_ -match 'TcpHostname=WIN-L5Q9CJACB5B' }).Count -eq 1) 'Log must name the divergent TCP/IP value'

$pending=$names.Clone()
$pending['PendingName']='S07-08'
$issues=@(Get-JoinNameConsistencyIssues $pending 'LAPTOP-D9MFLC2P')
Assert-True ($issues.Count -eq 1) 'Pending rename must not allow join before restart'

$issues=@(Get-JoinNameConsistencyIssues $names 'S07-08')
Assert-True ($issues.Count -eq 1) 'Plan source name mismatch must block join'

$missing=$names.Clone()
$missing['TcpNvHostname']=''
$issues=@(Get-JoinNameConsistencyIssues $missing 'LAPTOP-D9MFLC2P')
Assert-True ($issues.Count -eq 1) 'Unreadable name must fail closed'

Write-Output 'JOIN NAME PREFLIGHT UNIT TESTS OK; no Windows, AD, network, join or restart operations.'

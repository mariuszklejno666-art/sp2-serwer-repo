$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

# No AD/SMB/restart operations. Simulate a native join that failed after begin.
function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
}
$script:State=@{ plan=[pscustomobject]@{id='test-plan';state='pending';action='join';version=3} }
$script:StatusReads=0
$script:FailedReports=0
$script:FailureMessage=''
function Invoke-Api($Path,$Data,[string]$Method='POST') {
    Assert-True ($Path -eq 'status/test-plan') 'Must re-read exact reserved plan'
    $script:StatusReads++
    return $script:State.plan
}
function Set-Progress([string]$Event,[bool]$Approved=$false) {
    Assert-True ($Event -eq 'failed') 'Only failure report is allowed'
    Assert-True ($script:State.plan.state -eq 'pending') 'Only pending plan may be failed'
    $script:FailedReports++
    $script:State.plan.state='manual_review'
}
$plan=[pscustomobject]@{id='test-plan';action='join'}
Report-UnconfirmedWorkgroupJoin $plan
Assert-True ($script:FailedReports -eq 1) 'Failure must be reported once'
Assert-True ($script:State.plan.state -eq 'manual_review') 'Reserved plan stays in manual review'
Assert-True ($script:FailureMessage -match 'NetSetup.log') 'Diagnostic must refer to Windows join log'
Report-UnconfirmedWorkgroupJoin $plan
Assert-True ($script:FailedReports -eq 1) 'Manual review never re-reports or retries join'
$before=$script:StatusReads
Report-UnconfirmedWorkgroupJoin ([pscustomobject]@{id='test-plan';action='machine_account_recovery'})
Assert-True ($script:StatusReads -eq $before) 'Other repair actions unaffected'
# The cloud join check must protect both new plans and existing recovery
# plans from a second NetJoinDomain call on an Entra joined workstation.
function Get-CloudJoinDeviceState { return $script:MockNativeCloudState }
$script:MockNativeCloudState=1
$blocked=$false
try { Assert-WorkgroupNotCloudJoined } catch { $blocked=$true }
Assert-True $blocked 'Native Entra device join must block Windows join'
Assert-True ($script:FailureMessage -match '0xA8C') 'Block must explain Windows 0xA8C'
$script:MockNativeCloudState=0
Assert-WorkgroupNotCloudJoined
$script:MockNativeCloudState=-1
$blocked=$false
try { Assert-WorkgroupNotCloudJoined } catch { $blocked=$true }
Assert-True $blocked 'Unknown native cloud join state must fail closed'
Assert-True ($script:FailureMessage -match 'natywne API') 'Unknown state must give useful diagnostics'
Write-Output 'WORKGROUP JOIN FAILURE TESTS OK; only mock plan status calls.'

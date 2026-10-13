$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

# Operator rejected the reserved name (wrong room/number). No Windows join,
# rename, AD, DNS, scheduled task, disk state or real server is touched.
function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
}
$script:CancelCalls=0
$script:LastReason=''
$script:ServerMode='accept'
$script:Local=@{hostname='DESKTOP-ABC1'; part_of_domain=$false; secure_channel=$null; domain='WORKGROUP'; boot_id='boot1'}
function Get-LocalState { return $script:Local }
function Save-State { }
function Unregister-ScheduledTask { }
function Set-Progress([string]$Event,[bool]$Approved=$false,[string]$Reason='') {
    Assert-True ($Event -eq 'cancel' -and $Approved) 'Only explicit approved cancellation allowed'
    $script:CancelCalls++
    $script:LastReason=$Reason
    if ($script:ServerMode -eq 'reject') {
        $script:LastHttpStatus=409
        $script:FailureMessage='Plan zostal juz rozpoczety w Windows/AD. Anulowanie niedozwolone; uzyj WZNOW RECOVERY.'
        throw 'Mock server rejected cancellation'
    }
    if ($script:ServerMode -eq 'ignore') { return }
    $script:State.plan.state='cancelled'
}
function Add-Computer { throw 'TEST FAILURE: Add-Computer must never execute' }
function Rename-Computer { throw 'TEST FAILURE: Rename-Computer must never execute' }
function Make-Plan([string[]]$Events=@('observe')) {
    return [pscustomobject]@{
        id='11111111-1111-1111-1111-111111111111'; version=2
        state='ready'; action='join'; device_id='dev-1'
        source_name='DESKTOP-ABC1'; target_name='S07-03'
        target_ou='OU=Sala7,OU=Komputery,DC=sp2,DC=lan'
        history=@($Events | ForEach-Object { [pscustomobject]@{event=$_;action='join'} })
    }
}
function New-TestState($Plan) {
    return @{device_id='dev-1'; plan=$Plan; request_id='req-old'; target_name='S07-03'; target_ou=$Plan.target_ou}
}

# Pure helpers
Assert-True ((Get-TargetGroupPrefix 'S07-03') -eq 'S07') 'Student prefix'
Assert-True ((Get-TargetGroupPrefix 'PL-S04-01') -eq 'PL-S04') 'Teacher prefix'
$p=Make-Plan
Assert-True (-not (Test-PlanSelectionMismatch $p 'S07-09' '' $false)) 'auto_name: same room is not a mismatch'
Assert-True (Test-PlanSelectionMismatch $p 'S11-03' '' $false) 'auto_name: other room is a mismatch'
Assert-True (Test-PlanSelectionMismatch $p 'S07-09' '' $true) 'exact name: other number is a mismatch'
Assert-True (Test-PlanSelectionMismatch $p 'S07-03' 'OU=Sala11,OU=Komputery,DC=sp2,DC=lan' $false) 'Other OU is a mismatch'

# 1. Untouched ready plan: server-confirmed cancel clears plan, name and request ID.
$script:State=New-TestState (Make-Plan)
Assert-True (Cancel-PlanBeforeStart 'operator_rejected_target_name' $true) 'Untouched plan must be cancellable'
Assert-True ($script:CancelCalls -eq 1 -and $script:LastReason -eq 'operator_rejected_target_name') 'Cancel sent once with reason'
Assert-True ($null -eq $script:State.plan) 'Local plan cleared after server cancel'
Assert-True ($script:State.target_name -eq '') 'Wrong name must not be reused by WZNOW'
Assert-True ($script:State.request_id -ne 'req-old') 'New request ID so the cancelled plan is not returned'

# 2. Started plans are never cancelled from the client.
foreach ($event in @('begin','credential_issued','approve_ad','retry','failed')) {
    $script:State=New-TestState (Make-Plan @('observe',$event))
    $before=$script:CancelCalls
    Assert-True (-not (Cancel-PlanBeforeStart 'operator_rejected_target_name' $true)) ("Event $event must block cancel")
    Assert-True ($script:CancelCalls -eq $before) ("Event $event must not call server")
    Assert-True ($null -ne $script:State.plan) 'Reservation preserved'
}

# 3. Windows name already changed or plan of another device: blocked.
$script:State=New-TestState (Make-Plan)
$script:Local.hostname='S07-03'
$before=$script:CancelCalls
Assert-True (-not (Cancel-PlanBeforeStart 'operator_rejected_target_name' $true)) 'Renamed Windows must block cancel'
Assert-True ($script:CancelCalls -eq $before) 'Renamed Windows must not call server'
$script:Local.hostname='DESKTOP-ABC1'
$script:State=New-TestState (Make-Plan)
$script:State.device_id='dev-2'
Assert-True (-not (Cancel-PlanBeforeStart 'operator_rejected_target_name' $true)) 'Other device must block cancel'

# 4. Pending (in progress) plan: blocked.
$plan=Make-Plan; $plan.state='pending'
$script:State=New-TestState $plan
Assert-True (-not (Cancel-PlanBeforeStart 'operator_rejected_target_name' $true)) 'Pending plan must block cancel'

# 5. Server veto or unconfirmed state keeps the reservation.
$script:ServerMode='reject'
$script:State=New-TestState (Make-Plan)
Assert-True (-not (Cancel-PlanBeforeStart 'operator_rejected_target_name' $true)) 'Server 409 must not clear plan'
Assert-True ($null -ne $script:State.plan -and $script:State.target_name -eq 'S07-03') 'Server veto preserves local state'
$script:ServerMode='ignore'
$script:State=New-TestState (Make-Plan)
Assert-True (-not (Cancel-PlanBeforeStart 'operator_rejected_target_name' $true)) 'Unconfirmed cancel must not clear plan'
Assert-True ($null -ne $script:State.plan) 'Unconfirmed cancel preserves plan'

Write-Output 'CANCEL BEFORE START UNIT TESTS OK; no join, rename, AD, DNS or server writes.'

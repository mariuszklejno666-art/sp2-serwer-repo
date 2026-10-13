$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

# No calls to Windows Add-Computer, AD, HTTPS, DNS, restart or actual server.
function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
}
$script:CancelCalls=0
$script:PromptCalls=0
$script:Approved=$false
$script:ServerRejects=$false
$script:Local=@{
    hostname='LAPTOP-KVUTV4G3'
    domain='WORKGROUP'
    part_of_domain=$false
    secure_channel=$null
    boot_id='2026-10-09T07:00:00Z'
}
function Get-LocalState { return $script:Local }
function Confirm-UnconfirmedWorkgroupJoinCancellation($Plan) {
    $script:PromptCalls++
    return [bool]$script:Approved
}
function Set-Progress([string]$Event,[bool]$Approved=$false) {
    Assert-True ($Event -eq 'cancel' -and $Approved) 'Only explicit approved cancellation allowed'
    $script:CancelCalls++
    if ($script:ServerRejects) {
        $script:LastHttpStatus=409
        throw 'Mock server rejected cancellation'
    }
    $script:State.plan.state='cancelled'
}
function Add-Computer { throw 'TEST FAILURE: Add-Computer must never execute' }
function Make-Plan {
    return [pscustomobject]@{
        state='manual_review'
        action='join'
        source_name='LAPTOP-KVUTV4G3'
        target_name='S07-02'
        target_ou='OU=Sala7,OU=Komputery,DC=sp2,DC=lan'
        history=@(
            [pscustomobject]@{event='observe';action='join';boot_id='2026-10-09T06:15:00Z'}
            [pscustomobject]@{event='begin';action='join';boot_id='2026-10-09T06:15:00Z'}
            [pscustomobject]@{event='failed';action='join'}
        )
        diagnosis=[pscustomobject]@{
            status='OUTSIDE_DOMAIN'
            target_conflict=$false
            target_ad=[pscustomobject]@{exists=$false}
            checks=[pscustomobject]@{dns_spn_conflict=$false}
        }
    }
}

$script:Plan=Make-Plan
$script:State=@{plan=$script:Plan}
$script:Approved=$false
$r=Reconcile-UnconfirmedWorkgroupJoin $script:Plan
Assert-True ($r -match 'Nie wycofano planu') 'Refusal must preserve plan'
Assert-True ($script:PromptCalls -eq 1 -and $script:CancelCalls -eq 0) 'Refusal must never send cancel'

$script:Plan=Make-Plan
$script:Plan.diagnosis.target_ad.exists=$true
$script:State.plan=$script:Plan
$script:Approved=$true
$r=Reconcile-UnconfirmedWorkgroupJoin $script:Plan
Assert-True ($r -match 'ZATRZYMANO') 'Existing target AD account must prevent cancellation'
Assert-True ($script:PromptCalls -eq 1 -and $script:CancelCalls -eq 0) 'AD conflict must not offer approval'

$script:Plan=Make-Plan
$script:Plan.history[1].boot_id=$script:Local.boot_id
$script:State.plan=$script:Plan
$r=Reconcile-UnconfirmedWorkgroupJoin $script:Plan
Assert-True ($r -match 'restart') 'Cancellation requires reboot after begin'
Assert-True ($script:CancelCalls -eq 0) 'Same boot must not cancel'

$script:Plan=Make-Plan
$script:State.plan=$script:Plan
$script:Local.part_of_domain=$true
$r=Reconcile-UnconfirmedWorkgroupJoin $script:Plan
Assert-True ($r -match 'ZATRZYMANO') 'Joined Windows cannot cancel workgroup join'
Assert-True ($script:CancelCalls -eq 0) 'Domain member must not cancel'
$script:Local.part_of_domain=$false

$script:Plan=Make-Plan
$script:State.plan=$script:Plan
$script:ServerRejects=$true
$script:LastHttpStatus=0
$r=Reconcile-UnconfirmedWorkgroupJoin $script:Plan
Assert-True ($r -match 'Serwer nie potwierdzil') 'Server 409 leaves manual review'
Assert-True ($script:Plan.state -eq 'manual_review') 'Server veto preserves reservation'

$script:Plan=Make-Plan
$script:State.plan=$script:Plan
$script:ServerRejects=$false
$script:LastHttpStatus=0
$r=Reconcile-UnconfirmedWorkgroupJoin $script:Plan
Assert-True ($script:Plan.state -eq 'cancelled') 'Only server-confirmed cancel releases old plan'
Assert-True ($r -match 'NAPRAW TEN KOMPUTER' -and $r -match 'nie uruchomiono join') 'Fresh join must remain separate action'

$script:Plan=Make-Plan
$script:Plan.action='machine_account_recovery'
Assert-True ($null -eq (Reconcile-UnconfirmedWorkgroupJoin $script:Plan)) 'Machine account recovery must be unaffected'

# Regression: a second school PC with inconsistent local identity must not cancel.
$script:Plan=Make-Plan
$script:Plan.source_name='WIN-L5Q9CJACB5B'
$script:State.plan=$script:Plan
$before=$script:CancelCalls
$r=Reconcile-UnconfirmedWorkgroupJoin $script:Plan
Assert-True ($r -match 'ZATRZYMANO') 'Source-name mismatch must block cancellation'
Assert-True ($script:CancelCalls -eq $before) 'Source-name mismatch must not call cancel'

# Regression: an ambiguous local secure-channel report must fail closed.
$script:Plan=Make-Plan
$script:State.plan=$script:Plan
$script:Local.secure_channel=$false
$before=$script:CancelCalls
$r=Reconcile-UnconfirmedWorkgroupJoin $script:Plan
Assert-True ($r -match 'ZATRZYMANO') 'Unexpected secure-channel status must block cancellation'
Assert-True ($script:CancelCalls -eq $before) 'Ambiguous channel must not call cancel'
$script:Local.secure_channel=$null

# Regression: DNS/SPN conflict cannot be cleared by client logic.
$script:Plan=Make-Plan
$script:Plan.diagnosis.checks.dns_spn_conflict=$true
$script:State.plan=$script:Plan
$before=$script:CancelCalls
$r=Reconcile-UnconfirmedWorkgroupJoin $script:Plan
Assert-True ($r -match 'ZATRZYMANO') 'Server conflict must block cancellation'
Assert-True ($script:CancelCalls -eq $before) 'Server conflict must preserve reservation'

Write-Output 'JOIN CANCEL RECONCILIATION UNIT TESTS OK; no real join, AD, DNS, or server writes.'

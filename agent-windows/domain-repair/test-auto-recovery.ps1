$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
}
$script:MockCalls=0
$script:Steps=@()
$script:State=@{token='encrypted-test-only';plan=$null}
$script:ResumeRemoved=0
$script:Saved=0
$script:AutoLogs=@()
function Write-UiLog([string]$Message) { $script:AutoLogs+= $Message }
function Run-Recovery {
    $step=$script:Steps[$script:MockCalls]
    $script:MockCalls++
    $script:State.plan=$step.plan
    return [string]$step.message
}
function Unregister-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName,[switch]$Confirm)
    Assert-True ($TaskName -eq 'SP2-Domain-Recovery') 'Only SP2 recovery task is eligible for cleanup'
    $script:ResumeRemoved++
}
function Save-State { $script:Saved++ }

function Make-Step([string]$State,[string]$Action,[string]$Status,[string]$Message) {
    return [pscustomobject]@{
        message=$Message
        plan=[pscustomobject]@{
            state=$State;action=$Action
            diagnosis=[pscustomobject]@{status=$Status}
        }
    }
}
$cn='Serwer sprawdzil korekte AD. Nacisnij WZNOW, aby zatwierdzic kolejny etap.'
$repair='Kanal sprawdzony. Nacisnij WZNOW, aby wykonac kolejny etap.'
$success='GOTOWE: secure channel oraz konto, OU, DNS/SPN potwierdzone przez serwer.'
$script:Steps=@(
    (Make-Step 'ready' 'repair_secure_channel' 'TRUST_BROKEN_AD_EXISTS' $cn),
    (Make-Step 'manual_review' 'blocked' 'AD_METADATA_REVIEW' $repair),
    (Make-Step 'complete' 'none' 'OK' $success)
)
$script:MockCalls=0
Assert-True ((Run-RecoveryUntilStable) -eq $success) 'Successful CN + trust + DNS chain should complete'
Assert-True ($script:MockCalls -eq 3) 'Exactly 3 safe steps should run'

$script:Steps=@(
    (Make-Step 'ready' 'join' 'OUTSIDE_DOMAIN' $cn),
    (Make-Step 'complete' 'none' 'OK' $success)
)
$script:MockCalls=0
Assert-True ((Run-RecoveryUntilStable) -eq $cn) 'Never auto-start another domain join'
Assert-True ($script:MockCalls -eq 1) 'Blocked join cannot execute the next step'

$script:Steps=@(
    (Make-Step 'manual_review' 'repair_secure_channel' 'TRUST_BROKEN_AD_EXISTS' $repair),
    (Make-Step 'complete' 'none' 'OK' $success)
)
$script:MockCalls=0
Assert-True ((Run-RecoveryUntilStable) -eq $repair) 'Never automatically retry an ambiguous secure-channel operation'
Assert-True ($script:MockCalls -eq 1) 'Ambiguous retry must stop'

$script:Steps=@(
    (Make-Step 'manual_review' 'blocked' 'SOURCE_IDENTITY_CHANGED' $repair),
    (Make-Step 'complete' 'none' 'OK' $success)
)
$script:MockCalls=0
Assert-True ((Run-RecoveryUntilStable) -eq $repair) 'Identity mismatch cannot auto-progress'
Assert-True ($script:MockCalls -eq 1) 'Blocked identity should stop'

$script:Steps=@(
    (Make-Step 'ready' 'repair_secure_channel' 'TRUST_BROKEN_AD_EXISTS' $cn),
    (Make-Step 'ready' 'repair_secure_channel' 'TRUST_BROKEN_AD_EXISTS' $cn),
    (Make-Step 'ready' 'repair_secure_channel' 'TRUST_BROKEN_AD_EXISTS' $cn),
    (Make-Step 'ready' 'repair_secure_channel' 'TRUST_BROKEN_AD_EXISTS' $cn),
    (Make-Step 'ready' 'repair_secure_channel' 'TRUST_BROKEN_AD_EXISTS' $cn)
)
$script:MockCalls=0
Assert-True ((Run-RecoveryUntilStable) -match '5 krokach') 'Auto sequence must have a hard limit'
Assert-True ($script:MockCalls -eq 5) 'No sixth attempt is allowed'

$script:Steps=@(
    (Make-Step 'ready' 'repair_secure_channel' 'UNKNOWN' 'Nie zatwierdzono zmiany AD.'),
    (Make-Step 'complete' 'none' 'OK' $success)
)
$script:MockCalls=0
Assert-True ((Run-RecoveryUntilStable) -eq 'Nie zatwierdzono zmiany AD.') 'User cancellation must stop'
Assert-True ($script:MockCalls -eq 1) 'Cancellation must not trigger another step'

$script:State.token='encrypted-test-only'
$result=Complete-RecoveryClientState
Assert-True ($result -eq $success) 'Completed plan should show correct success'
Assert-True ($script:State.token -eq '') 'Completed plan must clear its stored token'
Assert-True ($script:ResumeRemoved -eq 1 -and $script:Saved -eq 1) 'Completed plan cleanup must be recorded'

# Regression: after server completion /identify returns plan=$null.
# RESUME must never open another plan on a healthy, joined workstation.
$workgroup=[pscustomobject]@{part_of_domain=$false;secure_channel=$null;domain='WORKGROUP'}
$joined=[pscustomobject]@{part_of_domain=$true;secure_channel=$true;domain='sp2.lan'}
$broken=[pscustomobject]@{part_of_domain=$true;secure_channel=$false;domain='sp2.lan'}
Assert-True (Test-ResumeMayCreatePlan $workgroup $null $null) 'Interrupted first workgroup plan may be resumed'
Assert-True (-not (Test-ResumeMayCreatePlan $joined $null $null)) 'Healthy completed join must never POST plan on RESUME'
Assert-True (-not (Test-ResumeMayCreatePlan $broken $null $null)) 'Broken domain channel requires an explicit new plan'
Assert-True (-not (Test-ResumeMayCreatePlan $workgroup ([pscustomobject]@{state='complete'}) $null)) 'Archived plan must be reconciled, not replaced'
Assert-True (-not (Test-ResumeMayCreatePlan $workgroup $null ([pscustomobject]@{state='ready'}))) 'Active plan must not be replaced'

$source=Get-Content (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -Raw
Assert-True (([regex]::Matches($source,[regex]::Escape('Write-UiLog (Run-RecoveryUntilStable)'))).Count -eq 2) 'Both GUI actions must use bounded auto continuation'
Write-Output 'AUTO RECOVERY TESTS OK: safe phases, no auto join/retry, user cancellation, bounded loops and task cleanup.'

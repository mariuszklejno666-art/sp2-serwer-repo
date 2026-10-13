$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

# Stuck machine_account_recovery (S11-15 -> S11-16, join already authorized):
# Windows is still a domain member, so the client repairs the EXISTING
# account's trust and asks the server to verify AD and close the plan.
# No join, unjoin, rename, AD write, DNS change or real server is touched.
function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
}
function New-Names([string]$Active,[string]$Pending) {
    return @{WindowsName=$Active; DnsHostName=$Active; SocketHostName=$Active; ProcessName=$Active
        ActiveName=$Active; PendingName=$Pending; TcpHostname=$Active; TcpNvHostname=$Pending}
}

# --- Pure helpers ----------------------------------------------------------
Assert-True ((Get-PendingRenameState (New-Names 'S11-15' 'S11-15') 'S11-15').state -eq 'ok') 'Consistent names'
$staged=Get-PendingRenameState (New-Names 'S11-15' 'S11-16') 'S11-15'
Assert-True ($staged.state -eq 'staged' -and $staged.pending -eq 'S11-16') 'Queued rename detected'
$broken=New-Names 'S11-15' 'S11-15'; $broken.TcpHostname='S11-16'
Assert-True ((Get-PendingRenameState $broken 'S11-15').state -eq 'inconsistent') 'Active mismatch is inconsistent'
Assert-True (Test-UnsyncedTimeSource 'Local CMOS Clock') 'CMOS is unsynced'
Assert-True (Test-UnsyncedTimeSource 'Free-running System Clock') 'Free-running is unsynced'
Assert-True (-not (Test-UnsyncedTimeSource 'szkolaak.sp2.lan')) 'Domain DC source kept'
Assert-True (-not (Test-UnsyncedTimeSource '192.168.0.143,0x8')) 'Manual school peer kept'

function Make-Plan([string]$State='manual_review',[string]$Action='rename_domain',[string[]]$Events=@('begin','credential_issued','failed')) {
    return [pscustomobject]@{
        id='22222222-2222-2222-2222-222222222222'; version=7; state=$State; action=$Action
        device_id='dev-1'; source_name='S11-15'; target_name='S11-16'
        target_ou='OU=Komputery,DC=sp2,DC=lan'
        history=@($Events | ForEach-Object { [pscustomobject]@{event=$_;action='machine_account_recovery'} })
    }
}
Assert-True (Test-PlanRecoveryAttempted (Make-Plan)) 'Authorized recovery counts as attempted'
Assert-True (-not (Test-PlanRecoveryAttempted (Make-Plan -Events @('observe')))) 'Untouched plan is not attempted'

# --- Mocks: every side effect is recorded, destructive cmdlets explode ------
$script:Calls=New-Object 'System.Collections.Generic.List[string]'
$script:Local=@{hostname='S11-15'; part_of_domain=$true; secure_channel=$false; domain='sp2.lan'; boot_id='b1'}
$script:Names=New-Names 'S11-15' 'S11-15'
$script:RepairWorks=$true
$script:Answers=@{}
$script:ServerMode='accept'
function Get-LocalState { return $script:Local }
function Read-WindowsNames { return $script:Names }
function Save-State { $script:Calls.Add('save') }
function Unregister-ScheduledTask { $script:Calls.Add('unregister') }
function Register-DnsClient { $script:Calls.Add('dns') }
function Start-Sleep { }
function Ensure-DomainMemberTime { $script:Calls.Add('time') }
function Write-Crash { }
function Restore-StagedComputerName([string]$Hostname) {
    $script:Calls.Add('restage:' + $Hostname); $script:Names=New-Names $Hostname $Hostname
}
function Get-DomainCredential {
    $script:Calls.Add('credential')
    $script:Credential=[pscredential]::new('Administrator@SP2.LAN',(ConvertTo-SecureString 'x' -AsPlainText -Force))
    return $script:Credential
}
function Test-ComputerSecureChannel([string]$Server,[switch]$Repair,$Credential) {
    Assert-True ($Server -eq 'szkolaak.sp2.lan') 'Repair must target the school DC'
    if ($Repair) {
        $script:Calls.Add('repair')
        if ($script:RepairWorks) { $script:Local.secure_channel=$true }
        return $script:RepairWorks
    }
    return [bool]$script:Local.secure_channel
}
function Set-Progress([string]$Event,[bool]$Approved=$false,[string]$Reason='') {
    Assert-True ($Event -eq 'resolve' -and $Approved) 'Only an approved resolve may be sent'
    $script:Calls.Add('resolve')
    if ($script:ServerMode -eq 'reject') {
        $script:LastHttpStatus=409
        $script:FailureMessage='Serwer nie potwierdzil lokalnej naprawy zaufania w AD. Plan i rezerwacja zachowane.'
        throw 'Mock server rejected resolve'
    }
    $script:State.plan.state='cancelled'
}
Add-Type -AssemblyName System.Windows.Forms
function Show-Box([string]$Title) {
    $script:Calls.Add('ask:' + $Title)
    if ($script:Answers.ContainsKey($Title)) { return $script:Answers[$Title] }
    return 'Yes'
}
# MessageBox is a static .NET call; route it through a script-scope shim.
function Reset([hashtable]$Local) {
    $script:Calls.Clear(); $script:Local=$Local; $script:Names=New-Names $Local.hostname $Local.hostname
    $script:RepairWorks=$true; $script:ServerMode='accept'; $script:Answers=@{}
    $script:State=@{device_id='dev-1'; plan=(Make-Plan); token='protected'}
}
foreach ($forbidden in @('Add-Computer','Remove-Computer','Rename-Computer','Reset-ComputerMachinePassword')) {
    Set-Item -Path ('function:' + $forbidden) -Value ([scriptblock]::Create("throw 'TEST FAILURE: $forbidden must never execute'"))
}
$boxes=Get-Command Invoke-LocalSecureChannelRepair, Assert-NoStagedRename, Resolve-StuckMachineRecovery
foreach ($cmd in $boxes) {
    $text=$cmd.ScriptBlock.ToString() -replace '\[Windows\.Forms\.MessageBox\]::Show\(([^,]+),([^,]+),[^)]+\)','(Show-Box $2)'
    Set-Item -Path ('function:' + $cmd.Name) -Value ([scriptblock]::Create($text))
}

# 1. S11-15 today: broken trust, authorized plan -> repair + server-verified close.
Reset @{hostname='S11-15'; part_of_domain=$true; secure_channel=$false; domain='sp2.lan'; boot_id='b1'}
$result=Resolve-StuckMachineRecovery $script:State.plan
Assert-True ($result -like 'GOTOWE:*') ('Expected GOTOWE, got: ' + $result)
Assert-True ($script:Calls.Contains('time') -and $script:Calls.Contains('repair') -and $script:Calls.Contains('resolve')) 'Time, repair, resolve'
Assert-True ($script:Calls.IndexOf('time') -lt $script:Calls.IndexOf('repair')) 'Time is fixed before repair'
Assert-True ($script:Calls.IndexOf('repair') -lt $script:Calls.IndexOf('resolve')) 'Resolve only after verified repair'
Assert-True ($script:Calls.Contains('unregister') -and $script:State.token -eq '') 'Resume task and token cleared'
Assert-True ($null -eq $script:Credential) 'Domain credential disposed'

# 2. Trust already repaired by hand: no credential prompt, only server close.
Reset @{hostname='S11-15'; part_of_domain=$true; secure_channel=$true; domain='sp2.lan'; boot_id='b1'}
$result=Resolve-StuckMachineRecovery $script:State.plan
Assert-True ($result -like 'GOTOWE:*') 'Healthy channel closes plan'
Assert-True (-not $script:Calls.Contains('credential') -and -not $script:Calls.Contains('repair')) 'No repair when healthy'

# 3. Queued rename to S11-16 is undone before anything else; refusal blocks.
Reset @{hostname='S11-15'; part_of_domain=$true; secure_channel=$true; domain='sp2.lan'; boot_id='b1'}
$script:Names=New-Names 'S11-15' 'S11-16'
$result=Resolve-StuckMachineRecovery $script:State.plan
Assert-True ($script:Calls.Contains('restage:S11-15') -and $result -like 'GOTOWE:*') 'Queued rename restored'
Reset @{hostname='S11-15'; part_of_domain=$true; secure_channel=$true; domain='sp2.lan'; boot_id='b1'}
$script:Names=New-Names 'S11-15' 'S11-16'
$script:Answers['SP2 - zaplanowana zmiana nazwy']='No'
$result=Resolve-StuckMachineRecovery $script:State.plan
Assert-True ($result -like 'ZATRZYMANO:*' -and -not $script:Calls.Contains('resolve')) 'Refused restore blocks everything'

# 4. Server veto keeps the plan; repaired trust is reported honestly.
Reset @{hostname='S11-15'; part_of_domain=$true; secure_channel=$false; domain='sp2.lan'; boot_id='b1'}
$script:ServerMode='reject'
$result=Resolve-StuckMachineRecovery $script:State.plan
Assert-True ($result -like 'Zaufanie naprawione, ale plan nie zostal zamkniety*') 'Server veto reported'
Assert-True ($script:State.plan.state -eq 'manual_review' -and -not $script:Calls.Contains('unregister')) 'Plan kept'

# 5. Not applicable: workgroup, renamed Windows, untouched plan, failed repair.
Reset @{hostname='S11-15'; part_of_domain=$false; secure_channel=$null; domain='WORKGROUP'; boot_id='b1'}
Assert-True ($null -eq (Resolve-StuckMachineRecovery $script:State.plan)) 'Workgroup falls back'
Reset @{hostname='S11-16'; part_of_domain=$true; secure_channel=$false; domain='sp2.lan'; boot_id='b1'}
Assert-True ($null -eq (Resolve-StuckMachineRecovery $script:State.plan)) 'Renamed Windows falls back'
Reset @{hostname='S11-15'; part_of_domain=$true; secure_channel=$false; domain='sp2.lan'; boot_id='b1'}
Assert-True ($null -eq (Resolve-StuckMachineRecovery (Make-Plan -Events @('observe')))) 'Untouched plan falls back'
Reset @{hostname='S11-15'; part_of_domain=$true; secure_channel=$false; domain='sp2.lan'; boot_id='b1'}
$script:RepairWorks=$false
Assert-True ($null -eq (Resolve-StuckMachineRecovery $script:State.plan)) 'Failed repair falls back'
Assert-True (-not $script:Calls.Contains('resolve')) 'Failed repair never reports resolve'
Reset @{hostname='S11-15'; part_of_domain=$true; secure_channel=$false; domain='sp2.lan'; boot_id='b1'}
$script:Answers['SP2 - naprawa zaufania domeny']='No'
Assert-True ($null -eq (Resolve-StuckMachineRecovery $script:State.plan)) 'Declined repair falls back'
Assert-True (-not $script:Calls.Contains('credential')) 'Declined repair asks no password'

Write-Output 'LOCAL CHANNEL RESOLVE UNIT TESTS OK; no join, unjoin, rename, AD, DNS or server writes.'

$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

function Assert-True([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Reset-Test {
    $script:Endpoint='https://admin.example.test'
    $script:AgentConfig=$null; $script:DeploymentConfig=$null
    $script:Cached=''; $script:Calls=@(); $script:BrowserCalls=0; $script:Saves=0
    $script:Mode='ok'; $script:LastHttpStatus=0; $script:FailureMessage=''; $script:Token=''
}
function Read-SavedToken { return $script:Cached }
function Save-Authentication { $script:Saves++ }
function Get-BrowserToken { $script:BrowserCalls++; return 'new-agent' }
function Identify-Device { return Invoke-Api 'status' $null 'GET' }
function Invoke-Api([string]$Path,$Data=$null,[string]$Method='POST') {
    $script:Calls+=@([pscustomobject]@{path=$Path;token=$script:Token})
    $script:LastHttpStatus=0
    if ($Path -eq 'capabilities') {
        if ($script:Mode -eq 'missing') { $script:LastHttpStatus=404; throw 'mock missing API' }
        if ($script:Mode -eq 'wrong-service') { return [pscustomobject]@{service='other';protocol=2;pairing=$true} }
        return [pscustomobject]@{service='sp2-admin-domain-repair';protocol=2;pairing=$true;hardware_identity=$true}
    }
    if ($script:Mode -eq 'tls-failure') { throw 'mock certificate failure' }
    if ($Path -eq 'enroll') {
        if ($script:Mode -eq 'expired') { $script:LastHttpStatus=401; throw 'mock expired enrollment' }
        if ($script:Mode -eq 'registered') { $script:LastHttpStatus=409; throw 'mock existing agent' }
        return [pscustomobject]@{token='issued-agent'}
    }
    if ($Path -eq 'status') {
        if ($script:Token -eq 'stale-agent') { $script:LastHttpStatus=401; throw 'mock stale agent' }
        return [pscustomobject]@{plan=$null}
    }
    throw 'Unexpected API operation in authentication test'
}

Reset-Test
$script:Mode='missing'; $script:Token='never-send'
$failed=$false
try { Assert-ServerCapabilities } catch { $failed=$true }
Assert-True $failed 'Missing backend must stop before authentication'
Assert-True ($script:FailureMessage -match 'PR #52') 'Missing backend needs an actionable message'
Assert-True ($script:Calls[0].token -eq '' -and $script:BrowserCalls -eq 0) 'Discovery must not send a token or open a browser'

Reset-Test
$script:Mode='wrong-service'; $failed=$false
try { Assert-ServerCapabilities } catch { $failed=$true }
Assert-True $failed 'Reject incompatible API'

Reset-Test
$script:AgentConfig=[pscustomobject]@{server_url=$script:Endpoint;token='valid-agent'}
[void](Resolve-Authentication '' $false)
Assert-True ($script:BrowserCalls -eq 0 -and $script:Token -eq 'valid-agent') 'Reuse installed agent token automatically'

Reset-Test
$script:AgentConfig=[pscustomobject]@{server_url=$script:Endpoint;token='stale-agent'}
[void](Resolve-Authentication '' $false)
Assert-True ($script:BrowserCalls -eq 1 -and $script:Token -eq 'new-agent' -and $script:Saves -eq 1) 'Stale token must recover through one browser approval'

Reset-Test
$script:Cached='cached-agent'
[void](Resolve-Authentication '' $false)
Assert-True ($script:BrowserCalls -eq 0 -and $script:Token -eq 'cached-agent') 'Reuse protected cached authorization'

foreach ($caseMode in @('expired','registered')) {
    Reset-Test
    $script:Mode=$caseMode
    $script:DeploymentConfig=[pscustomobject]@{server_url=$script:Endpoint;enrollment_code='expired-code'}
    [void](Resolve-Authentication '' $false)
    Assert-True ($script:BrowserCalls -eq 1 -and $script:Token -eq 'new-agent') 'Enrollment failure must fall back to browser approval'
}

Reset-Test
$script:AgentConfig=[pscustomobject]@{server_url='https://different.example.test';token='never-send'}
[void](Resolve-Authentication '' $false)
Assert-True ($script:BrowserCalls -eq 1 -and $script:Calls[0].token -eq 'new-agent') 'Do not transmit a token configured for another server'

Reset-Test
$script:Mode='tls-failure'; $failed=$false
try { [void](Resolve-Authentication 'valid-agent' $false) } catch { $failed=$true }
Assert-True ($failed -and $script:BrowserCalls -eq 0) 'Do not turn transport errors into token rotation'
Write-Output 'AUTHENTICATION TESTS OK: missing API, incompatible API, agent reuse, stale token, cached token, enrollment 401/409, server isolation, transport failure.'

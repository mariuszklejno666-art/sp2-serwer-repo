$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

# All trust-store writes are mocked. This test does not alter Root, DNS or AD.
function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
}
$script:ProductionPin=$script:SchoolCaSha256
$script:FixturePin='e6d7e1f97422f0dc44280df81769b110f5c02b254a39abf12812cc377058e615'
$script:Fixture=Join-Path $PSScriptRoot 'test-fixtures\ca-test-only.crt'
Assert-True (Test-Path -LiteralPath $script:Fixture) 'Missing public test fixture'

# Exercise the real X.509 parser and DER fingerprint checks first.
$actual=Get-CertificateDerSha256 ([Text.Encoding]::ASCII.GetBytes('abc'))
Assert-True ($actual -eq 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') 'SHA-256 raw hashing failed'
$script:SchoolCaSha256=$script:FixturePin
Assert-PinnedSchoolCaCertificate $script:Fixture
$script:SchoolCaSha256=$script:ProductionPin
$blocked=$false
try { Assert-PinnedSchoolCaCertificate $script:Fixture } catch { $blocked=$true }
Assert-True $blocked 'Different CA fingerprint must never be accepted'

# Mock trust store and approval, never import a certificate during CI.
$script:Endpoint='https://dc.sp2.lan'
$script:SchoolCaSha256=$script:FixturePin
$script:MockFile=$script:Fixture
$script:MockTrusted=$false
$script:MockApproved=$true
$script:PromptCount=0
$script:ImportCount=0
function Get-SchoolCaFilePath { return $script:MockFile }
function Test-PinnedSchoolCaTrusted { return [bool]$script:MockTrusted }
function Confirm-SchoolCaTrust {
    $script:PromptCount++
    return [bool]$script:MockApproved
}
function Import-Certificate {
    [CmdletBinding()]
    param([string]$FilePath,[string]$CertStoreLocation)
    Assert-True ($FilePath -eq $script:Fixture) 'Only verified CA fixture can be imported'
    Assert-True ($CertStoreLocation -eq 'Cert:\LocalMachine\Root') 'System Root location required'
    $script:ImportCount++
    $script:MockTrusted=$true
    return [pscustomobject]@{ Thumbprint = 'MOCK' }
}

Ensure-SchoolCaTrust
Assert-True ($script:ImportCount -eq 1) 'One explicit approved import is required'
Assert-True ($script:PromptCount -eq 1) 'One approval must be displayed'
Ensure-SchoolCaTrust
Assert-True ($script:ImportCount -eq 1 -and $script:PromptCount -eq 1) 'Trusted CA must not be imported again'

$script:Endpoint='https://example.invalid'
$script:MockTrusted=$false
Ensure-SchoolCaTrust
Assert-True ($script:ImportCount -eq 1) 'Custom endpoint must never install school CA'
$script:Endpoint='https://dc.sp2.lan:8443'
Ensure-SchoolCaTrust
Assert-True ($script:ImportCount -eq 1) 'Nonstandard port must never install CA'

$script:Endpoint='https://dc.sp2.lan'
$script:MockApproved=$false
$blocked=$false
try { Ensure-SchoolCaTrust } catch { $blocked=$true }
Assert-True $blocked 'Approval rejection must block installation'
Assert-True ($script:ImportCount -eq 1) 'Refusal must not import'

$script:MockApproved=$true
$script:MockFile=Join-Path $PSScriptRoot 'test-fixtures\does-not-exist.crt'
$blocked=$false
try { Ensure-SchoolCaTrust } catch { $blocked=$true }
Assert-True ($blocked -and $script:FailureMessage -match 'Brak pliku') 'Missing CA must explain packaging'
Assert-True ($script:ImportCount -eq 1) 'Missing CA cannot import anything'

$script:MockTrusted=$true
Ensure-SchoolCaTrust
Assert-True ($script:ImportCount -eq 1) 'Existing trusted CA needs no companion file'

$script:MockTrusted=$false
$script:MockFile=$script:Fixture
$script:SchoolCaSha256=$script:ProductionPin
$blocked=$false
try { Ensure-SchoolCaTrust } catch { $blocked=$true }
Assert-True $blocked 'Tampered/foreign CA must be rejected'
Assert-True ($script:ImportCount -eq 1) 'Wrong CA never enters Root'
Write-Output 'SCHOOL CA UNIT TESTS OK: real DER pin, approval, idempotence, offline, no store writes.'

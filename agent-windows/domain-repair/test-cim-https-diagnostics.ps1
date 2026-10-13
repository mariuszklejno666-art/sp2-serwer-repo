$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly
function Assert-True([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }

# All probes are mocks. Never contact real CIM, HTTPS, AD or the Windows join API.
$script:Output=@()
function Write-UiLog([string]$Message) { $script:Output+= $Message }
function Get-CimInstance {
    param([string]$ClassName)
    if ($ClassName -eq 'Win32_ComputerSystem') {
        throw [System.InvalidOperationException]::new('Simulated private content not for logging')
    }
    return [pscustomobject]@{Name='TEST'}
}
$script:FailureMessage=''
$failed=$false
try { Read-RequiredCimClass 'Win32_ComputerSystem' | Out-Null } catch { $failed=$true }
Assert-True $failed 'Fail closed when required Windows CIM class fails'
Assert-True ($script:FailureMessage -match 'Win32_ComputerSystem') 'Operator must see failed class'
Assert-True ($script:FailureMessage -notmatch 'private content') 'Exception messages must not leak'
Assert-True (@($script:Output | Where-Object { $_ -match 'Win32_ComputerSystem' }).Count -eq 1) 'One safe CIM UI warning'

$script:Output=@()
$script:Endpoint='https://dc.sp2.lan'
$script:Token=''
function Invoke-WebRequest {
    throw [Net.WebException]::new('Synthetic transport failure without secrets',[Net.WebExceptionStatus]::NameResolutionFailure)
}
$failed=$false
try { Invoke-Api 'capabilities' $null 'GET' | Out-Null } catch { $failed=$true }
Assert-True $failed 'API transport exception must not be ignored'
Assert-True ($script:FailureMessage -match 'DNS / NRPT') 'DNS category must be visible'
Assert-True ($script:LastHttpStatus -eq 0) 'No fake HTTP status on transport error'
Assert-True (@($script:Output | Where-Object { $_ -match 'DNS / NRPT' }).Count -eq 1) 'Only sanitized transport diagnostics shown'
Write-Output 'CIM/HTTPS DIAGNOSTIC UNIT TESTS OK; no CIM, network, AD, join, or restart.'

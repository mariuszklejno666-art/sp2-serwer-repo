$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -LibraryOnly

# Mock all DNS/NRPT operations: no real network calls or system policy changes.
function Assert-True([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
$script:Endpoint='https://dc.sp2.lan'
$script:DomainDnsServer='192.168.0.143'
$script:NormalAvailable=$false
$script:DirectAvailable=$true
$script:NrptWorks=$true
$script:RuleInstalled=$false
$script:AddedCount=0
$script:RemovedCount=0
$script:ExistingRules=@()
$script:EffectiveRules=@()

function Resolve-DnsName {
    [CmdletBinding()]
    param([string]$Name,[string]$Type,[switch]$DnsOnly,[string]$Server)
    if ($Name -ne 'dc.sp2.lan' -or $Type -ne 'A') { throw 'Unexpected query' }
    if ($Server) {
        if ($Server -ne '192.168.0.143' -or -not $script:DirectAvailable) { throw 'DNS unreachable' }
    } elseif (-not $script:NormalAvailable -and
              -not ($script:RuleInstalled -and $script:NrptWorks)) {
        throw 'Normal resolver returns NXDOMAIN'
    }
    return [pscustomobject]@{ Type='A'; IPAddress='192.168.0.143' }
}
function Get-DnsClientNrptRule {
    [CmdletBinding()]
    param()
    foreach ($rule in $script:ExistingRules) { Write-Output $rule }
}
function Get-DnsClientNrptPolicy {
    [CmdletBinding()]
    param([switch]$Effective)
    foreach ($rule in $script:EffectiveRules) { Write-Output $rule }
}
function Add-DnsClientNrptRule {
    [CmdletBinding()]
    param([string[]]$Namespace,[string[]]$NameServers,
          [string]$DisplayName,[string]$Comment,[switch]$PassThru)
    Assert-True ($Namespace -contains '.sp2.lan') 'Domain child-name coverage required'
    Assert-True ($Namespace -contains 'sp2.lan') 'Root-domain coverage required'
    Assert-True ($NameServers -contains '192.168.0.143') 'School DNS required'
    $script:AddedCount++
    $script:RuleInstalled=$true
    return [pscustomobject]@{Name='SP2-TEST-NRPT';Namespace=$Namespace;NameServers=$NameServers}
}
function Remove-DnsClientNrptRule {
    [CmdletBinding()]
    param([string]$Name,[switch]$Force)
    Assert-True ($Name -eq 'SP2-TEST-NRPT') 'Must remove only the new rule'
    $script:RemovedCount++
    $script:RuleInstalled=$false
}
function Clear-DnsClientCache { [CmdletBinding()] param() }
function Set-DnsClientServerAddress { throw 'Adapter DNS must not be changed by NRPT preflight' }

# Expected success: primary DNS returns NXDOMAIN, direct school DNS is healthy.
Ensure-SchoolDomainDnsRoute
Assert-True ($script:AddedCount -eq 1) 'Scoped NRPT must be added once'
Assert-True $script:RuleInstalled 'Rule must remain on success'
Ensure-SchoolDomainDnsRoute
Assert-True ($script:AddedCount -eq 1) 'Second pass must be idempotent'

# A non-school endpoint must not change DNS routing.
$script:Endpoint='https://other.example.org'
$script:RuleInstalled=$false
Ensure-SchoolDomainDnsRoute
Assert-True ($script:AddedCount -eq 1) 'Custom endpoint must be untouched'

# If school DNS is unreachable, do not install the rule.
$script:Endpoint='https://dc.sp2.lan'
$script:DirectAvailable=$false
$blocked=$false
try { Ensure-SchoolDomainDnsRoute } catch { $blocked=$true }
Assert-True $blocked 'Unreachable school DNS must fail closed'
Assert-True ($script:AddedCount -eq 1) 'No rule for unreachable school DNS'
$script:DirectAvailable=$true

# Never override an existing rule (VPN/administrator/GPO).
$script:ExistingRules=@([pscustomobject]@{Namespace=@('.sp2.lan');NameServers=@('192.0.2.77')})
$blocked=$false
try { Ensure-SchoolDomainDnsRoute } catch { $blocked=$true }
Assert-True $blocked 'Conflicting NRPT rule must block changes'
Assert-True ($script:AddedCount -eq 1) 'Existing rule must never be overwritten'
$script:ExistingRules=@()

# Roll back only the newly-created rule if Windows still cannot resolve.
$script:NrptWorks=$false
$blocked=$false
try { Ensure-SchoolDomainDnsRoute } catch { $blocked=$true }
Assert-True $blocked 'Unusable NRPT must fail closed'
Assert-True ($script:AddedCount -eq 2) 'Rollback test must create one new rule'
Assert-True ($script:RemovedCount -eq 1) 'Rollback must remove the newly added rule'
Assert-True (-not $script:RuleInstalled) 'Rollback must leave no new rule'
Write-Output 'DOMAIN DNS UNIT TESTS OK; no actual DNS, NRPT, AD or network changes.'

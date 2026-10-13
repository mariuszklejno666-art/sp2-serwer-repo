param([switch]$SelfTest, [switch]$Resume, [switch]$LibraryOnly)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security
$script:Root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SP2-Domain-Recovery'
$script:StatePath = Join-Path $script:Root 'pending.json'
$script:State = $null
$script:Token = ''
$script:Credential = $null
$script:Endpoint = ''
$script:AgentConfig = $null
$script:DeploymentConfig = $null
$script:LastApiStatus = ''
$script:LastHttpStatus = 0
$script:LastApiErrorCode = ''
$script:FailureMessage = ''
$script:LogControl = $null
$script:IdentityProfile = $null
$script:DomainDnsServer = '192.168.0.143'
$script:DefaultEndpoint = 'https://dc.sp2.lan'
$script:DomainControllerFqdn = 'szkolaak.sp2.lan'
# SHA-256 of the DER encoded, public SP2 root CA (confirmed on 2026-10-09).
$script:SchoolCaSha256 = '45581ba7ef494ddce73702c8f7f4174a5f8309ddf342f12b78c7a097f2bbcd33'
$script:EntraModulePath = Join-Path $PSScriptRoot 'SP2-Entra-Transition.ps1'
if (Test-Path -LiteralPath $script:EntraModulePath) { . $script:EntraModulePath }

function Write-UiLog([string]$Message) {
    if ($null -ne $script:LogControl) {
        $script:LogControl.AppendText(('[' + (Get-Date -Format 'HH:mm:ss') + '] ' + $Message + [Environment]::NewLine))
        $script:LogControl.SelectionStart=$script:LogControl.TextLength
        $script:LogControl.ScrollToCaret()
        $script:LogControl.Refresh()
    }
}

function Get-ConfigText($Config, [string]$Name) {
    if ($null -ne $Config -and $Config.PSObject.Properties[$Name]) { return [string]$Config.$Name }
    return ''
}

function Resolve-ServerEndpoint {
    # Never derive the API URL from the DNS server IP. Prefer an explicit
    # HTTPS URL shipped with the agent/package; otherwise use the school
    # SP2 ADMIN HTTPS hostname.
    foreach ($config in @($script:AgentConfig,$script:DeploymentConfig)) {
        $candidate=(Get-ConfigText $config 'server_url').Trim().TrimEnd('/')
        if ($candidate) {
            try {
                $uri=[Uri]$candidate
                if ($uri.Scheme -eq 'https' -and -not $uri.UserInfo) { return $candidate }
            } catch { }
        }
    }
    return $script:DefaultEndpoint
}


function Get-SchoolCaFilePath {
    return (Join-Path $PSScriptRoot 'sp2-internal-ca.crt')
}

function Get-CertificateDerSha256([byte[]]$RawData) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($RawData))).Replace('-','').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Assert-PinnedSchoolCaCertificate([string]$Path) {
    # A pinned DER fingerprint prevents an altered CA file from expanding
    # Windows machine-wide trust, regardless of where the package came from.
    $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
    try {
        $digest=Get-CertificateDerSha256 $cert.RawData
        if ($digest -cne $script:SchoolCaSha256) {
            throw 'CERT SP2: niezgodny SHA-256 szkolnego certyfikatu CA. Nie zainstalowano.'
        }
        if ($cert.Subject -cne 'CN=SP2 ADMIN Internal CA' -or $cert.Issuer -cne $cert.Subject) {
            throw 'CERT SP2: to nie jest oczekiwany glowny certyfikat CA.'
        }
        $basic=@($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
        if ($basic.Count -ne 1) { throw 'CERT SP2: brak ograniczen CA.' }
        $decoded=[Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
            $basic[0], $basic[0].Critical)
        if (-not $decoded.CertificateAuthority) { throw 'CERT SP2: certyfikat nie ma uprawnien CA.' }
        $keyUsage=@($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
        if ($keyUsage.Count -gt 0) {
            $usage=[Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                $keyUsage[0], $keyUsage[0].Critical)
            if (($usage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign) -eq 0) {
                throw 'CERT SP2: brak uprawnienia KeyCertSign.'
            }
        }
        if ($cert.NotBefore -gt [DateTime]::Now -or $cert.NotAfter -lt [DateTime]::Now) {
            throw 'CERT SP2: certyfikat CA jest poza okresem waznosci.'
        }
    } finally {
        $cert.Dispose()
    }
}

function Test-PinnedSchoolCaTrusted {
    foreach ($cert in @(Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop)) {
        if ((Get-CertificateDerSha256 $cert.RawData) -ceq $script:SchoolCaSha256) {
            return $true
        }
    }
    return $false
}

function Confirm-SchoolCaTrust {
    $message='SP2 Serwis Domeny wymaga zaufania do szkolnego urzedu certyfikacji.' +
        [Environment]::NewLine +
        'CN=SP2 ADMIN Internal CA' + [Environment]::NewLine +
        'SHA-256: 45581BA7EF494DDCE73702C8F7F4174A5F8309DDF342F12B78C7A097F2BBCD33' +
        [Environment]::NewLine + [Environment]::NewLine +
        'Dodanie CA do magazynu LocalMachine/Root umozliwia mu wydawanie zaufanych certyfikatow na tym komputerze.' +
        [Environment]::NewLine + 'Czy zatwierdzasz instalacje zweryfikowanego CA SP2?'
    return ([Windows.Forms.MessageBox]::Show($message,
        'SP2 ADMIN - zaufanie do szkolnego CA', 'YesNo', 'Warning') -eq 'Yes')
}

function Ensure-SchoolCaTrust {
    # Trust bootstrap is restricted to the known production SP2 hostname.
    # Test/custom endpoints continue using the normal Windows trust store.
    if (-not $script:Endpoint) { return }
    $endpoint=[Uri]$script:Endpoint
    if ($endpoint.Scheme -ne 'https' -or $endpoint.DnsSafeHost -ine 'dc.sp2.lan' -or
        $endpoint.Port -ne 443 -or $endpoint.UserInfo) { return }

    $path=Get-SchoolCaFilePath
    $hasFile=Test-Path -LiteralPath $path -PathType Leaf
    if ($hasFile) {
        try { Assert-PinnedSchoolCaCertificate $path }
        catch {
            $script:FailureMessage='CERT SP2: plik szkolnego CA nie zgadza sie z zaufanym odciskiem SHA-256. Nie zainstalowano zadnego certyfikatu.'
            throw
        }
    }
    if (Test-PinnedSchoolCaTrusted) { return }
    if (-not $hasFile) {
        $script:FailureMessage='CERT SP2: Windows nie ufa szkolnemu CA. Brak pliku sp2-internal-ca.crt obok programu. Pobierz pelny pakiet przygotowany na serwerze SP2; nie wylaczaj HTTPS.'
        throw $script:FailureMessage
    }
    if (-not (Confirm-SchoolCaTrust)) {
        $script:FailureMessage='CERT SP2: operator nie zatwierdzil instalacji zaufanego CA. Bez tego HTTPS pozostaje zablokowany.'
        throw $script:FailureMessage
    }
    try {
        Import-Certificate -FilePath $path -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop | Out-Null
        if (-not (Test-PinnedSchoolCaTrusted)) {
            throw 'Nie potwierdzono instalacji certyfikatu w magazynie Windows.'
        }
    } catch {
        $script:FailureMessage='CERT SP2: instalacja szkolnego CA nie powiodla sie. Sprawdz uprawnienia administratora i magazyn certyfikatow Windows.'
        throw
    }
    Write-UiLog 'CERT SP2: szkolny certyfikat CA zweryfikowany SHA-256 i zainstalowany. Weryfikacja HTTPS pozostaje wlaczona.'
}

function Assert-ServerCapabilities {
    $script:Token=''
    try { Ensure-SchoolDomainDnsRoute }
    catch {
        $script:FailureMessage='DNS SP2: nie potwierdzono odpowiedzi dc.sp2.lan przez 192.168.0.143. Sprawdz siec, VLAN i reguly DNS/NRPT. Nie wylaczaj HTTPS.'
        throw
    }
    Ensure-SchoolCaTrust
    try { $capabilities=Invoke-Api 'capabilities' $null 'GET' }
    catch {
        if ($script:LastHttpStatus -in @(404,405)) {
            $script:FailureMessage='Ten adres nie udostepnia SP2 Serwis Domeny 2.0. Na serwerze brakuje API z PR #52 albo adres prowadzi do kontrolera domeny zamiast SP2 ADMIN. Wpisywanie tokenu tego nie naprawi.'
        } elseif ($script:LastHttpStatus -in @(301,302,307,308)) {
            $script:FailureMessage='API przekierowuje na inny adres. Ustaw bezposredni adres HTTPS panelu SP2 ADMIN; token nie zostal wyslany.'
        } elseif (-not $script:FailureMessage) {
            $script:FailureMessage='Serwer nie odpowiedzial zgodnym API SP2 ADMIN. Sprawdz adres panelu i wdrozenie PR #52; token nie zostal wyslany.'
        }
        throw
    }
    if ((Get-ConfigText $capabilities 'service') -ne 'sp2-admin-domain-repair' -or (Get-ConfigText $capabilities 'protocol') -ne '2' -or $capabilities.pairing -ne $true) {
        $script:FailureMessage='Pod tym adresem nie ma zgodnego API SP2 ADMIN do automatycznej autoryzacji. Sprawdz adres panelu i wdrozenie PR #52.'
        throw $script:FailureMessage
    }
    if (-not $capabilities.PSObject.Properties['hardware_identity'] -or $capabilities.hardware_identity -ne $true) {
        $script:FailureMessage='Serwer wymaga aktualizacji identyfikacji sprzetowej. Nie bedzie przejmowany plan innego komputera.'
        throw $script:FailureMessage
    }
}

function Read-RequiredCimClass([string]$ClassName) {
    # Hardware identity and domain membership must never be guessed on CIM failure.
    try {
        $data=Get-CimInstance -ClassName $ClassName -ErrorAction Stop
        if ($null -eq $data) { throw [InvalidOperationException]::new('Brak danych CIM.') }
        return $data
    } catch {
        $script:FailureMessage='CIM Windows: nie mozna odczytac ' + $ClassName + '. Sprawdz usluge Winmgmt i repozytorium WMI; nie rozpoczeto operacji domenowej.'
        Write-UiLog $script:FailureMessage
        throw
    }
}

function Get-HardwareIdentity {
    $uuid=[string](Read-RequiredCimClass 'Win32_ComputerSystemProduct').UUID
    $macs=@(Read-RequiredCimClass 'Win32_NetworkAdapter' | Where-Object { $_.PhysicalAdapter -and $_.MACAddress } | ForEach-Object { [string]$_.MACAddress } | Sort-Object -Unique)
    return @{uuid=$uuid;mac_addresses=$macs}
}

function Identify-Device {
    $result=Invoke-Api 'identify' @{device_id=(Get-DeviceId);hostname=$env:COMPUTERNAME;hardware=(Get-HardwareIdentity)}
    $canonical=([Guid]$result.device_id).ToString()
    [IO.File]::WriteAllText((Join-Path $script:Root 'device-id.txt'),$canonical)
    $script:IdentityProfile=$result
    Write-UiLog ('Rozpoznano urzadzenie: Windows=' + $result.observed_name + '; rekord=' + $result.registered_name + '; UUID=' + $canonical + '; OU=' + $result.ou)
    return $result
}

function Save-Authentication {
    $auth=@{endpoint=$script:Endpoint;device_id=(Get-DeviceId);token=(Protect-AgentToken $script:Token)}
    $path=Join-Path $script:Root 'auth.json'
    $temp=$path+'.tmp'
    [IO.File]::WriteAllText($temp,($auth | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $path) {
        try { [IO.File]::Replace($temp,$path,$null) }
        catch { Move-Item -LiteralPath $temp -Destination $path -Force }
    } else { [IO.File]::Move($temp,$path) }
}

function Read-SavedToken {
    $path=Join-Path $script:Root 'auth.json'
    if (Test-Path -LiteralPath $path) {
        try {
            $auth=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            if ($auth.endpoint -ceq $script:Endpoint -and $auth.device_id -eq (Get-DeviceId)) { return Unprotect-AgentToken $auth.token }
        } catch { }
    }
    return ''
}

function Resolve-Authentication([string]$ManualToken, [bool]$Enrollment) {
    $script:Token=$ManualToken
    if (-not $script:Token) { $script:Token=Read-SavedToken; $Enrollment=$false }
    if (-not $script:Token -and $null -ne $script:AgentConfig) {
        if ((Get-ConfigText $script:AgentConfig 'server_url').TrimEnd('/') -ceq $script:Endpoint) { $script:Token=Get-ConfigText $script:AgentConfig 'token' }
    }
    if (-not $script:Token -and $null -ne $script:DeploymentConfig) {
        if ((Get-ConfigText $script:DeploymentConfig 'server_url').TrimEnd('/') -ceq $script:Endpoint) {
            $script:Token=Get-ConfigText $script:DeploymentConfig 'enrollment_token'
            if (-not $script:Token) { $script:Token=Get-ConfigText $script:DeploymentConfig 'enrollment_code' }
            $Enrollment=[bool]$script:Token
        }
    }
    if ($script:Token) {
        try {
            if ($Enrollment) { $script:Token=''; throw 'Wymagane parowanie sprzetowe.' }
            $pending=Identify-Device
            Save-Authentication
            return $pending
        } catch {
            # Expired/shared agent tokens and expired/already-used enrollment
            # credentials fall back to the existing administrator approval flow.
            if (-not $Enrollment -and $script:LastHttpStatus -notin @(401,403)) { throw }
        }
    }
    $script:Token=''
    $script:Token=Get-BrowserToken
    $identified=Identify-Device
    Save-Authentication
    return $identified
}

function Protect-AgentToken([string]$Token) {
    $bytes=[Text.Encoding]::UTF8.GetBytes($Token)
    try { return [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)) }
    finally { [Array]::Clear($bytes,0,$bytes.Length) }
}

function Unprotect-AgentToken([string]$Token) {
    $bytes=[Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($Token),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    try { return [Text.Encoding]::UTF8.GetString($bytes) }
    finally { [Array]::Clear($bytes,0,$bytes.Length) }
}

function Read-DeploymentConfig {
    $path=Join-Path $PSScriptRoot 'deployment.json'
    if (Test-Path -LiteralPath $path) {
        $config=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ((Get-ConfigText $config 'server_url') -and ((Get-ConfigText $config 'enrollment_token') -or (Get-ConfigText $config 'enrollment_code'))) { return $config }
    }
    return $null
}

function Get-LocalAdministratorMembership([Microsoft.PowerShell.Commands.LocalUser]$User) {
    $adminSid='S-1-5-32-544'
    $group=Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='$adminSid'" -ErrorAction Stop
    $query="ASSOCIATORS OF {Win32_Group.Domain='$($group.Domain)',Name='$($group.Name)'} WHERE AssocClass=Win32_GroupUser Role=GroupComponent"
    $members=@(Get-CimInstance -Query $query -ErrorAction Stop)
    return @($members | Where-Object {
        $_.LocalAccount -eq $true -and $_.Domain -ieq $env:COMPUTERNAME -and $_.SID -eq [string]$User.SID
    }).Count -gt 0
}

function Ensure-LocalAdministrator {
    $user=Get-LocalUser -Name 'SP2' -ErrorAction SilentlyContinue
    if ($null -ne $user -and $user.Enabled -and (Get-LocalAdministratorMembership $user)) { return }
    $localCredential=Get-Credential -UserName ($env:COMPUTERNAME + '\\SP2') -Message 'Podaj wczesniej ustalone haslo lokalnego administratora SP2. Haslo nie zostanie zapisane w pliku.'
    if ($null -eq $localCredential -or $localCredential.Password.Length -lt 1) { throw 'Wymagane haslo lokalnego konta SP2.' }
    try {
        if ($null -eq $user) {
            $user=New-LocalUser -Name 'SP2' -Password $localCredential.Password -Description 'Lokalny administrator odzyskiwania SP2' -ErrorAction Stop
        } else {
            Set-LocalUser -Name 'SP2' -Password $localCredential.Password -ErrorAction Stop
            Enable-LocalUser -Name 'SP2' -ErrorAction Stop
        }
        if (-not (Get-LocalAdministratorMembership $user)) {
            $admins=Get-LocalGroup -SID 'S-1-5-32-544'
            Add-LocalGroupMember -Group $admins -Member $user -ErrorAction Stop
        }
    } finally { $localCredential.Password.Dispose(); $localCredential=$null }
}

function Read-AgentConfig {
    $path = Join-Path $env:ProgramFiles 'SP2 Agent\agent-config.json'
    if (Test-Path -LiteralPath $path) {
        $config = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ((Get-ConfigText $config 'server_url') -and (Get-ConfigText $config 'token')) { return $config }
    }
    return $null
}

function Get-BrowserToken {
    $device=Get-DeviceId
    $pair=Invoke-Api 'pair' @{hostname=$env:COMPUTERNAME;device_id=$device;hardware=(Get-HardwareIdentity)}
    $expected='/agents/domain-repair/approve/' + ([Guid]$pair.id).ToString()
    if ($pair.approval_path -ne $expected) { throw 'Nieprawidlowy adres zatwierdzenia.' }
    Start-Process ($script:Endpoint + $expected)
    Write-UiLog 'Zatwierdz urzadzenie w otwartej przegladarce. Program sam wykryje zatwierdzenie.'
    $deadline=[DateTime]::UtcNow.AddMinutes(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $result=Invoke-Api ('pair/' + $pair.id + '/claim') @{claim_secret=$pair.claim_secret}
            Write-UiLog 'Urzadzenie zatwierdzone. Autoryzacja pobrana.'
            return [string]$result.token
        } catch {
            if ($script:LastHttpStatus -eq 409) {
                [Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 1200
                continue
            }
            if ($script:LastHttpStatus -eq 410) { throw 'Autoryzacja wygasla. Rozpocznij ponownie.' }
            throw
        }
    }
    throw 'Uplynal czas oczekiwania na zatwierdzenie urzadzenia.'
}

function Get-TargetName([string]$Kind, [string]$Building, [int]$Room, [int]$Number) {
    if ($Room -lt 1 -or $Room -gt 999 -or $Number -lt 0 -or $Number -gt 99) { throw 'Nieprawidlowy numer sali lub komputera.' }
    if ($Kind -eq 'Nauczyciel') {
        if ($Building -notin @('BR','PL')) { throw 'Wybierz BR lub PL.' }
        $name = '{0}-S{1:00}' -f $Building,$Room
        if ($Number -gt 0) { $name += '-{0:00}' -f $Number }
        return $name
    }
    if ($Number -lt 1) { throw 'Numer ucznia musi wynosic 1-99.' }
    return 'S{0:00}-{1:00}' -f $Room,$Number
}

function Initialize-Storage {
    [IO.Directory]::CreateDirectory($script:Root) | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $script:Root -AclObject $acl
}

function Save-State {
    $temp = $script:StatePath + '.tmp'
    $json = $script:State | ConvertTo-Json -Depth 12
    [IO.File]::WriteAllText($temp, $json, [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $script:StatePath) {
        [IO.File]::Replace($temp, $script:StatePath, ($script:StatePath + ".bak"))
    } else { [IO.File]::Move($temp, $script:StatePath) }
}

function Write-Crash([string]$Code, $ErrorRecord) {
    # Never log exception messages, HTTP bodies, credentials or command arguments.
    $lineNumber=0
    if ($null -ne $ErrorRecord.InvocationInfo) { $lineNumber=$ErrorRecord.InvocationInfo.ScriptLineNumber }
    $line = '{0} code={1} type={2} line={3}' -f [DateTime]::UtcNow.ToString('o'),$Code,$ErrorRecord.Exception.GetType().Name,$lineNumber
    $errorId = 'OTHER'
    foreach ($known in @('CannotFindMachineAccount','CannotRepairSecureChannel','UnauthorizedAccess','WebCmdletWebResponseException','NameResolutionFailure','TrustFailure')) {
        if ([string]$ErrorRecord.FullyQualifiedErrorId -like ($known + '*')) { $errorId=$known; break }
    }
    $line += ' error_id=' + $errorId + ' http=' + $script:LastHttpStatus
    Write-UiLog ('BLAD: etap=' + $Code + '; typ=' + $ErrorRecord.Exception.GetType().Name + '; linia=' + $lineNumber + '; HTTP=' + $script:LastHttpStatus)
    Add-Content -LiteralPath (Join-Path $script:Root 'crash.log') -Value $line -Encoding UTF8
}

function Invoke-Api([string]$Path, $Data = $null, [string]$Method = 'POST') {
    $script:LastApiStatus = ''
    $script:LastHttpStatus = 0
    $script:LastApiErrorCode = ''
    $script:FailureMessage = ''
    $uri = [Uri]($script:Endpoint + '/api/v1/agent/domain-repair/' + $Path)
    if ($uri.Scheme -ne 'https' -or $uri.UserInfo) { throw 'Wymagany HTTPS z poprawnym certyfikatem.' }
    $parameters = @{ Uri=$uri; Method=$Method; Headers=@{}; TimeoutSec=30; MaximumRedirection=0; UseBasicParsing=$true }
    if ($script:Token) { $parameters.Headers.Authorization='Bearer ' + $script:Token }
    if ($null -ne $Data) { $parameters.Body = ($Data | ConvertTo-Json -Depth 8 -Compress); $parameters.ContentType='application/json; charset=utf-8' }
    Write-UiLog ('API: ' + $Method + ' ' + $Path)
    try { $response = Invoke-WebRequest @parameters; Write-UiLog ('API OK: HTTP ' + [int]$response.StatusCode) }
    catch {
        if ($null -ne $_.Exception.Response) {
            $script:LastHttpStatus=[int]$_.Exception.Response.StatusCode
            $script:LastApiStatus='HTTP ' + [int]$_.Exception.Response.StatusCode
            try {
                $reader=New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
                try { $buffer=New-Object char[] 8192; $count=$reader.Read($buffer,0,$buffer.Length); $failure=(-join $buffer[0..($count-1)]) | ConvertFrom-Json } finally { $reader.Dispose() }
                if ($failure.PSObject.Properties['diagnosis'] -and $failure.diagnosis.status -match '^[A-Z_]{1,64}$') { $script:LastApiStatus += ' / ' + $failure.diagnosis.status }
                if ($failure.PSObject.Properties['error_code'] -and [string]$failure.error_code -match '^[A-Z_]{1,64}$') {
                    $script:LastApiErrorCode=[string]$failure.error_code
                }
                $messages = @{
                    STALE_PLAN_VERSION='Plan zmienil sie na serwerze. Nacisnij WZNOW, aby pobrac aktualny stan.'
                    PREVIOUS_OPERATION_UNCONFIRMED='Poprzednia operacja zostala rozpoczeta. Wymagane sprawdzenie wyniku lub zatwierdzenie ponowienia naprawy zaufania.'
                    RETRY_NOT_ALLOWED='Serwer nie zatwierdzil ponowienia: sprawdz stan planu i tozsamosc konta AD.'
                    JOIN_CANCEL_NOT_VERIFIED='Nie potwierdzono bezpiecznego wycofania join. Sprawdz Windows, konto S07-XX w AD i NetSetup.log; rezerwacja zostala zachowana.'
                    NO_FREE_NAME='Brak wolnej nazwy komputera w tej sali.'
                    DEVICE_PLAN_MISMATCH='Plan nalezy do innego urzadzenia. Rozpocznij naprawe tego komputera.'
                    IDENTITY_PAIRING_REQUIRED='Urzadzenie wymaga zatwierdzenia w panelu SP2 ADMIN.'
                    PLAN_ALREADY_STARTED='Plan zostal juz rozpoczety w Windows/AD. Anulowanie niedozwolone; uzyj WZNOW RECOVERY.'
                    CANCEL_NOT_ALLOWED='Serwer nie zezwolil na anulowanie planu w tym stanie. Rezerwacja zachowana.'
                    NAME_TAKEN='Wybrana nazwa jest juz zajeta lub zarezerwowana przez inny komputer.'
                    LOCAL_REPAIR_NOT_VERIFIED='Serwer nie potwierdzil lokalnej naprawy zaufania w AD. Plan i rezerwacja zachowane.'
                }
                if ($failure.PSObject.Properties['blockers']) {
                    $codes=@($failure.blockers | Where-Object { [string]$_ -match '^[a-z_]{1,64}$' })
                    if ($codes.Count -gt 0) { Write-UiLog ('Serwer - warunki niespelnione: ' + ($codes -join ', ')) }
                }
                if ($failure.PSObject.Properties['error_code'] -and $messages.ContainsKey([string]$failure.error_code)) {
                    $script:FailureMessage=$messages[[string]$failure.error_code]
                    Write-UiLog ('API BLAD: ' + $script:FailureMessage)
                }
            } catch { }
        }
        if ($script:LastHttpStatus -eq 0) {
            if ($_.Exception -is [Net.WebException] -and $_.Exception.Status -eq [Net.WebExceptionStatus]::TrustFailure) {
                $script:FailureMessage='HTTPS SP2: Windows odrzucil certyfikat TLS (TrustFailure). Sprawdz szkolny CA, lancuch certyfikatow i dostepnosc CRL/OCSP. Weryfikacja TLS pozostaje wlaczona.'
            } else {
                $status=''
                if ($_.Exception -is [Net.WebException]) { $status=[string]$_.Exception.Status }
                $script:FailureMessage=switch ($status) {
                    'NameResolutionFailure' { 'HTTPS SP2: nie mozna rozwiazac nazwy serwera. Sprawdz DNS / NRPT.'; break }
                    'ConnectFailure' { 'HTTPS SP2: serwer nie przyjmuje polaczenia. Sprawdz TCP 443, nginx i sp2-admin.'; break }
                    'Timeout' { 'HTTPS SP2: uplynal limit oczekiwania na odpowiedz. Sprawdz lacznosc i serwer.'; break }
                    'SecureChannelFailure' { 'HTTPS SP2: nie powiodlo sie uzgodnienie protokolu TLS. Nie wylaczaj sprawdzania certyfikatow.'; break }
                    default { 'Nie udalo sie polaczyc przez HTTPS z SP2 ADMIN. Sprawdz adres, DNS, dostepnosc serwera i lancuch certyfikatu Windows. Weryfikacja TLS pozostaje wlaczona.'; break }
                }
            }
            Write-UiLog $script:FailureMessage
        }
        throw
    }
    return $response.Content | ConvertFrom-Json
}

function Ensure-SecondaryDomainDns {
    # SP2 policy: preserve the existing first DNS (Internet) and place Samba AD
    # DNS second. Do not invent/replace the primary resolver automatically.
    foreach ($adapter in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')) {
        $dns=Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
        $current=@($dns.ServerAddresses | Where-Object { $_ })
        if (-not ($current -contains $script:DomainDnsServer)) {
            if ($current.Count -lt 1) { continue }
            $desired=@($current[0],$script:DomainDnsServer)
            if ($current.Count -gt 1) { $desired += @($current | Select-Object -Skip 1) }
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $desired -ErrorAction Stop
        } elseif ($current.Count -gt 1 -and $current[0] -eq $script:DomainDnsServer) {
            $others=@($current | Where-Object { $_ -ne $script:DomainDnsServer })
            if ($others.Count -gt 0) {
                $desired=@($others[0],$script:DomainDnsServer)
                if ($others.Count -gt 1) { $desired += @($others | Select-Object -Skip 1) }
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $desired -ErrorAction Stop
            }
        }
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

function Ensure-SchoolDomainDnsRoute {
    # Adapter DNS remains unchanged here. A second DNS resolver is only
    # failover: a working Internet resolver may reply NXDOMAIN for sp2.lan.
    # Scope the internal resolver to the school namespace via Windows NRPT.
    if (-not $script:Endpoint) { return }
    $uri=[Uri]$script:Endpoint
    if ($uri.Scheme -ne 'https' -or $uri.DnsSafeHost -ine 'dc.sp2.lan') { return }
    $hostName='dc.sp2.lan'
    $namespaces=@('sp2.lan','.sp2.lan')

    $normal=@()
    try {
        $normal=@(Resolve-DnsName -Name $hostName -Type A -DnsOnly -ErrorAction Stop |
            Where-Object { $_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress })
    } catch { }
    if ($normal -contains $script:DomainDnsServer) { return }

    # Only install a DNS rule after independently verifying the configured
    # Samba resolver answers with the expected controller address.
    $direct=@()
    try {
        $direct=@(Resolve-DnsName -Name $hostName -Server $script:DomainDnsServer -Type A -DnsOnly -ErrorAction Stop |
            Where-Object { $_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress })
    } catch {
        throw 'Nie mozna polaczyc sie ze szkolnym DNS 192.168.0.143. Sprawdz siec/VLAN, port 53 i adres serwera. Nie zmieniono NRPT.'
    }
    if ($direct -notcontains $script:DomainDnsServer) {
        throw 'Szkolny DNS nie potwierdzil adresu dc.sp2.lan = 192.168.0.143. Nie zmieniono NRPT.'
    }

    # Never override a local, VPN, or domain-policy rule managed elsewhere.
    $existing=@()
    foreach ($rule in @(Get-DnsClientNrptRule -ErrorAction Stop)) {
        if (@($rule.Namespace | Where-Object { $_ -in $namespaces }).Count -gt 0) { $existing+= $rule }
    }
    $effective=@()
    foreach ($rule in @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)) {
        if (@($rule.Namespace | Where-Object { $_ -in $namespaces }).Count -gt 0) { $effective+= $rule }
    }
    if ($existing.Count -gt 0 -or $effective.Count -gt 0) {
        throw 'Istnieje juz regula DNS dla sp2.lan, ale dc.sp2.lan nadal sie nie rozwiazuje. Sprawdz polityke NRPT; nie nadpisano jej.'
    }

    $added=Add-DnsClientNrptRule -Namespace $namespaces -NameServers $script:DomainDnsServer -DisplayName 'SP2 ADMIN - DNS domeny szkolnej' -Comment 'SP2 domain-only DNS resolution; Internet DNS untouched' -PassThru -ErrorAction Stop
    try {
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        $after=@(Resolve-DnsName -Name $hostName -Type A -DnsOnly -ErrorAction Stop |
            Where-Object { $_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress })
        if ($after -notcontains $script:DomainDnsServer) {
            throw 'Regula NRPT nie przywrocila rozwiazywania dc.sp2.lan.'
        }
        Write-UiLog 'DNS SP2: skonfigurowano oddzielna regule dla sp2.lan (192.168.0.143). Internetowy DNS bez zmian.'
    } catch {
        if ($null -ne $added -and $added.Name) {
            Remove-DnsClientNrptRule -Name $added.Name -Force -ErrorAction SilentlyContinue
        }
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        throw 'Nie udalo sie potwierdzic szkolnego DNS. Wycofano nowa regule NRPT; sprawdz polityki sieci.'
    }
}

function Get-AuthoritativeSchoolARecords([string]$Fqdn) {
    # "Question" entries are NOT authoritative DNS answers (seen on SALA7).
    $rows=@()
    try {
        $rows=@(Resolve-DnsName -Name $Fqdn -Server $script:DomainDnsServer -Type A -DnsOnly -NoHostsFile -ErrorAction Stop)
    } catch {
        if ([string]$_.FullyQualifiedErrorId -match 'DNS_ERROR_RCODE_NAME_ERROR|DNS_ERROR_RCODE_NXRRSET') {
            return @()
        }
        throw 'Brak odpowiedzi szkolnego serwera DNS. Nie zmieniono rekordow.'
    }
    $addresses=@($rows | Where-Object { $_.Type -eq 'A' -and $_.Section -eq 'Answer' -and $_.IPAddress } |
        ForEach-Object { [string]$_.IPAddress } | Sort-Object -Unique)
    return $addresses
}

function Register-SchoolDnsAndVerify([string]$Fqdn,[string]$SourceIp) {
    # Standard Windows secure DNS registration under existing machine identity.
    Register-DnsClient -ErrorAction Stop | Out-Null
    for ($attempt=0; $attempt -lt 4; $attempt++) {
        Start-Sleep -Seconds 3
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        $current=@(Get-AuthoritativeSchoolARecords $Fqdn)
        if ($current.Count -gt 0 -and $current -notcontains $SourceIp) {
            throw 'DNS SP2 wskazuje inny adres A: nie nadpisano rekordu.'
        }
        if ($current -contains $SourceIp) { return $true }
    }
    return $false
}

function Assert-PostJoinDnsIdentity($Plan,$Local) {
    # Existing plan, same MAC/UUID-bound token, pinned AD SID and a completed
    # Windows join are mandatory. Never create records for a guessed name.
    # Older SP2 ADMIN responses omit source_sid. Never infer ownership from
    # target_ad.object_sid; fail closed instead of crashing under StrictMode.
    if (-not $Plan.PSObject.Properties['source_sid'] -or
        [string]::IsNullOrWhiteSpace([string]$Plan.source_sid)) {
        Write-UiLog 'DNS SP2: serwer nie przekazal przypietego SID planu. Nie wykonano rejestracji DNS.'
        return $false
    }
    $expected=[string]$Plan.target_name
    $targetAd=$Plan.diagnosis.target_ad
    $checks=$Plan.diagnosis.checks
    if (
        $Plan.state -ne 'manual_review' -or $Plan.action -ne 'blocked' -or
        $Plan.diagnosis.status -ne 'AD_METADATA_REVIEW' -or
        $Plan.device_id -ne (Get-DeviceId) -or
        $Plan.domain -ine 'sp2.lan' -or $expected -ine $Local.hostname -or
        $Local.part_of_domain -ne $true -or $Local.secure_channel -ne $true -or
        $Local.domain -ine $Plan.domain -or
        $expected -notmatch '^(?:S[0-9]{2,3}-[0-9]{2}|(?:BR|PL)-S[0-9]{2,3}(?:-[0-9]{2})?)$' -or
        -not $Plan.source_sid -or $Plan.source_sid -ne $targetAd.object_sid -or
        $targetAd.exists -ne $true -or $targetAd.enabled -ne $true -or
        $checks.ou_matches -ne $true -or $checks.spn_matches -ne $true -or
        $checks.dns_spn_conflict -ne $false -or $Plan.diagnosis.target_conflict -ne $false -or
        $checks.dns_resolves -ne $false
    ) { return $false }
    if (@($Plan.history | Where-Object { $_.event -eq 'begin' -and $_.action -eq 'join' }).Count -eq 0) {
        return $false
    }
    return $true
}

function Repair-MissingSchoolDnsA($Plan,$Local) {
    if (-not (Assert-PostJoinDnsIdentity $Plan $Local)) { return $false }
    $name=([string]$Plan.target_name).ToLowerInvariant() + '.sp2.lan'
    $dns=[string]$script:DomainDnsServer
    if ($dns -ne '192.168.0.143') { throw 'Nieznany szkolny DNS.' }

    $connection=Test-NetConnection -ComputerName $dns -Port 53 -InformationLevel Detailed -WarningAction SilentlyContinue
    if ($connection.TcpTestSucceeded -ne $true -or -not $connection.SourceAddress) {
        throw 'Nie potwierdzono trasy TCP 53 do szkolnego DNS.'
    }
    $sourceIp=[string]$connection.SourceAddress
    $parsed=$null
    if (-not [Net.IPAddress]::TryParse($sourceIp,[ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Brak poprawnego adresu IPv4 dla DNS SP2.'
    }
    $adapter=@(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {
        $_.Status -eq 'Up' -and $_.Name -eq [string]$connection.InterfaceAlias
    })
    if ($adapter.Count -ne 1) { throw 'Nie mozna jednoznacznie wybrac karty sieciowej.' }
    $configuredIps=@(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapter[0].ifIndex -ErrorAction Stop |
        ForEach-Object { [string]$_.IPAddress })
    if ($configuredIps -notcontains $sourceIp) {
        throw 'Adres do rejestracji DNS nie nalezy do aktywnej karty.'
    }

    $existing=@(Get-AuthoritativeSchoolARecords $name)
    if ($existing.Count -gt 0) {
        if ($existing -notcontains $sourceIp) { throw 'DNS SP2: istnieje rekord innego adresu. Wymagana kontrola.' }
        return $true
    }

    Write-UiLog ('DNS SP2: brak rekordu ' + $name + '. Proba rejestracji Windows.')
    if (Register-SchoolDnsAndVerify $name $sourceIp) {
        Write-UiLog 'DNS SP2: potwierdzono rekord bez zmiany Internetowego DNS.'
        return $true
    }

    # Bounded fallback: only if Samba DNS can also resolve public addresses.
    # Restore original (Internet-first) DNS servers in a finally block.
    $external=@()
    try {
        $external=@(Resolve-DnsName 'www.microsoft.com' -Server $dns -Type A -DnsOnly -NoHostsFile -ErrorAction Stop |
            Where-Object { $_.Type -eq 'A' -and $_.Section -eq 'Answer' -and $_.IPAddress })
    } catch { }
    if ($external.Count -eq 0) {
        throw 'Szkolny DNS nie obsluguje zapytan internetowych. Nie zmieniono kolejnosci DNS.'
    }
    $index=$adapter[0].ifIndex
    $original=@((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses |
        Where-Object { $_ })
    if ($original.Count -eq 0 -or $original -notcontains $dns) {
        throw 'Karta nie ma potwierdzonej konfiguracji DNS.'
    }
    if ($original[0] -eq $dns) {
        throw 'DNS SP2 jest juz podstawowy; aktualizacja Windows nie powiodla sie.'
    }
    $temporary=@($dns) + @($original | Where-Object { $_ -ne $dns })
    $succeeded=$false
    $restoreFailed=$false
    try {
        Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $temporary -ErrorAction Stop
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        Write-UiLog 'DNS SP2: chwilowe ustawienie szkolnego DNS przed rejestracja; przywracanie automatyczne.'
        $succeeded=Register-SchoolDnsAndVerify $name $sourceIp
    } finally {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $original -ErrorAction Stop
            Clear-DnsClientCache -ErrorAction SilentlyContinue
            $restored=@((Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses)
            if (($restored -join ',') -ne ($original -join ',')) {
                throw 'Nie potwierdzono przywrocenia kolejnosci DNS.'
            }
        } catch { $restoreFailed=$true }
    }
    if ($restoreFailed) { throw 'KRYTYCZNE: nie potwierdzono przywrocenia DNS Internetu. Sprawdz karte.' }
    if (-not $succeeded) { throw 'Bezpieczna rejestracja rekordu A nie powiodla sie. Sprawdz Samba DNS.' }
    Write-UiLog 'DNS SP2: rekord A potwierdzony; oryginalne DNS Internetu przywrocone.'
    return $true
}

function Get-LocalState {
    $system = Read-RequiredCimClass 'Win32_ComputerSystem'
    $os = Read-RequiredCimClass 'Win32_OperatingSystem'
    $secure = $null
    if ($system.PartOfDomain) {
        try { $secure = [bool](Test-ComputerSecureChannel -ErrorAction Stop) } catch { Write-Crash 'SECURE_CHANNEL_PROBE_FAILED' $_; $secure = $null }
    }
    try {
        $macs=@(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object MacAddress | ForEach-Object { $_.MacAddress.Replace('-',':').ToUpperInvariant() })
    } catch {
        $script:FailureMessage='CIM Windows: nie mozna odczytac fizycznych kart sieciowych. Sprawdz Winmgmt i stan sterownika sieci; nie rozpoczeto operacji domenowej.'
        Write-UiLog $script:FailureMessage
        throw
    }
    $hardware=Get-HardwareIdentity
    return @{ hostname=$env:COMPUTERNAME; part_of_domain=[bool]$system.PartOfDomain; domain=[string]$system.Domain; secure_channel=$secure; boot_id=$os.LastBootUpTime.ToUniversalTime().ToString('o');mac_addresses=$macs;hardware_uuid=$hardware.uuid }
}

# Pure comparison: no registry, AD or network changes. Tested with synthetic names.
function Get-JoinNameConsistencyIssues($Names, [string]$SourceName) {
    $issues=New-Object 'System.Collections.Generic.List[string]'
    $required=@('WindowsName','DnsHostName','SocketHostName','ProcessName','ActiveName','PendingName','TcpHostname','TcpNvHostname')
    foreach ($key in $required) {
        if ([string]::IsNullOrWhiteSpace([string]$Names[$key])) {
            $issues.Add('Brak odczytu nazwy ' + $key + '.')
        }
    }
    if ([string]::IsNullOrWhiteSpace($SourceName)) { $issues.Add('Serwer nie przekazal nazwy zrodlowej planu.') }
    if ($issues.Count -gt 0) { return $issues.ToArray() }
    $expected=[string]$Names['WindowsName']
    if ($SourceName -ine $expected) {
        $issues.Add('Nazwa zrodlowa planu ' + $SourceName + ' rozni sie od Windows ' + $expected + '.')
    }
    foreach ($key in @('DnsHostName','SocketHostName','ProcessName','ActiveName','PendingName','TcpHostname','TcpNvHostname')) {
        if ([string]$Names[$key] -ine $expected) {
            $issues.Add($key + '=' + [string]$Names[$key] + ' rozni sie od Windows=' + $expected + '.')
        }
    }
    return $issues.ToArray()
}

function Read-WindowsNames {
    # Read-only: active and pending (after reboot) computer names.
    $system=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $tcp=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction Stop
    $active=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction Stop
    $pending=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction Stop
    return @{
        WindowsName=[string]$system.Name
        DnsHostName=[string]$system.DNSHostName
        SocketHostName=[string][System.Net.Dns]::GetHostName()
        ProcessName=[string]$env:COMPUTERNAME
        ActiveName=[string]$active.ComputerName
        PendingName=[string]$pending.ComputerName
        TcpHostname=[string]$tcp.Hostname
        TcpNvHostname=[string]$tcp.'NV Hostname'
    }
}

function Test-JoinLocalNamePreflight($Plan) {
    # Fail closed before credential prompts, progress begin or Add-Computer.
    # A pending name change is not enough; reboot until the active names agree.
    try {
        $names=Read-WindowsNames
        $issues=@(Get-JoinNameConsistencyIssues $names ([string]$Plan.source_name))
    } catch {
        Write-UiLog 'BLOKADA join: nie mozna bezpiecznie odczytac wszystkich nazw Windows.'
        return $false
    }
    if ($issues.Count -gt 0) {
        foreach ($issue in $issues) { Write-UiLog ('BLOKADA join: ' + $issue) }
        Write-UiLog 'Plan pozostaje ready; nie uruchomiono begin ani Add-Computer. Nie zmieniaj recznie rejestru.'
        return $false
    }
    Write-UiLog 'Nazwy Windows (NetBIOS, TCP/IP, DNS) sa spojne przed join.'
    return $true
}

function Get-DeviceId {
    $path=Join-Path $script:Root 'device-id.txt'
    if (Test-Path -LiteralPath $path) { return ([Guid]([IO.File]::ReadAllText($path).Trim())).ToString() }
    $device=[Guid]::NewGuid().ToString()
    foreach ($name in @('pending.json','auth.json')) {
        $oldPath=Join-Path $script:Root $name
        if (Test-Path -LiteralPath $oldPath) {
            try { $old=Get-Content -LiteralPath $oldPath -Raw | ConvertFrom-Json; $device=([Guid]$old.device_id).ToString(); break } catch { }
        }
    }
    [IO.File]::WriteAllText($path,$device)
    return $device
}

function Set-Progress([string]$Event, [bool]$Approved = $false, [string]$Reason = '') {
    $plan = $script:State.plan
    $data=@{version=$plan.version; event=$Event; device_id=$script:State.device_id; local=(Get-LocalState)}
    if ($Event -in @('retry','cancel','resolve')) { $data.approved=$Approved }
    if ($Reason) { $data.reason=$Reason }
    Write-UiLog ('Etap planu: ' + $Event)
    $updated = Invoke-Api ('progress/' + $plan.id) $data
    $script:State.plan = $updated
    Save-State
}

function Install-Resume {
    $installedScript = Join-Path $script:Root 'SP2-Serwis-Domeny.ps1'
    if ($PSCommandPath -ne $installedScript) { Copy-Item -LiteralPath $PSCommandPath -Destination $installedScript -Force }
    if (Test-Path -LiteralPath $script:EntraModulePath) {
        $installedModule=Join-Path $script:Root 'SP2-Entra-Transition.ps1'
        if ($script:EntraModulePath -ne $installedModule) {
            Copy-Item -LiteralPath $script:EntraModulePath -Destination $installedModule -Force
        }
    }
    $nativeSource=Join-Path $PSScriptRoot 'MachineAccountRecovery.cs'
    $installedSource=Join-Path $script:Root 'MachineAccountRecovery.cs'
    if ($nativeSource -ne $installedSource) { Copy-Item -LiteralPath $nativeSource -Destination $installedSource -Force }
    $nativeDll=Join-Path $PSScriptRoot 'SP2MachineAccountRecovery.dll'
    $installedDll=Join-Path $script:Root 'SP2MachineAccountRecovery.dll'
    if ((Test-Path -LiteralPath $nativeDll) -and $nativeDll -ne $installedDll) { Copy-Item -LiteralPath $nativeDll -Destination $installedDll -Force }
    $launcher = Join-Path (Split-Path -Parent $PSCommandPath) 'SP2-Serwis-Domeny.exe'
    $installedLauncher=Join-Path $script:Root 'SP2-Serwis-Domeny.exe'
    if ((Test-Path -LiteralPath $launcher) -and $launcher -ne $installedLauncher) { Copy-Item -LiteralPath $launcher -Destination $installedLauncher -Force }
    # Interactive task uses the logging-on administrator, never a saved password.
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -STA -ExecutionPolicy RemoteSigned -File "' + $installedScript + '" -Resume')
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-544' -RunLevel Highest
    Register-ScheduledTask -TaskName 'SP2-Domain-Recovery' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

function Get-DomainCredential {
    if ($null -ne $script:Credential) { return $script:Credential }
    $credential = Get-Credential -UserName 'Administrator@SP2.LAN' -Message 'Podaj haslo domenowe. Program zapamieta je tylko do zamkniecia tego okna.'
    if ($null -eq $credential) { throw 'Anulowano podanie poswiadczen.' }
    if ($credential.Password.Length -lt 1) { $credential.Password.Dispose(); throw 'Wymagane haslo administratora domeny.' }
    $script:Credential = $credential
    return $credential
}

function Authorize-RecoveryJoin {
    $plan=$script:State.plan
    $authorization=Invoke-Api ('join-authorize/' + $plan.id) @{version=$plan.version;device_id=$script:State.device_id;local=(Get-LocalState)}
    if ($authorization.authorized -ne $true) { throw 'Serwer nie zatwierdzil odbudowy konta.' }
}

function Request-RecoveryPlan($Data) {
    try { return Invoke-Api 'plan' $Data }
    catch {
        # Re-pair only when the server explicitly says that this hardware
        # identity is not bound to the current recovery token. A generic 403
        # from plan validation must not open another approval loop.
        if ($script:LastHttpStatus -ne 403 -or $script:LastApiErrorCode -ne 'IDENTITY_PAIRING_REQUIRED') { throw }
        $script:Token=''
        $script:Token=Get-BrowserToken
        $identified=Identify-Device
        Save-Authentication
        $script:State.device_id=$identified.device_id
        $script:State.token=Protect-AgentToken $script:Token
        Save-State
        return Invoke-Api 'plan' $Data
    }
}

function Invoke-MachineAccountRecovery($Plan, [Management.Automation.PSCredential]$Credential) {
    $local=Get-LocalState
    if ($local.part_of_domain -ne $true -or $local.secure_channel -ne $false -or $local.domain -ine $Plan.domain -or (Get-DeviceId) -ne $script:State.device_id) {
        throw 'Stan komputera zmienil sie przed join. Wymagana kontrola.'
    }
    if (-not ('SP2MachineAccountRecovery' -as [type])) {
        $nativeDll=Join-Path $PSScriptRoot 'SP2MachineAccountRecovery.dll'
        if (Test-Path -LiteralPath $nativeDll) { Add-Type -Path $nativeDll -ErrorAction Stop }
        else { Add-Type -Path (Join-Path $PSScriptRoot 'MachineAccountRecovery.cs') -ErrorAction Stop }
    }
    $code=[SP2MachineAccountRecovery]::Join($Plan.target_name,$Plan.domain,$Plan.target_ou,$Credential.UserName,$Credential.Password)
    if ($code -ne 0) {
        # The native API returns a numeric Win32/NetJoin status. Safe to display:
        # never log the domain credential, arguments or raw exception payload.
        Write-UiLog ('Natywny join Windows niepowodzenie: kod=' + [string]$code + '. Zobacz C:\Windows\Debug\NetSetup.log.')
        throw 'Kontrolowany join niepotwierdzony. Zobacz kod Windows w oknie programu.'
    }
}

function Report-UnconfirmedWorkgroupJoin($Plan) {
    # Add-Computer can make partial changes before reporting an error.
    # Record failed for manual review; never retry the Windows join here.
    if ($Plan.action -ne 'join') { return }
    try {
        $script:State.plan=Invoke-Api ('status/' + $Plan.id) $null 'GET'
        if ($script:State.plan.state -eq 'pending' -and $script:State.plan.action -eq 'join') {
            Set-Progress 'failed'
        }
    } catch {
        Write-UiLog 'Nie potwierdzono zapisania statusu failed. Sprawdz stan planu w SP2 ADMIN.'
    }
    $script:FailureMessage='Dolaczenie Windows niepotwierdzone. Plan i nazwa zachowane do kontroli. Sprawdz C:\Windows\Debug\NetSetup.log i stan AD przed ponowna proba; nie wykonuj kolejnego joinu.'
}

function Get-CloudJoinStatusText {
    # Read-only Microsoft device registration inspection. No dsregcmd /leave.
    $exe=Join-Path $env:WINDIR 'System32\dsregcmd.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw 'Brak narzedzia dsregcmd.exe.' }
    $report=(& $exe /status | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Nie udalo sie odczytac stanu Microsoft Entra.' }
    return $report
}

function Assert-WorkgroupNotCloudJoined {
    # PartOfDomain=False does not rule out Microsoft Entra device membership.
    # NetJoinDomain fails with 0xA8C on Microsoft Entra joined workstations.
    $joined=$false
    try {
        $joined=[bool](Get-CloudJoinFlag)
    } catch {
        $script:FailureMessage='Nie mozna potwierdzic stanu Microsoft Entra przez natywne API Windows. Zobacz dsregcmd /status. Nie odlaczono konta i nie rozpoczeto join.'
        throw 'Nieznany stan Microsoft Entra: brak wyniku natywnego API.'
    }
    if ($joined) {
        $script:FailureMessage='ZATRZYMANO: komputer jest dolaczony do Microsoft Entra. Windows odrzuci join do AD kodem 0xA8C. Sprawdz lokalnego administratora i profile przed migracja. Program nie wykona dsregcmd /leave automatycznie.'
        throw 'Microsoft Entra join blokuje operacje.'
    }
}

function Test-JoinAuthorizationRecorded($Plan) {
    return @($Plan.history | Where-Object {
        $_.event -eq 'credential_issued' -and $_.action -eq 'machine_account_recovery'
    }).Count -gt 0
}

function Complete-RecoveryClientState {
    # Server already committed complete; only local task/token cleanup remains.
    Unregister-ScheduledTask -TaskName 'SP2-Domain-Recovery' -Confirm:$false -ErrorAction SilentlyContinue
    $script:State.token=''
    Save-State
    return 'GOTOWE: secure channel oraz konto, OU, DNS/SPN potwierdzone przez serwer.'
}

function Confirm-UnconfirmedWorkgroupJoinCancellation($Plan) {
    $message="Plan join $($Plan.source_name) -> $($Plan.target_name) nie zostal potwierdzony." +
        [Environment]::NewLine +
        "Serwer sprawdzi po restarcie: ten sam komputer (UUID/MAC), brak czlonkostwa Windows," +
        " brak konta docelowego AD i konfliktu DNS/SPN." +
        [Environment]::NewLine + [Environment]::NewLine +
        "Tylko jesli wszystkie warunki sa spelnione, anuluje stary plan i zwolni nazwe." +
        [Environment]::NewLine +
        "Nie wykona ponownego Add-Computer. Nowa probe bedzie mozna rozpoczac osobno." +
        [Environment]::NewLine + [Environment]::NewLine +
        "Zatwierdzasz sprawdzenie i ewentualne wycofanie starego planu?"
    return ([Windows.Forms.MessageBox]::Show($message,
        'SP2 ADMIN - kontrolowane wycofanie join', 'YesNo', 'Warning') -eq 'Yes')
}

function Reconcile-UnconfirmedWorkgroupJoin($Plan) {
    # This is NOT a retry. No Windows/AD operations are performed locally.
    # Server rechecks the authenticated device and current AD state before
    # accepting the explicit cancel; any ambiguity keeps the name reserved.
    if ($Plan.state -ne 'manual_review' -or $Plan.action -ne 'join') { return $null }
    $local=Get-LocalState
    $blockers = New-Object 'System.Collections.Generic.List[string]'
    if ($Plan.diagnosis.status -ne 'OUTSIDE_DOMAIN') { $blockers.Add('Stan diagnozy serwera nie jest OUTSIDE_DOMAIN.') }
    if ($Plan.diagnosis.target_conflict -eq $true) { $blockers.Add('Serwer wykryl konflikt docelowej nazwy.') }
    if ($Plan.diagnosis.target_ad.exists -eq $true) { $blockers.Add('Docelowe konto AD istnieje.') }
    if ($Plan.diagnosis.checks.dns_spn_conflict -eq $true) { $blockers.Add('Serwer wykryl konflikt DNS/SPN.') }
    if ($local.part_of_domain -ne $false) { $blockers.Add('Windows nie potwierdza WORKGROUP.') }
    if ($null -ne $local.secure_channel) { $blockers.Add('Stan kanalu domenowego jest niejednoznaczny.') }
    if ([string]$local.hostname -ine [string]$Plan.source_name) {
        $blockers.Add('Nazwa Windows nie jest zgodna z nazwa zrodlowa planu.')
    }
    if ($blockers.Count -gt 0) {
        foreach ($reason in $blockers) { Write-UiLog ('BLOKADA anulowania: ' + $reason) }
        return 'ZATRZYMANO: serwer lub Windows nie potwierdzil warunkow anulowania. Rezerwacja zachowana.'
    }
    $begin=@($Plan.history | Where-Object {
        $_.event -eq 'begin' -and $_.action -eq 'join'
    } | Select-Object -Last 1)
    if ($begin.Count -ne 1 -or -not $local.boot_id -or
        [string]$begin[0].boot_id -eq [string]$local.boot_id) {
        return 'ZATRZYMANO: wymagany potwierdzony nowy restart Windows przed wycofaniem nieudanego join. Rezerwacja zachowana.'
    }
    Write-UiLog 'SP2: po restarcie Windows nadal jest poza domena. Mozliwe kontrolowane wycofanie planu, bez ponawiania join.'
    if (-not (Confirm-UnconfirmedWorkgroupJoinCancellation $Plan)) {
        return 'Nie wycofano planu. Rezerwacja nazwy zostala zachowana.'
    }
    try {
        Set-Progress 'cancel' $true
    } catch {
        if ($script:LastHttpStatus -eq 409) {
            return 'Serwer nie potwierdzil bezpiecznego wycofania planu. Sprawdz NetSetup.log, komputer w AD i stan planu. Rezerwacja zachowana.'
        }
        throw
    }
    if ($script:State.plan.state -ne 'cancelled') {
        throw 'Serwer nie potwierdzil wycofania planu. Nie rozpoczynaj nowego join.'
    }
    return 'Serwer bezpiecznie anulowal stary plan i zwolnil rezerwacje. Nacisnij NAPRAW TEN KOMPUTER, aby otrzymac nowy plan (nie uruchomiono join).'
}

function Test-ResumeMayCreatePlan($Local,$PreviousPlan,$ActivePlan) {
    # RESUME is idempotent only for an interrupted *new* workgroup plan.
    # Once a device is domain joined, it must never create another plan merely
    # because a completed plan is no longer returned as active by /identify.
    if ($null -ne $PreviousPlan -or $null -ne $ActivePlan -or $null -eq $Local) { return $false }
    return ($Local.part_of_domain -eq $false -and $null -eq $Local.secure_channel)
}

# --- Anulowanie planu przed rozpoczeciem / zmiana nazwy -------------------
# Plan, ktory nie przeszedl jeszcze etapu 'begin', niczego nie zmienil w
# Windows ani w AD - zawiera tylko rezerwacje nazwy na serwerze. Taki plan
# mozna bezpiecznie anulowac (np. po wpisaniu blednej sali/numeru). Klient
# sprawdza warunki tylko dla czytelnych komunikatow; o anulowaniu zawsze
# decyduje serwer (ponownie sprawdza historie planu i urzadzenie).
$script:PlanStartedEvents = @('begin','credential_issued','retry','failed','approve_ad','ad_approved')

function Get-PlanProperty($Object, [string]$Name) {
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $null
}

function Get-TargetGroupPrefix([string]$Name) {
    # S07-03 -> S07 ; BR-S30 / BR-S30-01 -> BR-S30 (sala + budynek, bez numeru)
    $m=[regex]::Match($Name,'^(S[0-9]{2,3})-[0-9]{2}$','IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value.ToUpperInvariant() }
    $m=[regex]::Match($Name,'^((?:BR|PL)-S[0-9]{2,3})(?:-[0-9]{2})?$','IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value.ToUpperInvariant() }
    return ''
}

function Get-PlanCancelBlockers($Plan, $Local) {
    # Pure check (no network/registry). Returns reasons why the client must
    # NOT request cancellation of this plan.
    $blockers=New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Plan) { $blockers.Add('Brak planu.'); return $blockers.ToArray() }
    $state=[string](Get-PlanProperty $Plan 'state')
    if ($state -notin @('ready','manual_review')) {
        $blockers.Add('Stan planu "' + $state + '" nie pozwala na anulowanie przed startem.')
    }
    foreach ($entry in @(Get-PlanProperty $Plan 'history')) {
        if ($null -eq $entry) { continue }
        $event=[string](Get-PlanProperty $entry 'event')
        if ($event -in $script:PlanStartedEvents) {
            $blockers.Add('Plan ma juz zdarzenie "' + $event + '" - Windows/AD moglo zostac zmienione.')
            break
        }
    }
    $source=[string](Get-PlanProperty $Plan 'source_name')
    if ($null -ne $Local -and $source -and [string]$Local.hostname -ine $source) {
        $blockers.Add('Nazwa Windows ' + $Local.hostname + ' rozni sie od nazwy zrodlowej planu ' + $source + '.')
    }
    $ownDevice=''
    if ($null -ne $script:State) { $ownDevice=[string]$script:State.device_id }
    $planDevice=[string](Get-PlanProperty $Plan 'device_id')
    if ($ownDevice -and $planDevice -and $planDevice -ne $ownDevice) {
        $blockers.Add('Plan nalezy do innego urzadzenia.')
    }
    return $blockers.ToArray()
}

function Test-PlanSelectionMismatch($Plan, [string]$Target, [string]$Ou, [bool]$ExactName) {
    # Czy plan na serwerze nie odpowiada temu, co operator wybral teraz w oknie?
    $planTarget=[string](Get-PlanProperty $Plan 'target_name')
    $planOu=[string](Get-PlanProperty $Plan 'target_ou')
    if ($Ou -and $planOu -and $Ou -ine $planOu) { return $true }
    if ($ExactName) { return ($planTarget -ine $Target) }
    # auto_name: serwer moze wybrac kolejny wolny numer w tej samej sali,
    # wiec porownujemy tylko sale/budynek/typ.
    return ((Get-TargetGroupPrefix $planTarget) -ine (Get-TargetGroupPrefix $Target))
}

function Cancel-PlanBeforeStart([string]$Reason, [bool]$AlreadyConfirmed = $false) {
    $plan=$script:State.plan
    $local=Get-LocalState
    $blockers=@(Get-PlanCancelBlockers $plan $local)
    if ($blockers.Count -gt 0) {
        foreach ($b in $blockers) { Write-UiLog ('BLOKADA anulowania: ' + $b) }
        return $false
    }
    if (-not $AlreadyConfirmed) {
        $message="Anulowac plan i zwolnic rezerwacje nazwy?" + [Environment]::NewLine + [Environment]::NewLine +
            "Plan: $($plan.action)  $($plan.source_name) -> $($plan.target_name)" + [Environment]::NewLine +
            "OU: $($plan.target_ou)" + [Environment]::NewLine + [Environment]::NewLine +
            "Plan nie zostal rozpoczety - Windows i AD nie zostaly zmienione." + [Environment]::NewLine +
            "Po anulowaniu wybierz poprawna sale/numer i kliknij NAPRAW TEN KOMPUTER."
        if ([Windows.Forms.MessageBox]::Show($message,'SP2 - anulowanie planu','YesNo','Warning') -ne 'Yes') {
            Write-UiLog 'Nie anulowano planu. Rezerwacja zachowana.'
            return $false
        }
    }
    $oldTarget=[string]$plan.target_name
    try {
        Set-Progress 'cancel' $true $Reason
    } catch {
        if (-not $script:FailureMessage) {
            if ($script:LastHttpStatus -in @(400,409,422)) {
                $script:FailureMessage='Serwer nie zezwolil na anulowanie planu (HTTP ' + $script:LastHttpStatus + '). Na serwerze brakuje obslugi anulowania planu przed startem albo plan zostal juz rozpoczety. Rezerwacja zachowana.'
            }
        }
        if ($script:FailureMessage) { Write-UiLog $script:FailureMessage }
        return $false
    }
    if ([string]$script:State.plan.state -ne 'cancelled') {
        Write-UiLog ('Serwer nie potwierdzil anulowania (stan=' + $script:State.plan.state + '). Rezerwacja zachowana.')
        return $false
    }
    Unregister-ScheduledTask -TaskName 'SP2-Domain-Recovery' -Confirm:$false -ErrorAction SilentlyContinue
    # Nowy request_id: serwer nie moze zwrocic anulowanego planu jako idempotentnej odpowiedzi.
    # Wyczysc tez zapamietana nazwe, aby WZNOW nie zarezerwowal ponownie blednej.
    $script:State.plan=$null
    foreach ($pair in @(@('request_id',[Guid]::NewGuid().ToString()),@('target_name',''))) {
        if ($script:State -is [hashtable]) { $script:State[$pair[0]]=$pair[1] }
        else { $script:State | Add-Member -NotePropertyName $pair[0] -NotePropertyValue $pair[1] -Force }
    }
    Save-State
    Write-UiLog ('Plan anulowany na serwerze. Nazwa ' + $oldTarget + ' zwolniona. Windows i AD bez zmian.')
    return $true
}

# --- Samodzielna naprawa zaufania (secure channel) bez odbudowy konta ------
# Komputer jest w domenie, konto AD istnieje, tylko haslo konta komputera
# rozjechalo sie z AD. Wystarczy Test-ComputerSecureChannel -Repair (reset
# hasla TEGO SAMEGO konta: nazwa, OU, SID bez zmian) zamiast odbudowy konta
# pod nowa nazwa. Nigdy nie wykonuje join/unjoin/rename.

function Invoke-W32Tm([string[]]$Arguments) {
    $exe=Join-Path $env:WINDIR 'System32\w32tm.exe'
    $output=@(& $exe @Arguments 2>&1 | ForEach-Object { [string]$_ })
    return @{code=$LASTEXITCODE; text=($output -join ' ')}
}

function Test-UnsyncedTimeSource([string]$Source) {
    # Samba bez chrony/ntp_signd nie podpisuje NTP: Windows w domenie po cichu
    # zostaje na zegarze lokalnym.
    return ([string]::IsNullOrWhiteSpace($Source) -or
        $Source -match 'Local CMOS Clock|Free-running System Clock|VM IC Time Synchronization Provider')
}

function Ensure-DomainMemberTime {
    $source=Invoke-W32Tm @('/query','/source')
    if ($source.code -ne 0) {
        Set-Service -Name W32Time -StartupType Automatic -ErrorAction Stop
        Start-Service -Name W32Time -ErrorAction Stop
        $source=Invoke-W32Tm @('/query','/source')
    }
    if (-not (Test-UnsyncedTimeSource $source.text)) {
        Write-UiLog ('Czas: zrodlo ' + $source.text.Trim() + ' (bez zmian).')
        return
    }
    # Only a clock that syncs with nothing is redirected. A working domain or
    # GPO time source is never overwritten.
    Write-UiLog 'Czas: Windows nie synchronizuje sie z domena (zegar lokalny). Ustawiam NTP 192.168.0.143.'
    foreach ($arguments in @(
        @('/config',('/manualpeerlist:' + $script:DomainDnsServer + ',0x8'),'/syncfromflags:manual','/reliable:no','/update'),
        @('/resync','/force'))) {
        $result=Invoke-W32Tm $arguments
        if ($result.code -ne 0) { throw ('Windows Time: nie ustawiono szkolnego NTP; kod=' + $result.code) }
    }
    if (Test-UnsyncedTimeSource (Invoke-W32Tm @('/query','/source')).text) {
        throw 'Windows Time nadal nie synchronizuje sie z 192.168.0.143. Sprawdz UDP 123 na serwerze.'
    }
    Write-UiLog 'Czas: zsynchronizowano z 192.168.0.143.'
}

function Get-PendingRenameState($Names, [string]$Hostname) {
    # Pure. 'ok' = all names agree; 'staged' = the running system is
    # consistent but a different name is queued for the next boot (left by a
    # failed NetJoinDomain/SetComputerNameEx); 'inconsistent' = anything else.
    $activeKeys=@('WindowsName','ProcessName','ActiveName','SocketHostName','TcpHostname')
    foreach ($key in $activeKeys) {
        if ([string]::IsNullOrWhiteSpace([string]$Names[$key]) -or [string]$Names[$key] -ine $Hostname) {
            return @{state='inconsistent'; pending=''}
        }
    }
    $pending=@(@('PendingName','TcpNvHostname','DnsHostName') |
        ForEach-Object { [string]$Names[$_] } | Where-Object { $_ -and $_ -ine $Hostname } | Sort-Object -Unique)
    if ($pending.Count -eq 0) { return @{state='ok'; pending=''} }
    return @{state='staged'; pending=($pending -join ', ')}
}

function Restore-StagedComputerName([string]$Hostname) {
    if (-not ('SP2StagedNameRestore' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class SP2StagedNameRestore {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetComputerNameEx(int type, string name);
    // ComputerNamePhysicalDnsHostname: re-stage the CURRENT name (undo a queued rename).
    public static int Restage(string name) {
        return SetComputerNameEx(5, name) ? 0 : Marshal.GetLastWin32Error();
    }
}
'@ -ErrorAction Stop
    }
    $code=[SP2StagedNameRestore]::Restage($Hostname)
    if ($code -ne 0) { throw ('Nie cofnieto zaplanowanej zmiany nazwy; kod Windows=' + $code) }
}

function Assert-NoStagedRename([string]$Hostname) {
    # Returns $true when safe. A queued rename on a domain member would break
    # the repaired trust again at the next reboot.
    $state=Get-PendingRenameState (Read-WindowsNames) $Hostname
    if ($state.state -eq 'ok') { return $true }
    if ($state.state -eq 'inconsistent') {
        $script:FailureMessage='ZATRZYMANO: nazwy Windows sa niespojne (aktywna nazwa rozni sie miedzy NetBIOS/TCP/IP). Uruchom ponownie komputer i sprawdz nazwe przed naprawa.'
        return $false
    }
    $message="Windows ma zaplanowana zmiane nazwy na: $($state.pending)`n" +
        "To pozostalosc nieudanej proby odbudowy konta. Po restarcie komputer zmienilby nazwe, " +
        "a konto AD to nadal $Hostname - zaufanie znowu by sie zerwalo.`n`n" +
        "Cofnac zaplanowana zmiane i zostawic nazwe $($Hostname)?"
    if ([Windows.Forms.MessageBox]::Show($message,'SP2 - zaplanowana zmiana nazwy','YesNo','Warning') -ne 'Yes') {
        $script:FailureMessage='ZATRZYMANO: zaplanowana zmiana nazwy na ' + $state.pending + ' nie zostala cofnieta. Nie restartuj komputera przed jej wyjasnieniem.'
        return $false
    }
    Restore-StagedComputerName $Hostname
    $after=Get-PendingRenameState (Read-WindowsNames) $Hostname
    if ($after.state -ne 'ok') {
        $script:FailureMessage='ZATRZYMANO: nie potwierdzono cofniecia zmiany nazwy (' + $after.pending + '). Nie restartuj komputera.'
        return $false
    }
    Write-UiLog ('Nazwa: cofnieto zaplanowana zmiane na ' + $state.pending + '; po restarcie zostaje ' + $Hostname + '.')
    return $true
}

function Invoke-LocalSecureChannelRepair {
    # Returns: healthy | repaired | declined | failed | blocked
    $local=Get-LocalState
    if (-not $local.part_of_domain -or [string]$local.domain -ine 'sp2.lan') { return 'failed' }
    if (-not (Assert-NoStagedRename ([string]$local.hostname))) { return 'blocked' }
    if ($local.secure_channel -eq $true) { return 'healthy' }
    try { Ensure-DomainMemberTime }
    catch {
        Write-Crash 'DOMAIN_TIME_FAILED' $_
        Write-UiLog ('Czas: ' + $_.Exception.Message + ' Proba naprawy mimo to.')
    }
    $message="Komputer $($local.hostname) jest w domenie sp2.lan, ale zaufanie (secure channel) jest zerwane.`n`n" +
        "Program zresetuje haslo ISTNIEJACEGO konta $($local.hostname) w AD (Test-ComputerSecureChannel -Repair).`n" +
        "Nazwa, OU i SID pozostaja bez zmian. Bez odlaczania od domeny i bez restartu.`n`nNaprawic teraz?"
    if ([Windows.Forms.MessageBox]::Show($message,'SP2 - naprawa zaufania domeny','YesNo','Question') -ne 'Yes') {
        Write-UiLog 'Lokalna naprawa zaufania nie zostala zatwierdzona.'
        return 'declined'
    }
    $credential=Get-DomainCredential
    try {
        $ok=[bool](Test-ComputerSecureChannel -Server $script:DomainControllerFqdn -Repair -Credential $credential -ErrorAction Stop)
    } catch {
        Write-Crash 'LOCAL_CHANNEL_REPAIR_FAILED' $_
        $ok=$false
    } finally {
        if ($null -ne $script:Credential) { $script:Credential.Password.Dispose(); $script:Credential=$null }
    }
    if (-not $ok) {
        Write-UiLog 'Lokalna naprawa zaufania nie powiodla sie (konto AD moze nie istniec lub haslo/uprawnienia sa bledne).'
        return 'failed'
    }
    # Independent read-back; never trust only the repair's return value.
    Start-Sleep -Seconds 2
    $verified=$false
    try { $verified=[bool](Test-ComputerSecureChannel -Server $script:DomainControllerFqdn -ErrorAction Stop) } catch { }
    if (-not $verified -or (Get-LocalState).secure_channel -ne $true) {
        Write-UiLog 'Naprawa zglosila sukces, ale weryfikacja secure channel nie przeszla.'
        return 'failed'
    }
    try { Register-DnsClient -ErrorAction Stop } catch { Write-UiLog 'DNS: rejestracja rekordu nie zostala potwierdzona (nie blokuje).' }
    Write-UiLog ('Zaufanie domeny naprawione lokalnie: ' + $local.hostname + ' <-> ' + $script:DomainControllerFqdn + ' (secure channel OK).')
    return 'repaired'
}

function Test-PlanRecoveryAttempted($Plan) {
    return @(@(Get-PlanProperty $Plan 'history') | Where-Object {
        $null -ne $_ -and [string]$_.action -eq 'machine_account_recovery' -and
        [string]$_.event -in @('begin','credential_issued')
    }).Count -gt 0
}

function Resolve-StuckMachineRecovery($Plan) {
    # Returns $null when not applicable (caller keeps the old fail-closed path).
    if ($Plan.state -ne 'manual_review' -or -not (Test-PlanRecoveryAttempted $Plan)) { return $null }
    $local=Get-LocalState
    if (-not $local.part_of_domain -or [string]$local.hostname -ine [string]$Plan.source_name) { return $null }
    Write-UiLog ('AUTOMAT: Windows jest nadal w domenie jako ' + $local.hostname +
        '. Zamiast odbudowy konta jako ' + $Plan.target_name + ' wystarczy naprawa zaufania istniejacego konta.')
    $repair=Invoke-LocalSecureChannelRepair
    if ($repair -eq 'blocked') { return $script:FailureMessage }
    if ($repair -notin @('repaired','healthy')) { return $null }
    $resolveMessage="Zaufanie $($local.hostname) dziala.`n`nZamknac stary plan $($Plan.source_name) -> $($Plan.target_name) " +
        "i zwolnic rezerwacje $($Plan.target_name)?`nSerwer sam sprawdzi konto w AD (OU, SID, data zmiany hasla)."
    if ([Windows.Forms.MessageBox]::Show($resolveMessage,'SP2 - zamkniecie planu','YesNo','Question') -ne 'Yes') {
        return 'Zaufanie naprawione. Stary plan pozostaje otwarty (nie zatwierdzono zamkniecia).'
    }
    try { Set-Progress 'resolve' $true }
    catch {
        if ($script:LastHttpStatus -in @(400,404,405) -and -not $script:FailureMessage) {
            $script:FailureMessage='Serwer SP2 ADMIN nie obsluguje jeszcze zamykania planu po lokalnej naprawie. Zaufanie jest naprawione; zamknij plan w panelu.'
        }
        return ('Zaufanie naprawione, ale plan nie zostal zamkniety. ' + $script:FailureMessage)
    }
    if ([string]$script:State.plan.state -ne 'cancelled') {
        return ('Zaufanie naprawione, serwer nie potwierdzil zamkniecia planu (stan=' + $script:State.plan.state + ').')
    }
    Unregister-ScheduledTask -TaskName 'SP2-Domain-Recovery' -Confirm:$false -ErrorAction SilentlyContinue
    $script:State.token=''
    Save-State
    return ('GOTOWE: ' + $local.hostname + ' naprawiony lokalnie (secure channel OK). Stary plan zamkniety, nazwa ' +
        $Plan.target_name + ' zwolniona. Zalecane: gpupdate /force i logowanie kontem domenowym.')
}

function Run-RecoveryUntilStable {
    # Preserve every original SID check, safe transition, and confirmation.
    # Never auto-start join/unjoin/rename, or an unconfirmed retry.
    for ($pass=1; $pass -le 5; $pass++) {
        $result=Run-Recovery
        if ([string]$result -notmatch 'Nacisnij WZNOW') { return $result }
        $plan=$script:State.plan
        if ($null -eq $plan) { return $result }
        if ($plan.state -eq 'complete') { return (Complete-RecoveryClientState) }
        $continue=$false
        if ($plan.state -eq 'ready' -and $plan.action -in @('repair_ad_cn','repair_secure_channel')) {
            $continue=$true
        } elseif ($plan.state -eq 'manual_review' -and $plan.action -eq 'blocked' -and
            $plan.diagnosis.status -eq 'AD_METADATA_REVIEW') {
            $continue=$true
        }
        if (-not $continue) { return $result }
        Write-UiLog ('AUTOMAT: bezpieczne wznowienie kroku ' + ($pass+1) + '/5 bez nowego join.')
    }
    return 'Plan wymaga dalszej kontroli. Zatrzymano po 5 krokach, bez ponawiania join.'
}

function Run-Recovery {
    # Recover the latest committed version after a timeout or process crash.
    $script:State.plan = Invoke-Api ('status/' + $script:State.plan.id) $null 'GET'
    Save-State
    Write-UiLog ('Plan: stan=' + $script:State.plan.state + '; operacja=' + $script:State.plan.action + '; cel=' + $script:State.plan.target_name + '; OU=' + $script:State.plan.target_ou)
    if ($script:State.plan.state -eq 'complete') { return (Complete-RecoveryClientState) }
    if ($script:State.plan.state -eq 'cancelled') { return 'Plan anulowany.' }
    if ($script:State.plan.action -eq 'join') {
        $cloudPreflightLocal=Get-LocalState
        if ($cloudPreflightLocal.part_of_domain -eq $false) {
            Assert-WorkgroupNotCloudJoined
            if (Test-Path -LiteralPath $script:EntraModulePath) {
                Assert-PlanSchoolOu $script:State.plan
                Assert-SchoolAdReachability
                Assert-SchoolTime $true
            }
        }
    }
    Set-Progress 'observe'
    $plan = $script:State.plan
    if ((Test-Path -LiteralPath $script:EntraModulePath) -and
        (Assert-PostJoinDnsIdentity $plan (Get-LocalState))) {
        try {
            if (Repair-MissingSchoolDnsA $plan (Get-LocalState)) {
                # Re-read AD and authoritative DNS; never claim success from a
                # client cache or mark a recovery plan complete locally.
                Set-Progress 'observe'
                $plan=$script:State.plan
            }
        } catch {
            $script:FailureMessage='DNS SP2: automatyczna rejestracja nie zostala potwierdzona. Zweryfikuj rekord A na serwerze. Nie ponawiaj join.'
            Write-UiLog 'DNS SP2: naprawa nieudana. Plan zachowany, bez ponawiania dolaczenia do domeny.'
        }
    }
    $serverTime=[DateTimeOffset]::Parse($plan.server_time_utc)
    $skew=[Math]::Abs(([DateTimeOffset]::UtcNow-$serverTime).TotalSeconds)
    if ($skew -gt 240) { return 'ZATRZYMANO: zegar Windows rozni sie od SP2 ADMIN o ponad 4 minuty. Sprawdz czas serwera i synchronizacje Windows z kontrolerem domeny, potem WZNOW.' }
    if ($plan.state -eq 'complete') { return (Complete-RecoveryClientState) }
    # Stuck machine_account_recovery (even after join authorization): if Windows
    # is still the same domain member, repair the existing account's trust and
    # let the server verify AD before closing the plan. Never retries the join.
    $resolved=Resolve-StuckMachineRecovery $plan
    if ($null -ne $resolved) { return $resolved }
    if ($plan.state -eq 'manual_review' -and $plan.action -eq 'join') {
        return (Reconcile-UnconfirmedWorkgroupJoin $plan)
    }
    if ($plan.state -eq 'manual_review' -and $plan.action -eq 'repair_secure_channel') {
        Write-UiLog 'Poprzednia proba naprawy zaufania nie zostala potwierdzona. Serwer ponownie sprawdzi konto AD przed ponowieniem.'
        $retryMessage="Poprzednia naprawa zaufania nie zostala potwierdzona.`nZatwierdzic nowa probe naprawy kanalu dla $($plan.source_name)?`nDocelowa nazwa pozostaje $($plan.target_name)."
        if ([Windows.Forms.MessageBox]::Show($retryMessage,'Ponowienie naprawy zaufania','YesNo','Warning') -ne 'Yes') { return 'Nie zatwierdzono ponowienia naprawy.' }
        Set-Progress 'retry' $true
        $plan=$script:State.plan
    }
    if ($plan.state -eq 'manual_review' -and $plan.action -eq 'machine_account_recovery') {
        if (Test-JoinAuthorizationRecorded $plan) {
            Write-UiLog 'ZATRZYMANO: serwer wydal juz autoryzacje joinu. Nie wolno powtarzac operacji bez sprawdzenia wyniku Windows i AD.'
            return 'Join niepotwierdzony. Sprawdz C:\Windows\Debug\NetSetup.log i stan konta docelowego AD; rezerwacja zostala zachowana.'
        }
        Write-UiLog 'Poprzednia odbudowa konta zatrzymala sie przed autoryzacja joinu. Serwer sprawdzi, czy mozna bezpiecznie rozpoczac nowa probe.'
        $retryMessage="Poprzednia odbudowa konta komputera nie zostala zakonczona.`nSerwer zezwoli na ponowienie tylko wtedy, gdy nie wydano jeszcze autoryzacji joinu.`nZatwierdzic ponowna probe dla $($plan.source_name) -> $($plan.target_name)?"
        if ([Windows.Forms.MessageBox]::Show($retryMessage,'Ponowienie odbudowy konta','YesNo','Warning') -ne 'Yes') { return 'Nie zatwierdzono ponowienia odbudowy konta.' }
        Set-Progress 'retry' $true
        $plan=$script:State.plan
    }
    if ($plan.state -ne 'ready' -or $plan.action -in @('blocked','blocked_conflict','diagnose')) {
        $hint=''
        if (@(Get-PlanCancelBlockers $plan $null).Count -eq 0) {
            $hint=' Jesli wybrano bledna nazwe/sale, kliknij ANULUJ PLAN (bezpieczne - plan nie zostal rozpoczety).'
        }
        return ('ZATRZYMANO: ' + $plan.diagnosis.status + '. Sprawdz AD i stan komputera. Nie ponawiaj unjoin w ciemno.' + $hint)
    }
    if ($plan.action -eq 'join' -and -not (Test-JoinLocalNamePreflight $plan)) {
        return 'ZATRZYMANO: niespojne nazwy Windows. Plan i rezerwacja pozostaja bez zmian; bez join.'
    }
    $message = "Operacja: $($plan.action)`n$($plan.source_name) -> $($plan.target_name)`nOU: $($plan.target_ou)`n`n" +
        "TAK - wykonaj operacje`n" +
        "NIE - nazwa/sala jest bledna: anuluj plan i zwolnij rezerwacje nazwy`n" +
        "ANULUJ - nic nie zmieniaj (plan zostaje zarezerwowany)"
    $decision=[Windows.Forms.MessageBox]::Show($message,'Plan naprawy','YesNoCancel','Warning')
    if ($decision -eq 'No') {
        if (Cancel-PlanBeforeStart 'operator_rejected_target_name' $true) {
            return 'Plan anulowany, nazwa zwolniona. Popraw typ/budynek/sale/numer i kliknij NAPRAW TEN KOMPUTER (lub ZMIEN NAZWE).'
        }
        return 'Nie anulowano planu - szczegoly powyzej. Nie wykonano operacji.'
    }
    if ($decision -ne 'Yes') { return 'Nie wykonano operacji. Plan i rezerwacja pozostaja bez zmian.' }
    if ($plan.action -eq 'repair_ad_cn') {
        $details = "Serwer zmieni CN istniejacego obiektu AD:`n$($plan.diagnosis.source_ad.dn)`nna CN=$($plan.source_name) w tym samym OU.`nGUID/SID zostana zachowane. Zatwierdzic?"
        if ([Windows.Forms.MessageBox]::Show($details,'Zatwierdzenie zmiany AD','YesNo','Warning') -ne 'Yes') { return 'Nie zatwierdzono zmiany AD.' }
        $script:State.plan = Invoke-Api ('approve-ad/' + $plan.id) @{version=$plan.version;device_id=$script:State.device_id;local=(Get-LocalState);approved=$true}
        Save-State
        Set-Progress 'observe'
        return 'Serwer sprawdzil korekte AD. Nacisnij WZNOW, aby zatwierdzic kolejny etap naprawy kanalu.'
    }
    if ($plan.action -in @('recovery_to_workgroup','machine_account_recovery')) {
        Ensure-LocalAdministrator
        $check = [Windows.Forms.MessageBox]::Show('Potwierdz, ze sprawdziles logowanie na dzialajace lokalne konto administratora i znasz jego haslo. Po odpieciu domeny bedzie potrzebne.','Dostep po restarcie','YesNo','Warning')
        if ($check -ne 'Yes') { return 'Przerwano przed odlaczeniem domeny.' }
    }
    if ($plan.action -in @('join','machine_account_recovery')) { Ensure-LocalAdministrator }
    $script:Credential = Get-DomainCredential
    try {
        Install-Resume
        # Write-ahead checkpoint: ambiguous outcomes never automatically repeat.
        Set-Progress 'begin'
        if ($plan.action -eq 'machine_account_recovery') {
            Authorize-RecoveryJoin
            $script:State.plan=Invoke-Api ('status/' + $plan.id) $null 'GET'
            Save-State
        }
        switch ($plan.action) {
            'machine_account_recovery' { Invoke-MachineAccountRecovery $plan $script:Credential }
            'repair_secure_channel' {
                $ok = Test-ComputerSecureChannel -Repair -Credential $script:Credential -ErrorAction Stop
                if (-not $ok) { throw 'Nie udalo sie naprawic kanalu.' }
            }
            'rename_domain' { Rename-Computer -NewName $plan.target_name -DomainCredential $script:Credential -Force -ErrorAction Stop }
            'recovery_to_workgroup' { Remove-Computer -UnjoinDomainCredential $script:Credential -WorkgroupName 'WORKGROUP' -Force -ErrorAction Stop }
            'join' {
                $joinArguments=@{DomainName=$plan.domain;OUPath=$plan.target_ou;Credential=$script:Credential;Force=$true;ErrorAction='Stop'}
                if ($env:COMPUTERNAME -ine $plan.target_name) { $joinArguments.NewName=$plan.target_name }
                Add-Computer @joinArguments
            }
            default { throw 'Nieobslugiwana operacja.' }
        }
    } catch {
        Write-Crash 'LOCAL_OPERATION_FAILED' $_
        if ($plan.action -eq 'join') { Report-UnconfirmedWorkgroupJoin $plan }
        if ($plan.action -eq 'machine_account_recovery') {
            # Read back the credential-delivery version before reporting failure.
            try {
                $script:State.plan=Invoke-Api ('status/' + $plan.id) $null 'GET'
                Set-Progress 'failed'
            } catch { }
            $script:FailureMessage='Join niepotwierdzony. Zachowano rezerwacje; WZNOW sprawdzi wynik bez ponawiania joinu. Nie zmieniaj NTLM ani konta AD.'
        }
        $errorText=[string]$_.Exception.Message
        if ($plan.action -eq 'recovery_to_workgroup' -and $errorText -match 'NTLM|uwierzytelnianie NTLM') {
            try { Set-Progress 'failed' } catch { }
            $script:FailureMessage='ZATRZYMANO: Windows blokuje standardowe odlaczenie od domeny, poniewaz NTLM jest wylaczone. Program nie wlacza NTLM i nie ponawia unjoin automatycznie. Plan oznaczono do recznej weryfikacji.'
        }
        if ([string]$_.FullyQualifiedErrorId -like 'CannotFindMachineAccount*') {
            $script:FailureMessage='Windows nie znajduje konta komputera (CannotFindMachineAccount). Zachowano plan. WZNOW ponownie sprawdzi konto i CN/DN przez serwer; nie odlaczaj domeny recznie.'
        }
        # Leave server pending: operation may have succeeded before a local error.
        throw 'Operacja niepotwierdzona. Zachowano recovery; po kontroli stanu uruchom WZNOW. Szczegoly: crash.log.'
    }
    finally {
        if ($null -ne $script:Credential) { $script:Credential.Password.Dispose(); $script:Credential=$null }
    }
    if ($plan.action -eq 'repair_secure_channel') {
        Set-Progress 'observe'
        return 'Kanal sprawdzony. Nacisnij WZNOW, aby wykonac kolejny etap planu.'
    }
    if ([Windows.Forms.MessageBox]::Show('Zapisano recovery. Uruchomic komputer ponownie teraz?','Restart wymagany','YesNo','Question') -eq 'Yes') { Restart-Computer -Force }
    return 'Wymagany restart. Po zalogowaniu na lokalnego administratora wznow recovery.'
}

function Show-RepairForm {
    $form = New-Object Windows.Forms.Form
    $form.Text = 'SP2 Serwis Domeny 2.0 - OBCHÓD SAL – NAPRAW TEN KOMPUTER'
    $form.Size = New-Object Drawing.Size(740,650)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $fields = @{}
    $labels = @('Serwer SP2 ADMIN HTTPS','Token/kod (puste = automatycznie)','OU (puste = automatycznie)','Typ komputera','Budynek','Sala (1-999)','Nr (0 = jedyny nauczyciel)')
    for ($i=0; $i -lt $labels.Count; $i++) {
        $label = New-Object Windows.Forms.Label
        $label.Text=$labels[$i]; $label.Location=New-Object Drawing.Point(20,(25+$i*43)); $label.Size=New-Object Drawing.Size(240,25)
        $form.Controls.Add($label)
        if ($i -in @(3,4)) {
            $input = New-Object Windows.Forms.ComboBox
            $input.DropDownStyle='DropDownList'
            if ($i -eq 3) { $input.Items.AddRange(@('Nauczyciel','Uczen')) } else { $input.Items.AddRange(@('BR','PL')) }
            $input.SelectedIndex=0
        } else { $input=New-Object Windows.Forms.TextBox }
        $input.Location=New-Object Drawing.Point(270,(22+$i*43)); $input.Size=New-Object Drawing.Size(420,26)
        if ($i -eq 1) { $input.UseSystemPasswordChar=$true }
        $fields[$i]=$input; $form.Controls.Add($input)
    }
    $fields[5].Text='30'; $fields[6].Text='0'
    if (-not $SelfTest) { $script:AgentConfig = Read-AgentConfig }
    if ($null -ne $script:AgentConfig) { $fields[0].Text=[string]$script:AgentConfig.server_url }
    if (-not $SelfTest) { $script:DeploymentConfig = Read-DeploymentConfig }
    if ($null -eq $script:AgentConfig -and $null -ne $script:DeploymentConfig) { $fields[0].Text=[string]$script:DeploymentConfig.server_url }
    $fields[0].Text=Resolve-ServerEndpoint
    $enroll = New-Object Windows.Forms.CheckBox
    $enroll.Text='Podany sekret to kod enrollment (nowy agent)'; $enroll.Location=New-Object Drawing.Point(270,325); $enroll.Size=New-Object Drawing.Size(430,25)
    $form.Controls.Add($enroll)
    $status = New-Object Windows.Forms.TextBox
    $script:LogControl=$status
    $status.ScrollBars='Vertical'
    $status.Multiline=$true; $status.ReadOnly=$true; $status.Location=New-Object Drawing.Point(20,430); $status.Size=New-Object Drawing.Size(670,160)
    Write-UiLog ('OBCHOD SAL - NAPRAW TEN KOMPUTER. Urzadzenie rozpoznawane po UUID i MAC. Serwer zarezerwuje nastepna wolna nazwe w sali. Login domenowy: Administrator@SP2.LAN; haslo tylko w pamieci sesji.')
    $form.Controls.Add($status)
    $preview = New-Object Windows.Forms.Label
    $preview.Location=New-Object Drawing.Point(20,328); $preview.Size=New-Object Drawing.Size(245,25)
    $preview.Font=New-Object Drawing.Font($form.Font,[Drawing.FontStyle]::Bold)
    $form.Controls.Add($preview)
    $updatePreview = {
        try {
            $preview.ForeColor=[Drawing.Color]::DarkGreen
            $preview.Text='Nazwa: ' + (Get-TargetName $fields[3].Text $fields[4].Text ([int]$fields[5].Text) ([int]$fields[6].Text))
        } catch {
            $preview.ForeColor=[Drawing.Color]::DarkRed
            $preview.Text='Nazwa: nieprawidlowe dane'
        }
    }
    $fields[3].Add_SelectedIndexChanged($updatePreview)
    $fields[4].Add_SelectedIndexChanged($updatePreview)
    $fields[5].Add_TextChanged($updatePreview)
    $fields[6].Add_TextChanged($updatePreview)
    & $updatePreview

    $start = New-Object Windows.Forms.Button
    $start.Text='NAPRAW TEN KOMPUTER'; $start.Location=New-Object Drawing.Point(20,375); $start.Size=New-Object Drawing.Size(165,38)
    $renameButton=New-Object Windows.Forms.Button
    $renameButton.Text='ZMIEN NAZWE'; $renameButton.Location=New-Object Drawing.Point(195,375); $renameButton.Size=New-Object Drawing.Size(160,38)
    $cancelButton=New-Object Windows.Forms.Button
    $cancelButton.Text='ANULUJ PLAN (bledna nazwa)'; $cancelButton.Location=New-Object Drawing.Point(365,375); $cancelButton.Size=New-Object Drawing.Size(160,38)
    $resumeButton=New-Object Windows.Forms.Button
    $resumeButton.Text='WZNOW RECOVERY'; $resumeButton.Location=New-Object Drawing.Point(535,375); $resumeButton.Size=New-Object Drawing.Size(155,38)
    $form.Controls.AddRange(@($start,$renameButton,$cancelButton,$resumeButton))
    $tips=New-Object Windows.Forms.ToolTip
    $tips.SetToolTip($renameButton,'Rezerwuje DOKLADNIE nazwe z podgladu. Stary, nierozpoczety plan zostanie anulowany po potwierdzeniu.')
    $tips.SetToolTip($cancelButton,'Anuluje plan, ktory nie zostal jeszcze rozpoczety, i zwalnia rezerwacje nazwy. Nie zmienia Windows ani AD.')
    $setButtons = { param([bool]$On) foreach ($b in @($start,$renameButton,$cancelButton,$resumeButton)) { $b.Enabled=$On } }

    # Wspolny przebieg NAPRAW / ZMIEN NAZWE. ExactName=$true wylacza auto_name:
    # serwer rezerwuje dokladnie wskazana nazwe albo odmawia.
    $startFlow = {
        param([bool]$ExactName)
        & $setButtons $false
        try {
            $script:FailureMessage=''
            # Walidacja wyboru przed jakakolwiek zmiana systemu lub zapytaniem.
            $target=Get-TargetName $fields[3].Text $fields[4].Text ([int]$fields[5].Text) ([int]$fields[6].Text)
            Ensure-SecondaryDomainDns
            $local=Get-LocalState
            $script:Endpoint=$fields[0].Text.Trim().TrimEnd('/')
            $transition=$null
            if (-not $local.part_of_domain -and (Test-Path -LiteralPath $script:EntraModulePath)) {
                $transition=Read-EntraTransition
                if ($null -ne $transition) {
                    Assert-EntraTransitionReady $transition
                } elseif (Get-CloudJoinFlag) {
                    [void](Get-TargetName $fields[3].Text $fields[4].Text ([int]$fields[5].Text) ([int]$fields[6].Text))
                    if ($fields[2].Text.Trim()) {
                        Assert-SelectedSchoolOu $fields[3].Text ([int]$fields[5].Text) $fields[2].Text.Trim()
                    }
                    Assert-ServerCapabilities
                    $selection=@{
                        endpoint=$script:Endpoint; kind=$fields[3].Text; building=$fields[4].Text
                        room=[int]$fields[5].Text; number=[int]$fields[6].Text; ou=$fields[2].Text.Trim()
                    }
                    Write-UiLog (Invoke-AutomaticEntraDetach $selection $local)
                    return
                }
            }
            if (-not $local.part_of_domain) { Assert-WorkgroupNotCloudJoined }
            Write-UiLog ('Diagnoza lokalna: {0}; w domenie: {1}; domena: {2}; secure channel: {3}. Laczenie z SP2 ADMIN...' -f $local.hostname,$local.part_of_domain,$local.domain,$local.secure_channel)
            $status.Refresh()
            $script:Endpoint=$fields[0].Text.Trim().TrimEnd('/')
            $manualToken=$fields[1].Text.Trim()
            $fields[1].Clear()
            Assert-ServerCapabilities
            if (-not $local.part_of_domain -and (Test-Path -LiteralPath $script:EntraModulePath)) {
                Assert-SchoolAdReachability
                Assert-SchoolTime $true
            }
            $pending=Resolve-Authentication $manualToken $enroll.Checked
            $manualToken=''
            $device=Get-DeviceId
            $requestId=[Guid]::NewGuid().ToString()
            # Persist token and request ID before plan POST, including enrollment.
            $protected=Protect-AgentToken $script:Token
            $script:State=@{endpoint=$script:Endpoint;token=$protected;device_id=$device;plan=$null;request_id=$requestId;target_name=$target;target_ou=$fields[2].Text.Trim();auto_name=(-not $ExactName)}
            Save-State
            $script:State.plan=$pending.plan
            if ($null -ne $script:State.plan -and $script:State.plan.device_id -ne $device) { throw 'Serwer zwrocil plan innego urzadzenia. Operacja zablokowana.' }
            Save-State
            # Istniejacy plan na serwerze a nowy wybor operatora (bledna nazwa / zmiana nazwy).
            if ($null -ne $script:State.plan -and $null -eq $transition) {
                $existingPlan=$script:State.plan
                $mismatch=Test-PlanSelectionMismatch $existingPlan $target $fields[2].Text.Trim() $ExactName
                if ($existingPlan.state -eq 'cancelled') {
                    $script:State.plan=$null; Save-State
                } elseif ($existingPlan.state -eq 'complete') {
                    if ($mismatch) {
                        Write-UiLog ('Poprzedni plan (' + $existingPlan.target_name + ') jest zakonczony. Nowy plan dla nazwy ' + $target + '.')
                        $script:State.plan=$null; Save-State
                    }
                } elseif ($mismatch) {
                    $blockers=@(Get-PlanCancelBlockers $existingPlan $local)
                    if ($blockers.Count -gt 0) {
                        foreach ($b in $blockers) { Write-UiLog ('Nie mozna zmienic nazwy planu: ' + $b) }
                        Write-UiLog ('Serwer ma juz rozpoczety plan ' + $existingPlan.source_name + ' -> ' + $existingPlan.target_name + '. Uzyj WZNOW RECOVERY; nie zmieniono nazwy.')
                        return
                    }
                    $question="Na serwerze jest juz plan dla tego komputera:" + [Environment]::NewLine +
                        "  $($existingPlan.source_name) -> $($existingPlan.target_name)" + [Environment]::NewLine +
                        "  OU: $($existingPlan.target_ou)" + [Environment]::NewLine + [Environment]::NewLine +
                        "Teraz wybrano: $target" + [Environment]::NewLine + [Environment]::NewLine +
                        "Plan nie zostal rozpoczety (Windows i AD bez zmian)." + [Environment]::NewLine +
                        "Anulowac stary plan, zwolnic nazwe $($existingPlan.target_name) i zarezerwowac nowa?"
                    $answer=[Windows.Forms.MessageBox]::Show($question,'SP2 - zmiana nazwy w planie','YesNoCancel','Question')
                    if ($answer -eq 'Yes') {
                        if (-not (Cancel-PlanBeforeStart 'operator_changed_target_name' $true)) {
                            Write-UiLog 'ZATRZYMANO: nie anulowano starego planu, wiec nie rezerwuje nowej nazwy.'
                            return
                        }
                        $script:State.target_name=$target
                        $script:State.target_ou=$fields[2].Text.Trim()
                        $script:State.auto_name=(-not $ExactName)
                        Save-State
                    } elseif ($answer -eq 'No' -and -not $ExactName) {
                        Write-UiLog ('Kontynuacja istniejacego planu ' + $existingPlan.target_name + '.')
                    } else {
                        Write-UiLog 'Przerwano. Plan i rezerwacja bez zmian.'
                        return
                    }
                }
            }
            if ($null -ne $transition -and $null -ne $script:State.plan) {
                Reconcile-PreviousCloudJoin
            }
            if ($null -eq $script:State.plan -and $null -eq $transition -and
                $local.part_of_domain -and $local.secure_channel -eq $false) {
                # Broken trust on an existing domain member: repair the SAME
                # account first. Only if that fails does the server plan an
                # account rebuild (which reserves a new name).
                $repair=Invoke-LocalSecureChannelRepair
                if ($repair -eq 'blocked') { Write-UiLog $script:FailureMessage; return }
                if ($repair -eq 'repaired') {
                    $local=Get-LocalState
                    $room=Get-TargetGroupPrefix ([string]$local.hostname)
                    if (-not $ExactName -and $room -and $room -ieq (Get-TargetGroupPrefix $target)) {
                        Unregister-ScheduledTask -TaskName 'SP2-Domain-Recovery' -Confirm:$false -ErrorAction SilentlyContinue
                        Write-UiLog ('GOTOWE: ' + $local.hostname + ' naprawiony lokalnie, nazwa zgodna z sala. Nie utworzono planu ani rezerwacji.')
                        return
                    }
                    Write-UiLog 'Zaufanie naprawione. Kontynuacja: plan zmiany nazwy zgodnie z wybrana sala/numerem.'
                } else {
                    Write-UiLog 'Lokalna naprawa niemozliwa lub odrzucona. Serwer zaplanuje odbudowe konta.'
                }
            }
            if ($null -eq $script:State.plan) {
                if (-not $script:State.target_ou) {
                    $configuration=Invoke-Api 'config' $null 'GET'
                    if ($fields[3].Text -eq 'Nauczyciel') {
                        $candidates=@($configuration.ous | Where-Object { $_ -eq $configuration.teacher_ou })
                    } else {
                        $room=[int]$fields[5].Text
                        $candidates=@($configuration.ous | Where-Object { $_ -match ('^OU=(?:Sala0*|S0*)' + $room + ',') })
                    }
                    if ($candidates.Count -ne 1) { throw 'Nie znaleziono jednoznacznego OU; podaj je w polu OU.' }
                    $script:State.target_ou=[string]$candidates[0]
                    $fields[2].Text=$script:State.target_ou
                    Save-State
                }
                if (Test-Path -LiteralPath $script:EntraModulePath) {
                    Assert-SelectedSchoolOu $fields[3].Text ([int]$fields[5].Text) $script:State.target_ou
                }
                # Ostatnia kontrola operatora PRZED rezerwacja nazwy na serwerze.
                $confirm="Serwer zarezerwuje dla tego komputera nazwe:" + [Environment]::NewLine + [Environment]::NewLine +
                    "        $target" + [Environment]::NewLine + [Environment]::NewLine +
                    "Obecna nazwa Windows: $($local.hostname)" + [Environment]::NewLine +
                    "OU: $($script:State.target_ou)" + [Environment]::NewLine
                if ($ExactName) {
                    $confirm+="Tryb ZMIEN NAZWE: dokladnie ta nazwa (jesli zajeta - serwer odmowi)." + [Environment]::NewLine
                    if ($local.part_of_domain) {
                        $confirm+="Komputer jest w domenie: po zatwierdzeniu planu Windows zmieni nazwe w AD i bedzie wymagany restart." + [Environment]::NewLine
                    }
                } else {
                    $confirm+="Jesli numer jest zajety, serwer wybierze nastepny wolny w tej sali." + [Environment]::NewLine
                }
                $confirm+=[Environment]::NewLine + "Sprawdz typ, budynek, sale i numer. Zarezerwowac?"
                if ([Windows.Forms.MessageBox]::Show($confirm,'SP2 - potwierdzenie nazwy','YesNo','Question') -ne 'Yes') {
                    Write-UiLog 'Nie zarezerwowano nazwy. Popraw dane i sprobuj ponownie.'
                    return
                }
                Write-UiLog 'Serwer sprawdza dostepnosc nazwy oraz rezerwuje wybrana nazwe dla tego planu.'
                $script:State.plan=Request-RecoveryPlan @{request_id=$script:State.request_id;device_id=$device;local=(Get-LocalState);target_name=$target;target_ou=$script:State.target_ou;auto_name=[bool]$script:State.auto_name}
                Save-State
            }
            if ($null -ne $transition -and $null -ne $script:State.plan) {
                # Entra phase is complete as soon as the new valid domain plan
                # is recorded. The plan itself has independent durable resume.
                Complete-EntraTransition
            }
            Write-UiLog (Run-RecoveryUntilStable)
        } catch {
            Write-Crash 'START_FAILED' $_
            if ($script:FailureMessage) { Write-UiLog ($script:FailureMessage) }
            else { Write-UiLog ('ZATRZYMANO. ' + $script:LastApiStatus + '. Sprawdz stan planu i OU; autoryzacja jest automatyczna.') }
        }
        finally { $script:Token=''; & $setButtons $true }
    }
    $start.Add_Click({ & $startFlow $false })
    $renameButton.Add_Click({ & $startFlow $true })

    $cancelButton.Add_Click({
        & $setButtons $false
        try {
            $script:FailureMessage=''
            if (Test-Path -LiteralPath $script:StatePath) {
                $script:State=Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json
                if ($script:State.device_id -ne (Get-DeviceId)) { throw 'Zapisany plan pochodzi z innego komputera.' }
                $script:Endpoint=[string]$script:State.endpoint
            } else {
                $script:Endpoint=$fields[0].Text.Trim().TrimEnd('/')
                $script:State=@{endpoint=$script:Endpoint;token='';device_id=(Get-DeviceId);plan=$null;request_id=[Guid]::NewGuid().ToString();target_name='';target_ou='';auto_name=$true}
            }
            Assert-ServerCapabilities
            $saved=''
            if ($script:State.token) {
                try { $saved=Unprotect-AgentToken $script:State.token } catch { $saved='' }
            }
            if (-not $saved) { $saved=$fields[1].Text.Trim(); $fields[1].Clear() }
            $identified=Resolve-Authentication $saved $false
            $saved=''
            $script:State.device_id=$identified.device_id
            $script:State.plan=$identified.plan
            $script:State.token=Protect-AgentToken $script:Token
            Save-State
            if ($null -eq $script:State.plan -or $script:State.plan.state -in @('cancelled','complete')) {
                if ($null -ne $script:State.plan -and $script:State.plan.state -eq 'cancelled') { $script:State.plan=$null; Save-State }
                Write-UiLog 'Brak aktywnego planu do anulowania. Mozesz wybrac sale/numer i kliknac NAPRAW TEN KOMPUTER.'
                return
            }
            $script:State.plan=Invoke-Api ('status/' + $script:State.plan.id) $null 'GET'
            Save-State
            $plan=$script:State.plan
            Write-UiLog ('Plan na serwerze: stan=' + $plan.state + '; operacja=' + $plan.action + '; ' + $plan.source_name + ' -> ' + $plan.target_name)
            $begun=@(@($plan.history) | Where-Object { $null -ne $_ -and $_.event -eq 'begin' }).Count -gt 0
            if ($plan.state -eq 'manual_review' -and $plan.action -eq 'join' -and $begun) {
                # Join juz rozpoczety: tylko istniejaca, kontrolowana sciezka
                # wycofania po restarcie (bez ponawiania Add-Computer).
                Set-Progress 'observe'
                Write-UiLog (Reconcile-UnconfirmedWorkgroupJoin $script:State.plan)
                return
            }
            if (Cancel-PlanBeforeStart 'operator_cancelled_wrong_name' $false) {
                Write-UiLog 'Wybierz poprawny typ/budynek/sale/numer i kliknij NAPRAW TEN KOMPUTER albo ZMIEN NAZWE.'
            } elseif (@(Get-PlanCancelBlockers $script:State.plan (Get-LocalState)).Count -gt 0) {
                Write-UiLog 'Tego planu nie mozna anulowac z programu (zostal rozpoczety). Uzyj WZNOW RECOVERY albo sprawdz plan w panelu SP2 ADMIN.'
            }
        } catch {
            Write-Crash 'CANCEL_FAILED' $_
            if ($script:FailureMessage) { Write-UiLog $script:FailureMessage }
            else { Write-UiLog ('Nie anulowano planu. ' + $script:LastApiStatus + '. Rezerwacja zachowana.') }
        }
        finally { $script:Token=''; & $setButtons $true }
    })

    $resumeButton.Add_Click({
        & $setButtons $false
        try {
            $script:FailureMessage=''
            if (Test-Path -LiteralPath $script:EntraModulePath) {
                $transition=Read-EntraTransition
                if ($null -ne $transition) { Assert-EntraTransitionReady $transition }
            }
            $script:State=Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json
            if ($script:State.device_id -ne (Get-DeviceId)) { throw 'Recovery pochodzi z innego komputera.' }
            $script:Endpoint=$script:State.endpoint
            Assert-ServerCapabilities
            if ($script:State.token) {
                try { $script:Token=Unprotect-AgentToken $script:State.token } catch { $script:Token='' }
            } else { $script:Token=$fields[1].Text.Trim() }
            $existing=$script:Token
            $identified=Resolve-Authentication $existing $false
            if ($script:State.plan -and $script:State.plan.device_id -ne $identified.device_id) {
                Write-UiLog 'Lokalnie zapisano plan innego urzadzenia. Wybierz sale i kliknij NAPRAW TEN KOMPUTER, aby utworzyc wlasny plan.'
                return
            }
            $previousPlan=$script:State.plan
            $script:State.device_id=$identified.device_id
            $script:State.plan=$identified.plan
            $existing=''
            $script:State.token=Protect-AgentToken $script:Token
            Save-State
            if ($null -eq $script:State.plan) {
                if ($null -ne $previousPlan) {
                    if (-not $previousPlan.PSObject.Properties['id'] -or -not $previousPlan.id) {
                        throw 'Poprzedni plan nie ma identyfikatora. Nie utworzono nowego planu.'
                    }
                    # /identify returns only active plans. A completed plan is
                    # intentionally absent: check its exact ID read-only.
                    $historical=Invoke-Api ('status/' + $previousPlan.id) $null 'GET'
                    $script:State.plan=$historical
                    Save-State
                    if ($historical.state -eq 'complete') {
                        Write-UiLog (Complete-RecoveryClientState)
                        return
                    }
                    if ($historical.state -eq 'cancelled') {
                        Write-UiLog 'Poprzedni plan jest anulowany na serwerze. WZNOW nie tworzy nowego planu.'
                        return
                    }
                    Write-UiLog ('ZATRZYMANO: nie ma aktywnego planu, a poprzedni ma stan ' + $historical.state + '. Bez nowego join.')
                    return
                }
                $localResume=Get-LocalState
                if (-not (Test-ResumeMayCreatePlan $localResume $previousPlan $identified.plan)) {
                    Write-UiLog 'BRAK AKTYWNEGO PLANU: WZNOW nie tworzy nowej operacji dla komputera domenowego. Sprawdz stan Windows i AD.'
                    return
                }
                if (-not $script:State.request_id -or -not $script:State.target_name -or -not $script:State.target_ou) {
                    Write-UiLog 'BRAK ZAPISANEGO PLANU: nie ma danych do bezpiecznego wznowienia. Uzyj NAPRAW TEN KOMPUTER dla nowego zadania.'
                    return
                }
                # Only restore an interrupted first plan for a workgroup device.
                $autoName=$false
                if ($script:State.PSObject.Properties['auto_name']) { $autoName=[bool]$script:State.auto_name }
                $script:State.plan=Request-RecoveryPlan @{request_id=$script:State.request_id;device_id=$script:State.device_id;local=$localResume;target_name=$script:State.target_name;target_ou=$script:State.target_ou;auto_name=$autoName}
                Save-State
            }
            Write-UiLog (Run-RecoveryUntilStable)
        } catch { Write-Crash 'RESUME_FAILED' $_; if ($script:FailureMessage) { Write-UiLog $script:FailureMessage } else { Write-UiLog ('Nie wznowiono. ' + $script:LastApiStatus + '. Sprawdz stan planu.') } }
        finally { $script:Token=''; & $setButtons $true }
    })
    if ($Resume) {
        $transition=$null
        if (Test-Path -LiteralPath $script:EntraModulePath) { $transition=Read-EntraTransition }
        if ($null -ne $transition) {
            $fields[0].Text=[string]$transition.endpoint
            $fields[2].Text=[string]$transition.ou
            $fields[3].SelectedItem=[string]$transition.kind
            $fields[4].SelectedItem=[string]$transition.building
            $fields[5].Text=[string]$transition.room
            $fields[6].Text=[string]$transition.number
            Write-UiLog 'Entra: wznowienie po restarcie. Wymagane lokalne logowanie jako .\SP2. Haslo domenowe podaj w oknie Windows.'
            $form.Add_Shown({
                try {
                    Assert-EntraTransitionReady $transition
                    $start.PerformClick()
                } catch {
                    Write-Crash 'ENTRA_RESUME_BLOCKED' $_
                    Write-UiLog ('Nie wznowiono migracji Entra: ' + $_.Exception.Message)
                }
            })
        } else {
            Write-UiLog 'Wykryto uruchomienie po restarcie. Nacisnij WZNOW RECOVERY. Haslo domenowe trzeba podac ponownie.'
        }
    }
    if ($SelfTest) {
        if ($form.Controls.Count -lt 15) { throw 'GUI controls missing' }
        $form.Dispose()
    } else { [void]$form.ShowDialog() }
}

if ($LibraryOnly) { return }
if ($SelfTest) {
    if ((Get-TargetName 'Nauczyciel' 'BR' 30 0) -ne 'BR-S30') { throw 'Naming test failed' }
    if ((Get-TargetName 'Nauczyciel' 'PL' 4 1) -ne 'PL-S04-01') { throw 'Naming test failed' }
    if ((Get-TargetName 'Uczen' 'BR' 4 9) -ne 'S04-09') { throw 'Naming test failed' }
    if ((Get-TargetGroupPrefix 'S07-03') -ne 'S07' -or (Get-TargetGroupPrefix 'BR-S30-01') -ne 'BR-S30') { throw 'Prefix test failed' }
    $testPlan=[pscustomobject]@{state='ready';action='join';source_name='PC';target_name='S07-03';target_ou='';device_id='';history=@([pscustomobject]@{event='observe'})}
    if (@(Get-PlanCancelBlockers $testPlan @{hostname='PC'}).Count -ne 0) { throw 'Cancel test failed (ready)' }
    $testPlan.history=@([pscustomobject]@{event='begin'})
    if (@(Get-PlanCancelBlockers $testPlan @{hostname='PC'}).Count -eq 0) { throw 'Cancel test failed (begin)' }
    if (-not (Test-PlanSelectionMismatch $testPlan 'S11-03' '' $false) -or (Test-PlanSelectionMismatch $testPlan 'S07-04' '' $false)) { throw 'Mismatch test failed' }
    Show-RepairForm
    $probe=Protect-AgentToken 'self-test-not-a-real-token'
    if ((Unprotect-AgentToken $probe) -ne 'self-test-not-a-real-token') { throw 'DPAPI test failed' }
    Write-Output 'SELFTEST OK: naming, GUI construction, machine DPAPI; no AD, network, storage or restart operations.'
    exit 0
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Uruchom launcher jako administrator.' }
$mutex=$null
try {
    $mutex=New-Object Threading.Mutex($false,'Global\SP2-Domain-Recovery-v2') -ErrorAction Stop
} catch {
    # The existing mutex can be owned by an SP2 process running under another
    # security context. Never change its ACL or delete saved recovery state.
    [void][Windows.Forms.MessageBox]::Show(
        'Brak dostepu do blokady SP2 Serwis Domeny. Program moze juz dzialac w innym kontekscie administratora. Zamknij stare okna SP2, zaloguj sie na to samo konto administratora i uruchom ponownie. Nie zmieniaj ACL ProgramData ani nie usuwaj pending.json.',
        'SP2 Serwis Domeny - odmowa dostepu', 'OK', 'Warning')
    exit 13
}
$ownsMutex=$false
try {
    try { $ownsMutex=$mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $ownsMutex=$true }
    if (-not $ownsMutex) {
        [void][Windows.Forms.MessageBox]::Show(
            'SP2 Serwis Domeny jest juz uruchomiony (byc moze w starszej wersji). Zamknij poprzednie okno i uruchom ponownie. Nie usuwaj pending.json ani nie ponawiaj join.',
            'SP2 Serwis Domeny - program juz dziala', 'OK', 'Information')
        exit 12
    }
    try { Initialize-Storage; Show-RepairForm }
    catch {
        Write-Crash 'GUI_FAILED' $_
        [void][Windows.Forms.MessageBox]::Show(
            'Blad uruchomienia. Zobacz C:\ProgramData\SP2-Domain-Recovery\crash.log.',
            'SP2 Serwis Domeny', 'OK', 'Error')
        exit 1
    }
}
finally {
    if ($null -ne $script:Credential) { $script:Credential.Password.Dispose(); $script:Credential = $null }
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
}


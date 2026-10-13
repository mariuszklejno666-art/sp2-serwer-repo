param([switch]$SelfTest, [switch]$Resume, [switch]$LibraryOnly)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security
$script:Root = Join-Path $env:ProgramData 'SP2-Domain-Recovery'
$script:StatePath = Join-Path $script:Root 'pending.json'
$script:State = $null
$script:Token = ''
$script:Credential = $null
$script:Endpoint = ''
$script:AgentConfig = $null
$script:DeploymentConfig = $null
$script:LastApiStatus = ''
$script:LastHttpStatus = 0
$script:FailureMessage = ''
$script:DomainDnsServer = '192.168.0.143'
$script:DefaultEndpoint = 'https://dc.sp2.lan'
$script:StatusControl = $null

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

function Assert-ServerCapabilities {
    $script:Token=''
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
            if ($Enrollment) { $registration=Invoke-Api 'enroll' @{hostname=$env:COMPUTERNAME}; $script:Token=$registration.token }
            $pending=Invoke-Api 'status' $null 'GET'
            Save-Authentication
            return $pending
        } catch {
            # Expired/shared agent tokens and expired/already-used enrollment
            # credentials fall back to the existing administrator approval flow.
            if ($script:LastHttpStatus -ne 401 -and -not ($Enrollment -and $script:LastHttpStatus -eq 409)) { throw }
        }
    }
    $script:Token=''
    $script:Token=Get-BrowserToken
    Save-Authentication
    return Invoke-Api 'status' $null 'GET'
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
    $pair=Invoke-Api 'pair' @{hostname=$env:COMPUTERNAME;device_id=$device}
    # Server returns only a path; never open an arbitrary remote URL.
    $expected='/agents/domain-repair/approve/' + ([Guid]$pair.id).ToString()
    if ($pair.approval_path -ne $expected) { throw 'Nieprawidlowy adres zatwierdzenia.' }
    Start-Process ($script:Endpoint + $expected)

    if ($null -ne $script:StatusControl) {
        $script:StatusControl.Text="Otworzono SP2 ADMIN. Zatwierdz komputer $env:COMPUTERNAME w przegladarce. Program czeka i po zatwierdzeniu sam pobierze token - nie trzeba klikac OK."
        $script:StatusControl.Refresh()
    }

    $deadline=[DateTime]::UtcNow.AddMinutes(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $result=Invoke-Api ('pair/' + $pair.id + '/claim') @{claim_secret=$pair.claim_secret}
            if ($null -ne $script:StatusControl) {
                $script:StatusControl.Text='Komputer zatwierdzony. Token pobrany automatycznie; przygotowuje plan naprawy...'
                $script:StatusControl.Refresh()
            }
            $pair=$null
            return [string]$result.token
        } catch {
            if ($script:LastHttpStatus -eq 409) {
                [Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 1200
                continue
            }
            if ($script:LastHttpStatus -eq 410) {
                throw 'Autoryzacja wygasla. Uruchom NAPRAW TEN KOMPUTER ponownie, aby utworzyc nowe zadanie.'
            }
            throw
        }
    }
    throw 'Uplynal czas oczekiwania na zatwierdzenie komputera w SP2 ADMIN. Uruchom operacje ponownie.'
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
        [IO.File]::Replace($temp, $script:StatePath, $null)
    } else { [IO.File]::Move($temp, $script:StatePath) }
}

function Write-Crash([string]$Code, $ErrorRecord) {
    # Never log exception messages, HTTP bodies, credentials or command arguments.
    $line = '{0} code={1} type={2} line={3}' -f [DateTime]::UtcNow.ToString('o'),$Code,$ErrorRecord.Exception.GetType().Name,$ErrorRecord.InvocationInfo.ScriptLineNumber
    Add-Content -LiteralPath (Join-Path $script:Root 'crash.log') -Value $line -Encoding UTF8
}

function Invoke-Api([string]$Path, $Data = $null, [string]$Method = 'POST') {
    $script:LastApiStatus = ''
    $script:LastHttpStatus = 0
    $uri = [Uri]($script:Endpoint + '/api/v1/agent/domain-repair/' + $Path)
    if ($uri.Scheme -ne 'https' -or $uri.UserInfo) { throw 'Wymagany HTTPS z poprawnym certyfikatem.' }
    $parameters = @{ Uri=$uri; Method=$Method; Headers=@{}; TimeoutSec=30; MaximumRedirection=0; UseBasicParsing=$true }
    if ($script:Token) { $parameters.Headers.Authorization='Bearer ' + $script:Token }
    if ($null -ne $Data) { $parameters.Body = ($Data | ConvertTo-Json -Depth 8 -Compress); $parameters.ContentType='application/json; charset=utf-8' }
    try { $response = Invoke-WebRequest @parameters }
    catch {
        if ($null -ne $_.Exception.Response) {
            $script:LastHttpStatus=[int]$_.Exception.Response.StatusCode
            $script:LastApiStatus='HTTP ' + [int]$_.Exception.Response.StatusCode
            try {
                $reader=New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
                try { $buffer=New-Object char[] 8192; $count=$reader.Read($buffer,0,$buffer.Length); $failure=(-join $buffer[0..($count-1)]) | ConvertFrom-Json } finally { $reader.Dispose() }
                if ($failure.PSObject.Properties['diagnosis'] -and $failure.diagnosis.status -match '^[A-Z_]{1,64}$') { $script:LastApiStatus += ' / ' + $failure.diagnosis.status }
            } catch { }
        }
        if ($script:LastHttpStatus -eq 0) { $script:FailureMessage='Nie udalo sie polaczyc przez HTTPS z SP2 ADMIN. Sprawdz adres panelu, DNS i zaufanie do certyfikatu Windows. Program nie wylacza kontroli certyfikatu.' }
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

function Get-LocalState {
    $system = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $secure = $null
    if ($system.PartOfDomain) {
        try { $secure = [bool](Test-ComputerSecureChannel -ErrorAction Stop) } catch { $secure = $null }
    }
    $macs=@(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object MacAddress | ForEach-Object { $_.MacAddress.Replace('-',':').ToUpperInvariant() })
    return @{ hostname=$env:COMPUTERNAME; part_of_domain=[bool]$system.PartOfDomain; domain=[string]$system.Domain; secure_channel=$secure; boot_id=$os.LastBootUpTime.ToUniversalTime().ToString('o');mac_addresses=$macs }
}

function Get-DeviceId {
    return ([Guid](Get-CimInstance Win32_ComputerSystemProduct).UUID).ToString()
}

function Set-Progress([string]$Event) {
    $plan = $script:State.plan
    $updated = Invoke-Api ('progress/' + $plan.id) @{version=$plan.version; event=$Event; device_id=$script:State.device_id; local=(Get-LocalState)}
    $script:State.plan = $updated
    Save-State
}

function Install-Resume {
    $installedScript = Join-Path $script:Root 'SP2-Serwis-Domeny.ps1'
    if ($PSCommandPath -ne $installedScript) { Copy-Item -LiteralPath $PSCommandPath -Destination $installedScript -Force }
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
    $credential = Get-Credential -Message 'Poswiadczenia domenowe tylko w pamieci tego komputera (np. SP2\Administrator)'
    if ($null -eq $credential) { throw 'Anulowano podanie poswiadczen.' }
    return $credential
}

function Get-RecoveryJoinCredential {
    $plan=$script:State.plan
    $response=$null
    $password=$null
    try {
        $response=Invoke-Api ('join-credential/' + $plan.id) @{version=$plan.version;device_id=$script:State.device_id;local=(Get-LocalState)}
        $password=ConvertTo-SecureString -String $response.password -AsPlainText -Force
        return [Management.Automation.PSCredential]::new([string]$response.username,$password)
    } finally {
        if ($null -ne $response) { $response.password=''; $response=$null }
    }
}

function Request-RecoveryPlan($Data) {
    try { return Invoke-Api 'plan' $Data }
    catch {
        if ($script:LastHttpStatus -ne 403) { throw }
        # Bind UUID through the existing browser approval instead of trusting JSON.
        $script:Token=''
        $script:Token=Get-BrowserToken
        Save-Authentication
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
    if ($code -ne 0) { throw ('Kontrolowany join niepotwierdzony; kod Windows: ' + $code) }
}

function Run-Recovery {
    # Recover the latest committed version after a timeout or process crash.
    $script:State.plan = Invoke-Api ('status/' + $script:State.plan.id) $null 'GET'
    Save-State
    if ($script:State.plan.state -in @('complete','cancelled')) { return 'Plan zakonczony.' }
    Set-Progress 'observe'
    $plan = $script:State.plan
    $serverTime=[DateTimeOffset]::Parse($plan.server_time_utc)
    $skew=[Math]::Abs(([DateTimeOffset]::UtcNow-$serverTime).TotalSeconds)
    if ($skew -gt 240) { return 'ZATRZYMANO: zegar Windows rozni sie od SP2 ADMIN o ponad 4 minuty. Sprawdz czas serwera i synchronizacje Windows z kontrolerem domeny, potem WZNOW.' }
    if ($plan.state -eq 'complete') {
        Unregister-ScheduledTask -TaskName 'SP2-Domain-Recovery' -Confirm:$false -ErrorAction SilentlyContinue
        $script:State.token = ''
        Save-State
        return 'GOTOWE: secure channel oraz konto, OU, DNS/SPN potwierdzone przez serwer.'
    }
    if ($plan.state -ne 'ready' -or $plan.action -in @('blocked','blocked_conflict','diagnose')) {
        return ('ZATRZYMANO: ' + $plan.diagnosis.status + '. Sprawdz AD i stan komputera. Nie ponawiaj unjoin w ciemno.')
    }
    $message = "Operacja: $($plan.action)`n$($plan.source_name) -> $($plan.target_name)`nOU: $($plan.target_ou)`nKontynuowac?"
    if ([Windows.Forms.MessageBox]::Show($message,'Plan naprawy','YesNo','Warning') -ne 'Yes') { return 'Nie wykonano operacji.' }
    if ($plan.action -in @('recovery_to_workgroup','machine_account_recovery')) {
        Ensure-LocalAdministrator
        $check = [Windows.Forms.MessageBox]::Show('Potwierdz, ze sprawdziles logowanie na dzialajace lokalne konto administratora i znasz jego haslo. Po odpieciu domeny bedzie potrzebne.','Dostep po restarcie','YesNo','Warning')
        if ($check -ne 'Yes') { return 'Przerwano przed odlaczeniem domeny.' }
    }
    if ($plan.action -in @('join','machine_account_recovery')) { Ensure-LocalAdministrator }
    if ($plan.action -ne 'machine_account_recovery') { $script:Credential = Get-DomainCredential }
    try {
        Install-Resume
        # Write-ahead checkpoint: ambiguous outcomes never automatically repeat.
        Set-Progress 'begin'
        if ($plan.action -eq 'machine_account_recovery') {
            $script:Credential=Get-RecoveryJoinCredential
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
        # Leave server pending: operation may have succeeded before a local error.
        throw 'Operacja niepotwierdzona. Zachowano recovery; po kontroli stanu uruchom WZNOW. Szczegoly: crash.log.'
    } finally {
        if ($null -ne $script:Credential) { $script:Credential.Password.Dispose() }
        $script:Credential = $null
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
    $labels = @('Serwer testowy HTTPS','Token/kod (puste = automatycznie)','OU (puste = automatycznie)','Typ komputera','Budynek','Sala (1-999)','Nr (0 = jedyny nauczyciel)')
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
    if (-not $fields[0].Text.Trim()) { $fields[0].Text=Resolve-ServerEndpoint }
    $enroll = New-Object Windows.Forms.CheckBox
    $enroll.Text='Podany sekret to kod enrollment (nowy agent)'; $enroll.Location=New-Object Drawing.Point(270,325); $enroll.Size=New-Object Drawing.Size(430,25)
    $form.Controls.Add($enroll)
    $status = New-Object Windows.Forms.TextBox
    $status.Multiline=$true; $status.ReadOnly=$true; $status.Location=New-Object Drawing.Point(20,430); $status.Size=New-Object Drawing.Size(670,160)
    $status.Text='OBCHOD SAL - NAPRAW TEN KOMPUTER. Puste pole tokenu = automatyczny odczyt SP2 Agenta. Gdy otworzy sie SP2 ADMIN, zatwierdz komputer w przegladarce; program sam wykryje zatwierdzenie i pobierze token.'
    $script:StatusControl=$status
    $form.Controls.Add($status)
    $start = New-Object Windows.Forms.Button
    $start.Text='NAPRAW TEN KOMPUTER'; $start.Location=New-Object Drawing.Point(20,375); $start.Size=New-Object Drawing.Size(320,38)
    $resumeButton=New-Object Windows.Forms.Button
    $resumeButton.Text='WZNOW RECOVERY'; $resumeButton.Location=New-Object Drawing.Point(365,375); $resumeButton.Size=New-Object Drawing.Size(325,38)
    $form.Controls.AddRange(@($start,$resumeButton))
    $start.Add_Click({
        $start.Enabled=$false; $resumeButton.Enabled=$false
        try {
            $script:FailureMessage=''
            Ensure-SecondaryDomainDns
            $local=Get-LocalState
            $status.Text=('Diagnoza lokalna: {0}; w domenie: {1}; domena: {2}; secure channel: {3}. Laczenie z SP2 ADMIN...' -f $local.hostname,$local.part_of_domain,$local.domain,$local.secure_channel)
            $status.Refresh()
            $enteredEndpoint=$fields[0].Text.Trim().TrimEnd('/')
            if (-not $enteredEndpoint -or $enteredEndpoint -match '^http://192[.]168[.]0[.]143') {
                $script:Endpoint=Resolve-ServerEndpoint
                $fields[0].Text=$script:Endpoint
            } else {
                $script:Endpoint=$enteredEndpoint
            }
            $manualToken=$fields[1].Text.Trim()
            $fields[1].Clear()
            Assert-ServerCapabilities
            $pending=Resolve-Authentication $manualToken $enroll.Checked
            $manualToken=''
            $device=Get-DeviceId
            $requestId=[Guid]::NewGuid().ToString()
            $target=Get-TargetName $fields[3].Text $fields[4].Text ([int]$fields[5].Text) ([int]$fields[6].Text)
            # Persist token and request ID before plan POST, including enrollment.
            $protected=Protect-AgentToken $script:Token
            $script:State=@{endpoint=$script:Endpoint;token=$protected;device_id=$device;plan=$null;request_id=$requestId;target_name=$target;target_ou=$fields[2].Text.Trim()}
            Save-State
            $script:State.plan=$pending.plan
            Save-State
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
                $script:State.plan=Request-RecoveryPlan @{request_id=$requestId;device_id=$device;local=(Get-LocalState);target_name=$target;target_ou=$script:State.target_ou}
                Save-State
            }
            $status.Text=Run-Recovery
        } catch {
            Write-Crash 'START_FAILED' $_
            if ($script:FailureMessage) { $status.Text=$script:FailureMessage }
            else { $status.Text='ZATRZYMANO. ' + $script:LastApiStatus + '. Sprawdz stan planu i OU; nie wpisuj recznie tokenu, autoryzacja odbywa sie automatycznie.' }
        }
        finally { $script:Token=''; $start.Enabled=$true; $resumeButton.Enabled=$true }
    })
    $resumeButton.Add_Click({
        $start.Enabled=$false; $resumeButton.Enabled=$false
        try {
            $script:FailureMessage=''
            $script:State=Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json
            if ($script:State.device_id -ne (Get-DeviceId)) { throw 'Recovery pochodzi z innego komputera.' }
            $script:Endpoint=$script:State.endpoint
            Assert-ServerCapabilities
            if ($script:State.token) {
                try { $script:Token=Unprotect-AgentToken $script:State.token } catch { $script:Token='' }
            } else { $script:Token=$fields[1].Text.Trim() }
            $existing=$script:Token
            [void](Resolve-Authentication $existing $false)
            $existing=''
            $script:State.token=Protect-AgentToken $script:Token
            Save-State
            if ($null -eq $script:State.plan) {
                $script:State.plan=Request-RecoveryPlan @{request_id=$script:State.request_id;device_id=$script:State.device_id;local=(Get-LocalState);target_name=$script:State.target_name;target_ou=$script:State.target_ou}
            }
            $status.Text=Run-Recovery
        } catch { Write-Crash 'RESUME_FAILED' $_; if ($script:FailureMessage) { $status.Text=$script:FailureMessage } else { $status.Text='Nie wznowiono. ' + $script:LastApiStatus + '. Sprawdz restart, polaczenie i stan planu. Autoryzacja jest pobierana automatycznie.' } }
        finally { $script:Token=''; $start.Enabled=$true; $resumeButton.Enabled=$true }
    })
    if ($Resume) { $status.Text='Wykryto uruchomienie po restarcie. Nacisnij WZNOW RECOVERY. Haslo domenowe trzeba podac ponownie.' }
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
    Show-RepairForm
    $probe=Protect-AgentToken 'self-test-not-a-real-token'
    if ((Unprotect-AgentToken $probe) -ne 'self-test-not-a-real-token') { throw 'DPAPI test failed' }
    Write-Output 'SELFTEST OK: naming, GUI construction, machine DPAPI; no AD, network, storage or restart operations.'
    exit 0
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Uruchom launcher jako administrator.' }
$mutex=New-Object Threading.Mutex($false,'Global\SP2-Domain-Recovery-v2')
if (-not $mutex.WaitOne(0)) { exit 1 }
try { Initialize-Storage; Show-RepairForm }
catch { Write-Crash 'GUI_FAILED' $_; [void][Windows.Forms.MessageBox]::Show('Blad programu. Zobacz C:\ProgramData\SP2-Domain-Recovery\crash.log') }
finally { $mutex.ReleaseMutex(); $mutex.Dispose() }

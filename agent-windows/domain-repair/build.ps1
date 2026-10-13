param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist'),
    [string]$SchoolCaFile = ''
)
$ErrorActionPreference='Stop'
[IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Brak kompilatora .NET Framework 4.x.' }
$output=Join-Path $OutputDirectory 'SP2-Serwis-Domeny.exe'
& $compiler /nologo /target:winexe /platform:x64 /reference:System.Windows.Forms.dll ("/out:"+$output) (Join-Path $PSScriptRoot 'Launcher.cs')
if ($LASTEXITCODE -ne 0) { throw 'Kompilacja launchera nie powiodla sie.' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'SP2-Serwis-Domeny.ps1') -Destination $OutputDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'SP2-Entra-Transition.ps1') -Destination $OutputDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'MachineAccountRecovery.cs') -Destination $OutputDirectory -Force
$native=Join-Path $OutputDirectory 'SP2MachineAccountRecovery.dll'
& $compiler /nologo /target:library /platform:x64 ("/out:"+$native) (Join-Path $PSScriptRoot 'MachineAccountRecovery.cs')
if ($LASTEXITCODE -ne 0) { throw 'Kompilacja kontrolowanego joinu nie powiodla sie.' }
& powershell.exe -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'test-native-cloud-status.ps1') -NativeDll $native
if ($LASTEXITCODE -ne 0) { throw 'Natywny odczyt Microsoft Entra jest niedostepny na tej wersji Windows.' }
# Windows PowerShell 5.1 needs a BOM for Polish UTF-8 text.
$script=Join-Path $OutputDirectory 'SP2-Serwis-Domeny.ps1'
$content=[IO.File]::ReadAllText($script)
[IO.File]::WriteAllText($script,$content,[Text.UTF8Encoding]::new($true))

# A school distribution can bundle the public, pinned SP2 root CA.
# The CI artifact deliberately contains no CA unless the real CA is supplied.
# Never ship an unverified or newly-generated substitute as a trust anchor.
$schoolCaSource = ''
if ($SchoolCaFile) {
    if (-not (Test-Path -LiteralPath $SchoolCaFile -PathType Leaf)) {
        throw 'Nie znaleziono wskazanego pliku szkolnego CA.'
    }
    $schoolCaSource = (Resolve-Path -LiteralPath $SchoolCaFile).Path
} else {
    $candidate = Join-Path $PSScriptRoot 'sp2-internal-ca.crt'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $schoolCaSource = $candidate
    }
}
$caOutput = Join-Path $OutputDirectory 'sp2-internal-ca.crt'
if ($schoolCaSource) {
    $ca = [Security.Cryptography.X509Certificates.X509Certificate2]::new($schoolCaSource)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $fingerprint = ([BitConverter]::ToString($sha.ComputeHash($ca.RawData))).Replace('-','').ToLowerInvariant()
        } finally { $sha.Dispose() }
        if ($fingerprint -cne '45581ba7ef494ddce73702c8f7f4174a5f8309ddf342f12b78c7a097f2bbcd33') {
            throw 'CERT SP2: odcisk CA nie zgadza sie z certyfikatem potwierdzonym na serwerze.'
        }
        if ($ca.Subject -cne 'CN=SP2 ADMIN Internal CA' -or $ca.Issuer -cne $ca.Subject) {
            throw 'CERT SP2: to nie jest oczekiwany certyfikat szkolnego CA.'
        }
        $basic=@($ca.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
        if ($basic.Count -ne 1 -or
            -not ([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($basic[0],$basic[0].Critical)).CertificateAuthority) {
            throw 'CERT SP2: brak uprawnienia CA.'
        }
    } finally { $ca.Dispose() }
    Copy-Item -LiteralPath $schoolCaSource -Destination $caOutput -Force
    Write-Output 'CERT SP2: szkolny CA zweryfikowany i dolaczony do pakietu.'
} elseif (Test-Path -LiteralPath $caOutput) {
    # Do not accidentally ship a stale CA from a previous build directory.
    Remove-Item -LiteralPath $caOutput -Force
}

# Portable standalone executable: all four companion files are embedded as
# .NET managed resources. No installation or pre-extraction is required.
$portable=Join-Path $OutputDirectory 'SP2-Serwis-Domeny-Portable.exe'
$resources=@(
    ("/resource:"+$script+",SP2.Portable.Main"),
    ("/resource:"+(Join-Path $OutputDirectory 'SP2-Entra-Transition.ps1')+",SP2.Portable.Entra"),
    ("/resource:"+(Join-Path $OutputDirectory 'MachineAccountRecovery.cs')+",SP2.Portable.NativeSource"),
    ("/resource:"+$native+",SP2.Portable.NativeDll")
)
if ($schoolCaSource) {
    $resources += ("/resource:"+$caOutput+",SP2.Portable.SchoolCa")
}
& $compiler /nologo /target:winexe /platform:x64 /reference:System.Windows.Forms.dll ("/out:"+$portable) $resources (Join-Path $PSScriptRoot 'PortableLauncher.cs')
if ($LASTEXITCODE -ne 0) { throw 'Kompilacja pojedynczego portable EXE nie powiodla sie.' }
& $portable '--self-test'
if ($LASTEXITCODE -ne 0) { throw 'Portable EXE: weryfikacja wbudowanych zasobow nie powiodla sie.' }
Write-Output $output
Write-Output $portable

param([Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$Destination=[IO.Path]::GetFullPath($Destination)
$package=Join-Path $Destination 'SP2-Serwis-Domeny-v2.0.1-test'
$git=Get-Command git -ErrorAction Stop
$status=& $git.Source -C $repo status --porcelain
if ($status) { throw 'Zapisz zmiany w commicie przed pakowaniem.' }
$commit=(& $git.Source -C $repo rev-parse HEAD).Trim()
& (Join-Path $PSScriptRoot 'build.ps1') -OutputDirectory $package
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $package -Force
& $git.Source -C $repo archive --format=zip ("--output="+(Join-Path $package 'SP2-ADMIN-source.zip')) HEAD
if ($LASTEXITCODE -ne 0) { throw 'Archiwizacja zrodel nie powiodla sie.' }
$info=@{version='2.0.1-test';branch='domain-repair-v2';commit=$commit;built_utc=[DateTime]::UtcNow.ToString('o');production_deployed=$false}
$info | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $package 'BUILD.json') -Encoding UTF8
$lines=Get-ChildItem -LiteralPath $package -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(),$_.Name
}
$lines | Set-Content -LiteralPath (Join-Path $package 'SHA256SUMS.txt') -Encoding ASCII
$zip=Join-Path $Destination 'SP2-Serwis-Domeny-v2.0.1-test.zip'
Compress-Archive -Path (Join-Path $package '*') -DestinationPath $zip -Force
('{0}  {1}' -f (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant(),[IO.Path]::GetFileName($zip)) | Set-Content -LiteralPath ($zip+'.sha256') -Encoding ASCII
Write-Output $zip

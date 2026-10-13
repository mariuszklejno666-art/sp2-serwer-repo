param([Parameter(Mandatory = $true)][string]$NativeDll)
$ErrorActionPreference='Stop'
# Only read-only native Windows device registration check. No dsregcmd /leave.
Add-Type -Path $NativeDll -ErrorAction Stop
$joinState=[SP2NativeCloudJoin]::GetDeviceJoinState()
if ($joinState -notin @(0,1)) {
    throw ('Unexpected native device join state: ' + [string]$joinState)
}
Write-Output ('NATIVE ENTRA STATUS OK: state=' + [string]$joinState + '; read only.')

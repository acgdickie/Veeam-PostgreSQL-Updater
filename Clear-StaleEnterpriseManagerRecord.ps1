<#
.SYNOPSIS
    Reports, and optionally clears, a leftover Enterprise Manager connection record
    inside the Veeam Backup & Replication configuration database.

.DESCRIPTION
    Two different records say "Enterprise Manager" on a VBR server:

      1. The registry key HKLM\SOFTWARE\Veeam\Veeam Backup Reporting, which is
         Enterprise Manager's own install footprint. Update-VeeamPostgres.ps1 reads
         that one, and can remove a proven-stale copy with
         -RemoveStaleEnterpriseManagerRecord.
      2. The connection record inside the VBR configuration database, which says
         this server is managed by Enterprise Manager at a URL. THIS script covers
         that one.

    Default behaviour is REPORT ONLY. Nothing is changed without -Clear.

    WARNING - UNSUPPORTED API. Clearing the record uses
    [Veeam.Backup.Core.SBackupOptions], an internal Veeam class with no public
    documentation. It writes directly to the VBR configuration database. Veeam
    Support does not support this, the class can change between versions, and a
    failed write affects VBR configuration. Test on a non-production VBR first.
    The supported route is to remove this VBR server from the Enterprise Manager
    console, or to ask Veeam Support to clear the record.

.PARAMETER Clear
    Clear the record. Asks for confirmation. Refuses unless Enterprise Manager is
    proven absent from this server and a recent successful VBR configuration backup
    exists.

.PARAMETER MaxConfigBackupAgeHours
    How recent the VBR configuration backup must be for -Clear. Default 24.

.PARAMETER SkipConfigBackupCheck
    Allow -Clear without a recent configuration backup. Only for a lab server.

.NOTES
    Run this ON the VBR server, elevated. VBR 13 ships a PowerShell module that
    needs PowerShell 7 (7.6 or later for VBR 13.1), so use pwsh.exe there. VBR 12
    works in Windows PowerShell 5.1.

    EXIT CODES
      0  No record, or the record was cleared
      5  A record exists and -Clear was not passed (nothing changed)
      1  Could not read the record, or -Clear was refused/failed (nothing changed)
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch] $Clear,
    [ValidateRange(1, 8760)][int] $MaxConfigBackupAgeHours = 24,
    [switch] $SkipConfigBackupCheck
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Write-Step { param([string] $Message) Write-Host ''; Write-Host "== $Message" -ForegroundColor Cyan }
function Write-Note { param([string] $Message) Write-Host "   $Message" }
function Write-Warn { param([string] $Message) Write-Host "   $Message" -ForegroundColor Yellow }
function Write-Good { param([string] $Message) Write-Host "   $Message" -ForegroundColor Green }
function Write-Bad  { param([string] $Message) Write-Host "   $Message" -ForegroundColor Red }

# ---------------------------------------------------------------------------
Write-Step 'Context'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Bad 'Must run elevated.'
    exit 1
}
Write-Note "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)) as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

if (-not (Test-Path 'HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication')) {
    Write-Bad 'Veeam Backup & Replication is not installed on this server.'
    exit 1
}

try {
    Import-Module Veeam.Backup.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
} catch {
    Write-Bad "Could not load Veeam.Backup.PowerShell: $($_.Exception.Message)"
    Write-Note 'Read the version in the message above. VBR 13.1 ships a module that needs PowerShell 7.6 or later; VBR 12 works in Windows PowerShell 5.1.'
    exit 1
}

# ---------------------------------------------------------------------------
Write-Step 'Is Enterprise Manager actually installed here?'
$emKey = 'HKLM:\SOFTWARE\Veeam\Veeam Backup Reporting'
$emServices = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue |
    Where-Object { "$($_.Name) $($_.DisplayName)" -match 'EnterpriseManager|Enterprise Manager' })
$emDefaultPath = 'C:\Program Files\Veeam\Backup and Replication\Enterprise Manager'
$emInstalled = ($emServices.Count -gt 0) -or (Test-Path -LiteralPath $emDefaultPath)

Write-Note "Registry key present : $(Test-Path $emKey)"
Write-Note "EM service(s)        : $(if ($emServices.Count -gt 0) { (@($emServices | ForEach-Object { $_.Name }) -join ', ') } else { 'none' })"
Write-Note "EM install folder    : $(if (Test-Path -LiteralPath $emDefaultPath) { $emDefaultPath } else { 'not present' })"
if ($emInstalled) { Write-Warn 'Enterprise Manager looks INSTALLED on this server.' }
else { Write-Good 'Enterprise Manager is not installed on this server.' }

# ---------------------------------------------------------------------------
Write-Step 'Enterprise Manager record inside the VBR configuration database'
# Touching a VBR cmdlet first makes the Veeam.Backup.Core assembly load.
try { Get-VBRServer -ErrorAction Stop | Out-Null } catch {
    Write-Bad "Could not query VBR: $($_.Exception.Message)"
    exit 1
}
try {
    $emInfo = [Veeam.Backup.Core.SBackupOptions]::GetEnterpriseServerInfo()
} catch {
    Write-Bad "Could not read the Enterprise Manager record: $($_.Exception.Message)"
    Write-Note 'This uses an internal Veeam class, which may not exist in this VBR version.'
    exit 1
}
if ($null -eq $emInfo) {
    Write-Good 'VBR returned no Enterprise Manager record. Nothing to clear.'
    exit 0
}

# Print whatever fields this VBR version exposes, rather than assuming three.
$fieldNames = @($emInfo.PSObject.Properties |
    Where-Object { $_.Name -notmatch 'pass|secret|token|cred|key' } |
    ForEach-Object { $_.Name })
foreach ($name in $fieldNames) {
    $value = $null
    try { $value = $emInfo.$name } catch {}
    if ($null -eq $value -or "$value" -eq '') { $value = '<empty>' }
    Write-Note ("{0,-22} : {1}" -f $name, $value)
}

function Get-Field { param($Object, [string] $Name)
    if ($Object -and @($Object.PSObject.Properties.Name) -contains $Name) { return $Object.$Name }
    return $null
}
$serverName  = "$(Get-Field $emInfo 'ServerName')"
$url         = "$(Get-Field $emInfo 'Url')"
$isConnected = [bool](Get-Field $emInfo 'IsConnected')
$hasRecord   = $isConnected -or $serverName -or $url

if (-not $hasRecord) {
    Write-Good 'The record is already empty. Nothing to clear.'
    exit 0
}
Write-Warn 'A leftover Enterprise Manager record EXISTS in the VBR configuration database.'

if (-not $Clear) {
    Write-Host ''
    Write-Warn 'Report only. Nothing was changed.'
    Write-Note 'To clear it, rerun with -Clear. Read the warning in this script first (Get-Help .\Clear-StaleEnterpriseManagerRecord.ps1 -Detailed).'
    exit 5
}

# ---------------------------------------------------------------------------
Write-Step 'Pre-checks for -Clear'
if ($emInstalled) {
    Write-Bad 'Enterprise Manager is installed on this server, so this record is not stale. Refusing to clear it.'
    exit 1
}

if ($SkipConfigBackupCheck) {
    Write-Warn 'Configuration-backup check skipped by request. Lab use only.'
} else {
    try {
        $cfgJob = Get-VBRConfigurationBackupJob -ErrorAction Stop
    } catch {
        Write-Bad "Could not read the VBR configuration backup job: $($_.Exception.Message)"
        exit 1
    }
    $lastResult = "$(Get-Field $cfgJob 'LastResult')"
    $lastRun    = Get-Field $cfgJob 'LastRun'
    Write-Note "Configuration backup : LastResult=$lastResult LastRun=$lastRun"
    if ($lastResult -ne 'Success') {
        Write-Bad "The last VBR configuration backup is '$lastResult', not Success. Run one, then retry."
        exit 1
    }
    $ageHours = $null
    try { $ageHours = ((Get-Date) - [datetime]$lastRun).TotalHours } catch {}
    if ($null -eq $ageHours) {
        Write-Bad 'Could not work out the age of the configuration backup. Refusing to continue.'
        exit 1
    }
    if ($ageHours -gt $MaxConfigBackupAgeHours) {
        Write-Bad ("The configuration backup is {0:N1} hours old; the limit is {1}. Run a fresh one, then retry." -f $ageHours, $MaxConfigBackupAgeHours)
        exit 1
    }
    Write-Good ("Configuration backup is {0:N1} hours old." -f $ageHours)
}

$before = ($fieldNames | ForEach-Object { "$_=$(try { $emInfo.$_ } catch { '' })" }) -join '; '
Write-Note "Before: $before"

# ---------------------------------------------------------------------------
Write-Step 'Clear the record (internal, unsupported API)'
$target = "VBR configuration database on $env:COMPUTERNAME"
$action = "clear the Enterprise Manager record (ServerName='$serverName', Url='$url')"
if (-not $PSCmdlet.ShouldProcess($target, $action)) {
    Write-Warn 'Not confirmed. Nothing was changed.'
    exit 1
}
try {
    if (@($emInfo.PSObject.Properties.Name) -contains 'ServerName')  { $emInfo.ServerName = '' }
    if (@($emInfo.PSObject.Properties.Name) -contains 'Url')         { $emInfo.Url = '' }
    if (@($emInfo.PSObject.Properties.Name) -contains 'IsConnected') { $emInfo.IsConnected = $false }
    [Veeam.Backup.Core.SBackupOptions]::UpdateEnterpriseServerInfo($emInfo)
} catch {
    Write-Bad "The write failed: $($_.Exception.Message)"
    Write-Note 'Nothing is guaranteed about partial state. Verify in the VBR console, and restore the configuration backup if VBR misbehaves.'
    exit 1
}

Write-Step 'Verify'
try {
    $after = [Veeam.Backup.Core.SBackupOptions]::GetEnterpriseServerInfo()
} catch {
    Write-Bad "Could not read the record back: $($_.Exception.Message)"
    exit 1
}
$afterName      = "$(Get-Field $after 'ServerName')"
$afterUrl       = "$(Get-Field $after 'Url')"
$afterConnected = [bool](Get-Field $after 'IsConnected')
Write-Note ("After : ServerName='{0}' Url='{1}' IsConnected={2}" -f $afterName, $afterUrl, $afterConnected)
if ($afterName -or $afterUrl -or $afterConnected) {
    Write-Bad 'The record is still present. VBR may rewrite it, or the write did not take effect.'
    exit 1
}
Write-Good 'The Enterprise Manager record is cleared.'
Write-Note 'Restart the Veeam Backup Service if the console still shows the old connection.'
exit 0

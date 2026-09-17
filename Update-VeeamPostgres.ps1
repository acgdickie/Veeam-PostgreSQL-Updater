<#
.SYNOPSIS
    Audits and (optionally) applies a PostgreSQL MINOR version update on a Windows
    server running Veeam Backup & Replication (VBR) and/or Veeam Backup for
    Microsoft 365 (VB365 / "VBM").

.DESCRIPTION
    Veeam does not patch the bundled PostgreSQL engine on Windows. Product upgrades
    leave it untouched, so most Veeam servers run a PostgreSQL build that is missing
    current security fixes.

    This script follows Veeam KB4386 (VBR) and KB4729 (VB365):
      https://www.veeam.com/kb4386
      https://www.veeam.com/kb4729

    SAME MAJOR VERSION ONLY. 15.x -> 15.y is an in-place binary swap and is safe.
    15.x -> 16.x is a major upgrade, needs pg_upgrade, and is HARD BLOCKED here.

    Default mode is AUDIT: it reports and changes nothing. Pass -Install to commit.

    Everything happens in ONE run, while your RMM script is running: wait for
    active work to finish, disable jobs, back up, stop services, update
    PostgreSQL, tune it, start services, and turn jobs back on. No backup or
    restore is forcibly terminated.

    It does NOT reboot. Veeam's KBs recommend a server restart after the update,
    so it reports RebootRequired=True for the RMM to handle under a change freeze.
    The legacy -Reboot switch is accepted but safely deferred for the same reason.

.PARAMETER Install
    Actually perform the update. Without this the script only reports.

.PARAMETER Reboot
    Compatibility switch retained for existing RMM commands. The script does not
    reboot automatically: after schedules are re-enabled there is no atomic VBR
    barrier that can prevent new work between an idle check and Windows shutdown.
    A successful run therefore returns 6 (or 8 on EOL) with RebootRequired=True so
    the RMM can enforce a change freeze, reboot, verify boot time, and rerun audit.

.PARAMETER Recover
    Recover a run that was interrupted before the PostgreSQL installer started.
    This restores captured service and job state only from the validated recovery
    manifest. If the installer may have started, recovery is diagnostic-only and
    exits 40 or 50 for an operator; it never rolls database files back automatically.

.PARAMETER ConfigPath
    OPTIONAL. A JSON file whose keys override the built-in settings (see
    Get-DefaultConfig below). You normally never need this - the script carries its
    own settings so an RMM only has to upload this one file.
    Without it the script looks for an override in <WorkRoot>\config.json, then
    next to the script as VeeamPostgresUpdate.config.json, then uses built-ins.

.PARAMETER WorkRoot
    Local folder for logs, dumps and the cold copy. Default C:\ProgramData\VeeamPgUpdate
    Logs are ALWAYS written here, and pruned after retentionDays.

.PARAMETER SkipDownloadInAudit
    Audit mode normally checks the EnterpriseDB download page for the exact
    Windows x64 installer. This skips that check. The audit still contacts
    postgresql.org to resolve the latest minor release.

.NOTES
    EXIT CODES (for your RMM):
      0  OK            - healthy, with no outstanding RMM action
      5  UPDATE        - supported branch: audit found an update
      6  REBOOT        - supported branch: update succeeded; reboot required
      7  EOL           - EOL branch; major migration required
      8  EOL+REBOOT    - EOL branch; reboot and major migration required
      9  EOL+UPDATE    - EOL branch; minor update and major migration required
      10 RETRY         - safe transient result; retry later
      11 UNSUPPORTED   - topology/guardrail exclusion; manual handling required
      20 PREFLIGHT     - pre-flight failed, needs attention. The server was either
                         untouched or fully rolled back by this script
      30 DOWNLOAD      - download or signature verification failed, nothing changed
      40 ESCALATE      - operator recovery/state cleanup is required, or non-database
                         post-change health/tuning checks failed. PAGE A HUMAN
      50 ESCALATE_NOW  - PostgreSQL is missing, down, unqueryable, or at the wrong
                         version after install/tuning/recovery. PAGE A HUMAN NOW

    WHEN IT RUNS is up to you: it runs when the RMM script or policy runs it.
    There is no maintenance window and nothing is scheduled. -Install means "go now".

    Run it through an independent RMM agent or scheduler, LOCALLY and ELEVATED.
    Do not launch it through the Veeam Management Agent: all Veeam* services,
    including that agent, are deliberately disabled and stopped during the update.
    Do NOT drive this over WinRM / Invoke-Command - the EDB installer is documented
    to fail under PSRemoting.
#>
[CmdletBinding()]
param(
    [switch] $Install,
    [switch] $Reboot,
    [switch] $Recover,
    [string] $ConfigPath,
    [string] $WorkRoot = 'C:\ProgramData\VeeamPgUpdate',
    [switch] $SkipDownloadInAudit
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------
$EXIT = @{
    OK                   = 0
    UPDATE_AVAILABLE     = 5
    REBOOT_REQUIRED      = 6
    EOL                  = 7
    EOL_REBOOT_REQUIRED  = 8
    EOL_UPDATE_AVAILABLE = 9
    RETRY                = 10
    UNSUPPORTED          = 11
    PREFLIGHT            = 20
    DOWNLOAD             = 30
    ESCALATE             = 40
    ESCALATE_NOW         = 50
}

# ===========================================================================
#  BUILT-IN SETTINGS  -  EDIT THESE, THEN RE-UPLOAD THIS ONE FILE TO YOUR RMM
#
#  The PostgreSQL target is intentionally not configured here. The script reads
#  the running server's major branch, looks up PostgreSQL's latest published minor
#  release for that same branch, and updates to it. Major-version changes remain
#  hard blocked: 15.x can become the latest 15.x, but never 16.x or 17.x.
#
#  jobWaitTimeoutMinutes
#      Maximum time to wait for running Veeam work to finish naturally. Nothing
#      is forcibly stopped. A timeout returns exit 10 so the RMM can retry.
#  installerTimeoutMinutes
#      Maximum unattended-installer wait. A timed-out installer is NOT killed;
#      the recovery marker is retained and exit 40 pages an operator.
#  retentionDays
#      How long to keep completed logs and recovery sets (dumps + cold copy).
#      Unresolved runs and the two newest completed recovery sets are retained.
#
#  To override any of these on ONE server without editing the script, drop a JSON
#  file with just the keys you want to change at <WorkRoot>\config.json.
# ===========================================================================
function Get-DefaultConfig {
    $json = @'
{
  "jobWaitTimeoutMinutes": 720,
  "installerTimeoutMinutes": 120,
  "retentionDays": 30
}
'@
    return ($json | ConvertFrom-Json)
}

# Overlay an override object onto the built-in settings. Each recognized top-level
# key REPLACES the built-in value wholesale. Unknown keys and keys starting with _
# are ignored.
function Merge-Config {
    param([Parameter(Mandatory)] $Base, $Override)
    if (-not $Override) { return $Base }
    foreach ($p in @($Override.PSObject.Properties)) {
        if ($p.Name -like '_*') { continue }
        if (@($Base.PSObject.Properties.Name) -contains $p.Name) { $Base.($p.Name) = $p.Value }
    }
    return $Base
}

# ---------------------------------------------------------------------------
# How far the run has got. Drives honest abort messages and auto-recovery.
#   UNTOUCHED        nothing changed
#   JOBS_DISABLED    scheduled jobs disabled, services still up
#   SERVICES_STOPPED services + PostgreSQL stopped, but PostgreSQL NOT modified
#   INSTALLING       the installer has started. No auto-recovery beyond here
#   VERIFIED         PostgreSQL verified at the target version
#   COMPLETE         done
# ---------------------------------------------------------------------------
$script:Stage        = 'UNTOUCHED'
$script:Stamp        = '{0}-{1}' -f (Get-Date).ToString('yyyyMMdd-HHmmss-fff'), $PID
$script:LogDir       = Join-Path $WorkRoot 'logs'
$script:RunDir       = Join-Path $WorkRoot "runs\$($script:Stamp)"
$script:MarkerFile   = Join-Path $WorkRoot 'CHANGES-IN-PROGRESS.marker'
$script:Transcript   = $null
$script:Mutex        = $null
$script:MutexHeld    = $false
$script:Exiting      = $false
$script:DisabledJobs = @()
$script:ManagedJobInventory = @()
$script:VeeamServices = @()
$script:NatsStateCaptured = $false
$script:NatsWasRunning = $false
$script:NatsStartupType = $null
$script:PgServiceName = $null
$script:PgStartupType = $null
$script:Vb365MaintenanceSessionId = $null
$script:Vb365MaintenancePending = $false
$script:RecoveryState = $null
$script:EolBranch    = $false
$script:Report       = [ordered]@{
    Computer       = $env:COMPUTERNAME
    Timestamp      = (Get-Date).ToString('s')
    Mode           = $(if ($Recover) { 'RECOVER' } elseif ($Install) { 'INSTALL' } else { 'AUDIT' })
    VeeamProducts  = ''
    PgMajor        = ''
    PgInstalled    = ''
    PgTarget       = ''
    PgEol          = $false
    Stage          = 'UNTOUCHED'
    Outcome        = 'UNKNOWN'
    ExitCode       = $null
    RebootRequired = $false
    IssueCode      = ''
    ActionRequired = ''
    JobsLeftDisabled = ''
    UnhealthyServices = ''
    RecoveryRunDir = ''
    Detail         = ''
    LogPath        = ''
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet('INFO','WARN','ERROR','OK','STEP')][string] $Level = 'INFO'
    )
    $line = '{0} [{1,-5}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        'STEP'  { Write-Host ''; Write-Host $line -ForegroundColor Cyan }
        default { Write-Host $line }
    }
}

# Write recovery and RMM state without exposing a half-written JSON file if the
# process or host is interrupted. The temporary file is always on the same volume.
function Write-AtomicText {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][AllowEmptyString()][string] $Value
    )
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $tmp = "$Path.tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    try {
        Set-Content -LiteralPath $tmp -Value $Value -Encoding UTF8 -ErrorAction Stop
        if (Test-Path -LiteralPath $Path) {
            try { [IO.File]::Replace($tmp, $Path, $null, $true) }
            catch { Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop }
        } else {
            Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Write-AtomicJson {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)] $InputObject,
        [int] $Depth = 8
    )
    Write-AtomicText -Path $Path -Value (ConvertTo-Json -InputObject $InputObject -Depth $Depth)
}

function Set-RecoveryProperty {
    param([Parameter(Mandatory)][string] $Name, $Value)
    if (-not $script:RecoveryState) { return }
    if ($script:RecoveryState.PSObject.Properties.Name -contains $Name) {
        $script:RecoveryState.$Name = $Value
    } else {
        $script:RecoveryState | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

function Save-RecoveryState {
    param([string] $Stage, [Nullable[bool]] $InstallerStarted = $null)
    if (-not $script:RecoveryState) { return }
    if ($Stage) {
        Set-RecoveryProperty Stage $Stage
        $script:Stage = $Stage
    }
    if ($null -ne $InstallerStarted) { Set-RecoveryProperty InstallerStarted ([bool]$InstallerStarted) }
    Set-RecoveryProperty UpdatedAt (Get-Date).ToString('o')

    $statePath = Join-Path $script:RunDir 'recovery-state.json'
    Write-AtomicJson -Path $statePath -InputObject $script:RecoveryState
    $marker = [ordered]@{
        SchemaVersion    = 1
        RunId            = $script:Stamp
        RunDir           = $script:RunDir
        StateFile        = $statePath
        Stage            = $script:RecoveryState.Stage
        InstallerStarted = [bool]$script:RecoveryState.InstallerStarted
        UpdatedAt        = $script:RecoveryState.UpdatedAt
    }
    Write-AtomicJson -Path $script:MarkerFile -InputObject $marker
}

function Remove-RecoveryMarker {
    if (-not (Test-Path -LiteralPath $script:MarkerFile)) { return $true }
    try { Remove-Item -LiteralPath $script:MarkerFile -Force -ErrorAction Stop }
    catch { Write-Log "Could not remove recovery marker: $($_.Exception.Message)" ERROR; return $false }
    if (Test-Path -LiteralPath $script:MarkerFile) {
        Write-Log "Recovery marker still exists after removal: $($script:MarkerFile)" ERROR
        return $false
    }
    return $true
}

function Get-PolicyExitCode {
    param([bool] $Eol, [bool] $UpdateAvailable, [bool] $RebootRequired)
    if ($Eol -and $RebootRequired) { return 8 }
    if ($Eol -and $UpdateAvailable) { return 9 }
    if ($Eol) { return 7 }
    if ($RebootRequired) { return 6 }
    if ($UpdateAvailable) { return 5 }
    return 0
}

function Get-RmmActionForExitCode {
    param([int] $Code)
    switch ($Code) {
        0  { return 'None' }
        5  { return 'Schedule the latest same-major PostgreSQL minor update.' }
        6  { return 'Schedule and verify a server reboot.' }
        7  { return 'Open or maintain a PostgreSQL major-version migration ticket; this branch is EOL.' }
        8  { return 'Schedule and verify a reboot, and open or maintain a PostgreSQL major-version migration ticket.' }
        9  { return 'Schedule the minor update, and open or maintain a PostgreSQL major-version migration ticket.' }
        10 { return 'Retry this script later; no forced job termination was attempted.' }
        11 { return 'Handle this unsupported or excluded topology manually.' }
        20 { return 'Investigate the preflight failure before retrying.' }
        30 { return 'Investigate EnterpriseDB page, download, or signature validation.' }
        40 { return 'PAGE AN OPERATOR. Read Detail and RecoveryRunDir; jobs may remain disabled.' }
        50 { return 'PAGE AN OPERATOR NOW. PostgreSQL verification failed; use the recovery evidence.' }
        default { return 'Investigate the undocumented exit code.' }
    }
}

# ---------------------------------------------------------------------------
# Native command runner.
#
# Windows PowerShell 5.1 turns a native command's stderr into a TERMINATING
# NativeCommandError when $ErrorActionPreference is 'Stop' and stderr is merged
# with 2>&1. PowerShell 7 does not. Every psql / pg_dump / robocopy call in this
# script goes through here so that a failure is a return value we can inspect,
# never an unhandled crash, and so stdout stays clean for parsing.
# ---------------------------------------------------------------------------
function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]   $FilePath,
        [Parameter(Mandatory)][string[]] $Arguments
    )
    $errFile = [System.IO.Path]::GetTempFileName()
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $stdout = & $FilePath @Arguments 2>$errFile
        $code   = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEap
    }
    $stderr = ''
    try {
        if (Test-Path $errFile) { $stderr = (Get-Content $errFile -Raw -ErrorAction SilentlyContinue) }
    } catch {}
    if ($null -eq $stderr) { $stderr = '' }
    Remove-Item $errFile -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        ExitCode = $code
        StdOut   = (($stdout | Out-String).Trim())
        StdErr   = $stderr.Trim()
    }
}

# Capture and restore the exact startup mode of every Veeam service. `sc.exe` is
# used for startup-mode changes because Windows PowerShell 5.1 cannot represent
# Automatic (Delayed Start) through Set-Service, while `sc.exe` can.
function Get-ServiceStartupTypeExact {
    param([Parameter(Mandatory)][string] $Name)

    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $p = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
    switch ([int]$p.Start) {
        2 {
            $delayed = 0
            if ($p.PSObject.Properties.Name -contains 'DelayedAutoStart') { $delayed = [int]$p.DelayedAutoStart }
            if ($delayed -eq 1) { return 'AutomaticDelayedStart' }
            return 'Automatic'
        }
        3 { return 'Manual' }
        4 { return 'Disabled' }
        default { throw "Service $Name has unsupported startup value $($p.Start)" }
    }
}

function Set-ServiceStartupTypeExact {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][ValidateSet('Automatic','AutomaticDelayedStart','Manual','Disabled')][string] $StartupType
    )

    $scStart = switch ($StartupType) {
        'Automatic'             { 'auto' }
        'AutomaticDelayedStart' { 'delayed-auto' }
        'Manual'                { 'demand' }
        'Disabled'              { 'disabled' }
    }
    $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
    $r = Invoke-Native $sc @('config', $Name, 'start=', $scStart)
    if ($r.ExitCode -ne 0) {
        throw "sc.exe could not set $Name to $StartupType (exit $($r.ExitCode)): $($r.StdErr) $($r.StdOut)"
    }
}

function Test-PgServiceExecutableMatchesBaseDir {
    param(
        [Parameter(Mandatory)][string] $PathName,
        [Parameter(Mandatory)][string] $BaseDir
    )

    $commandLine = [Environment]::ExpandEnvironmentVariables($PathName).Trim()
    $executable = $null
    if ($commandLine -match '^\s*"([^"]+\.exe)"(?:\s|$)') {
        $executable = $Matches[1]
    } elseif ($commandLine -match '^\s*(.+?\.exe)(?:\s|$)') {
        $executable = $Matches[1]
    }
    if (-not $executable) { return $false }

    try {
        $actual = [IO.Path]::GetFullPath($executable).TrimEnd('\')
        $expected = @(
            (Join-Path $BaseDir 'bin\pg_ctl.exe'),
            (Join-Path $BaseDir 'bin\postgres.exe')
        ) | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
        return (@($expected | Where-Object { $_ -ieq $actual }).Count -eq 1)
    } catch {
        return $false
    }
}

function Test-PathTreeOverlap {
    param(
        [Parameter(Mandatory)][string] $Left,
        [Parameter(Mandatory)][string] $Right
    )
    try {
        $leftFull = [IO.Path]::GetFullPath($Left).TrimEnd('\','/')
        $rightFull = [IO.Path]::GetFullPath($Right).TrimEnd('\','/')
    } catch {
        return $true # An unnormalizable path is never safe for recovery artifacts.
    }
    if ($leftFull -ieq $rightFull) { return $true }
    return $leftFull.StartsWith("$rightFull\", [StringComparison]::OrdinalIgnoreCase) -or
           $rightFull.StartsWith("$leftFull\", [StringComparison]::OrdinalIgnoreCase)
}

function Get-VeeamServiceState {
    $result = @()
    foreach ($svc in @(Get-Service -Name 'Veeam*' -ErrorAction Stop)) {
        if ("$($svc.Status)" -notin @('Running','Stopped')) {
            throw "Service $($svc.Name) is $($svc.Status); wait for it to become Running or Stopped before updating"
        }
        $result += [pscustomobject]@{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            Status      = "$($svc.Status)"
            WasRunning  = ($svc.Status -eq 'Running')
            StartupType = Get-ServiceStartupTypeExact $svc.Name
        }
    }
    return $result
}

function Disable-VeeamServiceStartup {
    $problems = @()
    foreach ($rec in @($script:VeeamServices)) {
        try {
            Set-ServiceStartupTypeExact -Name $rec.Name -StartupType Disabled
            Write-Log "  disabled startup for $($rec.Name)"
        } catch { $problems += "$($rec.Name): $($_.Exception.Message)" }
    }
    return $problems
}

function Restore-VeeamServiceState {
    param([bool] $AllowStops = $true)
    $problems = @()
    $stateRequestWarnings = @()

    # Restore usable startup modes before starting dependencies. A service that
    # was running while configured Disabled is temporarily made Manual, started,
    # then returned to Disabled in the final pass.
    foreach ($rec in @($script:VeeamServices)) {
        try {
            $typeForStart = if ($rec.WasRunning -and $rec.StartupType -eq 'Disabled') { 'Manual' } else { "$($rec.StartupType)" }
            Set-ServiceStartupTypeExact -Name $rec.Name -StartupType $typeForStart
        } catch { $problems += "$($rec.Name) startup type: $($_.Exception.Message)" }
    }

    foreach ($rec in @($script:VeeamServices)) {
        try {
            $svc = Get-Service -Name $rec.Name -ErrorAction Stop
            if ($rec.WasRunning) {
                if ($svc.Status -ne 'Running') { Start-Service -Name $rec.Name -ErrorAction Stop }
                Write-Log "  restored and started $($rec.Name)"
            } elseif ($svc.Status -ne 'Stopped' -and $AllowStops) {
                # Do not use -Force while restoring: it could cascade into an
                # unrelated dependent service that is outside our snapshot.
                Stop-Service -Name $rec.Name -ErrorAction Stop
                Write-Log "  restored and stopped $($rec.Name)"
            } elseif ($svc.Status -eq 'Running') {
                Write-Log "  leaving externally running $($rec.Name) untouched during no-stop rollback" WARN
            } elseif ($svc.Status -ne 'Stopped') {
                Write-Log "  leaving $($rec.Name) untouched in transitional state $($svc.Status); bounded verification will fail closed if it does not settle" WARN
            }
        } catch { $stateRequestWarnings += "$($rec.Name): $($_.Exception.Message)" }
    }

    foreach ($rec in @($script:VeeamServices | Where-Object { $_.StartupType -eq 'Disabled' })) {
        try { Set-ServiceStartupTypeExact -Name $rec.Name -StartupType Disabled }
        catch { $problems += "$($rec.Name) final startup type: $($_.Exception.Message)" }
    }

    # Service-control calls can time out even though SCM completes the transition
    # shortly afterward. Judge the bounded final state, not only the request call.
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        $pending = @()
        foreach ($rec in @($script:VeeamServices)) {
            $svc = Get-Service -Name $rec.Name -ErrorAction SilentlyContinue
            if (-not $svc) { $pending += $rec.Name; continue }
            if ($rec.WasRunning -and "$($svc.Status)" -ne 'Running') { $pending += $rec.Name }
            if (-not $rec.WasRunning -and $AllowStops -and "$($svc.Status)" -ne 'Stopped') { $pending += $rec.Name }
            if (-not $rec.WasRunning -and -not $AllowStops -and "$($svc.Status)" -notin @('Running','Stopped')) { $pending += $rec.Name }
        }
        if ($pending.Count -eq 0) { break }
        if ($attempt -lt 12) { Start-Sleep -Seconds 5 }
    }
    if ($stateRequestWarnings.Count -gt 0) {
        Write-Log "Service-control request warning(s); final state will decide success: $($stateRequestWarnings -join ' | ')" WARN
    }

    foreach ($rec in @($script:VeeamServices)) {
        try {
            $svc = Get-Service -Name $rec.Name -ErrorAction Stop
            $expectedStatus = if ($rec.WasRunning) { 'Running' } else { 'Stopped' }
            if (($rec.WasRunning -or $AllowStops) -and "$($svc.Status)" -ne $expectedStatus) {
                $problems += "$($rec.Name) verification: expected $expectedStatus, got $($svc.Status)"
            }
            if (-not $rec.WasRunning -and -not $AllowStops -and "$($svc.Status)" -notin @('Running','Stopped')) {
                $problems += "$($rec.Name) verification: transitional state $($svc.Status) did not settle to Running or Stopped"
            }
            $actualStartup = Get-ServiceStartupTypeExact $rec.Name
            if ($actualStartup -ne $rec.StartupType) {
                $problems += "$($rec.Name) verification: expected startup $($rec.StartupType), got $actualStartup"
            }
        } catch { $problems += "$($rec.Name) verification: $($_.Exception.Message)" }
    }

    return $problems
}

# ---------------------------------------------------------------------------
# Try to put the server back the way we found it. Only ever called when the
# installer has NOT yet started, so PostgreSQL itself is unmodified.
# ---------------------------------------------------------------------------
function Invoke-Rollback {
    Write-Log 'ROLLBACK - putting the server back the way it was' STEP
    $problems = @()

    # JOBS_DISABLED means this run has not captured or changed PostgreSQL service
    # state. Never start/retune it merely because an unrelated preflight failure
    # happened after schedules were disabled.
    if ($script:Stage -eq 'SERVICES_STOPPED' -and $script:PgServiceName) {
        $pgRestoreRequestWarning = $null
        if ($script:PgStartupType) {
            $pgTypeForStart = if ($script:PgStartupType -eq 'Disabled') { 'Manual' } else { $script:PgStartupType }
            try { Set-ServiceStartupTypeExact -Name $script:PgServiceName -StartupType $pgTypeForStart }
            catch { $problems += "PostgreSQL startup type: $($_.Exception.Message)" }
        }
        $s = $null
        for ($attempt = 1; $attempt -le 24; $attempt++) {
            $s = Get-Service -Name $script:PgServiceName -ErrorAction SilentlyContinue
            if (-not $s -or $s.Status -eq 'Running') { break }
            if ($s.Status -eq 'Stopped') {
                try { Start-Service -Name $script:PgServiceName -ErrorAction Stop }
                catch { $pgRestoreRequestWarning = $_.Exception.Message }
            }
            if ($attempt -lt 24) { Start-Sleep -Seconds 5 }
        }
        $s = Get-Service -Name $script:PgServiceName -ErrorAction SilentlyContinue
        if ($pgRestoreRequestWarning) {
            Write-Log "PostgreSQL restore request warning: $pgRestoreRequestWarning; final state will decide rollback success." WARN
        }
        if (-not $s) {
            $problems += "PostgreSQL service $($script:PgServiceName) is missing"
        } elseif ($s.Status -ne 'Running') {
            $problems += "PostgreSQL service $($script:PgServiceName) expected Running, got $($s.Status)"
        } else {
            Write-Log "  started $($script:PgServiceName)"
            if ($script:PgStartupType -eq 'Disabled') {
                try { Set-ServiceStartupTypeExact -Name $script:PgServiceName -StartupType Disabled }
                catch { $problems += "PostgreSQL final startup type: $($_.Exception.Message)" }
            }
        }
        if ($script:PgStartupType) {
            try {
                $pgStartupNow = Get-ServiceStartupTypeExact $script:PgServiceName
                if ($pgStartupNow -ne $script:PgStartupType) { $problems += "PostgreSQL expected startup $($script:PgStartupType), got $pgStartupNow" }
            } catch { $problems += "PostgreSQL startup verification: $($_.Exception.Message)" }
        }
    }

    if ($script:Stage -eq 'SERVICES_STOPPED') {
        $natsRollbackRequestWarning = $null
        if ($script:NatsStateCaptured) {
            $nats = Get-Service -Name 'nats-server' -ErrorAction SilentlyContinue
            if (-not $nats) {
                $natsRollbackRequestWarning = 'nats-server service was missing when restoration was requested'
            } else {
                try {
                    if ($script:NatsStartupType) {
                        $natsTypeForStart = if ($script:NatsWasRunning -and $script:NatsStartupType -eq 'Disabled') { 'Manual' } else { $script:NatsStartupType }
                        Set-ServiceStartupTypeExact -Name 'nats-server' -StartupType $natsTypeForStart
                    }
                    if ($script:NatsWasRunning -and $nats.Status -ne 'Running') {
                        Start-Service -Name 'nats-server' -ErrorAction Stop
                    } elseif (-not $script:NatsWasRunning -and $nats.Status -eq 'Running') {
                        # Rollback must never stop a service that may have been
                        # started by newly-arrived work during a drain timeout.
                        Write-Log '  leaving externally running nats-server untouched during no-stop rollback' WARN
                    } elseif (-not $script:NatsWasRunning -and $nats.Status -ne 'Stopped') {
                        Write-Log "  leaving nats-server untouched in transitional state $($nats.Status); bounded verification will fail closed if it does not settle" WARN
                    }
                    if ($script:NatsStartupType -eq 'Disabled') { Set-ServiceStartupTypeExact -Name 'nats-server' -StartupType Disabled }
                } catch { $natsRollbackRequestWarning = "nats-server restore request: $($_.Exception.Message)" }
            }
        }

        $problems += @(Restore-VeeamServiceState -AllowStops:$false)

        if ($natsRollbackRequestWarning) {
            Write-Log "$natsRollbackRequestWarning; final state will decide rollback success." WARN
        }
        if ($script:NatsStateCaptured) {
            for ($attempt = 1; $attempt -le 12; $attempt++) {
                $nats = Get-Service -Name 'nats-server' -ErrorAction SilentlyContinue
                if ($nats) {
                    if ($script:NatsWasRunning -and "$($nats.Status)" -eq 'Running') { break }
                    if (-not $script:NatsWasRunning -and "$($nats.Status)" -in @('Running','Stopped')) { break }
                }
                if ($attempt -lt 12) { Start-Sleep -Seconds 5 }
            }
            if (-not $nats) {
                $problems += 'nats-server: service disappeared after its state was captured'
            } elseif ($script:NatsWasRunning -and "$($nats.Status)" -ne 'Running') {
                $problems += "nats-server: expected Running, got $($nats.Status)"
            } elseif (-not $script:NatsWasRunning -and "$($nats.Status)" -notin @('Running','Stopped')) {
                $problems += "nats-server: transitional state $($nats.Status) did not settle to Running or Stopped"
            } elseif ($script:NatsStartupType) {
                try {
                    $natsStartupNow = Get-ServiceStartupTypeExact 'nats-server'
                    if ($natsStartupNow -ne $script:NatsStartupType) { $problems += "nats-server: expected startup $($script:NatsStartupType), got $natsStartupNow" }
                } catch { $problems += "nats-server startup verification: $($_.Exception.Message)" }
            }
        }
    }

    # Jobs are a last step. If PostgreSQL or a required service did not recover,
    # leave schedules disabled and make the problem visible to the RMM.
    if ($script:Stage -eq 'SERVICES_STOPPED' -and $problems.Count -eq 0) {
        try {
            $pgProbe = Invoke-Psql 'SHOW server_version_num;'
            if ($pgProbe.ExitCode -ne 0 -or $pgProbe.StdOut -notmatch '^\d+$') { throw "database query failed: $($pgProbe.StdErr)" }
        } catch { $problems += "PostgreSQL health check: $($_.Exception.Message)" }
    }

    if ($problems.Count -eq 0 -and ($script:Vb365MaintenanceSessionId -or $script:Vb365MaintenancePending)) {
        try {
            $vbReconnect = @(Connect-VeeamModules -Vb365 -Quiet -Reconnect)
            if ($vbReconnect.Count -gt 0) { throw ($vbReconnect -join ' | ') }
            if ($script:Vb365MaintenancePending) { Resolve-Vb365PendingMaintenanceBarrier }
            if ($script:Vb365MaintenanceSessionId) { Stop-Vb365MaintenanceBarrier -SessionId $script:Vb365MaintenanceSessionId }
        } catch { $problems += "VB365 maintenance release: $($_.Exception.Message)" }
    }

    if ($problems.Count -eq 0) {
        foreach ($j in $script:DisabledJobs) {
            try {
                Enable-VeeamJobById $j
                if ($j.PSObject.Properties.Name -contains 'Restored') { $j.Restored = $true }
                Save-DisabledJobState
                Write-Log "  re-enabled $($j.Family): $($j.Name)"
            } catch { $problems += "job '$($j.Name)': $($_.Exception.Message)" }
        }
    } else {
        $script:Report.JobsLeftDisabled = (Get-UnrestoredJobNames -Records $script:DisabledJobs) -join ', '
    }

    if ($problems.Count -gt 0) {
        Write-Log "ROLLBACK INCOMPLETE: $($problems -join ' | ')" ERROR
        return $false
    }
    Write-Log 'Rollback complete - services running and jobs re-enabled' OK
    return $true
}

function Get-UnrestoredJobNames {
    param([AllowEmptyCollection()][object[]] $Records = @())
    return @($Records | Where-Object {
        -not ($_.PSObject.Properties.Name -contains 'Restored' -and [bool]$_.Restored)
    } | ForEach-Object { "$($_.Name)" } | Where-Object { $_ } | Sort-Object -Unique)
}

function Complete-Run {
    param(
        [Parameter(Mandatory)][int] $Code,
        [Parameter(Mandatory)][string] $Outcome,
        [string] $Detail = ''
    )
    if ($script:Exiting) { return }
    $script:Exiting = $true

    $finalCode = $Code
    $stateNote = ''

    # Tell the truth about what was left behind, and roll back where it is safe.
    switch ($script:Stage) {
        'UNTOUCHED' {
            $stateNote = 'Nothing was changed.'
        }
        'JOBS_DISABLED' {
            if ($Recover) {
                $stateNote = 'Recovery did not complete. The marker and captured job state remain for an operator.'
                if ($finalCode -lt $EXIT.ESCALATE) { $finalCode = $EXIT.ESCALATE }
            } elseif (Invoke-Rollback) {
                Save-RecoveryState -Stage 'COMPLETE' -InstallerStarted $false
                if (-not (Remove-RecoveryMarker)) {
                    $finalCode = $EXIT.ESCALATE
                    $Outcome = 'MARKER_REMOVE_FAILED'
                    $script:Report.IssueCode = 'MARKER_REMOVE_FAILED'
                    $script:Report.ActionRequired = 'PAGE AN OPERATOR. Rollback succeeded, but the recovery marker could not be removed; remove it only after confirming this completed run.'
                    $stateNote = 'Scheduled jobs were re-enabled and PostgreSQL/services were untouched, but the completed recovery marker remains.'
                } else {
                    $stateNote = 'Scheduled jobs were re-enabled. PostgreSQL and all services untouched.'
                }
            }
            else { $stateNote = 'WARNING: some scheduled jobs could NOT be re-enabled - check the Veeam console.'; $finalCode = $EXIT.ESCALATE }
        }
        'SERVICES_STOPPED' {
            # The installer never started, so PostgreSQL is unmodified and a full
            # restart is both safe and correct.
            if ($Recover) {
                $stateNote = 'Recovery did not complete. The marker and captured service/job state remain for an operator.'
                if ($finalCode -lt $EXIT.ESCALATE) { $finalCode = $EXIT.ESCALATE }
            } elseif (Invoke-Rollback) {
                Save-RecoveryState -Stage 'COMPLETE' -InstallerStarted $false
                if (-not (Remove-RecoveryMarker)) {
                    $finalCode = $EXIT.ESCALATE
                    $Outcome = 'MARKER_REMOVE_FAILED'
                    $script:Report.IssueCode = 'MARKER_REMOVE_FAILED'
                    $script:Report.ActionRequired = 'PAGE AN OPERATOR. Rollback succeeded, but the recovery marker could not be removed; remove it only after confirming this completed run.'
                    $stateNote = 'Service/job state was restored and PostgreSQL was never modified, but the completed recovery marker remains.'
                } else {
                    $stateNote = 'Service startup types and running states were restored, and jobs were re-enabled. PostgreSQL was never modified.'
                }
            }
            else { $stateNote = 'WARNING: rollback did not fully succeed - Veeam may still be down.'; $finalCode = $EXIT.ESCALATE }
        }
        'INSTALLING' {
            $stateNote = "SERVER IS MID-CHANGE. Veeam services are STOPPED and jobs are DISABLED. Backups are in $($script:RunDir). The changes-in-progress marker is deliberately left in place."
            if ($finalCode -lt $EXIT.ESCALATE) { $finalCode = $EXIT.ESCALATE }
        }
        'VERIFIED' {
            $stateNote = "PostgreSQL is at the target version. Backups are in $($script:RunDir)."
        }
        'COMPLETE' {
            $stateNote = ''
        }
    }

    $script:Report.Stage   = $script:Stage
    $script:Report.Outcome = $Outcome
    $script:Report.Detail  = (@($Detail, $stateNote) | Where-Object { $_ }) -join ' '
    $script:Report.LogPath = $script:Transcript
    $script:Report.ExitCode = $finalCode
    if (-not $script:Report.IssueCode -and $finalCode -ne $EXIT.OK) { $script:Report.IssueCode = $Outcome }
    if (-not $script:Report.ActionRequired) { $script:Report.ActionRequired = Get-RmmActionForExitCode $finalCode }
    if (-not $script:Report.JobsLeftDisabled -and $finalCode -ge $EXIT.ESCALATE -and $script:DisabledJobs.Count -gt 0) {
        $script:Report.JobsLeftDisabled = (Get-UnrestoredJobNames -Records $script:DisabledJobs) -join ', '
    }
    if (-not $script:Report.RecoveryRunDir -and $script:Stage -ne 'UNTOUCHED' -and (Test-Path -LiteralPath $script:RunDir)) {
        $script:Report.RecoveryRunDir = $script:RunDir
    }

    $summary = ($script:Report.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
    Write-Host ''
    Write-Host '=== RMM SUMMARY ===' -ForegroundColor Magenta
    Write-Host $summary
    if ($script:Report.ActionRequired -and $script:Report.ActionRequired -ne 'None') {
        Write-Host "RMM ACTION: $($script:Report.ActionRequired)" -ForegroundColor Yellow
    }
    if ($script:Report.IssueCode) {
        Write-Host "RMM ISSUE: $($script:Report.IssueCode) | $($script:Report.Detail)" -ForegroundColor Yellow
    }
    Write-Host '==================='

    try {
        Write-AtomicJson -Path (Join-Path $script:LogDir 'last-result.json') -InputObject $script:Report
        if (Test-Path -LiteralPath $script:RunDir) {
            Write-AtomicJson -Path (Join-Path $script:RunDir 'result.json') -InputObject $script:Report
        }
    } catch { Write-Log "Could not write last-result.json: $($_.Exception.Message)" WARN }

    if ($script:Mutex -and $script:MutexHeld) {
        try { $script:Mutex.ReleaseMutex() } catch {}
        try { $script:Mutex.Dispose() } catch {}
    }
    if ($script:Transcript) { try { Stop-Transcript | Out-Null } catch {} }

    exit $finalCode
}

# Any error we did not anticipate must still produce an RMM summary and an exit
# code from the documented set - never a bare 1 with no explanation.
trap {
    Write-Log "UNHANDLED ERROR: $($_.Exception.Message)" ERROR
    Write-Log "  at $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" ERROR
    $code = if ($script:Stage -eq 'UNTOUCHED') { $EXIT.PREFLIGHT } else { $EXIT.ESCALATE }
    Complete-Run $code 'UNHANDLED_ERROR' "$($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Lock a folder to SYSTEM + Administrators only, replacing its whole DACL.
#
# The work root holds privileged database dumps and a cold copy of the whole
# database. Restoring a dump runs code chosen by whoever wrote it, so ordinary
# users must not be able to read or change them. Well-known SIDs are used rather
# than names so this also works on non-English Windows ("VORDEFINIERT\Administratoren").
# ---------------------------------------------------------------------------
function Protect-Folder {
    param([Parameter(Mandatory)][string] $Path)
    try {
        $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
        $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($system, $admins)) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        $acl.SetOwner($admins)
        # Set-Acl, not DirectoryInfo.SetAccessControl(): in PowerShell 7 that is an
        # extension method PowerShell cannot call, and it fails silently here.
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Decide whether the work root is ours to lock down and clean up.
#
# -WorkRoot is user-supplied. Replacing the permissions of, or purging old folders
# inside, someone else's folder - or a whole drive - would be destructive. So the
# script only takes charge of a folder it created (it leaves a sentinel file), or
# one that is empty. Anything else is used for logs only, and -Install refuses.
# ---------------------------------------------------------------------------
function Initialize-WorkRoot {
    param([Parameter(Mandatory)][string] $Path)
    $sentinel = Join-Path $Path '.veeam-pg-updater'
    $full     = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root     = [System.IO.Path]::GetPathRoot($full).TrimEnd('\')

    if ($full -eq $root) {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
        return [pscustomobject]@{ IsOurs = $false; Protected = $false; Reason = "$Path is the root of a drive or share" }
    }

    $isOurs = $false
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        $isOurs = $true
    } elseif (Test-Path -LiteralPath $sentinel) {
        $isOurs = $true
    } elseif (@(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count -eq 0) {
        $isOurs = $true
    }
    if (-not $isOurs) {
        return [pscustomobject]@{ IsOurs = $false; Protected = $false; Reason = "$Path already existed with other files in it and was not created by this script" }
    }

    $protected = Protect-Folder $Path
    if ($protected -and -not (Test-Path -LiteralPath $sentinel)) {
        try { Set-Content -LiteralPath $sentinel -Value 'Created by Update-VeeamPostgres.ps1. Marks this folder as safe for the script to lock down and clean up.' -Encoding UTF8 } catch {}
    }
    $reason = if ($protected) { '' } else { "could not set permissions on $Path" }
    return [pscustomobject]@{ IsOurs = $true; Protected = $protected; Reason = $reason }
}

# ---------------------------------------------------------------------------
# Start harness
# ---------------------------------------------------------------------------
$wrInit = Initialize-WorkRoot $WorkRoot
$script:WorkRootIsOurs    = $wrInit.IsOurs
$script:WorkRootProtected = $wrInit.Protected
if (-not (Test-Path -LiteralPath $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null }
# NOTE: the per-run folder under runs\ is only created by -Install, when there is
# something to put in it. Audit runs leave nothing behind but their log.

$script:Transcript = Join-Path $script:LogDir "VeeamPgUpdate_$($env:COMPUTERNAME)_$($script:Stamp).log"
try { Start-Transcript -Path $script:Transcript -IncludeInvocationHeader | Out-Null } catch {}

Write-Log "Veeam PostgreSQL Updater - mode $($script:Report.Mode)" STEP
Write-Log "PowerShell: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
Write-Log "Work root : $WorkRoot"
Write-Log "Transcript: $($script:Transcript)"
if (-not $script:WorkRootProtected) {
    Write-Log "Work root not locked down: $($wrInit.Reason). Its permissions and contents are left alone. Audit can continue; -Install will refuse." WARN
}

# Single-instance lock. An abandoned mutex (previous run killed mid-flight) throws
# AbandonedMutexException and still grants ownership - that is not a reason to abort.
$script:Mutex = New-Object System.Threading.Mutex($false, 'Global\VeeamPgUpdate')
try {
    if ($script:Mutex.WaitOne(0)) { $script:MutexHeld = $true }
} catch [System.Threading.AbandonedMutexException] {
    $script:MutexHeld = $true
    Write-Log 'Took over an abandoned lock from a previous run that was killed.' WARN
}
if (-not $script:MutexHeld) {
    Complete-Run $EXIT.RETRY 'CONCURRENT_RUN' 'Another instance of this script is already running.'
}

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
function Get-RegValue {
    param([string] $Key, [string] $Name)
    try {
        $p = Get-ItemProperty -Path $Key -Name $Name -ErrorAction Stop
        if ($p.PSObject.Properties.Name -contains $Name) { return $p.$Name }
        return $null
    } catch { return $null }
}

function Get-CfgValue {
    param($Object, [string] $Name, $Default = $null)
    try {
        if ($Object -and $Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    } catch {}
    return $Default
}

function Get-FileVersionSafe {
    param([string] $Path)
    if ($Path -and (Test-Path $Path)) {
        try { return (Get-Item $Path).VersionInfo.ProductVersion } catch { return $null }
    }
    return $null
}

# Veeam modules must be loadable before we can prove anything about jobs.
function Connect-VeeamModules {
    param([switch] $Vbr, [switch] $Vb365, [switch] $Quiet, [switch] $Reconnect)
    $failed = @()
    if ($Vbr) {
        try { Import-Module Veeam.Backup.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue }
        catch { $failed += "Veeam.Backup.PowerShell (use the PowerShell version required by the installed VBR build): $($_.Exception.Message)" }
    }
    if ($Vb365) {
        $vboModule = 'C:\Program Files\Veeam\Backup365\Veeam.Archiver.PowerShell\Veeam.Archiver.PowerShell.psd1'
        try {
            Import-Module $vboModule -ErrorAction Stop -WarningAction SilentlyContinue
            if ($Reconnect -and (Get-Command Disconnect-VBOServer -ErrorAction SilentlyContinue)) {
                try { Disconnect-VBOServer -ErrorAction Stop | Out-Null } catch {}
            }
            Connect-VBOServer -ErrorAction Stop
        } catch { $failed += "Veeam.Archiver.PowerShell (needs PowerShell 7.4.2+): $($_.Exception.Message)" }
    }
    if ($failed.Count -gt 0 -and -not $Quiet) { Write-Log "Veeam module problem: $($failed -join ' | ')" WARN }
    return $failed
}

# Central allow-list of scheduler families. Every family is round-trippable: the
# script will not disable an object unless it knows how to find and re-enable it.
function Get-VeeamJobFamilyDefinitions {
    param([bool] $Vbr = $true, [bool] $Vb365 = $true)
    $defs = @()
    if ($Vbr) {
        # Put specialised families before Get-VBRJob so an object exposed by both
        # APIs is controlled through the purpose-built cmdlet and de-duplicated.
        $defs += @(
            [pscustomobject]@{ Family='VBRAgent';       Get='Get-VBRComputerBackupJob';       Disable='Disable-VBRComputerBackupJob';       Enable='Enable-VBRComputerBackupJob';       Argument='Job';             Transition='Command';      Required=$false; Enabled=@('JobEnabled','IsEnabled','IsScheduleEnabled') },
            [pscustomobject]@{ Family='VBRAgentCopy';   Get='Get-VBRComputerBackupCopyJob';   Disable='Disable-VBRComputerBackupCopyJob';   Enable='Enable-VBRComputerBackupCopyJob';   Argument='Job';             Transition='Command';      Required=$false; Enabled=@('JobEnabled','IsEnabled','IsScheduleEnabled') },
            [pscustomobject]@{ Family='VBRBackupCopy';  Get='Get-VBRBackupCopyJob';           Disable='Disable-VBRBackupCopyJob';           Enable='Enable-VBRBackupCopyJob';           Argument='Job';             Transition='Command';      Required=$false; Enabled=@('JobEnabled','IsEnabled','IsScheduleEnabled') },
            [pscustomobject]@{ Family='VBRTape';        Get='Get-VBRTapeJob';                 Disable='Disable-VBRJob';                     Enable='Enable-VBRJob';                     Argument='Job';             Transition='Command';      Required=$false; Enabled=@('Enabled','IsScheduleEnabled','IsEnabled') },
            [pscustomobject]@{ Family='VBRSureBackup';  Get='Get-VBRSureBackupJob';           Disable='Disable-VBRSureBackupJob';           Enable='Enable-VBRSureBackupJob';           Argument='Job';             Transition='Command';      Required=$false; Enabled=@('IsEnabled','Enabled','IsScheduleEnabled') },
            [pscustomobject]@{ Family='VBRApplication'; Get='Get-VBRApplicationBackupJob';    Disable='Disable-VBRApplicationBackupJob';    Enable='Enable-VBRApplicationBackupJob';    Argument='Job';             Transition='Command';      Required=$false; Enabled=@('ScheduleEnabled','IsScheduleEnabled','IsEnabled') },
            [pscustomobject]@{ Family='VBRPlugin';      Get='Get-VBRPluginJob';               Disable='Disable-VBRPluginJob';               Enable='Enable-VBRPluginJob';               Argument='Job';             Transition='Command';      Required=$false; Enabled=@('IsEnabled','Enabled','IsScheduleEnabled') },
            [pscustomobject]@{ Family='VBRStandalone';  Get='Get-VBREPJob';                  Disable='Disable-VBREPJob';                  Enable='Enable-VBREPJob';                  Argument='Job';             Transition='Command';      Required=$false; Enabled=@('IsEnabled','Enabled','IsScheduleEnabled') },
            [pscustomobject]@{ Family='VBRProtection';  Get='Get-VBRProtectionGroup';         Disable='Disable-VBRProtectionGroup';         Enable='Enable-VBRProtectionGroup';         Argument='ProtectionGroup'; Transition='Command';      Required=$false; Enabled=@('Enabled','IsEnabled') },
            [pscustomobject]@{ Family='VBRCatalystCopy';Get='Get-VBRCatalystCopyJob';         Disable='Disable-VBRCatalystCopyJob';         Enable='Enable-VBRCatalystCopyJob';         Argument='Job';             Transition='Command';      Required=$false; Enabled=@() },
            [pscustomobject]@{ Family='VBRStorageCopy'; Get='Get-VBRStorageCopyJob';          Disable='Disable-VBRStorageCopyJob';          Enable='Enable-VBRStorageCopyJob';          Argument='Job';             Transition='Command';      Required=$false; Enabled=@() },
            [pscustomobject]@{ Family='VBRCDP';         Get='Get-VBRCDPPolicy';               Disable='Disable-VBRCDPPolicy';               Enable='Enable-VBRCDPPolicy';               Argument='Policy';          Transition='Command';      Required=$false; Enabled=@('PolicyState','IsEnabled','Enabled') },
            [pscustomobject]@{ Family='VBRvCDReplica';  Get='Get-VBRvCDReplicaJob';           Disable='Disable-VBRvCDReplicaJob';           Enable='Enable-VBRvCDReplicaJob';           Argument='Job';             Transition='Command';      Required=$false; Enabled=@('ScheduleEnabled','IsScheduleEnabled','IsEnabled') },
            [pscustomobject]@{ Family='VBRUnstructured';Get='Get-VBRUnstructuredBackupJob';   Disable='Set-VBRNASBackupJob';                Enable='Set-VBRObjectStorageBackupJob';     Argument='Job';             Transition='Unstructured'; Required=$false; Enabled=@('ScheduleEnabled','IsScheduleEnabled') },
            [pscustomobject]@{ Family='VBRUnstructuredCopy';Get='Get-VBRUnstructuredBackupCopyJob';Disable='Disable-VBRJob';                 Enable='Enable-VBRJob';                     Argument='Job';             Transition='Command';      Required=$false; Enabled=@('IsScheduleEnabled','ScheduleEnabled','IsEnabled') },
            [pscustomobject]@{ Family='VBREntraTenant'; Get='Get-VBREntraIDTenantBackupJob';  Disable='Set-VBREntraIDTenantBackupJob';      Enable='Set-VBREntraIDTenantBackupJob';      Argument='Job';             Transition='ScheduleSwitch';Required=$false; Enabled=@('EnableSchedule','ScheduleEnabled') },
            [pscustomobject]@{ Family='VBREntraLogs';   Get='Get-VBREntraIDLogsBackupJob';    Disable='Set-VBREntraIDLogsBackupJob';        Enable='Set-VBREntraIDLogsBackupJob';        Argument='Job';             Transition='ScheduleSwitch';Required=$false; Enabled=@('ScheduleEnabled','EnableSchedule') },
            [pscustomobject]@{ Family='VBRConfig';      Get='Get-VBRConfigurationBackupJob';  Disable='Set-VBRConfigurationBackupJob';      Enable='Set-VBRConfigurationBackupJob';      Argument='Enable';          Transition='SingletonSwitch';Required=$true; Enabled=@('Enabled') },
            [pscustomobject]@{ Family='VBRJob';         Get='Get-VBRJob';                     Disable='Disable-VBRJob';                     Enable='Enable-VBRJob';                     Argument='Job';             Transition='Command';      Required=$true;  Enabled=@('IsScheduleEnabled','ScheduleEnabled','IsEnabled') }
        )
    }
    if ($Vb365) {
        $defs += @(
            [pscustomobject]@{ Family='VB365';     Get='Get-VBOJob';     Disable='Disable-VBOJob';     Enable='Enable-VBOJob';     Argument='Job'; Transition='Command'; Required=$true; Enabled=@('IsEnabled') },
            [pscustomobject]@{ Family='VB365Copy'; Get='Get-VBOCopyJob'; Disable='Disable-VBOCopyJob'; Enable='Enable-VBOCopyJob'; Argument='Job'; Transition='Command'; Required=$true; Enabled=@('IsEnabled') }
        )
    }
    return $defs
}

function Get-VeeamJobFamilyDefinition {
    param([Parameter(Mandatory)][string] $Family)
    $def = @(Get-VeeamJobFamilyDefinitions -Vbr $true -Vb365 $true | Where-Object { $_.Family -eq $Family })
    if ($def.Count -ne 1) { throw [System.NotSupportedException]::new("Unknown or ambiguous Veeam job family '$Family'") }
    return $def[0]
}

function Get-VeeamJobEnabledFlag {
    param([Parameter(Mandatory)] $Job, [Parameter(Mandatory)] $Definition)
    foreach ($propertyName in @($Definition.Enabled)) {
        if ($Job.PSObject.Properties.Name -contains $propertyName) {
            if ($propertyName -eq 'PolicyState') { return ("$($Job.$propertyName)" -ne 'Disabled') }
            return [bool]$Job.$propertyName
        }
    }
    throw [System.NotSupportedException]::new("$($Definition.Family) object '$($Job.Name)' exposes none of the expected enabled properties: $($Definition.Enabled -join ', ')")
}

function Get-VeeamJobIdentity {
    param([Parameter(Mandatory)] $Job, [Parameter(Mandatory)][string] $Family)
    if ($Family -eq 'VBRConfig') { return 'VBR-CONFIGURATION-BACKUP' }
    $displayName = if ($Job.PSObject.Properties.Name -contains 'Name') { "$($Job.Name)" } else { '<unnamed>' }
    $id = ''
    foreach ($propertyName in @('Id','ID','Uid','UID')) {
        if ($Job.PSObject.Properties.Name -contains $propertyName -and $Job.$propertyName) {
            $id = "$($Job.$propertyName)"
            break
        }
    }
    if (-not $id) { throw [System.NotSupportedException]::new("$Family object '$displayName' has no stable ID") }
    return $id
}

function Get-VeeamManagedJobInventory {
    param([bool] $Vbr, [bool] $Vb365)
    $inventory = @()
    $seen = @{}
    foreach ($def in @(Get-VeeamJobFamilyDefinitions -Vbr $Vbr -Vb365 $Vb365)) {
        $getter = Get-Command $def.Get -ErrorAction SilentlyContinue
        if (-not $getter) {
            if ($def.Required) { throw [System.NotSupportedException]::new("$($def.Get) is unavailable; $($def.Family) schedules cannot be controlled safely") }
            continue
        }
        $requiredTransitions = @($def.Disable, $def.Enable)
        if ($def.Transition -eq 'Unstructured') {
            $requiredTransitions = @('Set-VBRNASBackupJob','Set-VBRObjectStorageBackupJob')
        }
        foreach ($needed in $requiredTransitions) {
            if (-not (Get-Command $needed -ErrorAction SilentlyContinue)) {
                throw [System.NotSupportedException]::new("$($def.Get) is available but $needed is not; $($def.Family) cannot be round-tripped safely")
            }
        }
        $jobs = @(& $def.Get -ErrorAction Stop)
        if ($jobs.Count -eq 0) { continue }
        foreach ($job in $jobs) {
            $id = Get-VeeamJobIdentity -Job $job -Family $def.Family
            $dedupeKey = $id.ToLowerInvariant()
            if ($seen.ContainsKey($dedupeKey)) { continue }
            $seen[$dedupeKey] = $def.Family
            $inventory += [pscustomobject]@{
                Family  = $def.Family
                Id      = $id
                Name    = "$(if ($job.PSObject.Properties.Name -contains 'Name') { $job.Name } else { $id })"
                Enabled = Get-VeeamJobEnabledFlag -Job $job -Definition $def
                Object  = $job
            }
        }
    }
    return $inventory
}

function Invoke-VeeamJobTransition {
    param(
        [Parameter(Mandatory)] $Definition,
        [Parameter(Mandatory)] $Job,
        [Parameter(Mandatory)][ValidateSet('Disable','Enable')][string] $Action
    )
    $enableValue = ($Action -eq 'Enable')
    if ($Definition.Transition -eq 'SingletonSwitch') {
        $commandName = $Definition.Enable
        & $commandName -Enable:$enableValue -ErrorAction Stop | Out-Null
        return
    }
    if ($Definition.Transition -eq 'ScheduleSwitch') {
        $commandName = $Definition.Enable
        $invokeArgs = @{ Job=$Job; EnableSchedule=$enableValue; ErrorAction='Stop' }
        $command = Get-Command $commandName -ErrorAction Stop
        if ($command.Parameters.ContainsKey('Confirm')) { $invokeArgs['Confirm'] = $false }
        & $commandName @invokeArgs | Out-Null
        return
    }
    if ($Definition.Transition -eq 'Unstructured') {
        $typeName = $Job.GetType().Name
        if ($typeName -match 'ObjectStorage') { $commandName = 'Set-VBRObjectStorageBackupJob' }
        elseif ($typeName -match 'NAS|File')  { $commandName = 'Set-VBRNASBackupJob' }
        else { throw [System.NotSupportedException]::new("Unknown unstructured job subtype '$typeName' for '$($Job.Name)'") }
        $invokeArgs = @{ Job=$Job; EnableSchedule=$enableValue; ErrorAction='Stop' }
        & $commandName @invokeArgs | Out-Null
        return
    }
    $commandName = if ($Action -eq 'Disable') { $Definition.Disable } else { $Definition.Enable }
    $command = Get-Command $commandName -ErrorAction Stop
    $invokeArgs = @{ ErrorAction = 'Stop' }
    $invokeArgs[$Definition.Argument] = $Job
    if ($command.Parameters.ContainsKey('Confirm')) { $invokeArgs['Confirm'] = $false }
    & $commandName @invokeArgs | Out-Null
}

function Get-VeeamJobByRecord {
    param([Parameter(Mandatory)] $JobRecord)
    $def = Get-VeeamJobFamilyDefinition "$($JobRecord.Family)"
    if (-not (Get-Command $def.Get -ErrorAction SilentlyContinue)) {
        throw "$($def.Get) is unavailable while restoring $($JobRecord.Family) '$($JobRecord.Name)'"
    }
    $resolvedJobs = @(& $def.Get -ErrorAction Stop | Where-Object {
        (Get-VeeamJobIdentity -Job $_ -Family $def.Family) -eq "$($JobRecord.Id)"
    })
    if ($resolvedJobs.Count -ne 1) { throw "$($def.Family) job id $($JobRecord.Id) resolved to $($resolvedJobs.Count) objects" }
    return [pscustomobject]@{ Definition=$def; Job=$resolvedJobs[0] }
}

# Re-enable one recorded job and prove its enabled state. Used by normal and
# pre-installer recovery paths.
function Enable-VeeamJobById {
    param([Parameter(Mandatory)] $JobRecord)
    $found = Get-VeeamJobByRecord $JobRecord
    if (-not (Get-VeeamJobEnabledFlag -Job $found.Job -Definition $found.Definition)) {
        Invoke-VeeamJobTransition -Definition $found.Definition -Job $found.Job -Action Enable
    }
    $verify = Get-VeeamJobByRecord $JobRecord
    if (-not (Get-VeeamJobEnabledFlag -Job $verify.Job -Definition $verify.Definition)) {
        throw "$($JobRecord.Family) '$($JobRecord.Name)' is still disabled after Enable"
    }
}

function Save-DisabledJobState {
    if (-not (Test-Path -LiteralPath $script:RunDir)) { return }
    Write-AtomicJson -Path (Join-Path $script:RunDir 'disabled-jobs.json') -InputObject @($script:DisabledJobs) -Depth 5
}

function Disable-VeeamManagedJobs {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Inventory)

    # Persist the complete intent before the first mutation. If the process dies
    # between a Veeam call and the following state write, recovery can safely
    # re-enable every object that was known to be enabled on entry.
    $script:DisabledJobs = @($Inventory | Where-Object { $_.Enabled } | ForEach-Object {
        [pscustomobject][ordered]@{
            Family     = $_.Family
            Id         = $_.Id
            Name       = $_.Name
            WasEnabled = $true
            Disabled   = $false
            Restored   = $false
        }
    })
    Save-DisabledJobState
    Save-RecoveryState -Stage 'JOBS_DISABLED' -InstallerStarted $false

    foreach ($record in @($script:DisabledJobs)) {
        $found = Get-VeeamJobByRecord $record
        if (-not (Get-VeeamJobEnabledFlag -Job $found.Job -Definition $found.Definition)) {
            throw "$($record.Family) '$($record.Name)' changed to disabled before this run could disable it; refusing an ambiguous round trip"
        }
        Invoke-VeeamJobTransition -Definition $found.Definition -Job $found.Job -Action Disable
        $verify = Get-VeeamJobByRecord $record
        if (Get-VeeamJobEnabledFlag -Job $verify.Job -Definition $verify.Definition) {
            throw "$($record.Family) '$($record.Name)' is still enabled after Disable"
        }
        $record.Disabled = $true
        Save-DisabledJobState
        Write-Log "  disabled $($record.Family): $($record.Name)"
    }
}

function Start-Vb365MaintenanceBarrier {
    param([ValidateRange(1,10080)][int] $TimeoutMinutes)

    foreach ($commandName in @('Get-VBORepository','Start-VBORepositoryMaintenanceSession',
                                'Get-VBORepositoryMaintenanceSession','Stop-VBORepositoryMaintenanceSession')) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            throw "$commandName is unavailable. Safe VB365 maintenance requires the repository-maintenance API (VB365 8.6 or later)."
        }
    }
    $repositories = @(Get-VBORepository -ErrorAction Stop)
    if ($repositories.Count -eq 0) { throw 'VB365 has no repositories to place into maintenance mode' }

    $activeStates = @('Initialized','Preparing','Running','Finishing','Canceling','Failing')
    $existingSessions = @(Get-VBORepositoryMaintenanceSession -ErrorAction Stop | Where-Object { "$($_.State)" -in $activeStates })
    if ($existingSessions.Count -gt 0) {
        throw "VB365 already has $($existingSessions.Count) active repository-maintenance session(s); refusing to take ownership of an operator-created barrier"
    }

    $repositoryIds = @($repositories | ForEach-Object { "$($_.Id)" } | Sort-Object -Unique)
    if ($repositoryIds.Count -ne $repositories.Count -or @($repositoryIds | Where-Object { -not $_ }).Count -gt 0) {
        throw 'One or more VB365 repositories has no unique stable ID'
    }
    $attemptedAt = (Get-Date).ToUniversalTime().ToString('o')
    $script:Vb365MaintenancePending = $true
    Set-RecoveryProperty Vb365MaintenancePending $true
    Set-RecoveryProperty Vb365MaintenanceAttemptedAt $attemptedAt
    Set-RecoveryProperty Vb365MaintenanceRepositoryIds $repositoryIds
    Save-RecoveryState -Stage $script:Stage -InstallerStarted $false

    Write-Log "Starting VB365 repository maintenance mode for $($repositories.Count) repository/repositories. Existing work may finish naturally for up to $TimeoutMinutes minutes; ForceStopSessions is deliberately not used."
    try {
        $session = Start-VBORepositoryMaintenanceSession -Repository $repositories -WaitForSessionsTimeoutMinutes $TimeoutMinutes -ErrorAction Stop
    } catch {
        $startError = $_.Exception.Message
        # The server may have created a session before the client/RMM was
        # interrupted. A time/repository match is diagnostic evidence only: a
        # concurrent operator could have started the same scope, so never adopt
        # or stop a session whose ID was not returned by our Start call.
        try {
            $candidate = @(Find-Vb365MaintenanceBarrier -AttemptedAt $attemptedAt -RepositoryIds $repositoryIds)
            if ($candidate.Count -gt 0) {
                Write-Log "VB365 maintenance start outcome is unknown and $($candidate.Count) time/scope-matched active session(s) exist. None will be adopted or stopped automatically." WARN
            }
        } catch {}
        throw "VB365 maintenance start failed: $startError"
    }
    if (-not $session -or -not $session.Id) { throw 'VB365 did not return a maintenance-session ID' }
    $sessionId = "$($session.Id)"
    # Persist the ID before verification. If verification itself fails, the
    # pre-installer rollback path still knows which barrier it must release.
    $script:Vb365MaintenanceSessionId = $sessionId
    $script:Vb365MaintenancePending = $false
    Set-RecoveryProperty Vb365MaintenanceSessionId $sessionId
    Set-RecoveryProperty Vb365MaintenancePending $false
    Save-RecoveryState -Stage $script:Stage -InstallerStarted $false
    $verified = Get-VBORepositoryMaintenanceSession -Id $session.Id -ErrorAction Stop
    if (-not $verified -or "$($verified.State)" -ne 'Running') {
        $state = if ($verified) { "$($verified.State)" } else { 'missing' }
        throw "VB365 maintenance session $sessionId did not reach Running (state=$state)"
    }
    Write-Log "VB365 repository maintenance session $sessionId is Running; new repository operations are blocked" OK
    return $sessionId
}

function Find-Vb365MaintenanceBarrier {
    param(
        [Parameter(Mandatory)][string] $AttemptedAt,
        [Parameter(Mandatory)][string[]] $RepositoryIds
    )
    $recordedAttemptUtc = ([datetime]$AttemptedAt).ToUniversalTime()
    $attemptStartUtc = $recordedAttemptUtc.AddMinutes(-5)
    $attemptEndUtc = $recordedAttemptUtc.AddMinutes(5)
    $expected = @($RepositoryIds | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique)
    $activeStates = @('Initialized','Preparing','Running','Finishing','Canceling','Failing')
    return @(Get-VBORepositoryMaintenanceSession -ErrorAction Stop | Where-Object {
        if ("$($_.State)" -notin $activeStates -or -not $_.StartTime) { return $false }
        $sessionStartUtc = $_.StartTime.ToUniversalTime()
        if ($sessionStartUtc -lt $attemptStartUtc -or $sessionStartUtc -gt $attemptEndUtc) { return $false }
        $actual = @($_.RepositoryIds | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique)
        return ($actual.Count -eq $expected.Count -and (@(Compare-Object $actual $expected).Count -eq 0))
    })
}

function Resolve-Vb365PendingMaintenanceBarrier {
    if (-not $script:Vb365MaintenancePending -or $script:Vb365MaintenanceSessionId) { return }
    $attemptedAt = "$(Get-CfgValue $script:RecoveryState 'Vb365MaintenanceAttemptedAt' '')"
    $repositoryIds = @(Get-CfgValue $script:RecoveryState 'Vb365MaintenanceRepositoryIds' @())
    if (-not $attemptedAt -or $repositoryIds.Count -eq 0) {
        throw 'VB365 maintenance was pending but its attempted time/repository IDs are missing'
    }
    $attemptUtc = ([datetime]$attemptedAt).ToUniversalTime()
    # The ownership matcher accepts a session created up to five minutes after
    # the request timestamp. Do not interpret one immediate empty read as proof
    # that the server rejected a request whose client connection timed out.
    $discoveryDeadlineUtc = $attemptUtc.AddMinutes(5).AddSeconds(30)
    $boundedDeadlineUtc = (Get-Date).ToUniversalTime().AddMinutes(5).AddSeconds(30)
    if ($discoveryDeadlineUtc -gt $boundedDeadlineUtc) { $discoveryDeadlineUtc = $boundedDeadlineUtc }
    while ($true) {
        $candidate = @(Find-Vb365MaintenanceBarrier -AttemptedAt $attemptedAt -RepositoryIds $repositoryIds)
        if ($candidate.Count -gt 0) {
            throw "VB365 maintenance start outcome is unknown and $($candidate.Count) time/scope-matched active session(s) exist. Their IDs were not returned by this run, so they will not be adopted or stopped automatically; inspect them in the VB365 console."
        }
        if ((Get-Date).ToUniversalTime() -ge $discoveryDeadlineUtc) { break }
        Start-Sleep -Seconds 5
    }
    $script:Vb365MaintenancePending = $false
    Set-RecoveryProperty Vb365MaintenancePending $false
    $installerStarted = [bool](Get-CfgValue $script:RecoveryState 'InstallerStarted' $false)
    Save-RecoveryState -Stage $script:Stage -InstallerStarted $installerStarted
}

function Stop-Vb365MaintenanceBarrier {
    param([string] $SessionId)
    if (-not $SessionId) { return }
    foreach ($commandName in @('Get-VBORepositoryMaintenanceSession','Stop-VBORepositoryMaintenanceSession')) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            throw "$commandName is unavailable while releasing VB365 maintenance session $SessionId"
        }
    }

    $session = Get-VBORepositoryMaintenanceSession -Id ([guid]$SessionId) -ErrorAction Stop
    if ($session -and "$($session.State)" -notin @('Finished','Canceled','Failed')) {
        Stop-VBORepositoryMaintenanceSession -Id ([guid]$SessionId) -ErrorAction Stop
    }
    for ($attempt = 1; $attempt -le 24; $attempt++) {
        $session = Get-VBORepositoryMaintenanceSession -Id ([guid]$SessionId) -ErrorAction Stop
        if (-not $session -or "$($session.State)" -in @('Finished','Canceled')) { break }
        if ("$($session.State)" -eq 'Failed') { throw "VB365 maintenance session $SessionId failed: $($session.ErrorMessage)" }
        if ($attempt -lt 24) { Start-Sleep -Seconds 5 }
    }
    if ($session -and "$($session.State)" -notin @('Finished','Canceled')) {
        throw "VB365 maintenance session $SessionId is still $($session.State) after the stop request"
    }
    $script:Vb365MaintenanceSessionId = $null
    $script:Vb365MaintenancePending = $false
    Set-RecoveryProperty Vb365MaintenanceSessionId $null
    Set-RecoveryProperty Vb365MaintenancePending $false
    $installerStarted = $false
    if ($script:RecoveryState -and $script:RecoveryState.PSObject.Properties.Name -contains 'InstallerStarted') {
        $installerStarted = [bool]$script:RecoveryState.InstallerStarted
    }
    Save-RecoveryState -Stage $script:Stage -InstallerStarted $installerStarted
    Write-Log "VB365 repository maintenance session $SessionId released" OK
}

# PostgreSQL encodes server_version_num differently across the 10.0 boundary.
#   10+   : major*10000 + minor              170011 = 17.11
#   pre-10: major*10000 + minor*100 + patch   90624 = 9.6.24
function ConvertFrom-ServerVersionNum {
    param([Parameter(Mandatory)][int] $Num)
    $maj = [int][math]::Floor($Num / 10000)
    if ($maj -lt 10) {
        $min = [int][math]::Floor(($Num % 10000) / 100)
        $pat = $Num % 100
        return [pscustomobject]@{ Branch = "$maj.$min"; Version = "$maj.$min.$pat" }
    }
    return [pscustomobject]@{ Branch = "$maj"; Version = "$maj.$($Num % 10000)" }
}

function ConvertTo-ServerVersionNum {
    param([Parameter(Mandatory)][string] $Version)
    $p = $Version -split '\.'
    if ([int]$p[0] -lt 10) {
        if ($p.Count -lt 3) { throw "Pre-10 version '$Version' needs three parts to compute server_version_num" }
        return ([int]$p[0] * 10000) + ([int]$p[1] * 100) + [int]$p[2]
    }
    return ([int]$p[0] * 10000) + [int]$p[1]
}

function Get-BranchKey {
    param([Parameter(Mandatory)][string] $Version)
    $p = $Version -split '\.'
    if ([int]$p[0] -lt 10) { return ($p[0..1] -join '.') }
    return $p[0]
}

function Compare-PgVersion {
    param([string] $A, [string] $B)   # returns -1 / 0 / 1
    $pa = $A -split '\.'; $pb = $B -split '\.'
    for ($i = 0; $i -lt [math]::Max($pa.Count, $pb.Count); $i++) {
        $x = if ($i -lt $pa.Count) { [int]$pa[$i] } else { 0 }
        $y = if ($i -lt $pb.Count) { [int]$pb[$i] } else { 0 }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    return 0
}

function Resolve-LatestPgTarget {
    param(
        [Parameter(Mandatory)] $Versions,
        [Parameter(Mandatory)][string] $InstalledBranch
    )

    $branchRows = @($Versions | Where-Object { "$($_.major)" -eq "$InstalledBranch" })
    if ($branchRows.Count -eq 0) { throw "PostgreSQL branch $InstalledBranch does not appear in versions.json" }
    if ($branchRows.Count -gt 1) { throw "PostgreSQL branch $InstalledBranch appears more than once in versions.json" }

    $row = $branchRows[0]
    $major = "$($row.major)"
    $minor = "$($row.latestMinor)"
    if (-not $major -or $minor -notmatch '^\d+$') {
        throw "PostgreSQL branch $InstalledBranch has an invalid latestMinor value '$minor' in versions.json"
    }

    $version = "$major.$minor"
    if ((Get-BranchKey $version) -ne "$InstalledBranch") {
        throw "Resolved target $version does not stay on installed branch $InstalledBranch"
    }

    return [pscustomobject]@{
        Version   = $version
        Supported = [bool](Get-CfgValue $row 'supported' $false)
        EolDate   = Get-CfgValue $row 'eolDate' $null
    }
}

function Get-ActiveLabelsFromSessions {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Sessions,
        [Parameter(Mandatory)][string] $Prefix,
        [switch] $AssumeReturnedActive
    )
    $labels = @()
    # Idle means no I/O between scheduled runs; ActionRequired is a stopped
    # copy/move session awaiting operator action. Both are quiescent for the
    # outage decision, while the Azure IR Ready/Switching states below are live.
    $terminal = @('Stopped','Idle','ActionRequired','Success','Succeeded','Warning','Failed','Completed','Complete','Finished','Canceled','Cancelled','NotConfigured','None')
    $activeStates = @('Starting','Stopping','Working','Running','Pausing','Resuming','WaitingTape',
                       'WaitingRepository','WaitingSlot','Pending','Postprocessing','DirtyBlocks',
                       'Queued','Updating','Disconnected','InProgress','Initialized','Preparing','Finishing','Canceling','Failing',
                       'Ready','Migrating','ReadyToSwitch','Switching')
    foreach ($session in @($Sessions)) {
        $state = $null
        foreach ($propertyName in @('State','Status')) {
            if ($session.PSObject.Properties.Name -contains $propertyName -and $null -ne $session.$propertyName) {
                $state = "$($session.$propertyName)"
                break
            }
        }
        if (-not $state) {
            if ($AssumeReturnedActive) { $labels += "${Prefix}:Active"; continue }
            throw [System.NotSupportedException]::new("$Prefix session has no readable State or Status property")
        }
        if ($terminal -contains $state) { continue }
        if ($activeStates -notcontains $state) {
            throw [System.NotSupportedException]::new("$Prefix returned unknown session state '$state'; refusing to assume the server is idle")
        }
        $labels += "${Prefix}:$state"
    }
    return $labels
}

function Get-ActiveVb365OrganizationSyncWork {
    foreach ($required in @('Get-VBOOrganization','Get-VBOOrganizationSynchronizationState')) {
        if (-not (Get-Command $required -ErrorAction SilentlyContinue)) {
            throw [System.NotSupportedException]::new("$required is unavailable, so VB365 organization-cache synchronization cannot be checked safely")
        }
    }

    $labels = @()
    $organizationNumber = 0
    foreach ($organization in @(Get-VBOOrganization -ErrorAction Stop)) {
        $organizationNumber++
        $organizationLabel = if ($organization.PSObject.Properties.Name -contains 'Name' -and $organization.Name) {
            "$($organization.Name)"
        } elseif ($organization.PSObject.Properties.Name -contains 'Id' -and $organization.Id) {
            "$($organization.Id)"
        } else {
            "#$organizationNumber"
        }

        $syncState = Get-VBOOrganizationSynchronizationState -Organization $organization -ErrorAction Stop
        if ($null -eq $syncState) {
            throw [System.NotSupportedException]::new("VB365 organization '$organizationLabel' returned no synchronization-state object")
        }
        foreach ($propertyName in @('CurrentState','Parts')) {
            if ($syncState.PSObject.Properties.Name -notcontains $propertyName) {
                throw [System.NotSupportedException]::new("VB365 organization '$organizationLabel' synchronization state has no $propertyName property")
            }
        }
        if ($null -eq $syncState.Parts) {
            throw [System.NotSupportedException]::new("VB365 organization '$organizationLabel' synchronization state has no readable per-part state")
        }

        $currentStates = @([pscustomobject]@{ Scope='All'; Value=$syncState.CurrentState })
        foreach ($partName in @('Users','Groups','GroupMembers','Sites','Mailboxes')) {
            if ($syncState.Parts.PSObject.Properties.Name -notcontains $partName) {
                throw [System.NotSupportedException]::new("VB365 organization '$organizationLabel' synchronization state has no $partName part")
            }
            $partState = $syncState.Parts.$partName
            if ($null -eq $partState) { continue } # Outside this organization's synchronization scope.
            if ($partState.PSObject.Properties.Name -notcontains 'CurrentState') {
                throw [System.NotSupportedException]::new("VB365 organization '$organizationLabel' $partName synchronization state has no CurrentState property")
            }
            $currentStates += [pscustomobject]@{ Scope=$partName; Value=$partState.CurrentState }
        }

        foreach ($current in $currentStates) {
            if ($null -eq $current.Value) { continue }
            if ($current.Value.PSObject.Properties.Name -notcontains 'Status' -or $null -eq $current.Value.Status) {
                throw [System.NotSupportedException]::new("VB365 organization '$organizationLabel' $($current.Scope) synchronization has no readable Status")
            }
            $status = "$($current.Value.Status)"
            if ($status -notin @('Queued','Running')) {
                throw [System.NotSupportedException]::new("VB365 organization '$organizationLabel' $($current.Scope) synchronization returned unknown current status '$status'")
            }
            $labels += "VB365:OrganizationSync:${organizationLabel}:$($current.Scope):$status"
        }
    }
    return $labels
}

function Test-VbrFamilyInUse {
    param([Parameter(Mandatory)][string[]] $Family)
    try {
        if ($script:ManagedJobInventory) {
            return (@($script:ManagedJobInventory | Where-Object { $Family -contains $_.Family }).Count -gt 0)
        }
    } catch {}
    return $false
}

function Get-BlockingVeeamUiProcesses {
    param([bool] $Vbr, [bool] $Vb365)
    $processes = @(Get-Process -Name 'Veeam*' -ErrorAction SilentlyContinue)
    return @($processes | Where-Object {
        (($Vbr -or $Vb365) -and $_.ProcessName -like 'Veeam*Explorer*') -or
        ($Vbr -and $_.ProcessName -eq 'Veeam.Backup.Shell') -or
        ($Vb365 -and $_.ProcessName -eq 'Veeam.Archiver.Shell')
    })
}

# Returns one short label per active operation. Every relevant query is fail-closed:
# absence/error never means idle when that workload family is installed.
function Get-ActiveVeeamWork {
    param([bool] $Vbr, [bool] $Vb365)
    $active = @()
    if ($Vbr) {
        foreach ($required in @('Get-VBRBackupSession','Get-VBRRestoreSession')) {
            if (-not (Get-Command $required -ErrorAction SilentlyContinue)) {
                throw [System.NotSupportedException]::new("$required is unavailable, so VBR activity cannot be checked safely")
            }
        }
        $active += @(Get-ActiveLabelsFromSessions -Sessions @(Get-VBRBackupSession -ErrorAction Stop) -Prefix 'VBR:Backup')
        $active += @(Get-ActiveLabelsFromSessions -Sessions @(Get-VBRRestoreSession -ErrorAction Stop) -Prefix 'VBR:Restore')

        # Protection-group rescans own their deployment work until the discovery
        # session completes. Get-VBRBackupSession does not reliably expose these,
        # so query both current and legacy discovery session types explicitly.
        if (Test-VbrFamilyInUse @('VBRProtection')) {
            if (-not (Get-Command Get-VBRSession -ErrorAction SilentlyContinue)) {
                throw [System.NotSupportedException]::new('Get-VBRSession is unavailable for configured protection groups')
            }
            foreach ($discoveryType in @('EpAgentDiscovery','EpAgentDiscoveryObsolete')) {
                $discoverySessions = @(Get-VBRSession -Type $discoveryType -ErrorAction Stop)
                $active += @(Get-ActiveLabelsFromSessions -Sessions $discoverySessions -Prefix 'VBR:ProtectionDiscovery')
            }
        }

        $collectors = @(
            [pscustomobject]@{ Command='Get-VBRTapeBackupSession';          Families=@('VBRTape');        Prefix='VBR:Tape';          Assume=$false },
            [pscustomobject]@{ Command='Get-VBRComputerBackupJobSession';  Families=@('VBRAgent','VBRAgentCopy'); Prefix='VBR:Agent'; Assume=$false },
            [pscustomobject]@{ Command='Get-VBREPSession';                 Families=@('VBRStandalone');  Prefix='VBR:Standalone';    Assume=$false },
            [pscustomobject]@{ Command='Get-VBRApplicationBackupJobSession';Families=@('VBRApplication'); Prefix='VBR:Application';   Assume=$false },
            [pscustomobject]@{ Command='Get-VBRPluginBackupSession';       Families=@('VBRPlugin');      Prefix='VBR:PluginBackup';  Assume=$false },
            [pscustomobject]@{ Command='Get-VBRPluginRestoreSession';      Families=@('VBRPlugin');      Prefix='VBR:PluginRestore'; Assume=$true  },
            [pscustomobject]@{ Command='Get-VBRSureBackupSession';         Families=@('VBRSureBackup');  Prefix='VBR:SureBackup';    Assume=$false },
            [pscustomobject]@{ Command='Get-VBRUnstructuredBackupFLRSession';Families=@('VBRUnstructured');Prefix='VBR:UnstructuredRestore';Assume=$true },
            [pscustomobject]@{ Command='Get-VBRADForestRestoreSession';     Families=@(); Prefix='VBR:ADRestore';          Assume=$false },
            [pscustomobject]@{ Command='Get-VBRAmazonRestoreSession';      Families=@(); Prefix='VBR:AmazonRestore';      Assume=$false },
            [pscustomobject]@{ Command='Get-VBRAzureRestoreSession';       Families=@(); Prefix='VBR:AzureRestore';       Assume=$false },
            [pscustomobject]@{ Command='Get-VBRAzureApplianceSession';     Families=@(); Prefix='VBR:AzureAppliance';     Assume=$false },
            [pscustomobject]@{ Command='Get-VBRCloudTapeRestoreSession';   Families=@(); Prefix='VBR:CloudTapeRestore';   Assume=$false },
            [pscustomobject]@{ Command='Get-VBREntraIDTenantRestoreSession';Families=@();Prefix='VBR:EntraRestore';       Assume=$false },
            [pscustomobject]@{ Command='Get-VBRGoogleCloudRestoreSession'; Families=@(); Prefix='VBR:GoogleRestore';      Assume=$false },
            [pscustomobject]@{ Command='Get-VBRExchangeItemRestoreSession';Families=@(); Prefix='VBR:ExchangeRestore';    Assume=$true  },
            [pscustomobject]@{ Command='Get-VBRSharePointItemRestoreSession';Families=@();Prefix='VBR:SharePointRestore';  Assume=$true  },
            [pscustomobject]@{ Command='Get-VBRInstantRecovery';           Families=@(); Prefix='VBR:InstantRecovery';    Assume=$true  },
            [pscustomobject]@{ Command='Get-VBRNASInstantRecovery';        Families=@(); Prefix='VBR:NASInstantRecovery'; Assume=$true  },
            [pscustomobject]@{ Command='Get-VBRFCDInstantRecoverySession'; Families=@(); Prefix='VBR:FCDInstantRecovery'; Assume=$true  },
            [pscustomobject]@{ Command='Get-VBRPublishedBackupContentSession';Families=@();Prefix='VBR:PublishedContent'; Assume=$true  },
            [pscustomobject]@{ Command='Get-VBRPublishedBackupDiskSession';Families=@(); Prefix='VBR:PublishedDisk';       Assume=$true  },
            [pscustomobject]@{ Command='Get-VBRAzureInstantRecovery';      Families=@(); Prefix='VBR:AzureInstantRecovery';Assume=$true },
            [pscustomobject]@{ Command='Get-VBRVirtualMachineStartSession';Families=@(); Prefix='VBR:VMStart';             Assume=$false },
            [pscustomobject]@{ Command='Get-VBRTestQuickMigrationSession'; Families=@(); Prefix='VBR:QuickMigration';      Assume=$false },
            [pscustomobject]@{ Command='Get-VBRInstantRecoveryMigration';  Families=@(); Prefix='VBR:IRMigration';        Assume=$true  },
            [pscustomobject]@{ Command='Get-VBRNASInstantRecoveryMigration';Families=@();Prefix='VBR:NASIRMigration';     Assume=$true  }
        )
        foreach ($collector in $collectors) {
            $inUse = $false
            if (@($collector.Families).Count -gt 0) { $inUse = Test-VbrFamilyInUse $collector.Families }
            $command = Get-Command $collector.Command -ErrorAction SilentlyContinue
            if ($inUse -and -not $command) {
                throw [System.NotSupportedException]::new("$($collector.Command) is unavailable for installed family $($collector.Families -join '/')")
            }
            if ($command) {
                $sessions = @(& $collector.Command -ErrorAction Stop)
                $active += @(Get-ActiveLabelsFromSessions -Sessions $sessions -Prefix $collector.Prefix -AssumeReturnedActive:([bool]$collector.Assume))
            }
        }

        # Explorer modules expose only a subset of sessions (often those started
        # through PowerShell), so these are supplemental to the process barrier
        # below. Every object returned by these active-session APIs is busy.
        foreach ($commandName in @('Get-VEADRestoreSession','Get-VEHANARestoreSession','Get-VEMDBRestoreSession',
                                    'Get-VEODRestoreSession','Get-VEORRestoreSession','Get-VEORRMANRestoreSession',
                                    'Get-VEPSQLRestoreSession','Get-VESQLPluginRestoreSession','Get-VESQLRDSRestoreSession',
                                    'Get-VESQLRestoreSession')) {
            if (Get-Command $commandName -ErrorAction SilentlyContinue) {
                $active += @(Get-ActiveLabelsFromSessions -Sessions @(& $commandName -ErrorAction Stop) -Prefix "VBR:$commandName" -AssumeReturnedActive)
            }
        }

        # Get-VBRUnstructuredBackupSession has no all-sessions parameter set.
        # Query exact inventory-derived job-name patterns; its -Id parameter is a
        # session ID and must never be given a job ID.
        $unstructuredEntries = @($script:ManagedJobInventory | Where-Object { $_.Family -in @('VBRUnstructured','VBRUnstructuredCopy') })
        if ($unstructuredEntries.Count -gt 0) {
            if (-not (Get-Command Get-VBRUnstructuredBackupSession -ErrorAction SilentlyContinue)) {
                throw [System.NotSupportedException]::new('Get-VBRUnstructuredBackupSession is unavailable for configured unstructured jobs')
            }
            $unstructuredSessions = @()
            foreach ($entry in $unstructuredEntries) {
                $escapedName = [WildcardPattern]::Escape("$($entry.Name)")
                $unstructuredSessions += @(Get-VBRUnstructuredBackupSession -Name "${escapedName}*" -ErrorAction Stop)
            }
            $unstructuredSessions = @($unstructuredSessions | Sort-Object Id -Unique)
            $active += @(Get-ActiveLabelsFromSessions -Sessions $unstructuredSessions -Prefix 'VBR:Unstructured')
        }

        # Newer VBR builds expose an all-session parameter set. Prefer it so
        # orphaned or machine-scoped transfers are not missed; retain the
        # per-backup path for older builds whose command metadata requires it.
        foreach ($commandName in @('Get-VBRCopyBackupSession','Get-VBRMoveBackupSession')) {
            $command = Get-Command $commandName -ErrorAction SilentlyContinue
            if ($command) {
                $transferSessions = @()
                $hasZeroArgumentSet = @($command.ParameterSets | Where-Object {
                    @($_.Parameters | Where-Object { $_.IsMandatory }).Count -eq 0
                }).Count -gt 0
                if ($hasZeroArgumentSet) {
                    $transferSessions = @(& $commandName -ErrorAction Stop)
                } else {
                    if (-not (Get-Command Get-VBRBackup -ErrorAction SilentlyContinue)) {
                        throw [System.NotSupportedException]::new("$commandName is available but Get-VBRBackup is not")
                    }
                    foreach ($backup in @(Get-VBRBackup -ErrorAction Stop)) {
                        $transferSessions += @(& $commandName -Backup $backup -ErrorAction Stop)
                    }
                }
                $transferSessions = @($transferSessions | Sort-Object Id -Unique)
                $active += @(Get-ActiveLabelsFromSessions -Sessions $transferSessions -Prefix "VBR:$commandName")
            }
        }

        # Job objects captured before the wait loop are snapshots. Refresh each
        # relevant family once per poll so a completed job cannot leave a stale
        # IsRunning=True value that holds the maintenance window open forever.
        # The same fresh objects are used for CDP session queries.
        $freshVbrObjects = @{}
        $recordsToRefresh = @($script:ManagedJobInventory | Where-Object {
            $_.Family -like 'VBR*' -and
            ($_.Family -eq 'VBRCDP' -or $_.Object.PSObject.Properties.Name -contains 'IsRunning')
        })
        foreach ($familyGroup in @($recordsToRefresh | Group-Object Family)) {
            $definition = Get-VeeamJobFamilyDefinition $familyGroup.Name
            if (-not (Get-Command $definition.Get -ErrorAction SilentlyContinue)) {
                throw [System.NotSupportedException]::new("$($definition.Get) is unavailable while refreshing $($familyGroup.Name) activity")
            }
            $freshJobs = @(& $definition.Get -ErrorAction Stop)
            foreach ($entry in @($familyGroup.Group)) {
                $resolvedJobs = @($freshJobs | Where-Object {
                    (Get-VeeamJobIdentity -Job $_ -Family $definition.Family) -eq "$($entry.Id)"
                })
                if ($resolvedJobs.Count -ne 1) {
                    throw "$($entry.Family) job id $($entry.Id) resolved to $($resolvedJobs.Count) objects while checking activity"
                }
                $freshVbrObjects["$($entry.Family)::$($entry.Id)".ToLowerInvariant()] = $resolvedJobs[0]
            }
        }

        if (Test-VbrFamilyInUse @('VBRCDP')) {
            if (-not (Get-Command Get-VBRCDPSession -ErrorAction SilentlyContinue)) {
                throw [System.NotSupportedException]::new('Get-VBRCDPSession is unavailable for installed CDP policies')
            }
            foreach ($entry in @($script:ManagedJobInventory | Where-Object { $_.Family -eq 'VBRCDP' })) {
                $key = "$($entry.Family)::$($entry.Id)".ToLowerInvariant()
                $session = @(Get-VBRCDPSession -Policy $freshVbrObjects[$key] -Last -ErrorAction Stop)
                $active += @(Get-ActiveLabelsFromSessions -Sessions $session -Prefix 'VBR:CDP')
            }
        }

        # A family-specific session API can lag behind a running object. Treat a
        # fresh explicit IsRunning flag as an additional signal, never a substitute.
        foreach ($entry in @($script:ManagedJobInventory)) {
            if ($entry.Family -notlike 'VBR*') { continue }
            if ($entry.Object.PSObject.Properties.Name -contains 'IsRunning') {
                $key = "$($entry.Family)::$($entry.Id)".ToLowerInvariant()
                $freshJob = $freshVbrObjects[$key]
                if ($freshJob.PSObject.Properties.Name -notcontains 'IsRunning') {
                    throw [System.NotSupportedException]::new("$($entry.Family) '$($entry.Name)' lost its IsRunning activity property during refresh")
                }
                if ($freshJob.IsRunning -eq $true) { $active += "$($entry.Family):IsRunning" }
            }
        }
    }
    if ($Vb365) {
        foreach ($required in @('Get-VBOJobSession','Get-VBORestoreSession')) {
            if (-not (Get-Command $required -ErrorAction SilentlyContinue)) {
                throw [System.NotSupportedException]::new("$required is unavailable, so VB365 activity cannot be checked safely")
            }
        }
        $active += @(Get-ActiveLabelsFromSessions -Sessions @(Get-VBOJobSession -ErrorAction Stop) -Prefix 'VB365:Job')
        # This cmdlet returns only the requested active restore sessions.
        $active += @(Get-ActiveLabelsFromSessions -Sessions @(Get-VBORestoreSession -Status Running -ErrorAction Stop) -Prefix 'VB365:Restore' -AssumeReturnedActive)
        # Organization synchronization writes the PostgreSQL-backed organization
        # cache rather than a backup repository, so repository maintenance does
        # not cover it. VB365 8.6 can synchronize five parts independently.
        $active += @(Get-ActiveVb365OrganizationSyncWork)

        foreach ($commandName in @('Get-VBODataRetrievalSession','Get-VBODataManagementSession',
                                    'Get-VBORepositorySynchronizeSession','Get-VBORepositoryUpgradeSession')) {
            if (Get-Command $commandName -ErrorAction SilentlyContinue) {
                $active += @(Get-ActiveLabelsFromSessions -Sessions @(& $commandName -ErrorAction Stop) -Prefix "VB365:$commandName")
            }
        }
        foreach ($commandName in @('Get-VBOExchangeItemRestoreSession','Get-VBOSharePointItemRestoreSession','Get-VBOTeamsItemRestoreSession')) {
            if (Get-Command $commandName -ErrorAction SilentlyContinue) {
                $active += @(Get-ActiveLabelsFromSessions -Sessions @(& $commandName -ErrorAction Stop) -Prefix "VB365:$commandName" -AssumeReturnedActive)
            }
        }
    }
    foreach ($process in @(Get-BlockingVeeamUiProcesses -Vbr $Vbr -Vb365 $Vb365)) {
        $active += "UI:$($process.ProcessName):PID$($process.Id)"
    }
    return @($active | Sort-Object -Unique)
}

function Wait-VeeamIdle {
    param(
        [bool] $Vbr,
        [bool] $Vb365,
        [ValidateRange(1,10080)][int] $TimeoutMinutes = 720,
        [ValidateRange(1,300)][int] $PollSeconds = 60,
        [string] $Context = 'before maintenance'
    )
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $lastSummary = $null
    $lastHeartbeatMinute = -1
    while ($true) {
        $busy = @(Get-ActiveVeeamWork -Vbr $Vbr -Vb365 $Vb365)
        if ($busy.Count -eq 0) {
            return [pscustomobject]@{ Idle=$true; Labels=@(); ElapsedMinutes=[math]::Round($timer.Elapsed.TotalMinutes,1) }
        }
        $summary = $busy -join ', '
        $wholeMinute = [int][math]::Floor($timer.Elapsed.TotalMinutes)
        if ($summary -ne $lastSummary -or $wholeMinute -ge ($lastHeartbeatMinute + 10)) {
            Write-Log "Waiting for Veeam work to finish naturally $Context ($summary); elapsed $wholeMinute minute(s). No job or restore will be forcibly stopped." WARN
            $lastSummary = $summary
            $lastHeartbeatMinute = $wholeMinute
        }
        if ($timer.Elapsed.TotalMinutes -ge $TimeoutMinutes) {
            return [pscustomobject]@{ Idle=$false; Labels=$busy; ElapsedMinutes=[math]::Round($timer.Elapsed.TotalMinutes,1) }
        }
        Start-Sleep -Seconds $PollSeconds
    }
}

function Invoke-ExplicitRecovery {
    param([Parameter(Mandatory)][string] $MarkerPath, [Parameter(Mandatory)] $Cfg)

    if (-not (Test-TrustedOwner $MarkerPath)) {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'UNTRUSTED_RECOVERY_MARKER' 'The recovery marker is not owned by SYSTEM or Administrators. No automatic action was taken.'
    }
    $marker = $null
    try { $marker = Get-Content -LiteralPath $MarkerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'LEGACY_OR_INVALID_MARKER' "The marker is not a versioned recovery pointer. No automatic action was taken. Inspect it and recover manually: $($_.Exception.Message)"
    }
    foreach ($required in @('SchemaVersion','RunDir','StateFile','InstallerStarted','Stage')) {
        if ($marker.PSObject.Properties.Name -notcontains $required) {
            $script:Stage = 'INSTALLING'
            Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_MARKER' "Recovery marker is missing '$required'. No automatic action was taken."
        }
    }

    $runsRoot = [IO.Path]::GetFullPath((Join-Path $WorkRoot 'runs')).TrimEnd('\') + '\'
    try {
        $statePath = [IO.Path]::GetFullPath("$($marker.StateFile)")
        $runPath = [IO.Path]::GetFullPath("$($marker.RunDir)").TrimEnd('\')
    } catch {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_PATH' "Recovery path is invalid: $($_.Exception.Message)"
    }
    if (-not $statePath.StartsWith($runsRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (($runPath + '\').StartsWith($runsRoot, [StringComparison]::OrdinalIgnoreCase)) -or
        $statePath -ine (Join-Path $runPath 'recovery-state.json')) {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_PATH' 'Recovery paths do not resolve inside this WorkRoot\runs directory.'
    }
    if (-not (Test-Path -LiteralPath $statePath) -or -not (Test-TrustedOwner $statePath)) {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'UNTRUSTED_RECOVERY_STATE' "Recovery state is missing or is not owned by SYSTEM/Administrators: $statePath"
    }
    try { $state = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_STATE' "Could not parse $statePath : $($_.Exception.Message)"
    }
    if ([int]$state.SchemaVersion -ne 1 -or "$($state.RunDir)" -ine $runPath) {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_STATE' 'Recovery manifest schema or run-directory binding is invalid.'
    }

    $script:RunDir = $runPath
    $script:RecoveryState = $state
    $script:Report.RecoveryRunDir = $runPath
    $script:Stage = "$($state.Stage)"
    $script:Report.VeeamProducts = "$(Get-CfgValue $state 'Products' '')"
    $script:Report.PgInstalled = "$(Get-CfgValue $state 'OriginalVersion' '')"
    $script:Report.PgTarget = "$(Get-CfgValue $state 'TargetVersion' '')"
    $script:Vb365MaintenanceSessionId = "$(Get-CfgValue $state 'Vb365MaintenanceSessionId' '')"
    $script:Vb365MaintenancePending = [bool](Get-CfgValue $state 'Vb365MaintenancePending' $false)

    if ([bool]$state.InstallerStarted -or $script:Stage -in @('INSTALLING','VERIFIED','COMPLETE')) {
        $diagnostics = @()
        $emergency = $false
        $pgServiceName = "$(Get-CfgValue $state 'PgServiceName' '')"
        $psqlPath = "$(Get-CfgValue $state 'PsqlPath' '')"
        $port = "$(Get-CfgValue $state 'PgPort' '')"
        if ($pgServiceName) {
            $svc = Get-Service -Name $pgServiceName -ErrorAction SilentlyContinue
            if (-not $svc) { $diagnostics += "PostgreSQL service '$pgServiceName' is missing"; $emergency = $true }
            else { $diagnostics += "PostgreSQL service $pgServiceName=$($svc.Status)"; if ($svc.Status -ne 'Running') { $emergency = $true } }
        }
        if ($psqlPath -and $port -and (Test-Path -LiteralPath $psqlPath)) {
            $probe = Invoke-Native $psqlPath @('-U','postgres','-h','127.0.0.1','-p',"$port",'-w','-At','-c','SHOW server_version_num;')
            if ($probe.ExitCode -eq 0 -and $probe.StdOut -match '^\d+$') { $diagnostics += "server_version_num=$($probe.StdOut)" }
            else { $diagnostics += "PostgreSQL connection failed: $($probe.StdErr)"; $emergency = $true }
        }
        $postInstallJobsPath = Join-Path $runPath 'disabled-jobs.json'
        try {
            if (-not (Test-Path -LiteralPath $postInstallJobsPath)) { throw 'disabled-jobs.json is missing' }
            if (-not (Test-TrustedOwner $postInstallJobsPath)) { throw 'disabled-jobs.json is not owned by SYSTEM or Administrators' }
            $recordedJobs = @(Get-Content -LiteralPath $postInstallJobsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
            $script:DisabledJobs = @($recordedJobs)
            $script:Report.JobsLeftDisabled = (Get-UnrestoredJobNames -Records $recordedJobs) -join ', '
        } catch {
            $script:Report.JobsLeftDisabled = "UNKNOWN (could not read trusted disabled-jobs.json: $($_.Exception.Message))"
            $diagnostics += $script:Report.JobsLeftDisabled
        }
        $script:Report.IssueCode = 'POST_INSTALL_RECOVERY_REQUIRES_OPERATOR'
        $script:Report.ActionRequired = 'PAGE AN OPERATOR. The installer may have started; recovery was diagnostic-only and no state was changed.'
        $code = if ($emergency) { $EXIT.ESCALATE_NOW } else { $EXIT.ESCALATE }
        Complete-Run $code 'RECOVERY_DIAGNOSTIC_ONLY' "InstallerStarted=True. $($diagnostics -join '; '). Inspect installer logs, validate PostgreSQL, and use the recorded state to decide whether any service/job restoration is still required."
    }

    if ($script:Stage -notin @('JOBS_DISABLED','SERVICES_STOPPED')) {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'RECOVERY_STAGE_UNSAFE' "Stage '$($state.Stage)' is not eligible for automatic recovery."
    }

    Write-Log "Pre-installer recovery is eligible (stage=$($state.Stage), run=$runPath)" WARN
    $problems = @()
    $jobsPath = Join-Path $runPath 'disabled-jobs.json'
    $servicePath = Join-Path $runPath 'veeam-service-state.json'
    $natsPath = Join-Path $runPath 'nats-service-state.json'
    $pgPath = Join-Path $runPath 'pg-service-state.json'

    try {
        if (-not (Test-Path -LiteralPath $jobsPath)) { throw 'disabled-jobs.json is missing' }
        $script:DisabledJobs = @(Get-Content $jobsPath -Raw | ConvertFrom-Json)
        foreach ($jobRecord in $script:DisabledJobs) {
            foreach ($field in @('Family','Id','Name','WasEnabled')) {
                if ($jobRecord.PSObject.Properties.Name -notcontains $field) { throw "job record is missing '$field'" }
            }
        }
        $script:Report.JobsLeftDisabled = (@($script:DisabledJobs | ForEach-Object { $_.Name }) -join ', ')
    } catch { $problems += "disabled job state is unreadable: $($_.Exception.Message)" }

    if ($script:Stage -eq 'SERVICES_STOPPED') {
        try {
            if (-not (Test-Path -LiteralPath $pgPath)) { throw 'pg-service-state.json is missing' }
            $pgState = Get-Content $pgPath -Raw | ConvertFrom-Json
            $script:PgServiceName = "$($pgState.Name)"
            $pgTypeForStart = if ([bool]$pgState.WasRunning -and "$($pgState.StartupType)" -eq 'Disabled') { 'Manual' } else { "$($pgState.StartupType)" }
            Set-ServiceStartupTypeExact -Name $script:PgServiceName -StartupType $pgTypeForStart
            $pgSvc = Get-Service -Name $script:PgServiceName -ErrorAction Stop
            if ([bool]$pgState.WasRunning -and $pgSvc.Status -ne 'Running') { Start-Service $script:PgServiceName -ErrorAction Stop }
            if (-not [bool]$pgState.WasRunning -and $pgSvc.Status -eq 'Running') {
                Write-Log "  leaving externally running $($script:PgServiceName) untouched during no-stop recovery" WARN
            } elseif (-not [bool]$pgState.WasRunning -and $pgSvc.Status -ne 'Stopped') {
                throw "PostgreSQL is in transitional state $($pgSvc.Status); it was left untouched"
            }
            if ("$($pgState.StartupType)" -eq 'Disabled') { Set-ServiceStartupTypeExact -Name $script:PgServiceName -StartupType Disabled }
            if ([bool]$pgState.WasRunning) {
                $connected = $false
                for ($i=1; $i -le 24; $i++) {
                    $probe = Invoke-Native "$($pgState.PsqlPath)" @('-U','postgres','-h','127.0.0.1','-p',"$($pgState.Port)",'-w','-At','-c','SHOW server_version_num;')
                    if ($probe.ExitCode -eq 0 -and $probe.StdOut -match '^\d+$') { $connected = $true; break }
                    Start-Sleep -Seconds 5
                }
                if (-not $connected) { throw 'PostgreSQL service did not become queryable' }
            }
            $pgSvc = Get-Service -Name $script:PgServiceName -ErrorAction Stop
            if ([bool]$pgState.WasRunning -and "$($pgSvc.Status)" -ne 'Running') { throw "expected status Running, got $($pgSvc.Status)" }
            if (-not [bool]$pgState.WasRunning -and "$($pgSvc.Status)" -notin @('Running','Stopped')) { throw "transitional state $($pgSvc.Status) did not settle to Running or Stopped" }
            $actualPgStartup = Get-ServiceStartupTypeExact $script:PgServiceName
            if ($actualPgStartup -ne "$($pgState.StartupType)") { throw "expected startup $($pgState.StartupType), got $actualPgStartup" }
        } catch { $problems += "PostgreSQL restore: $($_.Exception.Message)" }

        try {
            if (Test-Path -LiteralPath $natsPath) {
                $natsState = Get-Content $natsPath -Raw | ConvertFrom-Json
                $natsTypeForStart = if ([bool]$natsState.WasRunning -and "$($natsState.StartupType)" -eq 'Disabled') { 'Manual' } else { "$($natsState.StartupType)" }
                Set-ServiceStartupTypeExact -Name "$($natsState.Name)" -StartupType $natsTypeForStart
                $natsSvc = Get-Service -Name "$($natsState.Name)" -ErrorAction Stop
                if ([bool]$natsState.WasRunning -and $natsSvc.Status -ne 'Running') { Start-Service $natsState.Name -ErrorAction Stop }
                if (-not [bool]$natsState.WasRunning -and $natsSvc.Status -eq 'Running') {
                    Write-Log "  leaving externally running $($natsState.Name) untouched during no-stop recovery" WARN
                } elseif (-not [bool]$natsState.WasRunning -and $natsSvc.Status -ne 'Stopped') {
                    throw "NATS is in transitional state $($natsSvc.Status); it was left untouched"
                }
                if ("$($natsState.StartupType)" -eq 'Disabled') { Set-ServiceStartupTypeExact -Name "$($natsState.Name)" -StartupType Disabled }
                $natsSvc = Get-Service -Name "$($natsState.Name)" -ErrorAction Stop
                if ([bool]$natsState.WasRunning -and "$($natsSvc.Status)" -ne 'Running') { throw "expected status Running, got $($natsSvc.Status)" }
                if (-not [bool]$natsState.WasRunning -and "$($natsSvc.Status)" -notin @('Running','Stopped')) { throw "transitional state $($natsSvc.Status) did not settle to Running or Stopped" }
                $actualNatsStartup = Get-ServiceStartupTypeExact "$($natsState.Name)"
                if ($actualNatsStartup -ne "$($natsState.StartupType)") { throw "expected startup $($natsState.StartupType), got $actualNatsStartup" }
            }
        } catch { $problems += "NATS restore: $($_.Exception.Message)" }

        try {
            if (-not (Test-Path -LiteralPath $servicePath)) { throw 'veeam-service-state.json is missing' }
            $script:VeeamServices = @(Get-Content $servicePath -Raw | ConvertFrom-Json)
            $problems += @(Restore-VeeamServiceState -AllowStops:$false)
        } catch { $problems += "Veeam service restore: $($_.Exception.Message)" }
    }

    if ($problems.Count -eq 0) {
        $hasVbr = "$($state.Products)" -match '(^|\+)VBR($|\+)'
        $hasVb365 = "$($state.Products)" -match '(^|\+)VB365($|\+)'
        $moduleProblems = @(Connect-VeeamModules -Vbr:$hasVbr -Vb365:$hasVb365 -Reconnect:$hasVb365)
        if ($moduleProblems.Count -gt 0) { $problems += $moduleProblems }
        else {
            try {
                $script:ManagedJobInventory = @(Get-VeeamManagedJobInventory -Vbr $hasVbr -Vb365 $hasVb365)
                if ($script:Vb365MaintenancePending) { Resolve-Vb365PendingMaintenanceBarrier }
                if ($script:Vb365MaintenanceSessionId) {
                    Stop-Vb365MaintenanceBarrier -SessionId $script:Vb365MaintenanceSessionId
                }
                $timeout = [int](Get-CfgValue $Cfg 'jobWaitTimeoutMinutes' 720)
                $idle = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $timeout -Context 'during recovery'
                if (-not $idle.Idle) { $problems += "active work did not finish within $timeout minutes: $($idle.Labels -join ', ')" }
            } catch { $problems += "activity verification: $($_.Exception.Message)" }
        }
    }

    if ($problems.Count -eq 0) {
        foreach ($job in @($script:DisabledJobs)) {
            try {
                Enable-VeeamJobById $job
                if ($job.PSObject.Properties.Name -contains 'Restored') { $job.Restored = $true }
                Save-DisabledJobState
                Write-Log "  recovery re-enabled $($job.Family): $($job.Name)"
            }
            catch { $problems += "job '$($job.Name)': $($_.Exception.Message)" }
        }
    }

    if ($problems.Count -gt 0) {
        $script:Report.IssueCode = 'PREINSTALL_RECOVERY_INCOMPLETE'
        $script:Report.ActionRequired = 'PAGE AN OPERATOR. Automatic pre-installer recovery was incomplete; jobs remain recorded in RecoveryRunDir.'
        Complete-Run $EXIT.ESCALATE 'RECOVERY_INCOMPLETE' ($problems -join ' | ')
    }

    $script:Report.JobsLeftDisabled = ''
    Save-RecoveryState -Stage 'COMPLETE' -InstallerStarted $false
    if (-not (Remove-RecoveryMarker)) {
        $script:Report.IssueCode = 'MARKER_REMOVE_FAILED'
        Complete-Run $EXIT.ESCALATE 'RECOVERY_MARKER_REMOVE_FAILED' 'State was restored, but the recovery marker could not be removed.'
    }
    Complete-Run $EXIT.OK 'RECOVERED_PREINSTALL' 'Captured PostgreSQL, NATS, Veeam service and job states were restored and verified. The installer never started.'
}

# ---------------------------------------------------------------------------
# STEP 1 - Load operator config
# ---------------------------------------------------------------------------
Write-Log 'STEP 1 - Load settings' STEP

# The script carries its own settings, so an RMM that uploads only this one file
# just works. An override file is optional and only changes the keys it contains.
function Test-TrustedOwner {
    param([string] $Path)
    try {
        $owner = (Get-Acl -LiteralPath $Path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        return ($owner -eq 'S-1-5-18' -or $owner -eq 'S-1-5-32-544')
    } catch { return $false }
}

$Cfg = Get-DefaultConfig
$overridePath = $null

if ($ConfigPath) {
    # Asked for explicitly, so a missing file is an error, not a fallback.
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        Complete-Run $EXIT.PREFLIGHT 'NO_CONFIG' "You passed -ConfigPath but the file does not exist: $ConfigPath"
    }
    if (-not (Test-TrustedOwner $ConfigPath)) {
        Complete-Run $EXIT.PREFLIGHT 'UNTRUSTED_CONFIG' "The settings file is not owned by SYSTEM or Administrators and will not be executed as trusted RMM input: $ConfigPath"
    }
    $overridePath = $ConfigPath
} else {
    $workRootCfg = Join-Path $WorkRoot 'config.json'
    if (Test-Path -LiteralPath $workRootCfg) {
        # This script runs as SYSTEM. Only honour a settings file that a
        # non-admin could not have planted.
        if (Test-TrustedOwner $workRootCfg) { $overridePath = $workRootCfg }
        else { Write-Log "Ignoring $workRootCfg - it is not owned by SYSTEM or Administrators, so it cannot be trusted." WARN }
    }
    if (-not $overridePath -and $PSScriptRoot) {
        $besideCfg = Join-Path $PSScriptRoot 'VeeamPostgresUpdate.config.json'
        if (Test-Path -LiteralPath $besideCfg) {
            if (Test-TrustedOwner $besideCfg) { $overridePath = $besideCfg }
            else { Write-Log "Ignoring $besideCfg - it is not owned by SYSTEM or Administrators, so it cannot be trusted." WARN }
        }
    }
}

if ($overridePath) {
    try {
        $override = Get-Content -LiteralPath $overridePath -Raw | ConvertFrom-Json
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'BAD_CONFIG' "Could not parse the settings override $overridePath : $($_.Exception.Message)"
    }
    $knownKeys = @((Get-DefaultConfig).PSObject.Properties.Name)
    foreach ($n in @($override.PSObject.Properties.Name)) {
        if ($n -notlike '_*' -and $knownKeys -notcontains $n) {
            if ($n -in @('approvedTargets','supportedBranches','branchFloors')) {
                Write-Log "Override key '$n' has been removed and is ignored. Target selection always uses the latest minor on the installed PostgreSQL major branch." WARN
            } elseif ($n -in @('abortIfVeeamOnePresent','abortIfRemoteVb365Proxies')) {
                Write-Log "Override key '$n' has been removed and is ignored. Unsupported topologies are always rejected; this safety check cannot be disabled." WARN
            } elseif ($n -eq 'reapplyTuning') {
                Write-Log "Override key '$n' has been removed and is ignored. Veeam PostgreSQL tuning is mandatory after every update." WARN
            } else {
                Write-Log "Override key '$n' is not a setting this script uses and is ignored - check for a typo." WARN
            }
        }
    }
    $Cfg = Merge-Config $Cfg $override
    Write-Log "Settings: built-in, overridden by $overridePath" OK
} else {
    Write-Log 'Settings: built-in' OK
}
Write-Log 'PostgreSQL target policy: latest published minor on the installed major branch'

# Housekeeping, every run - audit runs included, or daily audits pile up forever.
# retentionDays covers transcripts AND recovery sets. Unresolved evidence and the
# two newest completed recovery sets (including their transcripts) are retained
# regardless of age. Deletion is limited to an owned, normalized runs directory.
if ($script:WorkRootIsOurs) {
    $retain = 30
    try { $retain = [int](Get-CfgValue $Cfg 'retentionDays' 30) } catch {}
    if ($retain -lt 1) { $retain = 30 }
    $cutoff = (Get-Date).AddDays(-$retain)
    $runsRoot = Join-Path $WorkRoot 'runs'
    $protectedRuns = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $protectedLogs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    [void]$protectedLogs.Add([IO.Path]::GetFullPath($script:Transcript))
    $completedRuns = @()
    $protectEveryRun = $false

    if (Test-Path -LiteralPath $runsRoot) {
        $runsRootFull = [IO.Path]::GetFullPath($runsRoot).TrimEnd('\') + '\'
        foreach ($rd in @(Get-ChildItem -LiteralPath $runsRoot -Directory -ErrorAction SilentlyContinue)) {
            $manifest = $null
            foreach ($candidate in @((Join-Path $rd.FullName 'recovery-state.json'), (Join-Path $rd.FullName 'result.json'))) {
                if (-not (Test-Path -LiteralPath $candidate)) { continue }
                try { $manifest = Get-Content -LiteralPath $candidate -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop; break }
                catch { $manifest = $null }
            }
            $manifestStage = if ($manifest -and $manifest.PSObject.Properties.Name -contains 'Stage') { "$($manifest.Stage)" } else { '' }
            $manifestLog = if ($manifest -and $manifest.PSObject.Properties.Name -contains 'LogPath') { "$($manifest.LogPath)" } else { '' }
            if ($manifestStage -eq 'COMPLETE') {
                $completedRuns += [pscustomobject]@{ Path=$rd.FullName; LogPath=$manifestLog; LastWriteTime=$rd.LastWriteTime }
            } else {
                # Empty abandoned directories have no recovery value; every
                # non-empty run lacking a COMPLETE record is treated as unresolved.
                $isEmpty = @(Get-ChildItem -LiteralPath $rd.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0
                if (-not $isEmpty) {
                    [void]$protectedRuns.Add([IO.Path]::GetFullPath($rd.FullName).TrimEnd('\'))
                    if ($manifestLog) { [void]$protectedLogs.Add([IO.Path]::GetFullPath($manifestLog)) }
                }
            }
        }

        foreach ($keep in @($completedRuns | Sort-Object LastWriteTime -Descending | Select-Object -First 2)) {
            [void]$protectedRuns.Add([IO.Path]::GetFullPath($keep.Path).TrimEnd('\'))
            if ($keep.LogPath) { [void]$protectedLogs.Add([IO.Path]::GetFullPath($keep.LogPath)) }
        }

        if (Test-Path -LiteralPath $script:MarkerFile) {
            $protectEveryRun = $true
            try {
                $markerForRetention = Get-Content -LiteralPath $script:MarkerFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $markedRun = [IO.Path]::GetFullPath("$($markerForRetention.RunDir)").TrimEnd('\')
                if (($markedRun + '\').StartsWith($runsRootFull, [StringComparison]::OrdinalIgnoreCase)) { [void]$protectedRuns.Add($markedRun) }
            } catch {}
        }

        foreach ($rd in @(Get-ChildItem -LiteralPath $runsRoot -Directory -ErrorAction SilentlyContinue)) {
            $fullRun = [IO.Path]::GetFullPath($rd.FullName).TrimEnd('\')
            if ($protectEveryRun -or $protectedRuns.Contains($fullRun) -or $fullRun -eq [IO.Path]::GetFullPath($script:RunDir).TrimEnd('\')) { continue }
            $isEmpty = @(Get-ChildItem -LiteralPath $fullRun -Force -ErrorAction SilentlyContinue).Count -eq 0
            if (($isEmpty -or $rd.LastWriteTime -lt $cutoff) -and (($fullRun + '\').StartsWith($runsRootFull, [StringComparison]::OrdinalIgnoreCase))) {
                Write-Log "  purging completed run folder $($rd.Name)$(if ($isEmpty) { ' (empty)' })"
                Remove-Item -LiteralPath $fullRun -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    foreach ($log in @(Get-ChildItem -LiteralPath $script:LogDir -File -Filter 'VeeamPgUpdate_*.log' -ErrorAction SilentlyContinue)) {
        $fullLog = [IO.Path]::GetFullPath($log.FullName)
        if (-not $protectEveryRun -and $log.LastWriteTime -lt $cutoff -and -not $protectedLogs.Contains($fullLog)) {
            Remove-Item -LiteralPath $fullLog -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# STEP 2 - Context checks
# ---------------------------------------------------------------------------
Write-Log 'STEP 2 - Context checks' STEP

if ($Reboot -and -not $Install) {
    Write-Log '-Reboot does nothing without -Install. This audit run will not reboot.' WARN
}
if ($Recover -and ($Install -or $Reboot)) {
    Complete-Run $EXIT.PREFLIGHT 'INVALID_PARAMETERS' '-Recover is a separate operation and cannot be combined with -Install or -Reboot.'
}

# Windows only
if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
    Complete-Run $EXIT.PREFLIGHT 'NOT_WINDOWS' 'This script is Windows-only. Veeam Linux appliances are patched by Veeam Updater.'
}

# Veeam Software Appliance guard (belt and braces)
if (Test-Path 'C:\etc\veeam') {
    Complete-Run $EXIT.UNSUPPORTED 'VEEAM_APPLIANCE' 'Host looks like a Veeam appliance. PostgreSQL there comes from Veeam Updater - do not hand-patch.'
}

# Elevated
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Complete-Run $EXIT.PREFLIGHT 'NOT_ELEVATED' 'Must run elevated. Run it through your RMM agent, or from an elevated PowerShell prompt.'
}
Write-Log "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" OK

# Not over PSRemoting - the EDB installer is documented to fail there.
# $PSSenderInfo does not exist outside a remote session, so it must be probed
# via the Variable: provider or StrictMode makes reading it a terminating error.
if ($Install -and (Test-Path Variable:\PSSenderInfo) -and $PSSenderInfo) {
    Complete-Run $EXIT.PREFLIGHT 'REMOTING' 'Running over WinRM/PSRemoting. The PostgreSQL installer fails in this context. Run it through your RMM agent instead.'
}

# Leftover marker from a previous broken run. This is NOT routine - it means a
# prior run was interrupted mid-change, or finished with something needing a human.
if (Test-Path $script:MarkerFile) {
    if ($Recover) { Invoke-ExplicitRecovery -MarkerPath $script:MarkerFile -Cfg $Cfg }
    $marker = (Get-Content $script:MarkerFile -Raw).Trim()
    $script:Stage = 'INSTALLING'
    $script:Report.IssueCode = 'PRIOR_RUN_INCOMPLETE'
    $script:Report.ActionRequired = "PAGE AN OPERATOR. Run this script with -Recover for a validated pre-installer recovery or post-installer diagnosis."
    Complete-Run $EXIT.ESCALATE 'PRIOR_RUN_INCOMPLETE' "A previous run left a recovery marker, so normal audit/install is blocked: $marker"
}
if ($Recover) {
    Complete-Run $EXIT.OK 'RECOVERY_NOT_NEEDED' 'No recovery marker exists. Nothing was changed.'
}

# ---------------------------------------------------------------------------
# STEP 3 - Detect Veeam products (ADDITIVE - several can share one box)
# ---------------------------------------------------------------------------
Write-Log 'STEP 3 - Detect Veeam products' STEP

$products = @()

# --- VBR ---
$vbrKey = 'HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication'
$vbrCorePath = Get-RegValue $vbrKey 'CorePath'
if ($vbrCorePath -and (Test-Path $vbrCorePath)) {
    $vbrVer = Get-FileVersionSafe (Join-Path $vbrCorePath 'Veeam.Backup.Service.exe')
    if (-not $vbrVer) { $vbrVer = Get-FileVersionSafe (Join-Path $vbrCorePath 'Packages\VeeamDeploymentDll.dll') }
    if (-not $vbrVer) {
        $vbrVer = 'Unknown'
        Write-Log "VBR is installed at $vbrCorePath but its product version could not be read. PostgreSQL targeting uses the running database version, so the run can continue." WARN
    }
    $products += [pscustomobject]@{ Name='VBR'; Version=$vbrVer; CorePath=$vbrCorePath }
    Write-Log "Found Veeam Backup and Replication $vbrVer" OK
}

# --- VB365 / VBM ---
# The service OR the executable must be present. A leftover empty directory from
# an uninstall is not VB365 and must not hard-fail every future run.
$vb365Path = 'C:\Program Files\Veeam\Backup365'
$vb365Svc  = Get-Service -Name 'Veeam.Archiver.Service' -ErrorAction SilentlyContinue
$vb365Exe  = Join-Path $vb365Path 'Veeam.Archiver.Service.exe'
if ($vb365Svc -or (Test-Path $vb365Exe)) {
    $vboVer = Get-FileVersionSafe $vb365Exe
    if (-not $vboVer -and $vb365Svc) {
        try {
            $svcPath = (Get-CimInstance Win32_Service -Filter "Name='Veeam.Archiver.Service'").PathName -replace '^"|"$',''
            $vboVer = Get-FileVersionSafe $svcPath
        } catch {}
    }
    if (-not $vboVer) {
        $vboVer = 'Unknown'
        Write-Log 'VB365 appears to be installed but its product version could not be read. PostgreSQL targeting uses the running database version, so the run can continue.' WARN
    }
    $products += [pscustomobject]@{ Name='VB365'; Version=$vboVer; CorePath=$vb365Path }
    Write-Log "Found Veeam Backup for Microsoft 365 $vboVer" OK
} elseif (Test-Path $vb365Path) {
    Write-Log "$vb365Path exists but there is no VB365 service or executable - treating it as leftover, not an installation." WARN
}

# --- Veeam ONE (co-residence hazard, not a target) ---
if (Test-Path 'HKLM:\SOFTWARE\Veeam\Veeam ONE') {
    $products += [pscustomobject]@{ Name='VeeamONE'; Version=$null; CorePath=$null }
    Write-Log 'Found Veeam ONE on this server' WARN
}

# --- Enterprise Manager (has its own PostgreSQL-capable configuration DB) ---
if (Test-Path 'HKLM:\SOFTWARE\Veeam\Veeam Backup Reporting') {
    $products += [pscustomobject]@{ Name='EnterpriseManager'; Version=$null; CorePath=$null }
    Write-Log 'Found Veeam Backup Enterprise Manager; this topology is excluded until its separate configuration database is supported' WARN
}

$script:Report.VeeamProducts = ($products | ForEach-Object { $_.Name }) -join '+'

if (@($products | Where-Object { $_.Name -eq 'VeeamONE' }).Count -gt 0) {
    Complete-Run $EXIT.UNSUPPORTED 'VEEAM_ONE_PRESENT' 'Veeam ONE co-residence is not yet a certified topology. Handle this server manually.'
}
if (@($products | Where-Object { $_.Name -eq 'EnterpriseManager' }).Count -gt 0) {
    Complete-Run $EXIT.UNSUPPORTED 'ENTERPRISE_MANAGER_PRESENT' 'Enterprise Manager can have a separate PostgreSQL configuration database, which this script does not yet discover or protect. Handle this server manually.'
}

$pgBackedProducts = @($products | Where-Object { $_.Name -eq 'VBR' -or $_.Name -eq 'VB365' })
if ($pgBackedProducts.Count -eq 0) {
    Complete-Run $EXIT.OK 'NOT_APPLICABLE' 'No PostgreSQL-backed Veeam product found on this server.'
}
$hasVbr   = @($pgBackedProducts | Where-Object { $_.Name -eq 'VBR'   }).Count -gt 0
$hasVb365 = @($pgBackedProducts | Where-Object { $_.Name -eq 'VB365' }).Count -gt 0

if ($hasVbr -and $hasVb365) {
    Complete-Run $EXIT.UNSUPPORTED 'STACKED_VBR_VB365' 'Combined VBR+VB365 servers require a separate certified profile, especially for tuning and recovery. This initial production profile supports one of those products at a time.'
}

# ---------------------------------------------------------------------------
# STEP 4 - Confirm the Veeam database engine is LOCAL PostgreSQL
# ---------------------------------------------------------------------------
Write-Log 'STEP 4 - Confirm database engine' STEP

$veeamDatabases = @()
$remoteDatabaseProducts = @()

function Test-LocalDbHost {
    param([string] $DbHost)
    if (-not $DbHost) { return $true }
    $candidate = $DbHost.Trim().Trim('[',']')
    # Preserve the valid local alias "."; only a real DNS name can have a
    # trailing root-label dot to remove.
    if ($candidate.Length -gt 1) { $candidate = $candidate.TrimEnd('.') }
    $localNames = @('localhost','127.0.0.1','::1','.', '(local)', $env:COMPUTERNAME)
    try {
        $entry = [Net.Dns]::GetHostEntry($env:COMPUTERNAME)
        $localNames += $entry.HostName.TrimEnd('.')
        $localNames += @($entry.AddressList | ForEach-Object { $_.IPAddressToString })
        $localNames += @($entry.Aliases | ForEach-Object { $_.TrimEnd('.') })
    } catch {}
    return (@($localNames | Where-Object { $_ }) -contains $candidate)
}

function Get-VeeamControlSurfaceValidation {
    param([bool] $Vbr, [bool] $Vb365, [switch] $Reconnect)

    $result = [ordered]@{
        Kind      = 'OK'
        IssueCode = ''
        Detail    = ''
        Inventory = @()
    }

    $moduleErrors = @(Connect-VeeamModules -Vbr:$Vbr -Vb365:$Vb365 -Quiet -Reconnect:$Reconnect)
    if ($moduleErrors.Count -gt 0) {
        $result.Kind = 'PREFLIGHT'
        $result.IssueCode = 'VEEAM_MODULE_FAILED'
        $result.Detail = "Could not load/connect the Veeam PowerShell module(s): $($moduleErrors -join ' | ')"
        return [pscustomobject]$result
    }

    if ($Vb365) {
        $missingMaintenanceCommands = @('Get-VBORepository','Start-VBORepositoryMaintenanceSession',
            'Get-VBORepositoryMaintenanceSession','Stop-VBORepositoryMaintenanceSession') |
            Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) }
        if (@($missingMaintenanceCommands).Count -gt 0) {
            $result.Kind = 'UNSUPPORTED'
            $result.IssueCode = 'VB365_MAINTENANCE_API_UNAVAILABLE'
            $result.Detail = "Safe VB365 maintenance requires the repository-maintenance API. Missing: $($missingMaintenanceCommands -join ', ')."
            return [pscustomobject]$result
        }
    }

    try {
        $result.Inventory = @(Get-VeeamManagedJobInventory -Vbr $Vbr -Vb365 $Vb365)
    } catch {
        $result.Kind = if ($_.Exception -is [System.NotSupportedException]) { 'UNSUPPORTED' } else { 'PREFLIGHT' }
        $result.IssueCode = if ($result.Kind -eq 'UNSUPPORTED') { 'UNSUPPORTED_SCHEDULER_FAMILY' } else { 'JOB_INVENTORY_FAILED' }
        $result.Detail = "Could not inventory and round-trip every Veeam schedule/policy family safely: $($_.Exception.Message)"
        return [pscustomobject]$result
    }

    if ($Vb365) {
        if (-not (Get-Command Get-VBOProxy -ErrorAction SilentlyContinue)) {
            $result.Kind = 'UNSUPPORTED'
            $result.IssueCode = 'VB365_PROXY_API_UNAVAILABLE'
            $result.Detail = 'Get-VBOProxy is unavailable, so local standalone VB365 topology cannot be certified.'
            return [pscustomobject]$result
        }
        try {
            $allProxies = @(Get-VBOProxy -ErrorAction Stop)
        } catch {
            $result.Kind = 'PREFLIGHT'
            $result.IssueCode = 'PROXY_INVENTORY_FAILED'
            $result.Detail = "Could not inventory VB365 backup proxies: $($_.Exception.Message)"
            return [pscustomobject]$result
        }
        $unknownProxies = @($allProxies | Where-Object { -not $_.Hostname })
        if ($unknownProxies.Count -gt 0) {
            $result.Kind = 'UNSUPPORTED'
            $result.IssueCode = 'UNVERIFIABLE_PROXIES'
            $result.Detail = "$($unknownProxies.Count) VB365 proxy/proxies expose no readable Hostname, so local standalone topology cannot be certified."
            return [pscustomobject]$result
        }
        $remoteProxies = @($allProxies | Where-Object { -not (Test-LocalDbHost "$($_.Hostname)") })
        if ($remoteProxies.Count -gt 0) {
            $result.Kind = 'UNSUPPORTED'
            $result.IssueCode = 'REMOTE_PROXIES'
            $result.Detail = "VB365 has remote backup proxies ($((@($remoteProxies) | ForEach-Object { $_.Hostname }) -join ', ')). This profile supports local standalone topology only."
            return [pscustomobject]$result
        }
    }

    return [pscustomobject]$result
}

function ConvertFrom-PgConnectionString {
    param([Parameter(Mandatory)][string] $ConnectionString)

    $builder = New-Object System.Data.Common.DbConnectionStringBuilder
    # PowerShell's dictionary adapter treats direct property assignment here as
    # an entry named "ConnectionString" on some editions. Call the CLR setter so
    # Host/Port/Database are actually parsed into individual keys.
    $builder.set_ConnectionString($ConnectionString)
    $hostName = if ($builder.ContainsKey('host')) { "$($builder['host'])" } else { '' }
    $port = if ($builder.ContainsKey('port')) { "$($builder['port'])" } else { '5432' }
    $database = if ($builder.ContainsKey('database')) { "$($builder['database'])" } else { '' }
    if (-not $hostName) { throw 'connection string has no host value' }
    $portNumber = 0
    if (-not [int]::TryParse($port, [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) { throw "connection string has invalid port '$port'" }
    if (-not $database) { throw 'connection string has no database value' }
    return [pscustomobject]@{ Host=$hostName; Port=$portNumber; Database=$database }
}

function Test-Vb365CacheDatabaseName {
    param([string] $Database)
    if (-not $Database -or -not $Database.StartsWith('cache_', [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $cacheId = [guid]::Empty
    return [guid]::TryParse($Database.Substring(6), [ref]$cacheId)
}

if ($hasVbr) {
    $active = Get-RegValue "$vbrKey\DatabaseConfigurations" 'SqlActiveConfiguration'
    Write-Log "VBR SqlActiveConfiguration = $active"
    if (-not $active) {
        Complete-Run $EXIT.PREFLIGHT 'VBR_DB_ENGINE_UNKNOWN' 'VBR SqlActiveConfiguration is missing. Refusing to guess which database engine/registry branch is active.'
    }
    if ("$active" -ieq 'MsSql') {
        Write-Log "VBR is using $active, not PostgreSQL; it is not a database target for this run." WARN
    } elseif ("$active" -ieq 'PostgreSql') {
        $pgCfgKey = "$vbrKey\DatabaseConfigurations\PostgreSql"
        $vbrHost  = Get-RegValue $pgCfgKey 'SqlHostName'
        $vbrPort  = Get-RegValue $pgCfgKey 'SqlHostPort'
        $vbrDb    = Get-RegValue $pgCfgKey 'SqlDatabaseName'
        $missingVbrDbFields = @()
        if (-not $vbrHost) { $missingVbrDbFields += 'SqlHostName' }
        if (-not $vbrPort) { $missingVbrDbFields += 'SqlHostPort' }
        if (-not $vbrDb)   { $missingVbrDbFields += 'SqlDatabaseName' }
        if ($missingVbrDbFields.Count -gt 0) {
            Complete-Run $EXIT.PREFLIGHT 'VBR_DB_CONFIG_INCOMPLETE' "VBR's active PostgreSql configuration is missing: $($missingVbrDbFields -join ', '). Refusing to guess local defaults."
        }
        $vbrPortNumber = 0
        if (-not [int]::TryParse("$vbrPort", [ref]$vbrPortNumber) -or $vbrPortNumber -lt 1 -or $vbrPortNumber -gt 65535) {
            Complete-Run $EXIT.PREFLIGHT 'BAD_VBR_DB_PORT' "VBR reports invalid PostgreSQL port '$vbrPort'."
        }
        $vbrPort = $vbrPortNumber
        Write-Log ("VBR database: {0} on {1}:{2}" -f $vbrDb, $vbrHost, $vbrPort)
        if (-not (Test-LocalDbHost $vbrHost)) {
            $remoteDatabaseProducts += "VBR ($vbrHost)"
            Write-Log "VBR uses remote PostgreSQL at $vbrHost; it is not a database target for this local update." WARN
        } else {
            $veeamDatabases += [pscustomobject]@{ Product='VBR'; Database=$vbrDb; Port=$vbrPort }
        }
    } else {
        Complete-Run $EXIT.PREFLIGHT 'VBR_DB_ENGINE_UNKNOWN' "VBR SqlActiveConfiguration is '$active', not the exact supported values MsSql or PostgreSql. Refusing to guess."
    }
}

if ($hasVb365) {
    $vboCfgXml = 'C:\ProgramData\Veeam\Backup365\Config.xml'
    if (-not (Test-Path $vboCfgXml)) {
        Complete-Run $EXIT.PREFLIGHT 'NO_VB365_CONFIG' "VB365 detected but $vboCfgXml is missing."
    }
    try {
        [xml] $vboXml = Get-Content $vboCfgXml -Raw
        $controllerNodes = @($vboXml.SelectNodes('//ControllerPostgres'))
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'BAD_VB365_CONFIG' "Could not read $vboCfgXml : $($_.Exception.Message)"
    }
    if ($controllerNodes.Count -ne 1) {
        Complete-Run $EXIT.PREFLIGHT 'BAD_VB365_CONFIG' "Expected exactly one ControllerPostgres node in $vboCfgXml; found $($controllerNodes.Count)."
    }
    try {
        $vboConnectionString = $controllerNodes[0].GetAttribute('ControllerConnectionString')
        if (-not $vboConnectionString) { throw 'ControllerConnectionString is empty' }
        $vboControllerConnection = ConvertFrom-PgConnectionString $vboConnectionString
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'BAD_VB365_CONNECTION' "Could not parse ControllerPostgres in $vboCfgXml : $($_.Exception.Message)"
    }

    $vboProxyXml = 'C:\ProgramData\Veeam\Backup365\Proxy.xml'
    if (-not (Test-Path -LiteralPath $vboProxyXml)) {
        Complete-Run $EXIT.PREFLIGHT 'NO_VB365_PROXY_CONFIG' "VB365 detected but $vboProxyXml is missing, so cache database topology cannot be certified."
    }
    try {
        [xml] $proxyXml = Get-Content -LiteralPath $vboProxyXml -Raw -ErrorAction Stop
        $proxyControllerNodes = @($proxyXml.SelectNodes('//ProxyPostgres'))
        $cacheNodes = @($proxyXml.SelectNodes('//PersistentCachePostgres'))
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'BAD_VB365_PROXY_CONFIG' "Could not read $vboProxyXml : $($_.Exception.Message)"
    }
    if ($proxyControllerNodes.Count -ne 1) {
        Complete-Run $EXIT.PREFLIGHT 'BAD_VB365_PROXY_CONFIG' "Expected exactly one ProxyPostgres node in $vboProxyXml; found $($proxyControllerNodes.Count)."
    }

    $vboConnections = @([pscustomobject]@{ Product='VB365'; Source='Config.xml ControllerPostgres'; Connection=$vboControllerConnection })
    try {
        $proxyControllerString = $proxyControllerNodes[0].GetAttribute('ControllerConnectionString')
        if (-not $proxyControllerString) { throw 'ProxyPostgres ControllerConnectionString is empty' }
        $vboConnections += [pscustomobject]@{
            Product='VB365'; Source='Proxy.xml ProxyPostgres';
            Connection=(ConvertFrom-PgConnectionString $proxyControllerString)
        }
        foreach ($cacheNode in $cacheNodes) {
            $cacheConnectionString = $cacheNode.GetAttribute('PersistentCacheConnectionString')
            if (-not $cacheConnectionString) { throw 'PersistentCachePostgres PersistentCacheConnectionString is empty' }
            $cacheConnection = ConvertFrom-PgConnectionString $cacheConnectionString
            if (-not (Test-Vb365CacheDatabaseName $cacheConnection.Database)) {
                throw "Persistent cache database '$($cacheConnection.Database)' is not named cache_<guid>"
            }
            $vboConnections += [pscustomobject]@{
                Product='VB365Cache'; Source='Proxy.xml PersistentCachePostgres'; Connection=$cacheConnection
            }
        }
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'BAD_VB365_PROXY_CONNECTION' "Could not parse PostgreSQL connections in $vboProxyXml : $($_.Exception.Message)"
    }

    foreach ($configuredConnection in $vboConnections) {
        $conn = $configuredConnection.Connection
        Write-Log ("{0}: {1} on {2}:{3}" -f $configuredConnection.Source, $conn.Database, $conn.Host, $conn.Port)
        if (-not (Test-LocalDbHost $conn.Host)) {
            $remoteDatabaseProducts += "$($configuredConnection.Product) $($conn.Database) ($($conn.Host))"
        } else {
            $veeamDatabases += [pscustomobject]@{
                Product=$configuredConnection.Product; Database=$conn.Database; Port=[int]$conn.Port
            }
        }
    }
    if ($vboConnections[1].Connection.Database -cne $vboControllerConnection.Database) {
        Complete-Run $EXIT.PREFLIGHT 'VB365_CONTROLLER_DB_MISMATCH' "Config.xml names controller database '$($vboControllerConnection.Database)', but Proxy.xml names '$($vboConnections[1].Connection.Database)'."
    }
}

if ($remoteDatabaseProducts.Count -gt 0) {
    Complete-Run $EXIT.UNSUPPORTED 'REMOTE_DB' "Veeam PostgreSQL connection(s) are remote: $($remoteDatabaseProducts -join ', '). This production profile supports one local standalone PostgreSQL instance only."
}
if ($veeamDatabases.Count -eq 0) {
    Complete-Run $EXIT.OK 'NOT_APPLICABLE' 'No detected Veeam product uses a local PostgreSQL database.'
}

$localPgPorts = @($veeamDatabases | ForEach-Object { [int]$_.Port } | Sort-Object -Unique)
if ($localPgPorts.Count -ne 1) {
    Complete-Run $EXIT.UNSUPPORTED 'MULTIPLE_PG_PORTS' "Local Veeam products report different PostgreSQL ports ($($localPgPorts -join ', ')). Mapping them to one installation is ambiguous; handle manually."
}

# ---------------------------------------------------------------------------
# STEP 5 - Detect the PostgreSQL installation (never hard-code names)
# ---------------------------------------------------------------------------
Write-Log 'STEP 5 - Detect PostgreSQL installation' STEP

$installs = @()
if (Test-Path 'HKLM:\SOFTWARE\PostgreSQL\Installations') {
    foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\PostgreSQL\Installations') {
        $installs += [pscustomobject]@{
            Key       = $k.PSChildName
            Version   = Get-RegValue $k.PSPath 'Version'
            BaseDir   = Get-RegValue $k.PSPath 'Base Directory'
            DataDir   = Get-RegValue $k.PSPath 'Data Directory'
            ServiceID = Get-RegValue $k.PSPath 'Service ID'
        }
    }
}

if ($installs.Count -eq 0) {
    Complete-Run $EXIT.PREFLIGHT 'NO_PG_FOUND' 'No PostgreSQL installation found under HKLM:\SOFTWARE\PostgreSQL\Installations.'
}
if ($installs.Count -gt 1) {
    $list = ($installs | ForEach-Object { "$($_.Version) at $($_.BaseDir)" }) -join ' | '
    Complete-Run $EXIT.UNSUPPORTED 'MULTIPLE_PG' "More than one PostgreSQL instance found ($list). Mapping to Veeam is ambiguous - handle manually."
}

$pg = $installs[0]
foreach ($req in @('Version','BaseDir','DataDir')) {
    if (-not $pg.$req) {
        Complete-Run $EXIT.PREFLIGHT 'PG_REGISTRY_INCOMPLETE' "The PostgreSQL registry entry is missing '$req'. Cannot proceed safely."
    }
}

$pgServiceRows = @()
try {
    $pgServiceRows = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object {
        "$($_.Name)" -like 'postgresql*' -or
        "$($_.PathName)" -match '(?i)(?:^|[\\/"])(?:pg_ctl|postgres)\.exe(?:["\s]|$)'
    } | Sort-Object Name -Unique)
} catch {
    Complete-Run $EXIT.PREFLIGHT 'PG_SERVICE_INVENTORY_FAILED' "Could not enumerate Windows services to prove there is only one PostgreSQL cluster: $($_.Exception.Message)"
}

# Some vendor wrappers hide pg_ctl.exe from PathName. Always include the exact
# registry Service ID when it resolves, then still reject every multi-service case.
if ($pg.ServiceID) {
    $registeredService = Get-Service -Name $pg.ServiceID -ErrorAction SilentlyContinue
    if ($registeredService -and @($pgServiceRows | Where-Object { $_.Name -ieq $registeredService.Name }).Count -eq 0) {
        $pgServiceRows += [pscustomobject]@{ Name=$registeredService.Name; PathName='<registry Service ID>' }
    }
}
if ($pgServiceRows.Count -gt 1) {
    $serviceList = @($pgServiceRows | ForEach-Object { "$($_.Name) [$($_.PathName)]" }) -join ' | '
    Complete-Run $EXIT.UNSUPPORTED 'MULTIPLE_PG_CLUSTERS' "More than one PostgreSQL Windows service/cluster exists ($serviceList). This production profile supports one local standalone cluster only."
}

$pgSvc = $null
if ($pgServiceRows.Count -eq 1) { $pgSvc = Get-Service -Name $pgServiceRows[0].Name -ErrorAction SilentlyContinue }
if (-not $pgSvc) {
    Complete-Run $EXIT.PREFLIGHT 'NO_PG_SERVICE' "PostgreSQL registry entry found but no matching Windows service (Service ID '$($pg.ServiceID)')."
}
if ($pg.ServiceID -and $pgSvc.Name -ine "$($pg.ServiceID)") {
    Complete-Run $EXIT.PREFLIGHT 'PG_SERVICE_MISMATCH' "The only PostgreSQL service is '$($pgSvc.Name)', but the selected registry installation names '$($pg.ServiceID)'. Refusing an ambiguous installer target."
}
$pgServicePathName = "$($pgServiceRows[0].PathName)"
if (-not (Test-PgServiceExecutableMatchesBaseDir -PathName $pgServicePathName -BaseDir "$($pg.BaseDir)")) {
    Complete-Run $EXIT.PREFLIGHT 'PG_SERVICE_BINARY_MISMATCH' "PostgreSQL service '$($pgSvc.Name)' does not run pg_ctl.exe/postgres.exe from registry Base Directory '$($pg.BaseDir)'. Service command: $pgServicePathName. Refusing to patch an ambiguous installation."
}
$script:PgServiceName = $pgSvc.Name

$psql      = Join-Path $pg.BaseDir 'bin\psql.exe'
$pgDump    = Join-Path $pg.BaseDir 'bin\pg_dump.exe'
$pgDumpAll = Join-Path $pg.BaseDir 'bin\pg_dumpall.exe'
$pgRestore = Join-Path $pg.BaseDir 'bin\pg_restore.exe'
foreach ($tool in @($psql, $pgDump, $pgDumpAll, $pgRestore)) {
    if (-not (Test-Path $tool)) {
        Complete-Run $EXIT.PREFLIGHT 'MISSING_PG_TOOL' "Expected PostgreSQL tool not found: $tool"
    }
}

$pgPort = 5432
if ($veeamDatabases.Count -gt 0 -and $veeamDatabases[0].Port) { $pgPort = [int]$veeamDatabases[0].Port }

Write-Log "PostgreSQL $($pg.Version) (from registry)" OK
Write-Log "  Base directory: $($pg.BaseDir)"
Write-Log "  Data directory: $($pg.DataDir)"
Write-Log "  Service       : $($pgSvc.Name) [$($pgSvc.Status)]"
Write-Log "  Port          : $pgPort"

# ---------------------------------------------------------------------------
# STEP 6 - Read the RUNNING version, and prove we can talk to the database
# ---------------------------------------------------------------------------
Write-Log 'STEP 6 - Read running server version (also the SSPI pre-flight)' STEP

if ($pgSvc.Status -ne 'Running') {
    Complete-Run $EXIT.PREFLIGHT 'PG_NOT_RUNNING' "PostgreSQL service $($pgSvc.Name) is $($pgSvc.Status). Start it and investigate before patching."
}

function Invoke-Psql {
    param([string] $Sql, [string] $Database = 'postgres')
    # -w = never prompt for a password. Veeam-deployed PostgreSQL uses SSPI.
    return Invoke-Native $psql @('-U','postgres','-h','127.0.0.1','-p',"$pgPort",'-d',$Database,'-t','-A','-w','-c',$Sql)
}

$verRes = Invoke-Psql 'SHOW server_version_num;'
if ($verRes.ExitCode -ne 0 -or $verRes.StdOut -notmatch '^\d+$') {
    Complete-Run $EXIT.PREFLIGHT 'PG_UNREACHABLE' "Could not query PostgreSQL as user 'postgres'. This usually means the running identity is not mapped in pg_ident.conf (Veeam KB4542). stderr: $($verRes.StdErr) stdout: $($verRes.StdOut)"
}

$runningNum     = [int] $verRes.StdOut
$decoded        = ConvertFrom-ServerVersionNum $runningNum
$runningVersion = $decoded.Version
$pgBranch       = $decoded.Branch
$script:Report.PgInstalled = $runningVersion
$script:Report.PgMajor     = $pgBranch
Write-Log "Running server version: $runningVersion (server_version_num = $runningNum)" OK

# Prove the server reached on the Veeam port is the registry-selected instance
# that the installer will patch, not another cluster listening on that port.
$dataDirRes = Invoke-Psql 'SHOW data_directory;'
if ($dataDirRes.ExitCode -ne 0 -or -not $dataDirRes.StdOut) {
    Complete-Run $EXIT.PREFLIGHT 'PG_INSTANCE_UNVERIFIED' "Could not read data_directory from the running PostgreSQL server. stderr: $($dataDirRes.StdErr)"
}
try {
    $registryDataDir = [IO.Path]::GetFullPath("$($pg.DataDir)").TrimEnd('\')
    $runningDataDir  = [IO.Path]::GetFullPath("$($dataDirRes.StdOut)").TrimEnd('\')
} catch {
    Complete-Run $EXIT.PREFLIGHT 'PG_INSTANCE_UNVERIFIED' "Could not normalize the PostgreSQL data paths: $($_.Exception.Message)"
}
if ($runningDataDir -ine $registryDataDir) {
    Complete-Run $EXIT.PREFLIGHT 'PG_INSTANCE_MISMATCH' "Veeam's port $pgPort reaches data directory '$runningDataDir', but the registry-selected installer target uses '$registryDataDir'. Refusing to patch an ambiguous instance."
}
if (Test-PathTreeOverlap -Left $WorkRoot -Right $registryDataDir) {
    Complete-Run $EXIT.PREFLIGHT 'WORKROOT_DATA_OVERLAP' "WorkRoot '$WorkRoot' and PostgreSQL data directory '$registryDataDir' overlap. Recovery cleanup or the cold copy would be unsafe; choose a separate WorkRoot."
}
Write-Log "Running server data directory matches the installer target: $runningDataDir" OK

# The supported local profile connects directly to the PostgreSQL service. A
# pooler can report this data directory while listening on a different port and
# would require its own coordinated service/outage handling.
$serverPortRes = Invoke-Psql 'SHOW port;'
$serverPortNumber = 0
if ($serverPortRes.ExitCode -ne 0 -or -not [int]::TryParse("$($serverPortRes.StdOut)", [ref]$serverPortNumber)) {
    Complete-Run $EXIT.PREFLIGHT 'PG_PORT_UNVERIFIED' "Could not read the PostgreSQL server port. stderr: $($serverPortRes.StdErr) stdout: $($serverPortRes.StdOut)"
}
if ($serverPortNumber -ne $pgPort) {
    Complete-Run $EXIT.UNSUPPORTED 'PG_POOLER_OR_PORT_MISMATCH' "Veeam connects on port $pgPort, but PostgreSQL reports port $serverPortNumber. A pooler/proxy or ambiguous instance is in the path; coordinate it manually."
}

# Prove this PostgreSQL cluster is dedicated to the in-scope Veeam databases.
# VB365 keeps its configuration DB plus cache_<guid> databases; all of those are
# added to the dump set. Any other user database means stopping PostgreSQL would
# interrupt an untracked workload, so the topology is excluded.
$databaseListRes = Invoke-Psql "SELECT COALESCE(json_agg(datname ORDER BY datname)::text, '[]') FROM pg_database WHERE NOT datistemplate;"
if ($databaseListRes.ExitCode -ne 0 -or -not $databaseListRes.StdOut) {
    Complete-Run $EXIT.PREFLIGHT 'PG_DATABASE_INVENTORY_FAILED' "Could not inventory PostgreSQL databases. stderr: $($databaseListRes.StdErr)"
}
try { $actualDatabases = @($databaseListRes.StdOut | ConvertFrom-Json -ErrorAction Stop) }
catch { Complete-Run $EXIT.PREFLIGHT 'PG_DATABASE_INVENTORY_FAILED' "PostgreSQL database inventory was not valid JSON: $($_.Exception.Message)" }

$configuredDatabaseNames = @($veeamDatabases | ForEach-Object { "$($_.Database)" } | Select-Object -Unique)
$missingConfiguredDatabases = @($configuredDatabaseNames | Where-Object { $actualDatabases -cnotcontains $_ })
if ($missingConfiguredDatabases.Count -gt 0) {
    Complete-Run $EXIT.PREFLIGHT 'VEEAM_DATABASE_MISSING' "Configured Veeam database(s) are absent from this cluster: $($missingConfiguredDatabases -join ', ')."
}
$unexpectedDatabases = @()
foreach ($databaseName in $actualDatabases) {
    if ($databaseName -ceq 'postgres' -or $configuredDatabaseNames -ccontains $databaseName) { continue }
    if ($hasVb365 -and (Test-Vb365CacheDatabaseName "$databaseName")) {
        $veeamDatabases += [pscustomobject]@{ Product='VB365Cache'; Database="$databaseName"; Port=$pgPort }
        continue
    }
    $unexpectedDatabases += "$databaseName"
}
if ($unexpectedDatabases.Count -gt 0) {
    Complete-Run $EXIT.UNSUPPORTED 'UNTRACKED_POSTGRES_DATABASES' "The PostgreSQL cluster contains non-Veeam/untracked database(s): $($unexpectedDatabases -join ', '). Stopping this shared cluster could interrupt another workload."
}
$deduplicatedVeeamDatabases = @()
foreach ($databaseRecord in $veeamDatabases) {
    if (@($deduplicatedVeeamDatabases | Where-Object { $_.Database -ceq $databaseRecord.Database }).Count -eq 0) {
        $deduplicatedVeeamDatabases += $databaseRecord
    }
}
$veeamDatabases = @($deduplicatedVeeamDatabases)
Write-Log "Tracked Veeam database dump set: $($veeamDatabases.Database -join ', ')" OK

# Reject standby/replicated PostgreSQL before touching Veeam. A same-major binary
# update must be coordinated across an HA topology, which this single-host profile
# deliberately does not attempt.
$haSql = @"
SELECT CASE WHEN pg_is_in_recovery() THEN '1' ELSE '0' END || '|' ||
       CASE WHEN EXISTS (SELECT 1 FROM pg_stat_replication) THEN '1' ELSE '0' END || '|' ||
       CASE WHEN EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_type = 'physical') THEN '1' ELSE '0' END || '|' ||
       COALESCE(current_setting('synchronous_standby_names', true), '');
"@
$haRes = Invoke-Psql $haSql
if ($haRes.ExitCode -ne 0 -or $haRes.StdOut -notmatch '^(0|1)\|(0|1)\|(0|1)\|(.*)$') {
    Complete-Run $EXIT.PREFLIGHT 'PG_TOPOLOGY_UNVERIFIED' "Could not prove PostgreSQL is a standalone primary. stderr: $($haRes.StdErr) stdout: $($haRes.StdOut)"
}
$isStandby = ($Matches[1] -eq '1')
$hasStreamingReplica = ($Matches[2] -eq '1')
$hasPhysicalSlot = ($Matches[3] -eq '1')
$syncStandbys = "$($Matches[4])".Trim()
if ($isStandby -or $hasStreamingReplica -or $hasPhysicalSlot -or $syncStandbys) {
    Complete-Run $EXIT.UNSUPPORTED 'PG_HA_TOPOLOGY' "PostgreSQL is not a certified standalone cluster (standby=$isStandby, connectedReplica=$hasStreamingReplica, physicalReplicationSlot=$hasPhysicalSlot, synchronousStandbyNames='$syncStandbys'). Coordinate this update manually across the HA/replication topology."
}

# Also catch PostgreSQL registered as a Windows Failover Cluster generic service.
$clusterSvc = Get-Service -Name 'ClusSvc' -ErrorAction SilentlyContinue
if ($clusterSvc -and (Test-Path -LiteralPath 'HKLM:\Cluster\Resources')) {
    try {
        foreach ($resourceKey in @(Get-ChildItem -LiteralPath 'HKLM:\Cluster\Resources' -ErrorAction Stop)) {
            $clusterManagedService = $null
            $resourceParametersPath = Join-Path $resourceKey.PSPath 'Parameters'
            if (Test-Path -LiteralPath $resourceParametersPath) {
                $resourceParameters = Get-ItemProperty -LiteralPath $resourceParametersPath -ErrorAction Stop
                if ($resourceParameters.PSObject.Properties.Name -contains 'ServiceName') {
                    $clusterManagedService = $resourceParameters.ServiceName
                }
            }
            if ($clusterManagedService -and "$clusterManagedService" -ieq $pgSvc.Name) {
                Complete-Run $EXIT.UNSUPPORTED 'PG_FAILOVER_CLUSTER' "PostgreSQL service $($pgSvc.Name) is managed by Windows Failover Clustering. This production profile supports a standalone service only."
            }
        }
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'PG_CLUSTER_TOPOLOGY_UNVERIFIED' "Failover Clustering is installed, but its resources could not be inspected safely: $($_.Exception.Message)"
    }
}
Write-Log 'PostgreSQL topology verified as one local standalone primary' OK

# A read-only audit must certify the same Veeam control surface as an install.
# Otherwise an unsupported scheduler family or distributed VB365 proxy could be
# reported as "current" and never reach the install-only safety checks.
Write-Log 'STEP 6B - Validate Veeam scheduling, activity and topology APIs' STEP
$controlValidation = Get-VeeamControlSurfaceValidation -Vbr $hasVbr -Vb365 $hasVb365
if ($controlValidation.Kind -ne 'OK') {
    $validationCode = if ($controlValidation.Kind -eq 'UNSUPPORTED') { $EXIT.UNSUPPORTED } else { $EXIT.PREFLIGHT }
    Complete-Run $validationCode $controlValidation.IssueCode $controlValidation.Detail
}
$script:ManagedJobInventory = @($controlValidation.Inventory)
try {
    $auditActivity = @(Get-ActiveVeeamWork -Vbr $hasVbr -Vb365 $hasVb365)
} catch {
    $activityCode = if ($_.Exception -is [System.NotSupportedException]) { $EXIT.UNSUPPORTED } else { $EXIT.PREFLIGHT }
    $activityIssue = if ($activityCode -eq $EXIT.UNSUPPORTED) { 'UNSUPPORTED_ACTIVITY_API' } else { 'SESSION_CHECK_FAILED' }
    Complete-Run $activityCode $activityIssue "Could not query every applicable Veeam activity family safely: $($_.Exception.Message)"
}
if ($auditActivity.Count -gt 0) {
    Write-Log "Veeam work is currently active ($($auditActivity -join ', ')). Audit can continue; install mode will wait for it to finish naturally before disabling schedules." WARN
} else {
    Write-Log "Validated $($script:ManagedJobInventory.Count) schedule/policy object(s); all observed Veeam activity is currently quiescent" OK
}

$regBranch = Get-BranchKey $pg.Version
if ("$pgBranch" -ne "$regBranch") {
    Complete-Run $EXIT.PREFLIGHT 'PG_REGISTRY_VERSION_MISMATCH' "Registry installation version '$($pg.Version)' is branch $regBranch, but the running server is branch $pgBranch. Refusing to select an installer while registry and runtime targets disagree."
}

# ---------------------------------------------------------------------------
# STEP 7 - Resolve the target version
# ---------------------------------------------------------------------------
Write-Log 'STEP 7 - Resolve target version' STEP

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

try {
    $versions = Invoke-RestMethod -Uri 'https://www.postgresql.org/versions.json' -UseBasicParsing -TimeoutSec 60
} catch {
    # Fail CLOSED. Never fall back to a hard-coded or operator-selected version.
    Complete-Run $EXIT.PREFLIGHT 'VERSIONS_FETCH_FAILED' "Could not fetch https://www.postgresql.org/versions.json : $($_.Exception.Message)"
}
# 'major' and 'latestMinor' are STRINGS. Legacy rows carry dotted majors like
# '9.6', so compare branch keys as strings - never integer-cast.
try { $resolvedTarget = Resolve-LatestPgTarget -Versions $versions -InstalledBranch $pgBranch }
catch { Complete-Run $EXIT.PREFLIGHT 'BRANCH_NOT_LISTED' $_.Exception.Message }
$target = $resolvedTarget.Version
$script:EolBranch = -not [bool]$resolvedTarget.Supported
$script:Report.PgEol = $script:EolBranch

if ($script:EolBranch) {
    Write-Log "PostgreSQL $pgBranch is end-of-life (EOL $($resolvedTarget.EolDate)). Updating to its final published minor $target, but a major-version migration remains required." WARN
}

$eol = $resolvedTarget.EolDate
if ($eol) {
    try {
        $daysToEol = ([datetime]$eol - (Get-Date)).Days
        if ($daysToEol -ge 0 -and $daysToEol -lt 90) {
            Write-Log "PostgreSQL $pgBranch goes EOL in $daysToEol days ($eol). Plan a major-version migration." WARN
        }
    } catch {}
}
$script:Report.PgTarget = $target
Write-Log "Latest published minor for branch $pgBranch is $target"

# --- Guardrail: major version is immutable ---
try {
    $targetPattern = if ($pgBranch -match '\.') { '^\d+\.\d+\.\d+$' } else { '^\d+\.\d+$' }
    if ($target -notmatch $targetPattern) {
        throw "expected canonical version syntax for branch $pgBranch"
    }
    $targetBranch = Get-BranchKey $target
    [void](ConvertTo-ServerVersionNum $target)
} catch {
    Complete-Run $EXIT.PREFLIGHT 'INVALID_TARGET' "Target version '$target' is invalid: $($_.Exception.Message)"
}
if ("$targetBranch" -ne "$pgBranch") {
    Complete-Run $EXIT.UNSUPPORTED 'MAJOR_CHANGE_BLOCKED' "Target $target is on branch $targetBranch but the server is on $pgBranch. Major upgrades need pg_upgrade or a Veeam config restore and are out of scope for this script."
}

Write-Log "Target $target stays on installed PostgreSQL branch $pgBranch" OK

# ---------------------------------------------------------------------------
# STEP 8 - Idempotency gate
# ---------------------------------------------------------------------------
Write-Log 'STEP 8 - Idempotency gate' STEP

$versionComparison = Compare-PgVersion $runningVersion $target
if ($versionComparison -gt 0) {
    $code = Get-PolicyExitCode -Eol $script:EolBranch -UpdateAvailable $false -RebootRequired $false
    Complete-Run $code 'LOCAL_VERSION_AHEAD' "Running $runningVersion is newer than published target $target. Refusing to downgrade; no service was touched."
}
if ($versionComparison -eq 0) {
    $code = Get-PolicyExitCode -Eol $script:EolBranch -UpdateAvailable $false -RebootRequired $false
    Complete-Run $code 'ALREADY_CURRENT' "Running $runningVersion, target $target. Nothing to do. No service was touched."
}
Write-Log "Update available: $runningVersion -> $target" WARN

# ---------------------------------------------------------------------------
# STEP 9 - Environment pre-flight (things known to break unattended installs)
# ---------------------------------------------------------------------------
Write-Log 'STEP 9 - Environment pre-flight' STEP

# Windows Script Host must not be disabled (Veeam KB4698)
foreach ($wshKey in @('HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings',
                      'HKCU:\Software\Microsoft\Windows Script Host\Settings')) {
    $wshEnabled = Get-RegValue $wshKey 'Enabled'
    if ($null -ne $wshEnabled -and [int]$wshEnabled -eq 0) {
        Complete-Run $EXIT.PREFLIGHT 'WSH_DISABLED' "Windows Script Host is disabled at $wshKey. The PostgreSQL installer will fail part-way through (Veeam KB4698). Re-enable it first."
    }
}
Write-Log 'Windows Script Host is enabled' OK

# Visual C++ 2015-2022 redistributable (the installer helper needs it)
$vcOk = $false
foreach ($vcKey in @('HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64')) {
    if ((Get-RegValue $vcKey 'Installed') -eq 1) { $vcOk = $true }
}
if ($vcOk) { Write-Log 'Visual C++ 2015-2022 x64 runtime present' OK }
else       { Write-Log 'Visual C++ 2015-2022 x64 runtime not detected. The installer will try to install it (--install_runtimes stays at its default).' WARN }

# pgAdmin must not be running (modal prompt would hang an unattended run)
if (@(Get-Process -Name 'pgAdmin*' -ErrorAction SilentlyContinue).Count -gt 0) {
    Complete-Run $EXIT.PREFLIGHT 'PGADMIN_RUNNING' 'pgAdmin is running. Close it - it can block the installer with a modal prompt.'
}

# Disk space: installer (~400 MB) + cold copy of the data directory + dumps
$dataSize = 0
try {
    $measured = Get-ChildItem $pg.DataDir -Recurse -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum
    if ($measured -and $measured.Sum) { $dataSize = [int64]$measured.Sum }
} catch {}
$needBytes = 400MB + ($dataSize * 2) + 1GB
$sysDrive  = (Get-Item $WorkRoot).PSDrive.Name
$freeBytes = (Get-PSDrive $sysDrive).Free
Write-Log ("Data directory {0:N1} GB; need {1:N1} GB free on {2}: ; have {3:N1} GB" -f ($dataSize/1GB), ($needBytes/1GB), $sysDrive, ($freeBytes/1GB))
if ($freeBytes -lt $needBytes) {
    Complete-Run $EXIT.PREFLIGHT 'LOW_DISK' ("Not enough free space on {0}: - need {1:N1} GB, have {2:N1} GB." -f $sysDrive, ($needBytes/1GB), ($freeBytes/1GB))
}

Write-Log "OS locale: $((Get-Culture).Name) / system: $((Get-WinSystemLocale).Name)"

# ---------------------------------------------------------------------------
# STEP 10 - Resolve the exact Windows x64 link published by EnterpriseDB
# ---------------------------------------------------------------------------
Write-Log 'STEP 10 - Resolve installer URL' STEP

function Resolve-PgInstallerLinkFromHtml {
    param([Parameter(Mandatory)][string] $Html, [Parameter(Mandatory)][string] $Version)
    $escaped = [regex]::Escape($Version)
    $rows = [regex]::Matches($Html, "(?is)<tr\b[^>]*>\s*<td\b[^>]*>\s*$escaped\s*</td>.*?</tr>")
    if ($rows.Count -eq 0) { return $null }
    if ($rows.Count -ne 1) { throw "EnterpriseDB page contains $($rows.Count) rows for exact version $Version" }
    $cells = [regex]::Matches($rows[0].Value, '(?is)<td\b[^>]*>(.*?)</td>')
    # Published table columns: version, Linux x64, Linux x32, macOS,
    # Windows x64, Windows x32. Select only the Windows x64 cell.
    if ($cells.Count -lt 5) { throw "EnterpriseDB row for $Version has only $($cells.Count) columns" }
    $links = [regex]::Matches($cells[4].Groups[1].Value, '(?is)href\s*=\s*["'']([^"'']+)["'']')
    if ($links.Count -ne 1) { throw "EnterpriseDB Windows x64 cell for $Version has $($links.Count) links" }
    $link = [Net.WebUtility]::HtmlDecode($links[0].Groups[1].Value)
    $uri = $null
    if (-not [Uri]::TryCreate($link, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https') {
        throw "EnterpriseDB Windows x64 link for $Version is not an absolute HTTPS URL"
    }
    if ($uri.Host -notin @('sbp.enterprisedb.com','get.enterprisedb.com','www.enterprisedb.com')) {
        throw "EnterpriseDB page returned unexpected installer host '$($uri.Host)'"
    }
    return $uri.AbsoluteUri
}

function Resolve-PgInstallerUrl {
    param([Parameter(Mandatory)][string] $Version)
    $pageUrl = 'https://www.enterprisedb.com/downloads/postgres-postgresql-downloads'
    $page = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
    $publishedUrl = Resolve-PgInstallerLinkFromHtml -Html $page.Content -Version $Version
    if (-not $publishedUrl) { return $null }

    $head = Invoke-WebRequest -Uri $publishedUrl -Method Head -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
    if ($head.StatusCode -ne 200) { throw "EnterpriseDB installer link returned HTTP $($head.StatusCode)" }
    $resolvedUrl = $publishedUrl
    try {
        if ($head.BaseResponse.ResponseUri) { $resolvedUrl = $head.BaseResponse.ResponseUri.AbsoluteUri }
        elseif ($head.BaseResponse.RequestMessage.RequestUri) { $resolvedUrl = $head.BaseResponse.RequestMessage.RequestUri.AbsoluteUri }
    } catch {}
    $resolvedUri = [Uri]$resolvedUrl
    if ($resolvedUri.Scheme -ne 'https' -or $resolvedUri.Host -notin @('sbp.enterprisedb.com','get.enterprisedb.com','www.enterprisedb.com')) {
        throw "EnterpriseDB link redirected to unexpected URL '$resolvedUrl'"
    }
    $len = 0
    try {
        $cl = $head.Headers['Content-Length']
        if ($cl -is [array]) { $cl = $cl[0] }
        if ($cl) { $len = [int64]$cl }
    } catch {}
    Write-Log "EnterpriseDB publishes Windows x64 installer for $Version ($resolvedUrl)" OK
    return [pscustomobject]@{ PageUrl=$pageUrl; Url=$publishedUrl; ResolvedUrl=$resolvedUrl; Length=$len }
}

$installer = $null
if ($Install -or -not $SkipDownloadInAudit) {
    try { $installer = Resolve-PgInstallerUrl $target }
    catch { Complete-Run $EXIT.DOWNLOAD 'EDB_PAGE_OR_LINK_FAILED' "Could not resolve the Windows x64 installer from the EnterpriseDB download page: $($_.Exception.Message)" }
    if (-not $installer) {
        if ($script:EolBranch) {
            Complete-Run $EXIT.EOL 'EOL_INSTALLER_UNAVAILABLE' "PostgreSQL $pgBranch is EOL and EnterpriseDB does not list a Windows x64 installer for final minor $target. Handle the branch migration manually."
        }
        Complete-Run $EXIT.RETRY 'INSTALLER_NOT_PUBLISHED' "EnterpriseDB does not yet list a Windows x64 installer for PostgreSQL $target. Retry later."
    }
    Write-Log "EnterpriseDB page: $($installer.PageUrl)"
    Write-Log "Published installer URL: $($installer.Url)"
}

# ---------------------------------------------------------------------------
# AUDIT MODE STOPS HERE
# ---------------------------------------------------------------------------
if (-not $Install) {
    $msg = "Update available: PostgreSQL $runningVersion -> $target for $($script:Report.VeeamProducts). Re-run with -Install to apply."
    Write-Log $msg WARN
    $code = Get-PolicyExitCode -Eol $script:EolBranch -UpdateAvailable $true -RebootRequired $false
    Complete-Run $code 'UPDATE_AVAILABLE' $msg
}

# ---------------------------------------------------------------------------
# INSTALL ONLY FROM HERE
# ---------------------------------------------------------------------------
# The work root will hold database dumps, service/job state, and recovery evidence.
# If it could not be locked down, do not put those privileged artifacts in it.
if (-not $script:WorkRootProtected) {
    Complete-Run $EXIT.PREFLIGHT 'WORKROOT_UNSAFE' "The work root is not locked to SYSTEM and Administrators ($($wrInit.Reason)). Refusing to write database dumps or privileged recovery state there. Use the default -WorkRoot, or point it at a new or empty folder."
}
New-Item -ItemType Directory -Path $script:RunDir -Force | Out-Null
Write-Log "Run folder: $($script:RunDir)"
$script:RecoveryState = [pscustomobject][ordered]@{
    SchemaVersion                 = 1
    RunId                         = $script:Stamp
    RunDir                        = $script:RunDir
    Stage                         = 'UNTOUCHED'
    InstallerStarted              = $false
    Products                      = $script:Report.VeeamProducts
    OriginalVersion               = $runningVersion
    TargetVersion                 = $target
    PgServiceName                 = $pgSvc.Name
    PgPort                        = $pgPort
    PsqlPath                      = $psql
    DataDir                       = $pg.DataDir
    Vb365MaintenanceSessionId     = $null
    Vb365MaintenancePending       = $false
    Vb365MaintenanceAttemptedAt   = $null
    Vb365MaintenanceRepositoryIds = @()
    LogPath                       = $script:Transcript
    CreatedAt                     = (Get-Date).ToString('o')
    UpdatedAt                     = (Get-Date).ToString('o')
}

# ---------------------------------------------------------------------------
# STEP 11 - Inventory schedules and wait for Veeam work to finish naturally
# ---------------------------------------------------------------------------
Write-Log 'STEP 11 - Inventory schedules and wait for jobs/restores to finish naturally' STEP

# Revalidate immediately before any mutation; an administrator may have added a
# proxy or schedule after the earlier audit-safe capability probe.
$controlValidation = Get-VeeamControlSurfaceValidation -Vbr $hasVbr -Vb365 $hasVb365 -Reconnect:$hasVb365
if ($controlValidation.Kind -ne 'OK') {
    $validationCode = if ($controlValidation.Kind -eq 'UNSUPPORTED') { $EXIT.UNSUPPORTED } else { $EXIT.PREFLIGHT }
    Complete-Run $validationCode $controlValidation.IssueCode $controlValidation.Detail
}
$script:ManagedJobInventory = @($controlValidation.Inventory)
Write-Log "Inventoried $($script:ManagedJobInventory.Count) Veeam schedule/policy object(s) across all available families" OK

$jobWaitMinutes = 720
try { $jobWaitMinutes = [int](Get-CfgValue $Cfg 'jobWaitTimeoutMinutes' 720) } catch {}
if ($jobWaitMinutes -lt 1 -or $jobWaitMinutes -gt 10080) {
    Complete-Run $EXIT.PREFLIGHT 'BAD_JOB_WAIT_TIMEOUT' 'jobWaitTimeoutMinutes must be between 1 and 10080.'
}
$installerTimeoutMinutes = 120
try { $installerTimeoutMinutes = [int](Get-CfgValue $Cfg 'installerTimeoutMinutes' 120) } catch {}
if ($installerTimeoutMinutes -lt 1 -or $installerTimeoutMinutes -gt 10080) {
    Complete-Run $EXIT.PREFLIGHT 'BAD_INSTALLER_TIMEOUT' 'installerTimeoutMinutes must be between 1 and 10080. No schedule, service, or PostgreSQL state was changed.'
}
try { $idleBeforeDisable = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $jobWaitMinutes -Context 'before schedules are disabled' }
catch {
    $sessionCode = if ($_.Exception -is [System.NotSupportedException]) { $EXIT.UNSUPPORTED } else { $EXIT.PREFLIGHT }
    $sessionIssue = if ($sessionCode -eq $EXIT.UNSUPPORTED) { 'UNSUPPORTED_ACTIVITY_API' } else { 'SESSION_CHECK_FAILED' }
    Complete-Run $sessionCode $sessionIssue "Could not read every applicable Veeam session family, so it is impossible to prove the server is idle: $($_.Exception.Message)"
}
if (-not $idleBeforeDisable.Idle) {
    Complete-Run $EXIT.RETRY 'JOB_WAIT_TIMEOUT' "Veeam work did not finish within $jobWaitMinutes minutes ($($idleBeforeDisable.Labels -join ', ')). Nothing was changed and no job/restore was forcibly stopped."
}
Write-Log 'All observed Veeam jobs and restores are quiescent' OK

# ---------------------------------------------------------------------------
# STEP 12 - Download and verify the installer
# ---------------------------------------------------------------------------
Write-Log 'STEP 12 - Download and verify the installer' STEP

$installerPath = Join-Path $script:RunDir "postgresql-$target-windows-x64.exe"
$oldProgress = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'
try {
    Invoke-WebRequest -Uri $installer.Url -OutFile $installerPath -UseBasicParsing -TimeoutSec 1800
} catch {
    Complete-Run $EXIT.DOWNLOAD 'DOWNLOAD_FAILED' "Could not download $($installer.Url) : $($_.Exception.Message)"
} finally {
    $ProgressPreference = $oldProgress
}

$actualLen = (Get-Item $installerPath).Length
Write-Log ("Downloaded {0:N0} bytes" -f $actualLen)
if ($installer.Length -gt 0 -and $actualLen -ne $installer.Length) {
    Complete-Run $EXIT.DOWNLOAD 'SIZE_MISMATCH' ("Downloaded {0:N0} bytes but the server advertised {1:N0}. Aborting." -f $actualLen, $installer.Length)
}

# Authenticode is the ONLY authenticity control - EDB publishes no checksums.
$sig = Get-AuthenticodeSignature -FilePath $installerPath
Write-Log "Signature status : $($sig.Status)"
if ($sig.SignerCertificate) { Write-Log "Signature subject: $($sig.SignerCertificate.Subject)" }
if ($sig.Status -ne 'Valid') {
    Complete-Run $EXIT.DOWNLOAD 'BAD_SIGNATURE' "Authenticode status is $($sig.Status), not Valid. Refusing to run the installer."
}
if (-not $sig.SignerCertificate -or $sig.SignerCertificate.Subject -notmatch 'O=EnterpriseDB Corporation') {
    Complete-Run $EXIT.DOWNLOAD 'WRONG_SIGNER' "Installer is not signed by EnterpriseDB Corporation. Refusing to run it."
}
Write-Log 'Installer signature verified (EnterpriseDB Corporation)' OK

# ---------------------------------------------------------------------------
# STEP 13 - Disable scheduled jobs (remembering exactly which ones)
# ---------------------------------------------------------------------------
Write-Log 'STEP 13 - Disable scheduled jobs' STEP
try {
    # Refresh after the installer download so jobs created/disabled by an operator
    # during that interval are represented by their current, not stale, state.
    $script:ManagedJobInventory = @(Get-VeeamManagedJobInventory -Vbr $hasVbr -Vb365 $hasVb365)
    Disable-VeeamManagedJobs -Inventory $script:ManagedJobInventory
    $inventoryAfterDisable = @(Get-VeeamManagedJobInventory -Vbr $hasVbr -Vb365 $hasVb365)
    $unexpectedEnabled = @($inventoryAfterDisable | Where-Object { $_.Enabled })
    if ($unexpectedEnabled.Count -gt 0) {
        throw "schedule inventory changed during disable; still enabled: $((@($unexpectedEnabled) | ForEach-Object { \"$($_.Family):$($_.Name)\" }) -join ', ')"
    }
    $script:ManagedJobInventory = $inventoryAfterDisable
}
catch {
    # Complete-Run performs pre-installer rollback. The complete intent list was
    # saved before the first change, so even a mid-transition interruption is safe.
    Complete-Run $EXIT.PREFLIGHT 'JOB_DISABLE_FAILED' "Could not disable and verify every enabled Veeam schedule/policy: $($_.Exception.Message)"
}
Write-Log "Recovery marker and atomic job-state record written before the first schedule change: $($script:MarkerFile)" WARN
Write-Log "$($script:DisabledJobs.Count) job(s) disabled; recorded in disabled-jobs.json" OK

# Close the download/check-to-disable race: a job may have started after STEP 11
# but before its schedule was disabled. Disabling a schedule does not stop an
# already-running session, so wait for it naturally rather than terminating it.
try { $idleAfterDisable = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $jobWaitMinutes -Context 'after schedules were disabled' }
catch {
    Complete-Run $EXIT.PREFLIGHT 'SESSION_RECHECK_FAILED' "Could not re-check Veeam activity after disabling schedules: $($_.Exception.Message)"
}
if (-not $idleAfterDisable.Idle) {
    Complete-Run $EXIT.RETRY 'JOB_DRAIN_TIMEOUT' "Veeam work did not finish within $jobWaitMinutes minutes after schedules were disabled ($($idleAfterDisable.Labels -join ', ')). No job/restore was forcibly stopped; captured schedules will be restored."
}
Write-Log 'Re-check after disabling schedules confirms no Veeam work is active' OK

if ($hasVb365) {
    try { [void](Start-Vb365MaintenanceBarrier -TimeoutMinutes $jobWaitMinutes) }
    catch {
        Complete-Run $EXIT.RETRY 'VB365_MAINTENANCE_NOT_STARTED' "Could not establish the no-force VB365 repository maintenance barrier: $($_.Exception.Message)"
    }
}

# Generate the mandatory Veeam tuning SQL while the product control service and
# PowerShell connection are still healthy. The file is applied only after the
# minor update; generating it after stopping every Veeam service would make the
# server-connected tuner unreliable or unavailable.
$cs  = Get-CimInstance Win32_ComputerSystem
$cpu = [int]$cs.NumberOfLogicalProcessors
$ram = [math]::Floor([double]$cs.TotalPhysicalMemory / 1GB)
$tuneSql = Join-Path $script:RunDir 'pg-tuning.sql'
$tuningCommand = if ($hasVbr) { 'Set-VBRPSQLDatabaseServerLimits' } else { 'Set-VBOPSQLDatabaseServerLimits' }
try {
    if (-not (Get-Command $tuningCommand -ErrorAction SilentlyContinue)) {
        throw "$tuningCommand is unavailable for the detected Veeam product"
    }
    & $tuningCommand -OSType Windows -CPUCount $cpu -RamGb $ram -DumpToFile $tuneSql -ErrorAction Stop | Out-Null
    if (-not (Test-Path -LiteralPath $tuneSql) -or (Get-Item -LiteralPath $tuneSql).Length -eq 0) {
        throw "$tuningCommand did not produce a non-empty tuning SQL file"
    }
    Write-Log "Mandatory tuning SQL generated via $tuningCommand ($cpu vCPU, $ram GB RAM); it will be applied after the update" OK
} catch {
    Complete-Run $EXIT.PREFLIGHT 'VEEAM_TUNING_PREP_FAILED' "Could not generate mandatory Veeam PostgreSQL tuning before the outage: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# STEP 14 - Backups (VBR configuration backup, then logical dumps)
# ---------------------------------------------------------------------------
Write-Log 'STEP 14 - Backups' STEP

# Dumps are privileged data. The run folder inherits the SYSTEM + Administrators
# only ACL that was applied to the work root at start-up.
$backupDir = Join-Path $script:RunDir 'backup'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# VBR has a real configuration backup. A FAILED job is not a terminating error,
# so the result has to be read off the job object afterwards.
if ($hasVbr) {
    Write-Log 'Running VBR configuration backup (this can take a while)...'
    $lastRunBefore = $null
    try { $lastRunBefore = (Get-VBRConfigurationBackupJob -ErrorAction Stop).LastRun } catch {}

    try {
        Start-VBRConfigurationBackupJob -ErrorAction Stop | Out-Null
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'CONFIG_BACKUP_FAILED' "VBR configuration backup failed: $($_.Exception.Message). Refusing to continue without it."
    }

    $cfgResult = ''; $cfgLastRun = $null
    try {
        $cfgJobAfter = Get-VBRConfigurationBackupJob -ErrorAction Stop
        $cfgResult   = "$(Get-CfgValue $cfgJobAfter 'LastResult' '')"
        $cfgLastRun  = Get-CfgValue $cfgJobAfter 'LastRun' $null
    } catch {}

    if ($cfgResult -eq 'Failed') {
        Complete-Run $EXIT.PREFLIGHT 'CONFIG_BACKUP_FAILED' "VBR configuration backup finished with result 'Failed'. Refusing to continue without a good configuration backup."
    } elseif ($cfgResult -eq 'Success') {
        if ($lastRunBefore -and $cfgLastRun -and $cfgLastRun -eq $lastRunBefore) {
            Write-Log "VBR configuration backup reports Success but LastRun did not advance ($cfgLastRun) - the result may be stale. The cold copy and pg_dumps remain the primary restore path." WARN
        } else {
            Write-Log "VBR configuration backup completed (Result=Success, LastRun=$cfgLastRun)" OK
        }
    } elseif ($cfgResult -eq 'Warning') {
        Write-Log "VBR configuration backup completed with Result=Warning (LastRun=$cfgLastRun). Continuing - review the job in the VBR console." WARN
    } else {
        Write-Log "Could not read the VBR configuration backup result (got '$cfgResult'). Continuing on the strength of the cold copy and the verified pg_dumps - verify the .bco manually." WARN
    }
}

if ($hasVb365) {
    # VB365 has no configuration-backup feature at all. Config.xml plus the dumps
    # below are the whole safety net.
    foreach ($f in @('Config.xml','Proxy.xml')) {
        $src = Join-Path 'C:\ProgramData\Veeam\Backup365' $f
        if (Test-Path $src) { Copy-Item $src $backupDir -Force; Write-Log "  copied $f" }
    }
}

# Logical dumps of every Veeam database, plus globals (roles and grants).
foreach ($db in $veeamDatabases) {
    if ($db.Database -in @('.','..') -or ("$($db.Database)").IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
        Complete-Run $EXIT.PREFLIGHT 'UNSAFE_DATABASE_ARTIFACT_NAME' "Database '$($db.Database)' cannot be represented safely as a Windows recovery-artifact filename."
    }
    $dumpFile = Join-Path $backupDir "$($db.Database).dump"
    Write-Log "pg_dump $($db.Database) -> $dumpFile"
    $r = Invoke-Native $pgDump @('-U','postgres','-h','127.0.0.1','-p',"$pgPort",'-w','-F','c','-b','-f',$dumpFile,$db.Database)
    if ($r.StdErr) { Write-Log "    $($r.StdErr)" WARN }
    if ($r.ExitCode -ne 0 -or -not (Test-Path $dumpFile) -or (Get-Item $dumpFile).Length -lt 10KB) {
        Complete-Run $EXIT.PREFLIGHT 'DUMP_FAILED' "pg_dump of $($db.Database) failed (exit $($r.ExitCode)) or produced a suspiciously small file. $($r.StdErr)"
    }
    $listCheck = Invoke-Native $pgRestore @('--list', $dumpFile)
    if ($listCheck.ExitCode -ne 0 -or -not $listCheck.StdOut) {
        Complete-Run $EXIT.PREFLIGHT 'DUMP_VERIFY_FAILED' "pg_restore could not read the archive for $($db.Database) (exit $($listCheck.ExitCode)). $($listCheck.StdErr)"
    }
    Write-Log ("  {0:N1} MB" -f ((Get-Item $dumpFile).Length / 1MB)) OK
}

$globalsFile = Join-Path $backupDir 'globals.sql'
$r = Invoke-Native $pgDumpAll @('-U','postgres','-h','127.0.0.1','-p',"$pgPort",'-w','-g','-f',$globalsFile)
if ($r.StdErr) { Write-Log "    $($r.StdErr)" WARN }
if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $globalsFile) -or (Get-Item -LiteralPath $globalsFile).Length -eq 0) {
    Complete-Run $EXIT.PREFLIGHT 'DUMPALL_FAILED' "pg_dumpall -g (roles and grants) failed (exit $($r.ExitCode)). $($r.StdErr)"
}
Write-Log 'Globals dumped' OK

# Copy the four config files out of the data directory so we can diff later.
$confBackupDir = Join-Path $backupDir 'conf'
New-Item -ItemType Directory -Path $confBackupDir -Force | Out-Null
$confFiles = @('postgresql.conf','postgresql.auto.conf','pg_hba.conf','pg_ident.conf')
foreach ($cf in $confFiles) {
    $src = Join-Path $pg.DataDir $cf
    if (Test-Path $src) { Copy-Item $src $confBackupDir -Force; Write-Log "  saved $cf" }
    else { Write-Log "  $cf not found in $($pg.DataDir)" WARN }
}

# ---------------------------------------------------------------------------
# STEP 15 - Disable and stop services (Veeam first, then NATS, then PostgreSQL)
# ---------------------------------------------------------------------------
Write-Log 'STEP 15 - Disable and stop all Veeam services' STEP

try { $script:VeeamServices = @(Get-VeeamServiceState) }
catch {
    Complete-Run $EXIT.PREFLIGHT 'SERVICE_STATE_FAILED' "Could not capture Veeam service state: $($_.Exception.Message)"
}
if ($script:VeeamServices.Count -eq 0) {
    Complete-Run $EXIT.PREFLIGHT 'NO_VEEAM_SERVICES' 'A Veeam product was detected, but no Windows services named Veeam* were found.'
}

# This file is the exact manual-recovery record. Persist it before changing a
# startup type or stopping a service, including the Veeam Management Agent.
Write-AtomicJson -Path (Join-Path $script:RunDir 'veeam-service-state.json') -InputObject @($script:VeeamServices) -Depth 4
Write-Log "Captured $($script:VeeamServices.Count) Veeam service state(s) in veeam-service-state.json"
foreach ($rec in $script:VeeamServices) {
    Write-Log "  $($rec.Name): status=$($rec.Status), startup=$($rec.StartupType)"
}

$nats = Get-Service -Name 'nats-server' -ErrorAction SilentlyContinue
$script:NatsStateCaptured = ($null -ne $nats)
if ($nats -and "$($nats.Status)" -notin @('Running','Stopped')) {
    Complete-Run $EXIT.PREFLIGHT 'NATS_STATE_TRANSITION' "nats-server is $($nats.Status). Wait until it is Running or Stopped before updating."
}
$script:NatsWasRunning = ($nats -and $nats.Status -eq 'Running')

if ($nats) {
    try { $script:NatsStartupType = Get-ServiceStartupTypeExact 'nats-server' }
    catch { Complete-Run $EXIT.PREFLIGHT 'NATS_STARTUP_UNREADABLE' "Could not capture the nats-server startup type: $($_.Exception.Message)" }
    Write-AtomicJson -Path (Join-Path $script:RunDir 'nats-service-state.json') -InputObject ([pscustomobject]@{
        Name='nats-server'; Status="$($nats.Status)"; WasRunning=$script:NatsWasRunning; StartupType=$script:NatsStartupType
    }) -Depth 3
}

try { $script:PgStartupType = Get-ServiceStartupTypeExact $pgSvc.Name }
catch { Complete-Run $EXIT.PREFLIGHT 'PG_STARTUP_UNREADABLE' "Could not capture the PostgreSQL service startup type: $($_.Exception.Message)" }
Write-AtomicJson -Path (Join-Path $script:RunDir 'pg-service-state.json') -InputObject ([pscustomobject]@{
    Name=$pgSvc.Name
    Status="$($pgSvc.Status)"
    WasRunning=($pgSvc.Status -eq 'Running')
    StartupType=$script:PgStartupType
    PsqlPath=$psql
    Port=$pgPort
}) -Depth 3

# Refuse the outage if any running dependent is outside the exact Veeam* +
# nats-server + PostgreSQL stop set. The later stops also avoid -Force, so a
# dependency that starts after this check causes a safe failure, not a cascade.
$plannedServiceNames = @($script:VeeamServices.Name) + @($pgSvc.Name)
if ($nats) { $plannedServiceNames += 'nats-server' }
$externalDependents = @()
foreach ($plannedName in $plannedServiceNames) {
    try {
        $plannedService = Get-Service -Name $plannedName -ErrorAction Stop
        foreach ($dependent in @($plannedService.DependentServices)) {
            if ($dependent.Status -ne 'Stopped' -and $plannedServiceNames -notcontains $dependent.Name) {
                $externalDependents += "$($dependent.Name) (depends on $plannedName; status=$($dependent.Status))"
            }
        }
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'SERVICE_DEPENDENCY_CHECK_FAILED' "Could not inspect dependents of $plannedName : $($_.Exception.Message)"
    }
}
if ($externalDependents.Count -gt 0) {
    Complete-Run $EXIT.PREFLIGHT 'EXTERNAL_SERVICE_DEPENDENCY' "The planned shutdown has running dependent service(s) outside the Veeam/PostgreSQL scope: $((@($externalDependents) | Sort-Object -Unique) -join ', '). Nothing outside the planned scope was changed."
}

# The backup/dump phase can be long. Refresh the complete schedule inventory so
# a job created or re-enabled during it cannot remain enabled and start in the
# outage window (or immediately after services return).
try { $finalScheduleInventory = @(Get-VeeamManagedJobInventory -Vbr $hasVbr -Vb365 $hasVb365) }
catch {
    Complete-Run $EXIT.PREFLIGHT 'FINAL_JOB_INVENTORY_FAILED' "Could not refresh every schedule immediately before the outage: $($_.Exception.Message)"
}
$enabledBeforeOutage = @($finalScheduleInventory | Where-Object { $_.Enabled })
if ($enabledBeforeOutage.Count -gt 0) {
    $enabledNames = (@($enabledBeforeOutage) | ForEach-Object { "$($_.Family):$($_.Name)" }) -join ', '
    Complete-Run $EXIT.RETRY 'SCHEDULE_STATE_CHANGED' "Schedules were created or re-enabled during the protected backup phase ($enabledNames). The captured schedules will be restored; retry in a controlled window."
}
$script:ManagedJobInventory = $finalScheduleInventory

if ($hasVb365) {
    try {
        $barrierNow = Get-VBORepositoryMaintenanceSession -Id ([guid]$script:Vb365MaintenanceSessionId) -ErrorAction Stop
        if (-not $barrierNow -or "$($barrierNow.State)" -ne 'Running') {
            $barrierState = if ($barrierNow) { "$($barrierNow.State)" } else { 'missing' }
            throw "repository-maintenance barrier is $barrierState"
        }
    } catch {
        Complete-Run $EXIT.RETRY 'VB365_MAINTENANCE_LOST' "The VB365 repository-maintenance barrier did not remain Running through the backup phase: $($_.Exception.Message)"
    }
}

# The VBR configuration backup above is itself work, and an operator can still
# manually start work after schedules are disabled. Perform the last fail-closed
# drain only after every read-only service/dependency check, directly before the
# first outage-state write and startup-type mutation. VB365 is held by its
# repository-maintenance barrier; VBR has no equivalent global start barrier.
if ($hasVbr) {
    try { $finalIdle = Wait-VeeamIdle -Vbr $true -Vb365 $false -TimeoutMinutes $jobWaitMinutes -Context 'immediately before service shutdown' }
    catch { Complete-Run $EXIT.PREFLIGHT 'FINAL_SESSION_CHECK_FAILED' "Could not prove VBR was idle immediately before service shutdown: $($_.Exception.Message)" }
    if (-not $finalIdle.Idle) {
        Complete-Run $EXIT.RETRY 'FINAL_JOB_DRAIN_TIMEOUT' "VBR work did not finish within $jobWaitMinutes minutes before service shutdown ($($finalIdle.Labels -join ', ')). Nothing was forcibly stopped."
    }
}

Save-RecoveryState -Stage 'SERVICES_STOPPED' -InstallerStarted $false

$disableFailures = @(Disable-VeeamServiceStartup)
if ($disableFailures.Count -gt 0) {
    Complete-Run $EXIT.PREFLIGHT 'SERVICE_DISABLE_FAILED' "Could not disable every Veeam service: $($disableFailures -join ' | ')"
}

# Disabling startup does not stop the already-running scheduler services. Take
# one final bounded reading after that mutation and allow any manually-started
# VBR work to finish naturally before issuing the first Stop-Service request.
if ($hasVbr) {
    try { $lastChanceIdle = Wait-VeeamIdle -Vbr $true -Vb365 $false -TimeoutMinutes $jobWaitMinutes -Context 'after service startup was disabled' }
    catch { Complete-Run $EXIT.PREFLIGHT 'LAST_CHANCE_SESSION_CHECK_FAILED' "Could not prove VBR was idle after disabling service startup: $($_.Exception.Message)" }
    if (-not $lastChanceIdle.Idle) {
        Complete-Run $EXIT.RETRY 'LAST_CHANCE_JOB_DRAIN_TIMEOUT' "VBR work did not finish within $jobWaitMinutes minutes after service startup was disabled ($($lastChanceIdle.Labels -join ', ')). No service was stopped and no work was forcibly terminated."
    }
}

# A long final drain gives administrators time to create/re-enable a schedule.
# Refresh after the drain, then take one immediate activity read before the first
# service stop. Any drift rolls back; nothing is forcibly terminated.
try { $lastChanceInventory = @(Get-VeeamManagedJobInventory -Vbr $hasVbr -Vb365 $hasVb365) }
catch {
    $lastInventoryCode = if ($_.Exception -is [System.NotSupportedException]) { $EXIT.UNSUPPORTED } else { $EXIT.PREFLIGHT }
    $lastInventoryIssue = if ($lastInventoryCode -eq $EXIT.UNSUPPORTED) { 'UNSUPPORTED_SCHEDULER_FAMILY' } else { 'LAST_CHANCE_JOB_INVENTORY_FAILED' }
    Complete-Run $lastInventoryCode $lastInventoryIssue "Could not refresh every schedule after the final drain: $($_.Exception.Message)"
}
$lastChanceEnabled = @($lastChanceInventory | Where-Object { $_.Enabled })
if ($lastChanceEnabled.Count -gt 0) {
    $enabledNames = @($lastChanceEnabled | ForEach-Object { "$($_.Family):$($_.Name)" }) -join ', '
    Complete-Run $EXIT.RETRY 'LAST_CHANCE_SCHEDULE_STATE_CHANGED' "Schedules were created or re-enabled during the final drain ($enabledNames). No service was stopped; captured schedules will be restored and the run must be retried under a change freeze."
}
$script:ManagedJobInventory = @($lastChanceInventory)
try { $lastChanceActive = @(Get-ActiveVeeamWork -Vbr $hasVbr -Vb365 $hasVb365) }
catch {
    $lastActivityCode = if ($_.Exception -is [System.NotSupportedException]) { $EXIT.UNSUPPORTED } else { $EXIT.PREFLIGHT }
    $lastActivityIssue = if ($lastActivityCode -eq $EXIT.UNSUPPORTED) { 'UNSUPPORTED_ACTIVITY_API' } else { 'LAST_CHANCE_SESSION_CHECK_FAILED' }
    Complete-Run $lastActivityCode $lastActivityIssue "Could not complete the immediate pre-stop activity read: $($_.Exception.Message)"
}
if ($lastChanceActive.Count -gt 0) {
    Complete-Run $EXIT.RETRY 'LAST_CHANCE_ACTIVITY_RACE' "New Veeam work appeared after the final drain ($($lastChanceActive -join ', ')). No service was stopped and nothing was forcibly terminated; retry under a change freeze."
}

# Never kill a Veeam console or Explorer process. One can be opened in the small
# interval after the last drain check, so close the race with a final process read.
$blockingUi = @(Get-BlockingVeeamUiProcesses -Vbr $hasVbr -Vb365 $hasVb365)
if ($blockingUi.Count -gt 0) {
    Complete-Run $EXIT.RETRY 'VEEAM_UI_OPEN' "A Veeam console/Explorer process opened before service shutdown ($((@($blockingUi) | ForEach-Object { \"$($_.ProcessName):PID$($_.Id)\" }) -join ', ')). It was not terminated; close it and retry."
}

# VB365 order matters: proxy, then service, then REST. Stop every other captured
# Veeam service after those, with management-agent services last.
$preferredStopOrder = @('Veeam.Archiver.Proxy','Veeam.Archiver.Service','Veeam.Archiver.REST.Service')
$remainingServices = @($script:VeeamServices.Name | Where-Object { $preferredStopOrder -notcontains $_ } |
    Sort-Object @{ Expression = { if ($_ -match 'Management.*Agent') { 1 } else { 0 } } }, @{ Expression = { $_ } })
$stopOrder = @($preferredStopOrder + $remainingServices | Select-Object -Unique)
$stopRequestWarnings = @()
$maxStopPasses = [math]::Max(1, $script:VeeamServices.Count)
for ($stopPass = 1; $stopPass -le $maxStopPasses; $stopPass++) {
    foreach ($svcName in $stopOrder) {
        if ($script:VeeamServices.Name -notcontains $svcName) { continue }
        try {
            $s = Get-Service -Name $svcName -ErrorAction Stop
            if ($s.Status -ne 'Stopped') {
                Write-Log "  stopping $svcName (pass $stopPass)"
                # Deliberately no -Force: Windows must refuse rather than cascade
                # into a newly-running dependent outside the captured Veeam set.
                Stop-Service -Name $svcName -ErrorAction Stop
            }
        } catch { $stopRequestWarnings += "$svcName (pass $stopPass): $($_.Exception.Message)" }
    }
    $veeamStillStopping = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Stopped' })
    if ($veeamStillStopping.Count -eq 0) { break }
    if ($stopPass -lt $maxStopPasses) { Start-Sleep -Seconds 2 }
}

if ($nats -and $nats.Status -ne 'Stopped') {
    Write-Log '  stopping nats-server'
    try { Stop-Service -Name 'nats-server' -ErrorAction Stop }
    catch { $stopRequestWarnings += "nats-server: $($_.Exception.Message)" }
}

Start-Sleep -Seconds 10

$currentVeeamServices = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue)
$currentVeeamNames = @($currentVeeamServices | ForEach-Object { $_.Name })
$stillUp = @($currentVeeamServices | Where-Object { $_.Status -ne 'Stopped' })
$newVeeamServices = @($currentVeeamServices | Where-Object { $script:VeeamServices.Name -notcontains $_.Name })
$missingVeeamServices = @($script:VeeamServices | Where-Object { $currentVeeamNames -notcontains $_.Name })
$natsStillUp = $null
if ($nats) {
    $natsAfterStop = Get-Service -Name 'nats-server' -ErrorAction SilentlyContinue
    if (-not $natsAfterStop -or $natsAfterStop.Status -ne 'Stopped') {
        $natsStillUp = if ($natsAfterStop) { "nats-server=$($natsAfterStop.Status)" } else { 'nats-server missing after stop request' }
    }
}
$notDisabled = @()
foreach ($rec in $script:VeeamServices) {
    try {
        if ((Get-ServiceStartupTypeExact $rec.Name) -ne 'Disabled') { $notDisabled += $rec.Name }
    } catch { $notDisabled += "$($rec.Name) (unreadable)" }
}
if ($stopRequestWarnings.Count -gt 0) {
    Write-Log "Service stop request warning(s); final state will decide success: $($stopRequestWarnings -join ' | ')" WARN
}
if ($stillUp.Count -gt 0 -or $newVeeamServices.Count -gt 0 -or $missingVeeamServices.Count -gt 0 -or $natsStillUp -or $notDisabled.Count -gt 0) {
    $issues = @()
    if ($stillUp.Count -gt 0) { $issues += "still running: $((@($stillUp) | ForEach-Object { \"$($_.Name)=$($_.Status)\" }) -join ', ')" }
    if ($newVeeamServices.Count -gt 0) { $issues += "service inventory changed after capture: $((@($newVeeamServices) | ForEach-Object { $_.Name }) -join ', ')" }
    if ($missingVeeamServices.Count -gt 0) { $issues += "captured service disappeared: $((@($missingVeeamServices) | ForEach-Object { $_.Name }) -join ', ')" }
    if ($natsStillUp) { $issues += "still running: $natsStillUp" }
    if ($notDisabled.Count -gt 0) { $issues += "startup type not Disabled: $($notDisabled -join ', ')" }
    Complete-Run $EXIT.PREFLIGHT 'SERVICES_WONT_STOP' "Could not disable and stop every Veeam service: $($issues -join ' | '). PostgreSQL was NOT modified."
}
Write-Log 'All Veeam services are Disabled and stopped' OK

# Once every Veeam service is down, no tracked client should remain connected.
# Refuse to stop PostgreSQL if an operator, monitor, or other untracked client is
# still attached; Stop-Service would terminate that session. This is an immediate
# fail-closed gate, not a license to terminate the client.
$clientActivitySql = @"
SELECT COALESCE(
    json_agg(json_build_object(
        'pid', pid,
        'user', usename,
        'database', datname,
        'application', application_name,
        'client', client_addr::text,
        'state', state
    ) ORDER BY pid)::text,
    '[]'
)
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND backend_type = 'client backend';
"@
$clientActivityResult = Invoke-Psql $clientActivitySql
if ($clientActivityResult.ExitCode -ne 0 -or -not $clientActivityResult.StdOut) {
    Complete-Run $EXIT.PREFLIGHT 'PG_CLIENT_ACTIVITY_UNVERIFIED' "Could not verify that PostgreSQL has no remaining client sessions after Veeam stopped. PostgreSQL was NOT stopped. stderr: $($clientActivityResult.StdErr)"
}
try { $remainingPgClients = @($clientActivityResult.StdOut | ConvertFrom-Json -ErrorAction Stop) }
catch {
    Complete-Run $EXIT.PREFLIGHT 'PG_CLIENT_ACTIVITY_UNVERIFIED' "PostgreSQL client-session inventory was not valid JSON. PostgreSQL was NOT stopped: $($_.Exception.Message)"
}
if ($remainingPgClients.Count -gt 0) {
    $clientSummary = @($remainingPgClients | ForEach-Object {
        "pid=$($_.pid),user=$($_.user),db=$($_.database),app=$($_.application),client=$($_.client),state=$($_.state)"
    }) -join ' | '
    Complete-Run $EXIT.RETRY 'PG_CLIENTS_STILL_CONNECTED' "PostgreSQL still has untracked client connection(s) after Veeam stopped ($clientSummary). They were not terminated; close or coordinate them, then retry."
}
Write-Log 'No other PostgreSQL client sessions remain after Veeam stopped' OK

if ($script:PgStartupType -eq 'Disabled') {
    # PostgreSQL was running despite a Disabled startup type. Make it temporarily
    # Manual so the installer and mandatory tuning restart can bring it back; the
    # exact Disabled state is restored only after all health checks succeed.
    try { Set-ServiceStartupTypeExact -Name $pgSvc.Name -StartupType Manual }
    catch { Complete-Run $EXIT.PREFLIGHT 'PG_TEMP_STARTUP_FAILED' "Could not make the running Disabled PostgreSQL service temporarily Manual: $($_.Exception.Message)" }
}
Write-Log "  stopping $($pgSvc.Name)"
try { Stop-Service -Name $pgSvc.Name -ErrorAction Stop }
catch { Write-Log "PostgreSQL stop request warning: $($_.Exception.Message); final state will decide success." WARN }
Start-Sleep -Seconds 5
if ((Get-Service -Name $pgSvc.Name).Status -ne 'Stopped') {
    Complete-Run $EXIT.PREFLIGHT 'PG_WONT_STOP' "PostgreSQL service $($pgSvc.Name) would not stop. PostgreSQL was NOT modified."
}
Write-Log 'PostgreSQL stopped' OK

# ---------------------------------------------------------------------------
# STEP 16 - Cold copy of the data directory (only valid now the server is down)
# ---------------------------------------------------------------------------
Write-Log 'STEP 16 - Cold copy of the PostgreSQL data directory' STEP

$coldCopy = Join-Path $backupDir 'datadir'
$rc = Invoke-Native 'robocopy.exe' @($pg.DataDir, $coldCopy, '/E', '/COPYALL', '/DCOPY:DAT', '/R:1', '/W:1', '/XJ', '/NFL', '/NDL', '/NP', '/NJH', '/NJS')
# robocopy exit codes below 8 are success
if ($rc.ExitCode -ge 8) {
    Complete-Run $EXIT.PREFLIGHT 'COLD_COPY_FAILED' "robocopy of the data directory failed (exit $($rc.ExitCode)). PostgreSQL was NOT modified. $($rc.StdErr)"
}
$sourceMeasure = Get-ChildItem -LiteralPath $pg.DataDir -File -Recurse -Force -ErrorAction Stop | Measure-Object -Property Length -Sum
$copyMeasure = Get-ChildItem -LiteralPath $coldCopy -File -Recurse -Force -ErrorAction Stop | Measure-Object -Property Length -Sum
$sourceBytes = [int64]$(if ($sourceMeasure.Sum) { $sourceMeasure.Sum } else { 0 })
$copyBytes = [int64]$(if ($copyMeasure.Sum) { $copyMeasure.Sum } else { 0 })
if ($sourceMeasure.Count -ne $copyMeasure.Count -or $sourceBytes -ne $copyBytes) {
    Complete-Run $EXIT.PREFLIGHT 'COLD_COPY_VERIFY_FAILED' "Cold-copy verification failed: source=$($sourceMeasure.Count) files/$sourceBytes bytes, copy=$($copyMeasure.Count) files/$copyBytes bytes. PostgreSQL was NOT modified."
}
Write-Log "Cold copy written to $coldCopy (robocopy exit $($rc.ExitCode))" OK

# ---------------------------------------------------------------------------
# STEP 17 - Run the installer. The server IS being changed from here on.
# ---------------------------------------------------------------------------
Write-Log 'STEP 17 - Run the PostgreSQL installer' STEP
Set-RecoveryProperty BackupDirectory $backupDir
Set-RecoveryProperty ColdCopyDirectory $coldCopy
Save-RecoveryState -Stage 'INSTALLING' -InstallerStarted $true
Write-Log "Recovery marker updated: $($script:MarkerFile)" WARN

$debugTrace = Join-Path $script:RunDir 'pg_installer_debug.log'
# Quote the trace path - Start-Process does not quote array elements, so a
# WorkRoot containing a space would inject stray arguments into the installer.
$installerArgs = @(
    '--mode', 'unattended'
    '--unattendedmodeui', 'none'
    '--disable-components', 'pgAdmin,stackbuilder'
    '--debugtrace', ('"{0}"' -f $debugTrace)
)
# Deliberately NOT passed: --datadir (silently ignored on upgrade), --prefix,
# --serverport, --servicename, --serviceaccount, --superpassword, --locale.
# The installer reads all of those from the existing installation.

Write-Log "Command: `"$installerPath`" $($installerArgs -join ' ')"
$proc = Start-Process -FilePath $installerPath -ArgumentList $installerArgs -PassThru -NoNewWindow
$timeoutMilliseconds = [math]::Min([int]::MaxValue, [int64]$installerTimeoutMinutes * 60 * 1000)
if (-not $proc.WaitForExit([int]$timeoutMilliseconds)) {
    $script:Report.IssueCode = 'INSTALLER_TIMEOUT'
    $script:Report.ActionRequired = "PAGE AN OPERATOR. The EDB installer exceeded $installerTimeoutMinutes minutes and was deliberately not killed. Check PID $($proc.Id) and RecoveryRunDir."
    Complete-Run $EXIT.ESCALATE 'INSTALLER_TIMEOUT' "The installer (PID $($proc.Id)) did not exit within $installerTimeoutMinutes minutes. It was not forcibly terminated."
}
$proc.WaitForExit()
$installerExit = $proc.ExitCode
Write-Log "Installer exit code: $installerExit"

# Collect the installer's own logs from BOTH temp locations, before anything is deleted.
foreach ($tempDir in @($env:TEMP, 'C:\Windows\Temp')) {
    if (-not $tempDir -or -not (Test-Path $tempDir)) { continue }
    foreach ($pattern in @('install-postgresql*.log','bitrock_installer*.log')) {
        Get-ChildItem -Path $tempDir -Filter $pattern -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 2 |
            ForEach-Object { Copy-Item $_.FullName (Join-Path $script:RunDir "installer-$($_.Name)") -Force -ErrorAction SilentlyContinue }
    }
}
Write-Log "Installer logs collected into $($script:RunDir)"

if ($installerExit -ne 0) {
    Complete-Run $EXIT.ESCALATE 'INSTALLER_FAILED' "Installer exited $installerExit."
}

# ---------------------------------------------------------------------------
# STEP 18 - Verify (never trust the exit code alone)
# ---------------------------------------------------------------------------
Write-Log 'STEP 18 - Verify the update' STEP

$pgSvcAfter = Get-Service -Name $pgSvc.Name -ErrorAction SilentlyContinue
if (-not $pgSvcAfter) {
    Complete-Run $EXIT.ESCALATE_NOW 'SERVICE_GONE' "The PostgreSQL service $($pgSvc.Name) no longer exists after the install - this is the documented silent-failure mode. RESTORE FROM $coldCopy."
}
if ($pgSvcAfter.Status -ne 'Running') {
    try { Start-Service -Name $pgSvc.Name -ErrorAction Stop } catch { Write-Log "Start-Service failed: $($_.Exception.Message)" WARN }
    Start-Sleep -Seconds 15
}
if ((Get-Service -Name $pgSvc.Name).Status -ne 'Running') {
    Complete-Run $EXIT.ESCALATE_NOW 'PG_WONT_START' "PostgreSQL will not start after the update. RESTORE FROM $coldCopy."
}
Write-Log 'PostgreSQL service is running' OK

$expectedNum = ConvertTo-ServerVersionNum $target
$verOk = $false
for ($i = 1; $i -le 12; $i++) {
    Start-Sleep -Seconds 5
    $check = Invoke-Psql 'SHOW server_version_num;'
    if ($check.ExitCode -eq 0 -and $check.StdOut -match '^\d+$') {
        $newNum = [int]$check.StdOut
        Write-Log "server_version_num = $newNum (expected $expectedNum)"
        if ($newNum -eq $expectedNum) { $verOk = $true }
        break
    }
    Write-Log "  waiting for PostgreSQL to accept connections (attempt $i/12): $($check.StdErr)"
}
if (-not $verOk) {
    Complete-Run $EXIT.ESCALATE_NOW 'VERSION_MISMATCH' "PostgreSQL did not report the expected version $target after the update. RESTORE FROM $coldCopy."
}
Write-Log "Verified: PostgreSQL is now $target" OK
Save-RecoveryState -Stage 'VERIFIED' -InstallerStarted $true
$script:Report.PgInstalled = $target

# Diff the config files. listen_addresses matters a lot for VB365.
foreach ($cf in $confFiles) {
    $before = Join-Path $confBackupDir $cf
    $after  = Join-Path $pg.DataDir $cf
    if (-not (Test-Path $before)) { continue }
    if (-not (Test-Path $after)) {
        Write-Log "$cf is MISSING from the data directory after the update. Restoring it from backup." WARN
        Copy-Item $before $after -Force
        continue
    }
    try {
        # Compare-Object throws on an empty reference or difference set.
        $a = @(Get-Content $before -ErrorAction SilentlyContinue)
        $b = @(Get-Content $after  -ErrorAction SilentlyContinue)
        if ($a.Count -eq 0 -and $b.Count -eq 0) { Write-Log "$cf unchanged (both empty)" OK; continue }
        if ($a.Count -eq 0 -or  $b.Count -eq 0) { Write-Log "$cf CHANGED: one side is now empty ($($a.Count) -> $($b.Count) lines)" WARN; continue }
        $diff = Compare-Object $a $b
        if ($diff) {
            Write-Log "$cf CHANGED during the update:" WARN
            $diff | ForEach-Object { Write-Log "    $($_.SideIndicator) $($_.InputObject)" WARN }
        } else {
            Write-Log "$cf unchanged" OK
        }
    } catch { Write-Log "Could not diff $cf : $($_.Exception.Message)" WARN }
}

# ---------------------------------------------------------------------------
# STEP 19 - Apply Veeam's PostgreSQL tuning (mandatory and verified)
# ---------------------------------------------------------------------------
Write-Log 'STEP 19 - Apply mandatory Veeam PostgreSQL tuning' STEP

$tuningError = $null

try {
    if (-not (Test-Path -LiteralPath $tuneSql) -or (Get-Item -LiteralPath $tuneSql).Length -eq 0) {
        throw "the pre-generated $tuningCommand SQL file is missing or empty"
    }
    $t = Invoke-Native $psql @('-U','postgres','-h','127.0.0.1','-p',"$pgPort",'-w','-v','ON_ERROR_STOP=1','-f',$tuneSql)
    if ($t.StdErr) { Write-Log "    $($t.StdErr)" WARN }
    if ($t.ExitCode -ne 0) { throw "psql returned $($t.ExitCode) applying the tuning SQL" }

    # A restart is required for all generated server-limit settings. Do not use
    # -Force: an unexpected dependent must stop the workflow, never be cascaded.
    Stop-Service -Name $pgSvc.Name -ErrorAction Stop
    $pgStoppedForTuning = $false
    for ($i = 1; $i -le 12; $i++) {
        if ((Get-Service -Name $pgSvc.Name -ErrorAction Stop).Status -eq 'Stopped') { $pgStoppedForTuning = $true; break }
        Start-Sleep -Seconds 5
    }
    if (-not $pgStoppedForTuning) { throw 'PostgreSQL did not stop for the tuning restart' }
    Start-Service -Name $pgSvc.Name -ErrorAction Stop
    $back = $false
    for ($i = 1; $i -le 24; $i++) {
        $c = Invoke-Psql 'SHOW server_version_num;'
        if ($c.ExitCode -eq 0 -and $c.StdOut -match '^\d+$' -and [int]$c.StdOut -eq $expectedNum) { $back = $true; break }
        Start-Sleep -Seconds 5
    }
    if (-not $back) {
        Complete-Run $EXIT.ESCALATE_NOW 'PG_DOWN_AFTER_TUNING' "PostgreSQL did not return at version $target after mandatory Veeam tuning. The tuning file is $tuneSql. RESTORE FROM $coldCopy if it cannot be repaired."
    }
    Write-Log "Mandatory tuning applied via $tuningCommand ($cpu vCPU, $ram GB RAM) and PostgreSQL verified up" OK
} catch {
    $tuningError = $_.Exception.Message
}

if ($tuningError) {
    # Try only to recover database availability; never pretend tuning succeeded,
    # restore Veeam services, or re-enable schedules after a tuning failure.
    $pgRecovered = $false
    for ($i = 1; $i -le 24; $i++) {
        $pgNow = Get-Service -Name $pgSvc.Name -ErrorAction SilentlyContinue
        if ($pgNow -and $pgNow.Status -eq 'Stopped') {
            try { Start-Service -Name $pgSvc.Name -ErrorAction Stop } catch {}
        }
        $probe = Invoke-Psql 'SHOW server_version_num;'
        if ($probe.ExitCode -eq 0 -and $probe.StdOut -match '^\d+$') { $pgRecovered = $true; break }
        Start-Sleep -Seconds 5
    }
    $script:Report.IssueCode = 'VEEAM_TUNING_FAILED'
    $script:Report.JobsLeftDisabled = (@($script:DisabledJobs | ForEach-Object { $_.Name }) -join ', ')
    if (-not $pgRecovered) {
        $script:Report.ActionRequired = 'PAGE AN OPERATOR NOW. PostgreSQL is unavailable after mandatory tuning; Veeam services and schedules remain down/disabled.'
        Complete-Run $EXIT.ESCALATE_NOW 'PG_DOWN_AFTER_TUNING' "$tuningCommand failed ($tuningError), and PostgreSQL could not be made queryable. Recovery evidence: $($script:RunDir)."
    }
    $script:Report.ActionRequired = 'PAGE AN OPERATOR. Mandatory Veeam PostgreSQL tuning failed; PostgreSQL is queryable, but Veeam services and schedules remain down/disabled.'
    Complete-Run $EXIT.ESCALATE 'VEEAM_TUNING_FAILED' "$tuningCommand failed: $tuningError. PostgreSQL is queryable; correct the tuning issue before restoring Veeam services and jobs."
}

# ---------------------------------------------------------------------------
# STEP 20 - Restore Veeam service startup types and running states
# ---------------------------------------------------------------------------
Write-Log 'STEP 20 - Restore Veeam service state' STEP

$natsRequestWarning = $null
try { Set-ServiceStartupTypeExact -Name $pgSvc.Name -StartupType $script:PgStartupType }
catch { $natsRequestWarning = "PostgreSQL startup-type restore: $($_.Exception.Message)" }
if ($script:NatsStateCaptured) {
    try {
        $natsTypeForStart = if ($script:NatsWasRunning -and $script:NatsStartupType -eq 'Disabled') { 'Manual' } else { $script:NatsStartupType }
        Set-ServiceStartupTypeExact -Name 'nats-server' -StartupType $natsTypeForStart
        $natsCurrent = Get-Service -Name 'nats-server' -ErrorAction Stop
        if ($script:NatsWasRunning -and $natsCurrent.Status -ne 'Running') {
            Start-Service -Name 'nats-server' -ErrorAction Stop
        } elseif (-not $script:NatsWasRunning -and $natsCurrent.Status -eq 'Running') {
            # Once the Veeam control plane is coming back, a service can be
            # started by newly-arrived manual work. Never stop it merely to
            # reproduce the old snapshot; restore its startup mode and leave
            # the live instance alone.
            Write-Log '  leaving externally running nats-server untouched during no-stop restoration' WARN
        } elseif (-not $script:NatsWasRunning -and $natsCurrent.Status -ne 'Stopped') {
            Write-Log "  leaving nats-server untouched in transitional state $($natsCurrent.Status); final health verification will fail closed if it does not settle" WARN
        }
        if ($script:NatsStartupType -eq 'Disabled') { Set-ServiceStartupTypeExact -Name 'nats-server' -StartupType Disabled }
    } catch { $natsRequestWarning = "nats-server restore request: $($_.Exception.Message)" }
}
$serviceRestoreProblems = @(Restore-VeeamServiceState -AllowStops:$false)
if ($natsRequestWarning) { Write-Log "$natsRequestWarning; final state will decide success." WARN }
if ($serviceRestoreProblems.Count -gt 0) {
    Write-Log "Initial service-restore verification reported: $($serviceRestoreProblems -join ' | '). The post-settle state will decide success." WARN
}

Write-Log 'Waiting 90s for Automatic (Delayed Start) services to settle...'
Start-Sleep -Seconds 90

$notRunning = @()
$pgFinalProblems = @()
foreach ($rec in $script:VeeamServices) {
    $s = Get-Service -Name $rec.Name -ErrorAction SilentlyContinue
    if (-not $s) {
        $notRunning += "$($rec.Name) (service missing)"
        continue
    }
    if ($rec.WasRunning -and $s.Status -ne 'Running') {
        $notRunning += "$($rec.Name) (expected Running, got $($s.Status))"
    } elseif (-not $rec.WasRunning -and $s.Status -eq 'Running') {
        Write-Log "$($rec.Name) was originally stopped but is now $($s.Status); leaving it untouched to avoid interrupting newly-arrived work" WARN
    } elseif (-not $rec.WasRunning -and $s.Status -ne 'Stopped') {
        $notRunning += "$($rec.Name) (transitional state $($s.Status) did not settle to Running or Stopped)"
    }
    try {
        $actualStartup = Get-ServiceStartupTypeExact $rec.Name
        if ($actualStartup -ne $rec.StartupType) {
            $notRunning += "$($rec.Name) (startup expected $($rec.StartupType), got $actualStartup)"
        }
    } catch { $notRunning += "$($rec.Name) (startup type unreadable: $($_.Exception.Message))" }
}
if ($script:NatsStateCaptured) {
    $natsAfter = Get-Service -Name 'nats-server' -ErrorAction SilentlyContinue
    if (-not $natsAfter) {
        $notRunning += 'nats-server (service missing)'
    } else {
        if ($script:NatsWasRunning -and "$($natsAfter.Status)" -ne 'Running') {
            $notRunning += "nats-server (expected Running, got $($natsAfter.Status))"
        } elseif (-not $script:NatsWasRunning -and "$($natsAfter.Status)" -eq 'Running') {
            Write-Log "nats-server was originally stopped but is now $($natsAfter.Status); leaving it untouched to avoid interrupting newly-arrived work" WARN
        } elseif (-not $script:NatsWasRunning -and "$($natsAfter.Status)" -ne 'Stopped') {
            $notRunning += "nats-server (transitional state $($natsAfter.Status) did not settle to Running or Stopped)"
        }
        try {
            $natsStartupAfter = Get-ServiceStartupTypeExact 'nats-server'
            if ($natsStartupAfter -ne $script:NatsStartupType) {
                $notRunning += "nats-server (startup expected $($script:NatsStartupType), got $natsStartupAfter)"
            }
        } catch { $notRunning += "nats-server (startup type unreadable: $($_.Exception.Message))" }
    }
}
try {
    $pgAfterServices = Get-Service -Name $pgSvc.Name -ErrorAction Stop
    if ($pgAfterServices.Status -ne 'Running') { $pgFinalProblems += "$($pgSvc.Name) (expected Running, got $($pgAfterServices.Status))" }
    $pgStartupAfter = Get-ServiceStartupTypeExact $pgSvc.Name
    if ($pgStartupAfter -ne $script:PgStartupType) { $pgFinalProblems += "$($pgSvc.Name) (startup expected $($script:PgStartupType), got $pgStartupAfter)" }
    $pgHealth = Invoke-Psql 'SHOW server_version_num;'
    if ($pgHealth.ExitCode -ne 0 -or $pgHealth.StdOut -notmatch '^\d+$' -or [int]$pgHealth.StdOut -ne $expectedNum) {
        $pgFinalProblems += "$($pgSvc.Name) (database health/version query failed: $($pgHealth.StdErr) $($pgHealth.StdOut))"
    }
} catch { $pgFinalProblems += "$($pgSvc.Name) (health verification failed: $($_.Exception.Message))" }
if ($hasVbr) {
    $broker = Test-NetConnection -ComputerName 127.0.0.1 -Port 9501 -WarningAction SilentlyContinue
    if ($broker.TcpTestSucceeded) { Write-Log 'VeeamBrokerSvc is listening on TCP 9501' OK }
    else { Write-Log 'VeeamBrokerSvc is NOT listening on TCP 9501' WARN; $notRunning += 'VeeamBrokerSvc(port9501)' }
}

# The VB365 controller connection does not survive its service restart. Reconnect
# before releasing repository maintenance or touching schedules. VBR is imported
# again as a harmless health check of its local module surface.
$postStartModuleProblems = @(Connect-VeeamModules -Vbr:$hasVbr -Vb365:$hasVb365 -Quiet -Reconnect:$hasVb365)
if ($postStartModuleProblems.Count -gt 0) { $notRunning += @($postStartModuleProblems) }
if ($notRunning.Count -eq 0 -and $pgFinalProblems.Count -eq 0) {
    Write-Log 'All Veeam service startup types and running states were restored' OK
}

# ---------------------------------------------------------------------------
# STEP 21 - Turn the jobs back on and finish. No reboot, nothing left behind.
# ---------------------------------------------------------------------------
Write-Log 'STEP 21 - Re-enable jobs and finish' STEP

# Never re-enable schedules on an unhealthy platform. PostgreSQL unavailable or
# at the wrong version is the emergency exit 50; other Veeam/service health
# failures are exit 40. Both retain the marker and recovery evidence.
if ($pgFinalProblems.Count -gt 0) {
    $allHealthProblems = @($pgFinalProblems) + @($notRunning)
    $script:Report.UnhealthyServices = $allHealthProblems -join ', '
    $script:Report.JobsLeftDisabled = (Get-UnrestoredJobNames -Records $script:DisabledJobs) -join ', '
    $script:Report.IssueCode = 'POST_UPDATE_POSTGRES_UNHEALTHY'
    $script:Report.ActionRequired = 'PAGE AN OPERATOR NOW. PostgreSQL is unavailable, misconfigured, or at the wrong version after the update; schedules remain disabled. Use RecoveryRunDir evidence and the cold copy.'
    Complete-Run $EXIT.ESCALATE_NOW 'POST_UPDATE_POSTGRES_UNHEALTHY' "PostgreSQL updated attempt $runningVersion -> $target, but final PostgreSQL verification failed: $($pgFinalProblems -join ' | '). Jobs remain disabled."
}
if ($notRunning.Count -gt 0) {
    $script:Report.UnhealthyServices = $notRunning -join ', '
    $script:Report.JobsLeftDisabled = (@($script:DisabledJobs | ForEach-Object { $_.Name }) -join ', ')
    $script:Report.IssueCode = 'SERVICES_UNHEALTHY_JOBS_DISABLED'
    $script:Report.ActionRequired = 'PAGE AN OPERATOR. PostgreSQL/Veeam health verification failed; schedules were deliberately left disabled. See UnhealthyServices and RecoveryRunDir.'
    Complete-Run $EXIT.ESCALATE 'SERVICES_UNHEALTHY_JOBS_DISABLED' "PostgreSQL updated $runningVersion -> $target, but health checks failed: $($notRunning -join ' | '). Jobs remain disabled."
}

if ($script:Vb365MaintenanceSessionId) {
    try { Stop-Vb365MaintenanceBarrier -SessionId $script:Vb365MaintenanceSessionId }
    catch {
        $script:Report.JobsLeftDisabled = (@($script:DisabledJobs | ForEach-Object { $_.Name }) -join ', ')
        $script:Report.IssueCode = 'VB365_MAINTENANCE_RELEASE_FAILED'
        $script:Report.ActionRequired = 'PAGE AN OPERATOR. Services are healthy, but VB365 repository maintenance could not be released; schedules remain disabled.'
        Complete-Run $EXIT.ESCALATE 'VB365_MAINTENANCE_RELEASE_FAILED' $_.Exception.Message
    }
}

try { $idleBeforeEnable = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $jobWaitMinutes -Context 'before schedules are re-enabled' }
catch {
    $script:Report.JobsLeftDisabled = (@($script:DisabledJobs | ForEach-Object { $_.Name }) -join ', ')
    Complete-Run $EXIT.ESCALATE 'FINAL_SESSION_CHECK_FAILED' "Services are healthy, but final activity verification failed; schedules remain disabled: $($_.Exception.Message)"
}
if (-not $idleBeforeEnable.Idle) {
    $script:Report.JobsLeftDisabled = (@($script:DisabledJobs | ForEach-Object { $_.Name }) -join ', ')
    Complete-Run $EXIT.ESCALATE 'FINAL_JOB_DRAIN_TIMEOUT' "New Veeam work did not finish within $jobWaitMinutes minutes ($($idleBeforeEnable.Labels -join ', ')); schedules remain disabled and no work was forcibly terminated."
}

$failedJobs = @()
foreach ($j in $script:DisabledJobs) {
    try {
        Enable-VeeamJobById $j
        $j.Restored = $true
        Save-DisabledJobState
        Write-Log "  re-enabled $($j.Family): $($j.Name)"
    }
    catch { $failedJobs += "$($j.Name) ($($_.Exception.Message))"; Write-Log "  COULD NOT re-enable $($j.Name): $($_.Exception.Message)" ERROR }
}
if ($failedJobs.Count -eq 0) { Write-Log "$($script:DisabledJobs.Count) job(s) re-enabled" OK }

$script:Report.RebootRequired = $true

# Anything wrong: report it and leave the marker in place, so the next run stops
# and waits for a human instead of carrying on as if all is well.
if ($failedJobs.Count -gt 0) {
    $remaining = @($script:DisabledJobs | Where-Object { -not $_.Restored } | ForEach-Object { $_.Name })
    $script:Report.JobsLeftDisabled = $remaining -join ', '
    $script:Report.IssueCode = 'JOB_REENABLE_FAILED'
    $script:Report.ActionRequired = 'PAGE AN OPERATOR. Services are healthy, but one or more schedules could not be re-enabled; see JobsLeftDisabled and RecoveryRunDir.'
    Complete-Run $EXIT.ESCALATE 'JOB_REENABLE_FAILED' "PostgreSQL updated $runningVersion -> $target and services are healthy, but these schedules remain disabled: $($failedJobs -join '; ')"
}

Save-RecoveryState -Stage 'COMPLETE' -InstallerStarted $true
if (-not (Remove-RecoveryMarker)) {
    $script:Report.IssueCode = 'MARKER_REMOVE_FAILED'
    Complete-Run $EXIT.ESCALATE 'MARKER_REMOVE_FAILED' 'Update and state restoration succeeded, but the recovery marker could not be removed.'
}
Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
Write-Log 'Installer deleted'
$doneMsg = "PostgreSQL updated $runningVersion -> $target. Services verified and $($script:DisabledJobs.Count) job(s) re-enabled. Backups: $backupDir."

$successCode = Get-PolicyExitCode -Eol $script:EolBranch -UpdateAvailable $false -RebootRequired $true
if ($Reboot) {
    # Strict no-interruption policy: once schedules are enabled, VBR provides no
    # global/atomic "prevent new work" barrier. Even shutdown /t 0 has a TOCTOU
    # race. Defer the restart to the RMM's controlled change-freeze workflow.
    $script:Report.IssueCode = 'REBOOT_REQUIRES_RMM_COORDINATION'
    $script:Report.ActionRequired = 'RMM: enforce a Veeam change freeze, wait for all work to finish, reboot, verify LastBootUpTime, then rerun audit. Do not rerun the installer.'
    Complete-Run $successCode 'UPDATED_REBOOT_DEFERRED_SAFETY' "$doneMsg -Reboot was requested, but no shutdown was attempted because an atomic VBR new-work barrier does not exist. Reboot through the RMM change-freeze workflow."
}
Complete-Run $successCode 'UPDATED_REBOOT_REQUIRED' "$doneMsg Veeam recommends restarting the server. Reboot through the RMM change-freeze workflow, verify LastBootUpTime, then rerun audit."

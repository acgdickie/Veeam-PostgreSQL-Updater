<#
.SYNOPSIS
    Veeam PostgreSQL and NATS Update.
    Audits and (optionally) applies a PostgreSQL MINOR version update on a Windows
    server running Veeam Backup & Replication (VBR) and/or Veeam Backup for
    Microsoft 365 (VB365 / "VBM").

.DESCRIPTION
    Veeam does not patch the bundled PostgreSQL engine on Windows. Product upgrades
    leave it untouched, so a Veeam server can run a PostgreSQL build that is missing
    current security fixes.

    This script follows Veeam KB4386 (VBR) and KB4729 (VB365):
      https://www.veeam.com/kb4386
      https://www.veeam.com/kb4729

    SAME MAJOR VERSION ONLY. 15.x -> 15.y is an in-place binary swap and is safe.
    15.x -> 16.x is a major upgrade, needs pg_upgrade, and is HARD BLOCKED here.

    VB365 only: it also updates NATS, the nats-server service VB365 8 uses for its
    job queue, as Veeam KB4742 describes (https://www.veeam.com/kb4742). Again an
    update, never an upgrade: only to a newer version Veeam supports on the SAME
    2.x line (2.10.22 -> 2.10.28, never 2.10 -> 2.12), and only a download that
    matches a SHA256 pinned in this script. One change per run: when PostgreSQL
    also needs an update, this run updates PostgreSQL and the next -Install run
    updates NATS. Set updateNats to false below to only report NATS.

    Default mode is AUDIT: it reports and changes nothing. Pass -Install to commit.

    Everything happens in ONE run, while your RMM script is running: wait for
    active work to finish, disable jobs, back up, stop services, update
    PostgreSQL, tune it, start services, and turn jobs back on. No backup or
    restore is forcibly terminated.

    It does not reboot unless you pass -Reboot. Veeam's KBs recommend a server
    restart after the update. Without -Reboot it reports RebootRequired=True for
    the RMM to handle. With -Reboot, after a fully successful update, it books a
    restart -RebootDelaySeconds later (default 120), so the run finishes and the
    RMM collects its output before Windows restarts.

.PARAMETER Install
    Actually perform the update. Without this the script only reports.

.PARAMETER Reboot
    With -Install: after a fully successful update, book a Windows restart
    -RebootDelaySeconds later, so this run finishes and the RMM collects its output
    first. It returns 0 (or 7 on an EOL branch) with RebootScheduledAt set. Cancel a
    booked restart with: shutdown /a
    Just before booking it, the run checks for Veeam work once more. Once schedules
    are back on, VBR has no barrier that stops new work, so if a job or restore has
    started, or an Explorer is open, no restart is booked and the run returns 6 (or
    8) for the RMM to reboot later. An open console does not stop the restart.
    Never restarts after a failed, partial or rolled-back run, or when no update
    was needed. Does nothing without -Install.

.PARAMETER RebootDelaySeconds
    Seconds between booking the restart and Windows restarting, 30 to 3600.
    Default 120. Only used with -Reboot.

.PARAMETER Recover
    Recover a run that was interrupted before the PostgreSQL installer started.
    This restores captured service and job state only from the validated recovery
    manifest. If the installer has started, it finishes the run only when PostgreSQL
    proves healthy at the target version; otherwise it is diagnostic-only and exits
    40 or 50 for an operator. It never rolls database files back automatically.

.PARAMETER WorkRoot
    Local folder for logs, dumps and the cold copy. Default C:\ProgramData\VeeamPgUpdate
    The folder and its parent must pass ownership, ACL and reparse-point checks.
    Logs are written here only after those checks pass, and pruned after retentionDays.

.PARAMETER RemoveStaleEnterpriseManagerRecord
    Delete the leftover HKLM\SOFTWARE\Veeam\Veeam Backup Reporting registry key when
    this run has PROVEN Enterprise Manager is not installed (no service and no
    installed files). A .reg backup is exported into the log folder first, and the
    key is removed only after that backup is verified. If Enterprise Manager really
    is installed, or no leftover key was found, nothing is removed.
    This touches the registry only. It does not change the Veeam configuration
    database, so it does not clear a VBR-side Enterprise Manager connection record.

.PARAMETER SkipDownloadInAudit
    Audit mode normally checks the EnterpriseDB download page for the exact
    Windows x64 installer. This skips that check. The audit still contacts
    postgresql.org to resolve the latest minor release.

.NOTES
    EXIT CODES (for your RMM):
      0  OK            - healthy, with no outstanding RMM action. Also: updated,
                         and -Reboot booked the restart (RebootScheduledAt), or
                         NATS updated (no restart needed)
      5  UPDATE        - supported branch: audit found a PostgreSQL or NATS update
      6  REBOOT        - supported branch: update succeeded; reboot required
      7  EOL           - EOL branch; major migration required. Also: updated on
                         an EOL branch, and -Reboot booked the restart
      8  EOL+REBOOT    - EOL branch; reboot and major migration required
      9  EOL+UPDATE    - EOL branch; minor update and major migration required
      10 RETRY         - safe transient result; retry later
      11 UNSUPPORTED   - topology/guardrail exclusion; manual handling required
      20 PREFLIGHT     - pre-flight failed, needs attention. The server was either
                         untouched or fully rolled back by this script
      30 DOWNLOAD      - download, signature or hash check failed, nothing changed
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
    [ValidateRange(30, 3600)][int] $RebootDelaySeconds = 120,
    [switch] $Recover,
    [string] $WorkRoot = 'C:\ProgramData\VeeamPgUpdate',
    [switch] $SkipDownloadInAudit,
    [switch] $RemoveStaleEnterpriseManagerRecord
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
#  updateNats
#      VB365 only. true: an -Install run also updates NATS to the newest version
#      Veeam supports on the same 2.x line, on a run where PostgreSQL needs
#      nothing. false: NATS is only reported (NatsStatus=UPDATES_OFF).
#
#  These are the only adjustable settings. External settings/override files are
#  deliberately not supported; edit this block and redeploy the reviewed script.
# ===========================================================================
# Parse a JSON array into a flat list, on both PowerShell editions.
#
# Windows PowerShell 5.1's ConvertFrom-Json does NOT enumerate an array: it emits
# the whole array as ONE object, so @(...) yields a single Object[] element.
# PowerShell 7 enumerates and yields the items. Without this, a database list read
# on 5.1 comes back as "System.Object[]" and the Veeam database looks missing. Every
# json_agg result in this script goes through here.
function ConvertFrom-JsonArrayText {
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Text)
    $parsed = $Text | ConvertFrom-Json -ErrorAction Stop
    $items = @()
    foreach ($entry in @($parsed)) {
        if ($null -ne $entry -and $entry -isnot [string] -and $entry -is [System.Collections.IEnumerable]) {
            foreach ($inner in $entry) { $items += $inner }
        } else {
            $items += $entry
        }
    }
    return $items
}

function Get-DefaultConfig {
    $json = @'
{
  "jobWaitTimeoutMinutes": 720,
  "installerTimeoutMinutes": 120,
  "retentionDays": 30,
  "updateNats": true
}
'@
    return ($json | ConvertFrom-Json)
}

# Normalize the operator-supplied path before deriving any child paths. WorkRoot
# contains executable installers and database recovery material, so ambiguous,
# relative, UNC and drive-root paths fail before the script writes anything.
try {
    if ([string]::IsNullOrWhiteSpace($WorkRoot) -or
        -not [IO.Path]::IsPathRooted($WorkRoot) -or
        $WorkRoot -notmatch '^[A-Za-z]:[\\/]') {
        throw 'WorkRoot must be an absolute path on a local drive.'
    }
    $normalizedWorkRoot = [IO.Path]::GetFullPath($WorkRoot)
    $normalizedRoot = [IO.Path]::GetPathRoot($normalizedWorkRoot)
    if ($normalizedWorkRoot.TrimEnd('\') -ieq $normalizedRoot.TrimEnd('\')) {
        throw 'WorkRoot cannot be the root of a drive.'
    }
    $WorkRoot = $normalizedWorkRoot.TrimEnd('\')
} catch {
    $earlyMode = if ($Recover) { 'RECOVER' } elseif ($Install) { 'INSTALL' } else { 'AUDIT' }
    $earlyDetail = "WorkRoot '$WorkRoot' is unsafe: $($_.Exception.Message)"
    Write-Host '=== RMM SUMMARY ===' -ForegroundColor Magenta
    Write-Host "Computer=$env:COMPUTERNAME; Timestamp=$((Get-Date).ToString('s')); Mode=$earlyMode; Stage=UNTOUCHED; Outcome=WORKROOT_UNSAFE; ExitCode=$($EXIT.PREFLIGHT); IssueCode=WORKROOT_UNSAFE; ActionRequired=Use an absolute non-root path on a local drive.; Detail=$earlyDetail"
    Write-Host "RMM ISSUE: WORKROOT_UNSAFE | $earlyDetail" -ForegroundColor Yellow
    Write-Host '==================='
    exit $EXIT.PREFLIGHT
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
$script:WorkRootIsOurs = $false
$script:WorkRootProtected = $false
$script:DisabledJobs = @()
$script:ManagedJobInventory = @()
$script:VeeamServices = @()
$script:NatsStateCaptured = $false
$script:NatsWasRunning = $false
$script:NatsStartupType = $null
$script:PgServiceName = $null
$script:PgStartupType = $null
$script:StaleEnterpriseManagerKey = $null
# How long to let Veeam services reach their recorded state. VBR 13's Backup
# Service can take minutes because it starts and waits on the Identity Service as
# a child process, so the Windows 30-second service-start timeout fires first.
$script:ServiceSettleMinutes = 10
$script:Vb365MaintenanceSessionId = $null
$script:Vb365MaintenancePending = $false
$script:RecoveryState = $null
$script:RollbackProblems = @()
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
    NatsInstalled  = ''
    NatsTarget     = ''
    NatsStatus     = ''
    NatsDetail     = ''
    StaleEmRecord  = ''
    Stage          = 'UNTOUCHED'
    Outcome        = 'UNKNOWN'
    ExitCode       = $null
    RebootRequired = $false
    RebootScheduledAt = ''
    IssueCode      = ''
    ActionRequired = ''
    JobsLeftDisabled = ''
    UnhealthyServices = ''
    ServicesStarted = ''
    ConsolesClosed = ''
    Vb365SyncStuck = ''
    RecoveryRunDir = ''
    Detail         = ''
    LogPath        = ''
}

# Collapse whitespace and cap length. Veeam can throw multi-kilobyte dependency
# errors; one of those in the single-line RMM summary makes the whole result
# unreadable in an RMM console. The full text always stays in the transcript.
function Format-ShortText {
    param([string] $Text, [int] $MaxLength = 600)
    if (-not $Text) { return '' }
    $flat = ($Text -replace '\s+', ' ').Trim()
    if ($flat.Length -le $MaxLength) { return $flat }
    return $flat.Substring(0, $MaxLength) + "... [truncated, full text in the log]"
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
    # SchemaVersion 1 is a PostgreSQL run, 2 a NATS run. The marker always matches the state.
    $schema = 1
    if ($script:RecoveryState.PSObject.Properties.Name -contains 'SchemaVersion') { $schema = [int]$script:RecoveryState.SchemaVersion }
    $marker = [ordered]@{
        SchemaVersion    = $schema
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

# Book a Windows restart a short time from now, so this run can finish and the RMM
# can collect its output first. Called only after a fully successful update. Once
# schedules are back on, VBR has no barrier that stops new work, so one last
# activity read is the guard: a running job or restore, an open Explorer (it can be
# running a restore), or an activity read that fails means no restart is booked.
# An open console does not block; Windows closes it at restart.
# Cancel a booked restart with: shutdown /a
function Invoke-DelayedReboot {
    param(
        [Parameter(Mandatory)][ValidateRange(30, 3600)][int] $DelaySeconds,
        [bool] $Vbr,
        [bool] $Vb365
    )
    $busy = @()
    try { $busy = @(Get-ActiveVeeamWork -Vbr $Vbr -Vb365 $Vb365) }
    catch {
        return [pscustomobject]@{ Scheduled = $false; At = $null; Reason = "the last Veeam activity check failed: $(Format-ShortText $_.Exception.Message 300)" }
    }
    $blocking = @($busy | Where-Object { "$_" -notlike 'UI:Veeam.Backup.Shell:PID*' -and "$_" -notlike 'UI:Veeam.Archiver.Shell:PID*' })
    if ($blocking.Count -gt 0) {
        return [pscustomobject]@{ Scheduled = $false; At = $null; Reason = "Veeam work started after the jobs were turned back on ($($blocking -join ', '))" }
    }
    $shutdownExe = Join-Path $env:SystemRoot 'System32\shutdown.exe'
    $comment = 'Veeam PostgreSQL and NATS Update: restart after the PostgreSQL update, as Veeam recommends. Cancel with: shutdown /a'
    # /d p:4:1 records a planned application-maintenance restart in the event log.
    # Invoke-Native can only throw before shutdown.exe runs (for example when an
    # application-control policy blocks it), so no restart was booked then.
    try { $booked = Invoke-Native $shutdownExe @('/r', '/t', "$DelaySeconds", '/d', 'p:4:1', '/c', $comment) }
    catch {
        return [pscustomobject]@{ Scheduled = $false; At = $null; Reason = "shutdown.exe could not be started: $(Format-ShortText $_.Exception.Message 300)" }
    }
    if ($booked.ExitCode -ne 0) {
        return [pscustomobject]@{ Scheduled = $false; At = $null; Reason = "shutdown.exe returned $($booked.ExitCode): $(Format-ShortText "$($booked.StdErr) $($booked.StdOut)" 300)" }
    }
    return [pscustomobject]@{ Scheduled = $true; At = (Get-Date).AddSeconds($DelaySeconds); Reason = '' }
}

function Get-RmmActionForExitCode {
    param([int] $Code)
    switch ($Code) {
        0  { return 'None' }
        5  { return 'Schedule an -Install run for the update named in Detail (the latest same-major PostgreSQL minor, or a same-line NATS update on VB365).' }
        6  { return 'Schedule and verify a server reboot.' }
        7  { return 'Open or maintain a PostgreSQL major-version migration ticket; this branch is EOL.' }
        8  { return 'Schedule and verify a reboot, and open or maintain a PostgreSQL major-version migration ticket.' }
        9  { return 'Schedule the minor update, and open or maintain a PostgreSQL major-version migration ticket.' }
        10 { return 'Retry this script later; no forced job termination was attempted.' }
        11 { return 'Handle this unsupported or excluded topology manually.' }
        20 { return 'Investigate the preflight failure before retrying.' }
        30 { return 'Investigate the download and its check (EnterpriseDB page and signature for PostgreSQL, pinned SHA256 for NATS).' }
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

# Export a .reg backup, verify it, then delete the key. Callers must already have
# proven the record is stale; this helper only refuses to delete without a backup.
function Remove-StaleVeeamRegistryRecord {
    param(
        [Parameter(Mandatory)][string] $Key,
        [Parameter(Mandatory)][string] $BackupPath
    )
    if (-not (Test-Path -LiteralPath $Key)) { throw "$Key does not exist" }
    $nativeKey = $Key -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
    if ($nativeKey -notmatch '^HKEY_(LOCAL_MACHINE|CURRENT_USER)\\.+') { throw "unsupported registry path: $Key" }
    if (Test-Path -LiteralPath $BackupPath) { Remove-Item -LiteralPath $BackupPath -Force -ErrorAction Stop }
    $export = Invoke-Native (Join-Path $env:SystemRoot 'System32\reg.exe') @('export', $nativeKey, $BackupPath, '/y')
    if ($export.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $BackupPath) -or (Get-Item -LiteralPath $BackupPath).Length -eq 0) {
        throw "could not export a verified .reg backup to $BackupPath (exit $($export.ExitCode)) $($export.StdErr)"
    }
    Remove-Item -LiteralPath $Key -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $Key) { throw "$Key still exists after the removal request" }
    return $BackupPath
}

function Get-VeeamServiceState {
    $result = @()
    foreach ($svc in @(Get-Service -Name 'Veeam*' -ErrorAction Stop)) {
        if ("$($svc.Status)" -notin @('Running','Stopped')) {
            throw "Service $($svc.Name) is $($svc.Status); wait for it to become Running or Stopped before updating"
        }
        # Windows itself records the order. On VBR 13, for example, VeeamBackupSvc
        # depends on no other Veeam service, several services depend on it, and
        # VeeamWebSvc also depends on VeeamBackupRESTSvc. Capture that instead of hardcoding a list,
        # so each build and product mix is started in its own correct order.
        $dependsOn = @()
        try { $dependsOn = @($svc.ServicesDependedOn | ForEach-Object { "$($_.Name)" } | Where-Object { $_ }) } catch {}
        $result += [pscustomobject]@{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            Status      = "$($svc.Status)"
            WasRunning  = ($svc.Status -eq 'Running')
            StartupType = Get-ServiceStartupTypeExact $svc.Name
            DependsOn   = $dependsOn
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

# Order the services to start so that each one's Veeam dependencies go first.
# Dependencies come from Windows itself (ServicesDependedOn), captured per server.
# Services with no Veeam dependency keep their original relative order, so the
# result is stable. Anything left in a cycle, or depending on something outside
# the snapshot, is returned last rather than dropped.
function Get-VeeamServiceStartOrder {
    param([Parameter(Mandatory)] $Services)
    $records = @($Services)
    $names = @($records | ForEach-Object { "$($_.Name)" })
    $ordered = @()
    $startedNames = @{}
    $remaining = @($records)

    while ($remaining.Count -gt 0) {
        $ready = @()
        foreach ($rec in $remaining) {
            $deps = @()
            try { $deps = @($rec.DependsOn | Where-Object { $_ }) } catch {}
            # Only dependencies that are themselves in this snapshot can be waited
            # for. Windows handles RpcSs, Winmgmt and friends on its own.
            $veeamDeps = @($deps | Where-Object { $names -contains "$_" -and -not $startedNames.ContainsKey("$_") })
            if ($veeamDeps.Count -eq 0) { $ready += $rec }
        }
        if ($ready.Count -eq 0) {
            # A cycle or an unresolvable dependency. Append the rest unchanged.
            $ordered += $remaining
            break
        }
        foreach ($rec in $ready) { $startedNames["$($rec.Name)"] = $true }
        $ordered += $ready
        $readyNames = @($ready | ForEach-Object { "$($_.Name)" })
        $remaining = @($remaining | Where-Object { $readyNames -notcontains "$($_.Name)" })
    }
    return $ordered
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

    foreach ($rec in @(Get-VeeamServiceStartOrder $script:VeeamServices)) {
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
    #
    # VBR 13's Veeam Backup Service starts the Identity Service as a CHILD PROCESS
    # and waits for it inside its own OnStart, which can overrun the Windows
    # 30-second service-start timeout by minutes. Start-Service can therefore throw
    # while the service is in fact coming up, so wait on the real final state.
    # Read defensively: the tests exercise this function on its own, where the
    # script-scope setting does not exist and StrictMode would make reading it fatal.
    $settleMinutes = Get-Variable -Name ServiceSettleMinutes -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not $settleMinutes) { $settleMinutes = 10 }
    $settleDeadline = (Get-Date).AddMinutes($settleMinutes)
    $lastProgressLog = Get-Date
    while ($true) {
        $pending = @()
        foreach ($rec in @($script:VeeamServices)) {
            $svc = Get-Service -Name $rec.Name -ErrorAction SilentlyContinue
            if (-not $svc) { $pending += $rec.Name; continue }
            if ($rec.WasRunning -and "$($svc.Status)" -ne 'Running') { $pending += $rec.Name }
            if (-not $rec.WasRunning -and $AllowStops -and "$($svc.Status)" -ne 'Stopped') { $pending += $rec.Name }
            if (-not $rec.WasRunning -and -not $AllowStops -and "$($svc.Status)" -notin @('Running','Stopped')) { $pending += $rec.Name }
        }
        if ($pending.Count -eq 0) { break }
        if ((Get-Date) -ge $settleDeadline) {
            Write-Log "Still waiting after $settleMinutes minutes: $($pending -join ', '). Verification below decides the outcome." WARN
            break
        }
        if (((Get-Date) - $lastProgressLog).TotalSeconds -ge 30) {
            Write-Log "  waiting for $($pending.Count) service(s) to settle: $($pending -join ', ')"
            $lastProgressLog = Get-Date
        }
        Start-Sleep -Seconds 5
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

# Start every Veeam service that is set to start automatically but is stopped, and
# return the names that reached Running. Called only after the configuration
# backup has failed. A stopped Veeam Installer Service (VeeamDeploySvc) breaks every
# connection to a managed server, the backup server's own repositories included,
# and starting it is what VBR itself tries when it finds it stopped (KB2263).
# Services started here are left running: their startup type says they belong
# running, and the STEP 15 snapshot then records them as running.
function Start-StoppedAutomaticVeeamServices {
    param([ValidateRange(5,600)][int] $TimeoutSeconds = 120)
    $candidates = @()
    foreach ($svc in @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue)) {
        if ("$($svc.Status)" -ne 'Stopped') { continue }
        $startup = ''
        try { $startup = Get-ServiceStartupTypeExact $svc.Name } catch {}
        if ("$startup" -like 'Automatic*') { $candidates += "$($svc.Name)" }
    }
    if ($candidates.Count -eq 0) { return @() }
    foreach ($name in $candidates) {
        Write-Log "  starting $name (set to start automatically, but stopped)"
        # Start-Service can throw while a slow service is in fact still coming up,
        # so the state read below decides, not this call.
        try { Start-Service -Name $name -ErrorAction Stop }
        catch { Write-Log "  Start-Service $name reported: $(Format-ShortText $_.Exception.Message 300)" WARN }
    }
    $running = @()
    $polls = [int][math]::Ceiling($TimeoutSeconds / 5)
    for ($poll = 0; $poll -le $polls; $poll++) {
        $running = @($candidates | Where-Object {
            $current = @(Get-Service -Name $_ -ErrorAction SilentlyContinue)
            $current.Count -gt 0 -and "$($current[0].Status)" -eq 'Running'
        })
        if ($running.Count -eq $candidates.Count -or $poll -eq $polls) { break }
        Start-Sleep -Seconds 5
    }
    foreach ($name in $candidates) {
        if ($running -contains $name) { Write-Log "  $name is Running" OK }
        else { Write-Log "  $name did not reach Running within ${TimeoutSeconds}s" WARN }
    }
    return @($running)
}

# Run the VBR configuration backup once and judge the session it returns, not the
# job's historical LastResult. LastRun can be EMPTY on VBR 12 and 13 builds, so it
# cannot prove a result is fresh; the returned session carries Result for THIS run.
# Without -RunAsync the cmdlet returns once the session has finished.
function Invoke-VbrConfigBackupAttempt {
    $attempt = [pscustomobject]@{ Session=$null; Result=''; Reasons=@(); Error=''; ConnectionLost=$false; Seconds=0; LastRun=$null }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $configSession = $null
    try {
        $configSession = Start-VBRConfigurationBackupJob -ErrorAction Stop
    } catch {
        $attempt.Error = "$($_.Exception.Message)"
        # Any throw is a failure, even one with no message. Never fall through to
        # the job's historical LastResult on a run that did not take a backup.
        if (-not $attempt.Error) { $attempt.Error = "Start-VBRConfigurationBackupJob threw $($_.Exception.GetType().FullName) with no message" }
        $attempt.ConnectionLost = [bool](Test-VbrConnectionLostError $_)
    }
    $attempt.Seconds = [int][math]::Round($timer.Elapsed.TotalSeconds)
    if ($attempt.Error) { return $attempt }
    $attempt.Session = $configSession

    $sessionResult = "$(Get-CfgValue $configSession 'Result' '')"
    $jobResult = ''
    try {
        $cfgJobAfter = Get-VBRConfigurationBackupJob -ErrorAction Stop
        $jobResult = "$(Get-CfgValue $cfgJobAfter 'LastResult' '')"
        $attempt.LastRun = Get-CfgValue $cfgJobAfter 'LastRun' $null
    } catch {}
    if ($sessionResult) {
        if ($jobResult -and $jobResult -ne $sessionResult) {
            Write-Log "The configuration backup session this run started reports '$sessionResult' while the job's LastResult reads '$jobResult'. Trusting the session." WARN
        }
        $attempt.Result = $sessionResult
    } else {
        $attempt.Result = $jobResult
    }

    if ($attempt.Result -eq 'Failed') {
        # Say why, so an operator does not have to go hunting in the console. The
        # session log holds the real reason, for example an unavailable repository.
        $reasons = @()
        try {
            foreach ($record in @($configSession.Logger.GetLog().UpdatedRecords)) {
                if ("$($record.Status)" -match 'Failed|Error') { $reasons += "$($record.Title)" }
            }
        } catch {}
        $attempt.Reasons = @($reasons)
    }
    return $attempt
}

# ---------------------------------------------------------------------------
# NATS (VB365 only)
#
# VB365 8 keeps its job queue in a NATS server, the nats-server Windows service.
# A VB365 upgrade never updates NATS; Veeam leaves that to the customer (KB4742):
#   https://www.veeam.com/kb4742
# Veeam supports an exact list of NATS versions per VB365 release, not a range:
#   https://helpcenter.veeam.com/docs/vbo365/guide/vbo_system_requirements.html
# Like PostgreSQL, this is an UPDATE, never an upgrade: NATS only moves to a newer
# version that Veeam lists on the SAME 2.x line (2.10.22 -> 2.10.28, never 2.10 ->
# 2.12), so the message store format stays the same and the old version can go back.
# ---------------------------------------------------------------------------

# The NATS versions Veeam supports per VB365 release, and the SHA256 of every package
# this script may install. NATS publishes no signature, so the pinned hash is the only
# proof a download is genuine. Add a version only after Veeam lists it, with the hash
# from that release's SHA256SUMS file: https://github.com/nats-io/nats-server/releases
function Get-NatsPolicy {
    return [pscustomobject]@{
        SupportedByVb365 = @{
            '8.6' = @('2.10.18','2.10.22','2.10.28','2.12.5','2.12.8')
        }
        PackageSha256 = @{
            '2.10.28' = '98b8571231b00ebe0445cc7f317f6425c1fbc2edecd455949d37022e04281657'
            '2.12.8'  = '61836ff8d0cecbb773faf7daa22f5212b7ed3ab5a0c58c12b013d67d64edd6cc'
        }
    }
}

# Veeam.Archiver.Service.exe on VB365 8.6 reports its version as 13.6.x. A release
# that is not named here gets no NATS changes until its supported list is added.
function Get-Vb365ReleaseKey {
    param([AllowEmptyString()][string] $ProductVersion)
    if ("$ProductVersion" -match '^(?:13\.6|8\.6)(?:\.|$)') { return '8.6' }
    return ''
}

# Pick the update for an installed NATS version: the newest version Veeam lists on the
# same major.minor line that is newer than the installed one and has a pinned hash.
# Never a different line, and never older.
function Resolve-NatsTarget {
    param(
        [Parameter(Mandatory)][string] $Installed,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $Supported,
        [Parameter(Mandatory)][hashtable] $PackageSha256
    )
    $have = [version]$Installed
    $line = '{0}.{1}' -f $have.Major, $have.Minor
    $sameLine = @($Supported | ForEach-Object { [version]$_ } |
        Where-Object { $_.Major -eq $have.Major -and $_.Minor -eq $have.Minor } | Sort-Object)
    $newer = @($sameLine | Where-Object { $_ -gt $have })
    $pinned = @($newer | Where-Object { $PackageSha256.ContainsKey("$_") })
    if ($pinned.Count -gt 0) {
        $to = "$($pinned[$pinned.Count - 1])"
        return [pscustomobject]@{ Status='UPDATE_AVAILABLE'; Target=$to; Sha256="$($PackageSha256[$to])".ToLowerInvariant()
            Detail="NATS $Installed -> $to is available (same $line line, on Veeam's supported list)." }
    }
    if ($newer.Count -gt 0) {
        return [pscustomobject]@{ Status='UNPINNED'; Target="$($newer[$newer.Count - 1])"; Sha256=''
            Detail="Veeam lists NATS $($newer[$newer.Count - 1]), but this script has no pinned SHA256 for it, so NATS $Installed is left alone. Add it to Get-NatsPolicy." }
    }
    $listed = @($sameLine | Where-Object { $_ -eq $have }).Count -gt 0
    if ($listed) {
        return [pscustomobject]@{ Status='CURRENT'; Target=''; Sha256=''; Detail="NATS $Installed is the newest version Veeam lists on the $line line." }
    }
    if ($sameLine.Count -gt 0 -and $have -gt $sameLine[$sameLine.Count - 1]) {
        return [pscustomobject]@{ Status='AHEAD'; Target=''; Sha256=''
            Detail="NATS $Installed is newer than the newest version Veeam lists on the $line line ($($sameLine[$sameLine.Count - 1])). Left alone: NATS is never downgraded." }
    }
    return [pscustomobject]@{ Status='UNLISTED'; Target=''; Sha256=''
        Detail="NATS $Installed is not on Veeam's supported list, and Veeam lists no newer $line version to update to. Left alone: moving to another line is an upgrade, which this script never does." }
}

# Read the nats-server service command line. VB365 and KB4742 run
#   "C:\Program Files\NATS\nats-server-v<x.y.z>-windows-amd64\nats-server.exe" -c "<conf>"
# Anything else is refused, not guessed: another argument could move the message
# store or the port away from what this script backs up and checks.
function ConvertFrom-NatsImagePath {
    param([Parameter(Mandatory)][string] $PathName, [Parameter(Mandatory)][string] $NatsRoot)
    $text = $PathName.Trim()
    if ($text -match '^"(?<exe>[^"]+)"(?<rest>.*)$') {
        $exe = $Matches['exe']; $rest = $Matches['rest']
    } elseif ($text -match '^(?<exe>[^"]+?\.exe)(?<rest>(?:\s.*)?)$') {
        $exe = $Matches['exe']; $rest = $Matches['rest']
    } else {
        throw 'the service command line does not start with an .exe path'
    }
    $exe = [Environment]::ExpandEnvironmentVariables($exe)
    if ([IO.Path]::GetFileName($exe) -ine 'nats-server.exe') {
        throw "the service runs $([IO.Path]::GetFileName($exe)), not nats-server.exe"
    }
    if (-not [IO.Path]::IsPathRooted($exe)) { throw "the service runs a relative path: $exe" }
    $exeFull = [IO.Path]::GetFullPath($exe)
    $folder = [IO.Path]::GetDirectoryName($exeFull)
    $rootFull = [IO.Path]::GetFullPath($NatsRoot).TrimEnd('\')
    if ("$([IO.Path]::GetDirectoryName($folder))".TrimEnd('\') -ine $rootFull) {
        throw "nats-server.exe is at $exeFull, not in a version folder directly under $rootFull"
    }
    $m = [regex]::Match($rest.Trim(), '^(?:-c|--config)(?:\s+|=)(?:"(?<conf>[^"]+)"|(?<conf>[^\s"]+))$')
    if (-not $m.Success) {
        # Name the flags only. A value could be a credential.
        $flags = @([regex]::Matches($rest, '(?:^|\s)(-{1,2}[A-Za-z][\w-]*)') | ForEach-Object { $_.Groups[1].Value })
        $found = if ($flags.Count -gt 0) { $flags -join ' ' } else { 'none' }
        throw "the service arguments are not exactly -c <config file> (flags found: $found)"
    }
    $conf = [Environment]::ExpandEnvironmentVariables($m.Groups['conf'].Value)
    if ($conf -notmatch '^[A-Za-z]:\\') { throw "the config file is not a local absolute path: $conf" }
    $folderVersion = ''
    if ([IO.Path]::GetFileName($folder) -match '^nats-server-v(\d+\.\d+\.\d+)-windows-amd64$') { $folderVersion = $Matches[1] }
    return [pscustomobject]@{
        Exe           = $exeFull
        Folder        = $folder
        ConfPath      = [IO.Path]::GetFullPath($conf)
        Arguments     = $rest
        FolderVersion = $folderVersion
    }
}

# 'nats-server --version' prints "nats-server: vX.Y.Z". It is read before any config.
function ConvertFrom-NatsVersionText {
    param([AllowEmptyString()][string] $Text)
    $m = [regex]::Match("$Text", '(?m)^\s*nats-server:\s+v(?<v>\d+\.\d+\.\d+)\s*$')
    if ($m.Success) { return $m.Groups['v'].Value }
    return ''
}

# Split a nats-server.conf into its settings: "key: value", "key = value" or
# "key value", { } blocks, [ ] lists, and # or // comments. Returns every setting
# with its block path. Never log what this reads: the file holds the NATS credentials.
function Read-NatsConfText {
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Text)
    $entries = New-Object System.Collections.Generic.List[object]
    $blocks = New-Object System.Collections.Generic.List[string]
    $n = $Text.Length
    $i = 0
    while ($i -lt $n) {
        $c = $Text[$i]
        if ([char]::IsWhiteSpace($c) -or $c -eq ',' -or $c -eq ';') { $i++; continue }
        if ($c -eq '#' -or ($c -eq '/' -and $i + 1 -lt $n -and $Text[$i + 1] -eq '/')) {
            while ($i -lt $n -and $Text[$i] -ne "`n") { $i++ }
            continue
        }
        if ($c -eq '}') {
            if ($blocks.Count -eq 0) { throw "unbalanced '}' at character $i" }
            $blocks.RemoveAt($blocks.Count - 1)
            $i++
            continue
        }
        if ($c -eq '{' -or $c -eq '[' -or $c -eq ']' -or $c -eq ':' -or $c -eq '=') {
            throw "unexpected '$c' at character $i"
        }

        # The key.
        $key = ''
        if ($c -eq '"' -or $c -eq "'") {
            $quote = $c; $start = $i + 1; $i = $start
            while ($i -lt $n -and $Text[$i] -ne $quote) { $i++ }
            if ($i -ge $n) { throw 'unterminated quoted key' }
            $key = $Text.Substring($start, $i - $start)
            $i++
        } else {
            $start = $i
            while ($i -lt $n -and -not [char]::IsWhiteSpace($Text[$i]) -and ':={}[],;'.IndexOf($Text[$i]) -lt 0) { $i++ }
            $key = $Text.Substring($start, $i - $start)
        }
        while ($i -lt $n -and ($Text[$i] -eq ' ' -or $Text[$i] -eq "`t")) { $i++ }
        if ($i -lt $n -and ($Text[$i] -eq ':' -or $Text[$i] -eq '=')) {
            $i++
            while ($i -lt $n -and ($Text[$i] -eq ' ' -or $Text[$i] -eq "`t")) { $i++ }
        }
        $path = (@($blocks) + @($key)) -join '.'
        $depth = $blocks.Count

        # The value.
        if ($i -ge $n -or $Text[$i] -eq "`r" -or $Text[$i] -eq "`n") {
            $entries.Add([pscustomobject]@{ Depth=$depth; Path=$path; Key=$key; Value=''; Kind='None' })
            continue
        }
        $v = $Text[$i]
        if ($v -eq '{') {
            $entries.Add([pscustomobject]@{ Depth=$depth; Path=$path; Key=$key; Value=''; Kind='Block' })
            $blocks.Add($key)
            $i++
            continue
        }
        if ($v -eq '[') {
            # Skip the whole list. Nothing this script reads lives inside one.
            $level = 0
            while ($i -lt $n) {
                $d = $Text[$i]
                if ($d -eq '"' -or $d -eq "'") {
                    $i++
                    while ($i -lt $n -and $Text[$i] -ne $d) { if ($d -eq '"' -and $Text[$i] -eq '\') { $i++ }; $i++ }
                } elseif ($d -eq '#' -or ($d -eq '/' -and $i + 1 -lt $n -and $Text[$i + 1] -eq '/')) {
                    while ($i -lt $n -and $Text[$i] -ne "`n") { $i++ }
                    continue
                } elseif ($d -eq '[' -or $d -eq '{') { $level++ }
                elseif ($d -eq ']' -or $d -eq '}') { $level--; if ($level -eq 0) { $i++; break } }
                $i++
            }
            if ($level -ne 0) { throw "unbalanced list in '$key'" }
            $entries.Add([pscustomobject]@{ Depth=$depth; Path=$path; Key=$key; Value=''; Kind='List' })
            continue
        }
        if ($v -eq '"' -or $v -eq "'") {
            $sb = New-Object System.Text.StringBuilder
            $i++
            $closed = $false
            while ($i -lt $n) {
                $d = $Text[$i]
                if ($d -eq $v) { $closed = $true; $i++; break }
                if ($v -eq '"' -and $d -eq '\' -and $i + 1 -lt $n) {
                    $e = $Text[$i + 1]
                    switch -CaseSensitive ("$e") {
                        '\' { [void]$sb.Append('\') }
                        '"' { [void]$sb.Append('"') }
                        't' { [void]$sb.Append("`t") }
                        'n' { [void]$sb.Append("`n") }
                        'r' { [void]$sb.Append("`r") }
                        default { [void]$sb.Append('\').Append($e) }
                    }
                    $i += 2
                    continue
                }
                [void]$sb.Append($d)
                $i++
            }
            if (-not $closed) { throw "unterminated quoted value for '$key'" }
            $entries.Add([pscustomobject]@{ Depth=$depth; Path=$path; Key=$key; Value=$sb.ToString(); Kind='String' })
            continue
        }
        $start = $i
        while ($i -lt $n -and "`r`n,;}]".IndexOf($Text[$i]) -lt 0) {
            if ($Text[$i] -eq '#' -and $i -gt $start -and [char]::IsWhiteSpace($Text[$i - 1])) { break }
            $i++
        }
        $entries.Add([pscustomobject]@{ Depth=$depth; Path=$path; Key=$key; Value=$Text.Substring($start, $i - $start).Trim(); Kind='Bare' })
        if ($i -lt $n -and $Text[$i] -eq '#') {
            while ($i -lt $n -and $Text[$i] -ne "`n") { $i++ }
        }
    }
    if ($blocks.Count -ne 0) { throw "unbalanced '{' in block '$($blocks[$blocks.Count - 1])'" }
    return $entries.ToArray()
}

# The facts this script relies on from nats-server.conf. A setting that could put the
# store, the port or the clients somewhere this script does not check is refused.
function Get-NatsConfFacts {
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Text)
    $entries = @(Read-NatsConfText $Text)
    $stores = @($entries | Where-Object { $_.Key -in @('store_dir','storedir') } | ForEach-Object { "$($_.Value)" })
    $refused = @()
    if (@($entries | Where-Object { $_.Key -eq 'include' }).Count -gt 0) { $refused += 'include' }
    $refused += @($entries | Where-Object { $_.Depth -eq 0 -and $_.Key -in @('cluster','gateway','gateways','leafnodes','leaf') } | ForEach-Object { "$($_.Key)".ToLowerInvariant() })

    $port = 0
    $listenHost = ''
    $portEntry = @($entries | Where-Object { $_.Depth -eq 0 -and $_.Key -eq 'port' })
    $listenEntry = @($entries | Where-Object { $_.Depth -eq 0 -and $_.Key -eq 'listen' })
    $hostEntry = @($entries | Where-Object { $_.Depth -eq 0 -and $_.Key -in @('host','net') })
    if ($portEntry.Count -gt 1 -or $listenEntry.Count -gt 1 -or $hostEntry.Count -gt 1) { $refused += 'repeated port, listen or host' }
    if ($portEntry.Count -ge 1) {
        if ("$($portEntry[0].Value)" -notmatch '^\d{1,5}$') { throw "port '$($portEntry[0].Value)' is not a number" }
        $port = [int]$portEntry[0].Value
    }
    if ($listenEntry.Count -ge 1) {
        $listen = "$($listenEntry[0].Value)"
        if ($listen -match '^(?<h>\[[^\]]*\]|[^:]*):(?<p>\d{1,5})$') {
            $listenHost = $Matches['h'].Trim('[',']')
            if ($port -gt 0 -and $port -ne [int]$Matches['p']) { $refused += 'port and listen disagree' }
            $port = [int]$Matches['p']
        } elseif ($listen -match '^\d{1,5}$') {
            $port = [int]$listen
        } else {
            throw "listen '$listen' is not host:port"
        }
    }
    if ($hostEntry.Count -ge 1 -and -not $listenHost) { $listenHost = "$($hostEntry[0].Value)" }
    if ($port -eq 0) { $port = 4222 }
    if ($port -lt 1 -or $port -gt 65535) { throw "port $port is out of range" }
    $probeHost = if (-not $listenHost -or $listenHost -in @('0.0.0.0','::','*')) { '127.0.0.1' } else { $listenHost }
    return [pscustomobject]@{ StoreDirs=$stores; Refused=@($refused | Sort-Object -Unique); Port=$port; ListenHost=$listenHost; ProbeHost=$probeHost }
}

# VB365 reaches NATS through JetStreamConnectionString in Config.xml and Proxy.xml:
#   nats://admin:<encrypted>@<host>:4222?passwordEncrypted
# Only the host and port are returned. Never log or return the string itself.
function ConvertFrom-NatsConnectionString {
    param([Parameter(Mandatory)][string] $ConnectionString)
    # A comma means a list of servers, which this single-server profile does not support.
    if ($ConnectionString.IndexOf(',') -ge 0) { throw 'it names more than one NATS server' }
    $m = [regex]::Match($ConnectionString.Trim(), '^(?i:nats|tls)://(?:.*@)?(?<host>\[[^\]]+\]|[^:/?#@\[\],\s]+)(?::(?<port>\d{1,5}))?(?:[/?#][^,]*)?$')
    if (-not $m.Success) { throw 'it is not a single nats://host:port address' }
    $port = if ($m.Groups['port'].Success) { [int]$m.Groups['port'].Value } else { 4222 }
    if ($port -lt 1 -or $port -gt 65535) { throw "its port $port is out of range" }
    return [pscustomobject]@{ Host=$m.Groups['host'].Value.Trim('[',']'); Port=$port }
}

# The first line a NATS server sends on a new client connection is INFO {...} with
# its "version". That is the version clients really get.
function ConvertFrom-NatsInfoLine {
    param([AllowEmptyString()][string] $Line)
    if ("$Line" -notmatch '^INFO\s+(?<json>\{.*\})\s*$') { return '' }
    try { $info = $Matches['json'] | ConvertFrom-Json -ErrorAction Stop } catch { return '' }
    $version = "$(Get-CfgValue $info 'version' '')"
    if ($version -match '^\d+\.\d+\.\d+$') { return $version }
    return ''
}

function Get-NatsInfoVersion {
    param([Parameter(Mandatory)][string] $HostName, [Parameter(Mandatory)][int] $Port, [int] $TimeoutMs = 5000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMs)) { return '' }
        $client.EndConnect($connect)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs
        $buffer = New-Object byte[] 4096
        $text = ''
        while ($text.IndexOf("`n") -lt 0 -and $text.Length -lt 65536) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $text += [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        }
        return (ConvertFrom-NatsInfoLine (($text -split "`r?`n")[0]))
    } catch {
        return ''
    } finally {
        $client.Close()
    }
}

# Poll until NATS answers with the expected version, for a NATS that is starting.
function Wait-NatsInfoVersion {
    param([Parameter(Mandatory)][string] $HostName, [Parameter(Mandatory)][int] $Port, [Parameter(Mandatory)][string] $Expected, [int] $Seconds = 60)
    $seen = ''
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ($true) {
        $seen = Get-NatsInfoVersion -HostName $HostName -Port $Port
        if ($seen -eq $Expected -or (Get-Date) -ge $deadline) { break }
        Start-Sleep -Seconds 3
    }
    return $seen
}

# Established connections on the NATS client port. RemoteAddresses: clients on other
# machines; this profile supports a single server only, so they block the update.
# Vb365Processes: Veeam.Archiver processes on this server connected as clients.
function Get-NatsClientSummary {
    param([Parameter(Mandatory)][int] $Port)
    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { throw 'Get-NetTCPConnection is unavailable' }
    $rows = @()
    foreach ($side in @('LocalPort','RemotePort')) {
        $query = @{ State = 'Established'; ErrorAction = 'Stop' }
        $query[$side] = $Port
        try {
            $rows += @(Get-NetTCPConnection @query | ForEach-Object {
                [pscustomobject]@{ Side=$side; RemoteAddress=("$($_.RemoteAddress)" -replace '^::ffff:', ''); OwningProcess=[int]$_.OwningProcess }
            })
        } catch {
            # No connection at all is reported as "not found", not as an empty list.
            if ("$($_.CategoryInfo.Category)" -ne 'ObjectNotFound') { throw }
        }
    }
    $remote = @($rows | Where-Object { $_.Side -eq 'LocalPort' -and -not (Test-LocalDbHost $_.RemoteAddress) } |
        ForEach-Object { $_.RemoteAddress } | Sort-Object -Unique)
    $vb365 = @($rows | Where-Object { $_.Side -eq 'RemotePort' -and (Test-LocalDbHost $_.RemoteAddress) } | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($process -and "$($process.ProcessName)" -match '^Veeam\.Archiver\.') { "$($process.ProcessName)" }
    } | Sort-Object -Unique)
    return [pscustomobject]@{ RemoteAddresses=$remote; Vb365Processes=$vb365 }
}

# A store path the rollback may mirror back into must be a real data folder, never a
# drive root, a system folder, or anything that holds this script's own evidence.
function Test-NatsStorePathSafe {
    param([Parameter(Mandatory)][string] $StoreDir, [Parameter(Mandatory)][string] $WorkRoot, [string] $NatsRoot = '')
    try {
        if ($StoreDir -notmatch '^[A-Za-z]:\\') { return $false }
        $full = [IO.Path]::GetFullPath($StoreDir).TrimEnd('\')
        if (@($full.Substring(3) -split '\\' | Where-Object { $_ }).Count -lt 2) { return $false }
        $protected = @($WorkRoot, $env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, $env:USERPROFILE, $NatsRoot) | Where-Object { $_ }
        foreach ($path in $protected) {
            $other = [IO.Path]::GetFullPath($path).TrimEnd('\')
            # The store may live under ProgramData or Program Files, but never be one of
            # them, contain one of them, or overlap WorkRoot or the NATS binaries.
            if ($full -ieq $other) { return $false }
            if ($other.StartsWith("$full\", [StringComparison]::OrdinalIgnoreCase)) { return $false }
        }
        if (Test-PathTreeOverlap $full $WorkRoot) { return $false }
        if ($NatsRoot -and (Test-PathTreeOverlap $full $NatsRoot)) { return $false }
        return $true
    } catch { return $false }
}

# The release zip is nats-server-v<x.y.z>-windows-amd64/ with nats-server.exe in it.
# Only that one file is ever extracted, to a fixed name, so no entry name is used as a
# path. Still refuse a package with a climbing, rooted or foreign-folder entry.
function Test-NatsZipEntryNames {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]] $Names, [Parameter(Mandatory)][string] $Version)
    $prefix = "nats-server-v$Version-windows-amd64/"
    if ($Names.Count -eq 0) { return 'the package is empty' }
    foreach ($name in $Names) {
        if ($name -match '\\' -or $name -match '(^|/)\.\.(/|$)' -or $name -match '^/' -or $name -match '^[A-Za-z]:') { return "the package has an unsafe entry name '$name'" }
        if (-not $name.StartsWith($prefix, [StringComparison]::Ordinal)) { return "the package has an entry outside $prefix ('$name')" }
    }
    if (@($Names | Where-Object { $_ -ceq "${prefix}nats-server.exe" }).Count -ne 1) { return "the package does not hold exactly one ${prefix}nats-server.exe" }
    return ''
}

function Expand-NatsPackage {
    param([Parameter(Mandatory)][string] $ZipPath, [Parameter(Mandatory)][string] $Version, [Parameter(Mandatory)][string] $Destination)
    # Windows PowerShell 5.1 does not load the zip classes by itself.
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $names = @($zip.Entries | ForEach-Object { $_.FullName })
        $problem = Test-NatsZipEntryNames -Names $names -Version $Version
        if ($problem) { throw $problem }
        $entry = @($zip.Entries | Where-Object { $_.FullName -ceq "nats-server-v$Version-windows-amd64/nats-server.exe" })[0]
        if (Test-Path -LiteralPath $Destination) { throw "$Destination already exists" }
        New-Item -ItemType Directory -Path $Destination -ErrorAction Stop | Out-Null
        $exe = Join-Path $Destination 'nats-server.exe'
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $exe, $false)
        return $exe
    } finally {
        $zip.Dispose()
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

# Read-only. Works out what NATS this VB365 server runs, whether this script can
# update it safely, and the plan for doing so. Any doubt leaves NATS alone, with the
# reason in Detail; it never stops a PostgreSQL update.
function Get-NatsDiscovery {
    param(
        [AllowEmptyString()][string] $Vb365Version,
        $ConfigXml,
        $ProxyXml,
        [Parameter(Mandatory)][string] $WorkRoot,
        [bool] $UpdatesEnabled = $true,
        [string] $NatsRoot = (Join-Path $env:ProgramFiles 'NATS')
    )
    $result = [ordered]@{ Status=''; Installed=''; Target=''; Detail=''; Plan=$null }

    $service = $null
    try { $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='nats-server'" -ErrorAction Stop }
    catch { $result.Status = 'UNRECOGNISED_LAYOUT'; $result.Detail = "Could not read the nats-server service: $($_.Exception.Message)"; return [pscustomobject]$result }
    if (-not $service) {
        $result.Status = 'NOT_LOCAL'; $result.Detail = 'There is no nats-server service on this server, so NATS is not updated here.'
        return [pscustomobject]$result
    }

    try { $image = ConvertFrom-NatsImagePath -PathName "$($service.PathName)" -NatsRoot $NatsRoot }
    catch { $result.Status = 'UNRECOGNISED_LAYOUT'; $result.Detail = "NATS is not laid out the way VB365 installs it: $($_.Exception.Message)."; return [pscustomobject]$result }
    if (-not (Test-Path -LiteralPath $image.Exe -PathType Leaf) -or (Test-PathTreeHasReparsePoint -Path $image.Exe)) {
        $result.Status = 'UNRECOGNISED_LAYOUT'; $result.Detail = "The nats-server service points at $($image.Exe), which is missing or a reparse point."
        return [pscustomobject]$result
    }
    $versionRun = Invoke-Native $image.Exe @('--version')
    $installed = ConvertFrom-NatsVersionText "$($versionRun.StdOut)`n$($versionRun.StdErr)"
    if (-not $installed) {
        $result.Status = 'UNRECOGNISED_LAYOUT'; $result.Detail = "$($image.Exe) --version did not report a version (exit $($versionRun.ExitCode))."
        return [pscustomobject]$result
    }
    $result.Installed = $installed
    if ($image.FolderVersion -and $image.FolderVersion -ne $installed) {
        $result.Status = 'UNRECOGNISED_LAYOUT'; $result.Detail = "The folder says NATS $($image.FolderVersion), but the program reports $installed."
        return [pscustomobject]$result
    }
    if ("$($service.State)" -ne 'Running' -or "$($service.StartMode)" -eq 'Disabled') {
        $result.Status = 'NOT_RUNNING'; $result.Detail = "nats-server is $($service.State) (startup $($service.StartMode)). NATS is only updated while it is running normally."
        return [pscustomobject]$result
    }

    $release = Get-Vb365ReleaseKey $Vb365Version
    $policy = Get-NatsPolicy
    if (-not $release -or -not $policy.SupportedByVb365.ContainsKey($release)) {
        $result.Status = 'POLICY_UNKNOWN_VB365'; $result.Detail = "This script has no NATS support list for VB365 $Vb365Version, so NATS $installed is left alone."
        return [pscustomobject]$result
    }
    $choice = Resolve-NatsTarget -Installed $installed -Supported $policy.SupportedByVb365[$release] -PackageSha256 $policy.PackageSha256
    $result.Status = $choice.Status
    $result.Target = $choice.Target
    $result.Detail = $choice.Detail
    if ($choice.Status -ne 'UPDATE_AVAILABLE') { return [pscustomobject]$result }

    # An update is due. Prove everything the update and its rollback rely on, or refuse.
    $refuse = {
        param([string] $Why)
        $result.Status = 'UNRECOGNISED_LAYOUT'
        $result.Detail = "NATS $installed -> $($choice.Target) is due, but $Why NATS is left alone."
        return [pscustomobject]$result
    }
    if (-not (Test-Path -LiteralPath $image.ConfPath -PathType Leaf) -or (Test-PathTreeHasReparsePoint -Path $image.ConfPath)) {
        return (& $refuse "the config file $($image.ConfPath) is missing or a reparse point.")
    }
    try { $facts = Get-NatsConfFacts (Get-Content -LiteralPath $image.ConfPath -Raw -ErrorAction Stop) }
    catch { return (& $refuse "$($image.ConfPath) could not be read: $($_.Exception.Message).") }
    if ($facts.Refused.Count -gt 0) { return (& $refuse "$($image.ConfPath) uses $($facts.Refused -join ', '), which this single-server profile does not support.") }
    if ($facts.StoreDirs.Count -ne 1) { return (& $refuse "$($image.ConfPath) names $($facts.StoreDirs.Count) store_dir settings, not exactly one.") }
    $store = "$($facts.StoreDirs[0])" -replace '/', '\'
    if (-not (Test-NatsStorePathSafe -StoreDir $store -WorkRoot $WorkRoot -NatsRoot $NatsRoot)) {
        return (& $refuse "the message store $store is not a safe local data folder for this script, or it overlaps $WorkRoot.")
    }
    $store = [IO.Path]::GetFullPath($store).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $store -PathType Container) -or (Test-PathTreeHasReparsePoint -Path $store -IncludeDescendants)) {
        return (& $refuse "the message store $store is missing, or it or something in it is a reparse point.")
    }

    $connections = @()
    foreach ($doc in @(@{ Name='Config.xml'; Xml=$ConfigXml }, @{ Name='Proxy.xml'; Xml=$ProxyXml })) {
        if (-not $doc.Xml) { continue }
        foreach ($attribute in @($doc.Xml.SelectNodes('//@JetStreamConnectionString'))) {
            try { $connections += [pscustomobject]@{ File=$doc.Name; Endpoint=(ConvertFrom-NatsConnectionString "$($attribute.Value)") } }
            catch { return (& $refuse "the JetStreamConnectionString in $($doc.Name) could not be read: $($_.Exception.Message).") }
        }
    }
    if ($connections.Count -eq 0) { return (& $refuse 'Config.xml and Proxy.xml hold no JetStreamConnectionString.') }
    foreach ($connection in $connections) {
        if (-not (Test-LocalDbHost $connection.Endpoint.Host)) { return (& $refuse "$($connection.File) sends VB365 to NATS on $($connection.Endpoint.Host), which is not this server.") }
        if ($connection.Endpoint.Port -ne $facts.Port) { return (& $refuse "$($connection.File) uses NATS port $($connection.Endpoint.Port), but the config file uses $($facts.Port).") }
    }

    $answered = Get-NatsInfoVersion -HostName $facts.ProbeHost -Port $facts.Port
    if ($answered -ne $installed) {
        $said = if ($answered) { "answered version $answered" } else { 'did not answer' }
        return (& $refuse "NATS on $($facts.ProbeHost):$($facts.Port) $said, so its version cannot be checked after the update.")
    }
    try { $clients = Get-NatsClientSummary -Port $facts.Port }
    catch { return (& $refuse "its client connections could not be read: $($_.Exception.Message).") }
    if ($clients.RemoteAddresses.Count -gt 0) {
        $result.Status = 'REMOTE_CLIENTS'
        $result.Detail = "NATS $installed -> $($choice.Target) is due, but other machines are connected to NATS ($($clients.RemoteAddresses -join ', ')). This profile updates a single-server NATS only, so NATS is left alone."
        return [pscustomobject]$result
    }

    if (-not $UpdatesEnabled) {
        $result.Status = 'UPDATES_OFF'
        $result.Detail = "NATS $installed -> $($choice.Target) is due, but updateNats is false in the built-in settings, so -Install leaves NATS alone."
        return [pscustomobject]$result
    }

    $newDir = Join-Path ([IO.Path]::GetFullPath($NatsRoot).TrimEnd('\')) "nats-server-v$($choice.Target)-windows-amd64"
    $newExe = Join-Path $newDir 'nats-server.exe'
    $result.Plan = [pscustomobject][ordered]@{
        OldVersion             = $installed
        TargetVersion          = $choice.Target
        TargetSha256           = $choice.Sha256
        OldImagePath           = "$($service.PathName)"
        OldExe                 = $image.Exe
        OldFolder              = $image.Folder
        NewDir                 = $newDir
        NewExe                 = $newExe
        NewImagePath           = ('"{0}"{1}' -f $newExe, $image.Arguments)
        NewDirCreated          = $false
        ConfPath               = $image.ConfPath
        StoreDir               = $store
        Port                   = $facts.Port
        ProbeHost              = $facts.ProbeHost
        StartName              = "$($service.StartName)"
        BaselineVb365Connected = ($clients.Vb365Processes.Count -gt 0)
        OldExeSha256           = ''
        StagedExeSha256        = ''
        ConfSha256             = ''
        RegBackup              = ''
        ConfBackup             = ''
        StoreBackup            = ''
        StoreFiles             = 0
        StoreBytes             = [int64]0
    }
    $result.Detail = "$($choice.Detail) Store $store; port $($facts.Port)."
    return [pscustomobject]$result
}

function Set-NatsStage {
    param([Parameter(Mandatory)][string] $NatsStage)
    Set-RecoveryProperty NatsStage $NatsStage
    $installerStarted = [bool](Get-CfgValue $script:RecoveryState 'InstallerStarted' $false)
    Save-RecoveryState -Stage $script:Stage -InstallerStarted $installerStarted
}

# Point the nats-server service at another program, through the service manager like
# 'sc.exe config binPath=' in KB4742, and read it back. Never written to the registry
# directly.
function Set-NatsServicePath {
    param([Parameter(Mandatory)][string] $PathName)
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='nats-server'" -ErrorAction Stop
    if (-not $service) { throw 'the nats-server service is missing' }
    $change = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{ PathName = $PathName } -ErrorAction Stop
    if ([int]$change.ReturnValue -ne 0) { throw "the service manager refused the change (Win32_Service.Change returned $($change.ReturnValue))" }
    $after = Get-CimInstance -ClassName Win32_Service -Filter "Name='nats-server'" -ErrorAction Stop
    if ("$($after.PathName)" -cne $PathName) { throw "the service command line did not read back as set" }
}

# Stop one service without -Force and wait for it, so a dependent outside the plan
# makes this fail rather than being stopped too.
function Stop-ServiceAndWait {
    param([Parameter(Mandatory)][string] $Name, [int] $Seconds = 120)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service -or "$($service.Status)" -eq 'Stopped') { return }
    try { Stop-Service -Name $Name -ErrorAction Stop }
    catch { Write-Log "  Stop-Service $Name reported: $(Format-ShortText $_.Exception.Message 300)" WARN }
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ($true) {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $service -or "$($service.Status)" -eq 'Stopped') { return }
        if ((Get-Date) -ge $deadline) { throw "$Name is still $($service.Status) after $Seconds seconds" }
        Start-Sleep -Seconds 2
    }
}

# Stop a set of services in the given order, without -Force, in passes. A service
# another one still depends on refuses to stop on the first pass and stops on a later
# one, once its dependents are down. Fails when any is still up after $Seconds.
function Stop-ServicesInOrder {
    param([Parameter(Mandatory)][string[]] $Names, [int] $Seconds = 300)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ($true) {
        $live = @($Names | Where-Object {
            $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
            $service -and "$($service.Status)" -ne 'Stopped'
        })
        if ($live.Count -eq 0) { return }
        if ((Get-Date) -ge $deadline) { throw "still not stopped after $Seconds seconds: $($live -join ', ')" }
        foreach ($name in $live) {
            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            if (-not $service -or "$($service.Status)" -ne 'Running') { continue }
            try { Stop-Service -Name $name -ErrorAction Stop }
            catch { Write-Log "  Stop-Service $name reported: $(Format-ShortText $_.Exception.Message 300)" WARN }
        }
        Start-Sleep -Seconds 3
    }
}

# Is NATS running the planned new version, the way VB365 sees it?
function Test-NatsRunningAt {
    param([Parameter(Mandatory)] $Plan, [Parameter(Mandatory)][string] $Version, [Parameter(Mandatory)][string] $ImagePath)
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='nats-server'" -ErrorAction SilentlyContinue
    if (-not $service -or "$($service.State)" -ne 'Running' -or "$($service.PathName)" -cne $ImagePath) { return $false }
    return ((Get-NatsInfoVersion -HostName "$($Plan.ProbeHost)" -Port ([int]$Plan.Port)) -eq $Version)
}

# Put the store back from this run's copy. robocopy /MIR makes the folder match the
# copy exactly, so files the new version wrote go too.
function Restore-NatsStore {
    param([Parameter(Mandatory)] $Plan, [Parameter(Mandatory)][string] $WorkRoot)
    $backup = "$($Plan.StoreBackup)"
    $store = "$($Plan.StoreDir)"
    if (-not (Test-NatsStorePathSafe -StoreDir $store -WorkRoot $WorkRoot)) { throw "the recorded store path $store is not safe to restore into" }
    if (-not $backup -or -not (Test-Path -LiteralPath $backup -PathType Container) -or (Test-PathTreeHasReparsePoint -Path $backup -IncludeDescendants)) {
        throw "the store copy $backup is missing or holds a reparse point"
    }
    if ((Test-Path -LiteralPath $store) -and (Test-PathTreeHasReparsePoint -Path $store -IncludeDescendants)) { throw "the store $store now holds a reparse point" }
    $copy = Invoke-Native 'robocopy.exe' @($backup, $store, '/MIR', '/COPY:DAT', '/DCOPY:DAT', '/R:1', '/W:1', '/XJ', '/NFL', '/NDL', '/NP', '/NJH', '/NJS')
    if ($copy.ExitCode -ge 8) { throw "robocopy could not copy the store back (exit $($copy.ExitCode)) $($copy.StdErr)" }
    $measure = Get-ChildItem -LiteralPath $store -File -Recurse -Force -ErrorAction Stop | Measure-Object -Property Length -Sum
    $bytes = [int64]$(if ($measure.Sum) { $measure.Sum } else { 0 })
    if ($measure.Count -ne [int]$Plan.StoreFiles -or $bytes -ne [int64]$Plan.StoreBytes) {
        throw "the restored store holds $($measure.Count) files/$bytes bytes, the copy $($Plan.StoreFiles) files/$($Plan.StoreBytes) bytes"
    }
}

# Put the old NATS back after a failed update. Safe to run again after an interruption.
#   Before VB365 used the new version (Full): point the service back at the old
#   program and, if the new version ever started, restore the message store copy.
#   After VB365 used it (Binary): stop VB365, point the service back, and KEEP the
#   store. Old messages put back could make VB365 do work twice; the old version on
#   the same line reads the store as it is.
# Returns '' when NATS is back on its old program, or what went wrong.
function Restore-NatsInstallation {
    param([string] $WorkRootPath = '')
    $state = $script:RecoveryState
    if (-not $state -or "$(Get-CfgValue $state 'Change' '')" -ne 'NATS') { return '' }
    $natsStage = "$(Get-CfgValue $state 'NatsStage' '')"
    if ($natsStage -in @('','PLANNED','BACKING_UP','BACKED_UP','REVERTED','COMMITTED')) { return '' }
    $plan = Get-CfgValue $state 'NatsPlan' $null
    if (-not $plan) { return 'the recorded NATS plan is missing' }
    if (-not $WorkRootPath) { $WorkRootPath = Split-Path -Parent (Split-Path -Parent $script:RunDir) }
    $mode = "$(Get-CfgValue $state 'NatsRevertMode' '')"
    try {
        if ($natsStage -ne 'REVERTING' -or -not $mode) {
            $mode = if ($natsStage -eq 'VEEAM_STARTED') { 'Binary' } else { 'Full' }
            Set-RecoveryProperty NatsRevertMode $mode
        }
        Set-NatsStage 'REVERTING'
        Write-Log "Putting NATS $($plan.OldVersion) back ($(if ($mode -eq 'Binary') { 'program only; the message store VB365 used is kept' } else { 'program, and the message store if the new version started' }))" WARN
        if ($mode -eq 'Binary') {
            # VB365 is running on the new NATS. Stop it first, Proxy before Service.
            $order = @('Veeam.Archiver.Proxy','Veeam.Archiver.Service','Veeam.Archiver.REST.Service')
            $others = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)" } | Where-Object { $order -notcontains $_ } | Sort-Object)
            Stop-ServicesInOrder -Names @($order + $others) -Seconds 300
        }
        $live = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue | Where-Object { "$($_.Status)" -ne 'Stopped' })
        if ($live.Count -gt 0) { throw "Veeam service(s) are not stopped: $(@($live | ForEach-Object { $_.Name }) -join ', ')" }
        # A restart during the run can have started NATS on the new program already.
        # Then it may have written to the store, so a full revert restores the store too.
        $newRan = [bool](Get-CfgValue $state 'NatsNewBinaryStarted' $false)
        $before = Get-CimInstance -ClassName Win32_Service -Filter "Name='nats-server'" -ErrorAction Stop
        if ($before -and "$($before.State)" -ne 'Stopped' -and "$($before.PathName)" -ceq "$($plan.NewImagePath)") { $newRan = $true }
        Stop-ServiceAndWait -Name 'nats-server' -Seconds 120

        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='nats-server'" -ErrorAction Stop
        if (-not $service) { throw 'the nats-server service is missing' }
        if ("$($service.PathName)" -cne "$($plan.OldImagePath)") {
            Set-NatsServicePath -PathName "$($plan.OldImagePath)"
            Write-Log "  nats-server points at $($plan.OldExe) again" OK
        }
        if ($mode -eq 'Full' -and $newRan) {
            Restore-NatsStore -Plan $plan -WorkRoot $WorkRootPath
            Write-Log "  message store put back from $($plan.StoreBackup)" OK
        }
        if ($plan.OldExeSha256 -and (Get-FileSha256 "$($plan.OldExe)") -ne "$($plan.OldExeSha256)") { throw "$($plan.OldExe) changed during the run" }
        $oldRun = Invoke-Native "$($plan.OldExe)" @('--version')
        $oldReported = ConvertFrom-NatsVersionText "$($oldRun.StdOut)`n$($oldRun.StdErr)"
        if ($oldReported -ne "$($plan.OldVersion)") { throw "$($plan.OldExe) reports '$oldReported', not $($plan.OldVersion)" }

        # Remove the new folder only when this run created it, it sits beside the old
        # one, and it holds nothing but the program this run copied (even half-copied).
        $newDir = "$($plan.NewDir)"
        $besideOld = ("$([IO.Path]::GetDirectoryName($newDir))" -ieq "$([IO.Path]::GetDirectoryName("$($plan.OldFolder)"))") -and
                     ([IO.Path]::GetFileName($newDir) -match '^nats-server-v\d+\.\d+\.\d+-windows-amd64$')
        if ([bool]$plan.NewDirCreated -and $besideOld -and (Test-Path -LiteralPath $newDir -PathType Container) -and
            -not (Test-PathTreeHasReparsePoint -Path $newDir -IncludeDescendants)) {
            $inside = @(Get-ChildItem -LiteralPath $newDir -Force -ErrorAction Stop)
            if ($inside.Count -eq 0 -or ($inside.Count -eq 1 -and $inside[0].Name -ceq 'nats-server.exe' -and -not $inside[0].PSIsContainer)) {
                Remove-Item -LiteralPath $newDir -Recurse -Force -ErrorAction Stop
                Write-Log "  removed $newDir"
            } else {
                Write-Log "  left $newDir in place: it holds more than the program this run copied there" WARN
            }
        }
        Set-NatsStage 'REVERTED'
    } catch {
        return "NATS could not be put back to $($plan.OldVersion): $($_.Exception.Message)"
    }
    return ''
}

# A NATS-only -Install run on VB365: PostgreSQL needs nothing, and NATS has a
# same-line update. The outage follows the PostgreSQL pattern: wait for work, disable
# jobs, VB365 maintenance mode, stop Veeam and NATS, back up, switch, verify, start,
# re-enable jobs. PostgreSQL is never stopped or changed. Always ends in Complete-Run.
# Reads the run's settings ($hasVbr, $pgSvc, $runningVersion, ...) from script scope.
function Invoke-NatsOnlyUpdate {
    param([Parameter(Mandatory)] $Discovery)
    $natsPlan = $Discovery.Plan
    $natsFrom = "$($natsPlan.OldVersion)"
    $natsTo   = "$($natsPlan.TargetVersion)"
    $script:Report.NatsStatus = 'UPDATING'
    Write-Log "NATS $natsFrom -> $natsTo is due and PostgreSQL $runningVersion needs nothing, so this run updates NATS only." WARN

    if (-not $script:WorkRootProtected) {
        Complete-Run $EXIT.PREFLIGHT 'WORKROOT_UNSAFE' "The work root is not locked to SYSTEM and Administrators ($($wrInit.Reason)). Refusing to write NATS backups or recovery state there."
    }
    New-Item -ItemType Directory -Path $script:RunDir -Force | Out-Null
    Write-Log "Run folder: $($script:RunDir)"
    # SchemaVersion 2 marks a NATS run. An older copy of this script refuses to
    # -Recover it instead of restoring services around a half-switched NATS.
    $script:RecoveryState = [pscustomobject][ordered]@{
        SchemaVersion                 = 2
        RunId                         = $script:Stamp
        RunDir                        = $script:RunDir
        Stage                         = 'UNTOUCHED'
        InstallerStarted              = $false
        Change                        = 'NATS'
        Products                      = $script:Report.VeeamProducts
        OriginalVersion               = $runningVersion
        TargetVersion                 = $runningVersion
        PgServiceName                 = $pgSvc.Name
        PgPort                        = $pgPort
        PsqlPath                      = $psql
        DataDir                       = $pg.DataDir
        Vb365MaintenanceSessionId     = $null
        Vb365MaintenancePending       = $false
        Vb365MaintenanceAttemptedAt   = $null
        Vb365MaintenanceRepositoryIds = @()
        NatsStage                     = 'PLANNED'
        NatsRevertMode                = ''
        NatsNewBinaryStarted          = $false
        NatsPlan                      = $natsPlan
        LogPath                       = $script:Transcript
        CreatedAt                     = (Get-Date).ToString('o')
        UpdatedAt                     = (Get-Date).ToString('o')
    }

    $jobWaitMinutes = 720
    try { $jobWaitMinutes = [int](Get-CfgValue $Cfg 'jobWaitTimeoutMinutes' 720) } catch {}
    if ($jobWaitMinutes -lt 1 -or $jobWaitMinutes -gt 10080) {
        Complete-Run $EXIT.PREFLIGHT 'BAD_JOB_WAIT_TIMEOUT' 'jobWaitTimeoutMinutes must be between 1 and 10080.'
    }

    # -----------------------------------------------------------------------
    # NATS 1/7 - Download and check the package. Nothing has changed yet.
    # -----------------------------------------------------------------------
    Write-Log "NATS 1/7 - Download and check NATS $natsTo" STEP
    $natsWork = Join-Path $script:RunDir 'nats'
    New-Item -ItemType Directory -Path $natsWork -Force | Out-Null
    $natsZipName = "nats-server-v$natsTo-windows-amd64.zip"
    $natsZipUrl = "https://github.com/nats-io/nats-server/releases/download/v$natsTo/$natsZipName"
    $natsZip = Join-Path $natsWork $natsZipName
    $oldProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try { Invoke-WebRequest -Uri $natsZipUrl -OutFile $natsZip -UseBasicParsing -TimeoutSec 600 }
    catch { Complete-Run $EXIT.DOWNLOAD 'NATS_DOWNLOAD_FAILED' "Could not download $natsZipUrl : $($_.Exception.Message)" }
    finally { $ProgressPreference = $oldProgress }

    # NATS publishes no signature. The SHA256 pinned in Get-NatsPolicy is the proof.
    $natsZipHash = ''
    try { $natsZipHash = Get-FileSha256 $natsZip } catch {}
    if ($natsZipHash -ne "$($natsPlan.TargetSha256)") {
        Remove-Item -LiteralPath $natsZip -Force -ErrorAction SilentlyContinue
        Complete-Run $EXIT.DOWNLOAD 'NATS_HASH_MISMATCH' "The downloaded $natsZipName has SHA256 '$natsZipHash', not the pinned $($natsPlan.TargetSha256). It was deleted. Nothing was changed."
    }
    Write-Log "SHA256 matches the value pinned for NATS $natsTo" OK

    $natsStageDir = Join-Path $natsWork 'stage'
    try { $stagedExe = Expand-NatsPackage -ZipPath $natsZip -Version $natsTo -Destination $natsStageDir }
    catch { Complete-Run $EXIT.PREFLIGHT 'NATS_PACKAGE_INVALID' "The NATS $natsTo package cannot be used: $($_.Exception.Message). Nothing was changed." }
    $natsPlan.StagedExeSha256 = Get-FileSha256 $stagedExe
    $stagedRun = Invoke-Native $stagedExe @('--version')
    $stagedVersion = ConvertFrom-NatsVersionText "$($stagedRun.StdOut)`n$($stagedRun.StdErr)"
    if ($stagedVersion -ne $natsTo) {
        Complete-Run $EXIT.PREFLIGHT 'NATS_STAGED_BINARY_FAILED' "The downloaded nats-server.exe reports '$stagedVersion', not $natsTo (exit $($stagedRun.ExitCode)). An application-control or antivirus product may be blocking it. Nothing was changed."
    }
    # -t only reads the config file and exits. It opens no port and no store.
    $confTest = Invoke-Native $stagedExe @('-t', '-c', "$($natsPlan.ConfPath)")
    if ($confTest.ExitCode -ne 0) {
        Write-Log "nats-server $natsTo -t said: $(Format-ShortText "$($confTest.StdErr) $($confTest.StdOut)" 300)" WARN
        Complete-Run $EXIT.PREFLIGHT 'NATS_STAGED_BINARY_FAILED' "NATS $natsTo does not accept the current config file (exit $($confTest.ExitCode)); see the log. Nothing was changed."
    }
    Write-Log "NATS $natsTo runs on this server and accepts $($natsPlan.ConfPath)" OK

    # The store copy goes into WorkRoot. Measure while NATS runs; files can come and go.
    $storeMeasure = Get-ChildItem -LiteralPath "$($natsPlan.StoreDir)" -File -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
    $storeBytesNow = [int64]$(if ($storeMeasure -and $storeMeasure.Sum) { $storeMeasure.Sum } else { 0 })
    $needBytes = $storeBytesNow + 200MB
    $workDrive = (Get-Item -LiteralPath $WorkRoot).PSDrive.Name
    $freeBytes = (Get-PSDrive $workDrive).Free
    Write-Log ("NATS message store {0:N1} MB; need {1:N1} MB free on {2}: ; have {3:N1} MB" -f ($storeBytesNow/1MB), ($needBytes/1MB), $workDrive, ($freeBytes/1MB))
    if ($freeBytes -lt $needBytes) {
        Complete-Run $EXIT.PREFLIGHT 'LOW_DISK' ("Not enough free space on {0}: for the NATS store copy - need {1:N1} MB, have {2:N1} MB. Nothing was changed." -f $workDrive, ($needBytes/1MB), ($freeBytes/1MB))
    }

    # -----------------------------------------------------------------------
    # NATS 2/7 - Wait for Veeam work, disable jobs, VB365 maintenance mode
    # -----------------------------------------------------------------------
    Write-Log 'NATS 2/7 - Wait for Veeam work, disable jobs, start VB365 maintenance mode' STEP
    $controlValidation = Get-VeeamControlSurfaceValidation -Vbr $hasVbr -Vb365 $hasVb365 -Reconnect
    if ($controlValidation.Kind -ne 'OK') {
        $validationCode = if ($controlValidation.Kind -eq 'UNSUPPORTED') { $EXIT.UNSUPPORTED } else { $EXIT.PREFLIGHT }
        if ($controlValidation.Action) { $script:Report.ActionRequired = $controlValidation.Action }
        Complete-Run $validationCode $controlValidation.IssueCode $controlValidation.Detail
    }
    $script:ManagedJobInventory = @($controlValidation.Inventory)
    try { $idleBeforeDisable = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $jobWaitMinutes -Context 'before schedules are disabled' -CloseConsoles }
    catch {
        $sessionCode = if ($_.Exception -is [System.NotSupportedException]) { $EXIT.UNSUPPORTED } else { $EXIT.PREFLIGHT }
        $sessionIssue = if ($sessionCode -eq $EXIT.UNSUPPORTED) { 'UNSUPPORTED_ACTIVITY_API' } else { 'SESSION_CHECK_FAILED' }
        Complete-Run $sessionCode $sessionIssue "Could not read every applicable Veeam session family, so it is impossible to prove the server is idle: $($_.Exception.Message)"
    }
    if (-not $idleBeforeDisable.Idle) {
        Complete-Run $EXIT.RETRY 'JOB_WAIT_TIMEOUT' "Veeam work did not finish within $jobWaitMinutes minutes ($($idleBeforeDisable.Labels -join ', ')). No job or restore was forcibly stopped."
    }
    try {
        $script:ManagedJobInventory = @(Get-VeeamManagedJobInventory -Vbr $hasVbr -Vb365 $hasVb365)
        Disable-VeeamManagedJobs -Inventory $script:ManagedJobInventory
        $inventoryAfterDisable = @(Get-VeeamManagedJobInventory -Vbr $hasVbr -Vb365 $hasVb365)
        $unexpectedEnabled = @($inventoryAfterDisable | Where-Object { $_.Enabled })
        if ($unexpectedEnabled.Count -gt 0) {
            throw "schedule inventory changed during disable; still enabled: $((@($unexpectedEnabled) | ForEach-Object { "$($_.Family):$($_.Name)" }) -join ', ')"
        }
        $script:ManagedJobInventory = $inventoryAfterDisable
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'JOB_DISABLE_FAILED' "Could not disable and verify every enabled Veeam schedule/policy: $($_.Exception.Message)"
    }
    Write-Log "$($script:DisabledJobs.Count) job(s) disabled; recorded in disabled-jobs.json" OK
    try { $idleAfterDisable = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $jobWaitMinutes -Context 'after schedules were disabled' -CloseConsoles }
    catch { Complete-Run $EXIT.PREFLIGHT 'SESSION_RECHECK_FAILED' "Could not re-check Veeam activity after disabling schedules: $($_.Exception.Message)" }
    if (-not $idleAfterDisable.Idle) {
        Complete-Run $EXIT.RETRY 'JOB_DRAIN_TIMEOUT' "Veeam work did not finish within $jobWaitMinutes minutes after schedules were disabled ($($idleAfterDisable.Labels -join ', ')). No job/restore was forcibly stopped; captured schedules will be restored."
    }
    try { [void](Start-Vb365MaintenanceBarrier -TimeoutMinutes $jobWaitMinutes) }
    catch { Complete-Run $EXIT.RETRY 'VB365_MAINTENANCE_NOT_STARTED' "Could not establish the no-force VB365 repository maintenance barrier: $($_.Exception.Message)" }

    # -----------------------------------------------------------------------
    # NATS 3/7 - Stop Veeam services, then NATS. PostgreSQL keeps running.
    # -----------------------------------------------------------------------
    Write-Log 'NATS 3/7 - Stop Veeam services and NATS' STEP
    $backupDir = Join-Path $script:RunDir 'backup'
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    foreach ($f in @('Config.xml','Proxy.xml')) {
        $src = Join-Path 'C:\ProgramData\Veeam\Backup365' $f
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $backupDir -Force; Write-Log "  copied $f" }
    }

    try { $script:VeeamServices = @(Get-VeeamServiceState) }
    catch { Complete-Run $EXIT.PREFLIGHT 'SERVICE_STATE_FAILED' "Could not capture Veeam service state: $($_.Exception.Message)" }
    if ($script:VeeamServices.Count -eq 0) {
        Complete-Run $EXIT.PREFLIGHT 'NO_VEEAM_SERVICES' 'A Veeam product was detected, but no Windows services named Veeam* were found.'
    }
    Write-AtomicJson -Path (Join-Path $script:RunDir 'veeam-service-state.json') -InputObject @($script:VeeamServices) -Depth 4
    Write-Log "Captured $($script:VeeamServices.Count) Veeam service state(s) in veeam-service-state.json"

    $nats = Get-Service -Name 'nats-server' -ErrorAction SilentlyContinue
    if (-not $nats -or "$($nats.Status)" -ne 'Running') {
        $natsNow = if ($nats) { "$($nats.Status)" } else { 'missing' }
        Complete-Run $EXIT.PREFLIGHT 'NATS_STATE_CHANGED' "nats-server is $natsNow; it was Running when this run checked it."
    }
    try { $script:NatsStartupType = Get-ServiceStartupTypeExact 'nats-server' }
    catch { Complete-Run $EXIT.PREFLIGHT 'NATS_STARTUP_UNREADABLE' "Could not capture the nats-server startup type: $($_.Exception.Message)" }
    $script:NatsStateCaptured = $true
    $script:NatsWasRunning = $true
    Write-AtomicJson -Path (Join-Path $script:RunDir 'nats-service-state.json') -InputObject ([pscustomobject]@{
        Name='nats-server'; Status="$($nats.Status)"; WasRunning=$true; StartupType=$script:NatsStartupType; PathName="$($natsPlan.OldImagePath)"
    }) -Depth 3
    # PostgreSQL is not stopped. -Recover reads this record and finds nothing to do.
    $pgNow = Get-Service -Name $pgSvc.Name -ErrorAction SilentlyContinue
    try { $pgStartupNow = Get-ServiceStartupTypeExact $pgSvc.Name }
    catch { Complete-Run $EXIT.PREFLIGHT 'PG_STARTUP_UNREADABLE' "Could not capture the PostgreSQL service startup type: $($_.Exception.Message)" }
    Write-AtomicJson -Path (Join-Path $script:RunDir 'pg-service-state.json') -InputObject ([pscustomobject]@{
        Name=$pgSvc.Name; Status="$($pgNow.Status)"; WasRunning=($pgNow -and "$($pgNow.Status)" -eq 'Running'); StartupType=$pgStartupNow; PsqlPath=$psql; Port=$pgPort
    }) -Depth 3

    $plannedServiceNames = @($script:VeeamServices.Name) + @('nats-server')
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
        Complete-Run $EXIT.PREFLIGHT 'EXTERNAL_SERVICE_DEPENDENCY' "The planned shutdown has running dependent service(s) outside the Veeam/NATS scope: $((@($externalDependents) | Sort-Object -Unique) -join ', '). Nothing outside the planned scope was changed."
    }

    try { $finalScheduleInventory = @(Get-VeeamManagedJobInventory -Vbr $hasVbr -Vb365 $hasVb365) }
    catch { Complete-Run $EXIT.PREFLIGHT 'FINAL_JOB_INVENTORY_FAILED' "Could not refresh every schedule immediately before the outage: $($_.Exception.Message)" }
    $enabledBeforeOutage = @($finalScheduleInventory | Where-Object { $_.Enabled })
    if ($enabledBeforeOutage.Count -gt 0) {
        Complete-Run $EXIT.RETRY 'SCHEDULE_STATE_CHANGED' "Schedules were created or re-enabled before the outage ($((@($enabledBeforeOutage) | ForEach-Object { "$($_.Family):$($_.Name)" }) -join ', ')). The captured schedules will be restored; retry in a controlled window."
    }
    $script:ManagedJobInventory = $finalScheduleInventory
    try {
        $barrierNow = Get-VBORepositoryMaintenanceSession -Id ([guid]$script:Vb365MaintenanceSessionId) -ErrorAction Stop
        if (-not $barrierNow -or "$($barrierNow.State)" -ne 'Running') {
            $barrierState = if ($barrierNow) { "$($barrierNow.State)" } else { 'missing' }
            throw "repository-maintenance barrier is $barrierState"
        }
    } catch {
        Complete-Run $EXIT.RETRY 'VB365_MAINTENANCE_LOST' "The VB365 repository-maintenance barrier did not remain Running: $($_.Exception.Message)"
    }

    Save-RecoveryState -Stage 'SERVICES_STOPPED' -InstallerStarted $false
    $natsDisableFailures = @(Disable-VeeamServiceStartup)
    if ($natsDisableFailures.Count -gt 0) {
        Complete-Run $EXIT.PREFLIGHT 'SERVICE_DISABLE_FAILED' "Could not disable every Veeam service: $($natsDisableFailures -join ' | ')"
    }
    try { $lastChanceInventory = @(Get-VeeamManagedJobInventory -Vbr $hasVbr -Vb365 $hasVb365) }
    catch { Complete-Run $EXIT.PREFLIGHT 'LAST_CHANCE_JOB_INVENTORY_FAILED' "Could not refresh every schedule before the first service stop: $($_.Exception.Message)" }
    $lastChanceEnabled = @($lastChanceInventory | Where-Object { $_.Enabled })
    if ($lastChanceEnabled.Count -gt 0) {
        Complete-Run $EXIT.RETRY 'LAST_CHANCE_SCHEDULE_STATE_CHANGED' "Schedules were created or re-enabled before the first service stop ($(@($lastChanceEnabled | ForEach-Object { "$($_.Family):$($_.Name)" }) -join ', ')). No service was stopped; captured schedules will be restored."
    }
    try {
        $lastChanceActive = @(Get-ActiveVeeamWork -Vbr $hasVbr -Vb365 $hasVb365)
        if (Test-OnlyConsoleBlockers $lastChanceActive) {
            [void](Close-VeeamConsoleProcesses -Vbr $hasVbr -Vb365 $hasVb365)
            $lastChanceActive = @(Get-ActiveVeeamWork -Vbr $hasVbr -Vb365 $hasVb365)
        }
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'LAST_CHANCE_SESSION_CHECK_FAILED' "Could not complete the immediate pre-stop activity read: $($_.Exception.Message)"
    }
    if ($lastChanceActive.Count -gt 0) {
        Complete-Run $EXIT.RETRY 'LAST_CHANCE_ACTIVITY_RACE' "New Veeam work appeared before the first service stop ($($lastChanceActive -join ', ')). No service was stopped and no job or restore was forcibly terminated."
    }
    $blockingUi = @(Get-BlockingVeeamUiProcesses -Vbr $hasVbr -Vb365 $hasVb365)
    if (Test-OnlyConsoleBlockers @($blockingUi | ForEach-Object { "UI:$($_.ProcessName):PID$($_.Id)" })) {
        [void](Close-VeeamConsoleProcesses -Vbr $hasVbr -Vb365 $hasVb365)
        $blockingUi = @(Get-BlockingVeeamUiProcesses -Vbr $hasVbr -Vb365 $hasVb365)
    }
    if ($blockingUi.Count -gt 0) {
        Complete-Run $EXIT.RETRY 'VEEAM_UI_OPEN' "A Veeam Explorer, or a Veeam console that could not be closed, is open before service shutdown ($((@($blockingUi) | ForEach-Object { "$($_.ProcessName):PID$($_.Id)" }) -join ', ')). Explorers are never closed automatically. Close it and retry."
    }

    # KB4742 order: Proxy, then Service, then NATS. Every other Veeam service after them.
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
                    Stop-Service -Name $svcName -ErrorAction Stop
                }
            } catch { $stopRequestWarnings += "$svcName (pass $stopPass): $($_.Exception.Message)" }
        }
        $veeamStillStopping = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Stopped' })
        if ($veeamStillStopping.Count -eq 0) { break }
        if ($stopPass -lt $maxStopPasses) { Start-Sleep -Seconds 2 }
    }
    # A last look for clients on other machines, just before NATS stops.
    try { $clientsNow = Get-NatsClientSummary -Port ([int]$natsPlan.Port) }
    catch { Complete-Run $EXIT.PREFLIGHT 'NATS_CLIENT_CHECK_FAILED' "Could not read the NATS client connections: $($_.Exception.Message). NATS was NOT changed." }
    if ($clientsNow.RemoteAddresses.Count -gt 0) {
        Complete-Run $EXIT.PREFLIGHT 'NATS_REMOTE_CLIENTS' "Other machines are connected to NATS ($($clientsNow.RemoteAddresses -join ', ')). NATS was NOT changed."
    }
    Write-Log '  stopping nats-server'
    try { Stop-Service -Name 'nats-server' -ErrorAction Stop }
    catch { $stopRequestWarnings += "nats-server: $($_.Exception.Message)" }
    Start-Sleep -Seconds 10

    $currentVeeamServices = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue)
    $currentVeeamNames = @($currentVeeamServices | ForEach-Object { $_.Name })
    $stillUp = @($currentVeeamServices | Where-Object { $_.Status -ne 'Stopped' })
    $newVeeamServices = @($currentVeeamServices | Where-Object { $script:VeeamServices.Name -notcontains $_.Name })
    $missingVeeamServices = @($script:VeeamServices | Where-Object { $currentVeeamNames -notcontains $_.Name })
    $natsAfterStop = Get-Service -Name 'nats-server' -ErrorAction SilentlyContinue
    $natsStillUp = $null
    if (-not $natsAfterStop -or $natsAfterStop.Status -ne 'Stopped') {
        $natsStillUp = if ($natsAfterStop) { "nats-server=$($natsAfterStop.Status)" } else { 'nats-server missing after stop request' }
    }
    $notDisabled = @()
    foreach ($rec in $script:VeeamServices) {
        try { if ((Get-ServiceStartupTypeExact $rec.Name) -ne 'Disabled') { $notDisabled += $rec.Name } }
        catch { $notDisabled += "$($rec.Name) (unreadable)" }
    }
    if ($stopRequestWarnings.Count -gt 0) {
        Write-Log "Service stop request warning(s); final state will decide success: $($stopRequestWarnings -join ' | ')" WARN
    }
    if ($stillUp.Count -gt 0 -or $newVeeamServices.Count -gt 0 -or $missingVeeamServices.Count -gt 0 -or $natsStillUp -or $notDisabled.Count -gt 0) {
        $issues = @()
        if ($stillUp.Count -gt 0) { $issues += "still running: $((@($stillUp) | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join ', ')" }
        if ($newVeeamServices.Count -gt 0) { $issues += "service inventory changed after capture: $((@($newVeeamServices) | ForEach-Object { $_.Name }) -join ', ')" }
        if ($missingVeeamServices.Count -gt 0) { $issues += "captured service disappeared: $((@($missingVeeamServices) | ForEach-Object { $_.Name }) -join ', ')" }
        if ($natsStillUp) { $issues += "still running: $natsStillUp" }
        if ($notDisabled.Count -gt 0) { $issues += "startup type not Disabled: $($notDisabled -join ', ')" }
        Complete-Run $EXIT.PREFLIGHT 'SERVICES_WONT_STOP' "Could not disable and stop every Veeam service and NATS: $($issues -join ' | '). NATS was NOT changed."
    }
    Write-Log 'All Veeam services are Disabled and stopped, and nats-server is stopped' OK

    # -----------------------------------------------------------------------
    # NATS 4/7 - Back up the service record, the config file and the message store
    # -----------------------------------------------------------------------
    Write-Log 'NATS 4/7 - Back up the NATS service, config file and message store' STEP
    Set-NatsStage 'BACKING_UP'
    $natsBackup = Join-Path $backupDir 'nats'
    try {
        New-Item -ItemType Directory -Path $natsBackup -Force -ErrorAction Stop | Out-Null
        $natsPlan.OldExeSha256 = Get-FileSha256 "$($natsPlan.OldExe)"
        $natsPlan.ConfSha256 = Get-FileSha256 "$($natsPlan.ConfPath)"
        $regBackup = Join-Path $natsBackup 'nats-server-service.reg'
        $export = Invoke-Native (Join-Path $env:SystemRoot 'System32\reg.exe') @('export', 'HKLM\SYSTEM\CurrentControlSet\Services\nats-server', $regBackup, '/y')
        if ($export.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $regBackup) -or (Get-Item -LiteralPath $regBackup).Length -eq 0) {
            throw "reg.exe could not export the nats-server service key (exit $($export.ExitCode)) $($export.StdErr)"
        }
        $natsPlan.RegBackup = $regBackup
        # The config file holds the NATS credentials. The backup folder inherits the
        # SYSTEM + Administrators only ACL of WorkRoot.
        $confBackup = Join-Path $natsBackup 'nats-server.conf'
        Copy-Item -LiteralPath "$($natsPlan.ConfPath)" -Destination $confBackup -Force -ErrorAction Stop
        if ((Get-FileSha256 $confBackup) -ne $natsPlan.ConfSha256) { throw 'the copy of the config file does not match the original' }
        $natsPlan.ConfBackup = $confBackup
        $storeAcl = Join-Path $natsBackup 'store-acl.txt'
        $aclSave = Invoke-Native (Join-Path $env:SystemRoot 'System32\icacls.exe') @("$($natsPlan.StoreDir)", '/save', $storeAcl, '/t', '/q')
        if ($aclSave.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $storeAcl)) { throw "icacls could not save the message store permissions (exit $($aclSave.ExitCode)) $($aclSave.StdErr)" }
        $storeBackup = Join-Path $natsBackup 'store'
        $storeCopy = Invoke-Native 'robocopy.exe' @("$($natsPlan.StoreDir)", $storeBackup, '/E', '/COPY:DAT', '/DCOPY:DAT', '/R:1', '/W:1', '/XJ', '/NFL', '/NDL', '/NP', '/NJH', '/NJS')
        if ($storeCopy.ExitCode -ge 8) { throw "robocopy of the message store failed (exit $($storeCopy.ExitCode)) $($storeCopy.StdErr)" }
        $sourceMeasure = Get-ChildItem -LiteralPath "$($natsPlan.StoreDir)" -File -Recurse -Force -ErrorAction Stop | Measure-Object -Property Length -Sum
        $copyMeasure = Get-ChildItem -LiteralPath $storeBackup -File -Recurse -Force -ErrorAction Stop | Measure-Object -Property Length -Sum
        $sourceBytes = [int64]$(if ($sourceMeasure.Sum) { $sourceMeasure.Sum } else { 0 })
        $copyBytes = [int64]$(if ($copyMeasure.Sum) { $copyMeasure.Sum } else { 0 })
        if ($sourceMeasure.Count -ne $copyMeasure.Count -or $sourceBytes -ne $copyBytes) {
            throw "the store copy holds $($copyMeasure.Count) files/$copyBytes bytes, the store $($sourceMeasure.Count) files/$sourceBytes bytes"
        }
        $natsPlan.StoreBackup = $storeBackup
        $natsPlan.StoreFiles = [int]$sourceMeasure.Count
        $natsPlan.StoreBytes = $sourceBytes
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'NATS_BACKUP_FAILED' "Could not back up NATS before changing it: $($_.Exception.Message). NATS was NOT changed."
    }
    Set-NatsStage 'BACKED_UP'
    Write-Log "NATS backed up to $natsBackup ($($natsPlan.StoreFiles) store files, $([math]::Round($natsPlan.StoreBytes / 1MB, 1)) MB)" OK

    # -----------------------------------------------------------------------
    # NATS 5/7 - Point nats-server at the new version. NATS IS CHANGED FROM HERE.
    # -----------------------------------------------------------------------
    Write-Log "NATS 5/7 - Point nats-server at NATS $natsTo" STEP
    $newDirExists = $false
    try {
        $natsServiceNow = Get-CimInstance -ClassName Win32_Service -Filter "Name='nats-server'" -ErrorAction Stop
        if (-not $natsServiceNow -or "$($natsServiceNow.PathName)" -cne "$($natsPlan.OldImagePath)") { throw 'the nats-server service command line changed after this run read it' }
        $newDirExists = Test-Path -LiteralPath "$($natsPlan.NewDir)"
        if ($newDirExists) {
            # Left by an earlier attempt or a manual KB4742 copy. Use it only if it holds
            # exactly the program this run checked.
            if (Test-PathTreeHasReparsePoint -Path "$($natsPlan.NewDir)" -IncludeDescendants) { throw "$($natsPlan.NewDir) already exists and holds a reparse point" }
            if (-not (Test-Path -LiteralPath "$($natsPlan.NewExe)" -PathType Leaf) -or (Get-FileSha256 "$($natsPlan.NewExe)") -ne $natsPlan.StagedExeSha256) {
                throw "$($natsPlan.NewDir) already exists and does not hold the same nats-server.exe"
            }
            Write-Log "$($natsPlan.NewDir) already holds the identical nats-server.exe; using it"
        }
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'NATS_SWAP_REFUSED' "$($_.Exception.Message). NATS was NOT changed."
    }
    # Record the intent before the first change, so a rollback or -Recover undoes it.
    $natsPlan.NewDirCreated = -not $newDirExists
    Set-NatsStage 'SWAP_STARTED'
    try {
        if (-not $newDirExists) {
            New-Item -ItemType Directory -Path "$($natsPlan.NewDir)" -ErrorAction Stop | Out-Null
            Copy-Item -LiteralPath $stagedExe -Destination "$($natsPlan.NewExe)" -ErrorAction Stop
        }
        if ((Get-FileSha256 "$($natsPlan.NewExe)") -ne $natsPlan.StagedExeSha256) { throw "the copy at $($natsPlan.NewExe) does not match the checked download" }
        $newRun = Invoke-Native "$($natsPlan.NewExe)" @('--version')
        if ((ConvertFrom-NatsVersionText "$($newRun.StdOut)`n$($newRun.StdErr)") -ne $natsTo) { throw "$($natsPlan.NewExe) does not report $natsTo" }
        Set-NatsServicePath -PathName "$($natsPlan.NewImagePath)"
    } catch {
        Complete-Run $EXIT.PREFLIGHT 'NATS_UPDATE_FAILED' "Could not point nats-server at NATS $natsTo : $($_.Exception.Message)"
    }
    Set-NatsStage 'SWAPPED'
    Write-Log "nats-server now runs $($natsPlan.NewExe)" OK

    # -----------------------------------------------------------------------
    # NATS 6/7 - Start NATS on its own first, then VB365 on it, and verify
    # -----------------------------------------------------------------------
    Write-Log "NATS 6/7 - Start NATS $natsTo, then VB365, and verify" STEP
    # From here the new version may write to the store, so a rollback before VB365
    # starts also puts the store copy back.
    Set-RecoveryProperty NatsNewBinaryStarted $true
    Save-RecoveryState -Stage $script:Stage -InstallerStarted $false
    try { Start-Service -Name 'nats-server' -ErrorAction Stop }
    catch { Write-Log "Start-Service nats-server reported: $(Format-ShortText $_.Exception.Message 300); the state read below decides." WARN }
    $natsUp = $false
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        $s = Get-Service -Name 'nats-server' -ErrorAction SilentlyContinue
        if ($s -and "$($s.Status)" -eq 'Running') { $natsUp = $true; break }
        Start-Sleep -Seconds 2
    }
    $natsProblems = @()
    if (-not $natsUp) {
        $natsProblems += 'nats-server did not reach Running within 120 seconds'
    } else {
        $answered = Wait-NatsInfoVersion -HostName "$($natsPlan.ProbeHost)" -Port ([int]$natsPlan.Port) -Expected $natsTo -Seconds 60
        if ($answered -ne $natsTo) { $natsProblems += "NATS on $($natsPlan.ProbeHost):$($natsPlan.Port) answered '$answered', not $natsTo" }
        if ((Get-FileSha256 "$($natsPlan.ConfPath)") -ne $natsPlan.ConfSha256) { $natsProblems += 'the config file changed' }
    }
    if ($natsProblems.Count -gt 0) {
        Complete-Run $EXIT.PREFLIGHT 'NATS_UPDATE_FAILED' "NATS $natsTo did not start cleanly: $($natsProblems -join '; ')."
    }
    Set-NatsStage 'NATS_VERIFIED'
    Write-Log "NATS $natsTo is running and answers clients" OK

    # VB365 now uses the new version. A failure from here puts the old program back
    # but keeps the store VB365 used.
    Set-NatsStage 'VEEAM_STARTED'
    $serviceRestoreProblems = @(Restore-VeeamServiceState -AllowStops:$false)
    if ($serviceRestoreProblems.Count -gt 0) {
        Write-Log "Initial service-restore verification reported: $($serviceRestoreProblems -join ' | '). The post-settle state will decide success." WARN
    }
    Write-Log 'Waiting 90s for Automatic (Delayed Start) services to settle...'
    Start-Sleep -Seconds 90

    $healthProblems = @()
    foreach ($rec in $script:VeeamServices) {
        $s = Get-Service -Name $rec.Name -ErrorAction SilentlyContinue
        if (-not $s) { $healthProblems += "$($rec.Name) (service missing)"; continue }
        if ($rec.WasRunning -and $s.Status -ne 'Running') {
            $healthProblems += "$($rec.Name) (expected Running, got $($s.Status))"
        } elseif (-not $rec.WasRunning -and $s.Status -eq 'Running') {
            Write-Log "$($rec.Name) was originally stopped but is now $($s.Status); leaving it untouched to avoid interrupting newly-arrived work" WARN
        } elseif (-not $rec.WasRunning -and $s.Status -ne 'Stopped') {
            $healthProblems += "$($rec.Name) (transitional state $($s.Status) did not settle to Running or Stopped)"
        }
        try {
            $actualStartup = Get-ServiceStartupTypeExact $rec.Name
            if ($actualStartup -ne $rec.StartupType) { $healthProblems += "$($rec.Name) (startup expected $($rec.StartupType), got $actualStartup)" }
        } catch { $healthProblems += "$($rec.Name) (startup type unreadable: $($_.Exception.Message))" }
    }
    $natsAfter = Get-Service -Name 'nats-server' -ErrorAction SilentlyContinue
    if (-not $natsAfter -or "$($natsAfter.Status)" -ne 'Running') { $healthProblems += "nats-server (expected Running, got $(if ($natsAfter) { $natsAfter.Status } else { 'missing' }))" }
    try {
        $natsStartupAfter = Get-ServiceStartupTypeExact 'nats-server'
        if ($natsStartupAfter -ne $script:NatsStartupType) { $healthProblems += "nats-server (startup expected $($script:NatsStartupType), got $natsStartupAfter)" }
    } catch { $healthProblems += "nats-server (startup type unreadable: $($_.Exception.Message))" }
    if (-not (Test-NatsRunningAt -Plan $natsPlan -Version $natsTo -ImagePath "$($natsPlan.NewImagePath)")) {
        $healthProblems += "NATS is not running $natsTo from $($natsPlan.NewExe)"
    }
    try {
        $pgHealth = Invoke-Psql 'SHOW server_version_num;'
        if ($pgHealth.ExitCode -ne 0 -or $pgHealth.StdOut -notmatch '^\d+$' -or [int]$pgHealth.StdOut -ne $runningNum) {
            $healthProblems += "$($pgSvc.Name) (database health/version query failed: $($pgHealth.StdErr) $($pgHealth.StdOut))"
        }
    } catch { $healthProblems += "$($pgSvc.Name) (health query failed: $($_.Exception.Message))" }
    $postStartModuleProblems = @(Connect-VeeamModules -Vb365 -Quiet -Reconnect)
    if ($postStartModuleProblems.Count -gt 0) { $healthProblems += @($postStartModuleProblems) }
    # VB365 held a connection to NATS before the update, so it must hold one again.
    if ([bool]$natsPlan.BaselineVb365Connected -and $healthProblems.Count -eq 0) {
        $vb365Back = @()
        for ($attempt = 1; $attempt -le 24; $attempt++) {
            try { $vb365Back = @((Get-NatsClientSummary -Port ([int]$natsPlan.Port)).Vb365Processes) } catch { $vb365Back = @() }
            if ($vb365Back.Count -gt 0) { break }
            Start-Sleep -Seconds 5
        }
        if ($vb365Back.Count -eq 0) { $healthProblems += 'VB365 did not connect to NATS again within 120 seconds' }
        else { Write-Log "VB365 is connected to NATS again ($($vb365Back -join ', '))" OK }
    }
    if ($healthProblems.Count -gt 0) {
        $script:Report.UnhealthyServices = $healthProblems -join ', '
        Complete-Run $EXIT.PREFLIGHT 'NATS_UPDATE_FAILED' "VB365 did not come back healthy on NATS $natsTo : $($healthProblems -join ' | ')."
    }
    Set-RecoveryProperty NatsStage 'COMMITTED'
    Save-RecoveryState -Stage 'VERIFIED' -InstallerStarted $false
    $script:Report.NatsInstalled = $natsTo
    $script:Report.NatsTarget = $natsTo
    $script:Report.NatsStatus = 'UPDATED'
    Write-Log "VB365 is healthy on NATS $natsTo" OK

    # -----------------------------------------------------------------------
    # NATS 7/7 - Release maintenance mode, turn the jobs back on, finish
    # -----------------------------------------------------------------------
    Write-Log 'NATS 7/7 - Re-enable jobs and finish' STEP
    if ($script:Vb365MaintenanceSessionId) {
        try { Stop-Vb365MaintenanceBarrier -SessionId $script:Vb365MaintenanceSessionId }
        catch {
            $script:Report.JobsLeftDisabled = (@($script:DisabledJobs | ForEach-Object { $_.Name }) -join ', ')
            $script:Report.IssueCode = 'VB365_MAINTENANCE_RELEASE_FAILED'
            $script:Report.ActionRequired = 'PAGE AN OPERATOR. Services are healthy, but VB365 repository maintenance could not be released; schedules remain disabled.'
            Complete-Run $EXIT.ESCALATE 'VB365_MAINTENANCE_RELEASE_FAILED' $_.Exception.Message
        }
    }
    try { $idleBeforeEnable = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $jobWaitMinutes -Context 'before schedules are re-enabled' -CloseConsoles }
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
    if ($failedJobs.Count -gt 0) {
        $script:Report.JobsLeftDisabled = (@($script:DisabledJobs | Where-Object { -not $_.Restored } | ForEach-Object { $_.Name })) -join ', '
        $script:Report.IssueCode = 'JOB_REENABLE_FAILED'
        $script:Report.ActionRequired = 'PAGE AN OPERATOR. Services are healthy, but one or more schedules could not be re-enabled; see JobsLeftDisabled and RecoveryRunDir.'
        Complete-Run $EXIT.ESCALATE 'JOB_REENABLE_FAILED' "NATS updated $natsFrom -> $natsTo and services are healthy, but these schedules remain disabled: $($failedJobs -join '; ')"
    }
    Write-Log "$($script:DisabledJobs.Count) job(s) re-enabled" OK

    Save-RecoveryState -Stage 'COMPLETE' -InstallerStarted $false
    if (-not (Remove-RecoveryMarker)) {
        $script:Report.IssueCode = 'MARKER_REMOVE_FAILED'
        Complete-Run $EXIT.ESCALATE 'MARKER_REMOVE_FAILED' 'The NATS update and state restoration succeeded, but the recovery marker could not be removed.'
    }
    Remove-Item -LiteralPath $natsZip -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $natsStageDir -Recurse -Force -ErrorAction SilentlyContinue
    $doneMsg = "NATS updated $natsFrom -> $natsTo. PostgreSQL $runningVersion needed no update and was not touched. Services verified and $($script:DisabledJobs.Count) job(s) re-enabled. The old version stays in $($natsPlan.OldFolder); backups are in $natsBackup."
    if ($Reboot) {
        Write-Log 'A NATS update needs no restart, so -Reboot booked none.' WARN
        $doneMsg += ' A NATS update needs no restart, so -Reboot booked none.'
    }
    $script:Report.RebootRequired = $false
    Complete-Run (Get-PolicyExitCode -Eol $script:EolBranch -UpdateAvailable $false -RebootRequired $false) 'NATS_UPDATED' $doneMsg
}

# The NATS facts the RMM notes need, read defensively: Complete-Run can run on a
# half-written or hand-edited recovery state, and before Get-CfgValue exists.
function Get-NatsRunFacts {
    $facts = [pscustomobject]@{ IsNatsRun=$false; Stage=''; OldVersion=''; TargetVersion='' }
    $state = Get-Variable -Name RecoveryState -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not $state) { return $facts }
    $names = @($state.PSObject.Properties.Name)
    if ($names -notcontains 'Change' -or "$($state.Change)" -ne 'NATS') { return $facts }
    $facts.IsNatsRun = $true
    if ($names -contains 'NatsStage') { $facts.Stage = "$($state.NatsStage)" }
    if ($names -contains 'NatsPlan' -and $state.NatsPlan) {
        $planNames = @($state.NatsPlan.PSObject.Properties.Name)
        if ($planNames -contains 'OldVersion') { $facts.OldVersion = "$($state.NatsPlan.OldVersion)" }
        if ($planNames -contains 'TargetVersion') { $facts.TargetVersion = "$($state.NatsPlan.TargetVersion)" }
    }
    return $facts
}

# What an operator does when the automatic NATS rollback failed.
function Get-NatsManualRevertAction {
    param($Plan)
    if (-not $Plan) { return 'PAGE AN OPERATOR. NATS could not be put back automatically; see Detail and RecoveryRunDir.' }
    return "PAGE AN OPERATOR. NATS could not be put back to $($Plan.OldVersion) automatically. Veeam services stay stopped and jobs disabled. Old program: $($Plan.OldExe). Service key backup: $($Plan.RegBackup). Store copy: $($Plan.StoreBackup). Fix the problem in Detail, then run -Recover; it tries the rollback again."
}

# ---------------------------------------------------------------------------
# Try to put the server back the way we found it. Only ever called when the
# installer has NOT yet started, so PostgreSQL itself is unmodified. A NATS run
# also puts the old NATS program back first.
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
        # A NATS run puts the old NATS program back before anything starts again.
        # If that fails, nothing is started on a half-switched NATS.
        $natsRevertProblem = Restore-NatsInstallation -WorkRootPath $WorkRoot
        if ($natsRevertProblem) {
            Write-Log "ROLLBACK INCOMPLETE: $natsRevertProblem. Veeam services were left stopped and jobs disabled." ERROR
            $script:RollbackProblems = @($natsRevertProblem)
            $script:Report.JobsLeftDisabled = (Get-UnrestoredJobNames -Records $script:DisabledJobs) -join ', '
            $script:Report.ActionRequired = Get-NatsManualRevertAction -Plan (Get-CfgValue $script:RecoveryState 'NatsPlan' $null)
            return $false
        }
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
        # NATS was put back: clients must get the old version again.
        if ("$(Get-CfgValue $script:RecoveryState 'NatsStage' '')" -eq 'REVERTED') {
            $natsPlanBack = Get-CfgValue $script:RecoveryState 'NatsPlan' $null
            if ($natsPlanBack) {
                $answeredBack = Wait-NatsInfoVersion -HostName "$($natsPlanBack.ProbeHost)" -Port ([int]$natsPlanBack.Port) -Expected "$($natsPlanBack.OldVersion)" -Seconds 60
                if ($answeredBack -ne "$($natsPlanBack.OldVersion)") { $problems += "NATS answered '$answeredBack' after the rollback, not $($natsPlanBack.OldVersion)" }
                else { Write-Log "  NATS answers as $answeredBack again" OK }
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
        $script:RollbackProblems = @($problems)
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

# The stage notes in Complete-Run describe only what was rolled back. A run can also
# start a stopped automatic Veeam service (STEP 14), close an open Veeam console (the
# waits), or remove a leftover Enterprise Manager registry key (STEP 3). Add each one
# that happened, and never let "Nothing was changed." stand after any of them.
function Add-RunSideEffectNotes {
    param([AllowEmptyString()][string] $StateNote = '', [Parameter(Mandatory)] $Report)
    $notes = @()
    # Say "left them running" only while that is still true: STEP 15 stops every
    # Veeam service, so a later failure can leave a started service stopped.
    $startedList = "$($Report['ServicesStarted'])"
    if ($startedList) {
        $startedNames = @($startedList -split ',\s*' | Where-Object { $_ })
        $stillRunning = @($startedNames | Where-Object {
            $current = @(Get-Service -Name $_ -ErrorAction SilentlyContinue)
            $current.Count -gt 0 -and "$($current[0].Status)" -eq 'Running'
        })
        $startedNote = if ($stillRunning.Count -eq $startedNames.Count) {
            "This run started the stopped automatic Veeam service(s) $startedList and left them running."
        } else {
            "Before the outage this run started the stopped automatic Veeam service(s) $startedList so the configuration backup could run. Not all of them are running now."
        }
        $notes += $startedNote
    }
    $closedList = "$($Report['ConsolesClosed'])"
    if ($closedList) { $notes += "This run closed the open Veeam console(s) $closedList; anything unsaved in them was lost." }
    if ("$($Report['StaleEmRecord'])" -like 'removed*') {
        $notes += 'This run removed the leftover Enterprise Manager registry key; StaleEmRecord names its .reg backup.'
    }
    if ($notes.Count -eq 0) { return $StateNote }
    if ($StateNote -eq 'Nothing was changed.') { $StateNote = 'No schedule, service or PostgreSQL state was changed.' }
    return ((@($StateNote) + $notes) | Where-Object { $_ }) -join ' '
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
    # A NATS run (VB365) changes NATS, never PostgreSQL. The notes below say so.
    $natsRun = (Get-NatsRunFacts).IsNatsRun
    $rollbackWhy = ''
    if (@($script:RollbackProblems).Count -gt 0) { $rollbackWhy = " Rollback problem: $(Format-ShortText (@($script:RollbackProblems) -join ' | ') 300)" }

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
                    $stateNote = 'Scheduled jobs were re-enabled, PostgreSQL was untouched and no service was stopped, but the completed recovery marker remains.'
                } else {
                    $stateNote = 'Scheduled jobs were re-enabled. PostgreSQL was untouched and no service was stopped.'
                }
            }
            else {
                $stateNote = 'WARNING: some scheduled jobs could NOT be re-enabled - check the Veeam console.'
                if (@($script:RollbackProblems).Count -gt 0) { $stateNote += " Rollback problem: $(Format-ShortText (@($script:RollbackProblems) -join ' | ') 300)" }
                $finalCode = $EXIT.ESCALATE
            }
        }
        'SERVICES_STOPPED' {
            # The installer never started, so PostgreSQL is unmodified and a full
            # restart is both safe and correct.
            if ($Recover) {
                $stateNote = 'Recovery did not complete. The marker and captured service/job state remain for an operator.'
                if ($finalCode -lt $EXIT.ESCALATE) { $finalCode = $EXIT.ESCALATE }
            } elseif (Invoke-Rollback) {
                $untouched = 'PostgreSQL was never modified.'
                if ($natsRun) {
                    $natsAfter = Get-NatsRunFacts
                    $untouched = if ($natsAfter.Stage -eq 'REVERTED') {
                        "NATS was put back to $($natsAfter.OldVersion), and PostgreSQL was not touched."
                    } else { 'NATS was not changed, and PostgreSQL was not touched.' }
                }
                Save-RecoveryState -Stage 'COMPLETE' -InstallerStarted $false
                if (-not (Remove-RecoveryMarker)) {
                    $finalCode = $EXIT.ESCALATE
                    $Outcome = 'MARKER_REMOVE_FAILED'
                    $script:Report.IssueCode = 'MARKER_REMOVE_FAILED'
                    $script:Report.ActionRequired = 'PAGE AN OPERATOR. Rollback succeeded, but the recovery marker could not be removed; remove it only after confirming this completed run.'
                    $stateNote = "Service/job state was restored, but the completed recovery marker remains. $untouched"
                } else {
                    $stateNote = "Service startup types and running states were restored, and jobs were re-enabled. $untouched"
                }
            }
            else { $stateNote = "WARNING: rollback did not fully succeed - Veeam may still be down.$rollbackWhy"; $finalCode = $EXIT.ESCALATE }
        }
        'INSTALLING' {
            $stateNote = "SERVER IS MID-CHANGE. Veeam services are STOPPED and jobs are DISABLED. Backups are in $($script:RunDir). The changes-in-progress marker is deliberately left in place."
            if (-not $Recover) { $stateNote += ' Run this script with -Recover: it finishes the update when PostgreSQL is healthy at the target version, and changes nothing otherwise.' }
            if ($finalCode -lt $EXIT.ESCALATE) { $finalCode = $EXIT.ESCALATE }
        }
        'VERIFIED' {
            $stateNote = if ($natsRun) {
                "NATS is at the target version $((Get-NatsRunFacts).TargetVersion). Backups are in $($script:RunDir)."
            } else { "PostgreSQL is at the target version. Backups are in $($script:RunDir)." }
        }
        'COMPLETE' {
            $stateNote = ''
        }
    }

    $stateNote = Add-RunSideEffectNotes -StateNote $stateNote -Report $script:Report

    # A NATS update that ended early: say how far NATS got.
    if ($script:Report.Contains('NatsStatus') -and "$($script:Report['NatsStatus'])" -eq 'UPDATING') {
        $finalNatsStage = (Get-NatsRunFacts).Stage
        $script:Report['NatsStatus'] = if ($finalNatsStage -eq 'REVERTED') { 'UPDATE_FAILED_REVERTED' }
            elseif ($finalNatsStage -eq 'COMMITTED') { 'UPDATED' }
            elseif ($finalNatsStage -in @('','PLANNED','BACKING_UP','BACKED_UP')) { 'NOT_UPDATED' }
            else { 'UPDATE_FAILED' }
    }

    $script:Report.Stage   = $script:Stage
    $script:Report.Outcome = $Outcome
    # The transcript already holds the untruncated text; keep the RMM line readable.
    # Shorten the failure detail, never the state note: the note says what was left
    # behind, which is what an operator acts on.
    $detailMax = 900
    if ($stateNote) { $detailMax = [math]::Max(300, 900 - $stateNote.Length - 38) }
    $script:Report.Detail  = Format-ShortText ((@((Format-ShortText $Detail $detailMax), $stateNote) | Where-Object { $_ }) -join ' ') 900
    if ($Detail -and "$Detail".Length -gt $detailMax) { Write-Log "Full detail: $Detail" INFO }
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

    if ($script:WorkRootProtected) {
        try {
            Write-AtomicJson -Path (Join-Path $script:LogDir 'last-result.json') -InputObject $script:Report
            if (Test-Path -LiteralPath $script:RunDir) {
                Write-AtomicJson -Path (Join-Path $script:RunDir 'result.json') -InputObject $script:Report
            }
        } catch { Write-Log "Could not write last-result.json: $($_.Exception.Message)" WARN }
    }

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
# WorkRoot trust boundary
#
# The work root holds a downloaded installer, privileged database dumps and a
# cold copy. A marker filename alone is not proof that the folder is ours: an
# ordinary user could plant that marker and junctions below a writable parent
# such as a typical C:\temp.
# These helpers fail closed on reparse points and verify the exact ACL we set.
# Well-known SIDs keep the checks language-neutral.
# ---------------------------------------------------------------------------
function Get-WorkRootSentinelText {
    # NEVER change this text, not even when the script is renamed. Test-WorkRootSentinel
    # compares it exactly, so a new text would make any existing WorkRoot refuse its
    # own folder.
    return 'Created by Update-VeeamPostgres.ps1. Marks this folder as safe for the script to lock down and clean up.'
}

# Recovery artifacts are trusted only when owned by SYSTEM or Administrators.
function Test-TrustedOwner {
    param([string] $Path)
    try {
        $owner = (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        return ($owner -eq 'S-1-5-18' -or $owner -eq 'S-1-5-32-544')
    } catch { return $false }
}

function Test-PathTreeHasReparsePoint {
    param(
        [Parameter(Mandatory)][string] $Path,
        [switch] $IncludeDescendants
    )
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $pathRoot = [IO.Path]::GetPathRoot($full)
        $current = $pathRoot
        $relative = $full.Substring($pathRoot.Length)
        foreach ($part in @($relative -split '[\\/]' | Where-Object { $_ })) {
            $current = Join-Path $current $part
            try { $attributes = [IO.File]::GetAttributes($current) }
            catch [IO.FileNotFoundException] { break }
            catch [IO.DirectoryNotFoundException] { break }
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
        }

        if ($IncludeDescendants -and (Test-Path -LiteralPath $full -PathType Container)) {
            $pending = New-Object 'System.Collections.Generic.Queue[string]'
            $pending.Enqueue($full)
            while ($pending.Count -gt 0) {
                $directory = $pending.Dequeue()
                foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
                    if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
                    if ($child.PSIsContainer) { $pending.Enqueue($child.FullName) }
                }
            }
        }
        return $false
    } catch {
        # An ACL or path we cannot inspect is not a safe place for privileged data.
        return $true
    }
}

function Test-DirectoryHasReparseChild {
    param([Parameter(Mandatory)][string] $Path)
    try {
        foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
        }
        return $false
    } catch { return $true }
}

function Test-RegularTrustedFile {
    param([Parameter(Mandatory)][string] $Path)
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { return $false }
        if (-not (Test-TrustedOwner $Path)) { return $false }
        $trustedSids = @('S-1-5-18','S-1-5-32-544')
        $dangerous = [int64]([System.Security.AccessControl.FileSystemRights]::Write -bor
                             [System.Security.AccessControl.FileSystemRights]::Delete -bor
                             [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                             [System.Security.AccessControl.FileSystemRights]::TakeOwnership) -bor
                     [int64]0x10000000 -bor [int64]0x40000000
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
            if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                $trustedSids -notcontains $rule.IdentityReference.Value -and
                ([int64]$rule.FileSystemRights -band $dangerous) -ne 0) {
                return $false
            }
        }
        return $true
    } catch { return $false }
}

function Test-ProtectedFolderAcl {
    param([Parameter(Mandatory)][string] $Path)
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { return $false }
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        if (-not $acl.AreAccessRulesProtected) { return $false }
        if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { return $false }

        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        if ($rules.Count -ne 2) { return $false }
        $requiredInheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                               [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            $matching = @($rules | Where-Object { $_.IdentityReference.Value -eq $sid })
            if ($matching.Count -ne 1) { return $false }
            $rule = $matching[0]
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
                $rule.IsInherited -or
                [int]$rule.FileSystemRights -ne [int][System.Security.AccessControl.FileSystemRights]::FullControl -or
                [int]$rule.InheritanceFlags -ne [int]$requiredInheritance -or
                $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
                return $false
            }
        }
        return $true
    } catch { return $false }
}

# The parent must not let a non-privileged principal delete/replace children or
# rewrite the parent's ACL. Create-directory permission alone is tolerated: new
# folders use an unpredictable protected staging name and an atomic rename.
function Test-SafeWorkRootParent {
    param([Parameter(Mandatory)][string] $Path)
    try {
        if (Test-PathTreeHasReparsePoint -Path $Path) { return $false }
        $trustedSids = @(
            'S-1-5-18',       # SYSTEM
            'S-1-5-32-544',   # Administrators
            'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
        )
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
        if ($currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $trustedSids += $currentIdentity.User.Value
        }
        $dangerous = [int64]([System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                             [System.Security.AccessControl.FileSystemRights]::Delete -bor
                             [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                             [System.Security.AccessControl.FileSystemRights]::TakeOwnership) -bor
                     [int64]0x10000000 -bor # GENERIC_ALL
                     [int64]0x40000000      # GENERIC_WRITE

        # Validate every existing namespace component, not just the immediate
        # parent. Otherwise a protected parent can still be swapped by someone
        # who can delete it through its own parent.
        $resolvedPath = [IO.Path]::GetFullPath($Path)
        $pathRoot = [IO.Path]::GetPathRoot($resolvedPath)
        $full = if ($resolvedPath.TrimEnd('\') -ieq $pathRoot.TrimEnd('\')) { $pathRoot } else { $resolvedPath.TrimEnd('\') }
        $components = @($pathRoot)
        $current = $pathRoot
        $relative = $full.Substring($pathRoot.Length)
        foreach ($part in @($relative -split '[\\/]' | Where-Object { $_ })) {
            $current = Join-Path $current $part
            $components += $current
        }
        foreach ($component in $components) {
            $item = Get-Item -LiteralPath $component -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { return $false }
            $acl = Get-Acl -LiteralPath $component -ErrorAction Stop
            if ($trustedSids -notcontains $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value) { return $false }
            foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
                if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
                if ($trustedSids -contains $rule.IdentityReference.Value) { continue }
                if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
                if (([int64]$rule.FileSystemRights -band $dangerous) -ne 0) { return $false }
            }
        }
        return $true
    } catch { return $false }
}

# Lock a folder to SYSTEM + Administrators only, replacing its whole DACL, then
# read it back. Set-Acl can report success even when a provider did not produce
# the intended descriptor, so callers rely on the verification result.
function Protect-Folder {
    param([Parameter(Mandatory)][string] $Path)
    try {
        if (Test-PathTreeHasReparsePoint -Path $Path) { return $false }
        $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
        $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($system, $admins)) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        $acl.SetOwner($admins)
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
        return (Test-ProtectedFolderAcl $Path)
    } catch { return $false }
}

function New-ProtectedDirectory {
    param([Parameter(Mandatory)][string] $Path)
    $stage = $null
    try {
        $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $parent = [IO.Directory]::GetParent($full).FullName
        if (-not (Test-SafeWorkRootParent $parent) -or (Test-Path -LiteralPath $full)) { return $false }
        $stage = Join-Path $parent ('.veeam-pg-stage-' + [guid]::NewGuid().ToString('N'))
        $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
        $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $stageAcl = New-Object System.Security.AccessControl.DirectorySecurity
        $stageAcl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($system, $admins)) {
            $stageAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        $stageAcl.SetOwner($admins)

        # Create with the final DACL in the same native operation. Creating first
        # and calling Set-Acl later leaves a writable C:\ staging directory open
        # to a junction-swap race on standard Windows ACLs.
        $stageInfo = New-Object System.IO.DirectoryInfo($stage)
        if ($PSVersionTable.PSEdition -eq 'Core') {
            [System.IO.FileSystemAclExtensions]::Create($stageInfo, $stageAcl)
        } else {
            $stageInfo.Create($stageAcl)
        }
        if (-not (Test-ProtectedFolderAcl $stage)) { return $false }
        if (Test-PathTreeHasReparsePoint -Path $stage -IncludeDescendants) { return $false }
        if (@(Get-ChildItem -LiteralPath $stage -Force -ErrorAction Stop).Count -ne 0) { return $false }
        [IO.Directory]::Move($stage, $full)
        $stage = $null
        return ((Test-ProtectedFolderAcl $full) -and -not (Test-PathTreeHasReparsePoint -Path $full -IncludeDescendants))
    } catch {
        return $false
    } finally {
        if ($stage -and (Test-Path -LiteralPath $stage) -and
            (Test-ProtectedFolderAcl $stage) -and
            -not (Test-PathTreeHasReparsePoint -Path $stage -IncludeDescendants)) {
            try { [IO.Directory]::Delete($stage, $true) } catch {}
        }
    }
}

function Test-WorkRootSentinel {
    param([Parameter(Mandatory)][string] $Path)
    $sentinel = Join-Path $Path '.veeam-pg-updater'
    if (-not (Test-RegularTrustedFile $sentinel)) { return $false }
    try {
        $content = (Get-Content -LiteralPath $sentinel -Raw -ErrorAction Stop).TrimEnd([char[]]"`r`n")
        return ($content -ceq (Get-WorkRootSentinelText))
    } catch { return $false }
}

function Get-TrustedLegacyRecoveryMarker {
    param(
        [Parameter(Mandatory)][string] $CurrentWorkRoot,
        [string] $LegacyWorkRoot = 'C:\temp\VeeamPgUpdate'
    )
    try {
        $current = [IO.Path]::GetFullPath($CurrentWorkRoot).TrimEnd('\')
        $legacy = [IO.Path]::GetFullPath($LegacyWorkRoot).TrimEnd('\')
        if ($current -ieq $legacy) { return $null }
        $marker = Join-Path $legacy 'CHANGES-IN-PROGRESS.marker'
        if ((Test-PathTreeHasReparsePoint -Path $marker) -or -not (Test-RegularTrustedFile $marker)) { return $null }
        return $marker
    } catch { return $null }
}

function Get-ValidatedCompletedRunManifest {
    param([Parameter(Mandatory)][string] $RunDirectory)
    try {
        $fullRun = [IO.Path]::GetFullPath($RunDirectory).TrimEnd('\')
        $runId = [IO.Path]::GetFileName($fullRun)
        if ($runId -notmatch '^\d{8}-\d{6}-\d{3}-\d+$') { return $null }
        $statePath = Join-Path $fullRun 'recovery-state.json'
        if (-not (Test-RegularTrustedFile $statePath)) { return $null }
        $manifest = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        foreach ($required in @('SchemaVersion','RunId','RunDir','Stage')) {
            if ($manifest.PSObject.Properties.Name -notcontains $required) { return $null }
        }
        $boundRun = [IO.Path]::GetFullPath("$($manifest.RunDir)").TrimEnd('\')
        if ([int]$manifest.SchemaVersion -notin @(1, 2) -or
            "$($manifest.Stage)" -cne 'COMPLETE' -or
            "$($manifest.RunId)" -cne $runId -or
            $boundRun -ine $fullRun) {
            return $null
        }
        return $manifest
    } catch { return $null }
}

function Initialize-WorkRoot {
    param([Parameter(Mandatory)][string] $Path)
    try {
        $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $root = [IO.Path]::GetPathRoot($full).TrimEnd('\')
    } catch {
        return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$Path; Reason="invalid WorkRoot path: $($_.Exception.Message)" }
    }
    if ($full -eq $root) {
        return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="$Path is the root of a drive or share" }
    }
    if (Test-PathTreeHasReparsePoint -Path $full) {
        return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="$full or one of its ancestors is a reparse point" }
    }

    $parent = [IO.Directory]::GetParent($full).FullName
    if (-not (Test-Path -LiteralPath $parent)) {
        # A missing parent is never created: taking over an arbitrary parent would
        # be destructive. The default's parent, C:\ProgramData, always exists.
        return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="parent directory does not exist: $parent" }
    }
    if (-not (Test-SafeWorkRootParent $parent)) {
        return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="parent directory is replaceable or not trusted: $parent" }
    }

    if (-not (Test-Path -LiteralPath $full)) {
        if (-not (New-ProtectedDirectory $full)) {
            return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="could not create a protected WorkRoot at $full" }
        }
    }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSIsContainer) {
        return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="$full is not a directory" }
    }
    if (Test-DirectoryHasReparseChild -Path $full) {
        return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="$full contains a reparse point" }
    }

    try { $children = @(Get-ChildItem -LiteralPath $full -Force -ErrorAction Stop) }
    catch {
        return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="could not enumerate $full safely: $($_.Exception.Message)" }
    }
    if ($children.Count -eq 0) {
        if (-not (Test-ProtectedFolderAcl $full)) {
            return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="$full is empty but does not already have the protected SYSTEM/Administrators ACL" }
        }
        $sentinel = Join-Path $full '.veeam-pg-updater'
        try {
            Set-Content -LiteralPath $sentinel -Value (Get-WorkRootSentinelText) -Encoding UTF8 -NoNewline -ErrorAction Stop
            if (-not (Test-TrustedOwner $sentinel)) {
                $sentinelAcl = Get-Acl -LiteralPath $sentinel -ErrorAction Stop
                $sentinelAcl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
                Set-Acl -LiteralPath $sentinel -AclObject $sentinelAcl -ErrorAction Stop
            }
        } catch {
            return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="could not write the trusted WorkRoot sentinel: $($_.Exception.Message)" }
        }
    } elseif (-not (Test-ProtectedFolderAcl $full) -or -not (Test-WorkRootSentinel $full)) {
        return [pscustomobject]@{ IsOurs=$false; Protected=$false; Path=$full; Reason="$full is non-empty but lacks the protected ACL and trusted sentinel created by this script" }
    }

    $protected = (Test-ProtectedFolderAcl $full) -and
                 (Test-WorkRootSentinel $full) -and
                 -not (Test-DirectoryHasReparseChild -Path $full)
    $reason = if ($protected) { '' } else { "WorkRoot trust verification failed after initialization: $full" }
    return [pscustomobject]@{ IsOurs=$protected; Protected=$protected; Path=$full; Reason=$reason }
}

# ---------------------------------------------------------------------------
# Start harness
# ---------------------------------------------------------------------------
# Earlier versions used C:\temp\VeeamPgUpdate. A trusted marker there is handled only
# from that WorkRoot, so all recorded paths stay bound to the evidence that created
# them. C:\ProgramData is the default because an existing C:\temp is normally writable
# by every signed-in user.
$legacyWorkRoot = 'C:\temp\VeeamPgUpdate'
$legacyMarker = Get-TrustedLegacyRecoveryMarker -CurrentWorkRoot $WorkRoot -LegacyWorkRoot $legacyWorkRoot
if ($legacyMarker) {
    $script:Report.IssueCode = 'LEGACY_WORKROOT_RECOVERY_REQUIRED'
    $script:Report.ActionRequired = "PAGE AN OPERATOR. Run this script with -Recover -WorkRoot '$legacyWorkRoot' before using the new default."
    Complete-Run $EXIT.ESCALATE 'LEGACY_WORKROOT_RECOVERY_REQUIRED' "A trusted changes-in-progress marker exists at the former default: $legacyMarker. The new WorkRoot was not used for maintenance."
}

$wrInit = Initialize-WorkRoot $WorkRoot
$script:WorkRootIsOurs    = $wrInit.IsOurs
$script:WorkRootProtected = $wrInit.Protected
if (-not $script:WorkRootProtected) {
    Write-Log "Work root rejected before logging: $($wrInit.Reason)" ERROR
    Complete-Run $EXIT.PREFLIGHT 'WORKROOT_UNSAFE' "The work root failed its ownership, ACL or reparse-point checks ($($wrInit.Reason)). No log or result file was written there."
}
if (-not (Test-Path -LiteralPath $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null }
# NOTE: the per-run folder under runs\ is only created by -Install, when there is
# something to put in it. Audit runs leave nothing behind but their log.

$script:Transcript = Join-Path $script:LogDir "VeeamPgUpdate_$($env:COMPUTERNAME)_$($script:Stamp).log"
try { Start-Transcript -Path $script:Transcript -IncludeInvocationHeader | Out-Null } catch {}

Write-Log "Veeam PostgreSQL and NATS Update - mode $($script:Report.Mode)" STEP
Write-Log "PowerShell: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
Write-Log "Work root : $WorkRoot"
Write-Log "Transcript: $($script:Transcript)"

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
    # Read through the key's own GetValue rather than Get-ItemProperty -Name. A
    # missing value makes Get-ItemProperty throw, and with ErrorActionPreference
    # 'Stop' PowerShell writes an alarming "TerminatingError" block into the RMM
    # transcript even though this function handles it. Probing for optional values
    # is normal here, so it must look normal in the log too.
    try {
        $item = Get-Item -LiteralPath $Key -ErrorAction SilentlyContinue
        if (-not $item) { return $null }
        return $item.GetValue($Name)
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
        # The VBR module holds a live connection to the Veeam Backup Service. Restarting
        # that service kills it, and every later cmdlet then fails with "Remote
        # connection was terminated. Either re-establish remote connection or use local
        # one, ex. Connect-VBRServer -Server localhost". Reconnect explicitly after any
        # service restart, or the final activity check fails and schedules stay off.
        if ($Reconnect -and $failed.Count -eq 0) {
            if (Get-Command Disconnect-VBRServer -ErrorAction SilentlyContinue) {
                try { Disconnect-VBRServer -ErrorAction Stop | Out-Null } catch {}
            }
            if (Get-Command Connect-VBRServer -ErrorAction SilentlyContinue) {
                try { Connect-VBRServer -Server localhost -ErrorAction Stop | Out-Null }
                catch { $failed += "Connect-VBRServer -Server localhost failed: $($_.Exception.Message)" }
            } else {
                $failed += 'Connect-VBRServer is unavailable, so the VBR connection cannot be re-established after the service restart'
            }
        }
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
        $jobs = @()
        try {
            $jobs = @(& $def.Get -ErrorAction Stop)
        } catch {
            # A feature the licence does not include cannot have jobs, so it cannot
            # start work during the outage. Below Enterprise Plus, for example,
            # Get-VBRApplicationBackupJob throws "This functionality is available in
            # the Enterprise Plus edition only." Record it and move on. Every other
            # failure still fails closed, because then the family may well exist.
            if (Test-VeeamEditionBlockedError $_) {
                Write-Log "  $($def.Get): $(Format-ShortText $_.Exception.Message 200) This edition cannot run $($def.Family) jobs, so there are none to control." WARN
                continue
            }
            throw "$($def.Get) failed while inventorying $($def.Family) schedules: $($_.Exception.Message)"
        }
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
    # Start returns while VB365 is still Preparing: VB365 first lets repository work
    # finish, for up to -WaitForSessionsTimeoutMinutes, and only then reports Running.
    # A run that checked once gave up on a healthy session after one second. Poll for
    # Running; a Preparing session is not yet a barrier. Any other state, or still
    # preparing after the wait plus five minutes, fails and the rollback releases it.
    $pollSeconds = 10
    $maxPolls = [int][math]::Ceiling((($TimeoutMinutes + 5) * 60) / $pollSeconds)
    $state = ''
    $lastLogged = ''
    for ($poll = 1; $poll -le $maxPolls; $poll++) {
        $verified = Get-VBORepositoryMaintenanceSession -Id $session.Id -ErrorAction Stop
        $state = if ($verified) { "$($verified.State)" } else { 'missing' }
        if ($state -eq 'Running') { break }
        if ($state -notin @('Initialized','Preparing')) {
            $why = ''
            if ($verified -and $verified.PSObject.Properties.Name -contains 'ErrorMessage' -and $verified.ErrorMessage) { $why = ": $($verified.ErrorMessage)" }
            throw "VB365 maintenance session $sessionId did not reach Running (state=$state)$why"
        }
        if ($state -ne $lastLogged -or ($poll % 30) -eq 0) {
            Write-Log "  VB365 maintenance session $sessionId is $state; waiting for VB365 to finish preparing it"
            $lastLogged = $state
        }
        Start-Sleep -Seconds $pollSeconds
    }
    if ($state -ne 'Running') {
        throw "VB365 maintenance session $sessionId was still $state after $($TimeoutMinutes + 5) minutes"
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
        [switch] $AssumeReturnedActive,
        # States that mean "ended" for THIS caller's product only. VB365 marks a job
        # session that was cut off as Disconnected and never resumes it, while VBR
        # uses Disconnected for live work, so it stays active everywhere else.
        [string[]] $EndedStates = @()
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
        if ($terminal -contains $state -or $EndedStates -contains $state) { continue }
        if ($activeStates -notcontains $state) {
            throw [System.NotSupportedException]::new("$Prefix returned unknown session state '$state'; refusing to assume the server is idle")
        }
        $labels += "${Prefix}:$state"
    }
    return $labels
}

# Judges a Queued VB365 organisation sync from its ScheduledTime:
#   Later - booked beyond the guard window. Veeam documents this as the normal
#           state between the daily syncs, so it does not hold the run.
#   Due   - overdue by less than the stuck limit, starting within the guard window,
#           or with no readable time. The run waits for it.
#   Stuck - overdue by more than the stuck limit and never started. A sync booked
#           days ago that never ran is not writing the organisation cache, so the
#           run warns and does not wait 12 hours for it.
# A time with no zone is read both as UTC and as local time. It is Later only if
# both readings are, and Stuck only if both readings are, so a wrong guess makes
# the run wait. A sync that starts later is still caught by the activity read just
# before services stop.
function Get-Vb365QueuedSyncTiming {
    param(
        [Parameter(Mandatory)] $CurrentState,
        [int] $GuardMinutes = 15,
        [int] $StuckAfterMinutes = 60,
        [datetime] $NowUtc = [datetime]::UtcNow
    )
    $names = @($CurrentState.PSObject.Properties.Name)
    if ($names -notcontains 'ScheduledTime') { return 'Due' }
    # A start time on a Queued sync is not a documented combination: wait.
    if ($names -contains 'StartTime' -and $null -ne $CurrentState.StartTime) { return 'Due' }
    $scheduled = $CurrentState.ScheduledTime
    if ($scheduled -is [DateTimeOffset]) { $scheduled = $scheduled.UtcDateTime }
    if ($scheduled -isnot [datetime] -or $scheduled.Year -le 1900) { return 'Due' }
    $readings = if ($scheduled.Kind -eq [DateTimeKind]::Unspecified) {
        @([datetime]::SpecifyKind($scheduled, [DateTimeKind]::Utc),
          [datetime]::SpecifyKind($scheduled, [DateTimeKind]::Local).ToUniversalTime())
    } else {
        @($scheduled.ToUniversalTime())
    }
    $guard = $NowUtc.AddMinutes($GuardMinutes)
    $stuckBefore = $NowUtc.AddMinutes(-$StuckAfterMinutes)
    if (@($readings | Where-Object { $_ -le $guard }).Count -eq 0) { return 'Later' }
    if (@($readings | Where-Object { $_ -ge $stuckBefore }).Count -eq 0) { return 'Stuck' }
    return 'Due'
}

# Say once per organisation per run that its sync is stuck, in the log and in the
# RMM summary. The idle check runs many times while it waits.
function Write-Vb365StuckSyncOnce {
    param([Parameter(Mandatory)][string] $Organization, $ScheduledTime)
    $seen = Get-Variable -Name Vb365StuckSyncSeen -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $seen) {
        $seen = @{}
        Set-Variable -Name Vb365StuckSyncSeen -Scope Script -Value $seen
    }
    if ($seen.ContainsKey($Organization)) { return }
    $seen[$Organization] = $true
    $when = if ($ScheduledTime -is [datetime]) { $ScheduledTime.ToString('yyyy-MM-dd HH:mm') } else { "$ScheduledTime" }
    Write-Log "VB365 organisation sync for $Organization was booked for $when and never started. It is stuck, not running, so the update does not wait for it. VB365 has not refreshed this organisation's data since then: check VB365 on this server." WARN
    Add-ReportListItem -Field 'Vb365SyncStuck' -Value "$Organization (queued since $when)"
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
            # Queued is VB365's resting state between its daily syncs: it only books
            # the next one. Wait only when that sync is due, or its time is unreadable.
            # One overdue for more than an hour that never started is stuck: warn, do
            # not wait.
            if ($status -eq 'Queued') {
                $timing = Get-Vb365QueuedSyncTiming -CurrentState $current.Value
                if ($timing -eq 'Later') { continue }
                if ($timing -eq 'Stuck') {
                    Write-Vb365StuckSyncOnce -Organization $organizationLabel -ScheduledTime $current.Value.ScheduledTime
                    continue
                }
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

# Append one item to a comma-separated RMM summary field. Safe where the report
# does not exist, because the unit tests run these functions on their own.
function Add-ReportListItem {
    param([Parameter(Mandatory)][string] $Field, [Parameter(Mandatory)][string] $Value)
    $report = Get-Variable -Name Report -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $report) { return }
    $existing = "$($report[$Field])"
    $report[$Field] = $(if ($existing) { "$existing, $Value" } else { $Value })
}

# The VBR and VB365 consoles are clients. Jobs and restores run inside the Veeam
# services, so closing a console cannot stop server-side work, and Veeam's own
# procedure closes the console before stopping services (KB2991). An Explorer is
# different: it runs its own item-level restore, so Explorers are never closed
# here and stay a barrier that waits and then fails closed.
function Get-VeeamConsoleProcesses {
    param([bool] $Vbr, [bool] $Vb365)
    $processes = @(Get-Process -Name 'Veeam*' -ErrorAction SilentlyContinue)
    return @($processes | Where-Object {
        ($Vbr -and $_.ProcessName -eq 'Veeam.Backup.Shell') -or
        ($Vb365 -and $_.ProcessName -eq 'Veeam.Archiver.Shell')
    })
}

# True when every blocking label is an open Veeam console. Closing a console only
# helps then: while a job or an Explorer still blocks, closing it gains nothing and
# would kill a console an operator reopens to watch that job, every poll.
function Test-OnlyConsoleBlockers {
    param([object[]] $Labels)
    $all = @($Labels | Where-Object { "$_" })
    return ($all.Count -gt 0 -and
            @($all | Where-Object { "$_" -notlike 'UI:Veeam.Backup.Shell:PID*' -and "$_" -notlike 'UI:Veeam.Archiver.Shell:PID*' }).Count -eq 0)
}

# Close every open Veeam console rather than wait hours for a person to close it.
# Ask first, then force. The RMM runs as SYSTEM in session 0, where a console in a
# user's session has no window this process can message, so the forced close is
# the normal path. A console that will not close stays a blocker, and is not tried
# again on every poll, so the log does not fill with the same failure.
function Close-VeeamConsoleProcesses {
    param([bool] $Vbr, [bool] $Vb365, [ValidateRange(1,120)][int] $GraceSeconds = 10)
    $failedIds = Get-Variable -Name ConsoleCloseFailedIds -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $failedIds) {
        $failedIds = @{}
        Set-Variable -Name ConsoleCloseFailedIds -Scope Script -Value $failedIds
    }
    $results = @()
    foreach ($proc in @(Get-VeeamConsoleProcesses -Vbr $Vbr -Vb365 $Vb365)) {
        $name = "$($proc.ProcessName)"
        $procId = [int]$proc.Id
        $label = "${name}:PID$procId"
        if ($failedIds.ContainsKey($procId)) { continue }
        $session = "$(Get-CfgValue $proc 'SessionId' '?')"
        # Re-read by ID AND name. A PID can be reused once the console exits, and
        # the process that inherits it must never be touched.
        $isAlive = { @(Get-Process -Id $procId -ErrorAction SilentlyContinue | Where-Object { "$($_.ProcessName)" -eq $name }).Count -gt 0 }
        $method = ''
        $problem = ''
        $asked = $false
        try { $asked = [bool]$proc.CloseMainWindow() } catch {}
        if ($asked) {
            for ($i = 0; $i -lt $GraceSeconds -and (& $isAlive); $i++) { Start-Sleep -Seconds 1 }
            if (-not (& $isAlive)) { $method = 'closed' }
        }
        if (-not $method) {
            if (& $isAlive) {
                try { Stop-Process -Id $procId -Force -ErrorAction Stop } catch { $problem = "$($_.Exception.Message)" }
                for ($i = 0; $i -lt $GraceSeconds -and (& $isAlive); $i++) { Start-Sleep -Seconds 1 }
            }
            if (-not (& $isAlive)) { $method = 'forced' }
        }
        if ($method) {
            Write-Log "Closed the open Veeam console $label (session $session, $method) so the update does not wait for it. Anything unsaved in that console is lost." WARN
            Add-ReportListItem -Field 'ConsolesClosed' -Value "$label(session $session)"
        } else {
            $failedIds[$procId] = $true
            $why = if ($problem) { $problem } else { "still running after ${GraceSeconds}s" }
            Write-Log "Could not close the Veeam console ${label}: $why. It stays a blocker." WARN
        }
        $results += [pscustomobject]@{ Name=$name; Id=$procId; SessionId=$session; Closed=[bool]$method; Method=$method; Problem=$problem }
    }
    return @($results)
}

# Returns one short label per active operation. Every relevant query is fail-closed:
# absence/error never means idle when that workload family is installed.
# A session getter can be enumerated with no arguments only when it has a parameter
# set whose parameters are ALL optional. VBR ships getters where every set demands
# -Id, -Session or -Job; calling one of those bare fails with "Specify either -Id or
# -Session parameter", which would fail the whole idle test. Decide from the
# cmdlet's own metadata on the installed build,
# not from documentation, which differs between 13.0 and 13.1 and has gaps.
function Test-CommandCallableBare {
    param([Parameter(Mandatory)][string] $Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) { return $false }
    try {
        foreach ($set in @($command.ParameterSets)) {
            if (@($set.Parameters | Where-Object { $_.IsMandatory }).Count -eq 0) { return $true }
        }
    } catch {
        return $false   # Unreadable metadata is never treated as safe to call bare.
    }
    return $false
}

# Some getters pass parameter binding and then refuse at runtime, with Veeam's own
# message "Specify either -Id or -Session parameter". That means the cmdlet has no
# enumerate-everything mode on this build, which metadata alone cannot reveal.
function Test-NoAllSessionsError {
    param([Parameter(Mandatory)] $ErrorRecord)
    $message = ''
    try { $message = "$($ErrorRecord.Exception.Message)" } catch {}
    return ($message -match 'Specify\s+either\b.*\b(Id|Session)\b')
}

# Veeam refuses a cmdlet whose feature the installed licence edition does not
# include. A feature that cannot run cannot have jobs, so the family is genuinely
# empty rather than unreadable.
function Test-VeeamEditionBlockedError {
    param([Parameter(Mandatory)] $ErrorRecord)
    $message = ''
    try { $message = "$($ErrorRecord.Exception.Message)" } catch {}
    return ($message -match 'available in the .+ edition only' -or
            $message -match 'not supported by (your|the current) license' -or
            $message -match 'license does not (allow|include)')
}

# Ask Veeam what exists, tolerating a licence-edition refusal. A feature the
# licence excludes cannot have anything to enumerate, so an empty result is the
# true answer, not a gap. Warned once per run. ANY other failure is reported with
# its label and fails closed, and this is never used for a change to a job.
function Invoke-VeeamEnumeration {
    param(
        [Parameter(Mandatory)][string] $Label,
        [Parameter(Mandatory)][scriptblock] $Enumerate
    )
    try {
        return @(& $Enumerate)
    } catch {
        if (Test-VeeamEditionBlockedError $_) {
            $key = "enumeration:$Label"
            Set-UnusableSessionGetter $key "$Label is not available in this Veeam licence edition: $($_.Exception.Message)"
            Write-UnusableSessionGetterOnce $key '; nothing of that kind can exist on this edition, so it was not queried'
            return @()
        }
        throw "$Label failed: $($_.Exception.Message)"
    }
}

# Veeam refuses a PowerShell connection for an account with multi-factor
# authentication enabled, whatever cmdlet triggered it.
function Test-VeeamMfaBlockedError {
    param([Parameter(Mandatory)] $ErrorRecord)
    $message = ''
    try { $message = "$($ErrorRecord.Exception.Message)" } catch {}
    return ($message -match 'MFA-enabled user account' -or
            $message -match 'multi-factor authentication')
}

# Restarting the Veeam Backup Service kills the module's connection. Veeam says so
# in the error itself: "Remote connection was terminated. Either re-establish remote
# connection or use local one, ex. Connect-VBRServer -Server localhost".
function Test-VbrConnectionLostError {
    param([Parameter(Mandatory)] $ErrorRecord)
    $message = ''
    try { $message = "$($ErrorRecord.Exception.Message)" } catch {}
    return ($message -match 'Remote connection was terminated' -or
            $message -match 're-establish remote connection' -or
            $message -match 'Connect-VBRServer')
}

# Getters proven unusable on this build, so the idle check does not pay for them
# again. The install path polls this check repeatedly while waiting for Veeam work
# to finish, and the dead getters can cost over a minute a poll.
$script:UnusableSessionGetters = @{}

# Fetch the map, creating it on demand. The functions below are also exercised in
# isolation by the tests, where the script-scope variable does not exist yet, and
# StrictMode makes reading an unset variable a terminating error.
function Get-UnusableSessionGetterMap {
    $map = Get-Variable -Name UnusableSessionGetters -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $map) {
        $map = @{}
        Set-Variable -Name UnusableSessionGetters -Scope Script -Value $map
    }
    return $map
}

function Set-UnusableSessionGetter {
    param([Parameter(Mandatory)][string] $Command, [Parameter(Mandatory)][string] $Reason)
    $map = Get-UnusableSessionGetterMap
    if (-not $map.ContainsKey($Command)) {
        $map[$Command] = [pscustomobject]@{ Reason = $Reason; Logged = $false }
    }
}

function Test-UnusableSessionGetter {
    param([Parameter(Mandatory)][string] $Command)
    return (Get-UnusableSessionGetterMap).ContainsKey($Command)
}

# Say it once per run. A polling loop must not reprint the same warning every pass.
function Write-UnusableSessionGetterOnce {
    param([Parameter(Mandatory)][string] $Command, [string] $Suffix = '')
    if (-not (Test-UnusableSessionGetter $Command)) { return }
    $entry = (Get-UnusableSessionGetterMap)[$Command]
    if ($entry.Logged) { return }
    Write-Log "  $(Format-ShortText $entry.Reason 300)$Suffix" WARN
    $entry.Logged = $true
}

# Enumerate one session getter. Any failure is reported WITH the command name, so a
# log never leaves an operator guessing which of forty getters refused.
function Get-SessionsFromGetter {
    param([Parameter(Mandatory)][string] $Command)
    if (Test-UnusableSessionGetter $Command) {
        throw [System.NotSupportedException]::new((Get-UnusableSessionGetterMap)[$Command].Reason)
    }
    try {
        return @(& $Command -ErrorAction Stop)
    } catch {
        if (Test-NoAllSessionsError $_) {
            $reason = "$Command refuses to enumerate without -Id/-Session on this build: $($_.Exception.Message)"
            Set-UnusableSessionGetter $Command $reason
            throw [System.NotSupportedException]::new($reason)
        }
        # The licence does not include this feature, so it has no sessions. Classed
        # the same way: skipped when no configured family needs it, fail-closed when
        # one does, because that combination would contradict itself.
        if (Test-VeeamEditionBlockedError $_) {
            $reason = "$Command is not available in this Veeam licence edition: $($_.Exception.Message)"
            Set-UnusableSessionGetter $Command $reason
            throw [System.NotSupportedException]::new($reason)
        }
        # A dropped VBR connection is recoverable: reconnect and ask once more. Bound
        # the attempts per run so a genuinely broken service cannot loop.
        if (Test-VbrConnectionLostError $_) {
            $tries = Get-Variable -Name VbrReconnectAttempts -Scope Script -ValueOnly -ErrorAction SilentlyContinue
            if ($null -eq $tries) { $tries = 0 }
            if ($tries -lt 3) {
                Set-Variable -Name VbrReconnectAttempts -Scope Script -Value ($tries + 1)
                Write-Log "  $Command lost its VBR connection; re-establishing it and retrying (attempt $($tries + 1)/3)" WARN
                $reconnectProblems = @(Connect-VeeamModules -Vbr -Quiet -Reconnect)
                if ($reconnectProblems.Count -gt 0) {
                    throw "$Command failed and the VBR connection could not be re-established: $($reconnectProblems -join ' | ')"
                }
                try { return @(& $Command -ErrorAction Stop) }
                catch { throw "$Command failed again after re-establishing the VBR connection: $($_.Exception.Message)" }
            }
        }
        throw "$Command failed: $($_.Exception.Message)"
    }
}

function Get-ActiveVeeamWork {
    param([bool] $Vbr, [bool] $Vb365)
    $active = @()
    if ($Vbr) {
        foreach ($required in @('Get-VBRBackupSession','Get-VBRRestoreSession')) {
            if (-not (Get-Command $required -ErrorAction SilentlyContinue)) {
                throw [System.NotSupportedException]::new("$required is unavailable, so VBR activity cannot be checked safely")
            }
            if (-not (Test-CommandCallableBare $required)) {
                throw [System.NotSupportedException]::new("$required has no all-sessions parameter set on this build, so VBR activity cannot be checked safely")
            }
        }
        $active += @(Get-ActiveLabelsFromSessions -Sessions @(Get-SessionsFromGetter 'Get-VBRBackupSession') -Prefix 'VBR:Backup')
        $active += @(Get-ActiveLabelsFromSessions -Sessions @(Get-SessionsFromGetter 'Get-VBRRestoreSession') -Prefix 'VBR:Restore')

        # Protection-group rescans own their deployment work until the discovery
        # session completes. Get-VBRBackupSession does not reliably expose these,
        # so query both current and legacy discovery session types explicitly.
        if (Test-VbrFamilyInUse @('VBRProtection')) {
            if (-not (Get-Command Get-VBRSession -ErrorAction SilentlyContinue)) {
                throw [System.NotSupportedException]::new('Get-VBRSession is unavailable for configured protection groups')
            }
            foreach ($discoveryType in @('EpAgentDiscovery','EpAgentDiscoveryObsolete')) {
                $discoverySessions = @(Invoke-VeeamEnumeration -Label "Get-VBRSession -Type $discoveryType" -Enumerate {
                    Get-VBRSession -Type $discoveryType -ErrorAction Stop
                })
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
                if (-not (Test-CommandCallableBare $collector.Command)) {
                    # No all-sessions set on this build. If a configured family needs
                    # this getter, fail closed; otherwise there is nothing of that kind
                    # to enumerate, so record the gap and carry on.
                    if ($inUse) {
                        throw [System.NotSupportedException]::new("$($collector.Command) has no all-sessions parameter set on this build, so configured family $($collector.Families -join '/') cannot be checked safely")
                    }
                    Write-Log "  $($collector.Command) has no all-sessions parameter set on this build; no configured family needs it, so it was not queried" WARN
                    continue
                }
                $sessions = @()
                try {
                    $sessions = @(Get-SessionsFromGetter $collector.Command)
                } catch [System.NotSupportedException] {
                    # The getter exists but will not enumerate everything. Fail closed
                    # when a configured family depends on it; otherwise there is nothing
                    # of that kind here, so record the gap by name and carry on.
                    if ($inUse) { throw }
                    Set-UnusableSessionGetter $collector.Command "$($_.Exception.Message)"
                    Write-UnusableSessionGetterOnce $collector.Command '; no configured family needs it, so it was not queried'
                    continue
                }
                $active += @(Get-ActiveLabelsFromSessions -Sessions $sessions -Prefix $collector.Prefix -AssumeReturnedActive:([bool]$collector.Assume))
            }
        }

        # Explorer modules expose only a subset of sessions (often those started
        # through PowerShell), so these are supplemental to the process barrier
        # below. Every object returned by these active-session APIs is busy.
        # These are supplemental, so ANY failure here is recorded and skipped rather
        # than failing the idle proof. On some VBR 13 builds, Explorer modules cannot
        # construct their own services outside an Explorer session and throw a long
        # dependency-injection error; the process barrier is what actually covers
        # Explorer work, and the core session getters above are the real proof.
        foreach ($commandName in @('Get-VEADRestoreSession','Get-VEHANARestoreSession','Get-VEMDBRestoreSession',
                                    'Get-VEODRestoreSession','Get-VEORRestoreSession','Get-VEORRMANRestoreSession',
                                    'Get-VEPSQLRestoreSession','Get-VESQLPluginRestoreSession','Get-VESQLRDSRestoreSession',
                                    'Get-VESQLRestoreSession')) {
            if (Get-Command $commandName -ErrorAction SilentlyContinue) {
                if (-not (Test-CommandCallableBare $commandName)) {
                    Write-Log "  $commandName has no all-sessions parameter set on this build; it was not queried. The Explorer process barrier still applies." WARN
                    continue
                }
                try {
                    $active += @(Get-ActiveLabelsFromSessions -Sessions @(Get-SessionsFromGetter $commandName) -Prefix "VBR:$commandName" -AssumeReturnedActive)
                } catch {
                    Set-UnusableSessionGetter $commandName "$($_.Exception.Message)"
                    Write-UnusableSessionGetterOnce $commandName '; it was not queried. The Explorer process barrier still applies.'
                }
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
                $unstructuredSessions += @(Invoke-VeeamEnumeration -Label "Get-VBRUnstructuredBackupSession -Name '$escapedName*'" -Enumerate {
                    Get-VBRUnstructuredBackupSession -Name "${escapedName}*" -ErrorAction Stop
                })
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
                $needsPerBackup = -not $hasZeroArgumentSet
                if ($hasZeroArgumentSet) {
                    try {
                        $transferSessions = @(Get-SessionsFromGetter $commandName)
                    } catch [System.NotSupportedException] {
                        # Metadata advertised a zero-argument set, but the cmdlet refused
                        # at runtime. Fall back to the per-backup path rather than losing
                        # the family or failing the whole idle proof.
                        Write-Log "  $($_.Exception.Message); falling back to per-backup enumeration" WARN
                        $needsPerBackup = $true
                        $transferSessions = @()
                    }
                }
                if ($needsPerBackup) {
                    if (-not (Get-Command Get-VBRBackup -ErrorAction SilentlyContinue)) {
                        throw [System.NotSupportedException]::new("$commandName is available but Get-VBRBackup is not")
                    }
                    $allBackups = @(Invoke-VeeamEnumeration -Label "Get-VBRBackup (for $commandName)" -Enumerate {
                        Get-VBRBackup -ErrorAction Stop
                    })
                    foreach ($backup in $allBackups) {
                        $transferSessions += @(Invoke-VeeamEnumeration -Label "$commandName -Backup '$($backup.Name)'" -Enumerate {
                            & $commandName -Backup $backup -ErrorAction Stop
                        })
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
            try { $freshJobs = @(& $definition.Get -ErrorAction Stop) }
            catch { throw "$($definition.Get) failed while refreshing $($familyGroup.Name) activity: $($_.Exception.Message)" }
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
                try { $session = @(Get-VBRCDPSession -Policy $freshVbrObjects[$key] -Last -ErrorAction Stop) }
                catch { throw "Get-VBRCDPSession -Policy '$($entry.Name)' failed: $($_.Exception.Message)" }
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
        # Get-VBOJobSession returns every session ever recorded. A session that was
        # cut off ends as Disconnected and is never resumed, so an old one must not
        # hold the update forever. Running, Queued and Updating still count.
        $active += @(Get-ActiveLabelsFromSessions -Sessions @(Get-SessionsFromGetter 'Get-VBOJobSession') -Prefix 'VB365:Job' -EndedStates @('Disconnected'))
        # This cmdlet returns only the requested active restore sessions.
        try { $vboRestoreSessions = @(Get-VBORestoreSession -Status Running -ErrorAction Stop) }
        catch { throw "Get-VBORestoreSession -Status Running failed: $($_.Exception.Message)" }
        $active += @(Get-ActiveLabelsFromSessions -Sessions $vboRestoreSessions -Prefix 'VB365:Restore' -AssumeReturnedActive)
        # Organization synchronization writes the PostgreSQL-backed organization
        # cache rather than a backup repository, so repository maintenance does
        # not cover it. VB365 8.6 can synchronize five parts independently.
        $active += @(Get-ActiveVb365OrganizationSyncWork)

        foreach ($commandName in @('Get-VBODataRetrievalSession','Get-VBODataManagementSession',
                                    'Get-VBORepositorySynchronizeSession','Get-VBORepositoryUpgradeSession')) {
            if (Get-Command $commandName -ErrorAction SilentlyContinue) {
                # Data-retrieval sessions use the same status values as job sessions.
                $vboEnded = if ($commandName -eq 'Get-VBODataRetrievalSession') { @('Disconnected') } else { @() }
                $active += @(Get-ActiveLabelsFromSessions -Sessions @(Get-SessionsFromGetter $commandName) -Prefix "VB365:$commandName" -EndedStates $vboEnded)
            }
        }
        foreach ($commandName in @('Get-VBOExchangeItemRestoreSession','Get-VBOSharePointItemRestoreSession','Get-VBOTeamsItemRestoreSession')) {
            if (Get-Command $commandName -ErrorAction SilentlyContinue) {
                $active += @(Get-ActiveLabelsFromSessions -Sessions @(Get-SessionsFromGetter $commandName) -Prefix "VB365:$commandName" -AssumeReturnedActive)
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
        [string] $Context = 'before maintenance',
        # Close open Veeam consoles instead of waiting for a person to close them,
        # once they are the only thing left blocking. Only runs that change the
        # server pass this; an audit closes nothing.
        [switch] $CloseConsoles
    )
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $lastSummary = $null
    $lastHeartbeatMinute = -1
    while ($true) {
        $busy = @(Get-ActiveVeeamWork -Vbr $Vbr -Vb365 $Vb365)
        if ($CloseConsoles -and (Test-OnlyConsoleBlockers $busy)) {
            [void](Close-VeeamConsoleProcesses -Vbr $Vbr -Vb365 $Vb365)
            $busy = @(Get-ActiveVeeamWork -Vbr $Vbr -Vb365 $Vb365)
        }
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

# Apply the pre-generated Veeam PostgreSQL tuning and restart PostgreSQL, for a
# recovery that finishes a run whose installer completed. Mirrors STEP 19. Returns
# '' on success, or why it failed; it always tries to leave PostgreSQL running.
function Invoke-RecoveryPgTuning {
    param(
        [Parameter(Mandatory)][string] $TuningSql,
        [Parameter(Mandatory)][string] $PsqlPath,
        [Parameter(Mandatory)][string] $Port,
        [Parameter(Mandatory)][string] $ServiceName,
        [Parameter(Mandatory)][int] $ExpectedNum
    )
    # psql runs this file as the postgres superuser, so it must be ours.
    if (-not (Test-RegularTrustedFile $TuningSql) -or (Get-Item -LiteralPath $TuningSql).Length -eq 0) {
        return "the tuning SQL $TuningSql is missing, empty or untrusted"
    }
    $applied = Invoke-Native $PsqlPath @('-U','postgres','-h','127.0.0.1','-p',"$Port",'-w','-v','ON_ERROR_STOP=1','-f',$TuningSql)
    if ($applied.StdErr) { Write-Log "    $($applied.StdErr)" WARN }
    if ($applied.ExitCode -ne 0) { return "psql returned $($applied.ExitCode) applying the tuning SQL" }

    $problem = ''
    try {
        # No -Force: an unexpected dependent must stop this, never be cascaded.
        Stop-Service -Name $ServiceName -ErrorAction Stop
        $stopped = $false
        for ($i = 1; $i -le 12; $i++) {
            if ("$((Get-Service -Name $ServiceName -ErrorAction Stop).Status)" -eq 'Stopped') { $stopped = $true; break }
            Start-Sleep -Seconds 5
        }
        if (-not $stopped) { $problem = 'PostgreSQL did not stop for the tuning restart' }
    } catch { $problem = "PostgreSQL could not be stopped for the tuning restart: $($_.Exception.Message)" }
    try {
        $now = @(Get-Service -Name $ServiceName -ErrorAction Stop)
        if ($now.Count -gt 0 -and "$($now[0].Status)" -eq 'Stopped') { Start-Service -Name $ServiceName -ErrorAction Stop }
    } catch { if (-not $problem) { $problem = "PostgreSQL could not be started after tuning: $($_.Exception.Message)" } }
    for ($i = 1; $i -le 24; $i++) {
        $c = Invoke-Native $PsqlPath @('-U','postgres','-h','127.0.0.1','-p',"$Port",'-w','-At','-c','SHOW server_version_num;')
        if ($c.ExitCode -eq 0 -and "$($c.StdOut)" -match '^\d+$' -and [int]$c.StdOut -eq $ExpectedNum) { return $problem }
        Start-Sleep -Seconds 5
    }
    return (@($problem, "PostgreSQL did not answer at server_version_num $ExpectedNum after the tuning restart") | Where-Object { $_ }) -join '; '
}

function Invoke-ExplicitRecovery {
    param([Parameter(Mandatory)][string] $MarkerPath, [Parameter(Mandatory)] $Cfg)

    if ((Test-PathTreeHasReparsePoint -Path $MarkerPath) -or -not (Test-RegularTrustedFile $MarkerPath)) {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'UNTRUSTED_RECOVERY_MARKER' 'The recovery marker is missing, untrusted, or resolves through a reparse point. No automatic action was taken.'
    }
    $marker = $null
    try { $marker = Get-Content -LiteralPath $MarkerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'LEGACY_OR_INVALID_MARKER' "The marker is not a versioned recovery pointer. No automatic action was taken. Inspect it and recover manually: $($_.Exception.Message)"
    }
    foreach ($required in @('SchemaVersion','RunId','RunDir','StateFile','InstallerStarted','Stage')) {
        if ($marker.PSObject.Properties.Name -notcontains $required) {
            $script:Stage = 'INSTALLING'
            Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_MARKER' "Recovery marker is missing '$required'. No automatic action was taken."
        }
    }

    $runsRootPath = [IO.Path]::GetFullPath((Join-Path $WorkRoot 'runs')).TrimEnd('\')
    $runsRoot = $runsRootPath + '\'
    try {
        $statePath = [IO.Path]::GetFullPath("$($marker.StateFile)")
        $runPath = [IO.Path]::GetFullPath("$($marker.RunDir)").TrimEnd('\')
    } catch {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_PATH' "Recovery path is invalid: $($_.Exception.Message)"
    }
    $runParent = try { [IO.Directory]::GetParent($runPath).FullName.TrimEnd('\') } catch { '' }
    $runLeaf = [IO.Path]::GetFileName($runPath)
    if (-not $statePath.StartsWith($runsRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (($runPath + '\').StartsWith($runsRoot, [StringComparison]::OrdinalIgnoreCase)) -or
        $runParent -ine $runsRootPath -or
        $runLeaf -notmatch '^\d{8}-\d{6}-\d{3}-\d+$' -or
        "$($marker.RunId)" -cne $runLeaf -or
        $statePath -ine (Join-Path $runPath 'recovery-state.json') -or
        (Test-PathTreeHasReparsePoint -Path $runsRootPath) -or
        (Test-PathTreeHasReparsePoint -Path $statePath)) {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_PATH' 'Recovery paths must be non-reparse direct children of this WorkRoot\runs directory and match the recorded run ID.'
    }
    if (-not (Test-Path -LiteralPath $runPath -PathType Container) -or
        -not (Test-TrustedOwner $runPath) -or
        -not (Test-RegularTrustedFile $statePath)) {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'UNTRUSTED_RECOVERY_STATE' "Recovery directory/state is missing, reparse-backed, or not owned by SYSTEM/Administrators: $statePath"
    }
    try { $state = Get-Content -LiteralPath $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_STATE' "Could not parse $statePath : $($_.Exception.Message)"
    }
    foreach ($required in @('SchemaVersion','RunId','RunDir','InstallerStarted','Stage')) {
        if ($state.PSObject.Properties.Name -notcontains $required) {
            $script:Stage = 'INSTALLING'
            Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_STATE' "Recovery state is missing '$required'. No automatic action was taken."
        }
    }
    # SchemaVersion 1 is a PostgreSQL run; 2 is a NATS run (Change = NATS).
    $stateSchema = 0
    try { $stateSchema = [int]$state.SchemaVersion } catch {}
    $markerSchema = 0
    try { $markerSchema = [int]$marker.SchemaVersion } catch {}
    $stateChange = "$(Get-CfgValue $state 'Change' '')"
    $schemaOk = ($stateSchema -eq 1 -and -not $stateChange) -or ($stateSchema -eq 2 -and $stateChange -ceq 'NATS')
    if (-not $schemaOk -or $markerSchema -ne $stateSchema -or
        "$($state.RunDir)" -ine $runPath -or
        "$($state.RunId)" -cne $runLeaf -or
        "$($state.RunId)" -cne "$($marker.RunId)" -or
        "$($state.Stage)" -cne "$($marker.Stage)" -or
        [bool]$state.InstallerStarted -ne [bool]$marker.InstallerStarted) {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_STATE' 'Recovery marker/state schema, run ID, stage, or run-directory binding is invalid.'
    }

    $script:RunDir = $runPath
    # Every Save-RecoveryState below writes the marker with $script:Stamp as its RunId.
    # Keep it the original run's, or a recovery that saved and then failed leaves a
    # marker the next -Recover refuses as not matching its state.
    $script:Stamp = $runLeaf
    $script:RecoveryState = $state
    $script:Report.RecoveryRunDir = $runPath
    $script:Stage = "$($state.Stage)"
    $script:Report.VeeamProducts = "$(Get-CfgValue $state 'Products' '')"
    $script:Report.PgInstalled = "$(Get-CfgValue $state 'OriginalVersion' '')"
    $script:Report.PgTarget = "$(Get-CfgValue $state 'TargetVersion' '')"
    $script:Vb365MaintenanceSessionId = "$(Get-CfgValue $state 'Vb365MaintenanceSessionId' '')"
    $script:Vb365MaintenancePending = [bool](Get-CfgValue $state 'Vb365MaintenancePending' $false)

    # A NATS run (VB365). PostgreSQL was never stopped, so there is no installer to
    # finish. Put the old NATS back, or keep the new one when VB365 already ran on it
    # and NATS answers at that version, then restore services and jobs as usual.
    $natsRun = ($stateChange -ceq 'NATS')
    $natsFinish = $false
    $natsKeptNew = $false
    if ($natsRun) {
        $natsPlan = Get-CfgValue $state 'NatsPlan' $null
        $natsStage = "$(Get-CfgValue $state 'NatsStage' '')"
        if (-not $natsPlan) {
            Complete-Run $EXIT.ESCALATE 'INVALID_RECOVERY_STATE' 'The NATS recovery state holds no NATS plan. No automatic action was taken.'
        }
        $script:Report.NatsInstalled = "$($natsPlan.OldVersion)"
        $script:Report.NatsTarget = "$($natsPlan.TargetVersion)"
        $script:Report.NatsStatus = 'UPDATING'
        if ($script:Stage -eq 'VERIFIED' -and $natsStage -eq 'COMMITTED') {
            $natsFinish = $true
            $natsKeptNew = $true
            Write-Log "VB365 was verified on NATS $($natsPlan.TargetVersion) before the run stopped. Finishing the run." WARN
        } elseif ($script:Stage -eq 'SERVICES_STOPPED' -and $natsStage -in @('SWAP_STARTED','SWAPPED','NATS_VERIFIED','VEEAM_STARTED','REVERTING')) {
            if ($natsStage -eq 'VEEAM_STARTED' -and (Test-NatsRunningAt -Plan $natsPlan -Version "$($natsPlan.TargetVersion)" -ImagePath "$($natsPlan.NewImagePath)")) {
                $natsKeptNew = $true
                Write-Log "The run stopped after VB365 was started on NATS $($natsPlan.TargetVersion), and NATS answers at that version. Keeping it and finishing the run." WARN
            } else {
                $binaryRevert = ($natsStage -eq 'VEEAM_STARTED' -or ($natsStage -eq 'REVERTING' -and "$(Get-CfgValue $state 'NatsRevertMode' '')" -eq 'Binary'))
                $liveVeeam = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue | Where-Object { "$($_.Status)" -ne 'Stopped' })
                if (-not $binaryRevert -and $liveVeeam.Count -gt 0) {
                    # VB365 never used the new NATS, but someone started Veeam by hand. The
                    # store copy may no longer be safe to put back. Change nothing.
                    $script:Report.IssueCode = 'NATS_RECOVERY_REQUIRES_OPERATOR'
                    $script:Report.ActionRequired = 'PAGE AN OPERATOR. NATS may be half-switched and Veeam service(s) were started by hand. Stop the Veeam services, then run -Recover again.'
                    Complete-Run $EXIT.ESCALATE 'RECOVERY_DIAGNOSTIC_ONLY' "NATS stage is $natsStage, but Veeam service(s) are running ($(@($liveVeeam | ForEach-Object { $_.Name }) -join ', ')). NATS was not touched."
                }
                $natsRevertProblem = Restore-NatsInstallation -WorkRootPath $WorkRoot
                if ($natsRevertProblem) {
                    $script:Report.IssueCode = 'NATS_RECOVERY_INCOMPLETE'
                    $script:Report.ActionRequired = Get-NatsManualRevertAction -Plan $natsPlan
                    Complete-Run $EXIT.ESCALATE 'RECOVERY_INCOMPLETE' $natsRevertProblem
                }
                Write-Log "NATS $($natsPlan.OldVersion) is back" OK
            }
        } elseif ($script:Stage -notin @('JOBS_DISABLED','SERVICES_STOPPED')) {
            Complete-Run $EXIT.ESCALATE 'RECOVERY_STAGE_UNSAFE' "NATS run stage '$($state.Stage)' (NATS stage '$natsStage') is not eligible for automatic recovery."
        }
    }

    $finishAfterInstall = $false
    $finishTargetNum = 0
    if (-not $natsRun -and ([bool]$state.InstallerStarted -or $script:Stage -in @('INSTALLING','VERIFIED','COMPLETE'))) {
        $diagnostics = @()
        $emergency = $false
        $runningNum = $null
        $jobsReadable = $false
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
            if ($probe.ExitCode -eq 0 -and $probe.StdOut -match '^\d+$') { $diagnostics += "server_version_num=$($probe.StdOut)"; $runningNum = [int]$probe.StdOut }
            else { $diagnostics += "PostgreSQL connection failed: $($probe.StdErr)"; $emergency = $true }
        }
        $postInstallJobsPath = Join-Path $runPath 'disabled-jobs.json'
        try {
            if (-not (Test-RegularTrustedFile $postInstallJobsPath)) { throw 'disabled-jobs.json is missing, reparse-backed, or writable by an untrusted principal' }
            $recordedJobs = @(ConvertFrom-JsonArrayText (Get-Content -LiteralPath $postInstallJobsPath -Raw -ErrorAction Stop))
            $script:DisabledJobs = @($recordedJobs)
            $script:Report.JobsLeftDisabled = (Get-UnrestoredJobNames -Records $recordedJobs) -join ', '
            $jobsReadable = $true
        } catch {
            $script:Report.JobsLeftDisabled = "UNKNOWN (could not read trusted disabled-jobs.json: $($_.Exception.Message))"
            $diagnostics += $script:Report.JobsLeftDisabled
        }

        # The installer can finish while the run that started it does not: Windows
        # PowerShell 5.1 can lose the installer's exit code, and the run then stops
        # mid-change. When PostgreSQL PROVES it is healthy at the target
        # version and nobody has started finishing by hand, do what that run would
        # have done next: tuning, Veeam services, jobs. Anything less certain stays
        # diagnostic-only and changes nothing.
        $finishBlockers = @()
        $finishTarget = "$(Get-CfgValue $state 'TargetVersion' '')"
        try { $finishTargetNum = [int](ConvertTo-ServerVersionNum $finishTarget) } catch { $finishTargetNum = 0 }
        if ($script:Stage -notin @('INSTALLING','VERIFIED')) { $finishBlockers += "the recorded stage is $($script:Stage)" }
        if ($emergency) { $finishBlockers += 'PostgreSQL is not healthy' }
        if ($finishTargetNum -le 0) { $finishBlockers += "the recorded target version '$finishTarget' is unreadable" }
        if ($null -eq $runningNum) { $finishBlockers += 'the running PostgreSQL version could not be read' }
        elseif ($finishTargetNum -gt 0 -and $runningNum -ne $finishTargetNum) { $finishBlockers += "PostgreSQL reports $runningNum, not the target $finishTargetNum" }
        if (-not $jobsReadable) { $finishBlockers += 'the disabled-job record is unreadable' }
        $installerProcs = @(Get-Process -Name 'postgresql-*-windows-x64' -ErrorAction SilentlyContinue)
        if ($installerProcs.Count -gt 0) { $finishBlockers += "the PostgreSQL installer is still running (PID $(@($installerProcs | ForEach-Object { $_.Id }) -join ', '))" }
        $liveVeeam = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue | Where-Object { "$($_.Status)" -ne 'Stopped' })
        if ($liveVeeam.Count -gt 0) { $finishBlockers += "Veeam service(s) are no longer stopped ($(@($liveVeeam | ForEach-Object { $_.Name }) -join ', ')), so finishing has already started by hand" }

        if ($finishBlockers.Count -eq 0) {
            $finishAfterInstall = $true
            # PostgreSQL is proven at the target. Say so in every later note, without
            # rewriting the marker (it must stay bound to the original run ID).
            $script:Stage = 'VERIFIED'
            $script:Report.PgInstalled = $finishTarget
            Write-Log "The installer finished and PostgreSQL is healthy at the target version $finishTarget. Finishing the run: mandatory tuning, then Veeam services, then jobs." WARN
        } else {
            $script:Report.IssueCode = 'POST_INSTALL_RECOVERY_REQUIRES_OPERATOR'
            $script:Report.ActionRequired = 'PAGE AN OPERATOR. The installer may have started; recovery was diagnostic-only and no state was changed.'
            $code = if ($emergency) { $EXIT.ESCALATE_NOW } else { $EXIT.ESCALATE }
            Complete-Run $code 'RECOVERY_DIAGNOSTIC_ONLY' "InstallerStarted=True. $($diagnostics -join '; '). Not finished automatically because $($finishBlockers -join '; '). Inspect installer logs, validate PostgreSQL, and use the recorded state to decide whether any service/job restoration is still required."
        }
    }

    if (-not $finishAfterInstall -and -not $natsFinish -and $script:Stage -notin @('JOBS_DISABLED','SERVICES_STOPPED')) {
        $script:Stage = 'INSTALLING'
        Complete-Run $EXIT.ESCALATE 'RECOVERY_STAGE_UNSAFE' "Stage '$($state.Stage)' is not eligible for automatic recovery."
    }

    if (-not $finishAfterInstall) { Write-Log "Pre-installer recovery is eligible (stage=$($state.Stage), run=$runPath)" WARN }
    $problems = @()
    $jobsPath = Join-Path $runPath 'disabled-jobs.json'
    $servicePath = Join-Path $runPath 'veeam-service-state.json'
    $natsPath = Join-Path $runPath 'nats-service-state.json'
    $pgPath = Join-Path $runPath 'pg-service-state.json'

    try {
        if (-not (Test-RegularTrustedFile $jobsPath)) { throw 'disabled-jobs.json is missing or untrusted' }
        # ConvertFrom-JsonArrayText, not a bare ConvertFrom-Json: Windows PowerShell 5.1
        # returns a JSON list as ONE nested array, which would leave every record unreadable.
        $script:DisabledJobs = @(ConvertFrom-JsonArrayText (Get-Content -LiteralPath $jobsPath -Raw -ErrorAction Stop))
        foreach ($jobRecord in $script:DisabledJobs) {
            foreach ($field in @('Family','Id','Name','WasEnabled')) {
                if ($jobRecord.PSObject.Properties.Name -notcontains $field) { throw "job record is missing '$field'" }
            }
        }
        $script:Report.JobsLeftDisabled = (@($script:DisabledJobs | ForEach-Object { $_.Name }) -join ', ')
    } catch { $problems += "disabled job state is unreadable: $($_.Exception.Message)" }

    # Mirrors STEP 19: never restore Veeam services or jobs after a tuning failure.
    $tuningFailed = $false
    if ($finishAfterInstall) {
        $tuningProblem = Invoke-RecoveryPgTuning -TuningSql (Join-Path $runPath 'pg-tuning.sql') -PsqlPath "$($state.PsqlPath)" -Port "$($state.PgPort)" -ServiceName "$($state.PgServiceName)" -ExpectedNum $finishTargetNum
        if ($tuningProblem) {
            $tuningFailed = $true
            $problems += "mandatory Veeam PostgreSQL tuning: $tuningProblem. Veeam services and jobs were left down; correct the tuning, then run -Recover again"
        } else {
            Write-Log "Mandatory Veeam PostgreSQL tuning applied; PostgreSQL verified at $finishTarget" OK
        }
    }

    if ($script:Stage -eq 'SERVICES_STOPPED' -or ($finishAfterInstall -and -not $tuningFailed) -or $natsFinish) {
        try {
            if (-not (Test-RegularTrustedFile $pgPath)) { throw 'pg-service-state.json is missing or untrusted' }
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
                if (-not (Test-RegularTrustedFile $natsPath)) { throw 'nats-service-state.json is untrusted' }
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
            if (-not (Test-RegularTrustedFile $servicePath)) { throw 'veeam-service-state.json is missing or untrusted' }
            $script:VeeamServices = @(ConvertFrom-JsonArrayText (Get-Content -LiteralPath $servicePath -Raw -ErrorAction Stop))
            $problems += @(Restore-VeeamServiceState -AllowStops:$false)
        } catch { $problems += "Veeam service restore: $($_.Exception.Message)" }
    }

    if ($problems.Count -eq 0) {
        $hasVbr = "$($state.Products)" -match '(^|\+)VBR($|\+)'
        $hasVb365 = "$($state.Products)" -match '(^|\+)VB365($|\+)'
        # Services were just restarted here, so VBR needs reconnecting too, not only VB365.
        $moduleProblems = @(Connect-VeeamModules -Vbr:$hasVbr -Vb365:$hasVb365 -Reconnect)
        if ($moduleProblems.Count -gt 0) { $problems += $moduleProblems }
        else {
            try {
                $script:ManagedJobInventory = @(Get-VeeamManagedJobInventory -Vbr $hasVbr -Vb365 $hasVb365)
                if ($script:Vb365MaintenancePending) { Resolve-Vb365PendingMaintenanceBarrier }
                if ($script:Vb365MaintenanceSessionId) {
                    Stop-Vb365MaintenanceBarrier -SessionId $script:Vb365MaintenanceSessionId
                }
                $timeout = [int](Get-CfgValue $Cfg 'jobWaitTimeoutMinutes' 720)
                $idle = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $timeout -Context 'during recovery' -CloseConsoles
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
        if ($finishAfterInstall) {
            $script:Report.IssueCode = 'POSTINSTALL_RECOVERY_INCOMPLETE'
            $script:Report.ActionRequired = 'PAGE AN OPERATOR. PostgreSQL is at the target version, but finishing the run was incomplete; jobs remain recorded in RecoveryRunDir. Fix the reported problem, then run -Recover again.'
        } else {
            $script:Report.IssueCode = 'PREINSTALL_RECOVERY_INCOMPLETE'
            $script:Report.ActionRequired = 'PAGE AN OPERATOR. Automatic pre-installer recovery was incomplete; jobs remain recorded in RecoveryRunDir.'
        }
        Complete-Run $EXIT.ESCALATE 'RECOVERY_INCOMPLETE' ($problems -join ' | ')
    }

    $script:Report.JobsLeftDisabled = ''
    if ($natsKeptNew) { Set-RecoveryProperty NatsStage 'COMMITTED' }
    Save-RecoveryState -Stage 'COMPLETE' -InstallerStarted ([bool]$finishAfterInstall)
    if (-not (Remove-RecoveryMarker)) {
        $script:Report.IssueCode = 'MARKER_REMOVE_FAILED'
        Complete-Run $EXIT.ESCALATE 'RECOVERY_MARKER_REMOVE_FAILED' 'State was restored, but the recovery marker could not be removed.'
    }
    if ($natsRun) {
        if ($natsKeptNew) {
            $script:Report.NatsInstalled = "$($natsPlan.TargetVersion)"
            $script:Report.NatsStatus = 'UPDATED'
            Complete-Run $EXIT.OK 'RECOVERED_NATS_UPDATED' "NATS runs $($natsPlan.TargetVersion), as the interrupted run intended. The captured NATS, Veeam service and job states were restored and verified. PostgreSQL was not touched."
        }
        if ("$(Get-CfgValue $script:RecoveryState 'NatsStage' '')" -eq 'REVERTED') {
            $script:Report.NatsStatus = 'UPDATE_FAILED_REVERTED'
            Complete-Run $EXIT.OK 'RECOVERED_NATS_REVERTED' "NATS is back on $($natsPlan.OldVersion). The captured NATS, Veeam service and job states were restored and verified. PostgreSQL was not touched."
        }
        $script:Report.NatsStatus = 'NOT_UPDATED'
        Complete-Run $EXIT.OK 'RECOVERED_PREINSTALL' 'Captured NATS, Veeam service and job states were restored and verified. NATS was not changed, and PostgreSQL was not touched.'
    }
    if ($finishAfterInstall) {
        Complete-Run $EXIT.OK 'RECOVERED_POSTINSTALL' "The installer had finished. PostgreSQL is at $finishTarget; mandatory tuning was applied, and the captured PostgreSQL, NATS, Veeam service and job states were restored and verified."
    }
    Complete-Run $EXIT.OK 'RECOVERED_PREINSTALL' 'Captured PostgreSQL, NATS, Veeam service and job states were restored and verified. The installer never started.'
}

# ---------------------------------------------------------------------------
# STEP 1 - Load built-in settings
# ---------------------------------------------------------------------------
Write-Log 'STEP 1 - Load settings' STEP

$Cfg = Get-DefaultConfig
Write-Log 'Settings: built-in; external override files are not supported' OK
Write-Log 'PostgreSQL target policy: latest published minor on the installed major branch'

# Housekeeping, every run - audit runs included, or daily audits pile up forever.
# retentionDays covers transcripts AND recovery sets. Unresolved evidence and the
# two newest completed recovery sets (including their transcripts) are retained
# regardless of age. Deletion is limited to an owned, normalized runs directory.
if ($script:WorkRootProtected) {
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
        if (Test-PathTreeHasReparsePoint -Path $runsRoot) {
            $protectEveryRun = $true
            Write-Log 'Skipping recovery-set housekeeping because the runs path contains a reparse point.' WARN
        } else {
            $runsRootFull = [IO.Path]::GetFullPath($runsRoot).TrimEnd('\') + '\'
            foreach ($rd in @(Get-ChildItem -LiteralPath $runsRoot -Directory -ErrorAction SilentlyContinue)) {
                $fullRun = [IO.Path]::GetFullPath($rd.FullName).TrimEnd('\')
                if (($rd.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    [IO.Directory]::GetParent($fullRun).FullName.TrimEnd('\') -ine $runsRootFull.TrimEnd('\') -or
                    $rd.Name -notmatch '^\d{8}-\d{6}-\d{3}-\d+$' -or
                    (Test-PathTreeHasReparsePoint -Path $fullRun)) {
                    [void]$protectedRuns.Add($fullRun)
                    continue
                }
                $manifest = Get-ValidatedCompletedRunManifest -RunDirectory $fullRun
                $manifestStage = if ($manifest) { 'COMPLETE' } else { '' }
                $manifestLog = if ($manifest -and $manifest.PSObject.Properties.Name -contains 'LogPath') { "$($manifest.LogPath)" } else { '' }
                if ($manifestStage -eq 'COMPLETE') {
                    $completedRuns += [pscustomobject]@{ Path=$rd.FullName; LogPath=$manifestLog; LastWriteTime=$rd.LastWriteTime }
                } else {
                    # Empty abandoned directories have no recovery value; every
                    # non-empty run lacking a COMPLETE record is treated as unresolved.
                    $isEmpty = @(Get-ChildItem -LiteralPath $rd.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0
                    if (-not $isEmpty) {
                        [void]$protectedRuns.Add($fullRun)
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
                if (Test-RegularTrustedFile $script:MarkerFile) {
                    try {
                        $markerForRetention = Get-Content -LiteralPath $script:MarkerFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                        $markedRun = [IO.Path]::GetFullPath("$($markerForRetention.RunDir)").TrimEnd('\')
                        if (($markedRun + '\').StartsWith($runsRootFull, [StringComparison]::OrdinalIgnoreCase)) { [void]$protectedRuns.Add($markedRun) }
                    } catch {}
                }
            }

            foreach ($rd in @(Get-ChildItem -LiteralPath $runsRoot -Directory -ErrorAction SilentlyContinue)) {
                $fullRun = [IO.Path]::GetFullPath($rd.FullName).TrimEnd('\')
                if ($protectEveryRun -or $protectedRuns.Contains($fullRun) -or $fullRun -eq [IO.Path]::GetFullPath($script:RunDir).TrimEnd('\')) { continue }
                if (($rd.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    [IO.Directory]::GetParent($fullRun).FullName.TrimEnd('\') -ine $runsRootFull.TrimEnd('\') -or
                    $rd.Name -notmatch '^\d{8}-\d{6}-\d{3}-\d+$' -or
                    (Test-PathTreeHasReparsePoint -Path $fullRun)) { continue }
                $isEmpty = @(Get-ChildItem -LiteralPath $fullRun -Force -ErrorAction SilentlyContinue).Count -eq 0
                if (($isEmpty -or $rd.LastWriteTime -lt $cutoff) -and (($fullRun + '\').StartsWith($runsRootFull, [StringComparison]::OrdinalIgnoreCase))) {
                    if (Test-PathTreeHasReparsePoint -Path $fullRun -IncludeDescendants) {
                        Write-Log "  retaining $($rd.Name) because it contains a reparse point" WARN
                        continue
                    }
                    Write-Log "  purging completed run folder $($rd.Name)$(if ($isEmpty) { ' (empty)' })"
                    Remove-Item -LiteralPath $fullRun -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    foreach ($log in @(Get-ChildItem -LiteralPath $script:LogDir -File -Filter 'VeeamPgUpdate_*.log' -ErrorAction SilentlyContinue)) {
        $fullLog = [IO.Path]::GetFullPath($log.FullName)
        if (($log.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and
            [IO.Directory]::GetParent($fullLog).FullName.TrimEnd('\') -ieq [IO.Path]::GetFullPath($script:LogDir).TrimEnd('\') -and
            -not $protectEveryRun -and $log.LastWriteTime -lt $cutoff -and -not $protectedLogs.Contains($fullLog)) {
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
if ($PSBoundParameters.ContainsKey('RebootDelaySeconds') -and -not $Reboot) {
    Write-Log '-RebootDelaySeconds does nothing without -Reboot.' WARN
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
# An uninstall can leave HKLM\SOFTWARE\Veeam\Veeam Backup Reporting behind, so the
# key alone is not proof. Require a service or installed files as corroboration,
# exactly as VB365 requires more than a leftover directory. Treating a stale key
# as an installation would exclude a server that has no Enterprise Manager at all.
$emKey = 'HKLM:\SOFTWARE\Veeam\Veeam Backup Reporting'
if (Test-Path $emKey) {
    $emServices = @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue |
        Where-Object { "$($_.Name) $($_.DisplayName)" -match 'EnterpriseManager|Enterprise Manager' })
    $emPaths = @()
    foreach ($emValueName in @('CorePath','InstallPath','Path','WebPath')) {
        $emCandidate = Get-RegValue $emKey $emValueName
        if ($emCandidate -and (Test-Path -LiteralPath "$emCandidate")) { $emPaths += "$emCandidate" }
    }
    $emDefaultPath = 'C:\Program Files\Veeam\Backup and Replication\Enterprise Manager'
    if (Test-Path -LiteralPath $emDefaultPath) { $emPaths += $emDefaultPath }

    if ($emServices.Count -gt 0 -or $emPaths.Count -gt 0) {
        $products += [pscustomobject]@{ Name='EnterpriseManager'; Version=$null; CorePath=$(if ($emPaths.Count -gt 0) { $emPaths[0] } else { $null }) }
        $emEvidence = @()
        if ($emServices.Count -gt 0) { $emEvidence += "service(s): $(@($emServices | ForEach-Object { $_.Name }) -join ', ')" }
        if ($emPaths.Count -gt 0)    { $emEvidence += "path(s): $(@($emPaths | Select-Object -Unique) -join ', ')" }
        Write-Log "Found Veeam Backup Enterprise Manager ($($emEvidence -join '; ')); this topology is excluded until its separate configuration database is supported" WARN
    } else {
        $script:StaleEnterpriseManagerKey = $emKey
        $script:Report.StaleEmRecord = 'present'
        Write-Log "$emKey exists but Enterprise Manager has no service and no installed files. Treating it as a leftover record from an uninstall, not an installation." WARN
        Write-Log '  To clear the leftover record, rerun this script once with -RemoveStaleEnterpriseManagerRecord. It exports a .reg backup into the log folder first.' WARN
    }
}

if ($RemoveStaleEnterpriseManagerRecord) {
    if (-not $script:StaleEnterpriseManagerKey) {
        Write-Log '-RemoveStaleEnterpriseManagerRecord was passed, but this run did not prove a leftover Enterprise Manager record. Nothing was removed.' WARN
    } else {
        $emBackup = Join-Path $script:LogDir "stale-enterprise-manager-record-$($script:Stamp).reg"
        try {
            [void](Remove-StaleVeeamRegistryRecord -Key $script:StaleEnterpriseManagerKey -BackupPath $emBackup)
        } catch {
            Complete-Run $EXIT.PREFLIGHT 'STALE_EM_RECORD_REMOVE_FAILED' "Could not remove the leftover Enterprise Manager registry record $($script:StaleEnterpriseManagerKey): $($_.Exception.Message)"
        }
        Write-Log "Removed the leftover record $($script:StaleEnterpriseManagerKey). Backup: $emBackup" OK
        $script:Report.StaleEmRecord = "removed; backup $emBackup"
        $script:StaleEnterpriseManagerKey = $null
    }
}

$script:Report.VeeamProducts = ($products | ForEach-Object { $_.Name }) -join '+'

if (@($products | Where-Object { $_.Name -eq 'VeeamONE' }).Count -gt 0) {
    Complete-Run $EXIT.UNSUPPORTED 'VEEAM_ONE_PRESENT' 'Veeam ONE co-residence is not yet a certified topology. Handle this server manually.'
}
# A Veeam service set to start automatically but sitting Stopped means the
# server is already degraded before this run touches anything. A stopped Veeam
# Installer (Deploy) Service takes every repository offline, which makes the
# configuration backup fail. Warn here, never block. If the configuration
# backup then fails, STEP 14 starts these services and retries it once.
$autoStoppedServices = @()
foreach ($svc in @(Get-Service -Name 'Veeam*' -ErrorAction SilentlyContinue)) {
    if ("$($svc.Status)" -ne 'Stopped') { continue }
    $svcStartup = ''
    try { $svcStartup = Get-ServiceStartupTypeExact $svc.Name } catch {}
    if ("$svcStartup" -like 'Automatic*') { $autoStoppedServices += "$($svc.Name) [$svcStartup]" }
}
if ($autoStoppedServices.Count -gt 0) {
    Write-Log "Veeam service(s) set to start automatically are currently stopped: $($autoStoppedServices -join ', ')" WARN
    # $hasVbr is not set yet, so read the product list directly.
    $stoppedTail = if (@($products | Where-Object { $_.Name -eq 'VBR' }).Count -eq 0) {
        'This server has no VBR configuration backup, so this run does not start them.'
    } elseif (-not $Install) {
        'This audit changes nothing. An -Install run starts these services and retries its configuration backup once, only if that backup fails.'
    } else {
        'If that backup fails, this run starts these services and retries it once.'
    }
    Write-Log "  This server may already be degraded. A stopped Veeam Installer/Deploy Service takes repositories offline, which makes the configuration backup fail. $stoppedTail" WARN
}

$hasEnterpriseManager = @($products | Where-Object { $_.Name -eq 'EnterpriseManager' }).Count -gt 0

$pgBackedProducts = @($products | Where-Object { $_.Name -eq 'VBR' -or $_.Name -eq 'VB365' })
if ($pgBackedProducts.Count -eq 0) {
    Complete-Run $EXIT.OK 'NOT_APPLICABLE' 'No PostgreSQL-backed Veeam product found on this server.'
}
$hasVbr   = @($pgBackedProducts | Where-Object { $_.Name -eq 'VBR'   }).Count -gt 0
$hasVb365 = @($pgBackedProducts | Where-Object { $_.Name -eq 'VB365' }).Count -gt 0

# Enterprise Manager is supported only beside VBR, which is how Veeam deploys it.
# Its own services are covered by the Veeam* service capture; only its separate
# configuration database needs discovering. Any other pairing keeps the exclusion.
if ($hasEnterpriseManager -and -not $hasVbr) {
    Complete-Run $EXIT.UNSUPPORTED 'ENTERPRISE_MANAGER_WITHOUT_VBR' 'Enterprise Manager was found without Veeam Backup & Replication on this server. That topology needs its own certified profile, including service and tuning handling. Handle this server manually.'
}

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
        Action    = ''   # specific RMM ActionRequired text, when there is a clear fix
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
            # Repository maintenance mode (Start/Get/Stop-VBORepositoryMaintenanceSession)
            # is new in VB365 8.6, build 8.6.0.1102:
            # https://helpcenter.veeam.com/docs/vbo365/powershell/start-vborepositorymaintenancesession.html
            # Read $products defensively: this function is also exercised on its own by the tests.
            $knownProducts = @(Get-Variable -Name products -Scope Script -ValueOnly -ErrorAction SilentlyContinue)
            $vb365Record = @($knownProducts | Where-Object { $_ -and $_.Name -eq 'VB365' }) | Select-Object -First 1
            $vb365Version = if ($vb365Record) { "$($vb365Record.Version)" } else { 'Unknown' }
            $result.Kind = 'UNSUPPORTED'
            $result.IssueCode = 'VB365_MAINTENANCE_API_UNAVAILABLE'
            $result.Detail = "VB365 $vb365Version is installed. Safe VB365 maintenance needs repository maintenance mode, which is new in VB365 8.6 (build 8.6.0.1102). Missing: $($missingMaintenanceCommands -join ', ')."
            $result.Action = 'Upgrade Veeam Backup for Microsoft 365 to 8.6 or later, then rerun the audit.'
            return [pscustomobject]$result
        }
    }

    try {
        $result.Inventory = @(Get-VeeamManagedJobInventory -Vbr $Vbr -Vb365 $Vb365)
    } catch {
        # Veeam blocks PowerShell for accounts with multi-factor authentication
        # enabled, with "Unable to connect to the server with MFA-enabled user
        # account. Execution environment cannot be initialized to Remote". This is
        # by design, not a bug:
        #   "MFA is not supported for PowerShell (either interactive logon or
        #    non-interactive connections)"
        #   https://helpcenter.veeam.com/docs/vbr/userguide/mfa.html
        #   https://www.veeam.com/kb4535
        # The REST API is excluded on the same page, so there is no fallback, and
        # the service-account flag has no cmdlet. A human must set it in the
        # console, so the message gives them the exact path. The script never
        # changes that flag itself: that would disable a customer's hardening
        # control unattended, and an interrupted run could leave MFA off.
        if (Test-VeeamMfaBlockedError $_) {
            $result.Kind = 'UNSUPPORTED'
            $result.IssueCode = 'VEEAM_MFA_BLOCKS_POWERSHELL'
            $result.Detail = "Veeam refused the PowerShell connection because the account has multi-factor authentication enabled: $($_.Exception.Message)"
            $result.Action = 'MFA ACCOUNT. Veeam does not support PowerShell for MFA-enabled accounts (KB4535). In the VBR console: Users and Roles > Security > add/select this account > Edit > tick "This is a service account (disables two-factor authentication)" > OK, then OK again on Users and Roles. Note MFA ignores groups, so the account must be listed individually.'
            return [pscustomobject]$result
        }
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

# Enterprise Manager v12+ records its configuration database in the registry with
# exactly the layout VBR uses, under its own product key. Veeam KB1471 publishes
# the same PowerShell block for both products with only the key swapped:
# https://www.veeam.com/kb1471   Default EM database name: VeeamBackupReporting.
# Nothing is guessed: a missing key or value returns UNKNOWN so the caller can
# exclude the server instead of assuming local defaults.
function Get-VeeamRegistryPostgresDatabase {
    param(
        [Parameter(Mandatory)][string] $ProductKey,
        [Parameter(Mandatory)][string] $Label
    )
    $configKey = "$ProductKey\DatabaseConfigurations"
    if (-not (Test-Path $configKey)) {
        return [pscustomobject]@{ Kind='UNKNOWN'; Host=''; Port=0; Database=''
            Detail = "$Label has no DatabaseConfigurations registry key (pre-v12 layout or an unexpected install), so its configuration database cannot be discovered." }
    }
    $active = Get-RegValue $configKey 'SqlActiveConfiguration'
    if (-not $active) {
        return [pscustomobject]@{ Kind='UNKNOWN'; Host=''; Port=0; Database=''
            Detail = "$Label has no SqlActiveConfiguration value, so its database engine cannot be determined." }
    }
    if ("$active" -ieq 'MsSql') {
        return [pscustomobject]@{ Kind='MSSQL'; Host=''; Port=0; Database=''; Detail = "$Label uses $active" }
    }
    if ("$active" -ine 'PostgreSql') {
        return [pscustomobject]@{ Kind='UNKNOWN'; Host=''; Port=0; Database=''
            Detail = "$Label SqlActiveConfiguration is '$active', not the exact supported values MsSql or PostgreSql." }
    }
    $pgKey = "$configKey\PostgreSql"
    $dbHost = Get-RegValue $pgKey 'SqlHostName'
    $dbPort = Get-RegValue $pgKey 'SqlHostPort'
    $dbName = Get-RegValue $pgKey 'SqlDatabaseName'
    $missing = @()
    if (-not $dbHost) { $missing += 'SqlHostName' }
    if (-not $dbPort) { $missing += 'SqlHostPort' }
    if (-not $dbName) { $missing += 'SqlDatabaseName' }
    if ($missing.Count -gt 0) {
        return [pscustomobject]@{ Kind='UNKNOWN'; Host=''; Port=0; Database=''
            Detail = "$Label's active PostgreSql configuration is missing: $($missing -join ', '). Refusing to guess local defaults." }
    }
    $portNumber = 0
    if (-not [int]::TryParse("$dbPort", [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) {
        return [pscustomobject]@{ Kind='UNKNOWN'; Host=''; Port=0; Database=''
            Detail = "$Label reports invalid PostgreSQL port '$dbPort'." }
    }
    return [pscustomobject]@{ Kind='POSTGRES'; Host="$dbHost"; Port=$portNumber; Database="$dbName"; Detail='' }
}

# Veeam records a database name; PostgreSQL stores the name the database was
# actually created with, and the case can differ between builds, so an exact
# match can report the database absent. Match case-insensitively, then adopt the SERVER's name
# for every later step, so dumps and comparisons use what PostgreSQL will accept.
# Two names differing only by case are genuinely ambiguous, so that fails closed.
function Resolve-VeeamDatabaseNames {
    param(
        [Parameter(Mandatory)] $Records,
        [Parameter(Mandatory)] $ActualNames
    )
    $actual = @($ActualNames | ForEach-Object { "$_" })
    $resolved = @()
    $missing = @()
    $renamed = @()
    foreach ($record in @($Records)) {
        $configuredName = "$($record.Database)"
        # Never call this $matches: that is PowerShell's automatic -match variable.
        $nameMatches = @($actual | Where-Object { $_ -ieq $configuredName })
        if ($nameMatches.Count -eq 0) { $missing += $configuredName; continue }
        if ($nameMatches.Count -gt 1) {
            return [pscustomobject]@{
                Resolved = @(); Missing = @(); Renamed = @()
                Ambiguous = [pscustomobject]@{ Configured = $configuredName; Matches = $nameMatches }
            }
        }
        $actualName = "$($nameMatches[0])"
        if ($actualName -cne $configuredName) {
            $renamed += [pscustomobject]@{ Configured = $configuredName; Actual = $actualName }
        }
        $resolved += [pscustomobject]@{ Product = $record.Product; Database = $actualName; Port = $record.Port }
    }
    return [pscustomobject]@{ Resolved = $resolved; Missing = $missing; Renamed = $renamed; Ambiguous = $null }
}

function Test-Vb365CacheDatabaseName {
    param([string] $Database)
    if (-not $Database) { return $false }
    # Exactly cache_ plus a GUID in one of the two forms .NET writes by default:
    # with hyphens (D) or without (N). [guid]::TryParse would also accept braced,
    # bracketed and 0x forms, which VB365 never produces, so a stranger database
    # could pass as a Veeam cache. The prefix is case-sensitive, like PostgreSQL
    # database names.
    return ($Database -cmatch '^cache_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32})$')
}

# Proxy.xml does not hold a real cache database name. It holds a pattern,
# 'cache_{0}', and VB365 puts a repository ID in place of {0} for each cache
# database it creates. Accept only that exact pattern. The real cache_<guid>
# databases are found later by listing the databases on the server.
function Test-Vb365CacheDatabaseTemplate {
    param([string] $Database)
    return ($null -ne $Database -and $Database -ceq 'cache_{0}')
}

# STEP 6 is the first login to PostgreSQL, so a refused login stops the run there.
# psql's stderr says why, and each cause has a different fix, so name the cause:
#   * Password (native) authentication. Veeam supports it (KB4818 shows the
#     layout), and a VBR server migrated to PostgreSQL by hand can have it:
#     scram-sha-256 or md5 loopback lines in pg_hba.conf. psql -w then stops
#     with "fe_sendauth: no password supplied", which libpq never translates. A
#     stale pgpass.conf gives "password authentication failed" instead.
#     pg_ident.conf is never read, so KB4542 cannot help.
#   * SSPI without a pg_ident.conf mapping: "SSPI authentication failed". The
#     "no match in usermap ... authenticated as ..." line goes to the PostgreSQL
#     log only, never to psql. The name it would show is this run's own account,
#     written user@DOMAIN, so build it from -Identity when stderr lacks it.
#   * No pg_hba.conf line matches this connection at all.
# A server set to another language translates the FATAL texts. Those fall through
# to the generic message.
# On Windows, PostgreSQL reads pg_hba.conf and pg_ident.conf again for each new
# login, so a fix to either file needs no reload.
# -Product 'VBR' means VBR's own database is on this PostgreSQL. Only then does the
# password case point to the Standardise VBR script, which converts VBR only.
function Get-PgLoginFailureHint {
    param(
        [string] $StdErr,
        [string] $Identity = '',
        [string] $Product = 'VBR'
    )
    # Windows PowerShell 5.1 saves psql's stderr wrapped at the console width, which
    # can split "no password supplied" over two lines. Match on one line.
    $text = ("$StdErr" -replace '\s+', ' ')
    if ($text -match '(?i)no password supplied|password authentication failed') {
        if ($Product -eq 'VBR') {
            $action = 'NATIVE AUTH. Convert this VBR server to Windows authentication with the Standardise VBR script (Invoke-VbrStandardise.ps1), then retry.'
        } else {
            $action = 'NATIVE AUTH. Give user postgres Windows (SSPI) authentication from 127.0.0.1 in pg_hba.conf, with this account in the veeam map in pg_ident.conf (Veeam KB4818), then retry.'
        }
        return [pscustomobject]@{
            Cause  = 'PASSWORD_AUTH'
            Detail = 'PostgreSQL asked for a password: it uses password (native) authentication (Veeam KB4818). Veeam supports that, but this script logs in with Windows (SSPI) authentication only, so pg_ident.conf (KB4542) is not the fix.'
            Action = $action
        }
    }
    if ($text -match '(?i)SSPI authentication failed|no match in usermap') {
        $account = ''
        if ($text -match '(?i)authenticated as "([^"]+)"') {
            $account = $Matches[1]
        } elseif ($Identity -match '^([^\\]+)\\(.+)$') {
            # pg_ident.conf names an SSPI account as user@DOMAIN, not DOMAIN\user.
            $account = "$($Matches[2])@$($Matches[1])"
        }
        $who = if ($account) { "'$account'" } else { 'the account this script runs as' }
        return [pscustomobject]@{
            Cause  = 'SSPI_MAP'
            Detail = "Windows (SSPI) login was refused: $who is not mapped to postgres in pg_ident.conf (Veeam KB4542)."
            Action = "SSPI MAPPING. Add $who to the veeam map in pg_ident.conf as postgres (Veeam KB4542), then retry."
        }
    }
    if ($text -match '(?i)no pg_hba\.conf entry') {
        return [pscustomobject]@{
            Cause  = 'NO_HBA_ENTRY'
            Detail = 'pg_hba.conf has no line for this connection (user postgres from 127.0.0.1).'
            Action = "PG_HBA LINE. Add a pg_hba.conf line for user postgres from 127.0.0.1. Veeam's default is 'host all all 127.0.0.1/32 sspi map=veeam' (Veeam KB4818). Then retry."
        }
    }
    return [pscustomobject]@{
        Cause  = 'UNKNOWN'
        Detail = 'This usually means the running identity is not mapped in pg_ident.conf (Veeam KB4542).'
        Action = ''
    }
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

if ($hasEnterpriseManager) {
    # Enterprise Manager always has its own database, separate from VBR's. It may
    # sit in the same local instance or somewhere else, so read it rather than
    # assume, and add it to the dump set when it is local.
    $emDb = Get-VeeamRegistryPostgresDatabase -ProductKey $emKey -Label 'Enterprise Manager'
    if ($emDb.Kind -eq 'MSSQL') {
        Write-Log "Enterprise Manager uses $($emDb.Detail -replace '^Enterprise Manager uses ',''), so it is not a PostgreSQL database target. Its services are still stopped and restarted with the other Veeam services." WARN
    } elseif ($emDb.Kind -eq 'POSTGRES') {
        Write-Log ("Enterprise Manager database: {0} on {1}:{2}" -f $emDb.Database, $emDb.Host, $emDb.Port)
        if (-not (Test-LocalDbHost $emDb.Host)) {
            $remoteDatabaseProducts += "EnterpriseManager ($($emDb.Host))"
            Write-Log "Enterprise Manager uses remote PostgreSQL at $($emDb.Host)." WARN
        } else {
            $veeamDatabases += [pscustomobject]@{ Product='EnterpriseManager'; Database=$emDb.Database; Port=$emDb.Port }
        }
    } else {
        Complete-Run $EXIT.UNSUPPORTED 'ENTERPRISE_MANAGER_DB_UNKNOWN' "$($emDb.Detail) Handle this server manually."
    }
}

$vboCacheTemplatePorts = @()
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

    $vboConnections = @([pscustomobject]@{ Product='VB365'; Source='Config.xml ControllerPostgres'; Connection=$vboControllerConnection; IsTemplate=$false })
    try {
        $proxyControllerString = $proxyControllerNodes[0].GetAttribute('ControllerConnectionString')
        if (-not $proxyControllerString) { throw 'ProxyPostgres ControllerConnectionString is empty' }
        $vboConnections += [pscustomobject]@{
            Product='VB365'; Source='Proxy.xml ProxyPostgres';
            Connection=(ConvertFrom-PgConnectionString $proxyControllerString); IsTemplate=$false
        }
        foreach ($cacheNode in $cacheNodes) {
            $cacheConnectionString = $cacheNode.GetAttribute('PersistentCacheConnectionString')
            if (-not $cacheConnectionString) { throw 'PersistentCachePostgres PersistentCacheConnectionString is empty' }
            $cacheConnection = ConvertFrom-PgConnectionString $cacheConnectionString
            $isTemplate = Test-Vb365CacheDatabaseTemplate $cacheConnection.Database
            if (-not $isTemplate -and -not (Test-Vb365CacheDatabaseName $cacheConnection.Database)) {
                throw "Persistent cache database '$($cacheConnection.Database)' is neither the cache_{0} pattern nor named cache_<guid>"
            }
            $vboConnections += [pscustomobject]@{
                Product='VB365Cache'; Source='Proxy.xml PersistentCachePostgres'; Connection=$cacheConnection; IsTemplate=$isTemplate
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
        } elseif ($configuredConnection.IsTemplate) {
            # A pattern, not a database. Keep its port so the single-instance check
            # below still proves the cache databases live on this same PostgreSQL.
            $vboCacheTemplatePorts += [int]$conn.Port
            Write-Log '  (pattern only - the real cache_<guid> databases are listed from the server in STEP 6)'
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

$localPgPorts = @((@($veeamDatabases | ForEach-Object { [int]$_.Port }) + @($vboCacheTemplatePorts)) | Sort-Object -Unique)
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
    # VBR left on SQL Server can still reach here for Enterprise Manager's database.
    $loginProduct = if (@($veeamDatabases | Where-Object { $_.Product -eq 'VBR' }).Count -gt 0) { 'VBR' } else { 'OTHER' }
    $loginHint = Get-PgLoginFailureHint -StdErr $verRes.StdErr -Identity ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -Product $loginProduct
    if ($loginHint.Action) { $script:Report.ActionRequired = $loginHint.Action }
    Complete-Run $EXIT.PREFLIGHT 'PG_UNREACHABLE' "Could not query PostgreSQL as user 'postgres'. $($loginHint.Detail) stderr: $($verRes.StdErr) stdout: $($verRes.StdOut)"
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
try { $actualDatabases = @(ConvertFrom-JsonArrayText $databaseListRes.StdOut) }
catch { Complete-Run $EXIT.PREFLIGHT 'PG_DATABASE_INVENTORY_FAILED' "PostgreSQL database inventory was not valid JSON: $($_.Exception.Message)" }

# Always log what the cluster actually holds. Without this line, a name mismatch
# costs a round trip to the server to diagnose.
Write-Log "PostgreSQL cluster holds database(s): $(@($actualDatabases) -join ', ')"

$resolution = Resolve-VeeamDatabaseNames -Records $veeamDatabases -ActualNames $actualDatabases
if ($resolution.Ambiguous) {
    Complete-Run $EXIT.PREFLIGHT 'AMBIGUOUS_DATABASE_NAME' "Veeam is configured for database '$($resolution.Ambiguous.Configured)' and this cluster holds $(@($resolution.Ambiguous.Matches).Count) databases whose names differ only by case ($(@($resolution.Ambiguous.Matches) -join ', ')). Refusing to guess which one Veeam uses."
}
foreach ($renamed in @($resolution.Renamed)) {
    Write-Log "Veeam records database '$($renamed.Configured)'; this cluster names it '$($renamed.Actual)'. Using the server's name." WARN
}
if (@($resolution.Missing).Count -gt 0) {
    Complete-Run $EXIT.PREFLIGHT 'VEEAM_DATABASE_MISSING' "Configured Veeam database(s) are absent from this cluster: $(@($resolution.Missing) -join ', '). This cluster holds: $(@($actualDatabases) -join ', ')."
}
$veeamDatabases = @($resolution.Resolved)
$configuredDatabaseNames = @($veeamDatabases | ForEach-Object { "$($_.Database)" } | Select-Object -Unique)
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
    if ($controlValidation.Action) { $script:Report.ActionRequired = $controlValidation.Action }
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
    Write-Log "Veeam work is currently active ($($auditActivity -join ', ')). Audit can continue; install mode closes any open Veeam console and waits for everything else to finish naturally before disabling schedules." WARN
} else {
    Write-Log "Validated $($script:ManagedJobInventory.Count) schedule/policy object(s); all observed Veeam activity is currently quiescent" OK
}

$regBranch = Get-BranchKey $pg.Version
if ("$pgBranch" -ne "$regBranch") {
    Complete-Run $EXIT.PREFLIGHT 'PG_REGISTRY_VERSION_MISMATCH' "Registry installation version '$($pg.Version)' is branch $regBranch, but the running server is branch $pgBranch. Refusing to select an installer while registry and runtime targets disagree."
}

# ---------------------------------------------------------------------------
# STEP 6C - NATS (VB365 only). Read-only in every mode. Any doubt leaves NATS alone
# and is reported in NatsStatus/NatsDetail; it never blocks the PostgreSQL update.
# ---------------------------------------------------------------------------
$natsDiscovery = $null
if (-not $hasVb365) {
    $script:Report.NatsStatus = 'NOT_APPLICABLE'
} else {
    Write-Log 'STEP 6C - Check NATS (VB365 only)' STEP
    $vb365Product = @($products | Where-Object { $_.Name -eq 'VB365' }) | Select-Object -First 1
    $updateNats = $true
    try { $updateNats = [bool](Get-CfgValue $Cfg 'updateNats' $true) } catch {}
    try {
        $natsDiscovery = Get-NatsDiscovery -Vb365Version "$($vb365Product.Version)" -ConfigXml $vboXml -ProxyXml $proxyXml -WorkRoot $WorkRoot -UpdatesEnabled $updateNats
    } catch {
        $natsDiscovery = [pscustomobject]@{ Status='UNRECOGNISED_LAYOUT'; Installed=''; Target=''; Detail="The NATS check failed: $($_.Exception.Message)"; Plan=$null }
    }
    $script:Report.NatsInstalled = "$($natsDiscovery.Installed)"
    $script:Report.NatsTarget = "$($natsDiscovery.Target)"
    $script:Report.NatsStatus = "$($natsDiscovery.Status)"
    $script:Report.NatsDetail = Format-ShortText "$($natsDiscovery.Detail)" 400
    $natsLevel = if ($natsDiscovery.Status -eq 'CURRENT') { 'OK' } elseif ($natsDiscovery.Status -eq 'NOT_LOCAL') { 'INFO' } else { 'WARN' }
    Write-Log "NATS: $($natsDiscovery.Status). $($natsDiscovery.Detail)" $natsLevel
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

# Enterprise Manager 13 lists PostgreSQL 14.x, 15.x and 17.x; 16.x is absent from
# that list. This update never changes the major version, so patching an existing
# 16.x instance does not make the server any less supported than it already is.
# Warn rather than block: withholding a security patch would be the worse outcome.
if ($hasEnterpriseManager -and $pgBranch -eq '16') {
    Write-Log "Enterprise Manager's documented PostgreSQL list (14.x, 15.x, 17.x) does not include 16.x, and this instance is on branch 16. The minor update to $target keeps the same major version, so this is pre-existing; raise it with Veeam separately." WARN
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
# One change per run. NATS goes on a run where PostgreSQL needs nothing; when both
# are due, this run updates PostgreSQL and the next -Install run updates NATS.
$natsDue = ($null -ne $natsDiscovery -and "$($natsDiscovery.Status)" -eq 'UPDATE_AVAILABLE')
if ($natsDue -and $versionComparison -ge 0) {
    $pgNote = if ($versionComparison -gt 0) { "PostgreSQL $runningVersion is newer than the published $target and is never downgraded." } else { "PostgreSQL $runningVersion is current." }
    if (-not $Install) {
        $natsMsg = "Update available: NATS $($natsDiscovery.Installed) -> $($natsDiscovery.Target) for VB365. $pgNote Re-run with -Install to apply."
        Write-Log $natsMsg WARN
        $code = Get-PolicyExitCode -Eol $script:EolBranch -UpdateAvailable $true -RebootRequired $false
        Complete-Run $code 'UPDATE_AVAILABLE' $natsMsg
    }
    Invoke-NatsOnlyUpdate -Discovery $natsDiscovery
}
if ($versionComparison -gt 0) {
    $code = Get-PolicyExitCode -Eol $script:EolBranch -UpdateAvailable $false -RebootRequired $false
    Complete-Run $code 'LOCAL_VERSION_AHEAD' "Running $runningVersion is newer than published target $target. Refusing to downgrade; no service was touched."
}
if ($versionComparison -eq 0) {
    $code = Get-PolicyExitCode -Eol $script:EolBranch -UpdateAvailable $false -RebootRequired $false
    Complete-Run $code 'ALREADY_CURRENT' "Running $runningVersion, target $target. Nothing to do. No service was touched."
}
Write-Log "Update available: $runningVersion -> $target" WARN
if ($natsDue) {
    Write-Log "NATS $($natsDiscovery.Installed) -> $($natsDiscovery.Target) is also due. One change per run: PostgreSQL first, then NATS on the next -Install run." WARN
    if ($Install) { $script:Report.NatsStatus = 'UPDATE_PENDING' }
}

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

# The download page sits behind a CDN that intermittently answers 403 to a script,
# even right after it served the same request. The file host itself does not do
# that, and its naming is exact, so
# probe it directly first and keep the page scrape only as a fallback.
#
# The build suffix is NOT derivable and can change after release: EnterpriseDB can
# republish the same version under a higher suffix. Probe high to low and take the first hit. A
# missing object answers 403 from the CDN, so only an explicit 200 counts as found.
function Resolve-PgInstallerDirectUrl {
    param([Parameter(Mandatory)][string] $Version)
    foreach ($suffix in 5, 4, 3, 2, 1) {
        $url = "https://get.enterprisedb.com/postgresql/postgresql-$Version-$suffix-windows-x64.exe"
        try {
            $head = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            if ($head.StatusCode -ne 200) { continue }
            $len = 0
            try {
                $cl = $head.Headers['Content-Length']
                if ($cl -is [array]) { $cl = $cl[0] }
                if ($cl) { $len = [int64]$cl }
            } catch {}
            Write-Log ("EnterpriseDB file host publishes build -{0}- for {1} ({2:N0} bytes)" -f $suffix, $Version, $len) OK
            return [pscustomobject]@{ PageUrl='(direct file host, no page scrape)'; Url=$url; ResolvedUrl=$url; Length=$len }
        } catch {
            Write-Log "  build -$suffix- for $Version is not published on the file host"
        }
    }
    return $null
}

function Resolve-PgInstallerUrl {
    param([Parameter(Mandatory)][string] $Version)

    $direct = Resolve-PgInstallerDirectUrl $Version
    if ($direct) { return $direct }
    Write-Log "The EnterpriseDB file host published no build for $Version; falling back to the download page" WARN

    $pageUrl = 'https://www.enterprisedb.com/downloads/postgres-postgresql-downloads'
    # A browser user agent and a couple of retries, because the refusal is transient.
    $userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
    $page = $null
    $pageError = $null
    foreach ($attempt in 1, 2, 3) {
        try {
            $page = Invoke-WebRequest -Uri $pageUrl -UseBasicParsing -TimeoutSec 60 -UserAgent $userAgent -ErrorAction Stop
            break
        } catch {
            $pageError = $_.Exception.Message
            Write-Log "  EnterpriseDB page attempt $attempt/3 failed: $(Format-ShortText $pageError 200)" WARN
            if ($attempt -lt 3) { Start-Sleep -Seconds (5 * $attempt) }
        }
    }
    if (-not $page) { throw "the EnterpriseDB download page could not be read after 3 attempts: $pageError" }

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
    $msg = "Update available: PostgreSQL $runningVersion -> $target for $($script:Report.VeeamProducts)."
    if ($natsDue) { $msg += " NATS $($natsDiscovery.Installed) -> $($natsDiscovery.Target) is also due; -Install updates PostgreSQL first and NATS on the next -Install run." }
    $msg += ' Re-run with -Install to apply.'
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
    Complete-Run $EXIT.PREFLIGHT 'WORKROOT_UNSAFE' "The work root is not locked to SYSTEM and Administrators ($($wrInit.Reason)). Refusing to write database dumps or privileged recovery state there. Use the default WorkRoot with a safe parent, or a protected custom path."
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
    if ($controlValidation.Action) { $script:Report.ActionRequired = $controlValidation.Action }
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
try { $idleBeforeDisable = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $jobWaitMinutes -Context 'before schedules are disabled' -CloseConsoles }
catch {
    $sessionCode = if ($_.Exception -is [System.NotSupportedException]) { $EXIT.UNSUPPORTED } else { $EXIT.PREFLIGHT }
    $sessionIssue = if ($sessionCode -eq $EXIT.UNSUPPORTED) { 'UNSUPPORTED_ACTIVITY_API' } else { 'SESSION_CHECK_FAILED' }
    Complete-Run $sessionCode $sessionIssue "Could not read every applicable Veeam session family, so it is impossible to prove the server is idle: $($_.Exception.Message)"
}
if (-not $idleBeforeDisable.Idle) {
    Complete-Run $EXIT.RETRY 'JOB_WAIT_TIMEOUT' "Veeam work did not finish within $jobWaitMinutes minutes ($($idleBeforeDisable.Labels -join ', ')). No job or restore was forcibly stopped."
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
try { $idleAfterDisable = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $jobWaitMinutes -Context 'after schedules were disabled' -CloseConsoles }
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
# so Invoke-VbrConfigBackupAttempt judges the session each attempt returns.
if ($hasVbr) {
    Write-Log 'Running VBR configuration backup (this can take a while)...'
    $lastRunBefore = $null
    try { $lastRunBefore = (Get-VBRConfigurationBackupJob -ErrorAction Stop).LastRun } catch {}

    $cfgAttempt = Invoke-VbrConfigBackupAttempt
    $retryNote = ''

    # A Veeam service that is set to start automatically but is stopped can make
    # the backup fail: a stopped Installer Service takes every repository offline.
    # Start such services and retry exactly once. Never loop.
    if ($cfgAttempt.Error -or $cfgAttempt.Result -eq 'Failed') {
        $firstWhy = if ($cfgAttempt.Error) { $cfgAttempt.Error } elseif ($cfgAttempt.Reasons.Count -gt 0) { $cfgAttempt.Reasons -join '; ' } else { 'the session log gave no reason' }
        Write-Log "VBR configuration backup failed after $($cfgAttempt.Seconds)s: $(Format-ShortText $firstWhy 400)" WARN
        Write-Log 'Checking for Veeam services that are set to start automatically but are stopped...'
        $startedServices = @(Start-StoppedAutomaticVeeamServices)
        if ($startedServices.Count -eq 0) {
            Write-Log 'No stopped automatic Veeam service reached Running, so the configuration backup is not retried.' WARN
        } else {
            foreach ($startedName in $startedServices) { Add-ReportListItem -Field 'ServicesStarted' -Value $startedName }
            Write-Log "Started $($startedServices -join ', ') and left them running, because they are set to start automatically. Waiting 30 seconds for VBR to reach its repositories, then retrying the configuration backup once." WARN
            Start-Sleep -Seconds 30
            if ($cfgAttempt.ConnectionLost) {
                $cfgReconnectProblems = @(Connect-VeeamModules -Vbr -Quiet -Reconnect)
                if ($cfgReconnectProblems.Count -gt 0) { Write-Log "Could not re-establish the VBR connection before the retry: $($cfgReconnectProblems -join ' | ')" WARN }
            }
            $retryNote = " This run started the stopped automatic Veeam service(s) $($startedServices -join ', ') and retried once. The first attempt failed with: $(Format-ShortText $firstWhy 200)."
            $cfgAttempt = Invoke-VbrConfigBackupAttempt
            if (-not $cfgAttempt.Error -and $cfgAttempt.Result -ne 'Failed') {
                Write-Log "The configuration backup retry did not fail (Result=$($cfgAttempt.Result)) after starting $($startedServices -join ', ')" OK
            }
        }
    }

    if ($cfgAttempt.Error) {
        Complete-Run $EXIT.PREFLIGHT 'CONFIG_BACKUP_FAILED' "VBR configuration backup failed: $($cfgAttempt.Error).$retryNote Refusing to continue without it."
    }
    $cfgResult  = $cfgAttempt.Result
    $cfgLastRun = $cfgAttempt.LastRun

    if ($cfgResult -eq 'Failed') {
        $failureReasons = @($cfgAttempt.Reasons)
        $reasonText = if ($failureReasons.Count -gt 0) { " Reason: $(Format-ShortText ($failureReasons -join '; ') 400)" } else { ' The session log gave no reason; see History > Configuration Backup in the VBR console.' }
        $script:Report.IssueCode = 'CONFIG_BACKUP_FAILED'
        $script:Report.ActionRequired = 'Fix the VBR configuration backup job on this server, then retry. This server has no usable configuration backup, which matters well beyond this update.'
        Complete-Run $EXIT.PREFLIGHT 'CONFIG_BACKUP_FAILED' "The VBR configuration backup job failed when this run started it.$reasonText$retryNote Refusing to update PostgreSQL on a server with no working configuration backup."
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

# Logical dump of one database, checked readable. Also used after Veeam has
# stopped, for any cache database VB365 created after the list in STEP 6.
function Backup-VeeamDatabase {
    param([Parameter(Mandatory)][string] $Database)
    if ($Database -in @('.','..') -or $Database.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
        Complete-Run $EXIT.PREFLIGHT 'UNSAFE_DATABASE_ARTIFACT_NAME' "Database '$Database' cannot be represented safely as a Windows recovery-artifact filename."
    }
    $dumpFile = Join-Path $backupDir "$Database.dump"
    Write-Log "pg_dump $Database -> $dumpFile"
    $r = Invoke-Native $pgDump @('-U','postgres','-h','127.0.0.1','-p',"$pgPort",'-w','-F','c','-b','-f',$dumpFile,$Database)
    if ($r.StdErr) { Write-Log "    $($r.StdErr)" WARN }
    if ($r.ExitCode -ne 0 -or -not (Test-Path $dumpFile) -or (Get-Item $dumpFile).Length -lt 10KB) {
        Complete-Run $EXIT.PREFLIGHT 'DUMP_FAILED' "pg_dump of $Database failed (exit $($r.ExitCode)) or produced a suspiciously small file. $($r.StdErr)"
    }
    $listCheck = Invoke-Native $pgRestore @('--list', $dumpFile)
    if ($listCheck.ExitCode -ne 0 -or -not $listCheck.StdOut) {
        Complete-Run $EXIT.PREFLIGHT 'DUMP_VERIFY_FAILED' "pg_restore could not read the archive for $Database (exit $($listCheck.ExitCode)). $($listCheck.StdErr)"
    }
    Write-Log ("  {0:N1} MB" -f ((Get-Item $dumpFile).Length / 1MB)) OK
}

# Logical dumps of every Veeam database, plus globals (roles and grants).
foreach ($db in $veeamDatabases) {
    Backup-VeeamDatabase "$($db.Database)"
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
    try { $finalIdle = Wait-VeeamIdle -Vbr $true -Vb365 $false -TimeoutMinutes $jobWaitMinutes -Context 'immediately before service shutdown' -CloseConsoles }
    catch { Complete-Run $EXIT.PREFLIGHT 'FINAL_SESSION_CHECK_FAILED' "Could not prove VBR was idle immediately before service shutdown: $($_.Exception.Message)" }
    if (-not $finalIdle.Idle) {
        Complete-Run $EXIT.RETRY 'FINAL_JOB_DRAIN_TIMEOUT' "VBR work did not finish within $jobWaitMinutes minutes before service shutdown ($($finalIdle.Labels -join ', ')). No job or restore was forcibly stopped."
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
    try { $lastChanceIdle = Wait-VeeamIdle -Vbr $true -Vb365 $false -TimeoutMinutes $jobWaitMinutes -Context 'after service startup was disabled' -CloseConsoles }
    catch { Complete-Run $EXIT.PREFLIGHT 'LAST_CHANCE_SESSION_CHECK_FAILED' "Could not prove VBR was idle after disabling service startup: $($_.Exception.Message)" }
    if (-not $lastChanceIdle.Idle) {
        Complete-Run $EXIT.RETRY 'LAST_CHANCE_JOB_DRAIN_TIMEOUT' "VBR work did not finish within $jobWaitMinutes minutes after service startup was disabled ($($lastChanceIdle.Labels -join ', ')). No service was stopped and no work was forcibly terminated."
    }
}

# A long final drain gives administrators time to create/re-enable a schedule.
# Refresh after the drain, then take one immediate activity read before the first
# service stop. Any drift rolls back; no job or restore is forcibly terminated.
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
# A console opened since the last drain would otherwise read as new work here.
try {
    $lastChanceActive = @(Get-ActiveVeeamWork -Vbr $hasVbr -Vb365 $hasVb365)
    if (Test-OnlyConsoleBlockers $lastChanceActive) {
        [void](Close-VeeamConsoleProcesses -Vbr $hasVbr -Vb365 $hasVb365)
        $lastChanceActive = @(Get-ActiveVeeamWork -Vbr $hasVbr -Vb365 $hasVb365)
    }
}
catch {
    $lastActivityCode = if ($_.Exception -is [System.NotSupportedException]) { $EXIT.UNSUPPORTED } else { $EXIT.PREFLIGHT }
    $lastActivityIssue = if ($lastActivityCode -eq $EXIT.UNSUPPORTED) { 'UNSUPPORTED_ACTIVITY_API' } else { 'LAST_CHANCE_SESSION_CHECK_FAILED' }
    Complete-Run $lastActivityCode $lastActivityIssue "Could not complete the immediate pre-stop activity read: $($_.Exception.Message)"
}
if ($lastChanceActive.Count -gt 0) {
    Complete-Run $EXIT.RETRY 'LAST_CHANCE_ACTIVITY_RACE' "New Veeam work appeared after the final drain ($($lastChanceActive -join ', ')). No service was stopped and no job or restore was forcibly terminated; retry under a change freeze."
}

# Never kill a Veeam Explorer: one can be running an item-level restore. A console
# can be opened in the small interval after the last drain check, so take a final
# process read, close what is only a console, and read again. Whatever is left blocks.
$blockingUi = @(Get-BlockingVeeamUiProcesses -Vbr $hasVbr -Vb365 $hasVb365)
if (Test-OnlyConsoleBlockers @($blockingUi | ForEach-Object { "UI:$($_.ProcessName):PID$($_.Id)" })) {
    [void](Close-VeeamConsoleProcesses -Vbr $hasVbr -Vb365 $hasVb365)
    $blockingUi = @(Get-BlockingVeeamUiProcesses -Vbr $hasVbr -Vb365 $hasVb365)
}
if ($blockingUi.Count -gt 0) {
    Complete-Run $EXIT.RETRY 'VEEAM_UI_OPEN' "A Veeam Explorer, or a Veeam console that could not be closed, is open before service shutdown ($((@($blockingUi) | ForEach-Object { \"$($_.ProcessName):PID$($_.Id)\" }) -join ', ')). Explorers are never closed automatically, because one can be running a restore. Close it and retry."
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
try { $remainingPgClients = @(ConvertFrom-JsonArrayText $clientActivityResult.StdOut) }
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

# Veeam is stopped and nothing else is connected, so the database list cannot
# change any more. VB365 creates a cache database per repository, and one may
# have appeared after STEP 6 listed them. Compare now, while PostgreSQL is still
# running: dump any new cache database; stop on anything else unexpected.
$finalListRes = Invoke-Psql "SELECT COALESCE(json_agg(datname ORDER BY datname)::text, '[]') FROM pg_database WHERE NOT datistemplate;"
if ($finalListRes.ExitCode -ne 0 -or -not $finalListRes.StdOut) {
    Complete-Run $EXIT.PREFLIGHT 'PG_DATABASE_INVENTORY_FAILED' "Could not re-list PostgreSQL databases after Veeam stopped. PostgreSQL was NOT stopped. stderr: $($finalListRes.StdErr)"
}
try { $finalDatabases = @(ConvertFrom-JsonArrayText $finalListRes.StdOut) }
catch { Complete-Run $EXIT.PREFLIGHT 'PG_DATABASE_INVENTORY_FAILED' "The database re-list was not valid JSON. PostgreSQL was NOT stopped: $($_.Exception.Message)" }

$dumpedDatabases = @($veeamDatabases | ForEach-Object { "$($_.Database)" })
$vanishedDatabases = @($dumpedDatabases | Where-Object { $finalDatabases -cnotcontains $_ })
if ($vanishedDatabases.Count -gt 0) {
    Complete-Run $EXIT.PREFLIGHT 'VEEAM_DATABASE_MISSING' "Database(s) disappeared while Veeam was stopping: $($vanishedDatabases -join ', '). PostgreSQL was NOT stopped."
}
foreach ($databaseName in $finalDatabases) {
    if ("$databaseName" -ceq 'postgres' -or $dumpedDatabases -ccontains "$databaseName") { continue }
    if ($hasVb365 -and (Test-Vb365CacheDatabaseName "$databaseName")) {
        Write-Log "VB365 created cache database $databaseName after STEP 6 - dumping it now" WARN
        Backup-VeeamDatabase "$databaseName"
        $veeamDatabases += [pscustomobject]@{ Product='VB365Cache'; Database="$databaseName"; Port=$pgPort }
        continue
    }
    Complete-Run $EXIT.UNSUPPORTED 'UNTRACKED_POSTGRES_DATABASES' "A non-Veeam database appeared while Veeam was stopping: $databaseName. PostgreSQL was NOT stopped."
}
Write-Log "Every database is dumped: $($veeamDatabases.Database -join ', ')" OK

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
$coldCopyAcl = Join-Path $backupDir 'datadir-acl.txt'
$icaclsPath = Join-Path $env:SystemRoot 'System32\icacls.exe'
$aclCapture = Invoke-Native $icaclsPath @($pg.DataDir, '/save', $coldCopyAcl, '/t', '/q')
if ($aclCapture.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $coldCopyAcl) -or (Get-Item -LiteralPath $coldCopyAcl).Length -eq 0) {
    Complete-Run $EXIT.PREFLIGHT 'COLD_COPY_ACL_CAPTURE_FAILED' "Could not capture the original PostgreSQL data-directory DACLs before the cold copy (exit $($aclCapture.ExitCode)). PostgreSQL was NOT modified. $($aclCapture.StdErr)"
}
# Do not import PostgreSQL/service-account ACLs into the protected recovery tree.
# The original DACLs are retained separately in datadir-acl.txt for manual restore.
$rc = Invoke-Native 'robocopy.exe' @($pg.DataDir, $coldCopy, '/E', '/COPY:DAT', '/DCOPY:DAT', '/R:1', '/W:1', '/XJ', '/NFL', '/NDL', '/NP', '/NJH', '/NJS')
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
# Windows PowerShell 5.1 loses the exit code of a Start-Process -PassThru process
# unless its handle is opened while it runs. Without it, a good install logs
# "Installer exit code: " (empty) and the run stops mid-change.
try { $null = $proc.Handle } catch { Write-Log "Could not open the installer process handle: $($_.Exception.Message)" WARN }
$timeoutMilliseconds = [math]::Min([int]::MaxValue, [int64]$installerTimeoutMinutes * 60 * 1000)
if (-not $proc.WaitForExit([int]$timeoutMilliseconds)) {
    $script:Report.IssueCode = 'INSTALLER_TIMEOUT'
    $script:Report.ActionRequired = "PAGE AN OPERATOR. The EDB installer exceeded $installerTimeoutMinutes minutes and was deliberately not killed. Check PID $($proc.Id) and RecoveryRunDir."
    Complete-Run $EXIT.ESCALATE 'INSTALLER_TIMEOUT' "The installer (PID $($proc.Id)) did not exit within $installerTimeoutMinutes minutes. It was not forcibly terminated."
}
$proc.WaitForExit()
$installerExit = $proc.ExitCode
if ($null -eq $installerExit) {
    # The verification below never trusts the exit code alone. An unreadable exit
    # code is not proof of failure, so let the version check decide.
    Write-Log 'The installer exit code could not be read. STEP 18 decides from the running version.' WARN
} else {
    Write-Log "Installer exit code: $installerExit"
}

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

if ($null -ne $installerExit -and $installerExit -ne 0) {
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
$postStartModuleProblems = @(Connect-VeeamModules -Vbr:$hasVbr -Vb365:$hasVb365 -Quiet -Reconnect)
if ($postStartModuleProblems.Count -gt 0) { $notRunning += @($postStartModuleProblems) }
if ($notRunning.Count -eq 0 -and $pgFinalProblems.Count -eq 0) {
    Write-Log 'All Veeam service startup types and running states were restored' OK
}

# ---------------------------------------------------------------------------
# STEP 21 - Turn the jobs back on and finish. No reboot unless -Reboot asked for one.
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

try { $idleBeforeEnable = Wait-VeeamIdle -Vbr $hasVbr -Vb365 $hasVb365 -TimeoutMinutes $jobWaitMinutes -Context 'before schedules are re-enabled' -CloseConsoles }
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
if ($natsDue) { $doneMsg += " NATS $($natsDiscovery.Installed) -> $($natsDiscovery.Target) is still due: run -Install again to update it." }

$successCode = Get-PolicyExitCode -Eol $script:EolBranch -UpdateAvailable $false -RebootRequired $true
if ($Reboot) {
    # The restart is booked last, right before the summary, so the delay covers the
    # few seconds this run still needs and the RMM's collection of its output.
    $restart = Invoke-DelayedReboot -DelaySeconds $RebootDelaySeconds -Vbr $hasVbr -Vb365 $hasVb365
    if ($restart.Scheduled) {
        $at = $restart.At.ToString('HH:mm:ss')
        Write-Log "Server restart booked for $at ($RebootDelaySeconds seconds from now). To cancel it: shutdown /a" WARN
        $script:Report.RebootRequired = $false
        $script:Report.RebootScheduledAt = $restart.At.ToString('s')
        # A NATS update still due keeps the RMM asking for one more -Install run.
        $bookedCode = Get-PolicyExitCode -Eol $script:EolBranch -UpdateAvailable $natsDue -RebootRequired $false
        $bookedAction = Get-RmmActionForExitCode $bookedCode
        $script:Report.ActionRequired = if ($bookedAction -eq 'None') {
            "None. The server restarts at $at; after it is back, rerun the audit to confirm."
        } else {
            "$bookedAction The server restarts at $at; after it is back, rerun the audit to confirm."
        }
        Complete-Run $bookedCode 'UPDATED_REBOOT_SCHEDULED' "$doneMsg The server restarts at $at, as -Reboot asked. After it is back, rerun the audit."
    }
    Write-Log "-Reboot was requested, but no restart was booked: $($restart.Reason)." WARN
    $script:Report.IssueCode = 'REBOOT_NOT_SCHEDULED'
    # Keep the policy action for this exit code, so an EOL run (exit 8) still asks
    # for the major-version migration ticket.
    $script:Report.ActionRequired = "$(Get-RmmActionForExitCode $successCode) -Reboot booked no restart because $($restart.Reason)."
    Complete-Run $successCode 'UPDATED_REBOOT_NOT_SCHEDULED' "$doneMsg -Reboot was requested, but no restart was booked because $($restart.Reason). Reboot through the RMM, verify LastBootUpTime, then rerun audit."
}
Complete-Run $successCode 'UPDATED_REBOOT_REQUIRED' "$doneMsg Veeam recommends restarting the server. Reboot through the RMM change-freeze workflow, verify LastBootUpTime, then rerun audit."

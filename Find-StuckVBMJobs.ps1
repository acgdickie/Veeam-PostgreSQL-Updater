<#
.SYNOPSIS
    Finds stuck Veeam Backup for Microsoft 365 (VB365, also called VBM) jobs and a
    stuck organisation sync, for monitoring and alerting from an RMM such as NinjaOne.
    Read-only.

.DESCRIPTION
    Checks every VB365 backup job and backup copy job, and every organisation's data
    sync, and reports what is stuck: the job or organisation name, why, and the times
    that matter. It changes nothing.

    An ENABLED backup or backup copy job is STUCK when:
      - its latest run has been Running for more than MaxRunHours (default 12)
      - its latest run has been Queued or Updating for more than MaxWaitHours (24)
      - it is not running and its next run time passed more than OverdueMinutes
        ago (60)
      - it is not running and its last run is more than NotRunHours old (36), or it
        has never run. A job that runs only on some days gets more time: Workdays
        +48 hours, Weekends +120 hours, one day a week +144 hours. A job with its
        schedule turned off (run by hand) is never stuck for not running.
      - its latest run ended Disconnected (the run was cut off)
    Disabled jobs are listed as INFO, never as STUCK.

    An organisation sync is STUCK when:
      - it is Queued, its scheduled time passed more than OverdueMinutes ago, and it
        never started
      - it has been Running for more than MaxRunHours
      - its last sync is more than NotRunHours old (VB365 syncs every 24 hours),
        unless a sync is running within its limit
    Only Microsoft 365 organisations with modern app-only authentication have this
    sync. On-premises organisations, and ones still on basic or legacy modern
    authentication, are not checked.

    A machine counts as a VB365 server when the VB365 service, or its program in
    Program Files, is there. A machine with only the VB365 console or PowerShell
    toolkit has nothing to check.

    RUNNING IT FROM AN RMM
    The VB365 PowerShell module needs PowerShell 7.4.2 or later. Most RMMs, NinjaOne
    included, start Windows PowerShell 5.1, so the script restarts itself under
    PowerShell 7 (pwsh.exe) and passes the exit code back.

    NINJAONE
    Each setting can also come from a NinjaOne Script Variable with the same name:
    maxRunHours, maxWaitHours, notRunHours, overdueMinutes, ninjaField, showAll.
    A parameter given on the command line wins over a Script Variable. When the
    script runs under NinjaOne and ninjaField is set, the alert text is also written
    to that device custom field (Multi-line recommended). If NinjaOne refuses the
    full text, as it may for a 200-character Text field, a shortened version is
    written. A failed write only warns.

.PARAMETER MaxRunHours
    A run or sync counts as stuck after Running this many hours. Default 12.

.PARAMETER MaxWaitHours
    A job run counts as stuck after Queued or Updating this many hours. Default 24.

.PARAMETER NotRunHours
    A job, or an organisation sync, counts as stuck when its last run is older than
    this many hours. Default 36. A job that runs only on some days gets the extra
    time between its runs on top (see the description).

.PARAMETER OverdueMinutes
    A job that did not start this many minutes after its next run time, or a queued
    sync this many minutes past its scheduled time, counts as stuck. Default 60.

.PARAMETER NinjaField
    NinjaOne only: the device custom field to write the result to. Empty = none.

.PARAMETER ShowAll
    Also list every healthy and disabled job and organisation.

.NOTES
    Run it on the VB365 server, elevated (an RMM runs it as SYSTEM).

    EXIT CODES
      0  Nothing is stuck, or VB365 is not installed on this server (then PowerShell
         7 is not needed)
      5  Something is stuck: the output names each job or organisation and why
      1  The check could not run, for example PowerShell 7 is missing
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 8760)][int] $MaxRunHours = 12,
    [ValidateRange(1, 8760)][int] $MaxWaitHours = 24,
    [ValidateRange(1, 8760)][int] $NotRunHours = 36,
    [ValidateRange(1, 525600)][int] $OverdueMinutes = 60,
    [string] $NinjaField = '',
    [switch] $ShowAll
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# The child run under PowerShell 7 hands the alert text to the parent through this
# file, so the parent - the process NinjaOne started - writes the custom field.
$script:FieldFileVariable = 'FIND_STUCK_VBM_JOBS_FIELD_FILE'
# Set before the restart, so a restart that still did not reach PowerShell 7 never
# restarts again.
$script:RestartVariable = 'FIND_STUCK_VBM_JOBS_RESTARTED'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Read a property without tripping StrictMode on a missing one.
function Get-Prop {
    param($Object, [Parameter(Mandatory)][string] $Name)
    if ($null -eq $Object) { return $null }
    if (@($Object.PSObject.Properties.Name) -contains $Name) { return $Object.$Name }
    return $null
}

# VB365 returns local times. Convert UTC values; treat placeholders as no time.
function ConvertTo-LocalTime {
    param($Value)
    if ($Value -is [DateTimeOffset]) { $Value = $Value.LocalDateTime }
    if ($Value -isnot [datetime]) { return $null }
    if ($Value.Year -le 1900) { return $null }
    if ($Value.Kind -eq [DateTimeKind]::Utc) { return $Value.ToLocalTime() }
    return $Value
}

function Format-Time {
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm') }
    return 'unknown'
}

# A setting comes from the command line first, then from an environment variable
# of the same name (how NinjaOne passes Script Variables: always as text, with
# empty or 'null' meaning unset), then from the default.
function Resolve-CheckSetting {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)] $Bound,
        $Default,
        [ValidateSet('Int','String','Bool')][string] $Kind = 'Int',
        [int] $Min = 1,
        [int] $Max = 525600
    )
    if ($Bound.ContainsKey($Name)) {
        $value = $Bound[$Name]
        if ($Kind -eq 'Bool') { return [bool]$value }
        return $value
    }
    $raw = [Environment]::GetEnvironmentVariable($Name)
    if ($null -eq $raw) { return $Default }
    $text = "$raw".Trim()
    if ($text -eq '' -or $text -eq 'null') { return $Default }
    switch ($Kind) {
        'String' { return $text }
        'Bool' {
            if ($text -in @('true','1','yes')) { return $true }
            if ($text -in @('false','0','no')) { return $false }
            throw "Setting $Name is '$text', not true or false"
        }
        default {
            $number = 0
            if (-not [int]::TryParse($text, [ref]$number)) { throw "Setting $Name is '$text', not a whole number" }
            if ($number -lt $Min -or $number -gt $Max) { throw "Setting $Name is $number; it must be between $Min and $Max" }
            return $number
        }
    }
}

function Test-RunByNinjaOne {
    return [bool]("$env:NINJA_AGENT_NODE_ID".Trim())
}

function Find-NinjaCli {
    foreach ($candidate in @("$env:NINJARMMCLI", 'C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe')) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $candidate }
    }
    return $null
}

function Find-PowerShell7 {
    # Only PowerShell 7 or later: PowerShell 6 is also pwsh.exe, and restarting
    # under it would loop.
    $candidates = @(Get-Command pwsh.exe -CommandType Application -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    # A 32-bit RMM host sees the 32-bit Program Files; PowerShell 7 is 64-bit.
    foreach ($root in @($env:ProgramW6432, $env:ProgramFiles)) {
        if ($root) { $candidates += Join-Path $root 'PowerShell\7\pwsh.exe' }
    }
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        $major = 0
        try { $major = (Get-Item -LiteralPath $candidate).VersionInfo.FileMajorPart } catch {}
        if ($major -ge 7) { return $candidate }
    }
    return $null
}

# Is this a VB365 server, and where is its PowerShell module? Installed is true when
# the VB365 service, or its program in Program Files, is there. The module alone is
# not enough: the VB365 console and the PowerShell toolkit install it on machines
# that are not VB365 servers. The module is looked for in Program Files, then next
# to the service's program (VB365 can be installed in another folder).
function Find-Vb365Module {
    $relative = 'Veeam.Archiver.PowerShell\Veeam.Archiver.PowerShell.psd1'
    $folders = @()
    foreach ($root in @($env:ProgramW6432, $env:ProgramFiles)) {
        if ($root) { $folders += Join-Path $root 'Veeam\Backup365' }
    }
    $service = Get-Service -Name 'Veeam.Archiver.Service' -ErrorAction SilentlyContinue
    $installed = [bool]$service
    foreach ($folder in $folders) {
        if (Test-Path -LiteralPath (Join-Path $folder 'Veeam.Archiver.Service.exe') -PathType Leaf) { $installed = $true }
    }
    if (-not $installed) { return [pscustomobject]@{ Path = $null; Installed = $false } }
    foreach ($folder in $folders) {
        $candidate = Join-Path $folder $relative
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return [pscustomobject]@{ Path = $candidate; Installed = $true } }
    }
    if (-not $service) { return [pscustomobject]@{ Path = $null; Installed = $true } }
    $serviceCommand = "$((Get-CimInstance Win32_Service -Filter "Name='Veeam.Archiver.Service'" -ErrorAction Stop).PathName)".Trim()
    $exe = if ($serviceCommand -match '^"([^"]+)"') { $Matches[1] } elseif ($serviceCommand -match '^(.+?\.exe)\b') { $Matches[1] } else { $serviceCommand }
    if ($exe) {
        $candidate = Join-Path (Split-Path -Parent $exe) $relative
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return [pscustomobject]@{ Path = $candidate; Installed = $true } }
    }
    return [pscustomobject]@{ Path = $null; Installed = $true }
}

# Write the alert text to a NinjaOne custom field. The full text is tried first;
# if NinjaOne refuses it (a Text field holds 200 characters), the short version is
# tried. A failed write only warns: it never changes the result.
function Publish-NinjaField {
    param([Parameter(Mandatory)][string] $Field, [string] $Text, [string] $ShortText)
    $cli = Find-NinjaCli
    if (-not $cli) {
        Write-Output "WARNING: NinjaOne field '$Field' was not written: ninjarmm-cli.exe was not found."
        return
    }
    $last = $null
    foreach ($candidate in @($Text, $ShortText)) {
        if (-not $candidate) { continue }
        $last = Invoke-NinjaCliSet -Cli $cli -Field $Field -Text $candidate
        if ($last.ExitCode -eq 0) { return }
    }
    $why = if ($last -and $last.Output) { $last.Output } else { 'no reason given' }
    Write-Output "WARNING: NinjaOne field '$Field' was not written: $why"
}

function Invoke-NinjaCliSet {
    param([Parameter(Mandatory)][string] $Cli, [Parameter(Mandatory)][string] $Field, [Parameter(Mandatory)][string] $Text)
    # Native stderr must not become a terminating error. The text is sent as UTF-8
    # so job names with accents survive; Windows PowerShell 5.1 only reads the
    # global $OutputEncoding. A cli that cannot start is a failed write, never an
    # old exit code read as success.
    $ErrorActionPreference = 'Continue'
    $savedEncoding = $global:OutputEncoding
    $global:OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $global:LASTEXITCODE = $null
    try {
        $output = ($Text | & $Cli set --stdin $Field 2>&1 | Out-String).Trim()
    } catch {
        return [pscustomobject]@{ ExitCode = 1; Output = $_.Exception.Message }
    } finally {
        $global:OutputEncoding = $savedEncoding
    }
    $code = $global:LASTEXITCODE
    if ($null -eq $code) { $code = 1 }
    return [pscustomobject]@{ ExitCode = $code; Output = $output }
}

function New-RmmSummaryLine {
    param([string] $Outcome, [int] $ExitCode, [int] $StuckCount = 0, [string] $Stuck = '', [string] $Detail = '', [datetime] $Checked = (Get-Date))
    $parts = @(
        "Computer=$env:COMPUTERNAME",
        "Outcome=$Outcome",
        "ExitCode=$ExitCode",
        "StuckCount=$StuckCount",
        "Stuck=$Stuck",
        "Detail=$Detail",
        "Checked=$($Checked.ToString('s'))"
    )
    return ($parts -join '; ')
}

# The report when VB365 is not installed: nothing to check.
function New-NotInstalledReport {
    param([datetime] $Now = (Get-Date))
    $stamp = $Now.ToString('yyyy-MM-dd HH:mm')
    return [pscustomobject]@{
        Outcome = 'NOT_APPLICABLE'; ExitCode = 0
        Lines = @("VB365 is not installed on $env:COMPUTERNAME (checked $stamp): nothing to check.")
        Summary = New-RmmSummaryLine -Outcome 'NOT_APPLICABLE' -ExitCode 0 -Detail 'VB365 is not installed' -Checked $Now
        FieldText = "VB365 is not installed on $env:COMPUTERNAME (checked $stamp)."
        ShortFieldText = "NOT INSTALLED (checked $stamp)"
    }
}

# The report when the check cannot start under PowerShell 7 at all.
function New-CannotCheckReport {
    param([Parameter(Mandatory)][string] $Why, [datetime] $Now = (Get-Date))
    $Why = ($Why -replace '\s*[\r\n]+\s*', ' ').Trim().TrimEnd('.')
    $stamp = $Now.ToString('yyyy-MM-dd HH:mm')
    $text = "VB365 CHECK FAILED on $env:COMPUTERNAME (checked $stamp): $Why. The VB365 PowerShell module needs PowerShell 7.4.2 or later."
    $short = "CHECK FAILED: $Why (checked $stamp)"
    if ($short.Length -gt 200) { $short = $short.Substring(0, 197) + '...' }
    return [pscustomobject]@{
        Outcome = 'CHECK_FAILED'; ExitCode = 1; Lines = @($text)
        Summary = New-RmmSummaryLine -Outcome 'CHECK_FAILED' -ExitCode 1 -Detail $Why -Checked $Now
        FieldText = $text; ShortFieldText = $short
    }
}

# Print the report and the RMM summary line. Then the NinjaOne field: a run that
# Windows PowerShell 5.1 started hands the text back to it, else it writes the field.
function Write-ReportAndField {
    param([Parameter(Mandatory)] $Report, [string] $Field)
    foreach ($line in $Report.Lines) { Write-Output $line }
    Write-Output '=== RMM SUMMARY ==='
    Write-Output $Report.Summary
    $handOff = [Environment]::GetEnvironmentVariable($script:FieldFileVariable)
    if ($handOff) {
        try {
            # Line 1 is the short text; the rest is the full text.
            $content = @($Report.ShortFieldText -replace '[\r\n]+', ' ') + @($Report.FieldText -split "`n")
            Set-Content -LiteralPath $handOff -Value $content -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-Output "WARNING: could not hand the result to the NinjaOne field writer: $($_.Exception.Message)"
        }
    } elseif ($Field -and (Test-RunByNinjaOne)) {
        Publish-NinjaField -Field $Field -Text $Report.FieldText -ShortText $Report.ShortFieldText
    }
}

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

# The normal number of hours between a job's runs, from its schedule: 24 for a job
# that runs at least daily (or an unknown schedule), more for a job that runs only
# on some days. $null for a job whose schedule is off (it runs only by hand). An
# Immediate backup copy job follows the schedule of its backup job.
function Get-ScheduleGapHours {
    param($Job)
    $policy = Get-Prop $Job 'SchedulePolicy'
    if ("$(Get-Prop $policy 'Type')" -eq 'Immediate') { $policy = Get-Prop (Get-Prop $Job 'BackupJob') 'SchedulePolicy' }
    if ($null -eq $policy) { return 24 }
    $scheduleOn = Get-Prop $policy 'EnableSchedule'
    if ($scheduleOn -is [bool] -and -not $scheduleOn) { return $null }
    if ("$(Get-Prop $policy 'Type')" -ne 'Daily') { return 24 }
    $dailyType = "$(Get-Prop $policy 'DailyType')"
    if ($dailyType -eq 'Workdays') { return 72 }     # Friday to Monday
    if ($dailyType -eq 'Weekends') { return 144 }    # Sunday to Saturday
    if ($dailyType -in @('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')) { return 168 }
    return 24
}

# Judge one job from its own record and its latest session.
function Get-Vb365JobFinding {
    param(
        [Parameter(Mandatory)] $Job,
        [string] $JobType = 'backup job',
        $LastSession,
        [Parameter(Mandatory)][datetime] $Now,
        [int] $MaxRunHours = 12,
        [int] $MaxWaitHours = 24,
        [int] $NotRunHours = 36,
        [int] $OverdueMinutes = 60
    )
    $name = "$(Get-Prop $Job 'Name')"
    if (-not $name) { $name = "$(Get-Prop $Job 'Id')" }
    $finding = [pscustomobject]@{
        Kind = 'Job'; Name = $name; Type = $JobType; State = 'OK'
        Reasons = @(); Tags = @(); Context = ''
    }

    $enabled = Get-Prop $Job 'IsEnabled'
    if ($enabled -is [bool] -and -not $enabled) {
        $finding.State = 'INFO'
        $finding.Reasons = @('disabled')
        return $finding
    }

    $reasons = @(); $tags = @()
    $status = "$(Get-Prop $LastSession 'Status')"
    $started = ConvertTo-LocalTime (Get-Prop $LastSession 'CreationTime')
    $ended = ConvertTo-LocalTime (Get-Prop $LastSession 'EndTime')
    $active = $status -in @('Running','Queued','Updating')

    if ($status -eq 'Running' -and $started -and ($Now - $started).TotalHours -gt $MaxRunHours) {
        $reasons += ('has been running for {0:N1} hours (started {1})' -f ($Now - $started).TotalHours, (Format-Time $started))
        $tags += 'running too long'
    }
    if ($status -in @('Queued','Updating') -and $started -and ($Now - $started).TotalHours -gt $MaxWaitHours) {
        $reasons += ('has been {0} for {1:N1} hours (since {2})' -f $status, ($Now - $started).TotalHours, (Format-Time $started))
        $tags += 'waiting too long'
    }
    if ($status -eq 'Disconnected') {
        $when = if ($ended) { $ended } else { $started }
        $reasons += "last run was cut off (Disconnected) at $(Format-Time $when)"
        $tags += 'cut off'
    }

    if (-not $active) {
        $nextRun = ConvertTo-LocalTime (Get-Prop $Job 'NextRun')
        if ($nextRun -and $nextRun -lt $Now.AddMinutes(-$OverdueMinutes)) {
            $reasons += "missed its schedule: it was due at $(Format-Time $nextRun) and did not start"
            $tags += 'missed schedule'
        }
        $lastRun = ConvertTo-LocalTime (Get-Prop $Job 'LastRun')
        if (-not $lastRun) { $lastRun = $started }
        # NotRunHours is for a daily job; a job that runs only on some days gets
        # the extra hours between its runs on top.
        $gap = Get-ScheduleGapHours $Job
        if ($null -eq $gap) {
            # Its schedule is off: it runs only by hand, so not running is not stuck.
        } elseif (-not $lastRun) {
            # A new job waiting for its first scheduled run is not stuck. Its first
            # run gets the same grace as a missed schedule.
            if (-not ($nextRun -and $nextRun -ge $Now.AddMinutes(-$OverdueMinutes))) {
                $reasons += 'has never run'
                $tags += 'never run'
            }
        } elseif (($Now - $lastRun).TotalHours -gt ($NotRunHours + [math]::Max(0, $gap - 24))) {
            $reasons += ('has not run for {0:N1} hours (last run {1})' -f ($Now - $lastRun).TotalHours, (Format-Time $lastRun))
            $tags += 'not run'
        }
    }

    $lastBackup = ConvertTo-LocalTime (Get-Prop $Job 'LastBackup')
    if ($lastBackup) { $finding.Context = "Last backup: $(Format-Time $lastBackup)." }
    $finding.Reasons = @($reasons)
    $finding.Tags = @($tags)
    if ($reasons.Count -gt 0) { $finding.State = 'STUCK' }
    return $finding
}

# Judge one organisation's sync: the whole organisation and each part.
function Get-Vb365OrgSyncFinding {
    param(
        [Parameter(Mandatory)][string] $Organization,
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)][datetime] $Now,
        [int] $MaxRunHours = 12,
        [int] $NotRunHours = 36,
        [int] $OverdueMinutes = 60
    )
    $finding = [pscustomobject]@{
        Kind = 'Organisation'; Name = $Organization; Type = 'organisation sync'; State = 'OK'
        Reasons = @(); Tags = @(); Context = ''
    }

    $scopes = @([pscustomobject]@{ Scope = 'All'; Current = (Get-Prop $State 'CurrentState') })
    $parts = Get-Prop $State 'Parts'
    foreach ($partName in @('Users','Groups','GroupMembers','Sites','Mailboxes')) {
        $part = Get-Prop $parts $partName
        if ($null -eq $part) { continue }
        $scopes += [pscustomobject]@{ Scope = $partName; Current = (Get-Prop $part 'CurrentState') }
    }

    $neverStarted = [ordered]@{}
    $runningLong = [ordered]@{}
    $runningOk = $false
    $runSince = $null
    foreach ($entry in $scopes) {
        if ($null -eq $entry.Current) { continue }
        $status = "$(Get-Prop $entry.Current 'Status')"
        $startTime = ConvertTo-LocalTime (Get-Prop $entry.Current 'StartTime')
        $scheduled = ConvertTo-LocalTime (Get-Prop $entry.Current 'ScheduledTime')
        if ($status -eq 'Queued' -and -not $startTime -and $scheduled -and $scheduled -lt $Now.AddMinutes(-$OverdueMinutes)) {
            $key = Format-Time $scheduled
            if (-not $neverStarted.Contains($key)) { $neverStarted[$key] = [pscustomobject]@{ Since = $scheduled; Scopes = @() } }
            $neverStarted[$key].Scopes += $entry.Scope
        } elseif ($status -eq 'Running') {
            if ($startTime -and ($Now - $startTime).TotalHours -gt $MaxRunHours) {
                $key = Format-Time $startTime
                if (-not $runningLong.Contains($key)) { $runningLong[$key] = [pscustomobject]@{ Since = $startTime; Scopes = @() } }
                $runningLong[$key].Scopes += $entry.Scope
            } else {
                $runningOk = $true
                # When this run was booked: parts queued for the same run or later
                # are waiting their turn, not stuck.
                $since = if ($scheduled) { $scheduled } else { $startTime }
                if ($since -and (-not $runSince -or $since -lt $runSince)) { $runSince = $since }
            }
        }
    }

    $reasons = @(); $tags = @()
    foreach ($key in $neverStarted.Keys) {
        $queued = $neverStarted[$key]
        if ($runSince -and $queued.Since -ge $runSince) { continue }
        $reasons += "sync queued since $key and never started ($($queued.Scopes -join ', '))"
        $tags += 'never started'
    }
    foreach ($key in $runningLong.Keys) {
        $run = $runningLong[$key]
        $reasons += ('sync has been running for {0:N1} hours (since {1}) ({2})' -f ($Now - $run.Since).TotalHours, $key, ($run.Scopes -join ', '))
        $tags += 'sync running too long'
    }

    $lastSync = ConvertTo-LocalTime (Get-Prop $State 'LastSyncTime')
    $syncStatus = "$(Get-Prop $State 'SyncStatus')"
    if (-not $runningOk -and $runningLong.Count -eq 0) {
        if (-not $lastSync) {
            $reasons += 'has never synced'
            $tags += 'never synced'
        } elseif (($Now - $lastSync).TotalHours -gt $NotRunHours) {
            $reasons += ('has not synced for {0:N1} hours' -f ($Now - $lastSync).TotalHours)
            $tags += 'not synced'
        }
    }
    if ($lastSync) {
        $finding.Context = "Last sync: $(Format-Time $lastSync)$(if ($syncStatus) { " ($syncStatus)" })."
    }
    $finding.Reasons = @($reasons)
    $finding.Tags = @($tags)
    if ($reasons.Count -gt 0) { $finding.State = 'STUCK' }
    return $finding
}

# Build the alert text, the RMM summary line, the field texts and the exit code.
function Format-StuckReport {
    param(
        [AllowEmptyCollection()][object[]] $Findings = @(),
        [AllowEmptyCollection()][string[]] $CheckErrors = @(),
        [string] $Computer = $env:COMPUTERNAME,
        [datetime] $Now = (Get-Date),
        [switch] $ShowAll
    )
    $all = @($Findings | Where-Object { $_ })
    $stuck = @($all | Where-Object { $_.State -eq 'STUCK' })
    $okJobs = @($all | Where-Object { $_.State -eq 'OK' -and $_.Kind -eq 'Job' })
    $okOrgs = @($all | Where-Object { $_.State -eq 'OK' -and $_.Kind -eq 'Organisation' })
    $disabled = @($all | Where-Object { $_.State -eq 'INFO' })
    # One line each: the RMM summary and the field hand-off are line-based.
    $errors = @($CheckErrors | Where-Object { $_ } | ForEach-Object { ($_ -replace '\s*[\r\n]+\s*', ' ').Trim() })
    $checked = $Now.ToString('yyyy-MM-dd HH:mm')

    $itemLines = @()
    foreach ($item in $stuck) {
        $label = if ($item.Kind -eq 'Job') { "Job '$($item.Name)' ($($item.Type))" } else { "Organisation '$($item.Name)'" }
        $line = "- ${label}: $($item.Reasons -join '; ')."
        if ($item.Context) { $line += " $($item.Context)" }
        $itemLines += $line
    }
    foreach ($problem in $errors) { $itemLines += "- Could not check: $problem" }

    $footer = 'OK: {0} job(s) healthy, {1} organisation(s) syncing normally.' -f $okJobs.Count, $okOrgs.Count
    if ($disabled.Count -gt 0) { $footer += " INFO: $($disabled.Count) job(s) disabled." }

    if ($stuck.Count -gt 0) {
        $outcome = 'STUCK'; $exitCode = 5
        $header = "VB365 STUCK: $($stuck.Count) problem(s) on $Computer (checked $checked)"
    } elseif ($errors.Count -gt 0) {
        $outcome = 'CHECK_FAILED'; $exitCode = 1
        $header = "VB365 CHECK FAILED on $Computer (checked $checked)"
    } else {
        $outcome = 'OK'; $exitCode = 0
        $header = "VB365 OK on $Computer (checked $checked): $($footer.Substring(4))"
    }

    $lines = @($header)
    if ($outcome -ne 'OK') { $lines += $itemLines; $lines += $footer }
    if ($ShowAll) {
        foreach ($item in @($okJobs + $okOrgs)) {
            $label = if ($item.Kind -eq 'Job') { "Job '$($item.Name)' ($($item.Type))" } else { "Organisation '$($item.Name)'" }
            $lines += "  OK    $label$(if ($item.Context) { ". $($item.Context)" })"
        }
        foreach ($item in $disabled) { $lines += "  INFO  Job '$($item.Name)' ($($item.Type)): disabled" }
    }

    $stuckTags = @($stuck | ForEach-Object {
        $what = if ($_.Kind -eq 'Job') { $_.Name } else { "$($_.Name) sync" }
        "$what [$(@($_.Tags | Select-Object -Unique) -join ', ')]"
    }) -join '; '
    $detail = if ($outcome -eq 'CHECK_FAILED') { ($errors -join ' | ') } else { '' }
    $summary = New-RmmSummaryLine -Outcome $outcome -ExitCode $exitCode -StuckCount $stuck.Count -Stuck $stuckTags -Detail $detail -Checked $Now

    $fieldText = (@($header) + $(if ($outcome -ne 'OK') { @($itemLines) + @($footer) } else { @() })) -join "`n"
    $short = switch ($outcome) {
        'STUCK'        { "STUCK $($stuck.Count): $stuckTags (checked $checked)" }
        'CHECK_FAILED' { "CHECK FAILED: $($errors -join ' | ') (checked $checked)" }
        default        { "OK (checked $checked)" }
    }
    if ($short.Length -gt 200) { $short = $short.Substring(0, 197) + '...' }

    return [pscustomobject]@{
        Outcome = $outcome; ExitCode = $exitCode; Lines = $lines; Summary = $summary
        FieldText = $fieldText; ShortFieldText = $short
    }
}

# ---------------------------------------------------------------------------
# Windows PowerShell 5.1: restart under PowerShell 7 and pass the result back
# ---------------------------------------------------------------------------
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $fieldName = ''
    try { $fieldName = Resolve-CheckSetting -Name 'NinjaField' -Bound $PSBoundParameters -Default '' -Kind String } catch {}
    $wantField = $fieldName -and (Test-RunByNinjaOne)
    $restarted = [bool]"$([Environment]::GetEnvironmentVariable($script:RestartVariable))"
    $pwsh = if ($restarted) { $null } else { Find-PowerShell7 }

    if (-not $pwsh -or -not $PSCommandPath) {
        # PowerShell 7 is only needed for the VB365 module. No VB365: nothing to check.
        $installed = $true
        try { $installed = (Find-Vb365Module).Installed } catch {}
        if (-not $installed) {
            Write-ReportAndField -Report (New-NotInstalledReport) -Field $fieldName
            exit 0
        }
        if ($restarted) {
            $why = "the restart reached PowerShell $($PSVersionTable.PSVersion), not PowerShell 7"
        } elseif (-not $PSCommandPath) {
            $why = 'the script is not running from a file, so it cannot restart under PowerShell 7'
        } else {
            $why = 'PowerShell 7 (pwsh.exe) is not installed'
        }
        Write-ReportAndField -Report (New-CannotCheckReport -Why $why) -Field $fieldName
        exit 1
    }

    $childArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    foreach ($key in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { $childArgs += "-$key" }
        } else {
            $childArgs += "-$key"
            # Windows PowerShell 5.1 drops an empty argument; "" reaches pwsh as empty.
            $childArgs += $(if ("$value" -eq '') { '""' } else { "$value" })
        }
    }

    [Environment]::SetEnvironmentVariable($script:RestartVariable, '1', 'Process')
    $fieldFile = $null
    if ($wantField) {
        try {
            # Not GetTempFileName: it fails once %TEMP% holds 65,536 tmp*.tmp files.
            $fieldFile = Join-Path ([IO.Path]::GetTempPath()) ('find-stuck-vbm-jobs-{0}.txt' -f [guid]::NewGuid())
            [IO.File]::WriteAllText($fieldFile, '')
            [Environment]::SetEnvironmentVariable($script:FieldFileVariable, $fieldFile, 'Process')
        } catch {
            $fieldFile = $null
            Write-Output "WARNING: could not create the hand-off file for NinjaOne field '$fieldName' ($($_.Exception.Message)). The PowerShell 7 run writes the field itself."
        }
    }

    # Exit code: pwsh -File returns the child's exit code. Anything unreadable, or a
    # pwsh that cannot start, is a check failure, never success.
    $ErrorActionPreference = 'Continue'
    $childCode = 1
    $global:LASTEXITCODE = $null
    try {
        & $pwsh @childArgs
        if ($null -ne $global:LASTEXITCODE) { $childCode = $global:LASTEXITCODE }
    } catch {
        $reason = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        if ($fieldFile) { Remove-Item -LiteralPath $fieldFile -Force -ErrorAction SilentlyContinue }
        [Environment]::SetEnvironmentVariable($script:FieldFileVariable, $null, 'Process')
        Write-ReportAndField -Report (New-CannotCheckReport -Why "PowerShell 7 ($pwsh) could not start: $reason") -Field $fieldName
        exit 1
    }

    if ($fieldFile) {
        $fieldLines = @()
        try { $fieldLines = @(Get-Content -LiteralPath $fieldFile -Encoding UTF8 -ErrorAction Stop) } catch {}
        Remove-Item -LiteralPath $fieldFile -Force -ErrorAction SilentlyContinue
        if ($fieldLines.Count -ge 2) {
            Publish-NinjaField -Field $fieldName -Text (($fieldLines | Select-Object -Skip 1) -join "`n") -ShortText $fieldLines[0]
        } else {
            Write-Output "WARNING: NinjaOne field '$fieldName' was not written: the PowerShell 7 run returned no result."
        }
    }
    exit $childCode
}

# ---------------------------------------------------------------------------
# PowerShell 7: the check itself
# ---------------------------------------------------------------------------
$now = Get-Date
$findings = @()
$checkErrors = @()
$notApplicable = $false
$settings = $null

try {
    $settings = [pscustomobject]@{
        MaxRunHours    = Resolve-CheckSetting -Name 'MaxRunHours'    -Bound $PSBoundParameters -Default 12 -Max 8760
        MaxWaitHours   = Resolve-CheckSetting -Name 'MaxWaitHours'   -Bound $PSBoundParameters -Default 24 -Max 8760
        NotRunHours    = Resolve-CheckSetting -Name 'NotRunHours'    -Bound $PSBoundParameters -Default 36 -Max 8760
        OverdueMinutes = Resolve-CheckSetting -Name 'OverdueMinutes' -Bound $PSBoundParameters -Default 60
        NinjaField     = Resolve-CheckSetting -Name 'NinjaField'     -Bound $PSBoundParameters -Default '' -Kind String
        ShowAll        = Resolve-CheckSetting -Name 'ShowAll'        -Bound $PSBoundParameters -Default $false -Kind Bool
    }
} catch {
    $checkErrors += "invalid setting: $($_.Exception.Message)"
}

$modulePath = $null
if ($checkErrors.Count -eq 0) {
    try {
        $vb365 = Find-Vb365Module
        if (-not $vb365.Installed) { $notApplicable = $true }
        elseif (-not $vb365.Path) { $checkErrors += 'the VB365 service (Veeam.Archiver.Service) is installed, but its PowerShell module was not found' }
        else { $modulePath = $vb365.Path }
    } catch {
        $checkErrors += "could not find out if VB365 is installed: $($_.Exception.Message)"
    }
}
if ($modulePath) {
    try {
        Import-Module $modulePath -ErrorAction Stop -WarningAction SilentlyContinue
        $null = Connect-VBOServer -ErrorAction Stop 3>$null 6>$null
    } catch {
        $checkErrors += "could not connect to VB365: $($_.Exception.Message)"
    }
}

if (-not $notApplicable -and $checkErrors.Count -eq 0) {
    $jobs = @()
    try { $jobs += @(Get-VBOJob -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Job = $_; Type = 'backup job' } }) }
    catch { $checkErrors += "could not list backup jobs: $($_.Exception.Message)" }
    if (Get-Command Get-VBOCopyJob -ErrorAction SilentlyContinue) {
        try { $jobs += @(Get-VBOCopyJob -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Job = $_; Type = 'backup copy job' } }) }
        catch { $checkErrors += "could not list backup copy jobs: $($_.Exception.Message)" }
    }
    foreach ($entry in $jobs) {
        $jobName = "$(Get-Prop $entry.Job 'Name')"
        $session = $null
        try { $session = Get-VBOJobSession -Job $entry.Job -Last -ErrorAction Stop | Select-Object -First 1 }
        catch { $checkErrors += "job '$jobName': could not read its last run: $($_.Exception.Message)"; continue }
        $findings += Get-Vb365JobFinding -Job $entry.Job -JobType $entry.Type -LastSession $session -Now $now `
            -MaxRunHours $settings.MaxRunHours -MaxWaitHours $settings.MaxWaitHours `
            -NotRunHours $settings.NotRunHours -OverdueMinutes $settings.OverdueMinutes
    }

    $organizations = @()
    try { $organizations = @(Get-VBOOrganization -ErrorAction Stop) }
    catch { $checkErrors += "could not list organisations: $($_.Exception.Message)" }
    foreach ($org in $organizations) {
        $orgName = "$(Get-Prop $org 'Name')"
        if (-not $orgName) { $orgName = "$(Get-Prop $org 'Id')" }
        # Only Microsoft 365 organisations with modern app-only authentication have
        # this sync. On-premises ones, and ones still on basic or legacy modern
        # authentication, do not. When no authentication type can be read, the
        # organisation is still checked.
        if ("$(Get-Prop $org 'Type')" -eq 'OnPremises') { continue }
        $authTypes = @(foreach ($connection in @('Office365ExchangeConnectionSettings', 'Office365SharePointConnectionSettings')) {
            $authType = "$(Get-Prop (Get-Prop $org $connection) 'AuthenticationType')"
            if ($authType) { $authType }
        })
        if ($authTypes.Count -gt 0 -and $authTypes -notcontains 'ApplicationOnly') { continue }
        try { $syncState = Get-VBOOrganizationSynchronizationState -Organization $org -ErrorAction Stop }
        catch { $checkErrors += "organisation '$orgName': could not read its sync state: $($_.Exception.Message)"; continue }
        if ($null -eq $syncState) { $checkErrors += "organisation '$orgName': no sync state was returned"; continue }
        $findings += Get-Vb365OrgSyncFinding -Organization $orgName -State $syncState -Now $now `
            -MaxRunHours $settings.MaxRunHours -NotRunHours $settings.NotRunHours -OverdueMinutes $settings.OverdueMinutes
    }
}

if ($notApplicable) {
    $report = New-NotInstalledReport -Now $now
} else {
    $showAllNow = $ShowAll.IsPresent
    if ($settings) { $showAllNow = [bool]$settings.ShowAll }
    $report = Format-StuckReport -Findings $findings -CheckErrors $checkErrors -Now $now -ShowAll:$showAllNow
}

$fieldName = if ($settings) { "$($settings.NinjaField)" } else { '' }
Write-ReportAndField -Report $report -Field $fieldName

exit $report.ExitCode

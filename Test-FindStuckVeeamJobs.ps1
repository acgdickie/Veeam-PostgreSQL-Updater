# The tests for Find-StuckVeeamJobs.ps1. For whoever edits the script: never copy this
# file to a Veeam server or add it to the RMM.
#
# Extracts the real functions out of Find-StuckVeeamJobs.ps1 via the AST and runs the
# stuck rules against fake VB365 objects, so no VB365 is needed. The end-to-end part
# runs the real script on this PC (which has no VB365): Windows PowerShell 5.1 must
# restart it under PowerShell 7, pass the exit code back, and write a fake NinjaOne
# field. Only throw-away files under %TEMP% are created, and removed again.
#
# Run after every change, on BOTH editions:
#   powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\Test-FindStuckVeeamJobs.ps1
#   pwsh.exe       -ExecutionPolicy Bypass -NoProfile -File .\Test-FindStuckVeeamJobs.ps1
# A pass ends "RESULT: <n> passed, 0 failed" with exit code 0.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:Path = Join-Path $PSScriptRoot 'Find-StuckVeeamJobs.ps1'
$errs = $null; $toks = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Path, [ref]$toks, [ref]$errs)
if ($errs -and $errs.Count) { throw "parse errors: $($errs.Count)" }

$want = 'Get-Prop','ConvertTo-LocalTime','Format-Time','Resolve-CheckSetting','Test-RunByNinjaOne',
        'Find-NinjaCli','Find-PowerShell7','Find-Vb365Module','New-RmmSummaryLine','New-CannotCheckReport','Publish-NinjaField',
        'Get-ScheduleGapHours','Get-Vb365JobFinding','Get-Vb365OrgSyncFinding','Format-StuckReport'
$functionAsts = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
foreach ($fn in $functionAsts) {
    if ($want -contains $fn.Name) { . ([scriptblock]::Create($fn.Extent.Text)) }
}
$scriptText = Get-Content -LiteralPath $script:Path -Raw

$pass = 0; $fail = 0
function Check {
    param([string]$Name, $Actual, $Expected)
    # Case matters: 'false' and 'False' are not the same answer.
    if ("$Actual" -ceq "$Expected") { $script:pass++; "  PASS  $Name" }
    else { $script:fail++; "  FAIL  $Name  expected '$Expected' got '$Actual'" }
}
function Throws {
    param([Parameter(Mandatory)][scriptblock] $Action)
    try { & $Action | Out-Null; return $false } catch { return $true }
}

$now = [datetime]::new(2026, 10, 13, 12, 30, 0, [DateTimeKind]::Local)
function J($Name = 'Example Backup Job', $Enabled = $true, $LastRun = $now.AddHours(-20), $NextRun = $now.AddHours(4), $LastBackup = $now.AddHours(-20), $Policy = $null, $BackupJob = $null) {
    $job = [pscustomobject]@{ Name = $Name; IsEnabled = $Enabled; LastRun = $LastRun; NextRun = $NextRun; LastBackup = $LastBackup }
    if ($Policy) { $job | Add-Member -NotePropertyName SchedulePolicy -NotePropertyValue $Policy }
    if ($BackupJob) { $job | Add-Member -NotePropertyName BackupJob -NotePropertyValue $BackupJob }
    $job
}
function P($Type = 'Daily', $DailyType = 'Everyday', $On = $true) { [pscustomobject]@{ Type = $Type; DailyType = $DailyType; EnableSchedule = $On } }
function S($Status, $Created = $now.AddHours(-20), $Ended = $null) {
    [pscustomobject]@{ Status = $Status; CreationTime = $Created; EndTime = $Ended }
}
function JobFinding($Job, $Session) { Get-Vb365JobFinding -Job $Job -LastSession $Session -Now $now }

'--- Job rules ---'
$f = JobFinding (J) (S 'Success' $now.AddHours(-20) $now.AddHours(-19))
Check 'healthy job is OK'                     $f.State 'OK'
Check 'healthy job keeps its last backup'     ($f.Context -match '^Last backup: 2026-10-12 16:30\.$') 'True'

$f = JobFinding (J -LastRun $now.AddHours(-13)) (S 'Running' $now.AddHours(-13))
Check 'running 13 h is stuck'                 $f.State 'STUCK'
Check 'running too long is tagged'            ($f.Tags -join ',') 'running too long'
Check 'running reason has hours and start'    ($f.Reasons[0] -match '^has been running for 13\.0 hours \(started 2026-10-12 23:30\)$') 'True'
Check 'running 5 h is OK'                     (JobFinding (J) (S 'Running' $now.AddHours(-5))).State 'OK'

Check 'queued 25 h is stuck'                  (JobFinding (J) (S 'Queued' $now.AddHours(-25))).State 'STUCK'
Check 'queued 23 h is OK (24 h limit)'        (JobFinding (J) (S 'Queued' $now.AddHours(-23))).State 'OK'
$f = JobFinding (J) (S 'Updating' $now.AddHours(-30))
Check 'updating 30 h is stuck'                ($f.Reasons[0] -match '^has been Updating for 30\.0 hours') 'True'
Check 'waiting too long is tagged'            ($f.Tags -join ',') 'waiting too long'

# A job whose last run was cut off: it was not running, its latest session ended
# Disconnected.
$f = JobFinding (J -Name 'Exchange Backup') (S 'Disconnected' $now.AddHours(-14) $now.AddHours(-13))
Check 'cut-off run is stuck'                  $f.State 'STUCK'
Check 'cut-off reason gives the time'         ($f.Reasons[0]) 'last run was cut off (Disconnected) at 2026-10-12 23:30'
Check 'cut-off is tagged'                     ($f.Tags -join ',') 'cut off'

$f = JobFinding (J -NextRun $now.AddHours(-2)) (S 'Success' $now.AddHours(-20) $now.AddHours(-19))
Check 'missed schedule is stuck'              ($f.Reasons -join '|') 'missed its schedule: it was due at 2026-10-13 10:30 and did not start'
Check 'due 30 min ago is OK (60 min grace)'   (JobFinding (J -NextRun $now.AddMinutes(-30)) (S 'Success')).State 'OK'
Check 'running job never misses a schedule'   (JobFinding (J -NextRun $now.AddHours(-2)) (S 'Running' $now.AddHours(-1))).State 'OK'
Check 'queued job never misses a schedule'    (JobFinding (J -NextRun $now.AddHours(-2)) (S 'Queued' $now.AddHours(-1))).State 'OK'
Check 'updating job never misses a schedule'  (JobFinding (J -NextRun $now.AddHours(-2)) (S 'Updating' $now.AddHours(-1))).State 'OK'

$f = JobFinding (J -LastRun $now.AddHours(-40)) (S 'Success' $now.AddHours(-40) $now.AddHours(-39))
Check 'not run for 40 h is stuck'             ($f.Tags -join ',') 'not run'
Check 'not-run reason gives the last run'     ($f.Reasons[0]) 'has not run for 40.0 hours (last run 2026-10-11 20:30)'
Check 'never run, nothing scheduled: stuck'   ((JobFinding (J -LastRun $null -NextRun $null) $null).Tags -join ',') 'never run'
Check 'never run, first run booked: OK'       (JobFinding (J -LastRun $null -NextRun $now.AddHours(3)) $null).State 'OK'
Check 'never run, first run just due: OK'     (JobFinding (J -LastRun $null -NextRun $now.AddMinutes(-1)) $null).State 'OK'
Check 'never run, first run 2 h late: stuck'  ((JobFinding (J -LastRun $null -NextRun $now.AddHours(-2)) $null).Tags -join ',') 'missed schedule,never run'

'--- Not-run limit follows the schedule ---'
# NotRunHours (36) is for a daily job. A job that runs on fewer days gets the extra
# time between its runs: Workdays +48 h, Weekends +120 h, one day a week +144 h.
function NotRun($Policy, $Hours, $BackupJob = $null) { (JobFinding (J -Policy $Policy -BackupJob $BackupJob -LastRun $now.AddHours(-$Hours)) (S 'Success' $now.AddHours(-$Hours))).State }
Check 'daily job, 40 h: stuck'                (NotRun (P) 40) 'STUCK'
Check 'Workdays job over a weekend, 62 h: OK' (NotRun (P -DailyType 'Workdays') 62) 'OK'
Check 'Workdays job, 90 h: stuck'             (NotRun (P -DailyType 'Workdays') 90) 'STUCK'
Check 'Weekends job, 150 h: OK'               (NotRun (P -DailyType 'Weekends') 150) 'OK'
Check 'Weekends job, 160 h: stuck'            (NotRun (P -DailyType 'Weekends') 160) 'STUCK'
Check 'Monday-only job, 170 h: OK'            (NotRun (P -DailyType 'Monday') 170) 'OK'
Check 'Monday-only job, 185 h: stuck'         (NotRun (P -DailyType 'Monday') 185) 'STUCK'
Check 'periodic job, 40 h: stuck'             (NotRun (P -Type 'Periodically') 40) 'STUCK'
Check 'the extra time adds to NotRunHours'    (Get-Vb365JobFinding -Job (J -Policy (P -DailyType 'Workdays') -LastRun $now.AddHours(-110)) -LastSession $null -Now $now -NotRunHours 72).State 'OK'
$source = J -Name 'Source' -Policy (P -DailyType 'Workdays')
Check 'Immediate copy job follows its source' (NotRun (P -Type 'Immediate') 62 $source) 'OK'
Check 'Immediate copy job of a daily source'  (NotRun (P -Type 'Immediate') 40 (J -Policy (P))) 'STUCK'
$manual = P -On $false
Check 'schedule off, last run 30 days: OK'    (NotRun $manual (30 * 24)) 'OK'
Check 'schedule off, never run: OK'           (JobFinding (J -Policy $manual -LastRun $null -NextRun $null) $null).State 'OK'
Check 'schedule off, still stuck when running too long' (JobFinding (J -Policy $manual) (S 'Running' $now.AddHours(-13))).State 'STUCK'
Check 'schedule off, still stuck when cut off' (JobFinding (J -Policy $manual) (S 'Disconnected')).State 'STUCK'

$f = JobFinding (J -Enabled $false -LastRun $now.AddDays(-30)) (S 'Disconnected')
Check 'disabled job is INFO, never STUCK'     $f.State 'INFO'
Check 'several rules give several reasons'    (JobFinding (J -NextRun $now.AddHours(-3) -LastRun $now.AddHours(-50)) (S 'Disconnected' $now.AddHours(-50))).Tags.Count 3
$utcRun = [datetime]::SpecifyKind($now.AddHours(-13).ToUniversalTime(), [DateTimeKind]::Utc)
Check 'UTC times come back as local'          (ConvertTo-LocalTime $utcRun).Kind 'Local'
Check 'a UTC start is shown in local time'    ((JobFinding (J) (S 'Running' $utcRun)).Reasons[0]) 'has been running for 13.0 hours (started 2026-10-12 23:30)'
Check 'missing properties do not throw'       (Throws { Get-Vb365JobFinding -Job ([pscustomobject]@{ Name = 'Bare' }) -LastSession $null -Now $now }) 'False'

'--- Organisation sync rules ---'
function Cur($Status, $Scheduled = $null, $Start = $null) { [pscustomobject]@{ Status = $Status; ScheduledTime = $Scheduled; StartTime = $Start } }
function Org($All, $Users = $null, $LastSync = $now.AddHours(-10), $SyncStatus = 'Success', [switch] $NoMailboxes) {
    $part = { param($c) if ($null -eq $c) { [pscustomobject]@{ CurrentState = $null } } else { [pscustomobject]@{ CurrentState = $c } } }
    [pscustomobject]@{
        LastSyncTime = $LastSync; SyncStatus = $SyncStatus; CurrentState = $All
        Parts = [pscustomobject]@{
            Users = (& $part $Users); Groups = (& $part $Users); GroupMembers = (& $part $Users); Sites = (& $part $Users)
            Mailboxes = $(if ($NoMailboxes) { $null } else { (& $part $null) })
        }
    }
}
function OrgFinding($State) { Get-Vb365OrgSyncFinding -Organization 'contoso.onmicrosoft.com' -State $State -Now $now }

Check 'sync booked for later is OK'           (OrgFinding (Org (Cur 'Queued' $now.AddHours(6)) (Cur 'Queued' $now.AddHours(6)))).State 'OK'

# A real case: every part queued since 13 days earlier, never started, last sync the
# same day, Mailboxes outside the sync scope.
$stale = $now.AddDays(-13)
$f = OrgFinding (Org (Cur 'Queued' $stale) (Cur 'Queued' $stale) -LastSync $stale.AddMinutes(-59) -NoMailboxes)
Check 'stale queued sync is stuck'            $f.State 'STUCK'
Check 'stale sync names every part once'      ($f.Reasons[0]) 'sync queued since 2026-09-30 12:30 and never started (All, Users, Groups, GroupMembers, Sites)'
Check 'stale sync is also not synced'         ($f.Tags -join ',') 'never started,not synced'
Check 'stale sync keeps the last sync'        ($f.Context) 'Last sync: 2026-09-30 11:31 (Success).'

Check 'queued 30 min overdue is OK (grace)'   (OrgFinding (Org (Cur 'Queued' $now.AddMinutes(-30)))).State 'OK'
Check 'queued with a start time is not "never started"' (OrgFinding (Org (Cur 'Queued' $stale $now.AddMinutes(-5)))).State 'OK'
$f = OrgFinding (Org $null (Cur 'Running' $null $now.AddHours(-14)) -LastSync $now.AddDays(-2))
Check 'sync running 14 h is stuck'            ($f.Tags -join ',') 'sync running too long'
Check 'running reason names the parts'        ($f.Reasons[0] -match '^sync has been running for 14\.0 hours \(since 2026-10-12 22:30\) \(Users, Groups, GroupMembers, Sites\)$') 'True'
Check 'a sync running in time hides "not synced"' (OrgFinding (Org (Cur 'Running' $null $now.AddHours(-2)) -LastSync $now.AddDays(-3))).State 'OK'
# A big sync in progress: some parts run, the others wait their turn in the same run.
$booked = $now.AddHours(-2)
$waiting = [pscustomobject]@{
    LastSyncTime = $now.AddHours(-26); SyncStatus = 'Success'; CurrentState = (Cur 'Running' $booked $booked)
    Parts = [pscustomobject]@{
        Users = [pscustomobject]@{ CurrentState = (Cur 'Running' $booked $booked) }
        Sites = [pscustomobject]@{ CurrentState = (Cur 'Queued' $booked) }
    }
}
Check 'parts waiting in a running sync are OK' (OrgFinding $waiting).State 'OK'
$waiting.Parts.Sites.CurrentState = Cur 'Queued' $stale
Check 'an older booking is still stuck'       ((OrgFinding $waiting).Reasons -join '|') 'sync queued since 2026-09-30 12:30 and never started (Sites)'
Check 'no sync for 40 h is stuck'             ((OrgFinding (Org $null -LastSync $now.AddHours(-40))).Tags -join ',') 'not synced'
Check 'never synced is stuck'                 ((OrgFinding (Org $null -LastSync $null)).Tags -join ',') 'never synced'
Check 'missing parts do not throw'            (Throws { Get-Vb365OrgSyncFinding -Organization 'x' -State ([pscustomobject]@{ LastSyncTime = $now }) -Now $now }) 'False'

'--- Report for alerts ---'
$jobStuck = JobFinding (J -Name 'Exchange Backup') (S 'Disconnected' $now.AddHours(-14) $now.AddHours(-13))
$orgStuck = OrgFinding (Org (Cur 'Queued' $stale) (Cur 'Queued' $stale) -LastSync $stale -NoMailboxes)
$okJob = JobFinding (J -Name 'SharePoint Backup') (S 'Success')
$offJob = JobFinding (J -Name 'Old Job' -Enabled $false) $null
$r = Format-StuckReport -Findings @($jobStuck, $orgStuck, $okJob, $offJob) -Computer 'VB365-SERVER' -Now $now
Check 'stuck report exits 5'                  $r.ExitCode 5
Check 'stuck report outcome'                  $r.Outcome 'STUCK'
Check 'header counts the problems'            $r.Lines[0] 'VB365 STUCK: 2 problem(s) on VB365-SERVER (checked 2026-10-13 12:30)'
Check 'the job line names the job and why'    ($r.Lines[1] -match "^- Job 'Exchange Backup' \(backup job\): last run was cut off \(Disconnected\) at 2026-10-12 23:30\. Last backup: ") 'True'
Check 'the organisation line names it'        ($r.Lines[2] -match "^- Organisation 'contoso\.onmicrosoft\.com': sync queued since 2026-09-30 12:30 and never started") 'True'
Check 'footer counts healthy and disabled'    $r.Lines[3] 'OK: 1 job(s) healthy, 0 organisation(s) syncing normally. INFO: 1 job(s) disabled.'
Check 'healthy jobs are not listed by default' (@($r.Lines | Where-Object { $_ -match 'SharePoint' }).Count) 0
Check 'summary names what is stuck'           ($r.Summary -match 'Stuck=Exchange Backup \[cut off\]; contoso\.onmicrosoft\.com sync \[never started, not synced\]') 'True'
Check 'summary has the stuck count'           ($r.Summary -match 'StuckCount=2;') 'True'
Check 'field text has every stuck item'       (@($r.FieldText -split "`n").Count) 4
Check 'short field text fits a Text field'    ($r.ShortFieldText.Length -le 200) 'True'
Check 'short field text names the job'        ($r.ShortFieldText -match '^STUCK 2: Exchange Backup \[cut off\]') 'True'
$r = Format-StuckReport -Findings @($jobStuck, $okJob) -Now $now -ShowAll
Check 'ShowAll lists healthy jobs too'        (@($r.Lines | Where-Object { $_ -match "OK    Job 'SharePoint Backup'" }).Count) 1

$r = Format-StuckReport -Findings @($okJob) -Computer 'VB365-SERVER' -Now $now
Check 'healthy report exits 0'                $r.ExitCode 0
Check 'healthy report is one line'            @($r.Lines).Count 1
Check 'healthy line reads cleanly'            $r.Lines[0] 'VB365 OK on VB365-SERVER (checked 2026-10-13 12:30): 1 job(s) healthy, 0 organisation(s) syncing normally.'

$r = Format-StuckReport -Findings @($okJob) -CheckErrors @("job 'X': could not read its last run: denied") -Now $now
Check 'check failure alone exits 1'           $r.ExitCode 1
Check 'check failure is listed'               ($r.Lines -contains "- Could not check: job 'X': could not read its last run: denied") 'True'
Check 'stuck wins over a check failure'       (Format-StuckReport -Findings @($jobStuck) -CheckErrors @('x') -Now $now).ExitCode 5
$long = Format-StuckReport -Findings @(1..30 | ForEach-Object { JobFinding (J -Name ("Job number $_ with a long name")) (S 'Disconnected') }) -Now $now
Check 'a long short-text is cut to 200'       $long.ShortFieldText.Length 200
# An error text with line breaks must not split the one-line summary or the field hand-off.
$r = Format-StuckReport -CheckErrors @("could not connect to VB365: Connection failed.`r`nThe service is not running.") -Now $now
Check 'a multi-line error stays on one line'  ($r.Lines -contains '- Could not check: could not connect to VB365: Connection failed. The service is not running.') 'True'
Check 'the summary is one line'               ($r.Summary -match '[\r\n]') 'False'
Check 'the short text is one line'            ($r.ShortFieldText -match '[\r\n]') 'False'
$r = New-CannotCheckReport -Why "PowerShell 7 could not start: Bad image.`r`n" -Now $now
Check 'cannot-check report exits 1'           "$($r.Outcome)/$($r.ExitCode)" 'CHECK_FAILED/1'
Check 'cannot-check text reads cleanly'       ($r.Lines[0] -match ': PowerShell 7 could not start: Bad image\. The VB365 PowerShell module needs') 'True'

'--- Settings: command line, then NinjaOne Script Variable, then default ---'
$bound = @{}
$env:MaxRunHours = $null
Check 'unset setting uses the default'        (Resolve-CheckSetting -Name 'MaxRunHours' -Bound $bound -Default 12) 12
$env:MaxRunHours = '18'
Check 'Script Variable is used'               (Resolve-CheckSetting -Name 'MaxRunHours' -Bound $bound -Default 12) 18
Check 'command line beats Script Variable'    (Resolve-CheckSetting -Name 'MaxRunHours' -Bound @{ MaxRunHours = 6 } -Default 12) 6
$env:MaxRunHours = 'null'
Check '"null" means unset'                    (Resolve-CheckSetting -Name 'MaxRunHours' -Bound $bound -Default 12) 12
$env:MaxRunHours = 'abc'
Check 'a non-number is refused'               (Throws { Resolve-CheckSetting -Name 'MaxRunHours' -Bound $bound -Default 12 }) 'True'
$env:MaxRunHours = '0'
Check 'out of range is refused'               (Throws { Resolve-CheckSetting -Name 'MaxRunHours' -Bound $bound -Default 12 }) 'True'
$env:MaxRunHours = $null
$env:ShowAll = 'false'
# The type matters: the text 'false' would count as true.
$v = Resolve-CheckSetting -Name 'ShowAll' -Bound $bound -Default $false -Kind Bool
Check 'checkbox false is false, not true'     ($v -is [bool] -and -not $v) 'True'
$env:ShowAll = 'true'
$v = Resolve-CheckSetting -Name 'ShowAll' -Bound $bound -Default $false -Kind Bool
Check 'checkbox true is true'                 ($v -is [bool] -and $v) 'True'
$env:ShowAll = $null

'--- NinjaOne field write ---'
& {
    function Find-NinjaCli { 'C:\fake\ninjarmm-cli.exe' }
    $script:sent = @()
    function Invoke-NinjaCliSet { param($Cli, $Field, $Text) $script:sent += $Text; [pscustomobject]@{ ExitCode = $(if ($Text.Length -gt 200) { 1 } else { 0 }); Output = 'Value too long' } }
    $warn = @(Publish-NinjaField -Field 'f' -Text ('x' * 300) -ShortText 'STUCK 1: Job [cut off]')
    Check 'a refused full text falls back to the short text' ($script:sent -join '|') (('x' * 300) + '|STUCK 1: Job [cut off]')
    Check 'a working fallback does not warn'   $warn.Count 0
    $script:sent = @()
    $warn = @(Publish-NinjaField -Field 'f' -Text ('x' * 300) -ShortText ('y' * 300))
    Check 'both refused: one warning with the reason' ($warn -join '|') "WARNING: NinjaOne field 'f' was not written: Value too long"
}

'--- Finding PowerShell 7 ---'
$fakeDir = Join-Path $env:TEMP "find-stuck-fakepwsh-$PID"
New-Item -ItemType Directory -Path $fakeDir -Force | Out-Null
try {
    Set-Content -LiteralPath (Join-Path $fakeDir 'pwsh.exe') -Value 'not a program'
    $savedPath = $env:PATH
    try {
        $env:PATH = "$fakeDir;$env:PATH"
        $found = Find-PowerShell7
    } finally { $env:PATH = $savedPath }
    Check 'a pwsh.exe that is not PowerShell 7 is skipped' ($found -and $found -ne (Join-Path $fakeDir 'pwsh.exe')) 'True'
} finally {
    Remove-Item -LiteralPath $fakeDir -Recurse -Force -ErrorAction SilentlyContinue
}

'--- Finding VB365 ---'
# Program Files is empty here, so only the VB365 service can show where VB365 is.
$vbDir = Join-Path $env:TEMP "find-stuck-fakevb-$PID"
New-Item -ItemType Directory -Path (Join-Path $vbDir 'Veeam.Archiver.PowerShell') -Force | Out-Null
$savedRoots = $env:ProgramW6432, $env:ProgramFiles
try {
    $env:ProgramW6432 = Join-Path $vbDir 'empty'; $env:ProgramFiles = $env:ProgramW6432
    & {
        function Get-Service { $null }
        $r = Find-Vb365Module
        Check 'no module and no service: not installed' "$($r.Installed) $($null -eq $r.Path)" 'False True'
    }
    & {
        function Get-Service { [pscustomobject]@{ Name = 'Veeam.Archiver.Service' } }
        function Get-CimInstance { [pscustomobject]@{ PathName = "`"$vbDir\Veeam.Archiver.Service.exe`" -service" } }
        $r = Find-Vb365Module
        Check 'service only: installed, module not found' "$($r.Installed) $($null -eq $r.Path)" 'True True'
        Set-Content -LiteralPath (Join-Path $vbDir 'Veeam.Archiver.PowerShell\Veeam.Archiver.PowerShell.psd1') -Value '@{}'
        $r = Find-Vb365Module
        Check 'installed in another folder: module found next to the service' $r.Path (Join-Path $vbDir 'Veeam.Archiver.PowerShell\Veeam.Archiver.PowerShell.psd1')
    }
} finally {
    $env:ProgramW6432, $env:ProgramFiles = $savedRoots
    Remove-Item -LiteralPath $vbDir -Recurse -Force -ErrorAction SilentlyContinue
}

'--- Rules that must always hold ---'
$commands = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
$writes = @($commands | Where-Object { $_ -match '^(Set|Start|Stop|Remove|Enable|Disable|New|Restart|Update)-VBO' })
Check 'never changes VB365 (no VBO write cmdlets)' ($writes -join ',') ''
Check 'restarts under pwsh with -File'        ($scriptText -match "'-ExecutionPolicy', 'Bypass', '-File', \`$PSCommandPath\)") 'True'
Check 'never relaunches with -Command'        ($scriptText -match "'-Command'") 'False'
Check 'reads the latest run per job'          ($scriptText -match 'Get-VBOJobSession -Job \$entry\.Job -Last') 'True'

'--- End to end on this PC (no VB365 here) ---'
# Every run starts the real script with Windows PowerShell 5.1, the way an RMM does.
# A fake VB365 module under %TEMP% stands in for VB365 when ProgramW6432 points at it
# (Windows sets ProgramFiles from ProgramW6432 in each new 64-bit process). The fake
# module needs PowerShell 7, so a STUCK result proves the restart under pwsh worked.
$e2e = Join-Path $env:TEMP "find-stuck-e2e-$PID"
New-Item -ItemType Directory -Path $e2e -Force | Out-Null
$envNames = 'NINJA_AGENT_NODE_ID','NINJARMMCLI','NinjaField','MaxRunHours','ShowAll','ProgramW6432','FAKE_VBO_MODE',
            'FIND_STUCK_VEEAM_JOBS_RESTARTED','FIND_STUCK_VEEAM_JOBS_FIELD_FILE'
$saved = @{}
foreach ($name in $envNames) { $saved[$name] = [Environment]::GetEnvironmentVariable($name) }
$realProgramW6432 = $saved['ProgramW6432']
try {
    foreach ($name in $envNames) { if ($name -ne 'ProgramW6432') { [Environment]::SetEnvironmentVariable($name, $null) } }

    function Run {
        param([string[]] $Arguments = @(), [string] $Script = $script:Path)
        $ErrorActionPreference = 'Continue'
        $out = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Script @Arguments 2>&1 | ForEach-Object { "$_" })
        [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
    }
    function Has($Run, $Pattern) { @($Run.Out | Where-Object { $_ -match $Pattern }).Count }
    function AfterSummary($Run) {
        $at = [array]::IndexOf($Run.Out, '=== RMM SUMMARY ===')
        if ($at -lt 0) { return @() }
        @($Run.Out | Select-Object -Skip ($at + 1))
    }
    # A copy of the script with only Find-PowerShell7 swapped, to test what happens
    # when PowerShell 7 is missing, cannot start, or is not really PowerShell 7.
    $finder = $functionAsts | Where-Object { $_.Name -eq 'Find-PowerShell7' } | Select-Object -First 1
    $fullText = $ast.Extent.Text
    function New-ScriptCopy([string] $Name, [string] $FinderBody) {
        $text = $fullText.Substring(0, $finder.Extent.StartOffset) + "function Find-PowerShell7 { $FinderBody }" + $fullText.Substring($finder.Extent.EndOffset)
        $copy = Join-Path $e2e $Name
        [IO.File]::WriteAllText($copy, $text)
        $copy
    }

    $fakeRoot = Join-Path $e2e 'pf'
    $moduleDir = Join-Path $fakeRoot 'Veeam\Backup365\Veeam.Archiver.PowerShell'
    New-Item -ItemType Directory -Path $moduleDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $moduleDir 'Veeam.Archiver.PowerShell.psd1') -Encoding ASCII -Value "@{ RootModule = 'Veeam.Archiver.PowerShell.psm1'; ModuleVersion = '8.0.0'; PowerShellVersion = '7.0'; FunctionsToExport = '*' }"
    Set-Content -LiteralPath (Join-Path $moduleDir 'Veeam.Archiver.PowerShell.psm1') -Encoding ASCII -Value @'
# Fake VB365: a cut-off job with an accent in its name, a healthy job, an on-premises
# organisation (its sync state cannot be read) and an organisation sync queued 13 days.
$now = Get-Date
$daily = [pscustomobject]@{ Type = 'Daily'; DailyType = 'Everyday'; EnableSchedule = $true }
function Connect-VBOServer {
    [CmdletBinding()] param()
    if ($env:FAKE_VBO_MODE -eq 'connectfail') { throw "Connection to the server failed.`r`nThe service is not running." }
}
function Get-VBOJob {
    [CmdletBinding()] param()
    [pscustomobject]@{ Name = "Caf$([char]0xE9) Exchange Backup"; IsEnabled = $true; LastRun = $now.AddHours(-14); NextRun = $now.AddHours(10); LastBackup = $now.AddDays(-2); SchedulePolicy = $daily }
    [pscustomobject]@{ Name = 'SharePoint Backup'; IsEnabled = $true; LastRun = $now.AddHours(-3); NextRun = $now.AddHours(21); LastBackup = $now.AddHours(-3); SchedulePolicy = $daily }
}
function Get-VBOCopyJob { [CmdletBinding()] param() }
function Get-VBOJobSession {
    [CmdletBinding()] param($Job, [switch] $Last)
    if ($Job.Name -like 'Caf*') { [pscustomobject]@{ Status = 'Disconnected'; CreationTime = $now.AddHours(-14); EndTime = $now.AddHours(-13) } }
    else { [pscustomobject]@{ Status = 'Success'; CreationTime = $now.AddHours(-3); EndTime = $now.AddHours(-2) } }
}
function Get-VBOOrganization {
    [CmdletBinding()] param()
    [pscustomobject]@{ Name = 'onprem.example'; Type = 'OnPremises' }
    [pscustomobject]@{ Name = 'contoso.onmicrosoft.com'; Type = 'Office365' }
}
function Get-VBOOrganizationSynchronizationState {
    [CmdletBinding()] param($Organization)
    if ($Organization.Type -eq 'OnPremises') { throw 'This organization does not support synchronization.' }
    $queued = [pscustomobject]@{ Status = 'Queued'; ScheduledTime = $now.AddDays(-13); StartTime = $null }
    [pscustomobject]@{
        LastSyncTime = $now.AddDays(-13).AddMinutes(-59); SyncStatus = 'Success'; CurrentState = $queued
        Parts = [pscustomobject]@{ Users = [pscustomobject]@{ CurrentState = $queued } }
    }
}
'@

    $r = Run
    Check 'from 5.1 it restarts under pwsh and finds no VB365' (Has $r '^VB365 is not installed on') 1
    Check 'not installed exits 0 through the restart' $r.Code 0
    Check 'summary says NOT_APPLICABLE'          (Has $r 'Outcome=NOT_APPLICABLE; ExitCode=0') 1

    # A NinjaOne Script Variable with a bad value: the child fails, exit 1 comes back.
    [Environment]::SetEnvironmentVariable('MaxRunHours', 'abc')
    $r = Run
    Check 'a bad Script Variable exits 1 through the restart' $r.Code 1
    Check 'and says which setting'               ((Has $r "invalid setting: Setting MaxRunHours is 'abc'") -ge 1) 'True'

    # Command-line parameters must reach the pwsh run and beat a Script Variable: with
    # bad Script Variables set, only the passed-on values keep the run valid.
    [Environment]::SetEnvironmentVariable('ShowAll', 'maybe')
    $r = Run -Arguments @('-MaxRunHours', '6', '-ShowAll')
    Check 'command-line parameters reach the pwsh run' $r.Code 0
    [Environment]::SetEnvironmentVariable('MaxRunHours', $null)
    [Environment]::SetEnvironmentVariable('ShowAll', $null)

    # An empty parameter (a blank RMM preset) must reach pwsh as empty, not vanish.
    $savedEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '$($script:Path)' -NinjaField ''; exit `$LASTEXITCODE" 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $savedEap
    Check 'an empty parameter reaches the pwsh run' $code 0

    # NinjaOne: a fake ninjarmm-cli records what it is given, and whether the 5.1
    # parent called it with the field text the pwsh run handed back.
    $fakeCli = Join-Path $e2e 'ninjarmm-cli.cmd'
    $recordingCli = @(
        '@echo off',
        'echo %* > "%~dp0args.txt"',
        'if defined FIND_STUCK_VEEAM_JOBS_FIELD_FILE (echo yes> "%~dp0handoff.txt") else (echo no> "%~dp0handoff.txt")',
        'findstr "^" > "%~dp0stdin.txt"',
        'exit /b 0'
    )
    Set-Content -LiteralPath $fakeCli -Encoding ASCII -Value $recordingCli
    function Seen($File) { $path = Join-Path $e2e $File; if (Test-Path $path) { [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8) } else { '' } }
    [Environment]::SetEnvironmentVariable('NINJA_AGENT_NODE_ID', '12345')
    [Environment]::SetEnvironmentVariable('NINJARMMCLI', $fakeCli)
    [Environment]::SetEnvironmentVariable('NinjaField', 'vb365StuckStatus')
    $r = Run
    Check 'NinjaOne field is written'            (Seen 'args.txt').Trim() 'set --stdin vb365StuckStatus'
    Check 'the field gets the result text'       ((Seen 'stdin.txt') -match '^VB365 is not installed on ') 'True'
    Check 'the field came back from the pwsh run' (Seen 'handoff.txt').Trim() 'yes'
    Check 'writing the field keeps exit 0'       $r.Code 0
    Check 'no warning when the write works'      (Has $r '^WARNING: NinjaOne') 0

    # The whole check against the fake VB365, with the NinjaOne field.
    [Environment]::SetEnvironmentVariable('ProgramW6432', $fakeRoot)
    Remove-Item -LiteralPath (Join-Path $e2e 'stdin.txt') -Force -ErrorAction SilentlyContinue
    $r = Run
    $cafe = "Caf$([char]0xE9) Exchange Backup"
    Check 'stuck VB365 exits 5 through the restart' $r.Code 5
    Check 'the alert counts the problems'        (Has $r '^VB365 STUCK: 2 problem\(s\) on ') 1
    Check 'the alert names the cut-off job'      (Has $r "^- Job 'Caf.* Exchange Backup' \(backup job\): last run was cut off \(Disconnected\)") 1
    Check 'the alert names the stuck sync'       (Has $r "^- Organisation 'contoso\.onmicrosoft\.com': sync queued since .* and never started \(All, Users\)") 1
    Check 'an on-premises organisation is skipped' (Has $r 'onprem\.example') 0
    Check 'the summary names both'               (Has $r 'Outcome=STUCK; ExitCode=5; StuckCount=2; Stuck=Caf.* Exchange Backup \[cut off\]; contoso\.onmicrosoft\.com sync \[never started, not synced\]') 1
    Check 'the field names the job, accent kept' ((Seen 'stdin.txt').Contains("- Job '$cafe' (backup job)")) 'True'

    # A connection error with a line break: still one summary line.
    [Environment]::SetEnvironmentVariable('NINJA_AGENT_NODE_ID', $null)
    [Environment]::SetEnvironmentVariable('FAKE_VBO_MODE', 'connectfail')
    $r = Run
    Check 'a failed connection exits 1'          $r.Code 1
    $after = @(AfterSummary $r)
    Check 'exactly one line after the summary marker' $after.Count 1
    Check 'and it is the whole summary'          ($after.Count -eq 1 -and $after[0] -match '^Computer=.*; Outcome=CHECK_FAILED; .*Detail=could not connect to VB365: Connection to the server failed\. The service is not running\.; Checked=') 'True'
    [Environment]::SetEnvironmentVariable('FAKE_VBO_MODE', $null)

    # No PowerShell 7: on a server without VB365 there is nothing to check (exit 0);
    # with VB365 the check cannot run (exit 1).
    $noPwsh = New-ScriptCopy 'no-pwsh.ps1' 'return $null'
    [Environment]::SetEnvironmentVariable('ProgramW6432', $realProgramW6432)
    $r = Run -Script $noPwsh
    Check 'no pwsh and no VB365: nothing to check' "$($r.Code) $(Has $r 'Outcome=NOT_APPLICABLE')" '0 1'
    [Environment]::SetEnvironmentVariable('ProgramW6432', $fakeRoot)
    $r = Run -Script $noPwsh
    Check 'no pwsh with VB365: check failed'     "$($r.Code) $(Has $r 'PowerShell 7 \(pwsh\.exe\) is not installed')" '1 2'

    # A pwsh.exe that cannot start: exit 1, and the check never runs under 5.1.
    $badPwsh = Join-Path $e2e 'pwsh.exe'
    Set-Content -LiteralPath $badPwsh -Value 'not a program'
    $r = Run -Script (New-ScriptCopy 'bad-pwsh.ps1' "return '$badPwsh'")
    Check 'a pwsh that cannot start exits 1'     $r.Code 1
    Check 'and says it could not start'          ((Has $r 'Outcome=CHECK_FAILED; .*could not start') -ge 1) 'True'
    Check 'and never checks under 5.1'           (Has $r 'Outcome=(OK|STUCK|NOT_APPLICABLE)') 0

    # A restart that does not reach PowerShell 7 must not restart again (it would
    # loop forever). Here the "PowerShell 7" found is Windows PowerShell 5.1.
    $loopCopy = New-ScriptCopy 'loop.ps1' "return '$((Get-Command powershell.exe).Source)'"
    $loopOut = Join-Path $e2e 'loop-out.txt'
    $p = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$loopCopy`"") -RedirectStandardOutput $loopOut -NoNewWindow -PassThru
    $null = $p.Handle
    $done = $p.WaitForExit(120000)
    if (-not $done) {
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { "$($_.CommandLine)" -like "*$e2e*" } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    }
    Check 'a restart into 5.1 never restarts again' $done 'True'
    Check 'it exits 1 and says why'              "$($p.ExitCode) $(@(Get-Content -LiteralPath $loopOut | Where-Object { $_ -match 'the restart reached PowerShell 5\.1' }).Count -ge 1)" '1 True'
    [Environment]::SetEnvironmentVariable('ProgramW6432', $realProgramW6432)

    # A field write that fails only warns.
    Set-Content -LiteralPath $fakeCli -Encoding ASCII -Value @('@echo off', 'echo Field not found 1>&2', 'exit /b 1')
    [Environment]::SetEnvironmentVariable('NINJA_AGENT_NODE_ID', '12345')
    $r = Run
    Check 'a failed field write only warns'      (Has $r "^WARNING: NinjaOne field 'vb365StuckStatus' was not written") 1
    Check 'and the exit code is unchanged'       $r.Code 0
} finally {
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
    Remove-Item -LiteralPath $e2e -Recurse -Force -ErrorAction SilentlyContinue
}

''
"RESULT: $pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }

# Find-StuckVBMJobs.ps1 - design

Date: 2026-10-13. Status: approved for build.

## Purpose

A separate, read-only script for monitoring and alerting from an RMM (NinjaOne first,
any RMM supported). It finds stuck Veeam Backup for Microsoft 365 (VB365) work and says
which job or organisation is affected, why, and the times that matter.

Scope: VB365 only. VBR may follow later as a separate step.

## Stuck rules

Enabled backup jobs and backup copy jobs. Each rule that matches adds a reason:

| Rule | Stuck when | Default |
|---|---|---|
| Running too long | Latest run `Running` for more than MaxRunHours | 12 h |
| Waiting too long | Latest run `Queued` or `Updating` for more than MaxWaitHours | 24 h |
| Missed its schedule | Not active, and NextRun passed more than OverdueMinutes ago | 60 min |
| Not run for too long | Not active, and LastRun older than NotRunHours, or never run | 36 h |
| Last run cut off | Latest run ended `Disconnected` | - |

Disabled jobs are INFO, never STUCK.

The not-run limit follows the schedule (added after review): NotRunHours is for a daily
job; Daily Workdays adds 48 h, Weekends 120 h, a single weekday 144 h. A job whose
schedule is off (EnableSchedule false) is exempt from "not run" and "never run" only. An
Immediate copy job uses its source job's schedule. A never-run job whose first run is
due gets the same OverdueMinutes grace.

Organisation sync, one finding per organisation (whole organisation and each part:
Users, Groups, GroupMembers, Sites, Mailboxes):

| Rule | Stuck when |
|---|---|
| Never started | `Queued`, ScheduledTime passed more than OverdueMinutes ago, no StartTime |
| Running too long | `Running`, StartTime older than MaxRunHours |
| Not synced | LastSyncTime older than NotRunHours, or none, unless a sync is running within its limit |

A part queued for the same run as a sync that is running within its limit is waiting its
turn, not "never started". Organisations of Type `OnPremises` have no sync and are skipped, and so are organisations whose connection settings show basic or legacy modern authentication (no `ApplicationOnly`). An organisation with no authentication type shown is still checked.

Times from VB365 are compared in local time (VB365 returns local times; UTC values are
converted).

## How it runs

- Read-only. It changes nothing.
- The VB365 module needs PowerShell 7.4.2+. Under Windows PowerShell 5.1 (most RMMs,
  NinjaOne included) the script relaunches itself with `pwsh.exe -File` and passes the
  child's exit code back. No pwsh, or no script file path: exit 1 with the reason. Only a
  pwsh.exe of version 7 or later counts, and the restart happens once only (an env var
  marks it), so it can never loop. A pwsh that cannot start is exit 1, never a check
  under 5.1. An empty parameter is passed on as `""`.
- VB365 not installed: exit 0, "nothing to check", also when PowerShell 7 is missing.
  VB365 is found in Program Files, or next to the `Veeam.Archiver.Service` program. The
  service without the module is a check failure. A machine counts as VB365 only with the `Veeam.Archiver.Service` service or its program in Program Files: the module alone (VB365 console or PowerShell toolkit) is "not installed".
- Exit codes: 0 nothing stuck; 5 something stuck; 1 could not check. Stuck wins over a
  partial check failure; both are listed.

## Output (for alerts)

Default output is a short alert block, stuck items first:

```
VB365 STUCK: 2 problem(s) on SERVER (checked 2026-10-13 12:30)
- Job 'Exchange Backup' (backup job): last run was cut off (Disconnected) at 2026-10-12 23:00. Last backup: 2026-10-11 23:05.
- Organisation 'contoso.onmicrosoft.com': sync queued since 2026-10-01 03:00 and never started (All, Users). Last sync: 2026-10-01 02:05 (Success).
OK: 3 job(s) healthy. INFO: 1 job(s) disabled.
```

Nothing stuck: one line, `VB365 OK on SERVER (checked ...): ...`. `-ShowAll` adds a line
per healthy and disabled item. Then `=== RMM SUMMARY ===` and one line:
`Computer=..; Outcome=OK|STUCK|CHECK_FAILED|NOT_APPLICABLE; ExitCode=..; StuckCount=..;
Stuck=<name> [<tag>, ...]; ..; Checked=..`.

## Settings and NinjaOne

Parameters: `-MaxRunHours 12 -MaxWaitHours 24 -NotRunHours 36 -OverdueMinutes 60
-NinjaField '' -ShowAll`. Plain int/string/switch only (NinjaOne passes strings, no
booleans, positional presets).

A parameter not given on the command line falls back to an environment variable of the
same name (NinjaOne Script Variables arrive as `$env:` strings; empty or `null` means
unset; checkbox `true`/`false`). An invalid value is a check failure (exit 1).

NinjaOne is detected by `$env:NINJA_AGENT_NODE_ID`. When detected and a field name is
set, the alert text is written to that device custom field with
`ninjarmm-cli set --stdin <field>` (from `$env:NINJARMMCLI`, fallback
`C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe`), by the PowerShell process NinjaOne
started (the 5.1 parent, via a temp file from the child). If the full text is refused
(for example a 200-character Text field), a shortened one-line version is tried. A failed
write only warns; it never changes the exit code.

## Testing

Own test file `Test-FindStuckVBMJobs.ps1` (the update script's `Test-Helpers.ps1` is
untouched). It extracts the real functions by AST and runs the rules against fake VB365
objects, including the real case: a job whose last run ended Disconnected, and an
organisation whose sync was queued 13 days ago and never started. End-to-end on a PC
without VB365: the 5.1 parent relaunches under pwsh, passes exit codes 0 and 1 back, and
writes a fake NinjaOne field. A fake VB365 module under %TEMP% (found through
ProgramW6432) needs PowerShell 7, so its exit 5 proves the restart; it also covers the
on-premises skip, UTF-8 field text and a multi-line error. Script copies with only
Find-PowerShell7 swapped cover a missing, broken or too-old pwsh. Runs on both
PowerShell editions.

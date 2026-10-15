# Veeam PostgreSQL and NATS Update

Patches the PostgreSQL engine under **Veeam Backup & Replication (VBR)** and
**Veeam Backup for Microsoft 365 (VB365 / "VBM")** on Windows. Built to run from an RMM.

It updates PostgreSQL. On VB365 it also updates NATS, the message server VB365 8 uses for
its job queue. Both are **updates, never upgrades**: PostgreSQL stays on its major version,
and NATS stays on its 2.x line. See [Updating NATS (VB365)](#updating-nats-vb365).

## Why this exists

Veeam does not patch PostgreSQL or NATS for you on Windows. Upgrading the Veeam product
leaves the database engine alone. Veeam says so in writing:

> "When upgrading Veeam Backup for Microsoft 365, the previously deployed PostgreSQL
> database engine is not automatically upgraded." — [Veeam KB4729](https://www.veeam.com/kb4729)

So a Veeam server can remain on an older PostgreSQL minor release after the Veeam
product itself has been upgraded, missing later PostgreSQL security and bug fixes.

Procedure follows [KB4386](https://www.veeam.com/kb4386) (VBR) and
[KB4729](https://www.veeam.com/kb4729) (VB365).

Should you follow the above procedure this can take alot of time and effort and as an MSP engineer I need to work efficiently and reliably across all our clients hence looked to do vi a script.

## Scope — read this

* **Minor updates only, always to the latest release on the installed major.** The script
  reads the running PostgreSQL branch and selects its latest published minor. For example,
  15.2 becomes the latest 15.x release; it never becomes 16.x or 17.x. There is no target
  override or version allow-list.
* **Major upgrades are hard blocked.** A branch change needs `pg_upgrade` or a Veeam
  configuration restore and is outside this script.
* **No downgrades.** If the running version is equal to or newer than the resolved target,
  the script leaves PostgreSQL alone. On VB365, an `-Install` run still updates NATS when a
  same-line NATS update is due.
* **EOL branches stay on their branch.** The script warns, then targets the final minor
  published for that branch. It returns a distinct EOL exit code until a major-version
  migration is completed.
* **Initial production topology.** Supported targets are either VBR-only (Enterprise Manager
  beside VBR is allowed) or VB365-only, backed directly by one local, standalone PostgreSQL
  instance dedicated to the detected Veeam configuration/cache databases. Combined VBR+VB365
  servers, Veeam ONE co-residence, Enterprise Manager on a VB365 server without VBR or
  with a database the script cannot read, remote/distributed databases and proxies, and
  multiple or HA PostgreSQL instances return exit `11` for manual handling. A server with
  Enterprise Manager and neither VBR nor VB365 is not a target (exit `0`, `NOT_APPLICABLE`). See [Leftover Enterprise
  Manager records](#leftover-enterprise-manager-records).
* **Windows only.** On the Veeam Linux appliance, PostgreSQL comes from Veeam Updater.
  Do not hand-patch those. The script refuses.
* **Out of Veeam Support scope.** Both KBs cite Support Policy section 10. If it breaks,
  the backups this script takes are your only safety net.

## Files

| File | What it is |
|---|---|
| `Update-VeeamPreReqs.ps1` | The update script. **The only file your RMM needs for the update** |
| `Clear-StaleEnterpriseManagerRecord.ps1` | Separate manual tool. Checks, and can clear, a leftover Enterprise Manager connection record inside the VBR database. Not for the RMM. See [the separate tool](#the-separate-tool-clear-staleenterprisemanagerrecordps1) |
| `Test-Helpers.ps1` | The tests for `Update-VeeamPreReqs.ps1`, plus the configuration backup check in `Clear-StaleEnterpriseManagerRecord.ps1`. For whoever edits the scripts, never for a server. See [Why `Test-Helpers.ps1` is there](#why-test-helpersps1-is-there) |

The settings are built into the script, so an RMM that uploads just the one file to a
temp folder works.

Run the tests any time:

```bash
powershell -ExecutionPolicy Bypass -File .\Test-Helpers.ps1
```

The checks read the real functions out of the script — not a copy. Run them under both
`powershell.exe` and `pwsh.exe`; the two editions behave differently and both are
supported. Run from an elevated prompt: a run that is not elevated is never a pass (see
below).

### Why `Test-Helpers.ps1` is there

`Test-Helpers.ps1` is the safety net for changes to `Update-VeeamPreReqs.ps1`. It is for
whoever edits the script. Never copy it to a Veeam server or add it to the RMM.

**What it does**

* It reads the real functions out of `Update-VeeamPreReqs.ps1` with the PowerShell parser
  and runs them, so the function tests always run the shipped code.
* The main part of the script (STEP 1 to STEP 21) is not run, except one elevated check
  that starts the real script against an unsafe folder and expects it to refuse (exit
  `20`). The rest of the main part is checked by reading its text and structure. That
  catches changed wording and order, but not every change in behaviour.
* It fakes the Veeam cmdlets and every call that would change a service or a process
  (`Start-Service`, `Stop-Service`, `Stop-Process`, `sc.exe`). It needs no Veeam, no
  PostgreSQL and no network. A few harmless real calls remain: `Get-Process` and
  `Get-Service` lookups, `cmd.exe`, `reg.exe`, and the one elevated run of the real script.
* It creates only throw-away items named with its process ID: folders under `%TEMP%` and
  `C:\vpgu-wr-test-<PID>`, one `.reg` file under `%TEMP%`, and two registry keys under
  `HKCU:\Software`. It removes them all again.
* It also tests the configuration backup check in `Clear-StaleEnterpriseManagerRecord.ps1`,
  the same way: it reads that function out of the tool and runs it against a fake Veeam.
* It also checks rules that must always hold, by reading the script itself. For example:
  the script never force-stops a service, it uses `Stop-Process` only to close a Veeam
  console, an audit run never closes a console, and the configuration backup is never
  retried more than once.

**Why it matters**

VBR 12 runs on Windows PowerShell 5.1 and VBR 13 on PowerShell 7. Some bugs appear on one
edition only, and a production server is the most expensive place to find one. So the
tests cover both editions, for example:

* Windows PowerShell 5.1 can lose the installer exit code, which would stop a good install
  part-way through, with Veeam down.
* Windows PowerShell 5.1 reads a JSON list as one nested list, which would stop `-Recover`
  reading its own job and service records.
* Folder locking can fail silently on PowerShell 7.

**How to use it**

Run it after every change to the script and before every push, from an elevated prompt in
the project folder, on both editions:

```bash
powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\Test-Helpers.ps1
```

```bash
pwsh.exe -ExecutionPolicy Bypass -NoProfile -File .\Test-Helpers.ps1
```

A pass ends with `RESULT: <n> passed, 0 failed` and exit code `0`. Each `FAIL` line names
the rule that broke.

Always run it elevated. Without elevation, the folder-lock checks are skipped (one
`SKIP  not elevated` line) and many `-Recover` checks fail, because their throw-away work
folders cannot be locked to SYSTEM and Administrators. That run ends with exit code `1` and
is never a pass.

## Quick start

On VBR 13 and VB365 8.6 the Veeam PowerShell modules need PowerShell 7, so run these with
`pwsh` in place of `powershell` (see [How to run it from an RMM](#how-to-run-it-from-an-rmm)).

Audit one server (changes nothing):

```powershell
powershell -ExecutionPolicy Bypass -File .\Update-VeeamPreReqs.ps1
```

Apply the update:

```powershell
powershell -ExecutionPolicy Bypass -File .\Update-VeeamPreReqs.ps1 -Install
```

Recover an interrupted run. Before the installer started, it restores the captured state.
After it, it finishes the run only when PostgreSQL proves healthy at the target version, and
otherwise only reports (exit `40` or `50`). It also recovers an interrupted NATS update. See
[If it goes wrong](#if-it-goes-wrong):

```powershell
powershell -ExecutionPolicy Bypass -File .\Update-VeeamPreReqs.ps1 -Recover
```

The update happens in one RMM run. It waits for active Veeam work to finish naturally,
disables schedules, performs the maintenance, verifies services, and only then re-enables
the schedules it disabled. It never forcibly terminates a backup or restore. It restarts
the server only when you pass `-Reboot` (see [Rebooting](#rebooting)); otherwise the RMM
reboots after exit `6` or `8`.

## Exit codes

The process exit code is the RMM contract. Point RMM automation and alerting at these
exact values:

| Code | Meaning | Action |
|---|---|---|
| `0` | Healthy, with no outstanding RMM action. Also returned when no detected Veeam product uses a local PostgreSQL database, for example VBR on Microsoft SQL Server (`NOT_APPLICABLE`); after a NATS update (`NATS_UPDATED`); after an update where `-Reboot` booked the restart (`UPDATED_REBOOT_SCHEDULED`, see `RebootScheduledAt`); and after a successful `-Recover` (`RECOVERED_*`) or one with nothing to recover (`RECOVERY_NOT_NEEDED`) | None. After a booked restart, rerun audit to confirm |
| `5` | Supported branch: audit found a PostgreSQL minor update or a NATS update. Also returned when `-Reboot` booked a restart and a NATS update is still due | Schedule `-Install` through the rollout ring |
| `6` | Supported branch: update succeeded; reboot required | Schedule and verify a reboot |
| `7` | PostgreSQL branch is EOL | Open or maintain a major-version migration ticket |
| `8` | EOL branch and reboot required | Schedule a reboot and maintain the migration ticket |
| `9` | EOL branch, and a PostgreSQL minor update or a NATS update available | Schedule `-Install` and maintain the migration ticket |
| `10` | Safe transient condition, for example Veeam work did not finish in time, another run is in progress (`CONCURRENT_RUN`), or EnterpriseDB has not yet published the Windows installer for a new minor (`INSTALLER_NOT_PUBLISHED`; an audit can return this too) | Retry later; no backup or restore was forcibly stopped |
| `11` | Unsupported or excluded topology | Handle manually; do not repeatedly retry as a transient failure |
| `20` | Pre-flight failed, or a NATS update failed and the old NATS was put back (`NATS_UPDATE_FAILED`) | Investigate before retrying |
| `30` | EnterpriseDB page, download, size, or signature check failed, or the NATS download or its SHA256 check failed | Investigate the download path; nothing was installed |
| `40` | **Post-change failure, unhealthy service, mandatory tuning failure, or recovery needs an operator** | **Page an operator and read the RMM issue fields** |
| `50` | **PostgreSQL is missing, down, unqueryable, or reports the wrong version after change/tuning/recovery diagnosis** | **Page an operator immediately and use the recovery evidence** |

Failure codes `20`–`50` take precedence over informational EOL/reboot codes. For example,
an EOL server with a post-update service failure returns `40`, not `8`.

When NATS is left alone, the exit code does not show it: it follows PostgreSQL. A run can
return `0` (or `5`, `7`, `9`) while NATS was left alone for a reason worth a look. Alert on
`NatsStatus` too: `HASH_CONFLICT` above all (it always adds to `ActionRequired`, and sets
`IssueCode=NATS_HASH_CONFLICT` when no other issue is set), and also `REMOTE_CLIENTS`, `UNRECOGNISED_LAYOUT`, `HASH_UNAVAILABLE` and
`POLICY_UNKNOWN_VB365`: with any of these, a NATS update that may be due is not applied, run
after run. `NOT_RUNNING` (`nats-server` stopped or disabled on a VB365 server) is worth a
look too.

The console summary and `last-result.json` hold every report field, in this order:
`Computer`, `Timestamp`, `Mode`, `VeeamProducts`, `PgMajor`, `PgInstalled`, `PgTarget`,
`PgEol`, `NatsInstalled`, `NatsTarget`, `NatsStatus`, `NatsDetail`, `StaleEmRecord`,
`Stage`, `Outcome`, `ExitCode`, `RebootRequired`, `RebootScheduledAt`, `IssueCode`,
`ActionRequired`, `JobsLeftDisabled`, `UnhealthyServices`, `ServicesStarted`,
`ConsolesClosed`, `Vb365SyncStuck`, `RecoveryRunDir`, `Detail` and `LogPath`. When the run
has a run folder (`-Install` creates one; `-Recover` uses the interrupted run's), the same
result is also written to `result.json` there. `StaleEmRecord` is `present` when a leftover
Enterprise Manager registry key was found, and `removed; backup <path>` after
`-RemoveStaleEnterpriseManagerRecord` deleted it. `ServicesStarted` lists
stopped automatic Veeam services the run started to rescue a failed configuration backup,
`ConsolesClosed` lists the Veeam consoles it closed, and `Vb365SyncStuck` names any VB365
organisation whose data sync is stuck: VB365 needs attention there.
Those fields are the RMM-readable issue note for any action-bearing result; they name what
is unhealthy, what remains disabled, and where recovery evidence lives.

Every summary line carries a `Stage=` field telling you exactly how far it got:

| Stage | What it means |
|---|---|
| `UNTOUCHED` | No schedule, service, or PostgreSQL state was changed. Guaranteed. An `-Install` run may have closed an open Veeam console (see `ConsolesClosed`), and `-RemoveStaleEnterpriseManagerRecord` may have removed a leftover registry key, in an audit too (see `StaleEmRecord`) |
| `JOBS_DISABLED` | Schedules have been disabled; the installer has not started |
| `SERVICES_STOPPED` | Services are stopped; the PostgreSQL installer has not started. On a NATS update run, this stage also covers switching NATS, starting VB365 on it, and switching NATS back on failure: read `NatsStatus` |
| `INSTALLING` | **Mid-change.** The installer may have started; automatic rollback is prohibited |
| `VERIFIED` | PostgreSQL is at the target version. On a NATS update run: NATS is at its target version, and PostgreSQL was not touched |
| `COMPLETE` | Maintenance/state restoration completed. Inspect the exit code: exit `40` can still mean the completed recovery marker could not be removed |

Codes `10`, `11`, `20`, and `30` normally mean nothing was changed or a safe pre-installer
rollback succeeded. Always use `Stage`, `JobsLeftDisabled`, and `ActionRequired` as the
final state record. Codes `40` and `50` can deliberately leave schedules disabled.

## Parameters

| Parameter | Default | What it does |
|---|---|---|
| `-Install` | off | Actually do the update. Without it, audit only |
| `-Reboot` | off | With `-Install`: after a fully successful update, book a Windows restart `-RebootDelaySeconds` later. See [Rebooting](#rebooting) |
| `-RebootDelaySeconds` | `120` | Seconds from booking the restart to Windows restarting, 30 to 3600. Only used with `-Reboot` |
| `-Recover` | off | Restore captured state from an interrupted run; if the installer finished and PostgreSQL proves healthy at the target version, finish the run |
| `-WorkRoot` | `C:\ProgramData\VeeamPgUpdate` | Protected logs and recovery evidence, including dumps and the cold copy |
| `-SkipDownloadInAudit` | off | Skip the EnterpriseDB installer-availability check; the audit still contacts PostgreSQL's version feed and, on VB365, Veeam's help center (and GitHub when a NATS update is due) |
| `-RemoveStaleEnterpriseManagerRecord` | off | Delete a proven-stale `Veeam Backup Reporting` registry key, after exporting and verifying a `.reg` backup into the `logs` folder. Works in an audit run too, without `-Install`. `StaleEmRecord` reports the result; a failed removal is exit `20` (`STALE_EM_RECORD_REMOVE_FAILED`) |

**There is no maintenance window.** `-Install` means "go now". It runs when you run the
RMM script or policy. The independent RMM owns the maintenance window, retries, the reboot unless
`-Reboot` is used, and post-reboot verification. `-Recover` is a separate operation and cannot be combined
with `-Install` or `-Reboot`.

## How to run it from an RMM

**Use an independent RMM agent or Windows scheduled task** that runs locally and
elevated. Do not launch the install through the **Veeam Management Agent**: its Windows
service name matches `Veeam*`, so the script deliberately disables and stops it during
the maintenance. An unrelated RMM service whose service name does not match `Veeam*`
is not touched.

**Do not run it over WinRM / `Invoke-Command`.** The PostgreSQL installer is documented
to fail under PSRemoting. The script blocks this when `-Install` is used.

Suggested rollout:

1. Run audit mode across the fleet and inventory exit codes `5`, `7`, `9`, and `11`.
2. Pilot each new PostgreSQL minor on one non-production VBR and one non-production
   VB365 server.
3. Promote through a small production ring and a soak period before the wider fleet.
4. Let the RMM retry exit `10`, schedule reboots for `6`/`8` (or use `-Reboot`), create major-migration
   tickets for `7`/`8`/`9`, and page immediately for `40`/`50`.

The script intentionally has no in-script version allow-list. Rollout rings in the RMM
are the approval and canary mechanism for a newly published PostgreSQL minor.

PowerShell version matters:

* Current VBR 13.1 documentation requires **PowerShell 7.6.3**
* Current VB365 8.6 documentation requires **PowerShell 7.4.2+**

If the module will not load, the script **aborts** rather than assuming no jobs are
running. On those servers, invoke `pwsh.exe` instead of `powershell.exe`.

## Settings and version policy

The configurable settings live **only inside the script**, near the top, under the banner
`BUILT-IN SETTINGS`; the values themselves are the JSON block in `Get-DefaultConfig`, a
few lines below it. Edit there, review the change, then re-upload the script
to your RMM. There is no `-ConfigPath` parameter and no external settings file is read.

| Setting | Default | What it does |
|---|---|---|
| `jobWaitTimeoutMinutes` | `720` | Maximum time each wait gives active Veeam work to finish naturally; one run can wait more than once. 1 to 10080; anything else stops `-Install` with exit `20` (`BAD_JOB_WAIT_TIMEOUT`) before anything changes |
| `installerTimeoutMinutes` | `120` | Maximum unattended wait for the EnterpriseDB installer; it is not forcibly killed on timeout. 1 to 10080; anything else stops a PostgreSQL update with exit `20` (`BAD_INSTALLER_TIMEOUT`) before anything changes |
| `retentionDays` | `30` | Minimum age before completed logs and recovery sets become eligible for deletion. A value below 1 is treated as `30` |
| `updateNats` | `true` | VB365 only. `true`: `-Install` updates NATS when a same-line update is due, on a run where PostgreSQL needs nothing; when both are due, that run updates PostgreSQL and the next `-Install` run updates NATS. `false`: a due NATS update is only reported (`NatsStatus=UPDATES_OFF`) |

The PostgreSQL target is **not** a maintained setting. On every default run, the script:

1. reads the running server's version with `SHOW server_version_num`;
2. finds that exact branch in
   [`postgresql.org/versions.json`](https://www.postgresql.org/versions.json);
3. selects its latest published minor; and
4. verifies that the target is still on the installed branch before doing anything.

Thus 15.2 targets the latest 15.x and 17.3 targets the latest 17.x. A future installed
branch works the same way without adding it to the script. If PostgreSQL's version feed
is unavailable, missing the branch, duplicated, or malformed, the script fails closed.
If the branch is end-of-life, it targets the final published minor but continues to
return an EOL code until the server is migrated to a supported major. If the installed
version is already equal to or newer than the target, it never downgrades PostgreSQL.

The former `approvedTargets`, `supportedBranches`, and `branchFloors` settings have been
removed. New PostgreSQL minors are therefore selected automatically; they are no longer
held for a manual allow-list edit. Review PostgreSQL release notes and pilot normal RMM
rollout, because an unusual minor release can still require a follow-up action such as
`REINDEX`.

The removed settings also include `abortIfVeeamOnePresent`,
`abortIfRemoteVb365Proxies`, and `reapplyTuning`. Those behaviors are no longer operator
switches: the initial topology exclusions fail closed, and Veeam PostgreSQL tuning is
mandatory after every successful minor update.

**`jobWaitTimeoutMinutes`** — the script polls until all detected backup, copy, restore,
CDP, tape, agent, plug-in, configuration, protection-group, VB365 repository, and VB365
organization-cache synchronization work is idle. It never calls a stop-job cmdlet. When
the timeout expires before the outage, exit `10` tells the RMM to retry. After the update,
work still running when schedules are due to be re-enabled is exit `40`
(`FINAL_JOB_DRAIN_TIMEOUT`) instead, and the schedules stay disabled.

**`installerTimeoutMinutes`** — bounds how long the RMM run waits for the unattended
installer. A timed-out installer is not killed because it may be changing binaries. The
marker remains, schedules remain disabled, and exit `40` pages an operator.

**Mandatory Veeam tuning** — while the Veeam control service is still available but
schedules are disabled, the script runs the product-appropriate command
(`Set-VBRPSQLDatabaseServerLimits` or `Set-VBOPSQLDatabaseServerLimits`) for the server's
CPU and RAM and saves its generated SQL. Failure at this pre-installer point is exit `20`
with safe rollback. After the minor update it applies that exact SQL, restarts PostgreSQL,
and verifies the target version is queryable. SQL application/tuning failure is exit `40`;
PostgreSQL down or unqueryable is exit `50`. There is no setting to skip tuning.

**`retentionDays` is not only for script logs.** It covers transcript logs and completed
recovery sets. A PostgreSQL recovery set contains database dumps, roles, configuration copies,
the cold data-directory copy, service/job state, tuning and installer logs. A NATS run's
set holds service/job state, the NATS service's registry key, its config file (which
holds the NATS credentials), and a copy of the message store. Unresolved runs
and the two newest completed recovery sets are retained regardless of age; older completed
sets become eligible for deletion after `retentionDays`. Copy recovery evidence off-host
if your operational policy requires protection from loss of the Veeam server itself.

### Job and restore handling

Audit and install modes both inventory every job family the script knows how to round-trip
and check the corresponding job/restore/session APIs before an audit can report the server
current. If a required API is missing, a query fails, an enabled-state property is unknown,
or a job cannot be identified and later re-enabled by stable ID, the run fails closed.
The one exception is a feature the Veeam licence edition does not include (for example
application backup jobs below Enterprise Plus): Veeam refuses the query, so that family
cannot have jobs, and the run logs a warning and treats it as empty.
Protection-group rescans and their agent deployment work are checked through current and
legacy VBR discovery-session types. VB365 whole-organization synchronization and each of
its Users, Groups, GroupMembers, Sites, and Mailboxes parts are also fail-closed activity
barriers because they write the PostgreSQL-backed organization cache. A sync that is only
`Queued` for a later time is VB365's normal state between its daily syncs and does not
hold the run; one that is running, overdue by up to an hour, due within 15 minutes, or
has no readable time does. One overdue by more than an hour that never started is stuck,
not running: the run warns, names it in `Vb365SyncStuck`, and does not wait for it. A VB365 job session that ended as `Disconnected` does not count as running,
because VB365 never resumes it.

If work is active, the script waits for it to finish naturally for up to
`jobWaitTimeoutMinutes`. It does **not** forcibly stop or terminate backups, restores,
copies, CDP sessions, tape work, agent jobs, plug-in jobs, or VB365 operations. Once idle,
it disables every enabled managed schedule, durably records each change, verifies the
disabled state, then checks activity again before stopping services. A race that starts
new work causes a safe rollback/retry rather than termination.

The RMM maintenance policy must also prevent remote administrators from manually starting
new VBR work during `-Install`. VBR has no public atomic global new-work barrier; the script
disables every known schedule, repeatedly refreshes schedule/activity state, closes any
open local VBR or VB365 console, and blocks on Veeam Explorer processes, but only an
external change freeze closes the remote manual-start race completely.

An open console is not waited for. The VBR console (`Veeam.Backup.Shell`) and the VB365
console (`Veeam.Archiver.Shell`) are clients only, so `-Install` and `-Recover` close
them once a console is the only thing left blocking (while a job still runs, the console
is left alone). It asks first, then forces. Run from an RMM as SYSTEM, the forced close is
the normal path. Anything unsaved in that console is lost. Veeam's own procedure (KB2991)
also closes the console before stopping services. A Veeam Explorer is never closed,
because it runs its own item-level restore. An open Explorer counts as active work: the
run waits up to `jobWaitTimeoutMinutes` for it to close, then exits `10` as
`JOB_WAIT_TIMEOUT` (or `JOB_DRAIN_TIMEOUT`, `FINAL_JOB_DRAIN_TIMEOUT` or
`LAST_CHANCE_JOB_DRAIN_TIMEOUT` if it opens at a later check, or at once as
`LAST_CHANCE_ACTIVITY_RACE` if it opens just before services stop), with the Explorer
listed in `Detail` as `UI:<process>:PID<id>`. After the update, an Explorer still open
when schedules are due to be re-enabled is exit `40` (`FINAL_JOB_DRAIN_TIMEOUT`), and the
schedules stay disabled; during `-Recover` it is exit `40` (`RECOVERY_INCOMPLETE`). `VEEAM_UI_OPEN`
covers only an Explorer, or a console that could not be closed, found by the last process
check right before service shutdown. An audit run closes nothing.

For VB365, the script additionally places every repository into repository maintenance
mode without `-ForceStopSessions`. That API was added in VB365 8.6; an older VB365 build
cannot provide the required new-work barrier and therefore fails closed before changes.
The maintenance session is released only after services are healthy and the PowerShell
connection has been re-established.

After PostgreSQL, mandatory tuning, and all required service health checks succeed, the
script re-enables and verifies exactly the schedules it disabled. Schedules that were
already disabled remain disabled. If PostgreSQL, tuning, or a critical service is
unhealthy, schedules remain disabled and exit `40`/`50` includes their names and the
required RMM action.

### Veeam service handling

Immediately before shutdown, the script enumerates every Windows service whose **service
Name** matches `Veeam*`. It records each service's running state and exact startup type
(`Automatic`, `AutomaticDelayedStart`, `Manual`, or `Disabled`) in
`veeam-service-state.json` before changing anything. It then sets every captured service
to `Disabled` and stops it, including the Veeam Management Agent. VB365 services retain
their required stop order, and management-agent services are stopped last.

After PostgreSQL is healthy, or during a pre-installer rollback, the script restores each
captured service's exact startup type and starts every service that was running at the
start. It never stops a formerly stopped service that has since become running, because
that service may now own newly-arrived manual work; this conservative state drift is
logged while its startup type is still restored. The match is deliberately limited to
the Windows service Name pattern `Veeam*`; it does not disable unrelated RMM
or management services. Before shutdown it also checks service dependencies and aborts
if the shutdown would cascade into a running service outside the planned
`Veeam*`/NATS/PostgreSQL set. This is why the install must be launched by an independent RMM agent
or scheduler, not by the Veeam Management Agent that it will stop.

After Veeam is stopped, the script queries `pg_stat_activity` and refuses to stop
PostgreSQL while any other client session remains. It reports exit `10` and the client
details for the RMM; it never terminates those sessions.

## What the script does, step by step

Every run writes each step to its log under the name in the first column, so you can match
a log to this list.

* An **audit** (no switch) runs the start-up steps and STEPs 1 to 10, then stops. It
  changes nothing.
* **`-Install`** carries on with STEPs 11 to 21 when PostgreSQL needs an update. When
  PostgreSQL needs nothing and a NATS update is due on VB365, it takes the NATS path
  (`NATS 1/7` to `7/7`) after STEP 8 instead.
* **`-Recover`** stops at STEP 2 and recovers the interrupted run.

A step that finds a problem stops the run there with the exit code and `Outcome` shown in
the RMM summary. See [Exit codes](#exit-codes) and [If it goes wrong](#if-it-goes-wrong).

### Start-up (every run)

| Step | What it does | Why |
|---|---|---|
| Path check | Checks that `-WorkRoot` is an absolute path on a local drive and not a drive root. | The WorkRoot will hold the installer, dumps and recovery state. A bad path stops the run before anything is written (`WORKROOT_UNSAFE`, exit `20`). |
| Former WorkRoot | Looks for a changes-in-progress marker in `C:\temp\VeeamPgUpdate`, the folder earlier versions used. | An interrupted run there must be recovered first, not hidden (`LEGACY_WORKROOT_RECOVERY_REQUIRED`, exit `40`). |
| WorkRoot check | Creates the WorkRoot, or proves the existing one is the script's own: owner, ACL locked to SYSTEM and Administrators, the `.veeam-pg-updater` sentinel, and no junctions. Then starts the log (transcript). | A folder someone else can change could be used to swap files the script later runs or restores. Nothing is written to a folder that fails. |
| Single-instance lock | Takes the machine-wide lock `Global\VeeamPgUpdate`. | Two runs at once would fight over the same services and jobs. The second one stops (`CONCURRENT_RUN`, exit `10`). |

### Checks (audit and `-Install`)

| Step | What it does | Why |
|---|---|---|
| STEP 1 - Load settings | Loads the settings built into the script, then purges logs and completed run folders older than `retentionDays`. It keeps unresolved runs and the two newest completed recovery sets. | Settings come only from the reviewed script. Without the purge, daily audits would fill the disk. |
| STEP 2 - Context checks | Checks the switch combination, that the server runs Windows and is not a Veeam appliance, that the run is elevated, and that `-Install` is not over PowerShell remoting. A changes-in-progress marker sends `-Recover` to recovery and stops every other run (`PRIOR_RUN_INCOMPLETE`, exit `40`). `-Recover` with no marker ends here (`RECOVERY_NOT_NEEDED`, exit `0`). | Each of these breaks an unattended update. An interrupted run must be dealt with before a new one starts. |
| STEP 3 - Detect Veeam products | Finds VBR, VB365, Veeam ONE and Enterprise Manager, and a leftover Enterprise Manager registry key (removing it with `-RemoveStaleEnterpriseManagerRecord`). Warns about Veeam services set to start automatically that are stopped. Refuses topologies outside the supported profile. | Decides which product profile applies, and stops early on a server the script does not support. |
| STEP 4 - Confirm database engine | Reads where each product keeps its database: VBR's active engine and connection from the registry, Enterprise Manager's database the same way, and VB365's `Config.xml` and `Proxy.xml`. All must be local PostgreSQL on one port. | Nothing is guessed. A remote database or two ports means the script cannot tell what it is updating. |
| STEP 5 - Detect PostgreSQL installation | Requires exactly one PostgreSQL installation in the registry and one PostgreSQL Windows service, which must run `pg_ctl.exe` or `postgres.exe` from that installation. Checks that `psql`, `pg_dump`, `pg_dumpall` and `pg_restore` are there. | The installer must patch the instance Veeam really uses, and the backup tools must exist. |
| STEP 6 - Read running server version | Requires PostgreSQL to be running and logs in as `postgres` (Windows SSPI), naming the cause if the login is refused. Reads the running version. Proves the data directory on Veeam's port is the registry's, keeps `WorkRoot` outside it, checks for a pooler or port mismatch, lists the databases, and refuses replication, standby or Windows Failover Clustering. | Proves the instance is the right one, standalone, and reachable, before anything else. |
| STEP 6B - Validate Veeam scheduling, activity and topology APIs | Loads the Veeam PowerShell module. Lists every job and policy family it can safely turn off and back on. On VB365, checks the 8.6 maintenance-mode commands and that every proxy is local. Reads current Veeam activity. Checks the registry and the running server agree on the major version. | An audit must prove the same things an install relies on, so a server reported as fine really is safe to update. |
| STEP 6C - Check NATS (VB365 only) | Read-only. Reads the `nats-server` service, its version, config file and message store, VB365's connection to it, Veeam's supported NATS list, and the package SHA256. Fills `NatsInstalled`, `NatsTarget`, `NatsStatus` and `NatsDetail`. | Decides whether a same-line NATS update is due, and whether it can be done safely. Any doubt leaves NATS alone. |
| STEP 7 - Resolve target version | Reads `postgresql.org/versions.json` and picks the latest minor on the running branch. Flags an end-of-life branch. Blocks any major-version change. | Always the newest fixes, never an upgrade. A feed that cannot be read stops the run instead of guessing. |
| STEP 8 - Idempotency gate | When PostgreSQL is already current or newer, the run ends here: `ALREADY_CURRENT` or `LOCAL_VERSION_AHEAD`. If a NATS update is due instead, an audit reports it (exit `5` or `9`), and `-Install` takes the NATS path. | Never downgrades, never repeats work, and makes one change per run. |
| STEP 9 - Environment pre-flight | Checks that Windows Script Host is enabled, that pgAdmin is not running, and that the WorkRoot drive has 400 MB plus twice the data directory plus 1 GB free. | Each of these is a known cause of a failed unattended install (Veeam KB4698 for Windows Script Host). |
| STEP 10 - Resolve installer URL | Finds the exact Windows x64 installer on EnterpriseDB's file host, then on its download page. An audit skips this with `-SkipDownloadInAudit`. | An installer not published yet is reported (exit `10`, or `7` on an EOL branch) rather than run later from a guessed link. |
| Audit stops here | Reports the update that is due (exit `5`, or `9` on an EOL branch). | Audit never changes anything. |

### PostgreSQL update (`-Install` only)

| Step | What it does | Why |
|---|---|---|
| STEP 11 - Inventory schedules and wait for jobs/restores to finish naturally | Repeats the STEP 6B checks, checks the timeout settings, then waits for running jobs and restores to finish. Closes an open Veeam console once it is the only thing left. | No backup or restore is ever killed. A timeout returns exit `10` for a later retry. |
| STEP 12 - Download and verify the installer | Downloads the installer, checks its length, and requires a valid Authenticode signature from EnterpriseDB. | Only a genuine installer is run. Any failure is exit `30` with nothing changed. |
| STEP 13 - Disable scheduled jobs | Records every enabled job, then disables each one and checks it. Waits again for work that started in the meantime. On VB365, puts every repository into maintenance mode and waits until it is Running. Generates the mandatory Veeam tuning SQL. | Nothing new starts during the outage, and recovery knows exactly which jobs to turn back on. The tuning SQL needs the Veeam services, which stop next. |
| STEP 14 - Backups | Runs the VBR configuration backup and judges it (retrying once after starting stopped automatic Veeam services). On VB365, copies `Config.xml` and `Proxy.xml`. Dumps every Veeam database and the roles, checks each dump, and copies the four `.conf` files. | A restore path that does not depend on the update working. |
| STEP 15 - Disable and stop all Veeam services | Records every Veeam service's startup type and state, then disables and stops them (VB365 Proxy and Service first, the Management Agent last), then NATS. Checks nothing else is connected to PostgreSQL, dumps any cache database VB365 created meanwhile, and stops PostgreSQL. | The update and the cold copy need PostgreSQL offline with no one using it. |
| STEP 16 - Cold copy of the PostgreSQL data directory | Saves the data directory's permissions, copies the whole stopped data directory, and checks the copy file count and size. | A complete file-level copy to restore from if the installer breaks PostgreSQL. |
| STEP 17 - Run the PostgreSQL installer | Records that the installer is starting, then runs it unattended with a bounded wait. A timed-out installer is never killed. Collects the installer's logs. | The update itself. From here, automatic rollback is not allowed: only an operator decides. |
| STEP 18 - Verify the update | Starts PostgreSQL if needed and requires it to report the target version. Compares the `.conf` files with the copies from STEP 14. | The installer's exit code alone is never trusted. |
| STEP 19 - Apply mandatory Veeam PostgreSQL tuning | Applies the tuning SQL from STEP 13, restarts PostgreSQL, and checks it is back at the target version. | Veeam requires its tuning. If it fails, Veeam stays down and jobs stay off for an operator. |
| STEP 20 - Restore Veeam service state | Puts back every startup type and starts NATS and every service that was running, in dependency order. Waits 90 seconds, then checks every service, PostgreSQL, the broker port 9501 (VBR only), and the Veeam PowerShell connection. | Veeam must be healthy before any job runs again. |
| STEP 21 - Re-enable jobs and finish | Ends VB365 maintenance mode, waits for any new work, turns every recorded job back on, removes the changes-in-progress marker, and deletes the installer. Returns exit `6` (or `8`), or with `-Reboot` books the restart. | Leaves the server as it was, on the new version, with a clear result for the RMM. |

### NATS update (`-Install` on VB365, when PostgreSQL needs nothing)

| Step | What it does | Why |
|---|---|---|
| NATS 1/7 - Download and check NATS | Downloads the release, checks its SHA256, extracts only `nats-server.exe`, runs its version and config checks, and checks free disk space. | Everything that can fail without an outage is tested first. |
| NATS 2/7 - Wait for Veeam work, disable jobs, start VB365 maintenance mode | As STEPs 11 and 13. | No work runs while NATS is changed. |
| NATS 3/7 - Stop Veeam services and NATS | As STEP 15, but PostgreSQL keeps running. | VB365 must not use NATS while it is switched. |
| NATS 4/7 - Back up the NATS service, config file and message store | Saves the service's registry key, the config file, the store folder's permissions and a checked copy of the store. | Everything needed to put the old NATS back. |
| NATS 5/7 - Point nats-server at NATS | Copies the new program into a new version folder beside the old one, and switches the service to it through the Windows service manager. | The change itself, following Veeam KB4742. The old folder stays. |
| NATS 6/7 - Start NATS, then VB365, and verify | Starts NATS alone and checks its version, then starts VB365 and checks every service, PostgreSQL, and that VB365 connects again. | Proves VB365 works on the new version. A failure puts the old version back. |
| NATS 7/7 - Re-enable jobs and finish | Ends maintenance mode, waits for any new work, and turns the jobs back on. Returns exit `0` (or `7`). | No restart is needed after a NATS update. |

[Updating NATS (VB365)](#updating-nats-vb365) has the full detail and the rollback rules.

### `-Recover`

| Step | What it does | Why |
|---|---|---|
| Recovery (from STEP 2) | Checks that the marker and its recovery state are the script's own and belong together. Then, depending on how far the run got: puts back captured job and service state (installer not started), finishes the run (installer finished and PostgreSQL proven healthy at the target version), puts the old NATS back or finishes a NATS update, or only reports (anything less certain). | Finishes or undoes an interrupted run from its own records, never by guessing. |

### When a run ends

| Step | What it does | Why |
|---|---|---|
| ROLLBACK | Only after a failure before the installer started (or, on a NATS run, before VB365 was verified on the new version): puts the old NATS back on a NATS run, starts PostgreSQL, NATS and the Veeam services as they were, ends VB365 maintenance mode, turns the jobs back on, and removes the marker. | A failed run leaves the server as it found it. If that does not fully work, the run returns exit `40`. |
| RMM SUMMARY | Prints the one-line summary and writes `last-result.json` (and `result.json` in the run folder), then releases the lock and exits with the exit code. | The RMM reads the result. See [Exit codes](#exit-codes). |

## Updating NATS (VB365)

VB365 8 keeps its job queue in a NATS server: the `nats-server` Windows service. A VB365
upgrade never updates NATS. Veeam leaves that to you and documents the steps in
[KB4742](https://www.veeam.com/kb4742). The script follows those steps, with backups, checks
and an automatic rollback added. VBR does not use NATS, so on VBR `NatsStatus=NOT_APPLICABLE`.

**An update, never an upgrade.** Veeam supports an exact list of NATS versions per VB365
release, not a range
([system requirements](https://helpcenter.veeam.com/docs/vbo365/guide/vbo_system_requirements.html)).
The script moves NATS only to the newest version on that list that is on the **same 2.x line**
as the installed one. A move to another line changes the message-store format and has no
documented way back, so the script never does it.

**The list is read from Veeam's website on every run**, so a version Veeam adds is picked up
without a script change. The script uses the page only when it describes the server's own
VB365 release: the page says "Page content applies to build 8.6.0.1102", and that must be
8.6 on an 8.6 server. Veeam's page always shows the newest VB365 release, so after Veeam
ships 8.7, an 8.6 server falls back to the 8.6 list built into the script. The same happens
when the page cannot be read, or when its NATS sentence no longer reads as one plain list
("NATS server" followed by versions separated by commas, "and" or "or", ending in a full
stop). Then nothing from the page is used. `NatsDetail` names the list used.

Only 8.6 has a list built in. A server on another release gets NATS updates only while
Veeam's page describes that release and can be read. Otherwise it reports
`POLICY_UNKNOWN_VB365` until its list is added to `SupportedByVb365` in `Get-NatsPolicy`.

For VB365 8.6 the list is 2.10.18, 2.10.22, 2.10.28, 2.12.5 and 2.12.8 (October 2026):

| Installed | Result |
|---|---|
| 2.10.x below 2.10.28 (for example 2.10.18, 2.10.22 or 2.10.25) | Update to 2.10.28 |
| 2.12.x below 2.12.8 (for example 2.12.5, 2.12.6 or 2.12.7) | Update to 2.12.8 |
| 2.10.28 or 2.12.8 | `CURRENT`, nothing to do |
| 2.10.29, 2.12.9 or later on a line | `AHEAD`, left alone. Never downgraded |
| 2.11.x, 2.14.x, any other line | `UNLISTED`, left alone |

**One change per run.** When PostgreSQL also needs an update, `-Install` updates PostgreSQL
and reports `NatsStatus=UPDATE_PENDING`. The next `-Install` run updates NATS. Each change
then has its own outage and its own rollback, and you always know which one caused a problem.

**The download is checked against a SHA256.** NATS publishes no signature. Each
[NATS release](https://github.com/nats-io/nats-server/releases) has a `SHA256SUMS` file, and
the download must match the line for its `windows-amd64.zip`. A download that does not match
is deleted, and the run returns exit `30` with nothing changed.

That file comes from the same GitHub release as the download. It proves the file arrived
whole, but not that the release itself is genuine: GitHub lets a release be changed after it
is published. For the versions known when the script was written (2.10.28 and 2.12.8), the
script also has the SHA256 built in, in `Get-NatsPolicy`. If the release's `SHA256SUMS` ever
disagrees with it, the script installs nothing (`HASH_CONFLICT`). A version Veeam adds later
is checked against `SHA256SUMS` only. That is the trade-off for not editing the script.

### What a NATS update does

The audit reads all of this and changes nothing. An update is only planned when every
check passes; anything the script cannot prove leaves NATS alone, with the reason in
`NatsDetail`, and never blocks a PostgreSQL update.

* The `nats-server` service runs `nats-server.exe` from a folder directly under
  `C:\Program Files\NATS`, with exactly `-c <config file>`.
* `nats-server --version`, the folder name (when it carries a version), and the version
  NATS reports to a client on its port all agree.
* The config file names exactly one `store_dir`, uses no `include`, `cluster`, `gateway` or
  `leafnodes`, and the store is a local folder outside `WorkRoot`.
* `Config.xml` and `Proxy.xml` send VB365 to NATS on this server, on the port in the config
  file. No other machine is connected to NATS.

`-Install` then:

1. Downloads `nats-server-v<version>-windows-amd64.zip` from GitHub, checks its SHA256,
   extracts only `nats-server.exe`, and runs it with `--version` and `-t` (config check
   only). It also checks that the WorkRoot drive has room for a copy of the message store
   plus 200 MB (`LOW_DISK`, exit `20`). Nothing has changed yet.
2. Waits for VB365 work to finish, disables the jobs, and starts VB365 maintenance mode, as
   for a PostgreSQL update.
3. Stops every `Veeam*` service (Proxy first), then NATS. PostgreSQL keeps running.
4. Backs up the service's registry key, the config file, the store folder's permissions, and the
   whole message store, and checks that the copy holds the same number of files and bytes.
5. Copies the new `nats-server.exe` into a new version folder beside the old one, and points
   the service at it through the Windows service manager, as KB4742 does with `sc.exe`.
   The old folder stays.
6. Starts NATS on its own and checks the version clients get. Then starts VB365, waits 90
   seconds, and checks every service, PostgreSQL, the VB365 PowerShell connection, and,
   when VB365 was connected to NATS before, that it connects again.
7. Ends maintenance mode, waits for any new Veeam work to finish, and turns the jobs back on.
   Returns exit `0` (or `7` on an EOL PostgreSQL branch) with `Outcome=NATS_UPDATED`. A NATS
   update needs no restart, so `-Reboot` books none. If this step fails, NATS stays on the
   new version (`NatsStatus=UPDATED`), schedules stay disabled, and the run returns exit `40`.
   `-Recover` then finishes the run.

**If step 5 or 6 fails**, before VB365 is verified healthy on the new version, the old NATS
goes back automatically and the run returns exit `20` (`NATS_UPDATE_FAILED`,
`NatsStatus=UPDATE_FAILED_REVERTED`):

* Before VB365 used the new version, the service points back at the old program. If the new
  version started, the message store copy is put back too.
* After VB365 used it, VB365 is stopped and the service points back at the old program, but
  the store is **kept**. Old messages put back could make VB365 do work twice. The old
  version on the same line reads the store as it is.

If the rollback itself fails, the script starts nothing on a half-switched NATS: the jobs
stay disabled, Veeam services are not started again, and the run returns exit `40`.
`ActionRequired` names the old program, the registry backup and the store copy. Fix the
problem, then run `-Recover`: it tries the rollback again.

`-Recover` on an interrupted NATS run puts the old NATS back, unless VB365 was already
started on the new version and NATS answers at that version. Then it keeps the new version
and finishes the run (`RECOVERED_NATS_UPDATED`). It also finishes a run that stopped in step
7, after VB365 was verified on the new version. When the old NATS is back, the result is
`RECOVERED_NATS_REVERTED` (`NatsStatus=UPDATE_FAILED_REVERTED`). When the run stopped before
NATS was changed, it restores services and jobs only (`RECOVERED_PREINSTALL`,
`NatsStatus=NOT_UPDATED`). All three return exit `0`. If someone started Veeam services by
hand before VB365 ever used the new version, it changes nothing and asks an operator to stop
them first. NATS runs write recovery state version 2, so an older copy of this script
refuses to recover one instead of guessing.

| `NatsStatus` | What it means |
|---|---|
| `NOT_APPLICABLE` | Not a VB365 server |
| `NOT_LOCAL` | No `nats-server` service on this server |
| `NOT_RUNNING` | `nats-server` is stopped or disabled; it is only updated while it runs normally |
| `CURRENT` | The newest version Veeam lists on its line |
| `UPDATE_AVAILABLE` | An update is due. Audit returns exit `5` (or `9`) |
| `UPDATE_PENDING` | Due, but this run updated PostgreSQL. The next `-Install` run updates NATS |
| `UPDATES_OFF` | Due, but `updateNats` is `false` |
| `UPDATED` | This run updated NATS |
| `UPDATE_FAILED_REVERTED` | The update failed and the old version is back |
| `NOT_UPDATED` | The run stopped before NATS was changed |
| `UPDATE_FAILED` | The run stopped while NATS was half-switched. Read `ActionRequired` |
| `AHEAD` / `UNLISTED` | Not on Veeam's list, or nothing on its line to update to. Left alone |
| `HASH_UNAVAILABLE` | Due, but the release's `SHA256SUMS` could not be read (for example a proxy blocks `github.com` or `release-assets.githubusercontent.com`), and no SHA256 is built in. Each run checks again |
| `HASH_CONFLICT` | Due, but the release's `SHA256SUMS` disagrees with the SHA256 built into the script. The release may have been changed. Investigate before anything else. The exit code does not change. `ActionRequired` always says so. `IssueCode` says `NATS_HASH_CONFLICT` only when the run has no other `IssueCode`: any non-zero exit (for example `5` when PostgreSQL also has an update) already sets one |
| `POLICY_UNKNOWN_VB365` | No NATS list for this VB365 release: the server's release could not be identified, or Veeam's page could not be read or describes another release, and the script has none built in. `NatsDetail` says which |
| `REMOTE_CLIENTS` | Another machine is connected to NATS |
| `UNRECOGNISED_LAYOUT` | NATS is not set up the way the script expects. `NatsDetail` says what |
| (empty) | The run ended before the NATS check. A `-Recover` run fills it only when it recovers a NATS update |

**Before the first NATS update**, run the audit on the VB365 servers and read `NatsStatus`
and `NatsDetail`. The script was built from Veeam's documentation, not from a live VB365
NATS install: an `UNRECOGNISED_LAYOUT` result names the part that differs.

## Rebooting

Veeam's KBs recommend restarting after the update. A successful supported-branch update
returns exit `6`; an EOL update returns exit `8`. Without `-Reboot`, both report
`Outcome=UPDATED_REBOOT_REQUIRED` and `RebootRequired=True`.

Without `-Reboot` the script never restarts the server. The RMM must reboot, verify
`LastBootUpTime`, and rerun audit. Do not rerun the installer merely because exit `6` or `8`
was returned. After a verified reboot, audit returns `0` on a supported branch or the
persistent EOL result `7`. On VB365, if the update run reported `NatsStatus=UPDATE_PENDING`,
the audit returns `5` (or `9`) instead, because the NATS update is still due: schedule one
more `-Install` run.

**With `-Install -Reboot`**, after a fully successful update the script books a Windows
restart `-RebootDelaySeconds` later (default `120`), as its very last action. The delay
lets the run finish and the RMM collect its output before Windows restarts. The run then
returns `Outcome=UPDATED_REBOOT_SCHEDULED`, exit `0` (or `7` on an EOL branch), and the
restart time in `RebootScheduledAt`. Cancel a booked restart with `shutdown /a`. After the
restart, rerun audit to confirm. A NATS-only update needs no restart, so `-Reboot` books
none. When a PostgreSQL update booked a restart and a NATS update is still due, the run
returns exit `5` (or `9`) instead of `0` (or `7`), so the RMM schedules the next `-Install`
run.

The trade-off: once schedules are back on, VBR has no barrier that stops new work, so a job
that starts inside the delay is interrupted by the restart. To keep that window small, the
script checks for Veeam work once more just before booking. If a job or restore has started,
an Explorer is open, that check fails, or `shutdown.exe` cannot book the restart, it books
no restart (`IssueCode=REBOOT_NOT_SCHEDULED`) and returns
`Outcome=UPDATED_REBOOT_NOT_SCHEDULED` with exit `6` (or `8`) for the RMM to reboot. An open
Veeam console does not stop the restart. The script never restarts after a failed, partial
or rolled-back run, or when no update was needed.

## Where the evidence lives

```
C:\ProgramData\VeeamPgUpdate\
  CHANGES-IN-PROGRESS.marker   present only mid-change, or after a run that needs a human
  .veeam-pg-updater            marks the folder as created by the script
  logs\
    VeeamPgUpdate_<server>_<timestamp>.log   full transcript
    last-result.json                          machine-readable result
    stale-enterprise-manager-record-<timestamp>.reg   backup of a leftover key that
                                              -RemoveStaleEnterpriseManagerRecord deleted
  runs\<timestamp>\
    recovery-state.json       versioned state used by -Recover
    result.json               this run's result (logs\last-result.json is overwritten by each run)
    backup\
      <database>.dump        pg_dump custom format
      globals.sql            roles and grants
      conf\                  the four .conf files from before the update
      datadir\               cold copy of the whole data directory
      datadir-acl.txt         original data-directory DACLs for a manual restore
      Config.xml             VB365 only
      Proxy.xml              VB365 only; controller and persistent-cache connections
    disabled-jobs.json
    veeam-service-state.json
    pg-service-state.json
    nats-service-state.json       when nats-server is installed
    pg-tuning.sql
    postgresql-<version>-windows-x64.exe   the downloaded installer, removed on success
    pg_installer_debug.log    the installer's debug trace
    installer-*.log
  runs\<timestamp>\               a NATS update run holds the same recovery-state.json,
                                  result.json, disabled-jobs.json and *-service-state.json,
                                  but no dumps, cold copy, tuning or installer files. Also:
    nats\                          the downloaded zip and the checked program, removed on success
    backup\
      Config.xml, Proxy.xml
      nats\
        nats-server-service.reg     the service's registry key
        nats-server.conf            the config file (it holds the NATS credentials)
        store\                      copy of the whole message store
        store-acl.txt               the store folder's original permissions
```

**The WorkRoot and newly created evidence tree are locked to SYSTEM and Administrators.**
The cold copy records the source DACLs separately instead of importing them into that tree.
The dumps are privileged: restoring one runs code chosen by whoever made it. Before writing
even an audit log, the script verifies the WorkRoot owner and ACL, its parent, the
`.veeam-pg-updater` sentinel,
and that no active path component or top-level child is a junction/symbolic link. Recovery
paths are checked again before use, and a run is recursively checked for reparse points
before retention can delete it. A marker filename by itself is not trusted. Failure returns
`WORKROOT_UNSAFE` (exit 20) and writes no file in the rejected location.

The default is `C:\ProgramData\VeeamPgUpdate`. `C:\ProgramData` exists on every Windows
server and ordinary users cannot delete or replace what is in it, so the script can create
its folder there safely. Do not use a folder under a typical `C:\temp`: every signed-in user
can normally change it, so the script refuses (`WORKROOT_UNSAFE`). A custom WorkRoot's
parent must already exist, and every ancestor must be non-reparse and non-replaceable. Existing
non-empty WorkRoots are used only when they have the exact protected ACL and trusted
sentinel created by this script.
An existing empty WorkRoot must already have that exact protected ACL before the script will
claim it. Drive roots, UNC paths, relative paths, foreign content, forged
sentinels, and reparse points are rejected without changing their contents or permissions.

The script also checks `C:\temp\VeeamPgUpdate`, the work root earlier versions used, for a
trusted changes-in-progress marker. It returns `LEGACY_WORKROOT_RECOVERY_REQUIRED` (exit 40)
rather than hiding an interrupted run. Follow the RMM instruction to run `-Recover -WorkRoot
C:\temp\VeeamPgUpdate`; after recovery, normal runs can use the default. That `-Recover` run
makes the same WorkRoot checks as any other run, on `C:\temp` too, so on a typical `C:\temp`
it is refused (`WORKROOT_UNSAFE`, exit `20`). It runs only when `C:\temp` is owned by SYSTEM
or an administrator and gives ordinary users no right to delete, re-permission or take over
what is in it.

A `C:\ProgramData\VeeamPgUpdate` folder that the script cannot prove it created (for
example one left by an early version) is refused (`WORKROOT_UNSAFE`). If it holds no
`CHANGES-IN-PROGRESS.marker`, rename it and run again.

**Housekeeping runs every time**, audits included:

* Transcript logs older than `retentionDays` (default 30) are eligible for deletion.
* Completed recovery sets older than that are eligible for deletion, but the two newest
  completed sets are retained regardless of age.
* Unresolved runs are retained regardless of age. If a recovery marker exists, no run
  folder is purged.
* Audit runs do not create a recovery-set folder; `-Install` does.

These are local recovery assets, not merely script logs. Size the work volume for logical
dumps plus a full cold copy, and copy them off-host if required by your backup policy.

## If it goes wrong

Read `ExitCode`, `Stage`, `IssueCode`, `ActionRequired`, `JobsLeftDisabled`,
`UnhealthyServices`, and `RecoveryRunDir` first.

**Exit 40, Stage=INSTALLING** — the installer failed or timed out (`INSTALLER_FAILED`,
`INSTALLER_TIMEOUT`). Services are stopped, jobs disabled. Read `installer-*.log` and
`pg_installer_debug.log` in `RecoveryRunDir`. After `INSTALLER_TIMEOUT` the installer's own
`install-postgresql*.log` and `bitrock_installer*.log` are not copied there yet: look in
`%TEMP%` and `C:\Windows\Temp`. Do not use automatic database rollback.
A run blocked by a leftover marker (`PRIOR_RUN_INCOMPLETE`), and a `-Recover` that refuses
the marker or its recovery state, also report `Stage=INSTALLING` (a refused NATS recovery
keeps the stage it recorded). Those runs changed nothing
themselves; the server is as the earlier run left it. Read `Detail` and `ActionRequired`.

**Exit 40, Stage=VERIFIED** (`VEEAM_TUNING_FAILED`, `SERVICES_UNHEALTHY_JOBS_DISABLED`,
`VB365_MAINTENANCE_RELEASE_FAILED`, `FINAL_SESSION_CHECK_FAILED`, `FINAL_JOB_DRAIN_TIMEOUT` or
`JOB_REENABLE_FAILED`) — PostgreSQL updated fine but a
mandatory tuner failed, a service did not come back, or a schedule could not be safely
restored. The script leaves affected schedules disabled to prevent jobs running against
an unhealthy stack. The RMM summary names the problem and the disabled schedules. It
never reboots in this case.

**Exit 40, Stage=JOBS_DISABLED or SERVICES_STOPPED** — the run stopped before the installer
started (or, on VB365, before the new NATS was verified) and putting things back did not
fully succeed, or a `-Recover` run could not finish. PostgreSQL itself was not changed, but
it and the Veeam services may still be stopped and schedules disabled. On a NATS run, NATS
may be half-switched: see [Updating NATS (VB365)](#updating-nats-vb365). `Detail` names the
problem and `JobsLeftDisabled` the schedules. The marker stays. Fix the problem, then run
`-Recover`.

**Exit 50** — PostgreSQL is missing, will not start, is not queryable, or reports the wrong
version after install/tuning, or `-Recover` diagnosed that emergency after the installer
boundary. In an update failure, Veeam services/schedules are deliberately left down or
disabled. Diagnostic-only recovery does not change whatever state it found. Use the exact
`Stage`, `UnhealthyServices`, `JobsLeftDisabled`, and `ActionRequired` fields before acting.
Recovery evidence includes `runs\<timestamp>\backup\datadir\`, its original DACL record in
`datadir-acl.txt`, and validated logical dumps;
restoration is always an operator-reviewed operation.

A `CHANGES-IN-PROGRESS.marker` file in the work root blocks every normal audit/install;
those modes return exit `40`. Do not delete it merely to make the next run proceed.

Use `-Recover` for an interrupted run:

* It validates that the marker and versioned `recovery-state.json` resolve inside this
  work root and are trusted recovery data.
* For a NATS update run, see [Updating NATS (VB365)](#updating-nats-vb365).
* If the recorded installer-started flag is false and the stage is `JOBS_DISABLED` or
  `SERVICES_STOPPED`, it restores and verifies captured PostgreSQL, NATS, Veeam service,
  and job state. Successful recovery returns exit `0` and removes the marker.
* If the installer has started, recovery finishes the run only when everything proves it
  safe: PostgreSQL answers at the recorded target version, the installer is no longer
  running, every Veeam service is still stopped, and the disabled-job record is readable. It
  then applies the mandatory Veeam tuning, restores the captured service states, and
  re-enables the jobs (`RECOVERED_POSTINSTALL`, exit `0`). It does not report
  `RebootRequired=True`, so schedule the restart Veeam recommends through the RMM. If any
  check fails it changes nothing and exits as `RECOVERY_DIAGNOSTIC_ONLY`, naming the check.
  A tuning failure leaves Veeam down, as it does during `-Install`.
* If active work appears during recovery, it waits naturally; no job or restore is forcibly
  stopped, though an open Veeam console is closed once it is the only thing left blocking.
* If a VB365 maintenance start had an unknown client outcome, the script never adopts or
  stops a time/scope-matched session whose ID was not returned by its own start call. It
  leaves schedules and the marker in place for an operator if such a session exists.
* If the installer started or may have started and any of those checks fails, `-Recover` is
  **diagnostic-only** (`RECOVERY_DIAGNOSTIC_ONLY`). It reports PostgreSQL/service state plus
  the actual recorded, unrestored job names and returns `40` or `50` without rolling back
  database files or blindly re-enabling schedules.
* `-Recover` cannot be combined with `-Install` or `-Reboot`.

If rollback/state restoration succeeds but the completed marker cannot be removed, the
result is exit `40`, `Stage=COMPLETE`, and `IssueCode=MARKER_REMOVE_FAILED`. Jobs are not
reported as disabled when their durable records say they were restored. Confirm the
completed state, then remove the stale marker under the operator change record.

## Leftover Enterprise Manager records

Enterprise Manager has its own configuration database, separate from VBR's. The script
discovers it from the registry and adds it to the dump set, using the layout Veeam
publishes in [KB1471](https://www.veeam.com/kb1471) — the same layout as VBR, under
`HKLM\SOFTWARE\Veeam\Veeam Backup Reporting`. Its default database name is
`VeeamBackupReporting`. Enterprise Manager's own services (`VeeamEnterpriseManagerSvc`,
`VeeamRESTSvc`) are already covered, because every `Veeam*` service is stopped and restored.

Three topologies are still excluded:

* **Enterprise Manager without VBR** (`ENTERPRISE_MANAGER_WITHOUT_VBR`, exit 11), on a
  VB365 server. That needs its own profile for services and tuning. A server with
  Enterprise Manager and neither VBR nor VB365 is not a target at all: exit `0`,
  `Outcome=NOT_APPLICABLE`, and its PostgreSQL is not checked.
* **A database the script cannot read** (`ENTERPRISE_MANAGER_DB_UNKNOWN`, exit 11) — a
  pre-v12 registry layout, a missing value, an invalid port, or an unexpected engine name.
  Nothing is guessed.
* **An Enterprise Manager database on another server** (`REMOTE_DB`, exit 11), like any
  remote Veeam database.

If Enterprise Manager is on MS SQL, it is simply not a PostgreSQL target. Its services are
still stopped and restarted with the rest.

Enterprise Manager 13 lists PostgreSQL 14.x, 15.x and 17.x; **16.x is absent**. The update
never changes the major version, so a 16.x instance is only warned about, not blocked.

### Leftover records after an uninstall

An uninstall can leave records behind, and then the server would be excluded for a product
that is not there. There are two separate records:

| Record | Where | How to clear it |
|---|---|---|
| Install footprint | Registry `HKLM\SOFTWARE\Veeam\Veeam Backup Reporting` | `Update-VeeamPreReqs.ps1 -RemoveStaleEnterpriseManagerRecord` |
| Connection record | Inside the VBR configuration database | `Clear-StaleEnterpriseManagerRecord.ps1 -Clear` |

The registry key alone never counts as an installation. The script also needs an Enterprise
Manager **service** or its **installed files**. With only the key, the run continues and
logs that it found a leftover record.

`-RemoveStaleEnterpriseManagerRecord` deletes that key only when the same run proved
Enterprise Manager is absent. It exports a `.reg` backup into the log folder and verifies it
first; no backup means no deletion. It never touches the Veeam configuration database.
If the backup or the removal fails, the run stops with exit `20` and
`IssueCode=STALE_EM_RECORD_REMOVE_FAILED`. The report field `StaleEmRecord` is `present`
when a leftover key was found, and `removed; backup <path>` after the key is deleted. The
backup is `stale-enterprise-manager-record-<timestamp>.reg` in the log folder.

`Clear-StaleEnterpriseManagerRecord.ps1` covers the record inside the VBR database. See
[the separate tool](#the-separate-tool-clear-staleenterprisemanagerrecordps1) below.

> **The clear uses an unsupported API.** `[Veeam.Backup.Core.SBackupOptions]` is an internal
> Veeam class with no public documentation, and it writes directly to the VBR configuration
> database. Veeam Support does not support this and the class can change between versions.
> The supported route is to remove this VBR server from the Enterprise Manager console, or
> to ask Veeam Support. Test on a non-production VBR first.

### The separate tool: `Clear-StaleEnterpriseManagerRecord.ps1`

**What it is**

A small manual tool for one leftover: the Enterprise Manager connection record inside the
VBR configuration database. It shows what the record holds: the Enterprise Manager server
name and URL, whether VBR is connected to it, and its licence-update settings. It changes
nothing unless you pass `-Clear`.

**Why it is there**

When a VBR server is added to Enterprise Manager, VBR stores this record. The supported way
to remove it is to remove the VBR server from the Enterprise Manager console. Once
Enterprise Manager is uninstalled, that console is gone, so the record can stay behind, and
the supported route left is to ask Veeam Support. This tool can check for the record, and
can clear it without Support, through the unsupported class described above. It is for
servers where Enterprise Manager has been uninstalled.

**Why it is not part of `Update-VeeamPreReqs.ps1`**

* The PostgreSQL update does not need it. `Update-VeeamPreReqs.ps1` never reads this
  record. Of the two records, it uses only the registry key: together with the Enterprise
  Manager services and install folders, to decide whether an Enterprise Manager database
  must also be backed up, and, with `-RemoveStaleEnterpriseManagerRecord`, to delete the
  key when it is a leftover.
* `-Clear` writes to the VBR configuration database through the unsupported class above.
  Inside the main script, that write would be one switch away on every server the RMM
  reaches. As a separate script, a person runs it by hand, on one server, after reading its
  report.
* Reading the record uses the same internal class, which may not exist on every VBR
  version. Kept apart, that can never stop a PostgreSQL update.

**Do not add it to the RMM.** For the update, the RMM needs only `Update-VeeamPreReqs.ps1`.

**How to run it**

Run it on the VBR server, from an elevated prompt. VBR 12 works in Windows PowerShell 5.1.
VBR 13 needs PowerShell 7 (7.6.3 or later for VBR 13.1).

```powershell
.\Clear-StaleEnterpriseManagerRecord.ps1          # report only, changes nothing
.\Clear-StaleEnterpriseManagerRecord.ps1 -Clear   # checks, backs up, asks you, then clears
```

| Exit | Meaning |
|---|---|
| `0` | No record, the record is already empty, or `-Clear` cleared it and read it back empty |
| `5` | A record exists. Report only, so nothing was changed |
| `1` | The tool could not run or read the record, `-Clear` refused, or you did not confirm (or used `-WhatIf`): nothing was changed. Or the write failed, the record could not be read back after the write, or it read back not empty: the record may have changed, so check the VBR console, and restore the configuration backup if VBR misbehaves |

**What `-Clear` checks before it writes anything**

1. Enterprise Manager is not installed: no Veeam service with "Enterprise Manager" in its
   name, and no folder at the default install path
   `C:\Program Files\Veeam\Backup and Replication\Enterprise Manager`. A custom install path
   is not checked.
2. A fresh VBR configuration backup, taken by the tool itself, succeeds. `Success` and
   `Warning` both pass, because both write a backup file. A failure stops the tool, and it
   prints the reason from the backup's session log. With `-WhatIf` no backup is taken.
   `-SkipConfigBackupCheck` skips this step, for a lab server only.
3. You confirm the change at the prompt.

After the write it reads the record back, and fails if the record is not empty.

The tool takes a fresh backup instead of trusting an older one, because `LastRun` can be
empty on VBR 12 and 13 builds, so the age of an older backup cannot be proven.

## Known limits

The initial production profile intentionally returns exit `11` for:

* combined VBR+VB365 servers;
* Veeam ONE co-residence;
* Enterprise Manager on a VB365 server without VBR, or an Enterprise Manager database the
  script cannot read or that is on another server. Enterprise Manager beside VBR is
  supported (see [Leftover Enterprise Manager records](#leftover-enterprise-manager-records));
* remote VBR/VB365 databases or distributed VB365 proxies;
* multiple PostgreSQL installations, different Veeam database ports, or HA/clustered
  PostgreSQL;
* a PostgreSQL pooler/proxy in the connection path, unexpected non-Veeam databases in the
  cluster, or VB365 controller/cache connections that do not all map to the local instance;
  and
* any installed scheduler family that cannot be enumerated, disabled, re-enabled, and
  verified through the available Veeam PowerShell module.

In particular, current VBR storage-copy and Catalyst-copy wrappers do not expose their
original enabled/schedule state. If either object type exists, the script fails closed
instead of guessing how to round-trip it.

There is no configuration switch to bypass those exclusions. Add support only through a
tested profile that protects every database, proxy, service, and schedule involved.

* **No checksums.** EnterpriseDB publishes none. The Authenticode signature is the only
  authenticity control. Behind a TLS-inspecting proxy, test it before fleet rollout.
* **NATS has no signature.** A NATS version Veeam adds later is checked only against the
  `SHA256SUMS` file in its own GitHub release, so a release changed after publication would
  not be caught. Only 2.10.28 and 2.12.8 also have a SHA256 built into the script.
* **More sites to reach on VB365.** Every run, audit included, reads
  `helpcenter.veeam.com`. When a NATS update is due it also reads the release's
  `SHA256SUMS` from `github.com`, which redirects to `release-assets.githubusercontent.com`.
  The `-Install` download of NATS uses the same two GitHub hosts.
* **Single-server NATS only.** No cluster, gateway, leaf node, or client on another machine.
* **Pilot first.** VB365 support needs VB365 8.6 or later. The unit tests pass on both
  PowerShell editions. **Pilot each new product, version and PowerShell edition on one
  non-production server before fleet rollout.**

## Changelog

All notable changes, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project has no version
numbers, so each entry is the date the change reached GitHub, with its commit IDs. When
you change a script, add your entry at the top.

### 2026-10-15

#### Added

* README: [What the script does, step by step](#what-the-script-does-step-by-step), every
  step the script logs, with what it does and why. It replaces the shorter `-Install` list.
* README: this changelog.

### 2026-10-13

#### Added

* NATS updates on VB365 servers, following Veeam KB4742 (`460339f`). Same 2.x line only,
  never another line and never older. One change per run: PostgreSQL first, NATS on the
  next `-Install` run. The run backs up the NATS service, config file and message store,
  verifies NATS and then VB365 on the new version, and puts the old version back on a
  failure. New report fields `NatsInstalled`, `NatsTarget`, `NatsStatus` and `NatsDetail`.
  New built-in setting `updateNats`. `-Recover` recovers an interrupted NATS update.
* The NATS supported list is read from Veeam's website on every run, and the download is
  checked against the SHA256 published with the NATS release, so a version Veeam adds
  needs no script change. The SHA256 built in for 2.10.28 and 2.12.8 must still agree
  (`HASH_CONFLICT`) (`a6eea4d`).
* `-Reboot` books a delayed Windows restart after a fully successful update, and
  `-RebootDelaySeconds` sets the delay (default 120 seconds) (`936d2eb`).

#### Changed

* A stuck VB365 organisation sync gives a warning and fills `Vb365SyncStuck`, and the run
  carries on instead of waiting for it (`bc11a2d`).
* `NatsDetail` says what the run did with NATS, not only what the audit found (`3677568`).
* README brought up to date with the scripts: exit codes, report fields, stages, the
  `-Install` steps, Enterprise Manager rules and recovery (`ebdbe48`).

#### Fixed

* An ended VB365 job session (`Disconnected`) and an organisation sync booked for later no
  longer block the wait for Veeam work (`15322ac`).
* VB365 maintenance mode: the run waits for the session to reach `Running` instead of
  giving up while it is still `Preparing` (`cf4ca2b`).
* NATS backup failed on a real VB365 8.6 server: `icacls` cannot read message-store paths
  longer than 260 characters. Only the store folder's permissions are saved now
  (`67ec48f`).
* A `-Recover` that saved its state and then failed left a marker the next `-Recover`
  refused. The marker now stays bound to the original run (`460339f`).

#### Removed

* `Find-StuckVBMJobs.ps1`, a separate monitoring script added on this day (`dff6816`,
  `18fa748`, `570e2e1`), moved to its own repository,
  [acgdickie/Find-StuckVBMJobs](https://github.com/acgdickie/Find-StuckVBMJobs)
  (`50344dc`).

### 2026-10-12

#### Added

* First public version (`96ac772`). Earlier development history is not published.
  * Audits, and with `-Install` applies, the latest PostgreSQL minor update on the same
    major version, on VBR 12 and 13 and on VB365 8.6 or later. Audit is the default and
    changes nothing.
  * Waits for Veeam work to finish, never kills a job or restore, closes an open Veeam
    console, disables and restores jobs, and holds VB365 in repository maintenance mode.
  * Backs up first: the VBR configuration backup (retried once after starting stopped
    automatic Veeam services), a dump of every Veeam database, and a cold copy of the data
    directory.
  * Verifies the installer's signature and the running version afterwards, and applies
    Veeam's mandatory PostgreSQL tuning.
  * Fails closed on anything it cannot prove, rolls back automatically before the
    installer starts, and recovers interrupted runs with `-Recover`.
  * Supports Enterprise Manager beside VBR. `-RemoveStaleEnterpriseManagerRecord` clears a
    leftover Enterprise Manager registry key, and the separate tool
    `Clear-StaleEnterpriseManagerRecord.ps1` checks and clears the leftover record inside
    the VBR database.
  * `Test-Helpers.ps1` tests the scripts on Windows PowerShell 5.1 and PowerShell 7.

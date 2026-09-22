# Veeam PostgreSQL Updater

Patches the PostgreSQL engine under **Veeam Backup & Replication (VBR)** and
**Veeam Backup for Microsoft 365 (VB365 / "VBM")** on Windows. Built to run from an RMM.

## Why this exists

Veeam does not patch PostgreSQL for you on Windows. Upgrading the Veeam product
leaves the database engine alone. Veeam says so in writing:

> "When upgrading Veeam Backup for Microsoft 365, the previously deployed PostgreSQL
> database engine is not automatically upgraded." — [Veeam KB4729](https://www.veeam.com/kb4729)

So a Veeam server can remain on an older PostgreSQL minor release after the Veeam
product itself has been upgraded, missing later PostgreSQL security and bug fixes.

Procedure follows [KB4386](https://www.veeam.com/kb4386) (VBR) and
[KB4729](https://www.veeam.com/kb4729) (VB365).

## Scope — read this

* **Minor updates only, always to the latest release on the installed major.** The script
  reads the running PostgreSQL branch and selects its latest published minor. For example,
  15.2 becomes the latest 15.x release; it never becomes 16.x or 17.x. There is no target
  override or version allow-list.
* **Major upgrades are hard blocked.** A branch change needs `pg_upgrade` or a Veeam
  configuration restore and is outside this script.
* **No downgrades.** If the running version is equal to or newer than the resolved target,
  the script changes nothing.
* **EOL branches stay on their branch.** The script warns, then targets the final minor
  published for that branch. It returns a distinct EOL exit code until a major-version
  migration is completed.
* **Initial production topology.** Supported targets are either VBR-only or VB365-only,
  backed directly by one local, standalone PostgreSQL instance dedicated to the detected
  Veeam configuration/cache databases. Combined VBR+VB365 servers,
  Veeam ONE co-residence, Enterprise Manager, remote/distributed databases and proxies,
  and multiple or HA PostgreSQL instances return exit `11` for manual handling.
* **Windows only.** On the Veeam Linux appliance, PostgreSQL comes from Veeam Updater.
  Do not hand-patch those. The script refuses.
* **Out of Veeam Support scope.** Both KBs cite Support Policy section 10. If it breaks,
  the backups this script takes are your only safety net.

## Files

| File | What it is |
|---|---|
| `Update-VeeamPostgres.ps1` | The script. **The only file your RMM needs** |
| `Test-Helpers.ps1` | Unit tests. Run after any edit |

The settings are built into the script, so an RMM that uploads just the one file to a
temp folder works.

Run the tests any time:

```bash
powershell -ExecutionPolicy Bypass -File .\Test-Helpers.ps1
```

The checks read the real functions out of the script — not a copy. Run them under both
`powershell.exe` and `pwsh.exe`; the two editions behave differently and both are
supported. Run from an elevated prompt, or the folder-lock checks are skipped.

## Quick start

Audit one server (changes nothing):

```powershell
powershell -ExecutionPolicy Bypass -File .\Update-VeeamPostgres.ps1
```

Apply the update:

```powershell
powershell -ExecutionPolicy Bypass -File .\Update-VeeamPostgres.ps1 -Install
```

Recover captured state after an interrupted run, when the installer did not start:

```powershell
powershell -ExecutionPolicy Bypass -File .\Update-VeeamPostgres.ps1 -Recover
```

The update happens in one RMM run. It waits for active Veeam work to finish naturally,
disables schedules, performs the maintenance, verifies services, and only then re-enables
the schedules it disabled. It never forcibly terminates a backup or restore, and it does
not reboot the server. Reboot coordination belongs to the RMM after exit `6` or `8`.

## Exit codes

The process exit code is the RMM contract. Point RMM automation and alerting at these
exact values:

| Code | Meaning | Action |
|---|---|---|
| `0` | Healthy, with no outstanding RMM action | None |
| `5` | Supported branch: audit found a minor update | Schedule `-Install` through the rollout ring |
| `6` | Supported branch: update succeeded; reboot required | Schedule and verify a reboot |
| `7` | PostgreSQL branch is EOL | Open or maintain a major-version migration ticket |
| `8` | EOL branch and reboot required | Schedule a reboot and maintain the migration ticket |
| `9` | EOL branch and minor update available | Schedule the minor update and maintain the migration ticket |
| `10` | Safe transient condition | Retry later; no backup or restore was forcibly stopped |
| `11` | Unsupported or excluded topology | Handle manually; do not repeatedly retry as a transient failure |
| `20` | Pre-flight failed | Investigate before retrying |
| `30` | EnterpriseDB page, download, size, or signature check failed | Investigate the download path; nothing was installed |
| `40` | **Post-change failure, unhealthy service, mandatory tuning failure, or recovery needs an operator** | **Page an operator and read the RMM issue fields** |
| `50` | **PostgreSQL is missing, down, unqueryable, or reports the wrong version after change/tuning/recovery diagnosis** | **Page an operator immediately and use the recovery evidence** |

Failure codes `20`–`50` take precedence over informational EOL/reboot codes. For example,
an EOL server with a post-update service failure returns `40`, not `8`.

The console summary and `last-result.json` include `ExitCode`, `IssueCode`,
`ActionRequired`, `JobsLeftDisabled`, `UnhealthyServices`, `RecoveryRunDir`, and `Detail`.
Those fields are the RMM-readable issue note for any action-bearing result; they name what
is unhealthy, what remains disabled, and where recovery evidence lives.

Every summary line carries a `Stage=` field telling you exactly how far it got:

| Stage | What it means |
|---|---|
| `UNTOUCHED` | Nothing was changed. Guaranteed |
| `JOBS_DISABLED` | Schedules have been disabled; the installer has not started |
| `SERVICES_STOPPED` | Services are stopped; the installer has not started |
| `INSTALLING` | **Mid-change.** The installer may have started; automatic rollback is prohibited |
| `VERIFIED` | PostgreSQL is at the target version |
| `COMPLETE` | Maintenance/state restoration completed. Inspect the exit code: exit `40` can still mean the completed recovery marker could not be removed |

Codes `10`, `11`, `20`, and `30` normally mean nothing was changed or a safe pre-installer
rollback succeeded. Always use `Stage`, `JobsLeftDisabled`, and `ActionRequired` as the
final state record. Codes `40` and `50` can deliberately leave schedules disabled.

## Parameters

| Parameter | Default | What it does |
|---|---|---|
| `-Install` | off | Actually do the update. Without it, audit only |
| `-Reboot` | off | Compatibility switch only. It is accepted but safely deferred to the RMM; the script never invokes shutdown |
| `-Recover` | off | Validate and restore captured state from an interrupted pre-installer run; post-installer use is diagnostic-only |
| `-WorkRoot` | `C:\ProgramData\VeeamPgUpdate` | Protected logs and recovery evidence, including dumps and the cold copy |
| `-SkipDownloadInAudit` | off | Skip the EnterpriseDB installer-availability check; the audit still contacts PostgreSQL's version feed |

**There is no maintenance window.** `-Install` means "go now". It runs when you run the
RMM script or policy. The independent RMM owns the maintenance window, retries, reboot,
and post-reboot verification. `-Recover` is a separate operation and cannot be combined
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
4. Let the RMM retry exit `10`, schedule reboots for `6`/`8`, create major-migration
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
`BUILT-IN SETTINGS - EDIT THESE`. Edit there, review the change, then re-upload the script
to your RMM. There is no `-ConfigPath` parameter and no external settings file is read.

| Setting | Default | What it does |
|---|---|---|
| `jobWaitTimeoutMinutes` | `720` | Maximum time to wait for active Veeam work to finish naturally |
| `installerTimeoutMinutes` | `120` | Maximum unattended wait for the EnterpriseDB installer; it is not forcibly killed on timeout |
| `retentionDays` | `30` | Minimum age before completed logs and recovery sets become eligible for deletion |

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
the timeout expires, exit `10` tells the RMM to retry.

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
recovery sets. A recovery set contains database dumps, roles, configuration copies, the
cold data-directory copy, service/job state, tuning and installer logs. Unresolved runs
and the two newest completed recovery sets are retained regardless of age; older completed
sets become eligible for deletion after `retentionDays`. Copy recovery evidence off-host
if your operational policy requires protection from loss of the Veeam server itself.

### Job and restore handling

Audit and install modes both inventory every job family the script knows how to round-trip
and check the corresponding job/restore/session APIs before an audit can report the server
current. If a required API is missing, a query fails, an enabled-state property is unknown,
or a job cannot be identified and later re-enabled by stable ID, the run fails closed.
Protection-group rescans and their agent deployment work are checked through current and
legacy VBR discovery-session types. VB365 whole-organization synchronization and each of
its Users, Groups, GroupMembers, Sites, and Mailboxes parts are also fail-closed activity
barriers because they write the PostgreSQL-backed organization cache.

If work is active, the script waits for it to finish naturally for up to
`jobWaitTimeoutMinutes`. It does **not** forcibly stop or terminate backups, restores,
copies, CDP sessions, tape work, agent jobs, plug-in jobs, or VB365 operations. Once idle,
it disables every enabled managed schedule, durably records each change, verifies the
disabled state, then checks activity again before stopping services. A race that starts
new work causes a safe rollback/retry rather than termination.

The RMM maintenance policy must also prevent remote administrators from manually starting
new VBR work during `-Install`. VBR has no public atomic global new-work barrier; the script
disables every known schedule, repeatedly refreshes schedule/activity state, and blocks
local console/Explorer processes, but only an external change freeze closes the remote
manual-start race completely.

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
(`Automatic`, `Automatic (Delayed Start)`, `Manual`, or `Disabled`) in
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

## What the script does when you pass -Install

1. Checks that execution is Windows, elevated, local, and not blocked by an earlier marker.
2. Detects VBR, VB365, Veeam ONE, and Enterprise Manager and enforces the initial
   VBR-only/VB365-only supported topology.
3. Requires one local standalone PostgreSQL installation, Windows service/cluster, and
   direct Veeam database port; binds the service binary to the registry `Base Directory`;
   proves `data_directory` and the registry/runtime major version match the installer
   target; requires `WorkRoot` to be outside the data tree; and rejects standby,
   streaming-replication, physical-slot, synchronous-standby, and Windows Failover
   Cluster signals.
4. Reads the **running** version with `SHOW server_version_num`, resolves the latest minor
   on that same branch from `postgresql.org/versions.json`, and blocks major changes and
   downgrades. EOL branches receive their final minor and a persistent EOL result.
5. Resolves the exact Windows x64 installer link published on the
   [EnterpriseDB PostgreSQL download page](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads).
   It does not guess a CDN build suffix.
6. Requires exact VBR database-engine/connection registry values. For VB365 it parses both
   `Config.xml` and `Proxy.xml`, validates controller and every persistent-cache connection,
   and requires them all to resolve to the same local PostgreSQL service. It inventories
   the cluster and rejects unexpected non-Veeam databases or a pooler/port mismatch.
7. Loads the product PowerShell module, validates VB365 proxy/maintenance topology,
   inventories supported job families, and fails closed if schedules or activity cannot
   be safely enumerated and round-tripped. Install mode repeats this check before mutation.
8. Waits for active jobs and restores to finish naturally. Nothing is forcibly stopped;
   a timeout is exit `10` for the RMM to retry.
9. Downloads the EDB installer, checks its advertised length, and requires a valid
   EnterpriseDB Authenticode signature.
10. Disables and verifies every enabled managed schedule, writing durable recovery state
   before each mutation, then re-checks that no work started in the race window.
11. Generates the mandatory Veeam PostgreSQL tuning SQL while the product control service
    is healthy, then runs the VBR configuration backup when applicable, `pg_dump` for each
    Veeam database (including every VB365 `cache_<guid>` database), and `pg_dumpall -g`,
    validating the logical dumps before continuing.
12. Captures every `Veeam*` service's exact startup/running state, disables and stops all
    of them (including the Veeam Management Agent), captures NATS/PostgreSQL state, and
    stops NATS. It refuses to stop PostgreSQL while any other client remains connected,
    and never force-stops unrelated dependants or client sessions.
13. Takes a cold copy of the stopped PostgreSQL data directory.
14. Runs the EDB installer unattended with a bounded wait; a timeout is never killed.
15. Verifies the running server version and database connectivity instead of trusting the
    installer exit code alone, then compares the protected PostgreSQL configuration files.
16. Applies the pre-generated mandatory Veeam PostgreSQL tuning SQL, restarts PostgreSQL,
    and verifies the target version is queryable again.
17. Restores exact startup types and starts every service that was originally running;
    a formerly stopped service that is now live is not stopped.
18. Only when PostgreSQL, tuning, and services are healthy, re-enables and verifies exactly
    the schedules changed by this run.
19. Returns exit `6` (or `8` on an EOL branch) with `RebootRequired=True`; the RMM owns the
    controlled reboot and post-boot audit.

## Rebooting

Veeam's KBs recommend restarting after the update. A successful supported-branch update
returns exit `6`; an EOL update returns exit `8`. Both report `RebootRequired=True`.

The script intentionally never calls `shutdown.exe`. Once schedules have been restored,
VBR has no public atomic global barrier that can prevent a new backup or restore from
starting between an idle query and Windows shutdown. Even an immediate reboot would leave
a race and could violate the no-force rule.

The legacy `-Reboot` switch is retained so existing RMM commands do not break, but it
returns `Outcome=UPDATED_REBOOT_DEFERRED_SAFETY`, issue
`REBOOT_REQUIRES_RMM_COORDINATION`, and exit `6`/`8`; no shutdown is attempted. The RMM
must enforce a real Veeam change freeze, wait for work to finish, reboot, verify
`LastBootUpTime`, and rerun audit. Do not rerun the installer merely because exit `6` or
`8` was returned. After a verified reboot, audit returns `0` on a supported branch or the
persistent EOL result `7`.

## Where the evidence lives

```
C:\ProgramData\VeeamPgUpdate\
  CHANGES-IN-PROGRESS.marker   present only mid-change, or after a run that needs a human
  .veeam-pg-updater            marks the folder as created by the script
  logs\
    VeeamPgUpdate_<server>_<timestamp>.log   full transcript
    last-result.json                          machine-readable result
  runs\<timestamp>\
    recovery-state.json       versioned state used by -Recover
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
    installer-*.log
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

If upgrading from the release that used `C:\temp\VeeamPgUpdate`, the script checks that
former location for a trusted changes-in-progress marker. It returns
`LEGACY_WORKROOT_RECOVERY_REQUIRED` (exit 40) rather than hiding an interrupted run. Follow
the RMM instruction to run `-Recover -WorkRoot C:\temp\VeeamPgUpdate`; after recovery,
normal runs can use the default.

A `C:\ProgramData\VeeamPgUpdate` folder left by an older test version of the script is
refused (`WORKROOT_UNSAFE`) because the script cannot prove it created it. If it holds no
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

**Exit 40, Stage=INSTALLING** — the installer failed. Services are stopped, jobs disabled.
Read `installer-*.log` in `RecoveryRunDir`. Do not use automatic database rollback.

**Exit 40, Stage=VERIFIED** (`UPDATED_WITH_PROBLEMS`) — PostgreSQL updated fine but a
mandatory tuner failed, a service did not come back, or a schedule could not be safely
restored. The script leaves affected schedules disabled to prevent jobs running against
an unhealthy stack. The RMM summary names the problem and the disabled schedules. It
never reboots in this case.

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
* If the recorded installer-started flag is false and the stage is `JOBS_DISABLED` or
  `SERVICES_STOPPED`, it restores and verifies captured PostgreSQL, NATS, Veeam service,
  and job state. Successful recovery returns exit `0` and removes the marker.
* If active work appears during recovery, it waits naturally; nothing is forcibly stopped.
* If a VB365 maintenance start had an unknown client outcome, the script never adopts or
  stops a time/scope-matched session whose ID was not returned by its own start call. It
  leaves schedules and the marker in place for an operator if such a session exists.
* If the installer started or may have started, `-Recover` is **diagnostic-only**. It
  reports PostgreSQL/service state plus the actual recorded, unrestored job names and
  returns `40` or `50` without rolling back database files or blindly re-enabling schedules.
* `-Recover` cannot be combined with `-Install` or `-Reboot`.

If rollback/state restoration succeeds but the completed marker cannot be removed, the
result is exit `40`, `Stage=COMPLETE`, and `IssueCode=MARKER_REMOVE_FAILED`. Jobs are not
reported as disabled when their durable records say they were restored. Confirm the
completed state, then remove the stale marker under the operator change record.

## Known limits

The initial production profile intentionally returns exit `11` for:

* combined VBR+VB365 servers;
* Veeam ONE co-residence;
* Enterprise Manager co-residence, because it can have a separate configuration database;
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
* **Not yet run against a real Veeam server.** What *is* verified: the script parses and
  runs clean on Windows PowerShell 5.1 and supported PowerShell 7 editions; unit tests pass
  on each; the live version lookup and EDB installer-URL probe work against real endpoints;
  and job/session behavior is exercised against hermetic fake Veeam cmdlets. What is
  **not** verified is the actual installer workflow and every cmdlet against a live Veeam
  server. **Pilot on one non-production VBR and one non-production VB365 before fleet
  rollout.**

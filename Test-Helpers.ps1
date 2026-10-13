# The tests for Update-VeeamPreReqs.ps1, plus the configuration backup check in
# Clear-StaleEnterpriseManagerRecord.ps1. For whoever edits the scripts: never copy this
# file to a Veeam server or add it to the RMM.
#
# Extracts the real function definitions out of Update-VeeamPreReqs.ps1 via the
# AST and exercises them, so the function tests run the shipping code. The main script
# body is checked by reading its text and structure, plus one elevated run that must
# refuse an unsafe folder (exit 20).
# Veeam cmdlets and every call that would change a service or process are faked, so no
# Veeam, PostgreSQL or network is needed. A few harmless real calls remain (Get-Process,
# Get-Service lookups, cmd.exe, reg.exe). Only throw-away items named with the PID are
# created (folders, a .reg file, two HKCU:\Software keys), and removed again.
#
# Why it exists: VBR 12 runs on Windows PowerShell 5.1 and VBR 13 on PowerShell 7,
# and some bugs appear on one edition only (a lost installer exit code, JSON lists
# read as one nested list). A production server is the most expensive place to find
# one.
#
# Run after every change and before every push, elevated, on BOTH editions:
#   powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\Test-Helpers.ps1
#   pwsh.exe       -ExecutionPolicy Bypass -NoProfile -File .\Test-Helpers.ps1
# A pass ends "RESULT: <n> passed, 0 failed" with exit code 0. Without elevation the
# folder-lock checks are skipped and many -Recover checks fail (exit 1): never a pass.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:Path = Join-Path $PSScriptRoot 'Update-VeeamPreReqs.ps1'
$errs = $null; $toks = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Path, [ref]$toks, [ref]$errs)
if ($errs -and $errs.Count) { throw "parse errors: $($errs.Count)" }

$want = 'ConvertFrom-ServerVersionNum','ConvertTo-ServerVersionNum',
        'Get-BranchKey','Compare-PgVersion','Get-CfgValue','Invoke-Native','Remove-StaleVeeamRegistryRecord','Get-VeeamRegistryPostgresDatabase','Get-RegValue','Resolve-VeeamDatabaseNames','ConvertFrom-JsonArrayText','Test-CommandCallableBare','Test-NoAllSessionsError','Test-VbrConnectionLostError','Test-VeeamMfaBlockedError','Test-VeeamEditionBlockedError','Invoke-VeeamEnumeration','Get-SessionsFromGetter','Format-ShortText','Set-UnusableSessionGetter','Test-UnusableSessionGetter','Write-UnusableSessionGetterOnce','Get-UnusableSessionGetterMap','Get-VeeamServiceStartOrder',
        'Resolve-LatestPgTarget','ConvertFrom-PgConnectionString','Test-LocalDbHost','Test-Vb365CacheDatabaseName','Test-Vb365CacheDatabaseTemplate','Get-PgLoginFailureHint',
        'Get-DefaultConfig','Get-WorkRootSentinelText','Test-TrustedOwner','Test-PathTreeHasReparsePoint','Test-DirectoryHasReparseChild',
        'Test-RegularTrustedFile','Test-ProtectedFolderAcl','Test-SafeWorkRootParent',
        'Protect-Folder','New-ProtectedDirectory','Test-WorkRootSentinel','Get-TrustedLegacyRecoveryMarker',
        'Get-ValidatedCompletedRunManifest','Initialize-WorkRoot',
        'Get-PolicyExitCode','Get-RmmActionForExitCode','Invoke-DelayedReboot',
        'Resolve-PgInstallerLinkFromHtml',
        'Get-VeeamJobFamilyDefinitions','Get-VeeamJobFamilyDefinition',
        'Get-VeeamJobEnabledFlag','Get-VeeamJobIdentity','Get-VeeamManagedJobInventory',
        'Invoke-VeeamJobTransition','Get-VeeamJobByRecord','Enable-VeeamJobById',
        'Get-ActiveLabelsFromSessions','Get-ActiveVb365OrganizationSyncWork','Get-Vb365QueuedSyncTiming','Write-Vb365StuckSyncOnce','Test-VbrFamilyInUse','Get-BlockingVeeamUiProcesses',
        'Get-ActiveVeeamWork','Wait-VeeamIdle','Find-Vb365MaintenanceBarrier','Start-Vb365MaintenanceBarrier',
        'Get-UnrestoredJobNames',
        'Write-AtomicText','Write-AtomicJson','Set-RecoveryProperty','Save-RecoveryState',
        'Invoke-ExplicitRecovery',
        'Get-ServiceStartupTypeExact','Set-ServiceStartupTypeExact','Test-PgServiceExecutableMatchesBaseDir','Test-PathTreeOverlap',
        'Get-VeeamServiceState','Disable-VeeamServiceStartup','Restore-VeeamServiceState',
        'Add-ReportListItem','Get-VeeamConsoleProcesses','Close-VeeamConsoleProcesses','Test-OnlyConsoleBlockers',
        'Start-StoppedAutomaticVeeamServices','Invoke-VbrConfigBackupAttempt','Invoke-RecoveryPgTuning',
        'Add-RunSideEffectNotes',
        'Get-NatsPolicy','Get-Vb365ReleaseKey','Resolve-NatsTarget','ConvertFrom-NatsImagePath','ConvertFrom-NatsVersionText',
        'Read-NatsConfText','Get-NatsConfFacts','ConvertFrom-NatsConnectionString','ConvertFrom-NatsInfoLine','Get-NatsInfoVersion',
        'Wait-NatsInfoVersion','Get-NatsClientSummary','Test-NatsStorePathSafe','Test-NatsZipEntryNames','Expand-NatsPackage',
        'Get-FileSha256','Get-NatsDiscovery','Set-NatsStage','Set-NatsServicePath','Stop-ServiceAndWait','Test-NatsRunningAt',
        'Restore-NatsStore','Restore-NatsInstallation','Get-NatsManualRevertAction','Stop-ServicesInOrder','Get-NatsRunFacts',
        'Invoke-NatsWebText','ConvertFrom-VeeamNatsRequirementsHtml','Get-NatsSupportedVersions','ConvertFrom-NatsSha256Sums','Resolve-NatsPackageSha256'
foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if ($want -contains $fn.Name) { . ([scriptblock]::Create($fn.Extent.Text)) }
}
function Write-Log { param($Message, $Level) }   # stub

# The shipping script waits up to 10 minutes for Veeam services to settle, because
# VBR 13's Backup Service can genuinely take minutes. Tests use fakes that never
# settle, so shorten the window here instead of waiting it out.
$script:ServiceSettleMinutes = 0.02

$pass = 0; $fail = 0
function Check {
    param([string]$Name, $Actual, $Expected)
    if ("$Actual" -eq "$Expected") { $script:pass++; "  PASS  $Name" }
    else { $script:fail++; "  FAIL  $Name  expected '$Expected' got '$Actual'" }
}

function Throws {
    param([Parameter(Mandatory)][scriptblock] $Action)
    try { & $Action | Out-Null; return $false }
    catch { return $true }
}

'--- Script-level policy surface ---'
$scriptParameterNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
Check 'TargetVersion parameter removed' ($scriptParameterNames -contains 'TargetVersion') 'False'
Check 'ConfigPath parameter removed'    ($scriptParameterNames -contains 'ConfigPath')    'False'
Check 'Install parameter remains'       ($scriptParameterNames -contains 'Install')       'True'
Check 'Recover parameter exposed'       ($scriptParameterNames -contains 'Recover')       'True'
Check 'stale EM removal switch exposed' ($scriptParameterNames -contains 'RemoveStaleEnterpriseManagerRecord') 'True'
# A leftover registry key alone must never count as an installed Enterprise Manager.
$scriptText = Get-Content -LiteralPath $script:Path -Raw
Check 'EM needs service or files'       ($scriptText -match 'emServices\.Count -gt 0 -or \$emPaths\.Count -gt 0') 'True'
Check 'stale EM key is not a product'   ($scriptText -match 'StaleEnterpriseManagerKey = \$emKey') 'True'
Check 'EM removal needs proven stale'   ($scriptText -match 'if \(-not \$script:StaleEnterpriseManagerKey\)') 'True'
$workRootParameter = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'WorkRoot' })[0]
Check 'WorkRoot default is C:\ProgramData\VeeamPgUpdate' $workRootParameter.DefaultValue.Value 'C:\ProgramData\VeeamPgUpdate'
$legacyFunction = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-TrustedLegacyRecoveryMarker' }, $true))[0]
$legacyDefault = @($legacyFunction.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'LegacyWorkRoot' })[0].DefaultValue.Value
Check 'former default checked is C:\temp\VeeamPgUpdate' $legacyDefault 'C:\temp\VeeamPgUpdate'
Check 'script no longer creates C:\temp' ((Get-Content -LiteralPath $script:Path -Raw) -match "-ine 'C:\\temp'") 'False'
$functionNames = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
Check 'Merge-Config function removed' ($functionNames -contains 'Merge-Config') 'False'

$invokedCommands = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst]
}, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
$forcedVeeamWorkStops = @($invokedCommands | Where-Object {
    $_ -match '^Stop-(VBR|VBO).*(Backup|Restore|Job|Policy|Copy)'
})
Check 'never invokes a Veeam job/session stop cmdlet' $forcedVeeamWorkStops.Count 0
$commandParameters = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandParameterAst]
}, $true) | ForEach-Object { $_.ParameterName })
Check 'never requests ForceStopSessions' (@($commandParameters | Where-Object { $_ -eq 'ForceStopSessions' }).Count) 0
# Stop-Process is allowed in exactly one place: closing an open Veeam console,
# which is a client only. Nothing else, and never an Explorer, is ever killed.
$stopProcessCalls = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Stop-Process'
}, $true))
$stopProcessOwners = @($stopProcessCalls | ForEach-Object {
    $parent = $_.Parent
    while ($parent -and -not ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $parent = $parent.Parent }
    if ($parent) { $parent.Name } else { '<script body>' }
})
Check 'Stop-Process appears exactly once'        $stopProcessCalls.Count 1
Check 'Stop-Process only closes Veeam consoles'  (@($stopProcessOwners | Where-Object { $_ -ne 'Close-VeeamConsoleProcesses' }).Count) 0
$forcedServiceStops = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq 'Stop-Service' -and
    @($node.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Force' }).Count -gt 0
}, $true))
Check 'never force-stops a Windows service' $forcedServiceStops.Count 0
$scriptText = Get-Content -LiteralPath $script:Path -Raw
Check 'script never discovers external config JSON' ($scriptText -match '(?i)(?:config\.json|VeeamPostgresUpdate\.config)') 'False'
Check 'unsafe WorkRoot is rejected before log directory creation' ($scriptText.IndexOf("Complete-Run `$EXIT.PREFLIGHT 'WORKROOT_UNSAFE'") -lt $scriptText.IndexOf('New-Item -ItemType Directory -Path $script:LogDir')) 'True'
Check 'result JSON requires a protected WorkRoot' ($scriptText -match 'if \(\$script:WorkRootProtected\) \{\s*try \{\s*Write-AtomicJson -Path \(Join-Path \$script:LogDir ''last-result\.json''\)') 'True'
Check 'former WorkRoot marker cannot be bypassed' ($scriptText -match "LEGACY_WORKROOT_RECOVERY_REQUIRED") 'True'
Check 'cold copy does not import source ACLs' ($scriptText -match "'/COPYALL'") 'False'
Check 'cold copy captures original DACLs' ($scriptText -match "'datadir-acl\.txt'") 'True'
Check 'cold copy uses data-only copy flags' ($scriptText -match "'/COPY:DAT'") 'True'
# shutdown.exe may appear in exactly one place: the delayed restart that -Reboot books
# after a fully successful update.
$shutdownOwners = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -match 'shutdown\.exe' }, $true) | ForEach-Object {
    $p = $_.Parent
    while ($p -and -not ($p -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $p = $p.Parent }
    if ($p) { $p.Name } else { '<script body>' }
})
Check 'shutdown.exe is used in one place only'   (@($shutdownOwners | Sort-Object -Unique) -join ',') 'Invoke-DelayedReboot'
$delayedRebootCalls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-DelayedReboot' }, $true))
Check 'the restart is booked from one place'     $delayedRebootCalls.Count 1
Check 'the restart is booked only under -Reboot' ($scriptText -match '(?s)if \(\$Reboot\) \{\s+# The restart is booked last.*?\$restart = Invoke-DelayedReboot -DelaySeconds \$RebootDelaySeconds') 'True'
Check 'the restart is booked after the marker is gone' ($scriptText.IndexOf('$restart = Invoke-DelayedReboot') -gt $scriptText.IndexOf("Save-RecoveryState -Stage 'COMPLETE' -InstallerStarted `$true")) 'True'
Check 'reboot delay defaults to 120 seconds'     ($scriptText -match '\[ValidateRange\(30, 3600\)\]\[int\] \$RebootDelaySeconds = 120') 'True'
Check 'no restart keeps the EOL migration action' ($scriptText -match '\$script:Report\.ActionRequired = "\$\(Get-RmmActionForExitCode \$successCode\) -Reboot booked no restart because') 'True'
Check 'exit 8 action still asks for migration'   ((Get-RmmActionForExitCode 8) -match 'migration') 'True'
Check 'audit validates Veeam APIs before idempotent exit' ($scriptText.IndexOf("STEP 6B - Validate Veeam") -lt $scriptText.IndexOf("STEP 8 - Idempotency gate")) 'True'
Check 'tuning SQL is prepared before Veeam services are disabled' ($scriptText.IndexOf("VEEAM_TUNING_PREP_FAILED") -lt $scriptText.IndexOf('$disableFailures = @(Disable-VeeamServiceStartup)')) 'True'
Check 'final PostgreSQL health has emergency result' ($scriptText -match "ESCALATE_NOW 'POST_UPDATE_POSTGRES_UNHEALTHY'") 'True'
Check 'VBR database engine cannot be guessed' ($scriptText -match "'VBR_DB_ENGINE_UNKNOWN'") 'True'
Check 'VBR database fields cannot default silently' ($scriptText -match "'VBR_DB_CONFIG_INCOMPLETE'") 'True'
Check 'VB365 Proxy.xml is required for cache topology' ($scriptText -match "'NO_VB365_PROXY_CONFIG'") 'True'
Check 'shared PostgreSQL databases are excluded' ($scriptText -match "'UNTRACKED_POSTGRES_DATABASES'") 'True'
Check 'post-drain schedule drift is checked' ($scriptText -match "'LAST_CHANCE_SCHEDULE_STATE_CHANGED'") 'True'
Check 'registry/runtime major mismatch fails closed' ($scriptText -match "'PG_REGISTRY_VERSION_MISMATCH'") 'True'
Check 'PostgreSQL service binary is bound to BaseDir' ($scriptText -match "'PG_SERVICE_BINARY_MISMATCH'") 'True'
Check 'WorkRoot cannot overlap PostgreSQL data' ($scriptText -match "'WORKROOT_DATA_OVERLAP'") 'True'
Check 'remaining PostgreSQL clients block service stop' ($scriptText -match "'PG_CLIENTS_STILL_CONNECTED'") 'True'
Check 'client gate occurs before PostgreSQL stop' ($scriptText.IndexOf("'PG_CLIENTS_STILL_CONNECTED'") -lt $scriptText.IndexOf("Stop-Service -Name `$pgSvc.Name")) 'True'
Check 'JOBS_DISABLED rollback does not touch PostgreSQL' ($scriptText -match 'if \(\$script:Stage -eq ''SERVICES_STOPPED'' -and \$script:PgServiceName\)') 'True'
Check 'installer timeout validated before installer boundary' ($scriptText.IndexOf("'BAD_INSTALLER_TIMEOUT'") -lt $scriptText.IndexOf("Save-RecoveryState -Stage 'INSTALLING'")) 'True'
Check 'installer intent is durable before process start' ($scriptText.IndexOf("Save-RecoveryState -Stage 'INSTALLING'") -lt $scriptText.IndexOf('Start-Process -FilePath $installerPath')) 'True'
$startBarrierText = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-Vb365MaintenanceBarrier' }, $true))[0].Extent.Text
Check 'unknown VB365 barrier is never adopted by inferred ID' ($startBarrierText -match 'Vb365MaintenanceSessionId\s*=\s*"\$\(\$candidate') 'False'

'--- ConvertFrom-ServerVersionNum ---'
Check '170011 -> 17.11'   (ConvertFrom-ServerVersionNum 170011).Version 	'17.11'
Check '140024 -> 14.24'   (ConvertFrom-ServerVersionNum 140024).Version 	'14.24'
Check '150019 -> 15.19'   (ConvertFrom-ServerVersionNum 150019).Version 	'15.19'
Check '160015 -> 16.15'   (ConvertFrom-ServerVersionNum 160015).Version 	'16.15'
Check '90624 -> 9.6.24'   (ConvertFrom-ServerVersionNum 90624).Version  	'9.6.24'
Check '90624 branch 9.6'  (ConvertFrom-ServerVersionNum 90624).Branch   	'9.6'
Check '170011 branch 17'  (ConvertFrom-ServerVersionNum 170011).Branch  	'17'

'--- ConvertTo-ServerVersionNum (must round-trip) ---'
Check '17.11 -> 170011'   (ConvertTo-ServerVersionNum '17.11')  170011
Check '14.24 -> 140024'   (ConvertTo-ServerVersionNum '14.24')  140024
Check '15.19 -> 150019'   (ConvertTo-ServerVersionNum '15.19')  150019
Check '16.15 -> 160015'   (ConvertTo-ServerVersionNum '16.15')  160015
Check '9.6.24 -> 90624'   (ConvertTo-ServerVersionNum '9.6.24') 90624

'--- Get-BranchKey ---'
Check '17.11 -> 17'       (Get-BranchKey '17.11')   '17'
Check '9.6.24 -> 9.6'     (Get-BranchKey '9.6.24')  '9.6'

'--- Compare-PgVersion ---'
Check '17.10 < 17.11'     (Compare-PgVersion '17.10' '17.11')  -1
Check '17.11 = 17.11'     (Compare-PgVersion '17.11' '17.11')   0
Check '17.9 < 17.11'      (Compare-PgVersion '17.9'  '17.11')  -1
Check '15.19 > 15.9'      (Compare-PgVersion '15.19' '15.9')    1
Check '16.15 > 16.4'      (Compare-PgVersion '16.15' '16.4')    1

'--- Resolve-LatestPgTarget: latest published minor on the installed branch ---'
$versions = @(
    [pscustomobject]@{ major='17';  latestMinor='11'; supported=$true;  eolDate='2029-11-08' },
    [pscustomobject]@{ major='9.6'; latestMinor='24'; supported=$false; eolDate='2021-11-11' },
    [pscustomobject]@{ major='19';  latestMinor='8';  supported=$true;  eolDate='2031-11-13' },
    [pscustomobject]@{ major='15';  latestMinor='19'; supported=$true;  eolDate='2027-11-11' },
    [pscustomobject]@{ major='14';  latestMinor='24'; supported=$false; eolDate='2026-11-12' }
)
$t = Resolve-LatestPgTarget -Versions $versions -InstalledBranch '15'
Check 'modern branch -> latest minor' $t.Version    '15.19'
Check 'modern branch supported'       $t.Supported  'True'
Check 'irrelevant rows ignored'       $t.EolDate    '2027-11-11'

$t = Resolve-LatestPgTarget -Versions $versions -InstalledBranch '19'
Check 'future branch scales'           $t.Version    '19.8'
Check 'future branch remains supported' $t.Supported 'True'

$t = Resolve-LatestPgTarget -Versions $versions -InstalledBranch '9.6'
Check 'legacy dotted branch'           $t.Version    '9.6.24'

$t = Resolve-LatestPgTarget -Versions $versions -InstalledBranch '14'
Check 'EOL branch resolves final minor' $t.Version    '14.24'
Check 'EOL status is preserved'         $t.Supported  'False'

Check 'missing branch throws' (Throws { Resolve-LatestPgTarget -Versions $versions -InstalledBranch '16' }) 'True'
Check 'malformed latestMinor throws' (Throws {
    Resolve-LatestPgTarget -Versions @([pscustomobject]@{ major='17'; latestMinor='11beta'; supported=$true }) -InstalledBranch '17'
}) 'True'
Check 'missing latestMinor throws' (Throws {
    Resolve-LatestPgTarget -Versions @([pscustomobject]@{ major='17'; supported=$true }) -InstalledBranch '17'
}) 'True'
Check 'duplicate branch throws' (Throws {
    Resolve-LatestPgTarget -Versions @(
        [pscustomobject]@{ major='17'; latestMinor='10'; supported=$true },
        [pscustomobject]@{ major='17'; latestMinor='11'; supported=$true }
    ) -InstalledBranch '17'
}) 'True'

'--- Get-DefaultConfig: the built-in settings ---'
$d = Get-DefaultConfig
Check 'built-in JSON parses'          ($null -ne $d)  'True'
Check 'only current settings remain'  (@($d.PSObject.Properties.Name | Sort-Object) -join ',')  'installerTimeoutMinutes,jobWaitTimeoutMinutes,retentionDays,updateNats'
Check 'NATS updates are on by default' $d.updateNats 'True'
Check 'approvedTargets retired'       (@($d.PSObject.Properties.Name) -contains 'approvedTargets')   'False'
Check 'supportedBranches retired'     (@($d.PSObject.Properties.Name) -contains 'supportedBranches') 'False'
Check 'branchFloors retired'          (@($d.PSObject.Properties.Name) -contains 'branchFloors')       'False'
Check 'TargetVersion config retired'  (@($d.PSObject.Properties.Name) -contains 'TargetVersion')      'False'
Check 'tuning cannot be disabled'     (@($d.PSObject.Properties.Name) -contains 'reapplyTuning')      'False'
Check 'job wait defaults to 12 hours' $d.jobWaitTimeoutMinutes 720
Check 'installer timeout is bounded'  $d.installerTimeoutMinutes 120
Check 'retentionDays 30'              $d.retentionDays      30
Check 'no maintenanceWindow key'      (@($d.PSObject.Properties.Name) -contains 'maintenanceWindow')  'False'
Check 'fresh object every call'       ([object]::ReferenceEquals((Get-DefaultConfig), (Get-DefaultConfig)))  'False'

Check 'external config example removed' (Test-Path (Join-Path (Split-Path $script:Path) 'VeeamPostgresUpdate.config.example.json')) 'False'

'--- RMM exit-code policy ---'
Check 'healthy supported -> 0'              (Get-PolicyExitCode -Eol $false -UpdateAvailable $false -RebootRequired $false) 0
Check 'supported update available -> 5'     (Get-PolicyExitCode -Eol $false -UpdateAvailable $true  -RebootRequired $false) 5
Check 'supported reboot required -> 6'      (Get-PolicyExitCode -Eol $false -UpdateAvailable $false -RebootRequired $true)  6
Check 'EOL current -> 7'                    (Get-PolicyExitCode -Eol $true  -UpdateAvailable $false -RebootRequired $false) 7
Check 'EOL reboot required -> 8'            (Get-PolicyExitCode -Eol $true  -UpdateAvailable $false -RebootRequired $true)  8
Check 'EOL update available -> 9'           (Get-PolicyExitCode -Eol $true  -UpdateAvailable $true  -RebootRequired $false) 9
Check 'reboot wins impossible update combo' (Get-PolicyExitCode -Eol $false -UpdateAvailable $true  -RebootRequired $true)  6
Check 'EOL reboot wins impossible combo'    (Get-PolicyExitCode -Eol $true  -UpdateAvailable $true  -RebootRequired $true)  8
foreach ($code in @(0,5,6,7,8,9,10,11,20,30,40,50)) {
    Check "exit $code has an RMM action" ([string]::IsNullOrWhiteSpace((Get-RmmActionForExitCode $code))) 'False'
}

'--- EnterpriseDB download-page parser ---'
$edbHtml = @'
<table>
  <tr>
    <td>17.110</td><td><a href="https://get.enterprisedb.com/linux/postgresql-17.110.run">Linux x64</a></td><td>-</td><td>-</td>
    <td><a href="https://get.enterprisedb.com/postgresql/postgresql-17.110-windows-x64.exe">Windows x64</a></td>
    <td><a href="https://get.enterprisedb.com/postgresql/postgresql-17.110-windows.exe">Windows x32</a></td>
  </tr>
  <tr data-release="current">
    <td> 17.11 </td>
    <td><a href="https://get.enterprisedb.com/linux/postgresql-17.11.run">Linux x64</a></td>
    <td><a href="https://get.enterprisedb.com/linux/postgresql-17.11-x86.run">Linux x32</a></td>
    <td><a href="https://get.enterprisedb.com/macos/postgresql-17.11.dmg">macOS</a></td>
    <td><a class="download" href="https://get.enterprisedb.com/postgresql/postgresql-17.11-windows-x64.exe?source=page&amp;arch=x64">Windows x64</a></td>
    <td><a href="https://get.enterprisedb.com/postgresql/postgresql-17.11-windows.exe">Windows x32</a></td>
  </tr>
</table>
'@
$edbLink = Resolve-PgInstallerLinkFromHtml -Html $edbHtml -Version '17.11'
Check 'selects exact EDB version row' ($edbLink -match 'postgresql-17\.11-windows-x64\.exe') 'True'
Check 'selects Windows x64, not x32'  ($edbLink -match 'windows\.exe') 'False'
Check 'HTML-decodes published URL'    ($edbLink -match '\?source=page&arch=x64$') 'True'
Check 'version absent returns null'   ($null -eq (Resolve-PgInstallerLinkFromHtml -Html $edbHtml -Version '16.99')) 'True'

$duplicateEdbHtml = $edbHtml + $edbHtml
Check 'duplicate exact EDB rows throw' (Throws { Resolve-PgInstallerLinkFromHtml -Html $duplicateEdbHtml -Version '17.11' }) 'True'
$badHostHtml = $edbHtml -replace 'https://get\.enterprisedb\.com/postgresql/postgresql-17\.11-windows-x64\.exe\?source=page&amp;arch=x64','https://downloads.evil.invalid/postgresql-17.11.exe'
Check 'unexpected EDB host throws' (Throws { Resolve-PgInstallerLinkFromHtml -Html $badHostHtml -Version '17.11' }) 'True'
$httpHtml = $edbHtml -replace 'https://get\.enterprisedb\.com/postgresql/postgresql-17\.11-windows-x64\.exe\?source=page&amp;arch=x64','http://get.enterprisedb.com/postgresql-17.11.exe'
Check 'non-HTTPS EDB link throws' (Throws { Resolve-PgInstallerLinkFromHtml -Html $httpHtml -Version '17.11' }) 'True'
$relativeHtml = $edbHtml -replace 'https://get\.enterprisedb\.com/postgresql/postgresql-17\.11-windows-x64\.exe\?source=page&amp;arch=x64','/downloads/postgresql-17.11.exe'
Check 'relative EDB link throws' (Throws { Resolve-PgInstallerLinkFromHtml -Html $relativeHtml -Version '17.11' }) 'True'
$missingX64Html = $edbHtml -replace '<a class="download" href="https://get\.enterprisedb\.com/postgresql/postgresql-17\.11-windows-x64\.exe\?source=page&amp;arch=x64">Windows x64</a>','not published'
Check 'missing Windows x64 link throws' (Throws { Resolve-PgInstallerLinkFromHtml -Html $missingX64Html -Version '17.11' }) 'True'

'--- VB365 PostgreSQL connection strings + exact local-host matching ---'
$cs = $null; $csError = ''
try { $cs = ConvertFrom-PgConnectionString 'Host=localhost;Port=5433;Database=VeeamBackup365;Username=postgres;Password=not-used' }
catch { $csError = $_.Exception.Message }
Check 'valid connection string parses' $csError ''
if ($cs) {
    Check 'connection host parsed'        $cs.Host      'localhost'
    Check 'connection port parsed'        $cs.Port      5433
    Check 'connection database parsed'    $cs.Database  'VeeamBackup365'
}

$cs = $null; $csError = ''
try { $cs = ConvertFrom-PgConnectionString 'HOST=127.0.0.1;DATABASE=ControllerDb' }
catch { $csError = $_.Exception.Message }
Check 'case-insensitive connection parses' $csError ''
if ($cs) {
    Check 'connection keys case-insensitive' $cs.Host    '127.0.0.1'
    Check 'connection default port'          $cs.Port    5432
    Check 'connection database with default port' $cs.Database 'ControllerDb'
}
Check 'connection missing host throws' (Throws { ConvertFrom-PgConnectionString 'Port=5432;Database=db' }) 'True'
Check 'connection missing database throws' (Throws { ConvertFrom-PgConnectionString 'Host=localhost;Port=5432' }) 'True'
Check 'connection nonnumeric port throws' (Throws { ConvertFrom-PgConnectionString 'Host=localhost;Port=nope;Database=db' }) 'True'
Check 'connection out-of-range port throws' (Throws { ConvertFrom-PgConnectionString 'Host=localhost;Port=65536;Database=db' }) 'True'
Check 'VB365 cache GUID name accepted' (Test-Vb365CacheDatabaseName 'cache_12345678-1234-1234-1234-1234567890ab') 'True'
Check 'VB365 cache compact GUID accepted' (Test-Vb365CacheDatabaseName 'cache_123456781234123412341234567890ab') 'True'
Check 'VB365 cache non-GUID rejected' (Test-Vb365CacheDatabaseName 'cache_customerdata') 'False'
# Proxy.xml can hold the pattern cache_{0}, which VB365 fills in per repository; it is not a real name.
Check 'VB365 cache pattern accepted'     (Test-Vb365CacheDatabaseTemplate 'cache_{0}') 'True'
Check 'VB365 upper-case pattern rejected' (Test-Vb365CacheDatabaseTemplate 'CACHE_{0}') 'False'
Check 'VB365 cache upper-hex GUID accepted' (Test-Vb365CacheDatabaseName 'cache_12345678-ABCD-1234-1234-1234567890AB') 'True'
Check 'VB365 cache braced GUID rejected'   (Test-Vb365CacheDatabaseName 'cache_{12345678-1234-1234-1234-1234567890ab}') 'False'
Check 'VB365 cache 0x GUID rejected'       (Test-Vb365CacheDatabaseName 'cache_(12345678-1234-1234-1234-1234567890ab)') 'False'
Check 'VB365 cache upper prefix rejected'  (Test-Vb365CacheDatabaseName 'CACHE_12345678-1234-1234-1234-1234567890ab') 'False'
Check 'VB365 cache GUID + junk rejected'   (Test-Vb365CacheDatabaseName 'cache_12345678-1234-1234-1234-1234567890abX') 'False'
Check 'VB365 cache pattern + junk rejected' (Test-Vb365CacheDatabaseTemplate 'cache_{0}x') 'False'
Check 'VB365 other pattern rejected'     (Test-Vb365CacheDatabaseTemplate 'cache_{1}') 'False'
Check 'VB365 real name is not a pattern' (Test-Vb365CacheDatabaseTemplate 'cache_12345678-1234-1234-1234-1234567890ab') 'False'
Check 'VB365 config DB is not a pattern' (Test-Vb365CacheDatabaseTemplate 'VeeamBackup365') 'False'
Check 'VB365 empty is not a pattern'     (Test-Vb365CacheDatabaseTemplate '') 'False'
Check 'VB365 pattern is not a real name' (Test-Vb365CacheDatabaseName 'cache_{0}') 'False'
try { $tpl = ConvertFrom-PgConnectionString 'Host=localhost;Port=5432;Database=cache_{0};Username=postgres' } catch { $tpl = $null }
Check 'cache pattern connection parses'  ($null -ne $tpl -and $tpl.Database -eq 'cache_{0}' -and $tpl.Port -eq 5432) 'True'

Check 'blank DB host means local'      (Test-LocalDbHost '')          'True'
Check 'localhost exact is local'       (Test-LocalDbHost 'localhost') 'True'
Check 'localhost trailing dot local'   (Test-LocalDbHost 'localhost.') 'True'
Check 'IPv4 loopback is local'         (Test-LocalDbHost '127.0.0.1') 'True'
Check 'IPv6 loopback is local'         (Test-LocalDbHost '[::1]')     'True'
Check 'dot alias is local'             (Test-LocalDbHost '.')         'True'
Check 'machine name exact is local'    (Test-LocalDbHost $env:COMPUTERNAME) 'True'
Check 'machine name case-insensitive'  (Test-LocalDbHost $env:COMPUTERNAME.ToLowerInvariant()) 'True'
Check 'localhost prefix is remote'     (Test-LocalDbHost 'localhost.evil.invalid') 'False'
Check 'machine-name prefix is remote'  (Test-LocalDbHost "$($env:COMPUTERNAME)-remote") 'False'
Check 'machine-name fake FQDN remote'  (Test-LocalDbHost "$($env:COMPUTERNAME).evil.invalid") 'False'
try {
    $localFqdn = ([Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName).TrimEnd('.')
    if ($localFqdn) { Check 'local FQDN exact is local' (Test-LocalDbHost $localFqdn) 'True' }
} catch { '  SKIP  local FQDN could not be resolved' }

'--- PostgreSQL service/working-path binding ---'
$pgBase = 'C:\Program Files\PostgreSQL\17'
Check 'quoted pg_ctl service matches BaseDir' (Test-PgServiceExecutableMatchesBaseDir -PathName '"C:\Program Files\PostgreSQL\17\bin\pg_ctl.exe" runservice -N postgresql-x64-17' -BaseDir $pgBase) 'True'
Check 'unquoted pg_ctl service matches BaseDir' (Test-PgServiceExecutableMatchesBaseDir -PathName 'C:\Program Files\PostgreSQL\17\bin\pg_ctl.exe runservice' -BaseDir $pgBase) 'True'
Check 'postgres service binary matches BaseDir' (Test-PgServiceExecutableMatchesBaseDir -PathName '"C:\Program Files\PostgreSQL\17\bin\postgres.exe" -D data' -BaseDir $pgBase) 'True'
Check 'different major service binary rejected' (Test-PgServiceExecutableMatchesBaseDir -PathName '"C:\Program Files\PostgreSQL\16\bin\pg_ctl.exe" runservice' -BaseDir $pgBase) 'False'
Check 'wrapper service binary rejected' (Test-PgServiceExecutableMatchesBaseDir -PathName '"C:\Vendor\wrapper.exe" run' -BaseDir $pgBase) 'False'
Check 'same paths overlap' (Test-PathTreeOverlap 'C:\PG\data' 'C:\PG\data') 'True'
Check 'WorkRoot within DataDir overlaps' (Test-PathTreeOverlap 'C:\PG\data\recovery' 'C:\PG\data') 'True'
Check 'DataDir within WorkRoot overlaps' (Test-PathTreeOverlap 'C:\Recovery' 'C:\Recovery\pgdata') 'True'
Check 'sibling path trees do not overlap' (Test-PathTreeOverlap 'C:\Recovery' 'C:\PG\data') 'False'
Check 'prefix-only paths do not overlap' (Test-PathTreeOverlap 'C:\PG\data2' 'C:\PG\data') 'False'

'--- Protect-Folder + Test-TrustedOwner (needs an elevated prompt) ---'
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    $tmp = Join-Path $env:TEMP "vpgu-acl-test-$PID"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        Check 'Protect-Folder succeeds'   (Protect-Folder $tmp)  'True'
        $acl = Get-Acl -LiteralPath $tmp
        $sids = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
        Check 'only SYSTEM + Admins'      ($sids -join ',')  'S-1-5-18,S-1-5-32-544'
        Check 'inheritance blocked'       $acl.AreAccessRulesProtected  'True'
        Check 'owner is Administrators'   $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value  'S-1-5-32-544'
        Check 'protected folder trusted'  (Test-TrustedOwner $tmp)  'True'
        Check 'missing path not trusted'  (Test-TrustedOwner (Join-Path $tmp 'nope.json'))  'False'
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    '--- Initialize-WorkRoot: only ever take charge of our own folder ---'
    $base = "C:\vpgu-wr-test-$PID"
    if (Test-Path -LiteralPath $base) { throw "WorkRoot test parent already exists: $base" }
    if (-not (New-ProtectedDirectory $base)) { throw "Could not atomically create WorkRoot test parent: $base" }
    try {
        # 1. Brand new folder -> ours, locked, sentinel dropped
        $new = Join-Path $base 'new'
        $r = Initialize-WorkRoot $new
        Check 'new folder: ours'              $r.IsOurs     'True'
        Check 'new folder: locked'            $r.Protected  'True'
        Check 'new folder: sentinel written'  (Test-Path (Join-Path $new '.veeam-pg-updater'))  'True'
        Check 'new folder: exact protected ACL' (Test-ProtectedFolderAcl $new) 'True'
        Check 'new folder: trusted sentinel'  (Test-WorkRootSentinel $new) 'True'
        Check 'new folder: no reparses'        (Test-PathTreeHasReparsePoint -Path $new -IncludeDescendants) 'False'

        # 2. Second run on the same folder -> still ours (sentinel)
        Add-Content -LiteralPath (Join-Path $new 'something.log') -Value 'x'
        Check 'rerun with contents: ours'     (Initialize-WorkRoot $new).IsOurs  'True'

        # 3. Existing empty folders must already have the exact protected ACL.
        $inheritedEmpty = Join-Path $base 'inherited-empty'; New-Item -ItemType Directory $inheritedEmpty | Out-Null
        Check 'empty inherited folder: rejected' (Initialize-WorkRoot $inheritedEmpty).Protected 'False'
        Check 'empty inherited folder: no sentinel' (Test-Path (Join-Path $inheritedEmpty '.veeam-pg-updater')) 'False'

        $empty = Join-Path $base 'empty'; New-Item -ItemType Directory $empty | Out-Null
        Protect-Folder $empty | Out-Null
        Check 'empty existing: ours'          (Initialize-WorkRoot $empty).IsOurs  'True'

        # 4. THE DANGEROUS CASE: someone else's folder with files in it.
        #    Must NOT be claimed, and its permissions must be left exactly as they were.
        $foreign = Join-Path $base 'foreign'; New-Item -ItemType Directory $foreign | Out-Null
        Set-Content -LiteralPath (Join-Path $foreign 'their-data.txt') -Value 'do not touch'
        $sddlBefore = (Get-Acl -LiteralPath $foreign).Sddl
        $r = Initialize-WorkRoot $foreign
        Check 'foreign folder: NOT ours'      $r.IsOurs     'False'
        Check 'foreign folder: NOT locked'    $r.Protected  'False'
        Check 'foreign folder: ACL untouched' ((Get-Acl -LiteralPath $foreign).Sddl -eq $sddlBefore)  'True'
        Check 'foreign folder: no sentinel'   (Test-Path (Join-Path $foreign '.veeam-pg-updater'))  'False'
        Check 'foreign folder: says why'      ($r.Reason -match 'lacks the protected ACL and trusted sentinel')  'True'

        # A marker filename is not authority. Its content/type and the directory
        # ACL must all be exactly what the script creates.
        $forged = Join-Path $base 'forged'; New-Item -ItemType Directory $forged | Out-Null
        Protect-Folder $forged | Out-Null
        Set-Content -LiteralPath (Join-Path $forged '.veeam-pg-updater') -Value 'forged'
        $forgedSddl = (Get-Acl -LiteralPath $forged).Sddl
        $r = Initialize-WorkRoot $forged
        Check 'forged sentinel: rejected'      $r.Protected 'False'
        Check 'forged sentinel: ACL untouched' ((Get-Acl -LiteralPath $forged).Sddl -eq $forgedSddl) 'True'

        $sentinelDir = Join-Path $base 'sentinel-directory'; New-Item -ItemType Directory $sentinelDir | Out-Null
        Protect-Folder $sentinelDir | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $sentinelDir '.veeam-pg-updater') | Out-Null
        Check 'directory sentinel: rejected'  (Initialize-WorkRoot $sentinelDir).Protected 'False'

        $unsafeParent = Join-Path $base 'generic-all-parent'; New-Item -ItemType Directory $unsafeParent | Out-Null
        $unsafeAcl = New-Object System.Security.AccessControl.DirectorySecurity
        $unsafeAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;GA;;;WD)')
        Set-Acl -LiteralPath $unsafeParent -AclObject $unsafeAcl
        Check 'parent GenericAll is unsafe' (Test-SafeWorkRootParent $unsafeParent) 'False'

        $stateAclFile = Join-Path $base 'state-acl-test.json'; Set-Content -LiteralPath $stateAclFile -Value '{}'
        Check 'protected state file is trusted' (Test-RegularTrustedFile $stateAclFile) 'True'
        $stateAcl = Get-Acl -LiteralPath $stateAclFile
        $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
        $stateAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($everyone, 'Write', 'Allow')))
        Set-Acl -LiteralPath $stateAclFile -AclObject $stateAcl
        Check 'writable state file is untrusted' (Test-RegularTrustedFile $stateAclFile) 'False'

        $legacyFixture = Join-Path $base 'legacy-root'
        Check 'legacy fixture initializes' (Initialize-WorkRoot $legacyFixture).Protected 'True'
        $legacyFixtureMarker = Join-Path $legacyFixture 'CHANGES-IN-PROGRESS.marker'
        Set-Content -LiteralPath $legacyFixtureMarker -Value '{"SchemaVersion":1}' -Encoding UTF8
        Check 'trusted legacy marker is detected' (Get-TrustedLegacyRecoveryMarker -CurrentWorkRoot $new -LegacyWorkRoot $legacyFixture) $legacyFixtureMarker
        Check 'current root is never legacy' ($null -eq (Get-TrustedLegacyRecoveryMarker -CurrentWorkRoot $legacyFixture -LegacyWorkRoot $legacyFixture)) 'True'

        $completedRunId = '20260917-010203-004-2468'
        $completedRun = Join-Path $base $completedRunId; New-Item -ItemType Directory $completedRun | Out-Null
        $completedState = [ordered]@{ SchemaVersion=1; RunId=$completedRunId; RunDir=$completedRun; Stage='COMPLETE'; LogPath='' }
        Write-AtomicJson -Path (Join-Path $completedRun 'recovery-state.json') -InputObject $completedState
        Check 'completed manifest binds to exact run' ($null -ne (Get-ValidatedCompletedRunManifest $completedRun)) 'True'
        $copiedRun = Join-Path $base '20260917-010203-004-2469'; New-Item -ItemType Directory $copiedRun | Out-Null
        Write-AtomicJson -Path (Join-Path $copiedRun 'recovery-state.json') -InputObject $completedState
        Check 'copied COMPLETE manifest is rejected' ($null -eq (Get-ValidatedCompletedRunManifest $copiedRun)) 'True'
        $natsRunId = '20260917-010203-004-2470'
        $natsCompleted = Join-Path $base $natsRunId; New-Item -ItemType Directory $natsCompleted | Out-Null
        Write-AtomicJson -Path (Join-Path $natsCompleted 'recovery-state.json') -InputObject ([ordered]@{ SchemaVersion=2; RunId=$natsRunId; RunDir=$natsCompleted; Stage='COMPLETE'; LogPath=''; Change='NATS' })
        Check 'a completed NATS run can be purged' ($null -ne (Get-ValidatedCompletedRunManifest $natsCompleted)) 'True'

        # A previously managed root becomes unsafe if any child is a junction.
        $junctionRoot = Join-Path $base 'junction-root'
        Check 'junction fixture initializes' (Initialize-WorkRoot $junctionRoot).Protected 'True'
        $junctionTarget = Join-Path $base 'junction-target'; New-Item -ItemType Directory $junctionTarget | Out-Null
        $canary = Join-Path $junctionTarget 'outside-canary.txt'; Set-Content -LiteralPath $canary -Value 'untouched'
        $junctionPath = Join-Path $junctionRoot 'logs'
        $junctionCreated = $false
        try {
            New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget -ErrorAction Stop | Out-Null
            $junctionCreated = $true
            Check 'descendant junction: detected' (Test-PathTreeHasReparsePoint -Path $junctionRoot -IncludeDescendants) 'True'
            Check 'descendant junction: WorkRoot rejected' (Initialize-WorkRoot $junctionRoot).Protected 'False'
            Check 'descendant junction: target untouched' (Get-Content -LiteralPath $canary -Raw).Trim() 'untouched'
        } catch {
            '  SKIP  junction test could not create an NTFS junction'
        } finally {
            if ($junctionCreated -and (Test-Path -LiteralPath $junctionPath)) { [IO.Directory]::Delete($junctionPath) }
        }

        # Process-level check: an unsafe audit fails before creating logs/results.
        $foreignHash = (Get-FileHash -LiteralPath (Join-Path $foreign 'their-data.txt') -Algorithm SHA256).Hash
        $foreignSddl = (Get-Acl -LiteralPath $foreign).Sddl
        $childOutput = (& 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoLogo -NoProfile -File $script:Path -WorkRoot $foreign 2>&1 | Out-String)
        $childExit = $LASTEXITCODE
        Check 'unsafe root: exits 20'           $childExit 20
        Check 'unsafe root: reports issue'      ($childOutput -match 'WORKROOT_UNSAFE') 'True'
        Check 'unsafe root: no logs directory'  (Test-Path (Join-Path $foreign 'logs')) 'False'
        Check 'unsafe root: no result JSON'     (Test-Path (Join-Path $foreign 'last-result.json')) 'False'
        Check 'unsafe root: content untouched'  (Get-FileHash -LiteralPath (Join-Path $foreign 'their-data.txt') -Algorithm SHA256).Hash $foreignHash
        Check 'unsafe root: ACL untouched'      ((Get-Acl -LiteralPath $foreign).Sddl -eq $foreignSddl) 'True'

        # 5. Drive root -> never ours. Reads only; C:\ always exists, so nothing is created.
        $r = Initialize-WorkRoot 'C:\'
        Check 'drive root: NOT ours'          $r.IsOurs  'False'
        Check 'drive root: says why'          ($r.Reason -match 'root of a drive')  'True'
    } finally {
        Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    '  SKIP  not elevated - run from an elevated prompt to test the folder lock'
}

'--- Broad, round-trippable Veeam job-family registry ---'
$allJobFamilies = @(Get-VeeamJobFamilyDefinitions -Vbr $true -Vb365 $true)
$expectedFamilies = @(
    'VBRAgent','VBRAgentCopy','VBRBackupCopy','VBRTape','VBRSureBackup',
    'VBRApplication','VBRPlugin','VBRStandalone','VBRProtection','VBRCatalystCopy','VBRStorageCopy',
    'VBRCDP','VBRvCDReplica','VBRUnstructured','VBRUnstructuredCopy',
    'VBREntraTenant','VBREntraLogs','VBRConfig','VBRJob','VB365','VB365Copy'
)
Check 'all expected job families registered' (@($expectedFamilies | Where-Object { $allJobFamilies.Family -notcontains $_ }).Count) 0
Check 'job family names are unique'          (@($allJobFamilies.Family | Sort-Object -Unique).Count) $allJobFamilies.Count
Check 'registry has broad coverage'          ($allJobFamilies.Count -ge 20) 'True'
Check 'VBR-only registry excludes VB365'     (@(Get-VeeamJobFamilyDefinitions -Vbr $true -Vb365 $false | Where-Object { $_.Family -like 'VB365*' }).Count) 0
Check 'VB365-only registry has both families' (@(Get-VeeamJobFamilyDefinitions -Vbr $false -Vb365 $true).Family -join ',') 'VB365,VB365Copy'
Check 'all families have getter'             (@($allJobFamilies | Where-Object { -not $_.Get }).Count) 0
Check 'all families have disable path'       (@($allJobFamilies | Where-Object { -not $_.Disable }).Count) 0
Check 'all families have enable path'        (@($allJobFamilies | Where-Object { -not $_.Enable }).Count) 0
Check 'VB365 schedules are required'         (@($allJobFamilies | Where-Object { $_.Family -in @('VB365','VB365Copy') -and $_.Required }).Count) 2
Check 'unknown family lookup throws'         (Throws { Get-VeeamJobFamilyDefinition 'DefinitelyNotAJobFamily' }) 'True'

$flagDef = [pscustomobject]@{ Family='Test'; Enabled=@('IsScheduleEnabled','IsEnabled') }
Check 'enabled flag uses declared property'  (Get-VeeamJobEnabledFlag ([pscustomobject]@{ Name='a'; IsScheduleEnabled=$true }) $flagDef) 'True'
Check 'disabled flag remains false'          (Get-VeeamJobEnabledFlag ([pscustomobject]@{ Name='b'; IsScheduleEnabled=$false }) $flagDef) 'False'
Check 'missing enabled property fails closed' (Throws { Get-VeeamJobEnabledFlag ([pscustomobject]@{ Name='c' }) $flagDef }) 'True'
$policyDef = [pscustomobject]@{ Family='VBRCDP'; Enabled=@('PolicyState') }
Check 'CDP Disabled means disabled'           (Get-VeeamJobEnabledFlag ([pscustomobject]@{ Name='p'; PolicyState='Disabled' }) $policyDef) 'False'
Check 'CDP non-disabled means enabled'        (Get-VeeamJobEnabledFlag ([pscustomobject]@{ Name='p'; PolicyState='Running' }) $policyDef) 'True'
Check 'configuration backup gets stable ID'  (Get-VeeamJobIdentity ([pscustomobject]@{ Name='Configuration Backup' }) 'VBRConfig') 'VBR-CONFIGURATION-BACKUP'
Check 'ordinary job without stable ID throws' (Throws { Get-VeeamJobIdentity ([pscustomobject]@{ Name='No ID' }) 'VBRJob' }) 'True'

# Inventory must prefer a specialised family and de-duplicate the same stable ID
# if the generic API exposes the object too.
& {
    function Get-VeeamJobFamilyDefinitions {
        param([bool]$Vbr,[bool]$Vb365)
        @(
            [pscustomobject]@{ Family='Special'; Get='Get-FakeSpecial'; Disable='Disable-FakeSpecial'; Enable='Enable-FakeSpecial'; Argument='Job'; Transition='Command'; Required=$true; Enabled=@('IsEnabled') },
            [pscustomobject]@{ Family='Generic'; Get='Get-FakeGeneric'; Disable='Disable-FakeGeneric'; Enable='Enable-FakeGeneric'; Argument='Job'; Transition='Command'; Required=$true; Enabled=@('IsEnabled') }
        )
    }
    function Get-FakeSpecial { [CmdletBinding()]param() [pscustomobject]@{ Id='same-id'; Name='special'; IsEnabled=$true } }
    function Get-FakeGeneric { [CmdletBinding()]param() [pscustomobject]@{ Id='same-id'; Name='generic'; IsEnabled=$true } }
    function Disable-FakeSpecial { [CmdletBinding()]param($Job) }
    function Enable-FakeSpecial  { [CmdletBinding()]param($Job) }
    function Disable-FakeGeneric { [CmdletBinding()]param($Job) }
    function Enable-FakeGeneric  { [CmdletBinding()]param($Job) }
    $inventory = @(Get-VeeamManagedJobInventory -Vbr $true -Vb365 $false)
    Check 'inventory de-duplicates cross-family ID' $inventory.Count 1
    Check 'inventory keeps specialised family first' $inventory[0].Family 'Special'
}

& {
    function Get-VeeamJobFamilyDefinitions {
        param([bool]$Vbr,[bool]$Vb365)
        @([pscustomobject]@{ Family='RequiredMissing'; Get='Get-DefinitelyMissingRequired'; Disable='Disable-X'; Enable='Enable-X'; Argument='Job'; Transition='Command'; Required=$true; Enabled=@('IsEnabled') })
    }
    Check 'missing required family getter fails closed' (Throws { Get-VeeamManagedJobInventory -Vbr $true -Vb365 $false }) 'True'
    $exceptionType = ''
    try { Get-VeeamManagedJobInventory -Vbr $true -Vb365 $false | Out-Null } catch { $exceptionType = $_.Exception.GetType().FullName }
    Check 'missing required family is classified unsupported' $exceptionType 'System.NotSupportedException'
}

& {
    function Get-VeeamJobFamilyDefinitions {
        param([bool]$Vbr,[bool]$Vb365)
        @([pscustomobject]@{ Family='HalfInstalled'; Get='Get-FakeHalf'; Disable='Disable-FakeHalf'; Enable='Enable-DefinitelyMissing'; Argument='Job'; Transition='Command'; Required=$false; Enabled=@('IsEnabled') })
    }
    function Get-FakeHalf { [CmdletBinding()]param() @() }
    function Disable-FakeHalf { [CmdletBinding()]param($Job) }
    Check 'available getter without round trip fails closed' (Throws { Get-VeeamManagedJobInventory -Vbr $true -Vb365 $false }) 'True'
    $exceptionType = ''
    try { Get-VeeamManagedJobInventory -Vbr $true -Vb365 $false | Out-Null } catch { $exceptionType = $_.Exception.GetType().FullName }
    Check 'missing transition is classified unsupported' $exceptionType 'System.NotSupportedException'
}

'--- Terminal-state safety and natural job draining ---'
function S($state)  { [pscustomobject]@{ State  = $state } }
function V($status) { [pscustomobject]@{ Status = $status } }

$terminalStates = @('Stopped','Idle','ActionRequired','Success','Succeeded','Warning','Failed','Completed','Complete','Finished','Canceled','Cancelled','NotConfigured','None')
$terminalRows = @($terminalStates | ForEach-Object { S $_ })
Check 'known terminal states are idle' @(Get-ActiveLabelsFromSessions -Sessions $terminalRows -Prefix 'TEST').Count 0
$activeStates = @('Starting','Stopping','Working','Running','Pausing','Resuming','WaitingTape',
                   'WaitingRepository','WaitingSlot','Pending','Postprocessing','DirtyBlocks',
                  'Queued','Updating','Disconnected','InProgress','Initialized','Preparing','Finishing',
                  'Canceling','Failing','Ready','Migrating','ReadyToSwitch','Switching')
$activeRows = @($activeStates | ForEach-Object { S $_ })
Check 'known active states all remain active' @(Get-ActiveLabelsFromSessions -Sessions $activeRows -Prefix 'TEST').Count $activeStates.Count
Check 'unknown session state fails closed' (Throws { Get-ActiveLabelsFromSessions -Sessions @((S 'FutureMysteryState')) -Prefix 'TEST' }) 'True'
Check 'missing state fails closed'         (Throws { Get-ActiveLabelsFromSessions -Sessions @([pscustomobject]@{ Name='no-state' }) -Prefix 'TEST' }) 'True'
$assumed = @(Get-ActiveLabelsFromSessions -Sessions @([pscustomobject]@{ Name='active-only-api' }) -Prefix 'RESTORE' -AssumeReturnedActive)
Check 'active-only API can label stateless result' $assumed[0] 'RESTORE:Active'

& {
    function Get-Process {
        [CmdletBinding()] param([string]$Name)
        @(
            [pscustomobject]@{ ProcessName='Veeam.Backup.Shell'; Id=101 },
            [pscustomobject]@{ ProcessName='Veeam.Archiver.Shell'; Id=102 },
            [pscustomobject]@{ ProcessName='VeeamExplorerForMicrosoftExchange'; Id=103 },
            [pscustomobject]@{ ProcessName='VeeamRmmHelper'; Id=104 }
        )
    }
    $vbrUi = @(Get-BlockingVeeamUiProcesses -Vbr $true -Vb365 $false)
    Check 'VBR console is a shutdown barrier' ($vbrUi.ProcessName -contains 'Veeam.Backup.Shell') 'True'
    Check 'VBR Explorer is a shutdown barrier' ($vbrUi.ProcessName -contains 'VeeamExplorerForMicrosoftExchange') 'True'
    Check 'unrelated Veeam-prefixed process is not a UI barrier' ($vbrUi.ProcessName -contains 'VeeamRmmHelper') 'False'
    $vbUi = @(Get-BlockingVeeamUiProcesses -Vbr $false -Vb365 $true)
    Check 'VB365 console is a shutdown barrier' ($vbUi.ProcessName -contains 'Veeam.Archiver.Shell') 'True'
}

# Fakes read these variables, so each case just sets what the "server" looks like.
$script:ManagedJobInventory = @()
$script:FakeBackupSessions  = @()
$script:FakeBackupThrow     = $false
$script:FakeRestoreSessions = @()
$script:FakeRestoreThrow    = $false
$script:FakeVboSessions     = @()
$script:FakeVboThrow        = $false
$script:FakeVboRestoreSessions = @()
$script:FakeVboRestoreThrow = $false
$script:FakeVboLastRequested = $false
$script:FakeVboRestoreStatus = $null
$script:FakeVboOrganizations = @([pscustomobject]@{ Name='Org A'; Id='11111111-1111-1111-1111-111111111111' })
$script:FakeVboOrganizationThrow = $false
$script:FakeVboOrganizationSyncThrow = $false
$script:FakeVboOrganizationSyncState = [pscustomobject]@{
    CurrentState = $null
    Parts = [pscustomobject]@{ Users=$null; Groups=$null; GroupMembers=$null; Sites=$null; Mailboxes=$null }
}
$script:FakeDiscoveryTypes = @()
$script:FakeDiscoveryThrowType = ''
function Get-VBRBackupSession  { [CmdletBinding()] param() if ($script:FakeBackupThrow)  { throw 'backup sessions unreadable' }; $script:FakeBackupSessions }
function Get-VBRRestoreSession { [CmdletBinding()] param() if ($script:FakeRestoreThrow) { throw 'restore sessions unreadable' }; $script:FakeRestoreSessions }
function Get-VBRSession {
    [CmdletBinding()] param([string]$Type)
    $script:FakeDiscoveryTypes += $Type
    if ($script:FakeDiscoveryThrowType -eq $Type) { throw "discovery type $Type unreadable" }
    if ($Type -eq 'EpAgentDiscovery') { return @((S 'Working')) }
    return @((S 'Stopped'))
}
function Get-VBOJobSession     { [CmdletBinding()] param([switch]$Last) $script:FakeVboLastRequested = $PSBoundParameters.ContainsKey('Last'); if ($script:FakeVboThrow) { throw 'VB365 sessions unreadable' }; $script:FakeVboSessions }
function Get-VBORestoreSession { [CmdletBinding()] param([string]$Status) $script:FakeVboRestoreStatus = $Status; if ($script:FakeVboRestoreThrow) { throw 'VB365 restore sessions unreadable' }; $script:FakeVboRestoreSessions }
function Get-VBOOrganization {
    [CmdletBinding()] param()
    if ($script:FakeVboOrganizationThrow) { throw 'VB365 organizations unreadable' }
    $script:FakeVboOrganizations
}
function Get-VBOOrganizationSynchronizationState {
    [CmdletBinding()] param([Parameter(Mandatory)]$Organization)
    if ($script:FakeVboOrganizationSyncThrow) { throw 'VB365 organization synchronization state unreadable' }
    $script:FakeVboOrganizationSyncState
}
# Prevent installed VBR modules from being auto-loaded by Get-Command during
# unit tests. Production still discovers and invokes these real collectors.
$optionalVbrActivityCommands = @(
    'Get-VBRTapeBackupSession','Get-VBRComputerBackupJobSession','Get-VBREPSession',
    'Get-VBRApplicationBackupJobSession','Get-VBRPluginBackupSession','Get-VBRPluginRestoreSession',
    'Get-VBRSureBackupSession','Get-VBRUnstructuredBackupFLRSession','Get-VBRADForestRestoreSession',
    'Get-VBRAmazonRestoreSession','Get-VBRAzureRestoreSession','Get-VBRAzureApplianceSession',
    'Get-VBRCloudTapeRestoreSession','Get-VBREntraIDTenantRestoreSession','Get-VBRGoogleCloudRestoreSession',
    'Get-VBRExchangeItemRestoreSession','Get-VBRSharePointItemRestoreSession','Get-VBRInstantRecovery',
    'Get-VBRNASInstantRecovery','Get-VBRFCDInstantRecoverySession','Get-VBRPublishedBackupContentSession',
    'Get-VBRPublishedBackupDiskSession','Get-VBRAzureInstantRecovery','Get-VBRVirtualMachineStartSession',
    'Get-VBRTestQuickMigrationSession','Get-VBRInstantRecoveryMigration','Get-VBRNASInstantRecoveryMigration',
    'Get-VEADRestoreSession','Get-VEHANARestoreSession','Get-VEMDBRestoreSession','Get-VEODRestoreSession',
    'Get-VEORRestoreSession','Get-VEORRMANRestoreSession','Get-VEPSQLRestoreSession',
    'Get-VESQLPluginRestoreSession','Get-VESQLRDSRestoreSession','Get-VESQLRestoreSession',
    'Get-VBRCopyBackupSession','Get-VBRMoveBackupSession'
)
foreach ($commandName in $optionalVbrActivityCommands) {
    Set-Item -Path "Function:\$commandName" -Value { [CmdletBinding()] param() @() }
}
# Keep unit tests hermetic on machines that happen to have VB365 Explorer modules
# installed but no live controller connection.
function Get-VBODataRetrievalSession        { [CmdletBinding()] param() @() }
function Get-VBODataManagementSession       { [CmdletBinding()] param() @() }
function Get-VBORepositorySynchronizeSession{ [CmdletBinding()] param() @() }
function Get-VBORepositoryUpgradeSession    { [CmdletBinding()] param() @() }
function Get-VBOExchangeItemRestoreSession  { [CmdletBinding()] param() @() }
function Get-VBOSharePointItemRestoreSession{ [CmdletBinding()] param() @() }
function Get-VBOTeamsItemRestoreSession     { [CmdletBinding()] param() @() }

$script:FakeBackupSessions = @((S 'Stopped'), (S 'Idle'), (S 'ActionRequired'))
Check 'VBR quiescent sessions do not block maintenance' @(Get-ActiveVeeamWork -Vbr $true -Vb365 $false).Count 0

$script:FakeBackupSessions = @((S 'Stopped'), (S 'Working'))
$w = @(Get-ActiveVeeamWork -Vbr $true -Vb365 $false)
Check 'VBR one working -> 1'                 $w.Count 1
Check 'VBR label names family and state'     $w[0] 'VBR:Backup:Working'

$script:FakeBackupSessions = @((S 'Stopped'))
$script:FakeRestoreSessions = @((S 'Working'))
$w = @(Get-ActiveVeeamWork -Vbr $true -Vb365 $false)
Check 'VBR restore activity is included'     ($w -contains 'VBR:Restore:Working') 'True'

$script:FakeBackupThrow = $true
Check 'unreadable VBR sessions THROW'        (Throws { Get-ActiveVeeamWork -Vbr $true -Vb365 $false }) 'True'
$script:FakeBackupThrow = $false
$script:FakeRestoreThrow = $true
Check 'unreadable VBR restores THROW'        (Throws { Get-ActiveVeeamWork -Vbr $true -Vb365 $false }) 'True'
$script:FakeRestoreThrow = $false
$script:FakeBackupSessions = @(); $script:FakeRestoreSessions = @()

$script:ManagedJobInventory = @([pscustomobject]@{
    Family='VBRProtection'; Id='protection-1'; Name='Protection group'; Enabled=$true;
    Object=[pscustomobject]@{ Name='Protection group' }
})
$script:FakeDiscoveryTypes = @()
$protectionWork = @(Get-ActiveVeeamWork -Vbr $true -Vb365 $false)
Check 'protection-group discovery/deployment is observed' ($protectionWork -contains 'VBR:ProtectionDiscovery:Working') 'True'
Check 'current protection discovery type queried' ($script:FakeDiscoveryTypes -contains 'EpAgentDiscovery') 'True'
Check 'legacy protection discovery type queried' ($script:FakeDiscoveryTypes -contains 'EpAgentDiscoveryObsolete') 'True'
$script:FakeDiscoveryThrowType = 'EpAgentDiscoveryObsolete'
Check 'unreadable protection discovery fails closed' (Throws { Get-ActiveVeeamWork -Vbr $true -Vb365 $false }) 'True'
$script:FakeDiscoveryThrowType = ''
$script:ManagedJobInventory = @()

$script:ManagedJobInventory = @([pscustomobject]@{
    Family='VBRJob'; Id='running-flag'; Name='running'; Enabled=$true;
    Object=[pscustomobject]@{ IsRunning=$true }
})
$script:FakeVbrJobIsRunning = $true
function Get-VBRJob { [CmdletBinding()] param() [pscustomobject]@{ Id='running-flag'; Name='running'; IsRunning=$script:FakeVbrJobIsRunning } }
$w = @(Get-ActiveVeeamWork -Vbr $true -Vb365 $false)
Check 'job IsRunning flag is additional busy signal' ($w -contains 'VBRJob:IsRunning') 'True'
$script:FakeVbrJobIsRunning = $false
$w = @(Get-ActiveVeeamWork -Vbr $true -Vb365 $false)
Check 'stale true IsRunning snapshot does not block forever' ($w -contains 'VBRJob:IsRunning') 'False'
$script:ManagedJobInventory[0].Object.IsRunning = $false
$script:FakeVbrJobIsRunning = $true
$w = @(Get-ActiveVeeamWork -Vbr $true -Vb365 $false)
Check 'fresh true IsRunning catches a newly-started job' ($w -contains 'VBRJob:IsRunning') 'True'
$script:ManagedJobInventory = @()

$script:FakeVboSessions = @((V 'Success'), (V 'Running'), (V 'Queued'), (V 'Updating'), (V 'Disconnected'), (V 'Stopped'))
$script:FakeVboRestoreSessions = @((V 'Running'))
$w = @(Get-ActiveVeeamWork -Vbr $false -Vb365 $true)
Check 'VB365 active jobs + restore -> 4'     $w.Count 4
Check 'VB365 running label'                  ($w -contains 'VB365:Job:Running') 'True'
Check 'VB365 queued label'                   ($w -contains 'VB365:Job:Queued') 'True'
Check 'VB365 updating label'                 ($w -contains 'VB365:Job:Updating') 'True'
# A VB365 job session that was cut off ends as Disconnected and is never resumed.
# A run waited 12 hours on an old one while the job was not running at all.
Check 'VB365 ended Disconnected job is idle' ($w -contains 'VB365:Job:Disconnected') 'False'
Check 'VB365 restore label'                  ($w -contains 'VB365:Restore:Running') 'True'
Check 'VB365 does not use -Last'             $script:FakeVboLastRequested 'False'
Check 'VB365 requests running restores'      $script:FakeVboRestoreStatus 'Running'

$script:FakeVboSessions = @((V 'Success'), (V 'Stopped'))
$script:FakeVboRestoreSessions = @()
Check 'VB365 terminal sessions -> idle'      @(Get-ActiveVeeamWork -Vbr $false -Vb365 $true).Count 0
$script:FakeVboThrow = $true
Check 'unreadable VB365 sessions THROW'      (Throws { Get-ActiveVeeamWork -Vbr $false -Vb365 $true }) 'True'
$script:FakeVboThrow = $false
$script:FakeVboRestoreThrow = $true
Check 'unreadable VB365 restores THROW'      (Throws { Get-ActiveVeeamWork -Vbr $false -Vb365 $true }) 'True'
$script:FakeVboRestoreThrow = $false

$script:FakeVboOrganizationSyncState = [pscustomobject]@{
    CurrentState = [pscustomobject]@{ Status='Running' }
    Parts = [pscustomobject]@{ Users=$null; Groups=$null; GroupMembers=$null; Sites=$null; Mailboxes=$null }
}
$w = @(Get-ActiveVeeamWork -Vbr $false -Vb365 $true)
Check 'VB365 whole-organization sync is active' ($w -contains 'VB365:OrganizationSync:Org A:All:Running') 'True'

$script:FakeVboOrganizationSyncState = [pscustomobject]@{
    CurrentState = $null
    Parts = [pscustomobject]@{
        Users       = [pscustomobject]@{ CurrentState=[pscustomobject]@{ Status='Queued' } }
        Groups      = [pscustomobject]@{ CurrentState=[pscustomobject]@{ Status='Running' } }
        GroupMembers= [pscustomobject]@{ CurrentState=[pscustomobject]@{ Status='Queued' } }
        Sites       = [pscustomobject]@{ CurrentState=[pscustomobject]@{ Status='Running' } }
        Mailboxes   = [pscustomobject]@{ CurrentState=[pscustomobject]@{ Status='Queued' } }
    }
}
$w = @(Get-ActiveVeeamWork -Vbr $false -Vb365 $true)
Check 'VB365 all five independent sync parts are active' @($w | Where-Object { $_ -like 'VB365:OrganizationSync:Org A:*' }).Count 5
Check 'VB365 Users sync status is labelled' ($w -contains 'VB365:OrganizationSync:Org A:Users:Queued') 'True'
Check 'VB365 Mailboxes sync status is labelled' ($w -contains 'VB365:OrganizationSync:Org A:Mailboxes:Queued') 'True'

$script:FakeVboOrganizationSyncState = [pscustomobject]@{
    CurrentState = $null
    Parts = [pscustomobject]@{
        Users       = [pscustomobject]@{ CurrentState=$null }
        Groups      = [pscustomobject]@{ CurrentState=$null }
        GroupMembers= [pscustomobject]@{ CurrentState=$null }
        Sites       = [pscustomobject]@{ CurrentState=$null }
        Mailboxes   = [pscustomobject]@{ CurrentState=$null }
    }
}
Check 'VB365 quiescent organization sync is idle' @(Get-ActiveVeeamWork -Vbr $false -Vb365 $true).Count 0

# Queued with a later ScheduledTime is VB365's resting state between daily syncs.
# A run waited on All/Users/Groups/GroupMembers/Sites Queued, Mailboxes out of scope.
$later = [datetime]::UtcNow.AddHours(6)
function Q($When) { [pscustomobject]@{ CurrentState = [pscustomobject]@{ Status='Queued'; ScheduledTime=$When } } }
$script:FakeVboOrganizationSyncState = [pscustomobject]@{
    CurrentState = [pscustomobject]@{ Status='Queued'; ScheduledTime=$later }
    Parts = [pscustomobject]@{ Users=(Q $later); Groups=(Q $later); GroupMembers=(Q $later); Sites=(Q $later); Mailboxes=$null }
}
Check 'VB365 sync queued for later is idle'    @(Get-ActiveVeeamWork -Vbr $false -Vb365 $true).Count 0
$script:FakeVboOrganizationSyncState.Parts.Users = (Q ([datetime]::UtcNow.AddMinutes(-5)))
Check 'VB365 overdue queued sync is active'    (@(Get-ActiveVeeamWork -Vbr $false -Vb365 $true) -contains 'VB365:OrganizationSync:Org A:Users:Queued') 'True'
$script:FakeVboOrganizationSyncState.Parts.Users = (Q ([datetime]::UtcNow.AddMinutes(5)))
Check 'VB365 sync due within 15 min is active' (@(Get-ActiveVeeamWork -Vbr $false -Vb365 $true) -contains 'VB365:OrganizationSync:Org A:Users:Queued') 'True'
$script:FakeVboOrganizationSyncState.Parts.Users = (Q $null)
Check 'VB365 queued with no time is active'    (@(Get-ActiveVeeamWork -Vbr $false -Vb365 $true) -contains 'VB365:OrganizationSync:Org A:Users:Queued') 'True'
$script:FakeVboOrganizationSyncState.Parts.Users = [pscustomobject]@{ CurrentState = [pscustomobject]@{ Status='Running'; ScheduledTime=$later } }
$w = @(Get-ActiveVeeamWork -Vbr $false -Vb365 $true)
Check 'VB365 running sync is active whatever the time' ($w -contains 'VB365:OrganizationSync:Org A:Users:Running') 'True'
Check 'VB365 only the running part is listed'  $w.Count 1
$script:FakeVboOrganizationSyncState.CurrentState = [pscustomobject]@{ Status='FutureSyncState'; ScheduledTime=$later }
Check 'unknown sync status with a time still fails closed' (Throws { Get-ActiveVeeamWork -Vbr $false -Vb365 $true }) 'True'

$now = [datetime]::new(2026, 10, 13, 1, 0, 0, [DateTimeKind]::Utc)
function Timing($When, $Start = $null) { Get-Vb365QueuedSyncTiming -CurrentState ([pscustomobject]@{ Status='Queued'; ScheduledTime=$When; StartTime=$Start }) -NowUtc $now }
Check 'due: no ScheduledTime property'         (Get-Vb365QueuedSyncTiming -CurrentState ([pscustomobject]@{ Status='Queued' }) -NowUtc $now) 'Due'
Check 'due: placeholder year 1'                (Timing ([datetime]::MinValue)) 'Due'
Check 'later: UTC time in 6 hours'             (Timing $now.AddHours(6)) 'Later'
Check 'later: offset time in 6 hours'          (Timing ([DateTimeOffset]::new($now.AddHours(6)))) 'Later'
Check 'due: zone-less time 5 min ahead'        (Timing ([datetime]::SpecifyKind($now.AddMinutes(5), [DateTimeKind]::Unspecified))) 'Due'
Check 'later: zone-less time next year'        (Timing ([datetime]::SpecifyKind($now.AddYears(1), [DateTimeKind]::Unspecified))) 'Later'
Check 'due: 30 minutes overdue'                (Timing $now.AddMinutes(-30)) 'Due'
Check 'stuck: 13 days overdue, never started'  (Timing $now.AddDays(-13)) 'Stuck'
Check 'due: overdue but has a start time'      (Timing $now.AddDays(-13) $now.AddMinutes(-2)) 'Due'
Check 'stuck: zone-less 3 days overdue'        (Timing ([datetime]::SpecifyKind($now.AddDays(-3), [DateTimeKind]::Unspecified))) 'Stuck'
Check 'due: zone-less 10 min overdue'          (Timing ([datetime]::SpecifyKind($now.AddMinutes(-10), [DateTimeKind]::Unspecified))) 'Due'

# A VB365 server's sync was booked for 13 days earlier and never started: every part
# Queued, no start time, Mailboxes out of scope. The run waited for it.
$priorReport = Get-Variable -Name Report -Scope Script -ValueOnly -ErrorAction SilentlyContinue
$script:Report = [ordered]@{ Vb365SyncStuck = '' }
Remove-Variable -Name Vb365StuckSyncSeen -Scope Script -ErrorAction SilentlyContinue
$stale = [datetime]::UtcNow.AddDays(-13)
$script:FakeVboOrganizationSyncState = [pscustomobject]@{
    CurrentState = [pscustomobject]@{ Status='Queued'; ScheduledTime=$stale; StartTime=$null }
    Parts = [pscustomobject]@{ Users=(Q $stale); Groups=(Q $stale); GroupMembers=(Q $stale); Sites=(Q $stale); Mailboxes=$null }
}
Check 'stuck sync does not hold the run'       @(Get-ActiveVeeamWork -Vbr $false -Vb365 $true).Count 0
Check 'stuck sync reaches the RMM summary'     ($script:Report.Vb365SyncStuck -match '^Org A \(queued since \d{4}-\d\d-\d\d \d\d:\d\d\)$') 'True'
$null = @(Get-ActiveVeeamWork -Vbr $false -Vb365 $true)
Check 'stuck sync is reported once per run'    @($script:Report.Vb365SyncStuck -split ', ').Count 1
$script:FakeVboOrganizationSyncState.Parts.Users = [pscustomobject]@{ CurrentState = [pscustomobject]@{ Status='Running'; ScheduledTime=$stale; StartTime=[datetime]::UtcNow } }
Check 'a running part still holds the run'     (@(Get-ActiveVeeamWork -Vbr $false -Vb365 $true) -contains 'VB365:OrganizationSync:Org A:Users:Running') 'True'
Remove-Variable -Name Vb365StuckSyncSeen -Scope Script -ErrorAction SilentlyContinue
if ($null -eq $priorReport) { Remove-Variable -Name Report -Scope Script -ErrorAction SilentlyContinue } else { $script:Report = $priorReport }
Check 'report has a Vb365SyncStuck field'      ($scriptText -match "(?m)^\s+Vb365SyncStuck = ''") 'True'

$script:FakeVboOrganizationSyncState = [pscustomobject]@{
    CurrentState = $null
    Parts = [pscustomobject]@{
        Users       = [pscustomobject]@{ CurrentState=$null }
        Groups      = [pscustomobject]@{ CurrentState=$null }
        GroupMembers= [pscustomobject]@{ CurrentState=$null }
        Sites       = [pscustomobject]@{ CurrentState=$null }
        Mailboxes   = [pscustomobject]@{ CurrentState=$null }
    }
}

'--- Ended states are per product ---'
$vboEndedRows = @([pscustomobject]@{ Status='Disconnected' }, [pscustomobject]@{ Status='Running' })
Check 'VB365 Disconnected is ended, Running is not' ((Get-ActiveLabelsFromSessions -Sessions $vboEndedRows -Prefix 'VB365:Job' -EndedStates @('Disconnected')) -join ',') 'VB365:Job:Running'
Check 'without the list Disconnected stays active (VBR)' ((Get-ActiveLabelsFromSessions -Sessions @([pscustomobject]@{ State='Disconnected' }) -Prefix 'VBR:Backup') -join ',') 'VBR:Backup:Disconnected'
Check 'an ended list never hides an unknown state' (Throws { Get-ActiveLabelsFromSessions -Sessions @([pscustomobject]@{ Status='Mystery' }) -Prefix 'VB365:Job' -EndedStates @('Disconnected') }) 'True'
Check 'VB365 job sessions pass Disconnected as ended' ($scriptText -match "Get-SessionsFromGetter 'Get-VBOJobSession'\) -Prefix 'VB365:Job' -EndedStates @\('Disconnected'\)") 'True'
Check 'only data retrieval shares the job statuses' ($scriptText -match "if \(\`$commandName -eq 'Get-VBODataRetrievalSession'\) \{ @\('Disconnected'\) \} else \{ @\(\) \}") 'True'
Check 'VBR getters never pass ended states'   (@([regex]::Matches($scriptText, "-Prefix 'VBR[^']*'[^\r\n]*-EndedStates")).Count) 0

$script:FakeVboOrganizationSyncState.CurrentState = [pscustomobject]@{ Status='FutureSyncState' }
Check 'unknown VB365 organization sync status fails closed' (Throws { Get-ActiveVeeamWork -Vbr $false -Vb365 $true }) 'True'
$script:FakeVboOrganizationSyncState.CurrentState = $null

$script:FakeVboOrganizationSyncThrow = $true
Check 'unreadable VB365 organization sync THROW' (Throws { Get-ActiveVeeamWork -Vbr $false -Vb365 $true }) 'True'
$script:FakeVboOrganizationSyncThrow = $false

$script:FakeVboOrganizationThrow = $true
Check 'unreadable VB365 organization inventory THROW' (Throws { Get-ActiveVeeamWork -Vbr $false -Vb365 $true }) 'True'
$script:FakeVboOrganizationThrow = $false

& {
    function Get-Command {
        [CmdletBinding()] param([Parameter(Position=0)][string]$Name)
        if ($Name -eq 'Get-VBOOrganizationSynchronizationState') { return $null }
        Microsoft.PowerShell.Core\Get-Command -Name $Name -ErrorAction SilentlyContinue
    }
    Check 'missing VB365 organization sync command fails closed' (Throws { Get-ActiveVeeamWork -Vbr $false -Vb365 $true }) 'True'
}

Check 'no products -> idle'                  @(Get-ActiveVeeamWork -Vbr $false -Vb365 $false).Count 0

& {
    function Get-Process {
        [CmdletBinding()] param([string]$Name)
        @([pscustomobject]@{ ProcessName='Veeam.Archiver.Shell'; Id=102 },
          [pscustomobject]@{ ProcessName='VeeamExplorerForMicrosoftExchange'; Id=103 })
    }
    $w = @(Get-ActiveVeeamWork -Vbr $false -Vb365 $true)
    Check 'activity lists an open console'       ($w -contains 'UI:Veeam.Archiver.Shell:PID102') 'True'
    Check 'activity lists an open Explorer'      ($w -contains 'UI:VeeamExplorerForMicrosoftExchange:PID103') 'True'
}

& {
    $script:idlePoll = 0
    function Get-ActiveVeeamWork {
        param([bool]$Vbr,[bool]$Vb365)
        $script:idlePoll++
        if ($script:idlePoll -eq 1) { return @('VBR:Backup:Working') }
        return @()
    }
    function Start-Sleep { param([int]$Seconds) }
    $wait = Wait-VeeamIdle -Vbr $true -Vb365 $false -TimeoutMinutes 1 -PollSeconds 1 -Context 'unit test'
    Check 'wait polls until work finishes naturally' $wait.Idle 'True'
    Check 'wait rechecked activity' $script:idlePoll 2
}

'--- VB365 maintenance ownership and unrestored-job reporting ---'
& {
    $attempt = [datetime]'2026-09-17T01:00:00Z'
    $script:FakeMaintenanceSessions = @(
        [pscustomobject]@{ Id='11111111-1111-1111-1111-111111111111'; State='Running'; StartTime=$attempt.AddMinutes(2); RepositoryIds=@('Repo-B','Repo-A') },
        [pscustomobject]@{ Id='22222222-2222-2222-2222-222222222222'; State='Running'; StartTime=$attempt.AddDays(1); RepositoryIds=@('Repo-A','Repo-B') },
        [pscustomobject]@{ Id='33333333-3333-3333-3333-333333333333'; State='Running'; StartTime=$attempt; RepositoryIds=@('Repo-C') }
    )
    function Get-VBORepositoryMaintenanceSession { [CmdletBinding()] param() $script:FakeMaintenanceSessions }
    $owned = @(Find-Vb365MaintenanceBarrier -AttemptedAt $attempt.ToString('o') -RepositoryIds @('Repo-A','Repo-B'))
    Check 'maintenance ownership matches exact repositories and attempt window' $owned.Count 1
    Check 'maintenance ownership selects the near session' "$($owned[0].Id)" '11111111-1111-1111-1111-111111111111'
    Check 'maintenance ownership rejects a later unrelated session' (@($owned | Where-Object { "$($_.Id)" -eq '22222222-2222-2222-2222-222222222222' }).Count) 0
    Check 'maintenance ownership rejects different repositories' (@($owned | Where-Object { "$($_.Id)" -eq '33333333-3333-3333-3333-333333333333' }).Count) 0
}

'--- VB365 maintenance: wait for Preparing to become Running ---'
# Start-VBORepositoryMaintenanceSession returns while the session is still
# Preparing. A run that checked once gave up on a healthy session after one second.
& {
    $priorStage = Get-Variable -Name Stage -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $priorState = Get-Variable -Name RecoveryState -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $script:Stage = 'JOBS_DISABLED'
    $script:RecoveryState = $null
    $script:MaintSeq = @()
    $script:MaintPolls = 0
    $script:MaintStopped = 0
    function Get-VBORepository { [CmdletBinding()] param() @([pscustomobject]@{ Id='Repo-A' }, [pscustomobject]@{ Id='Repo-B' }) }
    function Start-VBORepositoryMaintenanceSession { [CmdletBinding()] param($Repository, $WaitForSessionsTimeoutMinutes) [pscustomobject]@{ Id='44444444-4444-4444-4444-444444444444'; State='Preparing' } }
    function Get-VBORepositoryMaintenanceSession {
        [CmdletBinding()] param($Id)
        if (-not $PSBoundParameters.ContainsKey('Id')) { return @() }
        $i = $script:MaintPolls; $script:MaintPolls++
        $row = if ($i -lt $script:MaintSeq.Count) { $script:MaintSeq[$i] } else { $script:MaintSeq[-1] }
        return $row
    }
    function Stop-VBORepositoryMaintenanceSession { [CmdletBinding()] param($Id) $script:MaintStopped++ }
    function Start-Sleep { [CmdletBinding()] param([int]$Seconds) }
    function M($State, $Err = $null) { [pscustomobject]@{ Id='44444444-4444-4444-4444-444444444444'; State=$State; ErrorMessage=$Err } }

    $script:MaintPolls = 0; $script:MaintSeq = @((M 'Preparing'), (M 'Preparing'), (M 'Running'))
    Check 'Preparing then Running is accepted'    (Start-Vb365MaintenanceBarrier -TimeoutMinutes 1) '44444444-4444-4444-4444-444444444444'
    Check 'it polled until Running'               $script:MaintPolls 3

    $script:MaintPolls = 0; $script:MaintSeq = @((M 'Running'))
    Check 'already Running is accepted at once'   (Start-Vb365MaintenanceBarrier -TimeoutMinutes 1) '44444444-4444-4444-4444-444444444444'
    Check 'one poll when already Running'         $script:MaintPolls 1

    $script:MaintPolls = 0; $script:MaintSeq = @((M 'Preparing'), (M 'Failed' 'Repository is locked'))
    $err = ''; try { [void](Start-Vb365MaintenanceBarrier -TimeoutMinutes 1) } catch { $err = $_.Exception.Message }
    Check 'a failed session stops the run'        ($err -match 'did not reach Running \(state=Failed\): Repository is locked') 'True'

    $script:MaintPolls = 0; $script:MaintSeq = @((M 'Preparing'))
    $err = ''; try { [void](Start-Vb365MaintenanceBarrier -TimeoutMinutes 1) } catch { $err = $_.Exception.Message }
    Check 'stuck in Preparing gives up in time'   ($err -match 'was still Preparing after 6 minutes') 'True'
    Check 'it gave up after the bounded polls'    $script:MaintPolls 36
    Check 'the barrier itself never stops a session' $script:MaintStopped 0

    if ($null -eq $priorStage) { Remove-Variable -Name Stage -Scope Script -ErrorAction SilentlyContinue } else { $script:Stage = $priorStage }
    $script:RecoveryState = $priorState
    Remove-Variable -Name Vb365MaintenanceSessionId, Vb365MaintenancePending -Scope Script -ErrorAction SilentlyContinue
}

'--- -Reboot books a delayed restart, only when Veeam is quiet ---'
& {
    $script:NativeCalls = New-Object System.Collections.ArrayList
    $script:FakeBusy = @()
    $script:FakeBusyThrow = $false
    $script:FakeShutdownExit = 0
    function Get-ActiveVeeamWork { param([bool]$Vbr, [bool]$Vb365) if ($script:FakeBusyThrow) { throw 'Veeam unreachable' }; @($script:FakeBusy) }
    function Invoke-Native {
        param([string]$FilePath, [string[]]$Arguments)
        $null = $script:NativeCalls.Add(@($FilePath) + @($Arguments))
        [pscustomobject]@{ ExitCode = $script:FakeShutdownExit; StdOut = ''; StdErr = $(if ($script:FakeShutdownExit) { 'A system shutdown has already been scheduled.' } else { '' }) }
    }

    $r = Invoke-DelayedReboot -DelaySeconds 120 -Vbr $true -Vb365 $false
    $call = @($script:NativeCalls[0])
    Check 'quiet server: restart is booked'       $r.Scheduled 'True'
    Check 'it calls shutdown.exe'                 ($call[0] -match 'System32\\shutdown\.exe$') 'True'
    Check 'it restarts, not shuts down'           ($call -contains '/r') 'True'
    Check 'it waits the delay'                    (($call -join ' ') -match '/t 120 ') 'True'
    Check 'it records a planned reason'           (($call -join ' ') -match '/d p:4:1') 'True'
    Check 'it says how to cancel'                 (($call -join ' ') -match 'shutdown /a') 'True'
    Check 'the restart time is about 2 min away'  ([math]::Round(($r.At - (Get-Date)).TotalSeconds / 10) * 10) 120

    $script:NativeCalls.Clear(); $script:FakeBusy = @('VBR:Backup:Nightly:Working')
    $r = Invoke-DelayedReboot -DelaySeconds 120 -Vbr $true -Vb365 $false
    Check 'a running job stops the restart'       $r.Scheduled 'False'
    Check 'and names the job'                     ($r.Reason -match 'VBR:Backup:Nightly:Working') 'True'
    Check 'nothing is booked then'                $script:NativeCalls.Count 0

    $script:FakeBusy = @('UI:Veeam.Exchange.Explorer:PID7')
    Check 'an open Explorer stops the restart'    (Invoke-DelayedReboot -DelaySeconds 120 -Vbr $true -Vb365 $false).Scheduled 'False'

    $script:NativeCalls.Clear(); $script:FakeBusy = @('UI:Veeam.Backup.Shell:PID9', 'UI:Veeam.Archiver.Shell:PID8')
    Check 'an open console does not stop it'      (Invoke-DelayedReboot -DelaySeconds 120 -Vbr $true -Vb365 $true).Scheduled 'True'

    $script:NativeCalls.Clear(); $script:FakeBusy = @(); $script:FakeBusyThrow = $true
    $r = Invoke-DelayedReboot -DelaySeconds 120 -Vbr $true -Vb365 $false
    Check 'a failed activity check stops it'      $r.Scheduled 'False'
    Check 'and says why'                          ($r.Reason -match 'activity check failed: Veeam unreachable') 'True'
    Check 'nothing is booked after a failed check' $script:NativeCalls.Count 0

    $script:FakeBusyThrow = $false; $script:FakeShutdownExit = 1190
    $r = Invoke-DelayedReboot -DelaySeconds 120 -Vbr $true -Vb365 $false
    Check 'a refused booking is not reported as booked' $r.Scheduled 'False'
    Check 'the refusal reason is kept'            ($r.Reason -match 'returned 1190: A system shutdown has already been scheduled') 'True'

    Check 'delay below 30 seconds is refused'     (Throws { Invoke-DelayedReboot -DelaySeconds 5 -Vbr $true -Vb365 $false }) 'True'

    # Application control can stop shutdown.exe from starting at all. That is "not
    # booked", never an unhandled error that pages an operator about a healthy server.
    $script:FakeShutdownExit = 0
    function Invoke-Native { param([string]$FilePath, [string[]]$Arguments) throw 'Program shutdown.exe failed to run: Access is denied' }
    $r = $null
    Check 'a blocked shutdown.exe does not throw'  (Throws { $script:r = Invoke-DelayedReboot -DelaySeconds 120 -Vbr $true -Vb365 $false }) 'False'
    $r = Invoke-DelayedReboot -DelaySeconds 120 -Vbr $true -Vb365 $false
    Check 'a blocked shutdown.exe is not booked'   $r.Scheduled 'False'
    Check 'and says it could not start'           ($r.Reason -match 'could not be started: Program shutdown\.exe failed to run') 'True'
}

$jobRecords = @(
    [pscustomobject]@{ Name='restored'; Restored=$true },
    [pscustomobject]@{ Name='still-disabled'; Restored=$false },
    [pscustomobject]@{ Name='legacy-unknown' }
)
$unrestoredNames = @(Get-UnrestoredJobNames -Records $jobRecords)
Check 'restored job omitted from RMM disabled list' ($unrestoredNames -contains 'restored') 'False'
Check 'unrestored job retained in RMM disabled list' ($unrestoredNames -contains 'still-disabled') 'True'
Check 'legacy record conservatively retained' ($unrestoredNames -contains 'legacy-unknown') 'True'

'--- Exact Windows service startup types (all OS calls mocked) ---'
& {
    $startupValues = @{
        SvcAuto     = [pscustomobject]@{ Start=2; DelayedAutoStart=0 }
        SvcDelayed  = [pscustomobject]@{ Start=2; DelayedAutoStart=1 }
        SvcAutoBare = [pscustomobject]@{ Start=2 }
        SvcManual   = [pscustomobject]@{ Start=3 }
        SvcDisabled = [pscustomobject]@{ Start=4 }
        SvcBad      = [pscustomobject]@{ Start=1 }
    }
    function Get-ItemProperty {
        [CmdletBinding()] param([string]$LiteralPath)
        $name = Split-Path -Leaf $LiteralPath
        if (-not $startupValues.ContainsKey($name)) { throw "missing fake startup state for $name" }
        return $startupValues[$name]
    }

    Check 'startup Automatic'          (Get-ServiceStartupTypeExact 'SvcAuto')     'Automatic'
    Check 'startup delayed Automatic'  (Get-ServiceStartupTypeExact 'SvcDelayed')  'AutomaticDelayedStart'
    Check 'startup Automatic no flag'  (Get-ServiceStartupTypeExact 'SvcAutoBare') 'Automatic'
    Check 'startup Manual'             (Get-ServiceStartupTypeExact 'SvcManual')   'Manual'
    Check 'startup Disabled'           (Get-ServiceStartupTypeExact 'SvcDisabled') 'Disabled'
    Check 'unsupported startup throws' (Throws { Get-ServiceStartupTypeExact 'SvcBad' }) 'True'

    $nativeCalls = New-Object System.Collections.ArrayList
    function Invoke-Native {
        [CmdletBinding()] param([string]$FilePath, [string[]]$Arguments)
        $null = $nativeCalls.Add([pscustomobject]@{ FilePath=$FilePath; Arguments=@($Arguments) })
        return [pscustomobject]@{ ExitCode=0; StdOut=''; StdErr='' }
    }
    Set-ServiceStartupTypeExact -Name 'SvcAuto'     -StartupType Automatic
    Set-ServiceStartupTypeExact -Name 'SvcDelayed'  -StartupType AutomaticDelayedStart
    Set-ServiceStartupTypeExact -Name 'SvcManual'   -StartupType Manual
    Set-ServiceStartupTypeExact -Name 'SvcDisabled' -StartupType Disabled
    Check 'sc automatic mapping' ($nativeCalls[0].Arguments -join '|') 'config|SvcAuto|start=|auto'
    Check 'sc delayed mapping'   ($nativeCalls[1].Arguments -join '|') 'config|SvcDelayed|start=|delayed-auto'
    Check 'sc manual mapping'    ($nativeCalls[2].Arguments -join '|') 'config|SvcManual|start=|demand'
    Check 'sc disabled mapping'  ($nativeCalls[3].Arguments -join '|') 'config|SvcDisabled|start=|disabled'
    Check 'sc.exe exact path'    (Split-Path -Leaf $nativeCalls[0].FilePath) 'sc.exe'
}

'--- Veeam service capture, disable and exact restore (service manager mocked) ---'
& {
    function New-FakeService($Name, $Status, $StartupType, $DisplayName) {
        [pscustomobject]@{ Name=$Name; DisplayName=$DisplayName; Status=$Status; StartupType=$StartupType }
    }
    $serviceRows = @(
        (New-FakeService 'VeeamBackupSvc'                'Running' 'Automatic'             'Veeam Backup Service'),
        (New-FakeService 'VeeamManagementAgentSvc'       'Running' 'AutomaticDelayedStart' 'Veeam Management Agent'),
        (New-FakeService 'VeeamManualSvc'                'Running' 'Manual'                'Veeam Manual Service'),
        (New-FakeService 'VeeamStoppedSvc'               'Stopped' 'Automatic'             'Veeam Initially Stopped'),
        (New-FakeService 'VeeamDisabledSvc'              'Stopped' 'Disabled'              'Veeam Initially Disabled'),
        (New-FakeService 'VeeamDisabledButRunningSvc'    'Running' 'Disabled'              'Veeam Disabled But Running'),
        (New-FakeService 'IndependentRmmSvc'             'Running' 'Automatic'             'Independent RMM Agent')
    )
    $actionLog = New-Object System.Collections.ArrayList

    function Get-Service {
        [CmdletBinding()] param([Parameter(Position=0)][string[]]$Name)
        $found = @()
        foreach ($pattern in @($Name)) {
            $found += @($serviceRows | Where-Object { $_.Name -like $pattern })
        }
        return $found
    }
    function Get-ServiceStartupTypeExact {
        [CmdletBinding()] param([string]$Name)
        $row = @($serviceRows | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
        if (-not $row) { throw "fake service $Name not found" }
        return "$($row.StartupType)"
    }
    function Set-ServiceStartupTypeExact {
        [CmdletBinding()] param([string]$Name, [string]$StartupType)
        $row = @($serviceRows | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
        if (-not $row) { throw "fake service $Name not found" }
        $null = $actionLog.Add("SET:${Name}:$StartupType")
        $row.StartupType = $StartupType
    }
    function Start-Service {
        [CmdletBinding()] param([Parameter(Position=0)][string]$Name)
        $row = @($serviceRows | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
        if (-not $row) { throw "fake service $Name not found" }
        $null = $actionLog.Add("START:$Name")
        $row.Status = 'Running'
    }
    function Stop-Service {
        [CmdletBinding()] param([Parameter(Position=0)][string]$Name, [switch]$Force)
        $row = @($serviceRows | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
        if (-not $row) { throw "fake service $Name not found" }
        $null = $actionLog.Add("STOP:$Name")
        $row.Status = 'Stopped'
    }
    function Start-Sleep { [CmdletBinding()] param([int]$Seconds) }

    $snapshot = @(Get-VeeamServiceState)
    Check 'captures every Veeam* service' $snapshot.Count 6
    Check 'captures stopped Veeam service' (@($snapshot | Where-Object { $_.Name -eq 'VeeamStoppedSvc' -and -not $_.WasRunning }).Count) 1
    Check 'captures management agent' (@($snapshot | Where-Object { $_.Name -eq 'VeeamManagementAgentSvc' }).Count) 1
    Check 'captures delayed-auto exactly' (@($snapshot | Where-Object { $_.Name -eq 'VeeamManagementAgentSvc' }).StartupType) 'AutomaticDelayedStart'
    Check 'does not capture unrelated RMM' (@($snapshot | Where-Object { $_.Name -eq 'IndependentRmmSvc' }).Count) 0

    $snapshotJson = ConvertTo-Json -InputObject @($snapshot) -Depth 3
    $snapshotRoundTrip = $snapshotJson | ConvertFrom-Json
    Check 'service snapshot JSON round-trip count' @($snapshotRoundTrip).Count 6
    Check 'snapshot JSON keeps delayed-auto' (@($snapshotRoundTrip | Where-Object { $_.Name -eq 'VeeamManagementAgentSvc' }).StartupType) 'AutomaticDelayedStart'

    $script:VeeamServices = @($snapshot)
    $actionLog.Clear()
    $disableProblems = @(Disable-VeeamServiceStartup)
    Check 'disable reports no problems' $disableProblems.Count 0
    Check 'all captured services disabled' (@($serviceRows | Where-Object { $_.Name -like 'Veeam*' -and $_.StartupType -eq 'Disabled' }).Count) 6
    Check 'unrelated RMM startup untouched' (@($serviceRows | Where-Object { $_.Name -eq 'IndependentRmmSvc' }).StartupType) 'Automatic'
    Check 'disable never targets unrelated RMM' (@($actionLog | Where-Object { $_ -match 'IndependentRmmSvc' }).Count) 0

    # Model the completed stop phase without calling the real service manager.
    foreach ($row in @($serviceRows | Where-Object { $_.Name -like 'Veeam*' })) { $row.Status = 'Stopped' }
    $actionLog.Clear()
    $restoreProblems = @(Restore-VeeamServiceState)
    Check 'restore reports no problems' $restoreProblems.Count 0

    $firstPhase = @($actionLog | Select-Object -First $snapshot.Count)
    Check 'all startup modes restored before starts' (@($firstPhase | Where-Object { $_ -notlike 'SET:*' }).Count) 0
    Check 'running Automatic restored' (@($serviceRows | Where-Object { $_.Name -eq 'VeeamBackupSvc' }).StartupType) 'Automatic'
    Check 'management delayed-auto restored' (@($serviceRows | Where-Object { $_.Name -eq 'VeeamManagementAgentSvc' }).StartupType) 'AutomaticDelayedStart'
    Check 'running Manual restored' (@($serviceRows | Where-Object { $_.Name -eq 'VeeamManualSvc' }).StartupType) 'Manual'
    Check 'stopped Automatic restored' (@($serviceRows | Where-Object { $_.Name -eq 'VeeamStoppedSvc' }).StartupType) 'Automatic'
    Check 'stopped Disabled restored' (@($serviceRows | Where-Object { $_.Name -eq 'VeeamDisabledSvc' }).StartupType) 'Disabled'
    Check 'running Disabled restored exactly' (@($serviceRows | Where-Object { $_.Name -eq 'VeeamDisabledButRunningSvc' }).StartupType) 'Disabled'
    Check 'previously running service restarted' (@($serviceRows | Where-Object { $_.Name -eq 'VeeamBackupSvc' }).Status) 'Running'
    Check 'management agent restarted' (@($serviceRows | Where-Object { $_.Name -eq 'VeeamManagementAgentSvc' }).Status) 'Running'
    Check 'previously stopped service stays stopped' (@($serviceRows | Where-Object { $_.Name -eq 'VeeamStoppedSvc' }).Status) 'Stopped'
    Check 'disabled-running service restarted' (@($serviceRows | Where-Object { $_.Name -eq 'VeeamDisabledButRunningSvc' }).Status) 'Running'
    Check 'disabled-running uses temporary Manual' ($actionLog -contains 'SET:VeeamDisabledButRunningSvc:Manual') 'True'
    Check 'unrelated RMM remains running' (@($serviceRows | Where-Object { $_.Name -eq 'IndependentRmmSvc' }).Status) 'Running'
    Check 'restore never targets unrelated RMM' (@($actionLog | Where-Object { $_ -match 'IndependentRmmSvc' }).Count) 0

    # A service that was originally stopped may be started by new manual work
    # while the control plane is returning. The production no-stop restoration
    # must restore its startup type without killing that newly-arrived work.
    $stoppedRow = @($serviceRows | Where-Object { $_.Name -eq 'VeeamStoppedSvc' }) | Select-Object -First 1
    $stoppedRow.Status = 'Running'
    $stoppedRow.StartupType = 'Disabled'
    $actionLog.Clear()
    $noStopProblems = @(Restore-VeeamServiceState -AllowStops:$false)
    Check 'no-stop restore reports no problems' $noStopProblems.Count 0
    Check 'no-stop restore never stops newly running service' ($actionLog -contains 'STOP:VeeamStoppedSvc') 'False'
    Check 'no-stop restore leaves newly running service running' $stoppedRow.Status 'Running'
    Check 'no-stop restore still restores startup type' $stoppedRow.StartupType 'Automatic'

    $stoppedRow.Status = 'StartPending'
    $actionLog.Clear()
    $transitionProblems = @(Restore-VeeamServiceState -AllowStops:$false)
    Check 'no-stop restore reports unsettled transition' ($transitionProblems.Count -gt 0) 'True'
    Check 'no-stop restore never stops transitional service' ($actionLog -contains 'STOP:VeeamStoppedSvc') 'False'

    $script:VeeamServices = @()
}

'--- Atomic recovery intent and diagnostic-only post-installer recovery ---'
$recoveryTemp = Join-Path $env:TEMP "vpgu-recovery-test-$PID"
New-Item -ItemType Directory -Path $recoveryTemp -Force | Out-Null
try {
    $atomicPath = Join-Path $recoveryTemp 'atomic.json'
    Write-AtomicJson -Path $atomicPath -InputObject ([ordered]@{ Generation=1; Text='first' })
    $firstAtomic = Get-Content -LiteralPath $atomicPath -Raw | ConvertFrom-Json
    Check 'atomic JSON first write parses' $firstAtomic.Generation 1
    Write-AtomicJson -Path $atomicPath -InputObject ([ordered]@{ Generation=2; Text='replacement' })
    $secondAtomic = Get-Content -LiteralPath $atomicPath -Raw | ConvertFrom-Json
    Check 'atomic JSON replacement parses' $secondAtomic.Generation 2
    Check 'atomic JSON replaces old content' $secondAtomic.Text 'replacement'
    Check 'atomic writer leaves no temp files' @(Get-ChildItem -LiteralPath $recoveryTemp -Filter 'atomic.json.tmp.*' -Force).Count 0

    $script:RunDir = Join-Path $recoveryTemp 'runs\unit-run'
    New-Item -ItemType Directory -Path $script:RunDir -Force | Out-Null
    $script:MarkerFile = Join-Path $recoveryTemp 'CHANGES-IN-PROGRESS.marker'
    $script:Stamp = 'unit-run'
    $script:Stage = 'JOBS_DISABLED'
    $script:RecoveryState = [pscustomobject][ordered]@{
        SchemaVersion=1
        RunId='unit-run'
        RunDir=$script:RunDir
        Stage='JOBS_DISABLED'
        InstallerStarted=$false
        OriginalVersion='15.2'
        TargetVersion='15.19'
    }
    Save-RecoveryState -Stage 'JOBS_DISABLED' -InstallerStarted $false
    $preState = Get-Content -LiteralPath (Join-Path $script:RunDir 'recovery-state.json') -Raw | ConvertFrom-Json
    $preMarker = Get-Content -LiteralPath $script:MarkerFile -Raw | ConvertFrom-Json
    Check 'pre-installer state is durable' $preState.InstallerStarted 'False'
    Check 'marker binds to recovery state file' $preMarker.StateFile (Join-Path $script:RunDir 'recovery-state.json')
    Check 'marker binds to run ID' $preMarker.RunId 'unit-run'

    # This flag must be durable before Start-Process is allowed. Both the full
    # manifest and the small marker must agree that automatic rollback is barred.
    Save-RecoveryState -Stage 'INSTALLING' -InstallerStarted $true
    $installState = Get-Content -LiteralPath (Join-Path $script:RunDir 'recovery-state.json') -Raw | ConvertFrom-Json
    $installMarker = Get-Content -LiteralPath $script:MarkerFile -Raw | ConvertFrom-Json
    Check 'installer-start intent persisted in state' $installState.InstallerStarted 'True'
    Check 'installer-start intent persisted in marker' $installMarker.InstallerStarted 'True'
    Check 'state advances to INSTALLING' $installState.Stage 'INSTALLING'
    Check 'marker advances to INSTALLING' $installMarker.Stage 'INSTALLING'
    Check 'recovery writes leave no temp files' @(Get-ChildItem -LiteralPath $recoveryTemp -Recurse -Filter '*.tmp.*' -Force).Count 0
} finally {
    Remove-Item -LiteralPath $recoveryTemp -Recurse -Force -ErrorAction SilentlyContinue
    $script:RecoveryState = $null
}

& {
    $WorkRoot = Join-Path $env:TEMP "vpgu-recover-diagnostic-$PID"
    $runId = '20260917-010203-004-1234'
    $runPath = [IO.Path]::GetFullPath((Join-Path $WorkRoot "runs\$runId")).TrimEnd('\')
    New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
    Protect-Folder $WorkRoot | Out-Null
    New-Item -ItemType Directory -Path $runPath -Force | Out-Null
    try {
        $statePath = Join-Path $runPath 'recovery-state.json'
        $markerPath = Join-Path $WorkRoot 'CHANGES-IN-PROGRESS.marker'
        $state = [ordered]@{
            SchemaVersion=1; RunId=$runId; RunDir=$runPath; Stage='INSTALLING'; InstallerStarted=$true
            Products='VBR'; OriginalVersion='15.2'; TargetVersion='15.19'
            PgServiceName=''; PsqlPath=''; PgPort=''
        }
        Write-AtomicJson -Path $statePath -InputObject $state
        Write-AtomicJson -Path $markerPath -InputObject ([ordered]@{
            SchemaVersion=1; RunId=$runId; RunDir=$runPath; StateFile=$statePath; Stage='INSTALLING'; InstallerStarted=$true
        })

        $EXIT = @{ ESCALATE=40; ESCALATE_NOW=50 }
        $script:Report = [ordered]@{ RecoveryRunDir=''; VeeamProducts=''; PgInstalled=''; PgTarget=''; JobsLeftDisabled=''; IssueCode=''; ActionRequired='' }
        $script:RecoveryCapture = $null
        $script:RecoveryMutationCount = 0
        function Test-TrustedOwner { param($Path) return $true }
        function Start-Service { $script:RecoveryMutationCount++ }
        function Stop-Service  { $script:RecoveryMutationCount++ }
        function Enable-VeeamJobById { $script:RecoveryMutationCount++ }
        function Complete-Run {
            param([int]$Code,[string]$Outcome,[string]$Detail)
            $script:RecoveryCapture = [pscustomobject]@{ Code=$Code; Outcome=$Outcome; Detail=$Detail }
            throw 'COMPLETE-RUN-TEST-SENTINEL'
        }
        try { Invoke-ExplicitRecovery -MarkerPath $markerPath -Cfg (Get-DefaultConfig) }
        catch { if ($_.Exception.Message -ne 'COMPLETE-RUN-TEST-SENTINEL') { throw } }
        Check 'post-installer recovery exits for operator' $script:RecoveryCapture.Code 40
        Check 'post-installer outcome is diagnostic only' $script:RecoveryCapture.Outcome 'RECOVERY_DIAGNOSTIC_ONLY'
        Check 'post-installer recovery performs no mutation' $script:RecoveryMutationCount 0
        Check 'post-installer marker remains' (Test-Path -LiteralPath $markerPath) 'True'
        Check 'post-installer RMM issue is explicit' $script:Report.IssueCode 'POST_INSTALL_RECOVERY_REQUIRES_OPERATOR'

        $state.RunId = '20260917-010203-004-9999'
        Write-AtomicJson -Path $statePath -InputObject $state
        $script:RecoveryCapture = $null
        try { Invoke-ExplicitRecovery -MarkerPath $markerPath -Cfg (Get-DefaultConfig) }
        catch { if ($_.Exception.Message -ne 'COMPLETE-RUN-TEST-SENTINEL') { throw } }
        Check 'recovery rejects marker/state RunId mismatch' $script:RecoveryCapture.Outcome 'INVALID_RECOVERY_STATE'
        Check 'RunId mismatch performs no mutation' $script:RecoveryMutationCount 0
    } finally {
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

'--- Recovery finishes a run whose installer completed ---'
# Windows PowerShell 5.1 can lose the installer exit code, which stops a good install
# mid-change with Veeam down. -Recover must finish it, but only on proof.
& {
    $WorkRoot = Join-Path $env:TEMP "vpgu-recover-finish-$PID"
    $runId = '20260917-010203-004-1111'
    $runPath = [IO.Path]::GetFullPath((Join-Path $WorkRoot "runs\$runId")).TrimEnd('\')
    New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
    Protect-Folder $WorkRoot | Out-Null
    New-Item -ItemType Directory -Path $runPath -Force | Out-Null
    try {
        $statePath = Join-Path $runPath 'recovery-state.json'
        $markerPath = Join-Path $WorkRoot 'CHANGES-IN-PROGRESS.marker'
        $psqlFake = Join-Path $runPath 'psql.exe'
        Set-Content -LiteralPath $psqlFake -Value 'fake'
        Set-Content -LiteralPath (Join-Path $runPath 'pg-tuning.sql') -Value 'ALTER SYSTEM SET max_connections = 200;'
        # Written in the same shape the script writes them, so PowerShell 5.1 parses
        # the same kind of JSON lists that would otherwise break recovery.
        Write-AtomicJson -Path (Join-Path $runPath 'disabled-jobs.json') -Depth 5 -InputObject @(
            [pscustomobject][ordered]@{ Family='VBRConfig';     Id='c1'; Name='Backup Configuration Job'; WasEnabled=$true; Restored=$false },
            [pscustomobject][ordered]@{ Family='VBRProtection'; Id='p1'; Name='Example Protection Group'; WasEnabled=$true; Restored=$false },
            [pscustomobject][ordered]@{ Family='VBRJob';        Id='j1'; Name='Example Backup Job';       WasEnabled=$true; Restored=$false })
        Write-AtomicJson -Path (Join-Path $runPath 'veeam-service-state.json') -Depth 4 -InputObject @(
            [pscustomobject][ordered]@{ Name='VeeamBackupSvc'; DisplayName='Veeam Backup Service';    Status='Running'; WasRunning=$true; StartupType='AutomaticDelayedStart'; DependsOn=@() },
            [pscustomobject][ordered]@{ Name='VeeamDeploySvc'; DisplayName='Veeam Installer Service'; Status='Running'; WasRunning=$true; StartupType='Automatic'; DependsOn=@() })
        Write-AtomicJson -Path (Join-Path $runPath 'pg-service-state.json') -InputObject ([pscustomobject][ordered]@{
            Name='postgresql-x64-15'; WasRunning=$true; StartupType='Automatic'; PsqlPath=$psqlFake; Port='5432' })

        $EXIT = @{ OK=0; ESCALATE=40; ESCALATE_NOW=50 }
        $script:Report = [ordered]@{ RecoveryRunDir=''; VeeamProducts=''; PgInstalled=''; PgTarget=''; JobsLeftDisabled=''; IssueCode=''; ActionRequired='' }
        function Test-TrustedOwner { param($Path) return $true }
        function Get-Service {
            [CmdletBinding()] param([Parameter(Position=0)][string[]]$Name)
            foreach ($n in @($Name)) {
                foreach ($k in @($script:Svc.Keys | Where-Object { $_ -like $n } | Sort-Object)) { [pscustomobject]@{ Name=$k; Status=$script:Svc[$k] } }
            }
        }
        function Stop-Service  { [CmdletBinding()] param([Parameter(Position=0)][string]$Name) $script:Actions += "STOP:$Name";  $script:Svc[$Name] = 'Stopped' }
        function Start-Service { [CmdletBinding()] param([Parameter(Position=0)][string]$Name) $script:Actions += "START:$Name"; $script:Svc[$Name] = 'Running' }
        function Set-ServiceStartupTypeExact { [CmdletBinding()] param([string]$Name, [string]$StartupType) $script:Actions += "SET:${Name}:$StartupType" }
        function Get-ServiceStartupTypeExact { [CmdletBinding()] param([string]$Name) 'Automatic' }
        function Get-Process { [CmdletBinding()] param([string]$Name) @($script:FakeInstallerProcs) }
        function Start-Sleep { [CmdletBinding()] param([int]$Seconds) }
        function Invoke-Native {
            param([string]$FilePath, [string[]]$Arguments)
            if ($Arguments -contains '-f') { $script:Actions += 'TUNING'; return [pscustomobject]@{ ExitCode=$script:FakeTuningExit; StdOut=''; StdErr='' } }
            return [pscustomobject]@{ ExitCode=0; StdOut="$script:FakePgNum"; StdErr='' }
        }
        function Restore-VeeamServiceState { param([switch]$AllowStops) $script:Actions += "RESTORE:$(@($script:VeeamServices).Count):$(@($script:VeeamServices | ForEach-Object { $_.Name }) -join '+')"; @() }
        function Connect-VeeamModules { param([switch]$Vbr, [switch]$Vb365, [switch]$Quiet, [switch]$Reconnect) @() }
        function Get-VeeamManagedJobInventory { param([bool]$Vbr, [bool]$Vb365) @() }
        function Wait-VeeamIdle { param([bool]$Vbr, [bool]$Vb365, [int]$TimeoutMinutes, [string]$Context, [switch]$CloseConsoles) [pscustomobject]@{ Idle=$true; Labels=@() } }
        function Enable-VeeamJobById { param($Record) $script:Actions += "ENABLE:$($Record.Name)" }
        function Save-DisabledJobState { }
        function Save-RecoveryState { param([string]$Stage, $InstallerStarted) $script:Actions += "SAVE:$Stage" }
        function Remove-RecoveryMarker { $script:Actions += 'MARKER-REMOVED'; $true }
        function Complete-Run {
            param([int]$Code, [string]$Outcome, [string]$Detail)
            $script:RecoveryCapture = [pscustomobject]@{ Code=$Code; Outcome=$Outcome; Detail=$Detail }
            throw 'COMPLETE-RUN-TEST-SENTINEL'
        }
        function Invoke-FinishScenario {
            param([string]$Stage = 'INSTALLING', [int]$PgNum = 150019, [string]$BackupSvcStatus = 'Stopped', $Installer = @(), [int]$TuningExit = 0)
            $script:Svc = @{ 'postgresql-x64-15'='Running'; 'VeeamBackupSvc'=$BackupSvcStatus; 'VeeamDeploySvc'='Stopped' }
            $script:FakePgNum = $PgNum; $script:FakeInstallerProcs = @($Installer); $script:FakeTuningExit = $TuningExit
            $script:Actions = @(); $script:RecoveryCapture = $null
            $script:Report.IssueCode = ''; $script:Report.ActionRequired = ''; $script:Report.PgInstalled = ''
            Write-AtomicJson -Path $statePath -InputObject ([ordered]@{
                SchemaVersion=1; RunId=$runId; RunDir=$runPath; Stage=$Stage; InstallerStarted=$true
                Products='VBR'; OriginalVersion='15.2'; TargetVersion='15.19'
                PgServiceName='postgresql-x64-15'; PsqlPath=$psqlFake; PgPort='5432' })
            Write-AtomicJson -Path $markerPath -InputObject ([ordered]@{
                SchemaVersion=1; RunId=$runId; RunDir=$runPath; StateFile=$statePath; Stage=$Stage; InstallerStarted=$true })
            try { Invoke-ExplicitRecovery -MarkerPath $markerPath -Cfg (Get-DefaultConfig) }
            catch { if ($_.Exception.Message -ne 'COMPLETE-RUN-TEST-SENTINEL') { throw } }
        }

        Invoke-FinishScenario
        $a = @($script:Actions)
        Check 'finished run: outcome'                 $script:RecoveryCapture.Outcome 'RECOVERED_POSTINSTALL'
        Check 'finished run: exit 0'                  $script:RecoveryCapture.Code 0
        Check 'finished run: tuning applied'          ($a -contains 'TUNING') 'True'
        Check 'finished run: PostgreSQL restarted'    (($a -contains 'STOP:postgresql-x64-15') -and ($a -contains 'START:postgresql-x64-15')) 'True'
        Check 'finished run: both services restored'  ($a -contains 'RESTORE:2:VeeamBackupSvc+VeeamDeploySvc') 'True'
        Check 'finished run: all three jobs back'     (@($a | Where-Object { $_ -like 'ENABLE:*' }).Count) 3
        Check 'finished run: tuning before services'  ([array]::IndexOf($a, 'TUNING') -lt [array]::IndexOf($a, 'RESTORE:2:VeeamBackupSvc+VeeamDeploySvc')) 'True'
        Check 'finished run: services before jobs'    ([array]::IndexOf($a, 'RESTORE:2:VeeamBackupSvc+VeeamDeploySvc') -lt [array]::IndexOf($a, 'ENABLE:Backup Configuration Job')) 'True'
        Check 'finished run: marker removed'          ($a -contains 'MARKER-REMOVED') 'True'
        Check 'finished run: reports the new version' $script:Report.PgInstalled '15.19'

        Invoke-FinishScenario -PgNum 150002
        Check 'old version: diagnostic only'          $script:RecoveryCapture.Outcome 'RECOVERY_DIAGNOSTIC_ONLY'
        Check 'old version: says why'                 ($script:RecoveryCapture.Detail -match 'not the target 150019') 'True'
        Check 'old version: changes nothing'          @($script:Actions).Count 0

        Invoke-FinishScenario -BackupSvcStatus 'Running'
        Check 'Veeam already started: diagnostic'     $script:RecoveryCapture.Outcome 'RECOVERY_DIAGNOSTIC_ONLY'
        Check 'Veeam already started: says why'       ($script:RecoveryCapture.Detail -match 'already started by hand') 'True'
        Check 'Veeam already started: no change'      @($script:Actions).Count 0

        Invoke-FinishScenario -Installer @([pscustomobject]@{ Id=77; ProcessName='postgresql-15.19-windows-x64' })
        Check 'installer still running: diagnostic'   $script:RecoveryCapture.Outcome 'RECOVERY_DIAGNOSTIC_ONLY'
        Check 'installer still running: says why'     ($script:RecoveryCapture.Detail -match 'installer is still running \(PID 77\)') 'True'
        Check 'installer still running: no change'    @($script:Actions).Count 0

        Invoke-FinishScenario -Stage 'COMPLETE'
        Check 'COMPLETE stage stays diagnostic'       $script:RecoveryCapture.Outcome 'RECOVERY_DIAGNOSTIC_ONLY'
        Check 'COMPLETE stage changes nothing'        @($script:Actions).Count 0

        Invoke-FinishScenario -TuningExit 3
        $a = @($script:Actions)
        Check 'tuning fails: incomplete'              $script:RecoveryCapture.Outcome 'RECOVERY_INCOMPLETE'
        Check 'tuning fails: says it is post-install' $script:Report.IssueCode 'POSTINSTALL_RECOVERY_INCOMPLETE'
        Check 'tuning fails: Veeam stays down'        (@($a | Where-Object { $_ -like 'RESTORE:*' }).Count) 0
        Check 'tuning fails: jobs stay off'           (@($a | Where-Object { $_ -like 'ENABLE:*' }).Count) 0
        Check 'tuning fails: marker kept'             ($a -contains 'MARKER-REMOVED') 'False'

        # Pre-installer recovery reads the same JSON lists, so it must work on 5.1 too.
        $script:Svc = @{ 'postgresql-x64-15'='Stopped'; 'VeeamBackupSvc'='Stopped'; 'VeeamDeploySvc'='Stopped' }
        $script:FakePgNum = 150002; $script:FakeInstallerProcs = @(); $script:FakeTuningExit = 0
        Write-AtomicJson -Path $statePath -InputObject ([ordered]@{
            SchemaVersion=1; RunId=$runId; RunDir=$runPath; Stage='SERVICES_STOPPED'; InstallerStarted=$false
            Products='VBR'; OriginalVersion='15.2'; TargetVersion='15.19'
            PgServiceName='postgresql-x64-15'; PsqlPath=$psqlFake; PgPort='5432' })
        Write-AtomicJson -Path $markerPath -InputObject ([ordered]@{
            SchemaVersion=1; RunId=$runId; RunDir=$runPath; StateFile=$statePath; Stage='SERVICES_STOPPED'; InstallerStarted=$false })
        $script:Actions = @(); $script:RecoveryCapture = $null
        try { Invoke-ExplicitRecovery -MarkerPath $markerPath -Cfg (Get-DefaultConfig) }
        catch { if ($_.Exception.Message -ne 'COMPLETE-RUN-TEST-SENTINEL') { throw } }
        $a = @($script:Actions)
        Check 'pre-install recovery: outcome'         $script:RecoveryCapture.Outcome 'RECOVERED_PREINSTALL'
        Check 'pre-install recovery: no tuning'       ($a -contains 'TUNING') 'False'
        Check 'pre-install recovery: reads 2 services' ($a -contains 'RESTORE:2:VeeamBackupSvc+VeeamDeploySvc') 'True'
        Check 'pre-install recovery: reads 3 jobs'    (@($a | Where-Object { $_ -like 'ENABLE:*' }).Count) 3
    } finally {
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

'--- Clear-StaleEnterpriseManagerRecord.ps1: -Clear takes and judges a fresh configuration backup ---'
# VBR 12 and 13 builds can leave the job's LastRun empty, so an age check on LastRun
# cannot work. The tool takes a fresh backup and judges the session it returns.
& {
    $toolPath = Join-Path $PSScriptRoot 'Clear-StaleEnterpriseManagerRecord.ps1'
    $toolErrs = $null; $toolToks = $null
    $toolAst = [System.Management.Automation.Language.Parser]::ParseFile($toolPath, [ref]$toolToks, [ref]$toolErrs)
    Check 'EM tool parses'                       @($toolErrs).Count 0
    foreach ($fn in $toolAst.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        if (@('Get-Field','Invoke-FreshConfigBackup') -contains $fn.Name) { . ([scriptblock]::Create($fn.Extent.Text)) }
    }
    function New-FakeSession($Result, $Records) {
        $logger = [pscustomobject]@{ Data = [pscustomobject]@{ UpdatedRecords = @($Records) } }
        $logger | Add-Member -MemberType ScriptMethod -Name GetLog -Value { $this.Data }
        [pscustomobject]@{ Result = $Result; Logger = $logger }
    }

    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() New-FakeSession 'Success' @() }
    $b = Invoke-FreshConfigBackup
    Check 'fresh backup Success passes'          $b.Ok 'True'

    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() New-FakeSession 'Warning' @() }
    $b = Invoke-FreshConfigBackup
    Check 'fresh backup Warning passes'          $b.Ok 'True'
    Check 'Warning is reported as Warning'       $b.Result 'Warning'

    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() New-FakeSession 'Failed' @([pscustomobject]@{ Status='Failed'; Title='Repository Repo-A is unavailable' }, [pscustomobject]@{ Status='Succeeded'; Title='Job started' }) }
    $b = Invoke-FreshConfigBackup
    Check 'fresh backup Failed refuses'          $b.Ok 'False'
    Check 'the failure reason is given'          ($b.Reason -match "'Failed' \(Repository Repo-A is unavailable\)") 'True'
    Check 'only failed log lines are given'      ($b.Reason -match 'Job started') 'False'

    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() throw 'Access is denied' }
    $b = Invoke-FreshConfigBackup
    Check 'a backup that cannot run refuses'     $b.Ok 'False'
    Check 'and says why'                         ($b.Reason -match 'could not run: Access is denied') 'True'

    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() throw ([System.InvalidOperationException]::new('')) }
    $b = Invoke-FreshConfigBackup
    Check 'a silent throw still refuses'         $b.Ok 'False'

    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() }
    $b = Invoke-FreshConfigBackup
    Check 'no session refuses'                   $b.Ok 'False'
    Check 'no session says so'                   ($b.Reason -match 'no result') 'True'

    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() [pscustomobject]@{ Note = 'no Result property' } }
    $b = Invoke-FreshConfigBackup
    Check 'a session with no Result refuses'     $b.Ok 'False'

    $toolText = Get-Content -LiteralPath $toolPath -Raw
    $toolParams = @($toolAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    Check 'the old age limit is gone'            ($toolParams -contains 'MaxConfigBackupAgeHours') 'False'
    Check 'LastRun is no longer trusted'         ($toolText -match "Get-Field \`$cfgJob 'LastRun'") 'False'
    $backupAt  = $toolText.IndexOf('$backup = Invoke-FreshConfigBackup')
    $emCheckAt = $toolText.IndexOf('if ($emInstalled) {')
    $confirmAt = $toolText.IndexOf('$PSCmdlet.ShouldProcess(')
    Check 'backup runs after the EM check'       ($emCheckAt -gt 0 -and $backupAt -gt $emCheckAt) 'True'
    Check 'backup runs before the confirmation'  ($backupAt -gt 0 -and $backupAt -lt $confirmAt) 'True'
    Check 'a failed backup stops the tool'       ($toolText -match '(?s)if \(-not \$backup\.Ok\) \{.*?exit 1') 'True'
    Check '-WhatIf takes no backup'              ($toolText -match '(?s)\} elseif \(\$WhatIfPreference\) \{\s+Write-Note ''WhatIf: a fresh VBR configuration backup would run here') 'True'
}

'--- The WorkRoot marker text never changes ---'
# Test-WorkRootSentinel compares this text case-sensitively, so it must never change,
# even though the script was renamed to Update-VeeamPreReqs.ps1.
Check 'WorkRoot marker text is unchanged'       (Get-WorkRootSentinelText) 'Created by Update-VeeamPostgres.ps1. Marks this folder as safe for the script to lock down and clean up.'

'--- Installer exit code survives Windows PowerShell 5.1 ---'
$installerStart = $scriptText.IndexOf('$proc = Start-Process -FilePath $installerPath')
$handleOpen = $scriptText.IndexOf('$null = $proc.Handle')
$firstWait = $scriptText.IndexOf('$proc.WaitForExit(')
Check 'installer handle is opened'              ($installerStart -gt 0 -and $handleOpen -gt $installerStart -and $handleOpen -lt $firstWait) 'True'
Check 'unreadable exit code is not a failure'   ($scriptText -match '(?m)^if \(\$null -ne \$installerExit -and \$installerExit -ne 0\) \{') 'True'
Check 'unreadable exit code is logged'          ($scriptText -match 'The installer exit code could not be read\. STEP 18 decides from the running version') 'True'
Check 'mid-change note points to -Recover'      ($scriptText -match 'Run this script with -Recover: it finishes the update when PostgreSQL is healthy at the target version') 'True'
# The same pattern on this PowerShell edition: without the handle, 5.1 reads ''.
$probeProc = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', 'ping -n 2 127.0.0.1 >nul & exit 3' -PassThru -NoNewWindow
try { $null = $probeProc.Handle } catch {}
[void]$probeProc.WaitForExit(60000); $probeProc.WaitForExit()
Check 'this edition reads the exit code'        $probeProc.ExitCode 3
Check 'no JSON list is read the 5.1-broken way' ([regex]::Matches($scriptText, '@\(Get-Content[^\r\n]*\| ConvertFrom-Json').Count) 0

& {
    $WorkRoot = Join-Path $env:TEMP "vpgu-recover-traversal-$PID"
    New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
    Protect-Folder $WorkRoot | Out-Null
    try {
        $outside = Join-Path $env:TEMP "vpgu-outside-$PID\recovery-state.json"
        $markerPath = Join-Path $WorkRoot 'CHANGES-IN-PROGRESS.marker'
        Write-AtomicJson -Path $markerPath -InputObject ([ordered]@{
            SchemaVersion=1; RunId='20260917-010203-004-1234'; RunDir=(Split-Path -Parent $outside); StateFile=$outside; Stage='JOBS_DISABLED'; InstallerStarted=$false
        })
        $EXIT = @{ ESCALATE=40; ESCALATE_NOW=50 }
        $script:RecoveryCapture = $null
        function Complete-Run {
            param([int]$Code,[string]$Outcome,[string]$Detail)
            $script:RecoveryCapture = [pscustomobject]@{ Code=$Code; Outcome=$Outcome; Detail=$Detail }
            throw 'COMPLETE-RUN-TEST-SENTINEL'
        }
        try { Invoke-ExplicitRecovery -MarkerPath $markerPath -Cfg (Get-DefaultConfig) }
        catch { if ($_.Exception.Message -ne 'COMPLETE-RUN-TEST-SENTINEL') { throw } }
        Check 'recovery rejects path outside WorkRoot' $script:RecoveryCapture.Outcome 'INVALID_RECOVERY_PATH'
        Check 'unsafe recovery path escalates' $script:RecoveryCapture.Code 40
    } finally {
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $env:TEMP "vpgu-outside-$PID") -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& {
    $WorkRoot = Join-Path $env:TEMP "vpgu-recover-junction-$PID"
    $outsideRoot = Join-Path $env:TEMP "vpgu-recover-junction-target-$PID"
    $runId = '20260917-010203-004-4321'
    $runsJunction = Join-Path $WorkRoot 'runs'
    $junctionCreated = $false
    New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
    Protect-Folder $WorkRoot | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $outsideRoot $runId) -Force | Out-Null
    try {
        try {
            New-Item -ItemType Junction -Path $runsJunction -Target $outsideRoot -ErrorAction Stop | Out-Null
            $junctionCreated = $true
        } catch {
            '  SKIP  recovery junction test could not create an NTFS junction'
        }
        if ($junctionCreated) {
            $runPath = [IO.Path]::GetFullPath((Join-Path $runsJunction $runId)).TrimEnd('\')
            $statePath = Join-Path $runPath 'recovery-state.json'
            $markerPath = Join-Path $WorkRoot 'CHANGES-IN-PROGRESS.marker'
            $canary = Join-Path $outsideRoot 'outside-canary.txt'
            Set-Content -LiteralPath $canary -Value 'untouched'
            Write-AtomicJson -Path $statePath -InputObject ([ordered]@{
                SchemaVersion=1; RunId=$runId; RunDir=$runPath; Stage='JOBS_DISABLED'; InstallerStarted=$false
            })
            Write-AtomicJson -Path $markerPath -InputObject ([ordered]@{
                SchemaVersion=1; RunId=$runId; RunDir=$runPath; StateFile=$statePath; Stage='JOBS_DISABLED'; InstallerStarted=$false
            })
            $EXIT = @{ ESCALATE=40; ESCALATE_NOW=50 }
            $script:RecoveryCapture = $null
            $script:RecoveryMutationCount = 0
            function Test-TrustedOwner { param($Path) return $true }
            function Start-Service { $script:RecoveryMutationCount++ }
            function Stop-Service  { $script:RecoveryMutationCount++ }
            function Enable-VeeamJobById { $script:RecoveryMutationCount++ }
            function Complete-Run {
                param([int]$Code,[string]$Outcome,[string]$Detail)
                $script:RecoveryCapture = [pscustomobject]@{ Code=$Code; Outcome=$Outcome; Detail=$Detail }
                throw 'COMPLETE-RUN-TEST-SENTINEL'
            }
            try { Invoke-ExplicitRecovery -MarkerPath $markerPath -Cfg (Get-DefaultConfig) }
            catch { if ($_.Exception.Message -ne 'COMPLETE-RUN-TEST-SENTINEL') { throw } }
            Check 'recovery rejects junction escape' $script:RecoveryCapture.Outcome 'INVALID_RECOVERY_PATH'
            Check 'junction recovery performs no mutation' $script:RecoveryMutationCount 0
            Check 'junction recovery leaves outside target' (Get-Content -LiteralPath $canary -Raw).Trim() 'untouched'
        }
    } finally {
        if ($junctionCreated -and (Test-Path -LiteralPath $runsJunction)) { [IO.Directory]::Delete($runsJunction) }
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $outsideRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

'--- Degraded server warning: auto-start services sitting stopped ---'
# A stopped Veeam Installer/Deploy Service takes the repositories offline, which
# makes the configuration backup fail.
Check 'warns on auto-but-stopped'    ($scriptText -match 'set to start automatically are currently stopped') 'True'
Check 'names the deploy service'     ($scriptText -match 'Veeam Installer/Deploy Service takes repositories offline') 'True'
Check 'only Automatic startups count' ($scriptText -match '"\$svcStartup" -like ''Automatic\*''') 'True'
Check 'it warns, never blocks'       ($scriptText -match "autoStoppedServices -join ', '\)`" WARN") 'True'
Check 'says it will start them and retry' ($scriptText -match 'If that backup fails, this run starts these services and retries it once') 'True'
Check 'audit says it changes nothing'    ($scriptText -match 'This audit changes nothing\. An -Install run starts these services') 'True'
Check 'VB365-only promises no start'     ($scriptText -match 'This server has no VBR configuration backup, so this run does not start them') 'True'
Check 'old "will not fix it" text is gone' ($scriptText -match 'so this run will not fix it') 'False'

'--- Configuration backup: judge this run, and say why it failed ---'
# A configuration backup can fail within seconds even with the job Enabled. LastRun
# can be EMPTY on VBR 12 and 13 builds, so the job's LastResult cannot be shown to
# belong to the run we started.
Check 'session result is preferred'     ($scriptText -match "\`$sessionResult = ""\`$\(Get-CfgValue \`$configSession 'Result' ''\)""") 'True'
Check 'disagreement is logged'          ($scriptText -match "Trusting the session") 'True'
Check 'failure reason is extracted'     ($scriptText -match '\$configSession\.Logger\.GetLog\(\)\.UpdatedRecords') 'True'
Check 'reason falls back to console'    ($scriptText -match 'see History > Configuration Backup in the VBR console') 'True'
Check 'action names the real problem'   ($scriptText -match 'Fix the VBR configuration backup job on this server, then retry') 'True'
Check 'still refuses to continue'       ($scriptText -match 'Refusing to update PostgreSQL on a server with no working configuration backup') 'True'
Check 'no override switch exists'       ($scriptParameterNames -contains 'AllowFailedConfigBackup') 'False'

'--- Configuration backup: one attempt, judged on its own session ---'
& {
    function Get-VBRConfigurationBackupJob { [CmdletBinding()] param() [pscustomobject]@{ LastResult = $script:FakeJobLastResult; LastRun = $null } }
    function New-FakeConfigSession($Result, $Records) {
        $logger = [pscustomobject]@{ Data = [pscustomobject]@{ UpdatedRecords = @($Records) } }
        $logger | Add-Member -MemberType ScriptMethod -Name GetLog -Value { $this.Data }
        [pscustomobject]@{ Result = $Result; Logger = $logger }
    }
    $failedRecords = @(
        [pscustomobject]@{ Status = 'Failed';    Title = 'Repository Repo-A is unavailable' },
        [pscustomobject]@{ Status = 'Succeeded'; Title = 'Job started' }
    )

    $script:FakeJobLastResult = 'Success'
    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() New-FakeConfigSession 'Failed' $failedRecords }
    $a = Invoke-VbrConfigBackupAttempt
    Check 'failed session is Failed'          $a.Result 'Failed'
    Check 'session beats a stale LastResult'  $a.Result 'Failed'
    Check 'failure reason is kept'            (@($a.Reasons) -join '|') 'Repository Repo-A is unavailable'
    Check 'a returned session is no error'    $a.Error ''

    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() New-FakeConfigSession 'Success' @() }
    $a = Invoke-VbrConfigBackupAttempt
    Check 'good session is Success'           $a.Result 'Success'
    Check 'no reasons on success'             @($a.Reasons).Count 0

    $script:FakeJobLastResult = 'Warning'
    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() [pscustomobject]@{ Note = 'no Result property' } }
    $a = Invoke-VbrConfigBackupAttempt
    Check 'empty session falls back to job'   $a.Result 'Warning'

    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() throw 'Remote connection was terminated. Either re-establish remote connection or use local one' }
    $a = Invoke-VbrConfigBackupAttempt
    Check 'a throw is reported as Error'      ($a.Error -match 'Remote connection was terminated') 'True'
    Check 'a dropped connection is flagged'   $a.ConnectionLost 'True'
    Check 'a throw has no Result'             $a.Result ''

    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() throw 'Access is denied' }
    $a = Invoke-VbrConfigBackupAttempt
    Check 'other throw is not a lost link'    $a.ConnectionLost 'False'

    # A throw with an empty message must never fall back to a stale LastResult.
    $script:FakeJobLastResult = 'Success'
    function Start-VBRConfigurationBackupJob { [CmdletBinding()] param() throw ([System.InvalidOperationException]::new('')) }
    $a = Invoke-VbrConfigBackupAttempt
    Check 'a silent throw is still an Error'  ([bool]$a.Error) 'True'
    Check 'a silent throw never reads Success' $a.Result ''
}

'--- Configuration backup failed: start stopped automatic services, retry once ---'
& {
    $serviceRows = @(
        [pscustomobject]@{ Name='VeeamDeploySvc';  Status='Stopped'; StartupType='Automatic' },
        [pscustomobject]@{ Name='VeeamDelayedSvc'; Status='Stopped'; StartupType='AutomaticDelayedStart' },
        [pscustomobject]@{ Name='VeeamManualSvc';  Status='Stopped'; StartupType='Manual' },
        [pscustomobject]@{ Name='VeeamOffSvc';     Status='Stopped'; StartupType='Disabled' },
        [pscustomobject]@{ Name='VeeamBackupSvc';  Status='Running'; StartupType='Automatic' },
        [pscustomobject]@{ Name='VeeamBrokenSvc';  Status='Stopped'; StartupType='Automatic' }
    )
    $actionLog = New-Object System.Collections.ArrayList
    function Get-Service {
        [CmdletBinding()] param([Parameter(Position=0)][string[]]$Name)
        $found = @()
        foreach ($pattern in @($Name)) { $found += @($serviceRows | Where-Object { $_.Name -like $pattern }) }
        return $found
    }
    function Get-ServiceStartupTypeExact {
        [CmdletBinding()] param([string]$Name)
        "$((@($serviceRows | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1).StartupType)"
    }
    function Start-Service {
        [CmdletBinding()] param([Parameter(Position=0)][string]$Name)
        $null = $actionLog.Add("START:$Name")
        if ($Name -eq 'VeeamBrokenSvc') { throw 'Service cannot be started' }
        (@($serviceRows | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1).Status = 'Running'
    }
    function Start-Sleep { [CmdletBinding()] param([int]$Seconds) }

    $started = @(Start-StoppedAutomaticVeeamServices -TimeoutSeconds 5)
    Check 'starts the stopped Deploy service'      ($started -contains 'VeeamDeploySvc') 'True'
    Check 'starts a delayed-automatic service'     ($started -contains 'VeeamDelayedSvc') 'True'
    Check 'a service that will not start is not reported started' ($started -contains 'VeeamBrokenSvc') 'False'
    Check 'it still tried the broken one'          ($actionLog -contains 'START:VeeamBrokenSvc') 'True'
    Check 'never starts a Manual service'          ($actionLog -contains 'START:VeeamManualSvc') 'False'
    Check 'never starts a Disabled service'        ($actionLog -contains 'START:VeeamOffSvc') 'False'
    Check 'leaves a running service alone'         ($actionLog -contains 'START:VeeamBackupSvc') 'False'
    Check 'reports exactly the started ones'       $started.Count 2

    $actionLog.Clear()
    foreach ($row in $serviceRows) { if ($row.Name -ne 'VeeamBrokenSvc' -and $row.StartupType -like 'Automatic*') { $row.Status = 'Running' } }
    foreach ($row in $serviceRows) { if ($row.Name -eq 'VeeamBrokenSvc') { $row.StartupType = 'Manual' } }
    $started = @(Start-StoppedAutomaticVeeamServices -TimeoutSeconds 5)
    Check 'nothing to start returns nothing'       $started.Count 0
    Check 'nothing to start touches nothing'       $actionLog.Count 0
}

# The STEP 14 flow is script body, so pin its shape from the AST and text.
$cfgAttemptCalls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-VbrConfigBackupAttempt' }, $true))
$serviceStartCalls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Start-StoppedAutomaticVeeamServices' }, $true))
Check 'config backup runs at most twice'         $cfgAttemptCalls.Count 2
Check 'services are started from one place'      $serviceStartCalls.Count 1
$retryGate = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$startedServices.Count -eq 0' }, $true))
$isCfgAttempt = { param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-VbrConfigBackupAttempt' }
Check 'no retry unless a service started'        ($retryGate.Count -eq 1 -and $null -ne $retryGate[0].ElseClause -and @($retryGate[0].Clauses[0].Item2.FindAll($isCfgAttempt, $true)).Count -eq 0 -and @($retryGate[0].ElseClause.FindAll($isCfgAttempt, $true)).Count -eq 1) 'True'
Check 'a lost connection is re-established before the retry' ($scriptText -match "(?s)Start-StoppedAutomaticVeeamServices.*?if \(\`$cfgAttempt\.ConnectionLost\) \{\s+\`$cfgReconnectProblems = @\(Connect-VeeamModules -Vbr -Quiet -Reconnect\).*?\`$cfgAttempt = Invoke-VbrConfigBackupAttempt") 'True'
Check 'retry happens inside the failure branch'  ($scriptText -match "(?s)if \(\`$cfgAttempt\.Error -or \`$cfgAttempt\.Result -eq 'Failed'\) \{.*?Start-StoppedAutomaticVeeamServices.*?\`$cfgAttempt = Invoke-VbrConfigBackupAttempt") 'True'
Check 'failure detail carries the retry note'    ($scriptText -match '\$reasonText\$retryNote Refusing to update PostgreSQL') 'True'
Check 'started services reach the RMM summary'   ($scriptText -match "Add-ReportListItem -Field 'ServicesStarted'") 'True'
Check 'report has a ServicesStarted field'       ($scriptText -match "(?m)^\s+ServicesStarted = ''") 'True'
Check 'Complete-Run adds the side-effect notes'  ($scriptText -match '\$stateNote = Add-RunSideEffectNotes -StateNote \$stateNote -Report \$script:Report') 'True'

'--- The RMM Detail admits every change a run made outside its stage ---'
& {
    $script:SvcState = @{}
    function Get-Service {
        [CmdletBinding()] param([Parameter(Position=0)][string[]]$Name)
        foreach ($n in @($Name)) { if ($script:SvcState.ContainsKey($n)) { [pscustomobject]@{ Name=$n; Status=$script:SvcState[$n] } } }
    }
    function New-Report($Started = '', $Closed = '', $Em = '') {
        [ordered]@{ ServicesStarted=$Started; ConsolesClosed=$Closed; StaleEmRecord=$Em }
    }

    Check 'nothing happened: note unchanged'      (Add-RunSideEffectNotes -StateNote 'Nothing was changed.' -Report (New-Report)) 'Nothing was changed.'
    Check 'EM key only present: note unchanged'   (Add-RunSideEffectNotes -StateNote 'Nothing was changed.' -Report (New-Report -Em 'present')) 'Nothing was changed.'

    # Removing the key is a change, so the Detail must never then say "Nothing was changed".
    $n = Add-RunSideEffectNotes -StateNote 'Nothing was changed.' -Report (New-Report -Em 'removed; backup C:\x.reg')
    Check 'EM key removed: no "Nothing was changed"' ($n -match 'Nothing was changed') 'False'
    Check 'EM key removed: says so'               ($n -match 'removed the leftover Enterprise Manager registry key') 'True'

    $n = Add-RunSideEffectNotes -StateNote 'Nothing was changed.' -Report (New-Report -Closed 'Veeam.Backup.Shell:PID9(session 2)')
    Check 'console closed: no "Nothing was changed"' ($n -match 'Nothing was changed') 'False'
    Check 'console closed: says so'               ($n -match 'closed the open Veeam console\(s\) Veeam\.Backup\.Shell:PID9') 'True'

    $script:SvcState = @{ VeeamDeploySvc = 'Running' }
    $n = Add-RunSideEffectNotes -StateNote 'Scheduled jobs were re-enabled.' -Report (New-Report -Started 'VeeamDeploySvc')
    Check 'started and running: "left running"'   ($n -match 'started the stopped automatic Veeam service\(s\) VeeamDeploySvc and left them running') 'True'
    Check 'other notes are kept'                  ($n -match '^Scheduled jobs were re-enabled\. ') 'True'

    $script:SvcState = @{ VeeamDeploySvc = 'Stopped' }
    $n = Add-RunSideEffectNotes -StateNote 'SERVER IS MID-CHANGE.' -Report (New-Report -Started 'VeeamDeploySvc')
    Check 'started but stopped now: never "left running"' ($n -match 'left them running') 'False'
    Check 'started but stopped now: says so'      ($n -match 'Not all of them are running now') 'True'

    Check 'empty note stays empty'                (Add-RunSideEffectNotes -StateNote '' -Report (New-Report)) ''
}
Check 'state note is never cut from Detail'      ($scriptText -match 'Format-ShortText \$Detail \$detailMax') 'True'
# The service snapshot is taken AFTER the configuration backup, so a service this
# run started is recorded as running and STEP 20 leaves it running.
# LastIndexOf: the NATS run takes its own snapshot earlier in the file, and VB365 has
# no configuration backup to retry.
Check 'snapshot is taken after the retry'        ($scriptText.IndexOf('$cfgAttempt = Invoke-VbrConfigBackupAttempt') -lt $scriptText.LastIndexOf('$script:VeeamServices = @(Get-VeeamServiceState)')) 'True'

'--- Open Veeam consoles are closed, never waited for; Explorers never ---'
& {
    $priorReport = Get-Variable -Name Report -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    $script:Report = [ordered]@{ ConsolesClosed = '' }
    $script:FakeProcs = New-Object System.Collections.ArrayList
    $script:Stopped = New-Object System.Collections.ArrayList
    $script:Unkillable = @()
    function New-FakeProc($Name, $Id, [switch]$Polite) {
        $p = [pscustomobject]@{ ProcessName = $Name; Id = $Id; SessionId = 2 }
        if ($Polite) {
            $p | Add-Member -MemberType ScriptMethod -Name CloseMainWindow -Value {
                $mine = @($script:FakeProcs | Where-Object { $_.Id -eq $this.Id })
                foreach ($m in $mine) { $script:FakeProcs.Remove($m) }
                $true
            }
        }
        $p
    }
    function Get-Process {
        [CmdletBinding()] param([string]$Name, [int]$Id)
        if ($PSBoundParameters.ContainsKey('Id')) { return @($script:FakeProcs | Where-Object { $_.Id -eq $Id }) }
        return @($script:FakeProcs | Where-Object { $_.ProcessName -like $Name })
    }
    function Stop-Process {
        [CmdletBinding()] param([int]$Id, [switch]$Force)
        $null = $script:Stopped.Add($Id)
        if ($script:Unkillable -contains $Id) { throw 'Access is denied' }
        $mine = @($script:FakeProcs | Where-Object { $_.Id -eq $Id })
        foreach ($m in $mine) { $script:FakeProcs.Remove($m) }
    }
    function Start-Sleep { [CmdletBinding()] param([int]$Seconds) }
    function Reset-Fakes {
        Remove-Variable -Name ConsoleCloseFailedIds -Scope Script -ErrorAction SilentlyContinue
        $script:FakeProcs.Clear(); $script:Stopped.Clear(); $script:Unkillable = @()
        $script:Report.ConsolesClosed = ''
    }

    Reset-Fakes
    $null = $script:FakeProcs.Add((New-FakeProc 'Veeam.Backup.Shell' 101))
    $null = $script:FakeProcs.Add((New-FakeProc 'Veeam.Archiver.Shell' 102))
    $null = $script:FakeProcs.Add((New-FakeProc 'Veeam.Exchange.Explorer' 103))
    $null = $script:FakeProcs.Add((New-FakeProc 'VeeamExplorerForMicrosoftExchange' 104))
    $r = @(Close-VeeamConsoleProcesses -Vbr $true -Vb365 $false)
    Check 'VBR console is closed'                 (@($script:FakeProcs | Where-Object { $_.Id -eq 101 }).Count) 0
    Check 'closed by force from session 0'        $r[0].Method 'forced'
    Check 'VB365 console left alone on VBR-only'  (@($script:FakeProcs | Where-Object { $_.Id -eq 102 }).Count) 1
    Check 'Explorer is never killed'              (($script:Stopped -contains 103) -or ($script:Stopped -contains 104)) 'False'
    Check 'Explorer still running'                (@($script:FakeProcs | Where-Object { $_.ProcessName -like '*Explorer*' }).Count) 2
    Check 'closed console reaches the RMM line'   ($script:Report.ConsolesClosed -match 'Veeam.Backup.Shell:PID101') 'True'

    Reset-Fakes
    $null = $script:FakeProcs.Add((New-FakeProc 'Veeam.Archiver.Shell' 201 -Polite))
    $r = @(Close-VeeamConsoleProcesses -Vbr $false -Vb365 $true)
    Check 'a console that can be asked closes politely' $r[0].Method 'closed'
    Check 'a polite close needs no kill'          $script:Stopped.Count 0

    Reset-Fakes
    $null = $script:FakeProcs.Add((New-FakeProc 'Veeam.Backup.Shell' 301))
    $script:Unkillable = @(301)
    $r = @(Close-VeeamConsoleProcesses -Vbr $true -Vb365 $false)
    Check 'an unkillable console is reported'     $r[0].Closed 'False'
    Check 'the reason is kept'                    ($r[0].Problem -match 'Access is denied') 'True'
    Check 'it is not reported as closed'          $script:Report.ConsolesClosed ''
    $r = @(Close-VeeamConsoleProcesses -Vbr $true -Vb365 $false)
    Check 'it is not retried on every poll'       $script:Stopped.Count 1
    Check 'it stays a shutdown barrier'           (@(Get-BlockingVeeamUiProcesses -Vbr $true -Vb365 $false).Count) 1

    # PID reuse: the console exits and a different program inherits its PID.
    Reset-Fakes
    $null = $script:FakeProcs.Add((New-FakeProc 'Veeam.Backup.Shell' 401))
    function Stop-Process {
        [CmdletBinding()] param([int]$Id, [switch]$Force)
        $null = $script:Stopped.Add($Id)
        $script:FakeProcs.Clear()
        $null = $script:FakeProcs.Add((New-FakeProc 'notepad' $Id))
    }
    $r = @(Close-VeeamConsoleProcesses -Vbr $true -Vb365 $false)
    Check 'a reused PID counts as closed'         $r[0].Closed 'True'
    Check 'the new owner of the PID is not killed' $script:Stopped.Count 1

    # PID reuse BEFORE the kill: the console exits and another program takes its PID
    # before the force step. The ID+name re-check must stop Stop-Process reaching it.
    Reset-Fakes
    $early = New-FakeProc 'Veeam.Backup.Shell' 501
    $early | Add-Member -MemberType ScriptMethod -Name CloseMainWindow -Value {
        $script:FakeProcs.Clear()
        $null = $script:FakeProcs.Add([pscustomobject]@{ ProcessName = 'notepad'; Id = $this.Id; SessionId = 2 })
        $false
    }
    $null = $script:FakeProcs.Add($early)
    $r = @(Close-VeeamConsoleProcesses -Vbr $true -Vb365 $false)
    Check 'a PID reused before the kill is never killed'    $script:Stopped.Count 0
    Check 'a console gone before the kill counts as closed' $r[0].Closed 'True'

    Remove-Variable -Name ConsoleCloseFailedIds -Scope Script -ErrorAction SilentlyContinue
    if ($null -eq $priorReport) { Remove-Variable -Name Report -Scope Script -ErrorAction SilentlyContinue }
    else { $script:Report = $priorReport }
}

Check 'only consoles: close'                     (Test-OnlyConsoleBlockers @('UI:Veeam.Backup.Shell:PID1','UI:Veeam.Archiver.Shell:PID2')) 'True'
Check 'a job still runs: do not close'           (Test-OnlyConsoleBlockers @('UI:Veeam.Backup.Shell:PID1','VBR:Backup:Nightly:Working')) 'False'
Check 'an Explorer is open: do not close'        (Test-OnlyConsoleBlockers @('UI:Veeam.Backup.Shell:PID1','UI:Veeam.Exchange.Explorer:PID3')) 'False'
Check 'nothing blocks: nothing to close'         (Test-OnlyConsoleBlockers @()) 'False'

& {
    $script:closeCalls = 0
    $script:polls = 0
    $script:pollScript = @()
    function Close-VeeamConsoleProcesses { param([bool]$Vbr, [bool]$Vb365) $script:closeCalls++ }
    function Get-ActiveVeeamWork {
        param([bool]$Vbr, [bool]$Vb365)
        $i = $script:polls; $script:polls++
        if ($i -lt $script:pollScript.Count) { return @($script:pollScript[$i]) }
        return @()
    }
    function Start-Sleep { param([int]$Seconds) }

    $script:closeCalls = 0; $script:polls = 0; $script:pollScript = @(,@('UI:Veeam.Backup.Shell:PID9'))
    $null = Wait-VeeamIdle -Vbr $true -Vb365 $false -TimeoutMinutes 1 -PollSeconds 1 -Context 'unit test'
    Check 'a plain wait closes nothing'           $script:closeCalls 0

    $script:closeCalls = 0; $script:polls = 0; $script:pollScript = @(,@('UI:Veeam.Backup.Shell:PID9'))
    $wait = Wait-VeeamIdle -Vbr $true -Vb365 $false -TimeoutMinutes 1 -PollSeconds 1 -Context 'unit test' -CloseConsoles
    Check 'an install wait closes a lone console' $script:closeCalls 1
    Check 'and is idle straight after'            $wait.Idle 'True'
    Check 'it re-read activity after closing'     $script:polls 2

    $script:closeCalls = 0; $script:polls = 0
    $script:pollScript = @(@('UI:Veeam.Backup.Shell:PID9','VBR:Backup:Nightly:Working'), @('UI:Veeam.Backup.Shell:PID9','VBR:Backup:Nightly:Working'))
    $null = Wait-VeeamIdle -Vbr $true -Vb365 $false -TimeoutMinutes 1 -PollSeconds 1 -Context 'unit test' -CloseConsoles
    Check 'a console is left alone while a job runs' $script:closeCalls 0
}

$idleWaits = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Wait-VeeamIdle' }, $true))
$idleWaitsThatClose = @($idleWaits | Where-Object { @($_.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'CloseConsoles' }).Count -gt 0 })
Check 'every idle wait closes consoles'          "$($idleWaitsThatClose.Count)/$($idleWaits.Count)" '9/9'
# Audit mode must change nothing: its one activity read is before the audit exit,
# and nothing that closes a console runs before that exit.
$auditExitToken = @($toks | Where-Object { $_.Kind -eq 'Comment' -and $_.Text.Trim() -eq '# AUDIT MODE STOPS HERE' })
$auditExit = if ($auditExitToken.Count -eq 1) { $auditExitToken[0].Extent.StartOffset } else { -1 }
$consoleClosers = @($ast.FindAll({
    param($n)
    $n -is [System.Management.Automation.Language.CommandAst] -and (
        $n.GetCommandName() -eq 'Close-VeeamConsoleProcesses' -or
        ($n.GetCommandName() -eq 'Wait-VeeamIdle' -and
         @($n.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'CloseConsoles' }).Count -gt 0))
}, $true) | ForEach-Object {
    $p = $_.Parent
    while ($p -and -not ($p -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $p = $p.Parent }
    [pscustomobject]@{ Name = $_.GetCommandName(); Owner = $(if ($p) { $p.Name } else { '<script body>' }); Offset = $_.Extent.StartOffset }
})
$closersBeforeAuditExit = @($consoleClosers | Where-Object { $_.Owner -eq '<script body>' -and $_.Offset -lt $auditExit })
# Inside functions, only the idle wait closes, and only recovery and the NATS -Install run
# (never audit) close that way. Audit exits before the NATS run starts (checked below).
$strayClosers = @($consoleClosers | Where-Object { $_.Owner -ne '<script body>' -and -not (
    ($_.Name -eq 'Close-VeeamConsoleProcesses' -and $_.Owner -eq 'Wait-VeeamIdle') -or
    ($_.Name -eq 'Wait-VeeamIdle' -and $_.Owner -eq 'Invoke-ExplicitRecovery') -or
    $_.Owner -eq 'Invoke-NatsOnlyUpdate') })
Check 'the audit exit marker exists once'        ($auditExit -gt 0) 'True'
Check 'audit never closes a console'             $closersBeforeAuditExit.Count 0
Check 'no closer hides in another function'      (@($strayClosers | ForEach-Object { "$($_.Name)@$($_.Owner)" }) -join ',') ''
$auditRead = $scriptText.IndexOf('$auditActivity = @(Get-ActiveVeeamWork')
Check 'audit still reports an open console'      ($auditRead -ge 0 -and $auditRead -lt $auditExit) 'True'
Check 'final gate closes only a lone console'    ($scriptText -match "(?s)\`$blockingUi = @\(Get-BlockingVeeamUiProcesses -Vbr \`$hasVbr -Vb365 \`$hasVb365\)\s+if \(Test-OnlyConsoleBlockers .*?\[void\]\(Close-VeeamConsoleProcesses -Vbr \`$hasVbr -Vb365 \`$hasVb365\)\s+\`$blockingUi = @\(Get-BlockingVeeamUiProcesses") 'True'
Check 'last-chance read closes only a lone console' ($scriptText -match "(?s)\`$lastChanceActive = @\(Get-ActiveVeeamWork -Vbr \`$hasVbr -Vb365 \`$hasVb365\)\s+if \(Test-OnlyConsoleBlockers \`$lastChanceActive\) \{\s+\[void\]\(Close-VeeamConsoleProcesses -Vbr \`$hasVbr -Vb365 \`$hasVb365\)\s+\`$lastChanceActive = @\(Get-ActiveVeeamWork") 'True'
Check 'final gate says Explorers are never closed' ($scriptText -match 'Explorers are never closed automatically, because one can be running a restore') 'True'
Check 'report has a ConsolesClosed field'        ($scriptText -match "(?m)^\s+ConsolesClosed = ''") 'True'

'--- Licence-restricted job families are empty, not unreadable ---'
# Below Enterprise Plus, Get-VBRApplicationBackupJob throws because the feature
# needs Enterprise Plus. A feature the licence excludes cannot have jobs running.
Check 'edition matcher: Veeam wording'  (Test-VeeamEditionBlockedError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'This functionality is available in the Enterprise Plus edition only.' } })) 'True'
Check 'edition matcher: other edition'  (Test-VeeamEditionBlockedError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'This functionality is available in the Enterprise edition only.' } })) 'True'
Check 'edition matcher: licence words'  (Test-VeeamEditionBlockedError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'This feature is not supported by your license' } })) 'True'
Check 'edition matcher: unrelated'      (Test-VeeamEditionBlockedError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'Access is denied' } })) 'False'
Check 'edition matcher: MFA is not it'  (Test-VeeamEditionBlockedError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'Unable to connect to the server with MFA-enabled user account' } })) 'False'
Check 'inventory skips licensed-out'    ($scriptText -match 'This edition cannot run \$\(\$def\.Family\) jobs, so there are none to control') 'True'
Check 'other inventory errors still throw' ($scriptText -match 'failed while inventorying \$\(\$def\.Family\) schedules') 'True'
# A licence-blocked session getter becomes NotSupported, so the collector can skip
# it when nothing needs it and still fail closed when a configured family does.
$script:UnusableSessionGetters = @{}
function Get-FakeLicensedOutGetter { [CmdletBinding()] param() throw 'This functionality is available in the Enterprise Plus edition only.' }
$licErr = $null
try { Get-SessionsFromGetter 'Get-FakeLicensedOutGetter' } catch { $licErr = $_ }
Check 'licence error is NotSupported'   ($licErr.Exception -is [System.NotSupportedException]) 'True'
Check 'licence error names the command' ($licErr.Exception.Message -match 'Get-FakeLicensedOutGetter') 'True'
Check 'licence error says licence'      ($licErr.Exception.Message -match 'not available in this Veeam licence edition') 'True'
$script:UnusableSessionGetters = @{}

# Invoke-VeeamEnumeration: every "what exists?" call tolerates a licence refusal
# and nothing else, and it is never used to change a job.
$script:UnusableSessionGetters = @{}
Check 'enumeration returns results'     (@(Invoke-VeeamEnumeration -Label 'fake' -Enumerate { 'a'; 'b' }).Count) 2
Check 'licence refusal returns empty'   (@(Invoke-VeeamEnumeration -Label 'fake licensed-out' -Enumerate { throw 'This functionality is available in the Enterprise Plus edition only.' }).Count) 0
$enumErr = $null
try { Invoke-VeeamEnumeration -Label 'fake broken' -Enumerate { throw 'the server is on fire' } } catch { $enumErr = $_ }
Check 'other failure still throws'      ($null -ne $enumErr) 'True'
Check 'other failure keeps the label'   ($enumErr.Exception.Message -match 'fake broken') 'True'
Check 'other failure keeps the reason'  ($enumErr.Exception.Message -match 'server is on fire') 'True'
Check 'licence refusal is remembered'   (Test-UnusableSessionGetter 'enumeration:fake licensed-out') 'True'
$script:UnusableSessionGetters = @{}
# Discovery, unstructured and transfer-session enumeration all route through it.
Check 'discovery uses the wrapper'      ($scriptText -match "Invoke-VeeamEnumeration -Label ""Get-VBRSession -Type \`$discoveryType""") 'True'
Check 'unstructured uses the wrapper'   ($scriptText -match 'Invoke-VeeamEnumeration -Label "Get-VBRUnstructuredBackupSession') 'True'
Check 'transfer uses the wrapper'       ($scriptText -match 'Invoke-VeeamEnumeration -Label "\$commandName -Backup') 'True'
# Job changes must NOT be licence-tolerant: those act on jobs already found.
Check 'transitions are not tolerant'    ($scriptText -match 'Invoke-VeeamEnumeration[^\r\n]*Enable:\$enableValue') 'False'

'--- MFA-enabled accounts are named as such in the RMM summary ---'
Check 'MFA matcher: Veeam wording'   (Test-VeeamMfaBlockedError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'Unable to connect to the server with MFA-enabled user account. Execution environment cannot be initialized to Remote' } })) 'True'
Check 'MFA matcher: long wording'    (Test-VeeamMfaBlockedError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'multi-factor authentication is enabled for this account' } })) 'True'
Check 'MFA matcher: unrelated text'  (Test-VeeamMfaBlockedError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'Access is denied' } })) 'False'
Check 'MFA has its own issue code'   ($scriptText -match "IssueCode = 'VEEAM_MFA_BLOCKS_POWERSHELL'") 'True'
Check 'MFA action says MFA ACCOUNT'  ($scriptText -match "Action = 'MFA ACCOUNT\.") 'True'
Check 'MFA action cites KB4535'      ($scriptText -match 'KB4535') 'True'
Check 'MFA action gives the path'    ($scriptText -match 'This is a service account \(disables two-factor authentication\)') 'True'
Check 'script never sets MFA flag'   ($scriptText -match 'Set-VBRUserRoleAssignment|service account \(disables two-factor authentication\)" *\)? *\|') 'False'
Check 'MFA action reaches the RMM'   ($scriptText -match 'if \(\$controlValidation\.Action\) \{ \$script:Report\.ActionRequired = \$controlValidation\.Action \}') 'True'

'--- STEP 6 says why PostgreSQL refused the login ---'
# A VBR server migrated to PostgreSQL by hand can keep scram-sha-256/md5 loopback lines
# in pg_hba.conf. psql -w then says "fe_sendauth: no password supplied"; a generic
# message would send the operator to pg_ident.conf (KB4542), which is never read there.
$h = Get-PgLoginFailureHint -StdErr 'psql: error: connection to server at "127.0.0.1", port 5432 failed: fe_sendauth: no password supplied' -Identity 'NT AUTHORITY\SYSTEM' -Product 'VBR'
Check 'no password supplied is password auth'  $h.Cause 'PASSWORD_AUTH'
Check 'password auth names native auth'        ($h.Detail -match 'password \(native\) authentication') 'True'
Check 'password auth cites KB4818'             ($h.Detail -match 'KB4818') 'True'
Check 'password auth says Veeam supports it'   ($h.Detail -match 'Veeam supports that') 'True'
Check 'password auth action is NATIVE AUTH'    ($h.Action -match '^NATIVE AUTH\.') 'True'
Check 'password auth action names the script'  ($h.Action -match 'Invoke-VbrStandardise\.ps1') 'True'
Check 'password auth action spells Standardise' ($h.Action -match 'Standardise VBR script') 'True'
Check 'password auth action skips KB4542'      ($h.Action -match 'KB4542') 'False'
# The psql prefix changed across versions; only the libpq text is stable.
$h = Get-PgLoginFailureHint -StdErr 'psql: fe_sendauth: no password supplied' -Product 'VBR'
Check 'psql 9.6-11 prefix is password auth'    $h.Cause 'PASSWORD_AUTH'
$h = Get-PgLoginFailureHint -StdErr 'psql: error: could not connect to server: fe_sendauth: no password supplied' -Product 'VBR'
Check 'psql 12.0-12.4 prefix is password auth' $h.Cause 'PASSWORD_AUTH'
# A stale pgpass.conf sends a wrong password, and libpq adds a second line.
$h = Get-PgLoginFailureHint -StdErr ("psql: error: connection to server at `"127.0.0.1`", port 5432 failed: FATAL:  password authentication failed for user `"postgres`"`npassword retrieved from file `"C:\Windows\system32\config\systemprofile\AppData\Roaming/postgresql/pgpass.conf`"") -Product 'VBR'
Check 'wrong password is password auth'        $h.Cause 'PASSWORD_AUTH'
$h = Get-PgLoginFailureHint -StdErr 'FE_SENDAUTH: NO PASSWORD SUPPLIED' -Product 'VBR'
Check 'password match ignores case'            $h.Cause 'PASSWORD_AUTH'
# Windows PowerShell 5.1 saves stderr as an error record wrapped at the console
# width. In a 100-column window the phrase splits over two lines.
$h = Get-PgLoginFailureHint -StdErr ("psql.exe : psql: error: connection to server at `"127.0.0.1`", port 5432 failed: fe_sendauth: no `r`npassword supplied`r`nAt line:1 char:1") -Product 'VBR'
Check '5.1 wrapped password text still found'  $h.Cause 'PASSWORD_AUTH'
$h = Get-PgLoginFailureHint -StdErr ("psql.exe : psql: error: connection to server at `"127.0.0.1`", port 5432 failed: FATAL:  SSPI `r`nauthentication failed for user `"postgres`"") -Identity 'NT AUTHORITY\SYSTEM' -Product 'VBR'
Check '5.1 wrapped SSPI text still found'      $h.Cause 'SSPI_MAP'
$h = Get-PgLoginFailureHint -StdErr ("psql.exe : psql: error: connection to server at `"127.0.0.1`", port 5432 failed: FATAL:  no `r`npg_hba.conf entry for host `"127.0.0.1`"") -Product 'VBR'
Check '5.1 wrapped pg_hba text still found'    $h.Cause 'NO_HBA_ENTRY'
# The standardise script converts VBR only. VB365, or Enterprise Manager beside a
# VBR left on SQL Server, must not be sent to it, but still gets an action.
$h = Get-PgLoginFailureHint -StdErr 'fe_sendauth: no password supplied' -Product 'OTHER'
Check 'non-VBR password auth is password auth' $h.Cause 'PASSWORD_AUTH'
Check 'non-VBR is not sent to the VBR script'  ($h.Action -match 'Invoke-VbrStandardise') 'False'
Check 'non-VBR action is NATIVE AUTH'          ($h.Action -match '^NATIVE AUTH\.') 'True'
Check 'non-VBR action names pg_hba.conf'       ($h.Action -match 'pg_hba\.conf') 'True'
Check 'non-VBR action names the veeam map'     ($h.Action -match 'veeam map in pg_ident\.conf') 'True'
Check 'non-VBR action skips KB4542'            ($h.Action -match 'KB4542') 'False'

# psql gets only "SSPI authentication failed"; the account comes from this run.
$h = Get-PgLoginFailureHint -StdErr 'psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  SSPI authentication failed for user "postgres"' -Identity 'NT AUTHORITY\SYSTEM' -Product 'VBR'
Check 'SSPI failure is a pg_ident problem'     $h.Cause 'SSPI_MAP'
Check 'SSPI failure keeps KB4542'              ($h.Detail -match 'KB4542') 'True'
Check 'SSPI failure names user@DOMAIN'         ($h.Detail -match "'SYSTEM@NT AUTHORITY'") 'True'
Check 'SSPI action names user@DOMAIN'          ($h.Action -match "'SYSTEM@NT AUTHORITY'") 'True'
Check 'SSPI action asks for no reload'         ($h.Action -match 'reload') 'False'
$h = Get-PgLoginFailureHint -StdErr 'psql: FATAL:  SSPI authentication failed for user "postgres"' -Identity 'CONTOSO\svc_backup' -Product 'VBR'
Check 'psql 9.6-11 SSPI is a pg_ident problem' $h.Cause 'SSPI_MAP'
Check 'domain account becomes user@DOMAIN'     ($h.Detail -match "'svc_backup@CONTOSO'") 'True'
# A failed SSPI handshake is not a mapping problem.
$h = Get-PgLoginFailureHint -StdErr ("psql: error: connection to server at `"127.0.0.1`", port 5432 failed: FATAL:  could not accept SSPI security context`nDETAIL:  The logon attempt failed (8009030c)") -Identity 'NT AUTHORITY\SYSTEM' -Product 'VBR'
Check 'SSPI handshake failure is not usermap'  ($h.Cause -eq 'SSPI_MAP') 'False'
# PostgreSQL logs "authenticated as" only to its own log, never to psql. If such a
# line ever reaches this function, its name wins over the run identity.
$h = Get-PgLoginFailureHint -StdErr 'LOG:  no match in usermap "veeam" for user "postgres" authenticated as "Administrator@HOST01"' -Identity 'NT AUTHORITY\SYSTEM' -Product 'VBR'
Check 'usermap miss is a pg_ident problem'     $h.Cause 'SSPI_MAP'
Check 'authenticated-as name is used'          ($h.Detail -match "'Administrator@HOST01'") 'True'
Check 'authenticated-as beats run identity'    ($h.Detail -match 'SYSTEM@NT AUTHORITY') 'False'
$h = Get-PgLoginFailureHint -StdErr 'FATAL:  SSPI authentication failed for user "postgres"' -Product 'VBR'
Check 'no identity still reads cleanly'        ($h.Detail -match 'the account this script runs as') 'True'

$h = Get-PgLoginFailureHint -StdErr 'psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  no pg_hba.conf entry for host "127.0.0.1", user "postgres", database "postgres", no encryption' -Product 'VBR'
Check 'no pg_hba entry is its own cause'       $h.Cause 'NO_HBA_ENTRY'
Check 'no pg_hba entry names pg_hba.conf'      ($h.Detail -match 'pg_hba\.conf has no line') 'True'
Check 'no pg_hba entry skips KB4542'           ($h.Detail -match 'KB4542') 'False'
Check 'no pg_hba entry gives the default line' ($h.Action -match 'host all all 127\.0\.0\.1/32 sspi map=veeam') 'True'
$h = Get-PgLoginFailureHint -StdErr 'psql: error: FATAL:  no pg_hba.conf entry for host "127.0.0.1", user "postgres", database "postgres", SSL off' -Product 'VBR'
Check 'psql 13 no pg_hba entry is its own'     $h.Cause 'NO_HBA_ENTRY'
# An explicit "reject" line is a different problem from a missing line.
$h = Get-PgLoginFailureHint -StdErr 'psql: error: connection to server at "127.0.0.1", port 5432 failed: FATAL:  pg_hba.conf rejects connection for host "127.0.0.1", user "postgres", database "postgres", no encryption' -Product 'VBR'
Check 'pg_hba reject is not a missing line'    ($h.Cause -eq 'NO_HBA_ENTRY') 'False'

# Anything else keeps the old message and the default RMM action.
$h = Get-PgLoginFailureHint -StdErr 'psql: error: connection to server at "127.0.0.1", port 5432 failed: Connection refused' -Product 'VBR'
Check 'other failure keeps generic cause'      $h.Cause 'UNKNOWN'
Check 'other failure keeps generic message'    ($h.Detail -match 'not mapped in pg_ident\.conf \(Veeam KB4542\)') 'True'
Check 'other failure sets no action'           $h.Action ''
# A server set to another language translates the FATAL text (German shown here), so
# it keeps the generic message.
$h = Get-PgLoginFailureHint -StdErr 'psql: Fehler: FATAL:  Passwort-Authentifizierung fuer Benutzer "postgres" fehlgeschlagen' -Product 'VBR'
Check 'translated failure keeps generic cause' $h.Cause 'UNKNOWN'
Check 'empty stderr does not throw'            (Throws { Get-PgLoginFailureHint -StdErr '' }) 'False'
Check 'null stderr is generic'                 (Get-PgLoginFailureHint -StdErr $null).Cause 'UNKNOWN'

# The RMM contract does not move: same issue code, same exit code.
Check 'STEP 6 uses the login hint'             ($scriptText -match "Get-PgLoginFailureHint -StdErr \`$verRes\.StdErr") 'True'
Check 'STEP 6 keeps PREFLIGHT PG_UNREACHABLE'  ($scriptText -match "Complete-Run \`$EXIT\.PREFLIGHT 'PG_UNREACHABLE' `"Could not query PostgreSQL as user 'postgres'\. \`$\(\`$loginHint\.Detail\)") 'True'
Check 'STEP 6 hint action reaches the RMM'     ($scriptText -match 'if \(\$loginHint\.Action\) \{ \$script:Report\.ActionRequired = \$loginHint\.Action \}') 'True'
# "VBR" must mean VBR's own database is on PostgreSQL, not just that VBR is installed.
Check 'STEP 6 picks VBR by its PG database'    ($scriptText -match "\`$loginProduct = if \(@\(\`$veeamDatabases \| Where-Object \{ \`$_\.Product -eq 'VBR' \}\)\.Count -gt 0\) \{ 'VBR' \} else \{ 'OTHER' \}") 'True'
Check 'STEP 6 passes the product on'           ($scriptText -match '-Product \$loginProduct') 'True'

'--- ConvertFrom-JsonArrayText (Windows PowerShell 5.1 does not enumerate) ---'
# On 5.1, ConvertFrom-Json returns the whole array as ONE object, so a database list
# reads as "System.Object[]" and VeeamBackup looks missing.
$names = @(ConvertFrom-JsonArrayText '["postgres","VeeamBackup"]')
Check 'array of strings: count'      $names.Count 2
Check 'array of strings: first'      $names[0] 'postgres'
Check 'array of strings: type'       $names[0].GetType().Name 'String'
Check 'empty JSON array'             @(ConvertFrom-JsonArrayText '[]').Count 0
Check 'single-item array'            @(ConvertFrom-JsonArrayText '["only"]')[0] 'only'
# pg_stat_activity returns objects, which must stay whole, not be flattened.
$clients = @(ConvertFrom-JsonArrayText '[{"pid":1,"user":"postgres"},{"pid":2,"user":"veeam"}]')
Check 'array of objects: count'      $clients.Count 2
Check 'array of objects: field kept' $clients[1].user 'veeam'
Check 'object is not flattened'      ($clients[0].pid) 1
# Names containing characters that could trip naive splitting.
$odd = @(ConvertFrom-JsonArrayText '["Veeam Backup","a,b","cache_12345678-1234-1234-1234-1234567890ab"]')
Check 'name with a space survives'   $odd[0] 'Veeam Backup'
Check 'name with a comma survives'   $odd[1] 'a,b'
Check 'every psql list uses helper'  ($scriptText -match '\$databaseListRes\.StdOut \| ConvertFrom-Json') 'False'
Check 'client list uses helper'      ($scriptText -match 'ConvertFrom-JsonArrayText \$clientActivityResult\.StdOut') 'True'
Check 'final list uses helper'       ($scriptText -match 'ConvertFrom-JsonArrayText \$finalListRes\.StdOut') 'True'

'--- Resolve-VeeamDatabaseNames (database name case mismatch) ---'
# VBR records "VeeamBackup"; a cluster can hold the name in a different case.
$cfg = @([pscustomobject]@{ Product='VBR'; Database='VeeamBackup'; Port=5432 })
$r = Resolve-VeeamDatabaseNames -Records $cfg -ActualNames @('postgres','veeambackup')
Check 'different case still resolves'   @($r.Resolved).Count 1
Check 'the server name wins'            @($r.Resolved)[0].Database 'veeambackup'
Check 'port and product preserved'      "$(@($r.Resolved)[0].Product)/$(@($r.Resolved)[0].Port)" 'VBR/5432'
Check 'rename is reported'              "$(@($r.Renamed)[0].Configured) -> $(@($r.Renamed)[0].Actual)" 'VeeamBackup -> veeambackup'
Check 'nothing missing'                 @($r.Missing).Count 0
Check 'not ambiguous'                   ($null -eq $r.Ambiguous) 'True'

$exact = Resolve-VeeamDatabaseNames -Records $cfg -ActualNames @('postgres','VeeamBackup')
Check 'exact match: no rename noise'    @($exact.Renamed).Count 0
Check 'exact match: name kept'          @($exact.Resolved)[0].Database 'VeeamBackup'

$gone = Resolve-VeeamDatabaseNames -Records $cfg -ActualNames @('postgres','SomethingElse')
Check 'genuinely absent is reported'    @($gone.Missing)[0] 'VeeamBackup'
Check 'absent resolves nothing'         @($gone.Resolved).Count 0

# Two names differing only by case: the script must not pick one.
$ambiguous = Resolve-VeeamDatabaseNames -Records $cfg -ActualNames @('VeeamBackup','veeambackup')
Check 'case clash is ambiguous'         ($null -ne $ambiguous.Ambiguous) 'True'
Check 'ambiguous resolves nothing'      @($ambiguous.Resolved).Count 0
Check 'ambiguous names both listed'     (@($ambiguous.Ambiguous.Matches) -join ',') 'VeeamBackup,veeambackup'

# VB365: config DB plus a cache DB, mixed case.
$vbo = @(
    [pscustomobject]@{ Product='VB365'; Database='VeeamBackup365'; Port=5432 }
    [pscustomobject]@{ Product='VB365Cache'; Database='cache_12345678-1234-1234-1234-1234567890ab'; Port=5432 }
)
$vboResolved = Resolve-VeeamDatabaseNames -Records $vbo -ActualNames @('postgres','veeambackup365','cache_12345678-1234-1234-1234-1234567890ab')
Check 'VB365 both resolve'              @($vboResolved.Resolved).Count 2
Check 'VB365 config DB adopts server'   @($vboResolved.Resolved)[0].Database 'veeambackup365'
Check 'VB365 cache DB unchanged'        @($vboResolved.Resolved)[1].Database 'cache_12345678-1234-1234-1234-1234567890ab'
Check 'empty record set is fine'        @((Resolve-VeeamDatabaseNames -Records @() -ActualNames @('postgres')).Resolved).Count 0
Check 'cluster contents are logged'     ($scriptText -match 'PostgreSQL cluster holds database\(s\)') 'True'
Check 'missing message lists contents'  ($scriptText -match 'This cluster holds: \$\(@\(\$actualDatabases\) -join') 'True'
# Probing optional registry values must not print TerminatingError into the log.
Check 'registry read avoids Get-ItemProperty -Name' ($scriptText -match 'Get-ItemProperty -Path \$Key -Name \$Name') 'False'
Check 'registry read uses GetValue'     ($scriptText -match '\$item\.GetValue\(\$Name\)') 'True'

'--- Reconnecting VBR after its service restarts ---'
# The VBR module keeps a live connection to the Veeam Backup Service. Restarting that
# service drops it, so the script must reconnect before its final activity check.
Check 'VBR reconnect: disconnect first'  ($scriptText -match 'Disconnect-VBRServer -ErrorAction Stop') 'True'
Check 'VBR reconnect: connect local'    ($scriptText -match 'Connect-VBRServer -Server localhost -ErrorAction Stop') 'True'
Check 'missing Connect-VBRServer fails' ($scriptText -match 'Connect-VBRServer is unavailable, so the VBR connection cannot be re-established') 'True'
Check 'post-start reconnects both'      ($scriptText -match 'Connect-VeeamModules -Vbr:\$hasVbr -Vb365:\$hasVb365 -Quiet -Reconnect\)') 'True'
Check 'recovery reconnects both'        ($scriptText -match 'Connect-VeeamModules -Vbr:\$hasVbr -Vb365:\$hasVb365 -Reconnect\)') 'True'
Check 'no VB365-only reconnect left'    ($scriptText -match 'Connect-VeeamModules .*-Reconnect:\$hasVb365') 'False'
Check 'lost-connection matcher: Veeam'  (Test-VbrConnectionLostError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'Remote connection was terminated. Either re-establish remote connection or use local one, ex. Connect-VBRServer -Server localhost' } })) 'True'
Check 'lost-connection matcher: other'  (Test-VbrConnectionLostError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'Access is denied' } })) 'False'
Check 'retry is bounded at 3'           ($scriptText -match 'if \(\$tries -lt 3\)') 'True'

'--- Patience for VBR 13 slow service starts ---'
Check 'settle window is 10 minutes'     ($scriptText -match '\$script:ServiceSettleMinutes = 10') 'True'
Check 'settle window read defensively'  ($scriptText -match "Get-Variable -Name ServiceSettleMinutes -Scope Script -ValueOnly -ErrorAction SilentlyContinue") 'True'
Check 'settle loop has a deadline'      ($scriptText -match '\$settleDeadline = \(Get-Date\)\.AddMinutes\(\$settleMinutes\)') 'True'
Check 'settle loop logs progress'       ($scriptText -match 'waiting for \$\(\$pending\.Count\) service\(s\) to settle') 'True'
Check 'identity service reason recorded' ($scriptText -match 'Identity Service as a CHILD PROCESS') 'True'

'--- Get-VeeamServiceStartOrder (example VBR 13 dependency layout) ---'
# Deliberately listed in the alphabetical order Get-Service returns, which puts two
# dependents BEFORE the service they need.
$vbrSnapshot = @(
    [pscustomobject]@{ Name='VeeamAHVSvc';           DependsOn=@('RpcSs','Winmgmt') }
    [pscustomobject]@{ Name='VeeamBackupCdpSvc';     DependsOn=@('RpcSs','VeeamBackupSvc') }
    [pscustomobject]@{ Name='VeeamBackupRESTSvc';    DependsOn=@('Winmgmt','RpcSs','VeeamBackupSvc') }
    [pscustomobject]@{ Name='VeeamBackupSvc';        DependsOn=@('RpcSs','Winmgmt') }
    [pscustomobject]@{ Name='VeeamBrokerSvc';        DependsOn=@('RpcSs','VeeamBackupSvc') }
    [pscustomobject]@{ Name='VeeamCloudSvc';         DependsOn=@('RpcSs','VeeamBackupSvc') }
    [pscustomobject]@{ Name='VeeamDataAnalyzerSvc';  DependsOn=@('RpcSs','VeeamBackupSvc') }
    [pscustomobject]@{ Name='VeeamGCPSvc';           DependsOn=@() }
    [pscustomobject]@{ Name='VeeamTransportSvc';     DependsOn=@('RpcSs','Winmgmt') }
    [pscustomobject]@{ Name='VeeamWebSvc';           DependsOn=@('VeeamBackupRESTSvc','RpcSs','VeeamBackupSvc') }
)
$order = @(Get-VeeamServiceStartOrder $vbrSnapshot | ForEach-Object { $_.Name })
function IndexOfName($list, $name) { [array]::IndexOf($list, $name) }
Check 'every service is returned once'   $order.Count 10
Check 'no service is lost'               (@($order | Sort-Object -Unique).Count) 10
Check 'BackupSvc before CdpSvc'          ((IndexOfName $order 'VeeamBackupSvc') -lt (IndexOfName $order 'VeeamBackupCdpSvc')) 'True'
Check 'BackupSvc before RESTSvc'         ((IndexOfName $order 'VeeamBackupSvc') -lt (IndexOfName $order 'VeeamBackupRESTSvc')) 'True'
Check 'BackupSvc before BrokerSvc'       ((IndexOfName $order 'VeeamBackupSvc') -lt (IndexOfName $order 'VeeamBrokerSvc')) 'True'
Check 'BackupSvc before CloudSvc'        ((IndexOfName $order 'VeeamBackupSvc') -lt (IndexOfName $order 'VeeamCloudSvc')) 'True'
Check 'BackupSvc before DataAnalyzer'    ((IndexOfName $order 'VeeamBackupSvc') -lt (IndexOfName $order 'VeeamDataAnalyzerSvc')) 'True'
Check 'RESTSvc before WebSvc'            ((IndexOfName $order 'VeeamBackupRESTSvc') -lt (IndexOfName $order 'VeeamWebSvc')) 'True'
Check 'independent ones keep order'      ((IndexOfName $order 'VeeamAHVSvc') -lt (IndexOfName $order 'VeeamTransportSvc')) 'True'
Check 'Windows-only deps are ignored'    ((IndexOfName $order 'VeeamAHVSvc') -eq 0) 'True'
# A dependency cycle must not drop services or loop forever.
$cycle = @(
    [pscustomobject]@{ Name='A'; DependsOn=@('B') }
    [pscustomobject]@{ Name='B'; DependsOn=@('A') }
    [pscustomobject]@{ Name='C'; DependsOn=@() }
)
$cycleOrder = @(Get-VeeamServiceStartOrder $cycle | ForEach-Object { $_.Name })
Check 'cycle keeps every service'        $cycleOrder.Count 3
Check 'cycle puts the free one first'    $cycleOrder[0] 'C'
# A missing DependsOn property (an older recovery file) must not throw.
Check 'missing DependsOn tolerated'      (@(Get-VeeamServiceStartOrder @([pscustomobject]@{ Name='X' })).Count) 1
Check 'empty snapshot tolerated'         (@(Get-VeeamServiceStartOrder @()).Count) 0

'--- Installer resolution prefers the file host over the download page ---'
Check 'direct probe exists'              ($scriptText -match 'function Resolve-PgInstallerDirectUrl') 'True'
Check 'direct probe tried first'         ($scriptText -match '\$direct = Resolve-PgInstallerDirectUrl \$Version\s*\r?\n\s*if \(\$direct\) \{ return \$direct \}') 'True'
Check 'build suffix is probed, not fixed' ($scriptText -match 'foreach \(\$suffix in 5, 4, 3, 2, 1\)') 'True'
Check 'only HTTP 200 counts as found'    ($scriptText -match 'if \(\$head\.StatusCode -ne 200\) \{ continue \}') 'True'
Check 'page scrape retries'              ($scriptText -match 'EnterpriseDB page attempt \$attempt/3 failed') 'True'
Check 'page scrape sends a user agent'   ($scriptText -match '-UserAgent \$userAgent') 'True'
Check 'host allowlist still enforced'    ($scriptText -match "notin @\('sbp\.enterprisedb\.com','get\.enterprisedb\.com','www\.enterprisedb\.com'\)") 'True'

'--- Test-CommandCallableBare (getters that cannot be called bare) ---'
# Shaped like Get-VBRSession: every parameter set demands something.
function Get-FakeSessionNeedsId {
    [CmdletBinding(DefaultParameterSetName='Job')]
    param(
        [Parameter(Mandatory, ParameterSetName='Job')] $Job,
        [Parameter(Mandatory, ParameterSetName='Id')] $Id,
        [Parameter(Mandatory, ParameterSetName='Session')] $Session
    )
}
# Shaped like Get-VBRBackupSession: a default set where everything is optional.
function Get-FakeSessionOptional {
    [CmdletBinding(DefaultParameterSetName='Name')]
    param(
        [Parameter(ParameterSetName='Name')] $Name,
        [Parameter(Mandatory, ParameterSetName='Id')] $Id
    )
}
function Get-FakeSessionNoParams { param() }
Check 'mandatory-only sets: not bare'   (Test-CommandCallableBare 'Get-FakeSessionNeedsId')   'False'
Check 'optional default set: bare OK'   (Test-CommandCallableBare 'Get-FakeSessionOptional')  'True'
Check 'no parameters at all: bare OK'   (Test-CommandCallableBare 'Get-FakeSessionNoParams')  'True'
Check 'absent command: not bare'        (Test-CommandCallableBare 'Get-NoSuchCommandAtAll')   'False'
Check 'idle check guards core getters'  ($scriptText -match 'has no all-sessions parameter set on this build, so VBR activity cannot be checked safely') 'True'
# A runtime refusal must be recognised, and every failure must name its command.
function Get-FakeRefusingGetter { [CmdletBinding()] param([string]$Name) throw 'Specify either -Id or -Session parameter' }
function Get-FakeBrokenGetter   { [CmdletBinding()] param([string]$Name) throw 'the server is on fire' }
function Get-FakeWorkingGetter  { [CmdletBinding()] param([string]$Name) 'session-a'; 'session-b' }
$refusal = $null
try { Get-SessionsFromGetter 'Get-FakeRefusingGetter' } catch { $refusal = $_ }
Check 'runtime refusal is NotSupported'  ($refusal.Exception -is [System.NotSupportedException]) 'True'
Check 'refusal names the command'        ($refusal.Exception.Message -match 'Get-FakeRefusingGetter') 'True'
$broken = $null
try { Get-SessionsFromGetter 'Get-FakeBrokenGetter' } catch { $broken = $_ }
Check 'other failure is NOT NotSupported' ($broken.Exception -is [System.NotSupportedException]) 'False'
Check 'other failure names the command'  ($broken.Exception.Message -match 'Get-FakeBrokenGetter') 'True'
Check 'other failure keeps the reason'   ($broken.Exception.Message -match 'server is on fire') 'True'
Check 'working getter returns sessions'  (@(Get-SessionsFromGetter 'Get-FakeWorkingGetter').Count) 2
# A refused getter must be remembered, so a polling install run does not pay for it
# every pass, and must be warned about only once.
$script:UnusableSessionGetters = @{}
$script:FakeRefuseCalls = 0
function Get-FakeCountingRefuser { [CmdletBinding()] param() $script:FakeRefuseCalls++; throw 'Specify either -Id or -Session parameter' }
for ($i = 1; $i -le 3; $i++) { try { Get-SessionsFromGetter 'Get-FakeCountingRefuser' } catch {} }
Check 'refused getter called once only' $script:FakeRefuseCalls 1
Check 'refused getter is remembered'    (Test-UnusableSessionGetter 'Get-FakeCountingRefuser') 'True'
$warned = 0
function Write-Log { param($Message, $Level) if ("$Level" -eq 'WARN') { $script:warned++ } }
Write-UnusableSessionGetterOnce 'Get-FakeCountingRefuser' ' suffix'
Write-UnusableSessionGetterOnce 'Get-FakeCountingRefuser' ' suffix'
Write-UnusableSessionGetterOnce 'Get-FakeCountingRefuser' ' suffix'
Check 'warned exactly once'             $warned 1
function Write-Log { param($Message, $Level) }
Check 'unknown getter warns not at all' (Write-UnusableSessionGetterOnce 'Get-NeverSeenGetter') ''
$script:UnusableSessionGetters = @{}
Check 'refusal matcher: Veeam wording'   (Test-NoAllSessionsError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'Specify either -Id or -Session parameter' } })) 'True'
Check 'refusal matcher: unrelated text'  (Test-NoAllSessionsError ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = 'Access is denied' } })) 'False'
# A multi-kilobyte Veeam dependency error must not swamp the one-line RMM summary.
$longText = ("word " * 500) + 'END'
Check 'long text is truncated'           ((Format-ShortText $longText 600).Length -le 650) 'True'
Check 'truncation is marked'             ((Format-ShortText $longText 600) -match 'truncated, full text in the log') 'True'
Check 'short text is untouched'          (Format-ShortText 'all good' 600) 'all good'
Check 'newlines are flattened'           (Format-ShortText "a`r`nb`tc" 600) 'a b c'
Check 'empty text stays empty'           (Format-ShortText '' 600) ''
Check 'Explorer failures never fatal'    ($scriptText -match 'it was not queried\. The Explorer process barrier still applies') 'True'
Check 'configured family fails closed'  ($scriptText -match 'cannot be checked safely"\)\s*\r?\n\s*\}\s*\r?\n\s*Write-Log "  \$\(\$collector\.Command\) has no all-sessions') 'True'

'--- Get-VeeamRegistryPostgresDatabase (throwaway HKCU keys, Veeam KB1471 layout) ---'
$dbKeyRoot = "HKCU:\Software\VpguDbLayoutTest-$PID"
try {
    # A PostgreSQL product, exactly as KB1471 documents it.
    $pgProduct = "$dbKeyRoot\PgProduct"
    New-Item -Path "$pgProduct\DatabaseConfigurations\PostgreSql" -Force | Out-Null
    New-ItemProperty -Path "$pgProduct\DatabaseConfigurations" -Name 'SqlActiveConfiguration' -Value 'PostgreSql' -Force | Out-Null
    New-ItemProperty -Path "$pgProduct\DatabaseConfigurations\PostgreSql" -Name 'SqlHostName' -Value 'localhost' -Force | Out-Null
    New-ItemProperty -Path "$pgProduct\DatabaseConfigurations\PostgreSql" -Name 'SqlHostPort' -Value '5432' -Force | Out-Null
    New-ItemProperty -Path "$pgProduct\DatabaseConfigurations\PostgreSql" -Name 'SqlDatabaseName' -Value 'VeeamBackupReporting' -Force | Out-Null
    $pgRead = Get-VeeamRegistryPostgresDatabase -ProductKey $pgProduct -Label 'EM test'
    Check 'EM PostgreSQL read: kind'      $pgRead.Kind     'POSTGRES'
    Check 'EM PostgreSQL read: host'      $pgRead.Host     'localhost'
    Check 'EM PostgreSQL read: port'      $pgRead.Port     5432
    Check 'EM PostgreSQL read: database'  $pgRead.Database 'VeeamBackupReporting'

    # MS SQL: a real answer, not an error - the engine simply is not PostgreSQL.
    $msProduct = "$dbKeyRoot\MsProduct"
    New-Item -Path "$msProduct\DatabaseConfigurations" -Force | Out-Null
    New-ItemProperty -Path "$msProduct\DatabaseConfigurations" -Name 'SqlActiveConfiguration' -Value 'MsSql' -Force | Out-Null
    Check 'EM MS SQL read'                (Get-VeeamRegistryPostgresDatabase -ProductKey $msProduct -Label 'EM test').Kind 'MSSQL'

    # Everything incomplete or unexpected must be UNKNOWN, never a guessed default.
    Check 'no DatabaseConfigurations key'  (Get-VeeamRegistryPostgresDatabase -ProductKey "$dbKeyRoot\Missing" -Label 'EM test').Kind 'UNKNOWN'
    $noEngine = "$dbKeyRoot\NoEngine"; New-Item -Path "$noEngine\DatabaseConfigurations" -Force | Out-Null
    Check 'no SqlActiveConfiguration'      (Get-VeeamRegistryPostgresDatabase -ProductKey $noEngine -Label 'EM test').Kind 'UNKNOWN'
    New-ItemProperty -Path "$noEngine\DatabaseConfigurations" -Name 'SqlActiveConfiguration' -Value 'Oracle' -Force | Out-Null
    Check 'unexpected engine name'         (Get-VeeamRegistryPostgresDatabase -ProductKey $noEngine -Label 'EM test').Kind 'UNKNOWN'
    $partial = "$dbKeyRoot\Partial"
    New-Item -Path "$partial\DatabaseConfigurations\PostgreSql" -Force | Out-Null
    New-ItemProperty -Path "$partial\DatabaseConfigurations" -Name 'SqlActiveConfiguration' -Value 'PostgreSql' -Force | Out-Null
    New-ItemProperty -Path "$partial\DatabaseConfigurations\PostgreSql" -Name 'SqlHostName' -Value 'localhost' -Force | Out-Null
    Check 'missing port and database'      (Get-VeeamRegistryPostgresDatabase -ProductKey $partial -Label 'EM test').Kind 'UNKNOWN'
    New-ItemProperty -Path "$partial\DatabaseConfigurations\PostgreSql" -Name 'SqlHostPort' -Value 'notaport' -Force | Out-Null
    New-ItemProperty -Path "$partial\DatabaseConfigurations\PostgreSql" -Name 'SqlDatabaseName' -Value 'db' -Force | Out-Null
    Check 'non-numeric port'               (Get-VeeamRegistryPostgresDatabase -ProductKey $partial -Label 'EM test').Kind 'UNKNOWN'
    Set-ItemProperty -Path "$partial\DatabaseConfigurations\PostgreSql" -Name 'SqlHostPort' -Value '70000'
    Check 'out-of-range port'              (Get-VeeamRegistryPostgresDatabase -ProductKey $partial -Label 'EM test').Kind 'UNKNOWN'
} finally {
    Remove-Item -LiteralPath $dbKeyRoot -Recurse -Force -ErrorAction SilentlyContinue
}
Check 'EM supported only beside VBR'  ($scriptText -match "hasEnterpriseManager -and -not \`$hasVbr") 'True'
Check 'EM database joins the dump set' ($scriptText -match "Product='EnterpriseManager'; Database=\`$emDb\.Database") 'True'

'--- Remove-StaleVeeamRegistryRecord (throwaway HKCU key, never a real Veeam key) ---'
$testKeyPath = "HKCU:\Software\VpguStaleRecordTest-$PID"
$testBackup  = Join-Path $env:TEMP "vpgu-stale-record-$PID.reg"
try {
    New-Item -Path $testKeyPath -Force | Out-Null
    New-ItemProperty -Path $testKeyPath -Name 'CorePath' -Value 'C:\nowhere' -PropertyType String -Force | Out-Null
    $returned = Remove-StaleVeeamRegistryRecord -Key $testKeyPath -BackupPath $testBackup
    Check 'key is removed'                (Test-Path -LiteralPath $testKeyPath) 'False'
    Check 'backup path returned'           ($returned -eq $testBackup) 'True'
    Check 'backup file exists'             (Test-Path -LiteralPath $testBackup) 'True'
    Check 'backup holds the value'         ((Get-Content -LiteralPath $testBackup -Raw) -match 'CorePath') 'True'
    Check 'missing key throws'             (Throws { Remove-StaleVeeamRegistryRecord -Key $testKeyPath -BackupPath $testBackup }) 'True'
    Check 'unsupported hive throws'        (Throws { Remove-StaleVeeamRegistryRecord -Key 'HKLM:\SOFTWARE' -BackupPath 'X:\no\such\path\x.reg' }) 'True'
    # An unwritable backup path must stop the deletion, not proceed without a backup.
    New-Item -Path $testKeyPath -Force | Out-Null
    Check 'no backup means no delete'      (Throws { Remove-StaleVeeamRegistryRecord -Key $testKeyPath -BackupPath 'X:\no\such\path\x.reg' }) 'True'
    Check 'key survives a failed backup'   (Test-Path -LiteralPath $testKeyPath) 'True'
} finally {
    Remove-Item -LiteralPath $testKeyPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $testBackup -Force -ErrorAction SilentlyContinue
}

'--- NATS: same-line update policy (an update, never an upgrade) ---'
$natsPolicy = Get-NatsPolicy
$natsList = @($natsPolicy.SupportedByVb365['8.6'])
function Get-TestNatsTarget([string] $Installed) { Resolve-NatsTarget -Installed $Installed -Supported $natsList }
Check 'VB365 8.6 list is exact'              ($natsList -join ',') '2.10.18,2.10.22,2.10.28,2.12.5,2.12.8'
Check 'every pinned package is on the list'  (@($natsPolicy.PackageSha256.Keys | Where-Object { $natsList -notcontains $_ }).Count) 0
Check 'pinned hashes are SHA256 hex'         (@($natsPolicy.PackageSha256.Values | Where-Object { $_ -cnotmatch '^[0-9a-f]{64}$' }).Count) 0
Check '2.10.28 hash is the published one'    $natsPolicy.PackageSha256['2.10.28'] '98b8571231b00ebe0445cc7f317f6425c1fbc2edecd455949d37022e04281657'
Check '2.12.8 hash is the published one'     $natsPolicy.PackageSha256['2.12.8'] '61836ff8d0cecbb773faf7daa22f5212b7ed3ab5a0c58c12b013d67d64edd6cc'
$t = Get-TestNatsTarget '2.10.18'; Check '2.10.18 -> 2.10.28'               "$($t.Status) $($t.Target)" 'UPDATE_AVAILABLE 2.10.28'
$t = Get-TestNatsTarget '2.10.22'; Check '2.10.22 -> 2.10.28'               "$($t.Status) $($t.Target)" 'UPDATE_AVAILABLE 2.10.28'
$t = Get-TestNatsTarget '2.10.28'; Check '2.10.28 is current, never 2.12'   "$($t.Status)|$($t.Target)" 'CURRENT|'
$t = Get-TestNatsTarget '2.10.29'; Check '2.10.29 is ahead, never downgraded' "$($t.Status)|$($t.Target)" 'AHEAD|'
$t = Get-TestNatsTarget '2.12.5';  Check '2.12.5 -> 2.12.8'                 "$($t.Status) $($t.Target)" 'UPDATE_AVAILABLE 2.12.8'
$t = Get-TestNatsTarget '2.12.6';  Check 'unlisted 2.12.6 -> 2.12.8'        "$($t.Status) $($t.Target)" 'UPDATE_AVAILABLE 2.12.8'
$t = Get-TestNatsTarget '2.12.8';  Check '2.12.8 is current'                $t.Status 'CURRENT'
$t = Get-TestNatsTarget '2.12.9';  Check '2.12.9 is ahead'                  $t.Status 'AHEAD'
$t = Get-TestNatsTarget '2.11.4';  Check '2.11.4 has no line to update on'  "$($t.Status)|$($t.Target)" 'UNLISTED|'
$t = Get-TestNatsTarget '2.14.0';  Check '2.14.0 is left alone'             "$($t.Status)|$($t.Target)" 'UNLISTED|'
$t = Resolve-NatsTarget -Installed '2.10.22' -Supported @('2.10.22','2.10.30')
Check 'a version Veeam adds becomes the target' "$($t.Status) $($t.Target)" 'UPDATE_AVAILABLE 2.10.30'
$crossLine = @(foreach ($v in @('2.10.18','2.10.22','2.10.28','2.10.29','2.11.0','2.12.5','2.12.6','2.12.7','2.12.8','2.14.1')) {
    $r = Get-TestNatsTarget $v
    if ($r.Target -and (([version]$r.Target).Major -ne ([version]$v).Major -or ([version]$r.Target).Minor -ne ([version]$v).Minor)) { $v }
    if ($r.Target -and $r.Status -eq 'UPDATE_AVAILABLE' -and [version]$r.Target -le [version]$v) { "$v down" }
})
Check 'no version moves to another line or down' ($crossLine -join ',') ''
Check 'VB365 8.6 file version maps to 8.6'   (Get-Vb365ReleaseKey '13.6.0.0') '8.6'
Check 'VB365 8.6 build number maps to 8.6'   (Get-Vb365ReleaseKey '8.6.0.1102') '8.6'
Check 'a later VB365 maps to its own release' (Get-Vb365ReleaseKey '13.7.0.0') '8.7'
Check '13.60 is not 13.6'                    (Get-Vb365ReleaseKey '13.60.0.0') '8.60'
Check 'VB365 7 has no NATS release key'      (Get-Vb365ReleaseKey '7.1.0.1413') ''
Check 'unknown VB365 version has no list'    (Get-Vb365ReleaseKey 'Unknown') ''

'--- NATS: service command line ---'
$natsRootT = 'C:\Program Files\NATS'
$img = ConvertFrom-NatsImagePath -PathName '"C:\Program Files\NATS\nats-server-v2.10.22-windows-amd64\nats-server.exe" -c "C:\ProgramData\NATS\nats-server.conf"' -NatsRoot $natsRootT
Check 'program read'                 $img.Exe 'C:\Program Files\NATS\nats-server-v2.10.22-windows-amd64\nats-server.exe'
Check 'config file read'             $img.ConfPath 'C:\ProgramData\NATS\nats-server.conf'
Check 'folder version read'          $img.FolderVersion '2.10.22'
Check 'arguments kept exactly'       $img.Arguments ' -c "C:\ProgramData\NATS\nats-server.conf"'
$img = ConvertFrom-NatsImagePath -PathName '"C:\Program Files\NATS\nats\nats-server.exe" --config=C:\ProgramData\NATS\nats-server.conf' -NatsRoot $natsRootT
Check '--config= form read'          $img.ConfPath 'C:\ProgramData\NATS\nats-server.conf'
Check 'unversioned folder is allowed' $img.FolderVersion ''
$img = ConvertFrom-NatsImagePath -PathName 'C:\Program Files\NATS\nats-server-v2.10.22-windows-amd64\nats-server.exe -c C:\ProgramData\NATS\nats-server.conf' -NatsRoot $natsRootT
Check 'unquoted program path read'   $img.Exe 'C:\Program Files\NATS\nats-server-v2.10.22-windows-amd64\nats-server.exe'
function Get-TestImageError([string] $PathName) { try { [void](ConvertFrom-NatsImagePath -PathName $PathName -NatsRoot $natsRootT); '' } catch { $_.Exception.Message } }
$e = Get-TestImageError '"C:\Program Files\NATS\v\nats-server.exe" -c "C:\x\n.conf" --pass s3cretValue'
Check 'extra flag refused'           ($e -match 'flags found: -c --pass') 'True'
Check 'flag value never shown'       ($e -match 's3cretValue') 'False'
Check 'no config file refused'       ((Get-TestImageError '"C:\Program Files\NATS\v\nats-server.exe"') -match 'not exactly -c') 'True'
Check 'another program refused'      ((Get-TestImageError '"C:\Program Files\NATS\v\other.exe" -c "C:\x\n.conf"') -match 'not nats-server\.exe') 'True'
Check 'program outside NATS refused' ((Get-TestImageError '"C:\Tools\nats\nats-server.exe" -c "C:\x\n.conf"') -match 'not in a version folder') 'True'
Check 'program nested deeper refused' ((Get-TestImageError '"C:\Program Files\NATS\a\b\nats-server.exe" -c "C:\x\n.conf"') -match 'not in a version folder') 'True'
Check 'relative config refused'      ((Get-TestImageError '"C:\Program Files\NATS\v\nats-server.exe" -c nats.conf') -match 'not a local absolute path') 'True'
Check 'version line read'            (ConvertFrom-NatsVersionText "nats-server: v2.10.22`r`n") '2.10.22'
Check 'other text is no version'     (ConvertFrom-NatsVersionText 'nats-server version 2.10.22') ''
Check 'empty text is no version'     (ConvertFrom-NatsVersionText '') ''

'--- NATS: config file ---'
$conf1 = @'
# Example layout, as the VB365 installer writes it
listen: 127.0.0.1:4222
http_port: 8222
jetstream {
    store_dir: "C:\\ProgramData\\Veeam\\Backup365\\nats"
    max_memory_store: 1GB   # a comment after a value
}
authorization {
    user: admin
    password: "$2a$11$abc{}#not-a-comment"
}
log_file: 'C:\ProgramData\NATS\nats.log'
websocket { port: 8080, no_tls: true }
accounts: { A: { users: [ { user: a, password: "x]}" } ] } }
'@
$f = Get-NatsConfFacts $conf1
Check 'store_dir read and unescaped' ($f.StoreDirs -join '|') 'C:\ProgramData\Veeam\Backup365\nats'
Check 'port from listen, not websocket' $f.Port 4222
Check 'version asked on the listen address' $f.ProbeHost '127.0.0.1'
Check 'nothing refused'              ($f.Refused -join ',') ''
$entries = @(Read-NatsConfText $conf1)
Check 'block path recorded'          (@($entries | Where-Object { $_.Key -eq 'store_dir' })[0].Path) 'jetstream.store_dir'
Check 'braces in a password are text' (@($entries | Where-Object { $_.Path -eq 'authorization.password' }).Count) 1
Check 'a list is skipped whole'      (@($entries | Where-Object { $_.Path -eq 'accounts.A.users' })[0].Kind) 'List'
$f = Get-NatsConfFacts "port = 4333`njetstream { store_dir = `"D:/nats-store/js`", max_file_store: 10G }"
Check 'one-line block store_dir'     ($f.StoreDirs -join '|') 'D:/nats-store/js'
Check 'port key read'                $f.Port 4333
$f = Get-NatsConfFacts "jetstream { store_dir: 'C:\data\nats' }`ninclude ./auth.conf`ncluster { name: c1, listen: 0.0.0.0:6222 }`nleafnodes { remotes = [ { url: `"nats://hub:7422`" } ] }"
Check 'include, cluster, leafnodes refused' ($f.Refused -join ',') 'cluster,include,leafnodes'
Check 'cluster listen is not the client port' $f.Port 4222
$f = Get-NatsConfFacts "jetstream { store_dir: 'C:\a\b' }`nother { store_dir: 'C:\c\d' }"
Check 'two store_dir settings counted' $f.StoreDirs.Count 2
$f = Get-NatsConfFacts "port: 4222`nlisten: 0.0.0.0:4333`njetstream { store_dir: 'C:\a\b' }"
Check 'port and listen disagree'     ($f.Refused -join ',') 'port and listen disagree'
$f = Get-NatsConfFacts "listen: 0.0.0.0:4222`njetstream { store_dir: 'C:\a\b' }"
Check 'any-address listen is asked on 127.0.0.1' $f.ProbeHost '127.0.0.1'
$f = Get-NatsConfFacts "listen: 10.20.30.40:4222`njetstream { store_dir: 'C:\a\b' }"
Check 'a specific listen address is asked there' $f.ProbeHost '10.20.30.40'
$f = Get-NatsConfFacts "jetstream { store_dir: 'C:\a\b' }"
Check 'no port means 4222'           $f.Port 4222
Check 'unbalanced braces refused'    (Throws { Get-NatsConfFacts "jetstream {`n store_dir: 'C:\a\b'" }) 'True'
Check 'unterminated string refused'  (Throws { Get-NatsConfFacts "jetstream { store_dir: `"C:\\a\\b }" }) 'True'
Check 'a stray brace refused'        (Throws { Get-NatsConfFacts "}`n" }) 'True'

'--- NATS: VB365 connection string and INFO line ---'
$c = ConvertFrom-NatsConnectionString 'nats://admin:AbC+/9z=@VBM-PILOT:4222?passwordEncrypted'
Check 'host read'                    $c.Host 'VBM-PILOT'
Check 'port read'                    $c.Port 4222
Check 'default port 4222'            (ConvertFrom-NatsConnectionString 'nats://localhost').Port 4222
Check 'IPv6 host read'               (ConvertFrom-NatsConnectionString 'nats://u:p@[::1]:4223').Host '::1'
function Get-TestConnError([string] $Text) { try { [void](ConvertFrom-NatsConnectionString $Text); '' } catch { $_.Exception.Message } }
$e = Get-TestConnError 'nats://admin:Secret1@a:4222,nats://admin:Secret1@b:4222'
Check 'a server list is refused'     ($e -match 'more than one') 'True'
Check 'the password is never shown'  ($e -match 'Secret1') 'False'
Check 'not nats:// refused'          ((Get-TestConnError 'http://a:4222') -ne '') 'True'
Check 'INFO version read'            (ConvertFrom-NatsInfoLine 'INFO {"server_id":"N","version":"2.10.28","proto":1,"jetstream":true}') '2.10.28'
Check 'an error line is no version'  (ConvertFrom-NatsInfoLine "-ERR 'Authorization Violation'") ''
Check 'broken JSON is no version'    (ConvertFrom-NatsInfoLine 'INFO {broken') ''
$listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
$listener.Start()
$infoPort = $listener.LocalEndpoint.Port
try {
    $serverPs = [powershell]::Create()
    [void]$serverPs.AddScript({
        param($Listener)
        $client = $Listener.AcceptTcpClient()
        $bytes = [Text.Encoding]::ASCII.GetBytes("INFO {`"server_id`":`"TEST`",`"version`":`"2.10.28`",`"proto`":1}`r`n")
        $stream = $client.GetStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        Start-Sleep -Milliseconds 500
        $client.Close()
    }).AddArgument($listener)
    $serverRun = $serverPs.BeginInvoke()
    Check 'version read from a live INFO line' (Get-NatsInfoVersion -HostName '127.0.0.1' -Port $infoPort) '2.10.28'
    [void]$serverPs.EndInvoke($serverRun)
    $serverPs.Dispose()
} finally {
    $listener.Stop()
}
Check 'nothing listening gives no version' (Get-NatsInfoVersion -HostName '127.0.0.1' -Port $infoPort -TimeoutMs 1000) ''

'--- NATS: the supported list is read from the Veeam website ---'
$veeamPage = @'
<html><head><title>System Requirements</title></head><body>
<nav>Step 9. Configure NATS Server Step 10. Begin Installation</nav>
<table><tr><td>NATS</td><td><p>Local or remote installation of the NATS server 2.10.18, 2.10.22, 2.10.28, 2.12.5, 2.12.8.</p>
<p>Note: If you plan to use the NATS server other than the version included in the setup, you must install and maintain it yourself.</p></td></tr></table>
<div class="footer">Page updated 2026-09-04 Page content applies to build&nbsp;8.6.0.1102</div></body></html>
'@
$parsedPage = ConvertFrom-VeeamNatsRequirementsHtml $veeamPage
Check 'page build read'                ($parsedPage.Build) '8.6.0.1102'
Check 'page release read'              ($parsedPage.Release) '8.6'
Check 'page NATS list read'            ($parsedPage.Versions -join ',') '2.10.18,2.10.22,2.10.28,2.12.5,2.12.8'
$pageAnd = $veeamPage -replace '2\.12\.5, 2\.12\.8\.', '2.12.8, 2.12.10 and 2.12.9.'
Check 'a list with "and" is read in version order' ((ConvertFrom-VeeamNatsRequirementsHtml $pageAnd).Versions -join ',') '2.10.18,2.10.22,2.10.28,2.12.8,2.12.9,2.12.10'
Check 'no build named is refused'      (Throws { ConvertFrom-VeeamNatsRequirementsHtml ($veeamPage -replace 'Page content applies to build', 'Built for') }) 'True'
Check 'two builds named are refused'   (Throws { ConvertFrom-VeeamNatsRequirementsHtml ($veeamPage + '<p>Page content applies to build 8.7.0.100</p>') }) 'True'
Check 'no NATS list is refused'        (Throws { ConvertFrom-VeeamNatsRequirementsHtml ($veeamPage -replace 'NATS server 2', 'NATS release 2') }) 'True'
Check 'two different lists are refused' (Throws { ConvertFrom-VeeamNatsRequirementsHtml ($veeamPage + '<p>the NATS server 2.14.1</p>') }) 'True'
# Any other wording is refused, never read as a shorter list (review finding).
$enDash = [string][char]0x2013
foreach ($case in @(
    @{ Name='a range with a dash';       Page=($veeamPage -replace '2\.12\.5, 2\.12\.8', "2.12.5${enDash}2.12.8") },
    @{ Name='an ampersand separator';    Page=($veeamPage -replace '2\.12\.5, 2\.12\.8', '2.12.5 &amp; 2.12.8') },
    @{ Name='a semicolon separator';     Page=($veeamPage -replace '2\.10\.28, 2\.12\.5', '2.10.28; 2.12.5') },
    @{ Name='a bullet list';             Page=($veeamPage -replace 'NATS server 2\.10\.18, 2\.10\.22, 2\.10\.28, 2\.12\.5, 2\.12\.8\.', 'NATS server</p><ul><li>2.10.18</li><li>2.10.22</li><li>2.12.8</li></ul><p>.') },
    @{ Name='a "from ... to" range';     Page=($veeamPage -replace '2\.10\.18, 2\.10\.22, 2\.10\.28', '2.10.18 to 2.10.28') },
    @{ Name='a note after the list';     Page=($veeamPage -replace '2\.12\.8\.', '2.12.8, 2.12.10 (starting from build 8.6.1.20).') })) {
    Check "page wording refused: $($case.Name)" (Throws { ConvertFrom-VeeamNatsRequirementsHtml $case.Page }) 'True'
}
Check 'a list at the end of the text is read' ((ConvertFrom-VeeamNatsRequirementsHtml '<p>Page content applies to build 8.6.0.1102</p><p>NATS server 2.10.28 or 2.12.8</p>').Versions -join ',') '2.10.28,2.12.8'

# Windows PowerShell 5.1 decodes a page served without a charset as ISO-8859-1. The
# raw bytes are decoded as UTF-8 instead, so a no-break space stays one character.
& {
    $nbsp = [string][char]0x00A0
    $utf8Bytes = [Text.Encoding]::UTF8.GetBytes("NATS server${nbsp}2.10.28.")
    function Invoke-WebRequest {
        [CmdletBinding()] param($Uri, [switch] $UseBasicParsing, $TimeoutSec)
        if ($script:FakeWebMode -eq 'Stream') {
            [pscustomobject]@{ RawContentStream = (New-Object IO.MemoryStream (,$utf8Bytes)); Content = [Text.Encoding]::GetEncoding(28591).GetString($utf8Bytes) }
        } else {
            [pscustomobject]@{ Content = $utf8Bytes }
        }
    }
    $script:FakeWebMode = 'Stream'
    Check 'web text is decoded as UTF-8'      (Invoke-NatsWebText -Uri 'https://example.invalid/') "NATS server${nbsp}2.10.28."
    $script:FakeWebMode = 'Bytes'
    Check 'downloaded bytes are decoded too'  (Invoke-NatsWebText -Uri 'https://example.invalid/') "NATS server${nbsp}2.10.28."
}

$sums = "0000000000000000000000000000000000000000000000000000000000000001  nats-server-v2.12.9-linux-amd64.tar.gz`n" +
        "ABCDEF0000000000000000000000000000000000000000000000000000000002 *nats-server-v2.12.9-windows-amd64.zip`n" +
        "0000000000000000000000000000000000000000000000000000000000000003  nats-server-v2.12.9-windows-arm64.zip`n"
Check 'SHA256SUMS line for the Windows zip' (ConvertFrom-NatsSha256Sums -Text $sums -Version '2.12.9') 'abcdef0000000000000000000000000000000000000000000000000000000002'
Check 'no line for that version is no hash' (ConvertFrom-NatsSha256Sums -Text $sums -Version '2.12.8') ''
Check 'two different lines are no hash' (ConvertFrom-NatsSha256Sums -Text ($sums + "1111111111111111111111111111111111111111111111111111111111111111  nats-server-v2.12.9-windows-amd64.zip") -Version '2.12.9') ''

& {
    function Invoke-NatsWebText {
        param([string] $Uri, [int] $TimeoutSec)
        $script:WebAsked += $Uri
        if ($Uri -match 'helpcenter\.veeam\.com') { if ($script:FakePage) { return $script:FakePage }; throw 'The remote name could not be resolved' }
        if ($Uri -match '/v(\d+\.\d+\.\d+)/SHA256SUMS$' -and $script:FakeSums.ContainsKey($Matches[1])) { return $script:FakeSums[$Matches[1]] }
        throw 'Response status code does not indicate success: 404 (Not Found).'
    }
    $policy = Get-NatsPolicy
    $script:WebAsked = @(); $script:FakeSums = @{}

    $script:FakePage = $veeamPage
    $l = Get-NatsSupportedVersions -ReleaseKey '8.6' -Policy $policy
    Check "Veeam's page is used for its own release" "$($l.Source) $(@($l.Versions).Count)" 'Veeam 5'
    Check "the page asked is Veeam's requirements page" ($script:WebAsked[-1]) 'https://helpcenter.veeam.com/docs/vbo365/guide/vbo_system_requirements.html'
    $script:FakePage = $veeamPage -replace '2\.12\.8\.', '2.12.8, 2.12.9.'
    Check 'a version Veeam adds is picked up' ((Get-NatsSupportedVersions -ReleaseKey '8.6' -Policy $policy).Versions -join ',') '2.10.18,2.10.22,2.10.28,2.12.5,2.12.8,2.12.9'
    $script:FakePage = $veeamPage -replace '8\.6\.0\.1102', '8.7.0.100'
    $l = Get-NatsSupportedVersions -ReleaseKey '8.6' -Policy $policy
    Check 'a page for another release is not used' "$($l.Source) $($l.Detail -match 'describes VB365 8\.7')" 'BuiltIn True'
    $l = Get-NatsSupportedVersions -ReleaseKey '8.7' -Policy $policy
    Check 'a newer release than the server knows has its list' "$($l.Source) $(@($l.Versions).Count)" 'Veeam 5'
    $script:FakePage = $null
    $l = Get-NatsSupportedVersions -ReleaseKey '8.6' -Policy $policy
    Check 'offline: the built-in list is used' "$($l.Source) $($l.Detail -match 'could not be read')" 'BuiltIn True'
    $l = Get-NatsSupportedVersions -ReleaseKey '8.7' -Policy $policy
    Check 'offline with no built-in list: none' "$($l.Source) $(@($l.Versions).Count)" 'None 0'
    $script:FakePage = $veeamPage + '<p>the NATS server 2.14.1</p>'
    Check 'an unreadable page falls back' ((Get-NatsSupportedVersions -ReleaseKey '8.6' -Policy $policy).Source) 'BuiltIn'
    $script:FakePage = $veeamPage
    Check 'an unknown release is never matched' ((Get-NatsSupportedVersions -ReleaseKey '' -Policy $policy).Source) 'None'

    $pin = $policy.PackageSha256['2.10.28']
    $script:FakeSums = @{ '2.10.28' = "$pin  nats-server-v2.10.28-windows-amd64.zip" }
    $h = Resolve-NatsPackageSha256 -Version '2.10.28' -Policy $policy
    Check 'pinned and published agree'     "$($h.Source) $($h.Sha256 -eq $pin) $($h.Detail -match 'matching')" 'Pinned True True'
    $script:FakeSums = @{}
    $h = Resolve-NatsPackageSha256 -Version '2.10.28' -Policy $policy
    Check 'pinned, published unreadable'   "$($h.Source) $($h.Sha256 -eq $pin)" 'Pinned True'
    $script:FakeSums = @{ '2.10.28' = ('f' * 64) + '  nats-server-v2.10.28-windows-amd64.zip' }
    $h = Resolve-NatsPackageSha256 -Version '2.10.28' -Policy $policy
    Check 'pinned and published differ: no hash' "$($h.Source) [$($h.Sha256)] $($h.Detail -match 'changed after it was published')" 'Conflict [] True'
    $script:FakeSums = @{ '2.12.9' = ('a' * 64) + '  nats-server-v2.12.9-windows-amd64.zip' }
    $h = Resolve-NatsPackageSha256 -Version '2.12.9' -Policy $policy
    Check 'a new version uses the published hash' "$($h.Source) $($h.Sha256 -eq ('a' * 64))" 'SHA256SUMS True'
    Check 'the hash comes from that release' ($script:WebAsked[-1]) 'https://github.com/nats-io/nats-server/releases/download/v2.12.9/SHA256SUMS'
    $script:FakeSums = @{}
    $h = Resolve-NatsPackageSha256 -Version '2.12.9' -Policy $policy
    Check 'a new version without a readable hash: none' "$($h.Source) [$($h.Sha256)]" 'None []'
}

'--- NATS: client connections ---'
& {
    function Get-NetTCPConnection {
        [CmdletBinding()] param($State, $LocalPort, $RemotePort)
        $rows = @(if ($PSBoundParameters.ContainsKey('LocalPort')) { $script:FakeServerRows } else { $script:FakeClientRows })
        if ($script:FakeTcpBroken) { throw 'WMI is broken' }
        if ($rows.Count -eq 0) { Write-Error -Category ObjectNotFound -Message 'No matching MSFT_NetTCPConnection objects found' }
        $rows
    }
    function Get-Process { [CmdletBinding()] param($Id) if ($script:FakeProcs.ContainsKey([int]$Id)) { [pscustomobject]@{ ProcessName = $script:FakeProcs[[int]$Id] } } }
    function Row([string] $Address, [int] $ProcessId) { [pscustomobject]@{ RemoteAddress=$Address; OwningProcess=$ProcessId } }
    $script:FakeProcs = @{ 100='nats-server'; 200='Veeam.Archiver.Service'; 300='Veeam.Archiver.Proxy'; 400='powershell' }
    $script:FakeTcpBroken = $false
    $script:FakeServerRows = @((Row '127.0.0.1' 100), (Row '::ffff:127.0.0.1' 100))
    $script:FakeClientRows = @((Row '127.0.0.1' 200), (Row '127.0.0.1' 300), (Row '127.0.0.1' 400))
    $s = Get-NatsClientSummary -Port 4222
    Check 'local clients are not remote'     $s.RemoteAddresses.Count 0
    Check 'VB365 processes found'            ($s.Vb365Processes -join ',') 'Veeam.Archiver.Proxy,Veeam.Archiver.Service'
    $script:FakeServerRows = @((Row '127.0.0.1' 100), (Row '10.9.9.9' 100))
    Check 'a client on another machine'      ((Get-NatsClientSummary -Port 4222).RemoteAddresses -join ',') '10.9.9.9'
    $script:FakeServerRows = @(); $script:FakeClientRows = @()
    $s = Get-NatsClientSummary -Port 4222
    Check 'no connections is not an error'   "$($s.RemoteAddresses.Count)/$($s.Vb365Processes.Count)" '0/0'
    $script:FakeTcpBroken = $true
    Check 'an unreadable table is an error'  (Throws { Get-NatsClientSummary -Port 4222 }) 'True'
}

'--- NATS: package checks ---'
$p = 'nats-server-v2.10.28-windows-amd64/'
Check 'release layout accepted'      (Test-NatsZipEntryNames -Names @($p, "${p}nats-server.exe", "${p}README.md", "${p}LICENSE") -Version '2.10.28') ''
Check 'extra file in the folder accepted' (Test-NatsZipEntryNames -Names @("${p}nats-server.exe", "${p}CHANGELOG.md") -Version '2.10.28') ''
Check 'climbing entry refused'       ((Test-NatsZipEntryNames -Names @("${p}nats-server.exe", "${p}../evil.exe") -Version '2.10.28') -match 'unsafe') 'True'
Check 'backslash entry refused'      ((Test-NatsZipEntryNames -Names @("${p}nats-server.exe", "nats-server-v2.10.28-windows-amd64\x") -Version '2.10.28') -match 'unsafe') 'True'
Check 'rooted entry refused'         ((Test-NatsZipEntryNames -Names @("${p}nats-server.exe", '/etc/x') -Version '2.10.28') -match 'unsafe') 'True'
Check 'entry outside the folder refused' ((Test-NatsZipEntryNames -Names @("${p}nats-server.exe", 'nats-server.exe') -Version '2.10.28') -match 'outside') 'True'
Check 'another version refused'      ((Test-NatsZipEntryNames -Names @('nats-server-v2.10.29-windows-amd64/nats-server.exe') -Version '2.10.28') -ne '') 'True'
Check 'missing program refused'      ((Test-NatsZipEntryNames -Names @("${p}README.md") -Version '2.10.28') -match 'exactly one') 'True'
Check 'empty package refused'        ((Test-NatsZipEntryNames -Names @() -Version '2.10.28') -match 'empty') 'True'
$zipTemp = Join-Path $env:TEMP "vpgu-nats-zip-$PID"
New-Item -ItemType Directory -Path $zipTemp -Force | Out-Null
try {
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    function New-TestZip([string] $Path, [string[]] $Entries) {
        $zip = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($name in $Entries) {
                $entry = $zip.CreateEntry($name)
                if (-not $name.EndsWith('/')) { $w = New-Object IO.StreamWriter($entry.Open()); $w.Write("content of $name"); $w.Dispose() }
            }
        } finally { $zip.Dispose() }
    }
    $good = Join-Path $zipTemp 'good.zip'
    New-TestZip $good @($p, "${p}nats-server.exe", "${p}README.md", "${p}LICENSE")
    $exe = Expand-NatsPackage -ZipPath $good -Version '2.10.28' -Destination (Join-Path $zipTemp 'stage1')
    Check 'program extracted'            ([IO.File]::ReadAllText($exe)) "content of ${p}nats-server.exe"
    Check 'only the program is extracted' (@(Get-ChildItem -LiteralPath (Join-Path $zipTemp 'stage1')).Count) 1
    $bad = Join-Path $zipTemp 'bad.zip'
    New-TestZip $bad @("${p}nats-server.exe", "${p}../../evil.txt")
    Check 'climbing package refused'     (Throws { Expand-NatsPackage -ZipPath $bad -Version '2.10.28' -Destination (Join-Path $zipTemp 'stage2') }) 'True'
    Check 'refused package writes nothing' (Test-Path (Join-Path $zipTemp 'stage2')) 'False'
    Check 'nothing escaped the folder'   (Test-Path (Join-Path (Split-Path $zipTemp) 'evil.txt')) 'False'
    Check 'an existing stage folder is refused' (Throws { Expand-NatsPackage -ZipPath $good -Version '2.10.28' -Destination (Join-Path $zipTemp 'stage1') }) 'True'
    $abc = Join-Path $zipTemp 'abc.txt'
    [IO.File]::WriteAllText($abc, 'abc')
    Check 'SHA256 is lower-case hex'     (Get-FileSha256 $abc) 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
} finally {
    Remove-Item -LiteralPath $zipTemp -Recurse -Force -ErrorAction SilentlyContinue
}

'--- NATS: store path safety ---'
$wr = 'C:\ProgramData\VeeamPgUpdate'
Check 'the VB365 store is safe'      (Test-NatsStorePathSafe -StoreDir 'C:\ProgramData\Veeam\Backup365\nats' -WorkRoot $wr) 'True'
Check 'a drive root is not'          (Test-NatsStorePathSafe -StoreDir 'C:\' -WorkRoot $wr) 'False'
Check 'one folder deep is not'       (Test-NatsStorePathSafe -StoreDir 'C:\nats' -WorkRoot $wr) 'False'
Check 'ProgramData itself is not'    (Test-NatsStorePathSafe -StoreDir $env:ProgramData -WorkRoot $wr) 'False'
Check 'Program Files itself is not'  (Test-NatsStorePathSafe -StoreDir $env:ProgramFiles -WorkRoot $wr) 'False'
Check 'inside WorkRoot is not'       (Test-NatsStorePathSafe -StoreDir 'C:\ProgramData\VeeamPgUpdate\nats' -WorkRoot $wr) 'False'
Check 'holding WorkRoot is not'      (Test-NatsStorePathSafe -StoreDir 'C:\Data\stuff' -WorkRoot 'C:\Data\stuff\work') 'False'
Check 'a relative path is not'       (Test-NatsStorePathSafe -StoreDir 'nats\store' -WorkRoot $wr) 'False'
Check 'the NATS program folder is not' (Test-NatsStorePathSafe -StoreDir 'C:\Program Files\NATS\store' -WorkRoot $wr -NatsRoot 'C:\Program Files\NATS') 'False'

'--- NATS: discovery is read-only and refuses what it cannot prove ---'
& {
    # Long path names: production normalises paths, and %TEMP% can be an 8.3 short name.
    $base = Join-Path $env:TEMP "vpgu-nats-discovery-$PID"
    New-Item -ItemType Directory -Path $base -Force | Out-Null
    $base = [IO.Path]::GetFullPath($base)
    $natsRootD = Join-Path $base 'Program Files\NATS'
    $oldDir = Join-Path $natsRootD 'nats-server-v2.10.22-windows-amd64'
    $plainDir = Join-Path $natsRootD 'nats'
    $confDir = Join-Path $base 'ProgramData\NATS'
    $storeD = Join-Path $base 'ProgramData\Veeam\Backup365\nats'
    $workD = Join-Path $base 'VeeamPgUpdate'
    foreach ($d in @($oldDir, $plainDir, $confDir, (Join-Path $storeD 'jetstream'), $workD)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    Set-Content -LiteralPath (Join-Path $oldDir 'nats-server.exe') -Value 'old program'
    Set-Content -LiteralPath (Join-Path $plainDir 'nats-server.exe') -Value 'plain program'
    Set-Content -LiteralPath (Join-Path $storeD 'jetstream\meta.inf') -Value 'store'
    $confD = Join-Path $confDir 'nats-server.conf'
    function Write-TestConf([string] $Store = $storeD, [string] $Extra = '') {
        $escaped = $Store -replace '\\', '\\'
        Set-Content -LiteralPath $confD -Value "port: 4222`njetstream {`n  store_dir: `"$escaped`"`n}`nauthorization { user: admin, password: `"`$2a`$11`$bcryptvalue`" }`n$Extra"
    }
    try {
        function Get-CimInstance { [CmdletBinding()] param($ClassName, $Filter) $script:FakeNatsService }
        function Invoke-Native { param([string] $FilePath, [string[]] $Arguments) $script:NativeCalls += "$FilePath $($Arguments -join ' ')"; [pscustomobject]@{ ExitCode=0; StdOut="nats-server: v$($script:FakeExeVersion)"; StdErr='' } }
        function Get-NatsInfoVersion { param($HostName, $Port, $TimeoutMs) $script:InfoAsked = "${HostName}:$Port"; $script:FakeInfo }
        function Get-NatsClientSummary { param($Port) [pscustomobject]@{ RemoteAddresses=@($script:FakeRemote); Vb365Processes=@('Veeam.Archiver.Service') } }
        function Invoke-NatsWebText {
            param([string] $Uri, [int] $TimeoutSec)
            if ($Uri -match 'helpcenter\.veeam\.com' -and $script:FakePage) { return $script:FakePage }
            if ($Uri -match '/v(\d+\.\d+\.\d+)/SHA256SUMS$' -and $script:FakeSums.ContainsKey($Matches[1])) { return $script:FakeSums[$Matches[1]] }
            throw 'offline'
        }
        $script:FakePage = $null; $script:FakeSums = @{}
        $cfgXml = [xml]'<Config><Server JetStreamConnectionString="nats://admin:SecretPw==@localhost:4222?passwordEncrypted" JetStreamReplicaCount="3"/></Config>'
        $proxyXmlD = [xml]'<Proxy><Proxy JetStreamConnectionString="nats://admin:SecretPw==@localhost:4222?passwordEncrypted"/></Proxy>'
        function Find-TestNats {
            param([string] $Exe = (Join-Path $oldDir 'nats-server.exe'), [string] $Version = '2.10.22', [string] $Info = '', [string] $State = 'Running',
                  $Remote = @(), [string] $Vb365 = '13.6.0.0', [bool] $Updates = $true, $Cfg = $cfgXml, $Proxy = $proxyXmlD, [string] $WorkRootD = $workD)
            $script:FakeExeVersion = $Version
            $script:FakeInfo = if ($Info) { $Info } else { $Version }
            $script:FakeRemote = @($Remote)
            $script:NativeCalls = @()
            $script:FakeNatsService = [pscustomobject]@{ Name='nats-server'; PathName="`"$Exe`" -c `"$confD`""; State=$State; StartMode='Auto'; StartName='LocalSystem' }
            Get-NatsDiscovery -Vb365Version $Vb365 -ConfigXml $Cfg -ProxyXml $Proxy -WorkRoot $WorkRootD -UpdatesEnabled $Updates -NatsRoot $natsRootD
        }
        Write-TestConf
        $d = Find-TestNats
        Check 'due update found'                 "$($d.Status) $($d.Installed) $($d.Target)" 'UPDATE_AVAILABLE 2.10.22 2.10.28'
        Check 'plan: old command line exact'     $d.Plan.OldImagePath "`"$(Join-Path $oldDir 'nats-server.exe')`" -c `"$confD`""
        Check 'plan: new folder beside the old'  $d.Plan.NewDir (Join-Path $natsRootD 'nats-server-v2.10.28-windows-amd64')
        Check 'plan: new command line keeps the arguments' $d.Plan.NewImagePath "`"$(Join-Path $natsRootD 'nats-server-v2.10.28-windows-amd64\nats-server.exe')`" -c `"$confD`""
        Check 'plan: store from the config file' $d.Plan.StoreDir $storeD
        Check 'plan: port'                       $d.Plan.Port 4222
        Check 'plan: pinned hash'                $d.Plan.TargetSha256 '98b8571231b00ebe0445cc7f317f6425c1fbc2edecd455949d37022e04281657'
        Check 'plan: hash source'                $d.Plan.HashSource 'Pinned'
        Check 'offline: the built-in list is named' ($d.Detail -match 'list built into this script') 'True'
        Check 'plan: VB365 was connected'        $d.Plan.BaselineVb365Connected 'True'
        Check 'version asked where NATS listens' $script:InfoAsked '127.0.0.1:4222'
        Check 'only --version is run'            ($script:NativeCalls -join ';') "$(Join-Path $oldDir 'nats-server.exe') --version"
        Check 'no credential in Detail'          ($d.Detail -match 'SecretPw|bcryptvalue') 'False'
        $d = Find-TestNats -Version '2.10.28' -Exe (Join-Path $plainDir 'nats-server.exe')
        Check 'current: nothing to do'           "$($d.Status) $($null -eq $d.Plan)" 'CURRENT True'
        $d = Find-TestNats -Version '2.12.6' -Exe (Join-Path $plainDir 'nats-server.exe')
        Check 'unlisted 2.12.6 -> 2.12.8'        "$($d.Status) $($d.Target)" 'UPDATE_AVAILABLE 2.12.8'
        $d = Find-TestNats -Version '2.10.18'
        Check 'folder and program disagree'      $d.Status 'UNRECOGNISED_LAYOUT'
        $d = Find-TestNats -State 'Stopped'
        Check 'stopped NATS is left alone'       "$($d.Status) $($d.Installed)" 'NOT_RUNNING 2.10.22'
        $script:FakeNatsService = $null
        $d = Get-NatsDiscovery -Vb365Version '13.6.0.0' -ConfigXml $cfgXml -ProxyXml $proxyXmlD -WorkRoot $workD -NatsRoot $natsRootD
        Check 'no nats-server service'           $d.Status 'NOT_LOCAL'
        $d = Find-TestNats -Vb365 '13.7.0.0'
        Check 'VB365 without a list'             "$($d.Status) $($d.Installed)" 'POLICY_UNKNOWN_VB365 2.10.22'
        $d = Find-TestNats -Updates $false
        Check 'updateNats false only reports'    "$($d.Status) $($d.Target) $($null -eq $d.Plan)" 'UPDATES_OFF 2.10.28 True'
        $d = Find-TestNats -Remote @('10.9.9.9')
        Check 'other machines connected'         "$($d.Status) $($null -eq $d.Plan)" 'REMOTE_CLIENTS True'
        Check 'a refusal still names the list used' ($d.Detail -match 'List: the list built into this script') 'True'
        $d = Find-TestNats -Info '2.10.18'
        Check 'NATS answers another version'     ($d.Status -eq 'UNRECOGNISED_LAYOUT' -and $d.Detail -match 'answered version 2\.10\.18') 'True'
        $d = Find-TestNats -Cfg ([xml]'<Config><Server JetStreamConnectionString="nats://admin:SecretPw==@nats-elsewhere.example:4222"/></Config>')
        Check 'NATS on another server'           ($d.Status -eq 'UNRECOGNISED_LAYOUT' -and $d.Detail -match 'not this server') 'True'
        Check 'connection password never shown'  ($d.Detail -match 'SecretPw') 'False'
        $d = Find-TestNats -Cfg ([xml]'<Config><Server JetStreamConnectionString="nats://admin:x@localhost:4333"/></Config>')
        Check 'port disagreement refused'        ($d.Detail -match 'port 4333') 'True'
        $d = Find-TestNats -Cfg ([xml]'<Config><Server/></Config>') -Proxy ([xml]'<Proxy/>')
        Check 'no connection string refused'     ($d.Detail -match 'no JetStreamConnectionString') 'True'
        Write-TestConf -Extra 'cluster { name: c1 }'
        $d = Find-TestNats
        Check 'clustered NATS refused'           ($d.Status -eq 'UNRECOGNISED_LAYOUT' -and $d.Detail -match 'uses cluster') 'True'
        Write-TestConf -Extra "other { store_dir: 'C:\elsewhere\nats' }"
        $d = Find-TestNats
        Check 'two stores refused'               ($d.Detail -match '2 store_dir') 'True'
        Write-TestConf -Store (Join-Path $base 'missing\store')
        $d = Find-TestNats
        Check 'missing store refused'            ($d.Detail -match 'missing') 'True'
        Write-TestConf
        $d = Find-TestNats -WorkRootD $storeD
        Check 'store overlapping WorkRoot refused' ($d.Detail -match 'overlaps') 'True'
        Check 'refusals carry no plan'           ($null -eq $d.Plan) 'True'

        # Veeam's website adds 2.12.9 and GitHub publishes its hash: no script change.
        $script:FakePage = $veeamPage -replace '2\.12\.8\.', '2.12.8, 2.12.9.'
        $script:FakeSums = @{ '2.12.9' = ('b' * 64) + '  nats-server-v2.12.9-windows-amd64.zip' }
        $d = Find-TestNats -Version '2.12.8' -Exe (Join-Path $plainDir 'nats-server.exe')
        Check 'a newly listed version is planned' "$($d.Status) $($d.Target) $($d.Plan.HashSource)" 'UPDATE_AVAILABLE 2.12.9 SHA256SUMS'
        Check 'its published hash is planned'    ($d.Plan.TargetSha256 -eq ('b' * 64)) 'True'
        Check "Veeam's list is named"            ($d.Detail -match "Veeam's current list for VB365 build 8\.6\.0\.1102") 'True'
        $script:FakeSums = @{}
        $d = Find-TestNats -Version '2.12.8' -Exe (Join-Path $plainDir 'nats-server.exe')
        Check 'no readable hash: left alone'      "$($d.Status) $($null -eq $d.Plan)" 'HASH_UNAVAILABLE True'
        $script:FakeSums = @{ '2.10.28' = ('c' * 64) + '  nats-server-v2.10.28-windows-amd64.zip' }
        $d = Find-TestNats
        Check 'pinned and published differ: left alone' "$($d.Status) $($null -eq $d.Plan)" 'HASH_CONFLICT True'
        $script:FakePage = $veeamPage -replace '8\.6\.0\.1102', '8.7.0.100'; $script:FakeSums = @{}
        $d = Find-TestNats -Version '2.12.8' -Exe (Join-Path $plainDir 'nats-server.exe')
        Check 'a page for VB365 8.7 is not used on 8.6' "$($d.Status) $($d.Detail -match 'describes VB365 8\.7')" 'CURRENT True'
        $d = Find-TestNats -Vb365 '13.7.0.0' -Version '2.12.8' -Exe (Join-Path $plainDir 'nats-server.exe')
        Check 'a VB365 8.7 server uses the 8.7 page' "$($d.Status) $($d.Detail -match 'build 8\.7\.0\.100')" 'CURRENT True'
        $script:FakePage = $null
    } finally {
        Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
    }
}

'--- NATS: the service is switched through the service manager ---'
& {
    function Get-CimInstance { [CmdletBinding()] param($ClassName, $Filter) [pscustomobject]@{ Name='nats-server'; PathName=$script:CimPath } }
    function Invoke-CimMethod {
        [CmdletBinding()] param($InputObject, $MethodName, $Arguments)
        $script:CimCalls += "$MethodName"
        if ($script:CimReturn -eq 0 -and -not $script:CimIgnore) { $script:CimPath = $Arguments['PathName'] }
        [pscustomobject]@{ ReturnValue=$script:CimReturn }
    }
    $script:CimCalls = @(); $script:CimPath = 'old'; $script:CimReturn = 0; $script:CimIgnore = $false
    Check 'a service manager change is accepted' (Throws { Set-NatsServicePath -PathName '"C:\new\nats-server.exe" -c "C:\c.conf"' }) 'False'
    Check 'it calls Win32_Service.Change'    ($script:CimCalls -join ',') 'Change'
    Check 'the new command line is in place' $script:CimPath '"C:\new\nats-server.exe" -c "C:\c.conf"'
    $script:CimReturn = 2
    Check 'a refused change throws'          (Throws { Set-NatsServicePath -PathName 'x' }) 'True'
    $script:CimReturn = 0; $script:CimIgnore = $true
    Check 'a change that reads back wrong throws' (Throws { Set-NatsServicePath -PathName 'y' }) 'True'

    function Get-Service { [CmdletBinding()] param([Parameter(Position=0)][string] $Name) if ($script:SvcState.ContainsKey($Name)) { [pscustomobject]@{ Name=$Name; Status=$script:SvcState[$Name] } } }
    function Stop-Service { [CmdletBinding()] param([Parameter(Position=0)][string] $Name) $script:Stops += $Name; if (-not $script:StuckStop) { $script:SvcState[$Name] = 'Stopped' } }
    function Start-Sleep { [CmdletBinding()] param([int] $Seconds) }
    $script:SvcState = @{ 'nats-server'='Running' }; $script:Stops = @(); $script:StuckStop = $false
    Stop-ServiceAndWait -Name 'nats-server' -Seconds 5
    Check 'a service is stopped and waited for' "$($script:Stops -join ',') $($script:SvcState['nats-server'])" 'nats-server Stopped'
    Stop-ServiceAndWait -Name 'nats-server' -Seconds 5
    Check 'a stopped service is left alone'  ($script:Stops -join ',') 'nats-server'
    Stop-ServiceAndWait -Name 'not-installed' -Seconds 5
    Check 'a missing service is no error'    ($script:Stops -join ',') 'nats-server'
    $script:SvcState = @{ 'nats-server'='Running' }; $script:StuckStop = $true
    Check 'a service that will not stop throws' (Throws { Stop-ServiceAndWait -Name 'nats-server' -Seconds 0 }) 'True'
}
& {
    function Get-Service { [CmdletBinding()] param([Parameter(Position=0)][string] $Name) if ($script:SvcState.ContainsKey($Name)) { [pscustomobject]@{ Name=$Name; Status=$script:SvcState[$Name] } } }
    function Stop-Service {
        [CmdletBinding()] param([Parameter(Position=0)][string] $Name)
        $script:Stops += $Name
        if ($Name -eq 'Veeam.Archiver.Service' -and $script:SvcState['Veeam.Archiver.REST.Service'] -eq 'Running') { throw 'Cannot stop service because it has dependent services' }
        $script:SvcState[$Name] = 'Stopped'
    }
    function Start-Sleep { [CmdletBinding()] param([int] $Seconds) }
    $script:SvcState = @{ 'Veeam.Archiver.Proxy'='Running'; 'Veeam.Archiver.Service'='Running'; 'Veeam.Archiver.REST.Service'='Running' }
    $script:Stops = @()
    Stop-ServicesInOrder -Names @('Veeam.Archiver.Proxy','Veeam.Archiver.Service','Veeam.Archiver.REST.Service') -Seconds 30
    Check 'a service with a dependent stops on a later pass' (@($script:SvcState.Values | Where-Object { $_ -ne 'Stopped' }).Count) 0
    Check 'it is tried again after its dependent'  ($script:Stops -join ',') 'Veeam.Archiver.Proxy,Veeam.Archiver.Service,Veeam.Archiver.REST.Service,Veeam.Archiver.Service'
    $script:SvcState = @{ 'Veeam.Archiver.Service'='StopPending' }
    Check 'a stuck service fails after the wait'   (Throws { Stop-ServicesInOrder -Names @('Veeam.Archiver.Service') -Seconds 0 }) 'True'
}
$priorRecoveryState = Get-Variable -Name RecoveryState -Scope Script -ValueOnly -ErrorAction SilentlyContinue
$script:RecoveryState = $null
Check 'no run is no NATS run'                  (Get-NatsRunFacts).IsNatsRun 'False'
$script:RecoveryState = [pscustomobject]@{ Stage='SERVICES_STOPPED' }
Check 'a PostgreSQL run is no NATS run'        (Get-NatsRunFacts).IsNatsRun 'False'
$script:RecoveryState = [pscustomobject]@{ Change='NATS' }
$nf = Get-NatsRunFacts
Check 'a NATS run without a plan is read safely' "$($nf.IsNatsRun)|$($nf.Stage)|$($nf.OldVersion)" 'True||'
$script:RecoveryState = [pscustomobject]@{ Change='NATS'; NatsStage='REVERTED'; NatsPlan=[pscustomobject]@{ OldVersion='2.10.22'; TargetVersion='2.10.28' } }
$nf = Get-NatsRunFacts
Check 'a NATS run is read in full'             "$($nf.Stage) $($nf.OldVersion) $($nf.TargetVersion)" 'REVERTED 2.10.22 2.10.28'
$script:RecoveryState = $priorRecoveryState
Check 'manual rollback text names the way back' ((Get-NatsManualRevertAction -Plan ([pscustomobject]@{ OldVersion='2.10.22'; OldExe='C:\o\nats-server.exe'; RegBackup='C:\r.reg'; StoreBackup='C:\s' })) -match '2\.10\.22.*C:\\o\\nats-server\.exe.*C:\\r\.reg.*C:\\s.*run -Recover') 'True'

'--- NATS: store restore mirrors the copy back ---'
$storeTest = Join-Path $env:TEMP "vpgu-nats-store-$PID"
try {
    $copyDir = Join-Path $storeTest 'work\runs\r\backup\nats\store'
    $liveDir = Join-Path $storeTest 'data\nats'
    New-Item -ItemType Directory -Path (Join-Path $copyDir 'jetstream') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $liveDir 'jetstream') -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $copyDir 'jetstream\a.dat'), 'aaaa')
    [IO.File]::WriteAllText((Join-Path $copyDir 'jetstream\b.dat'), 'bb')
    [IO.File]::WriteAllText((Join-Path $liveDir 'jetstream\a.dat'), 'changed by the new version')
    [IO.File]::WriteAllText((Join-Path $liveDir 'jetstream\new.idx'), 'written by the new version')
    $storePlan = [pscustomobject]@{ StoreDir=$liveDir; StoreBackup=$copyDir; StoreFiles=2; StoreBytes=6 }
    Restore-NatsStore -Plan $storePlan -WorkRoot (Join-Path $storeTest 'work')
    Check 'a changed store file is put back'  ([IO.File]::ReadAllText((Join-Path $liveDir 'jetstream\a.dat'))) 'aaaa'
    Check 'a missing store file is put back'  (Test-Path (Join-Path $liveDir 'jetstream\b.dat')) 'True'
    Check 'a file the new version wrote goes' (Test-Path (Join-Path $liveDir 'jetstream\new.idx')) 'False'
    $storePlan.StoreFiles = 3
    Check 'a count mismatch is an error'      (Throws { Restore-NatsStore -Plan $storePlan -WorkRoot (Join-Path $storeTest 'work') }) 'True'
    $unsafe = [pscustomobject]@{ StoreDir='C:\'; StoreBackup=$copyDir; StoreFiles=2; StoreBytes=6 }
    Check 'a drive root is never mirrored into' (Throws { Restore-NatsStore -Plan $unsafe -WorkRoot (Join-Path $storeTest 'work') }) 'True'
    $missingCopy = [pscustomobject]@{ StoreDir=$liveDir; StoreBackup=(Join-Path $storeTest 'nope'); StoreFiles=2; StoreBytes=6 }
    Check 'a missing copy is an error'        (Throws { Restore-NatsStore -Plan $missingCopy -WorkRoot (Join-Path $storeTest 'work') }) 'True'
    Check 'a missing copy deletes nothing'    (Test-Path (Join-Path $liveDir 'jetstream\a.dat')) 'True'
} finally {
    Remove-Item -LiteralPath $storeTest -Recurse -Force -ErrorAction SilentlyContinue
}

'--- NATS: rollback puts the old program back ---'
& {
    $base = Join-Path $env:TEMP "vpgu-nats-revert-$PID"
    $natsRootR = Join-Path $base 'NATS'
    $oldDirR = Join-Path $natsRootR 'nats-server-v2.10.22-windows-amd64'
    $newDirR = Join-Path $natsRootR 'nats-server-v2.10.28-windows-amd64'
    New-Item -ItemType Directory -Path $oldDirR -Force | Out-Null
    $oldExeR = Join-Path $oldDirR 'nats-server.exe'
    Set-Content -LiteralPath $oldExeR -Value 'old program'
    $script:RunDir = Join-Path $base 'work\runs\20261013-010203-004-1'
    New-Item -ItemType Directory -Path $script:RunDir -Force | Out-Null
    $oldImage = "`"$oldExeR`" -c `"C:\ProgramData\NATS\nats-server.conf`""
    $newImage = "`"$(Join-Path $newDirR 'nats-server.exe')`" -c `"C:\ProgramData\NATS\nats-server.conf`""
    try {
        function Save-RecoveryState { param([string] $Stage, $InstallerStarted) $script:Saves += "$($script:RecoveryState.NatsStage)" }
        function Get-Service {
            [CmdletBinding()] param([Parameter(Position=0)][string[]] $Name)
            foreach ($n in @($Name)) { foreach ($k in @($script:Svc.Keys | Where-Object { $_ -like $n } | Sort-Object)) { [pscustomobject]@{ Name=$k; Status=$script:Svc[$k] } } }
        }
        function Stop-Service { [CmdletBinding()] param([Parameter(Position=0)][string] $Name) $script:Actions += "STOP:$Name"; $script:Svc[$Name] = 'Stopped' }
        function Start-Sleep { [CmdletBinding()] param([int] $Seconds) }
        function Get-CimInstance { [CmdletBinding()] param($ClassName, $Filter) [pscustomobject]@{ Name='nats-server'; PathName=$script:FakePath; State=$script:FakeCimState } }
        function Set-NatsServicePath { param([string] $PathName) $script:Actions += 'PATH'; $script:FakePath = $PathName }
        function Restore-NatsStore { param($Plan, $WorkRoot) $script:Actions += 'STORE' }
        function Invoke-Native { param([string] $FilePath, [string[]] $Arguments) [pscustomobject]@{ ExitCode=0; StdOut="nats-server: v$($script:FakeOldReports)"; StdErr='' } }
        function Invoke-TestRevert {
            param([string] $NatsStage, [bool] $Started = $false, [string] $Mode = '', [hashtable] $Services = $null,
                  [string] $OldReports = '2.10.22', [bool] $NewDirMade = $true, [string[]] $NewDirFiles = @('nats-server.exe'), [string] $CimState = 'Stopped', [string] $StagedHash = '')
            $script:Svc = if ($Services) { @{} + $Services } else { @{ 'Veeam.Archiver.Proxy'='Stopped'; 'Veeam.Archiver.Service'='Stopped'; 'nats-server'='Running' } }
            $script:Actions = @(); $script:Saves = @(); $script:FakePath = $newImage; $script:FakeOldReports = $OldReports; $script:FakeCimState = $CimState
            Remove-Item -LiteralPath $newDirR -Recurse -Force -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Path $newDirR -Force | Out-Null
            foreach ($file in $NewDirFiles) { Set-Content -LiteralPath (Join-Path $newDirR $file) -Value 'new program' }
            $script:RecoveryState = [pscustomobject]@{
                Change='NATS'; InstallerStarted=$false; NatsStage=$NatsStage; NatsRevertMode=$Mode; NatsNewBinaryStarted=$Started
                NatsPlan=[pscustomobject]@{
                    OldVersion='2.10.22'; TargetVersion='2.10.28'; OldImagePath=$oldImage; NewImagePath=$newImage; OldExe=$oldExeR; OldFolder=$oldDirR
                    NewDir=$newDirR; NewExe=(Join-Path $newDirR 'nats-server.exe'); NewDirCreated=$NewDirMade
                    OldExeSha256=(Get-FileSha256 $oldExeR); StagedExeSha256=$(if ($StagedHash) { $StagedHash } elseif (Test-Path (Join-Path $newDirR 'nats-server.exe')) { Get-FileSha256 (Join-Path $newDirR 'nats-server.exe') } else { 'none' })
                    StoreDir='C:\x\y'; StoreBackup='C:\b'; StoreFiles=1; StoreBytes=1; RegBackup='C:\r.reg'
                }
            }
            return (Restore-NatsInstallation -WorkRootPath (Join-Path $base 'work'))
        }
        $r = Invoke-TestRevert -NatsStage 'SWAPPED'
        Check 'switched: reverted'                     $r ''
        Check 'switched: back on the old command line' $script:FakePath $oldImage
        Check 'switched: NATS stopped first'           $script:Actions[0] 'STOP:nats-server'
        Check 'switched: store kept (new never ran)'   ($script:Actions -contains 'STORE') 'False'
        Check 'switched: new folder removed'           (Test-Path $newDirR) 'False'
        Check 'switched: old program kept'             (Test-Path $oldExeR) 'True'
        Check 'switched: stage REVERTED'               $script:RecoveryState.NatsStage 'REVERTED'
        Check 'switched: REVERTING saved first'        ($script:Saves -join ',') 'REVERTING,REVERTED'
        Check 'switched: full mode recorded'           $script:RecoveryState.NatsRevertMode 'Full'
        $r = Invoke-TestRevert -NatsStage 'SWAPPED' -CimState 'Running'
        Check 'started on the new program at boot: store put back' ($script:Actions -contains 'STORE') 'True'
        $r = Invoke-TestRevert -NatsStage 'NATS_VERIFIED' -Started $true
        Check 'started alone: store put back'          ($script:Actions -contains 'STORE') 'True'
        Check 'started alone: command line before store' ([array]::IndexOf($script:Actions, 'PATH') -lt [array]::IndexOf($script:Actions, 'STORE')) 'True'
        $running = @{ 'Veeam.Archiver.Proxy'='Running'; 'Veeam.Archiver.Service'='Running'; 'Veeam.Archiver.REST.Service'='Running'; 'nats-server'='Running' }
        $r = Invoke-TestRevert -NatsStage 'VEEAM_STARTED' -Started $true -Services $running
        Check 'VB365 used it: reverted'                $r ''
        Check 'VB365 used it: Proxy stopped first'     $script:Actions[0] 'STOP:Veeam.Archiver.Proxy'
        Check 'VB365 used it: then the Service'        $script:Actions[1] 'STOP:Veeam.Archiver.Service'
        Check 'VB365 used it: NATS stopped after VB365' ([array]::IndexOf($script:Actions, 'STOP:nats-server') -gt [array]::IndexOf($script:Actions, 'STOP:Veeam.Archiver.REST.Service')) 'True'
        Check 'VB365 used it: store kept'              ($script:Actions -contains 'STORE') 'False'
        Check 'VB365 used it: program-only mode'       $script:RecoveryState.NatsRevertMode 'Binary'
        $r = Invoke-TestRevert -NatsStage 'REVERTING' -Mode 'Binary' -Started $true
        Check 'an interrupted program-only revert stays so' "$($script:RecoveryState.NatsRevertMode) $($script:Actions -contains 'STORE')" 'Binary False'
        foreach ($quiet in @('PLANNED','BACKING_UP','BACKED_UP','COMMITTED','REVERTED')) {
            $r = Invoke-TestRevert -NatsStage $quiet
            Check "${quiet}: nothing to undo"            "[$r] $($script:Actions.Count) $($script:FakePath -eq $newImage)" '[] 0 True'
        }
        $r = Invoke-TestRevert -NatsStage 'SWAPPED' -Services @{ 'Veeam.Archiver.Service'='Running'; 'nats-server'='Running' }
        Check 'Veeam running: no full revert'          ($r -match 'not stopped') 'True'
        Check 'Veeam running: command line untouched'  $script:FakePath $newImage
        $r = Invoke-TestRevert -NatsStage 'SWAPPED' -OldReports '2.10.18'
        Check 'old program wrong: reported'            ($r -match "reports '2\.10\.18'") 'True'
        Check 'old program wrong: not marked REVERTED' $script:RecoveryState.NatsStage 'REVERTING'
        $r = Invoke-TestRevert -NatsStage 'SWAPPED' -NewDirFiles @('nats-server.exe', 'notes.txt')
        Check 'foreign file: folder kept'              (Test-Path (Join-Path $newDirR 'notes.txt')) 'True'
        Check 'foreign file: still reverted'           $r ''
        $r = Invoke-TestRevert -NatsStage 'SWAPPED' -NewDirMade $false
        Check 'folder this run did not make: kept'     (Test-Path $newDirR) 'True'
        $r = Invoke-TestRevert -NatsStage 'SWAP_STARTED' -StagedHash ('0' * 64)
        Check 'a half-copied program this run made: removed' (Test-Path $newDirR) 'False'
        $r = Invoke-TestRevert -NatsStage 'SWAP_STARTED' -NewDirFiles @()
        Check 'an empty folder this run made: removed' (Test-Path $newDirR) 'False'
        $script:RecoveryState = [pscustomobject]@{ Stage='SERVICES_STOPPED'; NatsStage='SWAPPED' }
        Check 'a PostgreSQL run has no NATS to undo'   (Restore-NatsInstallation -WorkRootPath $base) ''
    } finally {
        $script:RecoveryState = $null
        Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
    }
}

'--- NATS: -Recover finishes or reverts an interrupted NATS run ---'
& {
    $WorkRoot = Join-Path $env:TEMP "vpgu-recover-nats-$PID"
    $runId = '20261013-010203-004-2222'
    $runPath = [IO.Path]::GetFullPath((Join-Path $WorkRoot "runs\$runId")).TrimEnd('\')
    New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
    Protect-Folder $WorkRoot | Out-Null
    New-Item -ItemType Directory -Path $runPath -Force | Out-Null
    try {
        $statePath = Join-Path $runPath 'recovery-state.json'
        $markerPath = Join-Path $WorkRoot 'CHANGES-IN-PROGRESS.marker'
        $psqlFake = Join-Path $runPath 'psql.exe'
        Set-Content -LiteralPath $psqlFake -Value 'fake'
        Write-AtomicJson -Path (Join-Path $runPath 'disabled-jobs.json') -Depth 5 -InputObject @(
            [pscustomobject][ordered]@{ Family='VB365';     Id='j1'; Name='Example Backup Job'; WasEnabled=$true; Restored=$false },
            [pscustomobject][ordered]@{ Family='VB365Copy'; Id='j2'; Name='Example Copy Job';   WasEnabled=$true; Restored=$false })
        Write-AtomicJson -Path (Join-Path $runPath 'veeam-service-state.json') -Depth 4 -InputObject @(
            [pscustomobject][ordered]@{ Name='Veeam.Archiver.Service'; DisplayName='Example VB365 Service'; Status='Running'; WasRunning=$true; StartupType='Automatic'; DependsOn=@() },
            [pscustomobject][ordered]@{ Name='Veeam.Archiver.Proxy';   DisplayName='Example VB365 Proxy';   Status='Running'; WasRunning=$true; StartupType='Automatic'; DependsOn=@() })
        Write-AtomicJson -Path (Join-Path $runPath 'pg-service-state.json') -InputObject ([pscustomobject][ordered]@{
            Name='postgresql-x64-15'; WasRunning=$true; StartupType='Automatic'; PsqlPath=$psqlFake; Port='5432' })
        Write-AtomicJson -Path (Join-Path $runPath 'nats-service-state.json') -InputObject ([pscustomobject][ordered]@{
            Name='nats-server'; Status='Running'; WasRunning=$true; StartupType='Automatic'; PathName='"C:\old\nats-server.exe" -c "C:\c.conf"' })

        $EXIT = @{ OK=0; ESCALATE=40; ESCALATE_NOW=50 }
        $script:Report = [ordered]@{ RecoveryRunDir=''; VeeamProducts=''; PgInstalled=''; PgTarget=''; JobsLeftDisabled=''; IssueCode=''; ActionRequired=''; NatsInstalled=''; NatsTarget=''; NatsStatus=''; NatsDetail='' }
        function Test-TrustedOwner { param($Path) return $true }
        function Get-Service {
            [CmdletBinding()] param([Parameter(Position=0)][string[]] $Name)
            foreach ($n in @($Name)) { foreach ($k in @($script:Svc.Keys | Where-Object { $_ -like $n } | Sort-Object)) { [pscustomobject]@{ Name=$k; Status=$script:Svc[$k] } } }
        }
        function Stop-Service  { [CmdletBinding()] param([Parameter(Position=0)][string] $Name) $script:Actions += "STOP:$Name";  $script:Svc[$Name] = 'Stopped' }
        function Start-Service { [CmdletBinding()] param([Parameter(Position=0)][string] $Name) $script:Actions += "START:$Name"; $script:Svc[$Name] = 'Running' }
        function Set-ServiceStartupTypeExact { [CmdletBinding()] param([string] $Name, [string] $StartupType) }
        function Get-ServiceStartupTypeExact { [CmdletBinding()] param([string] $Name) 'Automatic' }
        function Get-Process { [CmdletBinding()] param([string] $Name) @() }
        function Start-Sleep { [CmdletBinding()] param([int] $Seconds) }
        function Invoke-Native {
            param([string] $FilePath, [string[]] $Arguments)
            if ($Arguments -contains '-f') { $script:Actions += 'TUNING' }
            [pscustomobject]@{ ExitCode=0; StdOut='150019'; StdErr='' }
        }
        function Restore-VeeamServiceState { param([switch] $AllowStops) $script:Actions += 'RESTORE'; @() }
        function Connect-VeeamModules { param([switch] $Vbr, [switch] $Vb365, [switch] $Quiet, [switch] $Reconnect) @() }
        function Get-VeeamManagedJobInventory { param([bool] $Vbr, [bool] $Vb365) @() }
        function Wait-VeeamIdle { param([bool] $Vbr, [bool] $Vb365, [int] $TimeoutMinutes, [string] $Context, [switch] $CloseConsoles) [pscustomobject]@{ Idle=$true; Labels=@() } }
        function Enable-VeeamJobById { param($Record) $script:Actions += "ENABLE:$($Record.Name)" }
        function Save-DisabledJobState { }
        function Save-RecoveryState { param([string] $Stage, $InstallerStarted) $script:Actions += "SAVE:${Stage}:$($script:RecoveryState.NatsStage)" }
        function Remove-RecoveryMarker { $script:Actions += 'MARKER-REMOVED'; $true }
        function Test-NatsRunningAt { param($Plan, $Version, $ImagePath) $script:Actions += 'NATS-HEALTH'; $script:FakeNatsHealthy }
        function Restore-NatsInstallation {
            param([string] $WorkRootPath)
            $script:Actions += 'NATS-REVERT'
            if ($script:FakeRevertProblem) { return $script:FakeRevertProblem }
            Set-RecoveryProperty NatsStage 'REVERTED'
            return ''
        }
        function Complete-Run {
            param([int] $Code, [string] $Outcome, [string] $Detail)
            $script:RecoveryCapture = [pscustomobject]@{ Code=$Code; Outcome=$Outcome; Detail=$Detail }
            throw 'COMPLETE-RUN-TEST-SENTINEL'
        }
        $stoppedAll = @{ 'postgresql-x64-15'='Running'; 'Veeam.Archiver.Service'='Stopped'; 'Veeam.Archiver.Proxy'='Stopped'; 'nats-server'='Stopped' }
        $runningAll = @{ 'postgresql-x64-15'='Running'; 'Veeam.Archiver.Service'='Running'; 'Veeam.Archiver.Proxy'='Running'; 'nats-server'='Running' }
        function Invoke-TestNatsRecover {
            param([string] $Stage = 'SERVICES_STOPPED', [string] $NatsStage = 'SWAPPED', [int] $Schema = 2, [int] $MarkerSchema = 2,
                  [string] $Change = 'NATS', [bool] $Healthy = $false, [string] $RevertProblem = '', [string] $Mode = '', [hashtable] $Services = $stoppedAll)
            $script:Svc = @{} + $Services
            $script:FakeNatsHealthy = $Healthy; $script:FakeRevertProblem = $RevertProblem
            $script:Actions = @(); $script:RecoveryCapture = $null
            $script:Report.IssueCode = ''; $script:Report.ActionRequired = ''; $script:Report.NatsStatus = ''; $script:Report.NatsInstalled = ''; $script:Report.NatsDetail = ''
            $state = [ordered]@{
                SchemaVersion=$Schema; RunId=$runId; RunDir=$runPath; Stage=$Stage; InstallerStarted=$false
                Products='VB365'; OriginalVersion='15.19'; TargetVersion='15.19'
                PgServiceName='postgresql-x64-15'; PsqlPath=$psqlFake; PgPort='5432'
                NatsStage=$NatsStage; NatsRevertMode=$Mode; NatsNewBinaryStarted=$true
                NatsPlan=[ordered]@{ OldVersion='2.10.22'; TargetVersion='2.10.28'; NewImagePath='"C:\new\nats-server.exe" -c "C:\c.conf"'; ProbeHost='127.0.0.1'; Port=4222; OldExe='C:\old\nats-server.exe'; RegBackup='C:\r.reg'; StoreBackup='C:\s' }
            }
            if ($Change) { $state['Change'] = $Change }
            Write-AtomicJson -Path $statePath -InputObject $state
            Write-AtomicJson -Path $markerPath -InputObject ([ordered]@{
                SchemaVersion=$MarkerSchema; RunId=$runId; RunDir=$runPath; StateFile=$statePath; Stage=$Stage; InstallerStarted=$false })
            try { Invoke-ExplicitRecovery -MarkerPath $markerPath -Cfg (Get-DefaultConfig) }
            catch { if ($_.Exception.Message -ne 'COMPLETE-RUN-TEST-SENTINEL') { throw } }
        }

        Invoke-TestNatsRecover -NatsStage 'SWAPPED'
        $a = @($script:Actions)
        Check 'NATS switched: outcome'                $script:RecoveryCapture.Outcome 'RECOVERED_NATS_REVERTED'
        Check 'NATS switched: exit 0'                 $script:RecoveryCapture.Code 0
        Check 'NATS switched: put back before VB365'  ([array]::IndexOf($a, 'NATS-REVERT') -ge 0 -and [array]::IndexOf($a, 'NATS-REVERT') -lt [array]::IndexOf($a, 'RESTORE')) 'True'
        Check 'NATS switched: NATS started before VB365' ([array]::IndexOf($a, 'START:nats-server') -lt [array]::IndexOf($a, 'RESTORE')) 'True'
        Check 'NATS switched: jobs back on'           (@($a | Where-Object { $_ -like 'ENABLE:*' }).Count) 2
        Check 'NATS switched: no PostgreSQL tuning'   ($a -contains 'TUNING') 'False'
        Check 'NATS switched: PostgreSQL never stopped' ($a -contains 'STOP:postgresql-x64-15') 'False'
        Check 'NATS switched: marker removed'         ($a -contains 'MARKER-REMOVED') 'True'
        Check 'NATS switched: status'                 $script:Report.NatsStatus 'UPDATE_FAILED_REVERTED'
        Check 'NATS switched: detail'                 ($script:Report.NatsDetail -match 'put NATS 2\.10\.22 back') 'True'

        Invoke-TestNatsRecover -NatsStage 'VEEAM_STARTED' -Healthy $true -Services $runningAll
        $a = @($script:Actions)
        Check 'healthy on the new NATS: kept'         $script:RecoveryCapture.Outcome 'RECOVERED_NATS_UPDATED'
        Check 'healthy on the new NATS: not reverted' ($a -contains 'NATS-REVERT') 'False'
        Check 'healthy on the new NATS: committed'    (@($a | Where-Object { $_ -eq 'SAVE:COMPLETE:COMMITTED' }).Count) 1
        Check 'healthy on the new NATS: jobs back on' (@($a | Where-Object { $_ -like 'ENABLE:*' }).Count) 2
        Check 'healthy on the new NATS: version'      $script:Report.NatsInstalled '2.10.28'
        Check 'healthy on the new NATS: detail'       ($script:Report.NatsDetail -match 'is in place') 'True'

        Invoke-TestNatsRecover -NatsStage 'VEEAM_STARTED' -Healthy $false -Services $runningAll
        Check 'unhealthy on the new NATS: put back'   "$($script:RecoveryCapture.Outcome) $($script:Actions -contains 'NATS-REVERT')" 'RECOVERED_NATS_REVERTED True'

        Invoke-TestNatsRecover -Stage 'VERIFIED' -NatsStage 'COMMITTED'
        $a = @($script:Actions)
        Check 'verified NATS run: finished'           $script:RecoveryCapture.Outcome 'RECOVERED_NATS_UPDATED'
        Check 'verified NATS run: services restored'  ($a -contains 'RESTORE') 'True'
        Check 'verified NATS run: never reverted'     ($a -contains 'NATS-REVERT') 'False'
        Check 'verified NATS run: no PostgreSQL tuning' ($a -contains 'TUNING') 'False'

        Invoke-TestNatsRecover -NatsStage 'SWAPPED' -Services @{ 'postgresql-x64-15'='Running'; 'Veeam.Archiver.Service'='Running'; 'Veeam.Archiver.Proxy'='Stopped'; 'nats-server'='Running' }
        Check 'Veeam started by hand: diagnostic only' $script:RecoveryCapture.Outcome 'RECOVERY_DIAGNOSTIC_ONLY'
        Check 'Veeam started by hand: changes nothing' (@($script:Actions | Where-Object { $_ -in @('NATS-REVERT','RESTORE') -or $_ -like 'START:*' -or $_ -like 'ENABLE:*' }).Count) 0

        Invoke-TestNatsRecover -NatsStage 'SWAPPED' -RevertProblem 'NATS could not be put back to 2.10.22: example failure'
        Check 'revert fails: incomplete'              $script:RecoveryCapture.Outcome 'RECOVERY_INCOMPLETE'
        Check 'revert fails: named'                   $script:Report.IssueCode 'NATS_RECOVERY_INCOMPLETE'
        Check 'revert fails: VB365 stays down'        ($script:Actions -contains 'RESTORE') 'False'
        Check 'revert fails: jobs stay off'           (@($script:Actions | Where-Object { $_ -like 'ENABLE:*' }).Count) 0
        Check 'revert fails: says what to do'         ($script:Report.ActionRequired -match 'run -Recover') 'True'

        Invoke-TestNatsRecover -NatsStage 'BACKED_UP'
        Check 'nothing switched yet: restored'        $script:RecoveryCapture.Outcome 'RECOVERED_PREINSTALL'
        Check 'nothing switched yet: no revert'       ($script:Actions -contains 'NATS-REVERT') 'False'
        Check 'nothing switched yet: says NATS'       ($script:RecoveryCapture.Detail -match 'NATS was not changed') 'True'

        Invoke-TestNatsRecover -Change ''
        Check 'schema 2 without NATS is refused'      $script:RecoveryCapture.Outcome 'INVALID_RECOVERY_STATE'
        Invoke-TestNatsRecover -Schema 1 -MarkerSchema 1
        Check 'a NATS run with schema 1 is refused'   $script:RecoveryCapture.Outcome 'INVALID_RECOVERY_STATE'
        Invoke-TestNatsRecover -MarkerSchema 1
        Check 'marker and state schema must match'    $script:RecoveryCapture.Outcome 'INVALID_RECOVERY_STATE'
        Check 'a refused state changes nothing'       @($script:Actions).Count 0

        # A recovery that saves its state and then fails must leave a marker the next
        # -Recover accepts: bound to the original run, never to this recovery's own stamp.
        Remove-Item -LiteralPath Function:\Save-RecoveryState
        $priorMarkerFile = Get-Variable -Name MarkerFile -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        $script:MarkerFile = $markerPath
        $script:Stamp = '20261013-111111-111-9999'
        function Restore-NatsInstallation { param([string] $WorkRootPath) Set-NatsStage 'REVERTING'; 'NATS could not be put back to 2.10.22: example failure' }
        Invoke-TestNatsRecover -NatsStage 'SWAPPED'
        $markerAfter = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
        Check 'a failed recovery keeps the marker on the original run' "$($markerAfter.RunId) $($markerAfter.Stage) $($markerAfter.SchemaVersion)" "$runId SERVICES_STOPPED 2"
        Check 'the saved state records the revert attempt' (Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json).NatsStage 'REVERTING'
        $script:MarkerFile = $priorMarkerFile
    } finally {
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

'--- NATS: the update run changes things in a safe order ---'
$natsFlow = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-NatsOnlyUpdate' }, $true))[0].Extent.Text
function Get-FlowAt([string] $Text) { $at = $natsFlow.IndexOf($Text); if ($at -lt 0) { throw "not in Invoke-NatsOnlyUpdate: $Text" }; $at }
Check 'the download is hash-checked before it is opened' ((Get-FlowAt "'NATS_HASH_MISMATCH'") -lt (Get-FlowAt 'Expand-NatsPackage')) 'True'
Check 'the package is tried before any job changes' ((Get-FlowAt "'NATS_STAGED_BINARY_FAILED'") -lt (Get-FlowAt 'Disable-VeeamManagedJobs')) 'True'
Check 'disk space is checked before any job changes' ((Get-FlowAt "'LOW_DISK'") -lt (Get-FlowAt 'Disable-VeeamManagedJobs')) 'True'
Check 'the outage is recorded before startup changes' ((Get-FlowAt "Save-RecoveryState -Stage 'SERVICES_STOPPED'") -lt (Get-FlowAt '@(Disable-VeeamServiceStartup)')) 'True'
Check 'NATS stops after the Veeam services'   ((Get-FlowAt '$preferredStopOrder') -lt (Get-FlowAt "Stop-Service -Name 'nats-server'")) 'True'
# NATS consumer folders make paths in the store longer than 260 characters, which
# icacls /t cannot read. Seen on a VB365 8.6 server: only the folder's own ACL is saved.
Check 'store permissions are saved without /t'  ($natsFlow -match "'/save', \`$storeAcl, '/q'\)" -and $natsFlow -notmatch "'/save', \`$storeAcl, '/t'") 'True'
Check 'the backup is complete before the switch' ((Get-FlowAt "Set-NatsStage 'BACKED_UP'") -lt (Get-FlowAt "Set-NatsStage 'SWAP_STARTED'")) 'True'
Check 'switch intent is saved before the new folder' ((Get-FlowAt "Set-NatsStage 'SWAP_STARTED'") -lt (Get-FlowAt 'New-Item -ItemType Directory -Path "$($natsPlan.NewDir)"')) 'True'
Check 'the new folder exists before the service changes' ((Get-FlowAt 'New-Item -ItemType Directory -Path "$($natsPlan.NewDir)"') -lt (Get-FlowAt 'Set-NatsServicePath -PathName "$($natsPlan.NewImagePath)"')) 'True'
Check 'the store flag is saved before NATS starts' ((Get-FlowAt 'Set-RecoveryProperty NatsNewBinaryStarted $true') -lt (Get-FlowAt "Start-Service -Name 'nats-server'")) 'True'
Check 'NATS is verified alone before VB365 starts' ((Get-FlowAt "Set-NatsStage 'NATS_VERIFIED'") -lt (Get-FlowAt 'Restore-VeeamServiceState')) 'True'
Check 'the VB365 start is recorded first'      ((Get-FlowAt "Set-NatsStage 'VEEAM_STARTED'") -lt (Get-FlowAt 'Restore-VeeamServiceState')) 'True'
Check 'commit comes after the health checks'   ((Get-FlowAt 'VB365 did not come back healthy') -lt (Get-FlowAt "Set-RecoveryProperty NatsStage 'COMMITTED'")) 'True'
Check 'maintenance is released after the commit' ((Get-FlowAt "Set-RecoveryProperty NatsStage 'COMMITTED'") -lt (Get-FlowAt 'Stop-Vb365MaintenanceBarrier')) 'True'
Check 'jobs come back after maintenance ends'  ((Get-FlowAt 'Stop-Vb365MaintenanceBarrier') -lt (Get-FlowAt 'Enable-VeeamJobById')) 'True'
Check 'a NATS run never stops PostgreSQL'      ($natsFlow -match 'Stop-Service -Name \$pgSvc') 'False'
Check 'a NATS run never runs an installer'     ($natsFlow -match 'Start-Process') 'False'
Check 'a NATS run never books a restart'       ($natsFlow -match 'Invoke-DelayedReboot|shutdown\.exe') 'False'
Check 'a NATS run is recorded as schema 2'     ($natsFlow -match 'SchemaVersion\s+= 2') 'True'
Check 'a NATS run needs no reboot'             ($natsFlow -match '\$script:Report\.RebootRequired = \$false') 'True'
# The audit's "is available" text must not survive a run that updated NATS.
Check 'a finished update replaces the audit detail' ((Get-FlowAt "`$script:Report.NatsStatus = 'UPDATED'") -lt (Get-FlowAt '$script:Report.NatsDetail = "This run updated NATS')) 'True'
$natsCalls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-NatsOnlyUpdate' }, $true))
Check 'the NATS run starts from one place'     $natsCalls.Count 1
Check 'NATS goes only when PostgreSQL needs nothing' ($scriptText -match 'if \(\$natsDue -and \$versionComparison -ge 0\)') 'True'
Check 'audit exits before the NATS run'        ($scriptText -match "(?s)if \(-not \`$Install\) \{\s+\`$natsMsg = .*?Complete-Run \`$code 'UPDATE_AVAILABLE' \`$natsMsg\s+\}\s+Invoke-NatsOnlyUpdate -Discovery \`$natsDiscovery") 'True'
Check 'NATS is checked before PostgreSQL targets' ($scriptText.IndexOf("'STEP 6C - Check NATS (VB365 only)'") -lt $scriptText.IndexOf("'STEP 7 - Resolve target version'")) 'True'
Check 'the service is never edited in the registry' ($scriptText -match 'Set-ItemProperty[^\r\n]*ImagePath') 'False'
$rollbackText = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Rollback' }, $true))[0].Extent.Text
Check 'rollback puts NATS back before starting it' ($rollbackText.IndexOf('Restore-NatsInstallation') -ge 0 -and $rollbackText.IndexOf('Restore-NatsInstallation') -lt $rollbackText.IndexOf("Start-Service -Name 'nats-server'")) 'True'
Check 'the report has the NATS fields'         ($scriptText -match "(?m)^\s+NatsInstalled\s+= ''" -and $scriptText -match "(?m)^\s+NatsTarget\s+= ''" -and $scriptText -match "(?m)^\s+NatsStatus\s+= ''" -and $scriptText -match "(?m)^\s+NatsDetail\s+= ''") 'True'
$completeRunText = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Complete-Run' }, $true))[0].Extent.Text
Check 'a hash conflict reaches the RMM issue fields' ($completeRunText -match "'HASH_CONFLICT'" -and $completeRunText -match "IssueCode = 'NATS_HASH_CONFLICT'" -and $completeRunText.IndexOf("'NATS_HASH_CONFLICT'") -gt $completeRunText.IndexOf('$script:Report.ActionRequired = Get-RmmActionForExitCode $finalCode')) 'True'
Check 'a pending NATS update keeps exit 5 after a booked restart' ($scriptText -match '\$bookedCode = Get-PolicyExitCode -Eol \$script:EolBranch -UpdateAvailable \$natsDue -RebootRequired \$false') 'True'

'--- Get-CfgValue StrictMode safety ---'
$o = [pscustomobject]@{ a = 1 }
Check 'present key'   (Get-CfgValue $o 'a' 99)   1
Check 'absent key'    (Get-CfgValue $o 'zzz' 99) 99
Check 'null object'   (Get-CfgValue $null 'a' 7) 7

'--- Invoke-Native: native stderr must NOT throw under EAP=Stop ---'
$ErrorActionPreference = 'Stop'
$r = Invoke-Native 'cmd.exe' @('/c','echo oops 1>&2 & exit /b 3')
Check 'captures exit code'   $r.ExitCode 3
Check 'captures stderr'      ($r.StdErr -match 'oops')  'True'
Check 'stdout stays clean'   $r.StdOut ''
$r2 = Invoke-Native 'cmd.exe' @('/c','echo hello')
Check 'clean run exit 0'     $r2.ExitCode 0
Check 'clean run stdout'     $r2.StdOut 'hello'
Check 'clean run no stderr'  $r2.StdErr ''

''
"RESULT: $pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }

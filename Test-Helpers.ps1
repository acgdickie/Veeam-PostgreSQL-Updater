# Extracts the real function definitions out of Update-VeeamPostgres.ps1 via the
# AST and exercises them, so the tests run against the shipping code, not a copy.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:Path = Join-Path $PSScriptRoot 'Update-VeeamPostgres.ps1'
$errs = $null; $toks = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Path, [ref]$toks, [ref]$errs)
if ($errs -and $errs.Count) { throw "parse errors: $($errs.Count)" }

$want = 'ConvertFrom-ServerVersionNum','ConvertTo-ServerVersionNum',
        'Get-BranchKey','Compare-PgVersion','Get-CfgValue','Invoke-Native',
        'Resolve-LatestPgTarget','ConvertFrom-PgConnectionString','Test-LocalDbHost','Test-Vb365CacheDatabaseName',
        'Get-DefaultConfig','Merge-Config','Protect-Folder','Test-TrustedOwner','Initialize-WorkRoot',
        'Get-PolicyExitCode','Get-RmmActionForExitCode',
        'Resolve-PgInstallerLinkFromHtml',
        'Get-VeeamJobFamilyDefinitions','Get-VeeamJobFamilyDefinition',
        'Get-VeeamJobEnabledFlag','Get-VeeamJobIdentity','Get-VeeamManagedJobInventory',
        'Invoke-VeeamJobTransition','Get-VeeamJobByRecord','Enable-VeeamJobById',
        'Get-ActiveLabelsFromSessions','Get-ActiveVb365OrganizationSyncWork','Test-VbrFamilyInUse','Get-BlockingVeeamUiProcesses',
        'Get-ActiveVeeamWork','Wait-VeeamIdle','Find-Vb365MaintenanceBarrier',
        'Get-UnrestoredJobNames',
        'Write-AtomicText','Write-AtomicJson','Set-RecoveryProperty','Save-RecoveryState',
        'Invoke-ExplicitRecovery',
        'Get-ServiceStartupTypeExact','Set-ServiceStartupTypeExact','Test-PgServiceExecutableMatchesBaseDir','Test-PathTreeOverlap',
        'Get-VeeamServiceState','Disable-VeeamServiceStartup','Restore-VeeamServiceState'
foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if ($want -contains $fn.Name) { . ([scriptblock]::Create($fn.Extent.Text)) }
}
function Write-Log { param($Message, $Level) }   # stub

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
Check 'Install parameter remains'       ($scriptParameterNames -contains 'Install')       'True'
Check 'Recover parameter exposed'       ($scriptParameterNames -contains 'Recover')       'True'

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
Check 'never invokes Stop-Process'        (@($invokedCommands | Where-Object { $_ -eq 'Stop-Process' }).Count) 0
$forcedServiceStops = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq 'Stop-Service' -and
    @($node.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Force' }).Count -gt 0
}, $true))
Check 'never force-stops a Windows service' $forcedServiceStops.Count 0
$scriptText = Get-Content -LiteralPath $script:Path -Raw
Check 'strict no-force policy never invokes shutdown.exe' ($scriptText -match 'System32[\\/]shutdown\.exe') 'False'
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
Check 'only current settings remain'  (@($d.PSObject.Properties.Name | Sort-Object) -join ',')  'installerTimeoutMinutes,jobWaitTimeoutMinutes,retentionDays'
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

'--- Merge-Config: an override changes only its own keys ---'
$m = Merge-Config (Get-DefaultConfig) ('{ "retentionDays": 60, "jobWaitTimeoutMinutes": 30, "_comment": "ignored" }' | ConvertFrom-Json)
Check 'overridden key changes'        $m.retentionDays  60
Check 'overridden wait changes'       $m.jobWaitTimeoutMinutes 30
Check 'untouched key kept'            $m.installerTimeoutMinutes 120
Check '_comment keys skipped'         (@($m.PSObject.Properties.Name) -contains '_comment')  'False'
$legacyOverride = '{ "approvedTargets": ["17.12"], "supportedBranches": { "VBR99": ["99"] }, "branchFloors": { "17": "17.99" } }' | ConvertFrom-Json
$m2 = Merge-Config (Get-DefaultConfig) $legacyOverride
Check 'retired overrides ignored'     (@($m2.PSObject.Properties.Name | Where-Object { $_ -in @('approvedTargets','supportedBranches','branchFloors') }).Count)  0
Check 'retired overrides change nothing' $m2.retentionDays  30
Check 'null override = built-in'      (Merge-Config (Get-DefaultConfig) $null).retentionDays  30
Check 'shipped example file parses'   ($null -ne (Get-Content (Join-Path (Split-Path $script:Path) 'VeeamPostgresUpdate.config.example.json') -Raw | ConvertFrom-Json))  'True'

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
    $base = Join-Path $env:TEMP "vpgu-wr-test-$PID"
    New-Item -ItemType Directory -Path $base -Force | Out-Null
    try {
        # 1. Brand new folder -> ours, locked, sentinel dropped
        $new = Join-Path $base 'new'
        $r = Initialize-WorkRoot $new
        Check 'new folder: ours'              $r.IsOurs     'True'
        Check 'new folder: locked'            $r.Protected  'True'
        Check 'new folder: sentinel written'  (Test-Path (Join-Path $new '.veeam-pg-updater'))  'True'

        # 2. Second run on the same folder -> still ours (sentinel)
        Add-Content -LiteralPath (Join-Path $new 'something.log') -Value 'x'
        Check 'rerun with contents: ours'     (Initialize-WorkRoot $new).IsOurs  'True'

        # 3. Existing empty folder -> ours
        $empty = Join-Path $base 'empty'; New-Item -ItemType Directory $empty | Out-Null
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
        Check 'foreign folder: says why'      ($r.Reason -match 'not created by this script')  'True'

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
Check 'VB365 active jobs + restore -> 5'     $w.Count 5
Check 'VB365 running label'                  ($w -contains 'VB365:Job:Running') 'True'
Check 'VB365 queued label'                   ($w -contains 'VB365:Job:Queued') 'True'
Check 'VB365 updating label'                 ($w -contains 'VB365:Job:Updating') 'True'
Check 'VB365 disconnected label'             ($w -contains 'VB365:Job:Disconnected') 'True'
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
    $runPath = [IO.Path]::GetFullPath((Join-Path $WorkRoot 'runs\post-install')).TrimEnd('\')
    New-Item -ItemType Directory -Path $runPath -Force | Out-Null
    try {
        $statePath = Join-Path $runPath 'recovery-state.json'
        $markerPath = Join-Path $WorkRoot 'CHANGES-IN-PROGRESS.marker'
        $state = [ordered]@{
            SchemaVersion=1; RunDir=$runPath; Stage='INSTALLING'; InstallerStarted=$true
            Products='VBR'; OriginalVersion='15.2'; TargetVersion='15.19'
            PgServiceName=''; PsqlPath=''; PgPort=''
        }
        Write-AtomicJson -Path $statePath -InputObject $state
        Write-AtomicJson -Path $markerPath -InputObject ([ordered]@{
            SchemaVersion=1; RunDir=$runPath; StateFile=$statePath; Stage='INSTALLING'; InstallerStarted=$true
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
    } finally {
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

& {
    $WorkRoot = Join-Path $env:TEMP "vpgu-recover-traversal-$PID"
    New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
    try {
        $outside = Join-Path $env:TEMP "vpgu-outside-$PID\recovery-state.json"
        $markerPath = Join-Path $WorkRoot 'CHANGES-IN-PROGRESS.marker'
        Write-AtomicJson -Path $markerPath -InputObject ([ordered]@{
            SchemaVersion=1; RunDir=(Split-Path -Parent $outside); StateFile=$outside; Stage='JOBS_DISABLED'; InstallerStarted=$false
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

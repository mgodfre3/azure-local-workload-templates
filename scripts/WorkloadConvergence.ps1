function Assert-ConvergenceAnswers {
    param([hashtable]$Answers)
    if (!$Answers.ContainsKey('convergence')) { return }
    if (!$Answers.workloads.Count) { return }
    $client = @($Answers.workloads | Where-Object name -EQ $Answers.convergence.clientWorkloadName)
    if ($client.Count -ne 1 -or $client[0].profile -ne 'windowsApp') {
        throw 'convergence.clientWorkloadName must identify one enabled, expanded windowsApp workload.'
    }
    if ($Answers.passwordSource.type -eq 'keyVault') {
        throw 'Encrypted peer acceptance currently requires prompt/environment passwordSource; no Key Vault secret permissions are granted or assumed.'
    }
    foreach ($workload in $Answers.workloads) {
        if ($workload.profile -eq 'sqlServer' -and $workload.sqlServer['installationMode'] -eq 'marketplace' -and
            (!$workload.sqlServer['administratorPolicy'] -or $workload.sqlServer['clientAccess'] -ne $true)) {
            throw 'Marketplace SQL peer acceptance requires explicit administratorPolicy and clientAccess=true.'
        }
    }
}

function Get-WindowsConfigurationPayload {
    param([hashtable]$Answers, [hashtable]$Workload)
    $config = @{
        profile = $Workload.profile; adminUsername = $Answers.adminUsername
        allowedCidrs = $Workload.allowedCidrs; dataDiskSizeGB = $Workload.dataDiskSizeGB
    }
    if ($Workload.ContainsKey('windowsPreparation')) { $config.windowsPreparation = $Workload.windowsPreparation }
    if ($Workload.profile -in @('fileServer', 'sqlServer')) { $config[$Workload.profile] = $Workload[$Workload.profile] }
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($config | ConvertTo-Json -Depth 10 -Compress)))
}

function Get-ConvergenceRemainingSeconds {
    param([DateTime]$Deadline)
    $remaining = [int][Math]::Ceiling(($Deadline - [DateTime]::UtcNow).TotalSeconds)
    if ($remaining -le 0) { throw 'Fleet convergence deadline expired. Existing resources and protected recovery watchdogs were preserved; inspect before retrying.' }
    $remaining
}

function Get-FleetMachineId {
    param([hashtable]$Answers, [hashtable]$Workload)
    "/subscriptions/$($Answers.subscriptionId)/resourceGroups/$($Answers.resourceGroup)/providers/Microsoft.HybridCompute/machines/$($Workload.name)"
}

function Invoke-FleetGuestCommand {
    param([hashtable]$Answers, [hashtable]$Workload, [string]$Script, [DateTime]$Deadline)
    $machineId = Get-FleetMachineId $Answers $Workload
    do {
        $machine = Get-ArmResource $machineId '2024-07-10'
        Assert-OwnedResource $machine $Answers.deploymentName $Workload.configurationHash
        if ($machine.properties.status -eq 'Connected') { break }
        $null = Get-ConvergenceRemainingSeconds $Deadline
        Start-Sleep -Seconds 10
    } while ($true)
    $commandId = "$machineId/runCommands/wlf-$([guid]::NewGuid().ToString('N'))"
    $timeout = [Math]::Min(900, (Get-ConvergenceRemainingSeconds $Deadline))
    $request = @{ location = $Answers.location; properties = @{
        source = @{ script = $Script }; timeoutInSeconds = $timeout; asyncExecution = $false
    } }
    $null = Invoke-ArmRequest -Method PUT -Path "${commandId}?api-version=2024-07-10" -Body $request -CreateOnly
    do {
        $result = Get-ArmResource $commandId '2024-07-10'
        $view = $result.properties['instanceView']
        if ($view -and $view['executionState'] -eq 'Succeeded' -and $view['exitCode'] -eq 0) {
            $lines = @(([string]$view['output'] -split '\r?\n') | Where-Object { $_.StartsWith('WORKLOADFLEET_RESULT=') })
            if ($lines.Count -ne 1) { throw 'Guest command completed without one verifiable result; stdout/stderr are not echoed.' }
            try { return $lines[0].Substring('WORKLOADFLEET_RESULT='.Length) | ConvertFrom-Json -AsHashtable }
            catch { throw 'Guest command returned invalid structured evidence; raw output is suppressed.' }
        }
        if ($result.properties.provisioningState -in @('Failed', 'Canceled', 'Cancelled') -or
            ($view -and $view['executionState'] -in @('Failed', 'TimedOut', 'Canceled'))) {
            $failure = [InvalidOperationException]::new("Fleet guest acceptance failed on '$($Workload.name)'. Inspect its protected Run Command status; output and credentials are not echoed.")
            $failure.Data['RunCommandExecutionFailure'] = $true
            throw $failure
        }
        $null = Get-ConvergenceRemainingSeconds $Deadline
        Start-Sleep -Seconds 10
    } while ($true)
}

function Get-CommittedFleetGuest {
    param([ValidateSet('Configure-Windows.ps1', 'validate-linux.sh', 'Test-FleetClient.ps1')][string]$Name)
    $commit = Invoke-SourceGit @('rev-parse', 'HEAD')
    $path = Join-Path (Join-Path $script:Root 'guest') $Name
    $blob = Invoke-SourceGit @('rev-parse', "${commit}:guest/$Name")
    if ($blob -ne (Invoke-SourceGit @('hash-object', "--path=guest/$Name", $path))) {
        throw 'Fleet guest script has uncommitted changes. Commit and push it before guest execution.'
    }
    Invoke-SourceGit @('show', "${commit}:guest/$Name")
}

function Get-WindowsPreparationCommand {
    param([hashtable]$Answers, [hashtable]$Workload)
    $guest = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
        (Get-CommittedFleetGuest 'Configure-Windows.ps1')))
    $payload = Get-WindowsConfigurationPayload $Answers $Workload
    "`$ErrorActionPreference='Stop'; . ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$guest')))) -ConfigurationBase64 '$payload'; " +
        "`$result=Invoke-WorkloadPreparation '$payload'; 'WORKLOADFLEET_RESULT='+(`$result|ConvertTo-Json -Compress)"
}

function Invoke-FleetWindowsPreparation {
    param([hashtable]$Answers, [hashtable]$Workload, [DateTime]$Deadline, [hashtable]$RestartCounts)
    if ($RestartCounts[$Workload.name] -ge 2) { throw 'Per-guest two-restart limit reached; no third restart was scheduled.' }
    $before = Invoke-FleetGuestCommand $Answers $Workload (Get-WindowsPreparationCommand $Answers $Workload) $Deadline
    if ($before['restartScheduled'] -isnot [bool]) { throw 'Windows preparation did not return typed restart evidence.' }
    if ($before.restartScheduled -ne $true) { return $false }
    $RestartCounts[$Workload.name]++
    if ($before.task -notmatch '^AzureLocalWorkload-Restart-[0-9a-f]{32}$') { throw 'Unexpected guest restart evidence.' }
    $beforeBoot = [DateTimeOffset]::Parse($before.bootUtc)
    Start-Sleep -Seconds 60
    $verify = @'
$ErrorActionPreference='Stop'
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
if($boot -ceq '__BEFORE_BOOT__'){
 'WORKLOADFLEET_RESULT='+(@{restartVerified=$false;bootUtc=$boot;pendingRestart=$true}|ConvertTo-Json -Compress)
 exit 0
}
$pending=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
 (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
 [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
Unregister-ScheduledTask -TaskName '__TASK__' -Confirm:$false -ErrorAction Stop
'WORKLOADFLEET_RESULT='+(@{restartVerified=$true;bootUtc=$boot;pendingRestart=[bool]$pending}|ConvertTo-Json -Compress)
'@.Replace('__BEFORE_BOOT__', $beforeBoot.UtcDateTime.ToString('o')).Replace('__TASK__', $before.task)
    do {
        $null = Get-ConvergenceRemainingSeconds $Deadline
        try {
            $after = Invoke-FleetGuestCommand $Answers $Workload $verify $Deadline
        } catch {
            if (!$_.Exception.Data['RunCommandExecutionFailure']) { throw }
            Write-Verbose 'Restart observation was interrupted; waiting for the same scheduled restart without scheduling another.'
            Start-Sleep -Seconds 10
            continue
        }
        if ($after['restartVerified'] -isnot [bool] -or $after['pendingRestart'] -isnot [bool]) { throw 'Guest restart acceptance failed.' }
        if (!$after.restartVerified) { Start-Sleep -Seconds 10; continue }
        if ([DateTimeOffset]::Parse($after.bootUtc) -eq $beforeBoot) { throw 'Guest restart acceptance failed.' }
        break
    } while ($true)
    if ($after['pendingRestart'] -eq $true) {
        $null = Invoke-FleetWindowsPreparation $Answers $Workload $Deadline $RestartCounts
    }
    return $true
}

function Get-EligibleFleetRestartWorkloads {
    param([hashtable]$Answers, [array]$Resolved)
    $failed = @()
    foreach ($workload in @($Resolved | Where-Object configureGuest)) {
        $id = (Get-FleetMachineId $Answers $workload) + '/extensions/workload-configuration'
        $extension = Get-ArmResource $id '2024-07-10'
        if ($extension.properties.provisioningState -eq 'Succeeded') { continue }
        if ($workload.isLinux) { throw 'Deployment has a non-restart Linux configuration failure; Windows restart retries were not attempted.' }
        $original = $Answers.workloads | Where-Object name -EQ $workload.name
        if (!$original) { throw 'Failed configuration does not match the current workload plan; no restart was attempted.' }
        $settings = $original['windowsPreparation']
        $message = $extension.properties['instanceView'] | ConvertTo-Json -Depth 12 -Compress
        if (!$settings -or $settings['restartIfRequired'] -ne $true -or
            $message -notmatch 'A Windows restart is required\.|SQL setup requires a manual restart;') {
            throw 'Deployment has a non-restart guest failure or lacks explicit restart policy. No automatic restart/retry was attempted.'
        }
        $failed += $workload
    }
    if (!$failed.Count) { throw 'Deployment failed outside eligible Windows restart convergence; inspect Azure operation details.' }
    $failed
}

function Invoke-FleetConvergence {
    param([hashtable]$Answers, [array]$Resolved, [string]$DeploymentId, [hashtable]$Body, [int]$TimeoutSeconds)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $null = Wait-ArmResource $DeploymentId '2022-09-01' (Get-ConvergenceRemainingSeconds $deadline)
    $restarts = @{}
    foreach ($workload in $Resolved) {
        $restarts[$workload.name] = 0
        $original = $Answers.workloads | Where-Object name -EQ $workload.name
        if ($workload.isLinux) {
            $text = Get-CommittedFleetGuest 'validate-linux.sh'
            $key = ($original.sshPublicKey -split ' ')[0..1] -join ' '
            $text = $text.Replace('__ADMIN_USERNAME__', $Answers.adminUsername).
                Replace('__SSH_KEY_BASE64__', [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($key))).
                Replace('__UBUNTU_VERSION__', $(if ($original.image.os -eq 'Ubuntu2404') { '24.04' } else { '22.04' }))
            $text += "`n" + 'printf ''WORKLOADFLEET_RESULT={"accepted":true}\n'''
            $acceptance = Invoke-FleetGuestCommand $Answers $workload $text $deadline
            if ($acceptance['accepted'] -isnot [bool] -or $acceptance.accepted -ne $true) { throw 'Linux readiness gate did not pass; no application/owned monitoring deployment followed.' }
        } elseif ($workload.configureGuest) {
            $null = Invoke-FleetWindowsPreparation $Answers ($original + @{ configurationHash = $workload.configurationHash }) $deadline $restarts
        }
    }
    $Body.properties.parameters.configureServices = @{ value = $true }
    $Body.properties.parameters.deployMonitoring = @{ value = $true }
    do {
        $Body.properties.parameters.runId = @{ value = [guid]::NewGuid().ToString() }
        $null = Invoke-ArmRequest -Method PUT -Path "${DeploymentId}?api-version=2022-09-01" -Body $Body
        try {
            $null = Wait-ArmResource $DeploymentId '2022-09-01' (Get-ConvergenceRemainingSeconds $deadline)
            break
        } catch {
            $state = Get-ArmResource $DeploymentId '2022-09-01'
            if ($state.properties.provisioningState -ne 'Failed') { throw }
            foreach ($workload in @(Get-EligibleFleetRestartWorkloads $Answers $Resolved)) {
                $original = $Answers.workloads | Where-Object name -EQ $workload.name
                if (!(Invoke-FleetWindowsPreparation $Answers ($original + @{ configurationHash = $workload.configurationHash }) $deadline $restarts)) {
                    throw 'Configuration reported a restart but Windows has no pending-restart evidence; automatic retry refused.'
                }
            }
        }
    } while ($true)
    Invoke-FleetPeerAcceptance $Answers $Resolved $Body.properties.parameters.adminPassword $deadline
    Invoke-FleetMonitoringAcceptance $Answers $Resolved $deadline
}

function Get-FleetAddress {
    param([hashtable]$Answers, [hashtable]$Workload)
    $id = "/subscriptions/$($Answers.subscriptionId)/resourceGroups/$($Answers.resourceGroup)/providers/Microsoft.AzureStackHCI/networkInterfaces/$($Workload.name)-nic"
    $nic = Get-ArmResource $id
    Assert-OwnedResource $nic $Answers.deploymentName $Workload.configurationHash
    Assert-ReadyResource $nic $Answers.stamp.customLocationId $Answers.location
    $ips = @($nic.properties.ipConfigurations)
    if ($ips.Count -ne 1 -or $ips[0].properties.subnet.id -ne $Answers.logicalNetworkId) { throw 'Peer NIC does not match the single approved logical network.' }
    $address = $ips[0].properties.privateIPAddress
    $number = ConvertTo-IPv4Number $address
    $network = Get-ArmResource $Answers.logicalNetworkId
    Assert-ReadyResource $network $Answers.stamp.customLocationId $Answers.location
    $subnets = @($network.properties.subnets)
    if ($subnets.Count -ne 1) { throw 'Peer acceptance requires one verifiable logical-network subnet.' }
    $subnet = $subnets[0].properties
    $prefixes = @($subnet['addressPrefixes'])
    if ($subnet['addressPrefix']) { $prefixes += $subnet.addressPrefix }
    $prefixes = @($prefixes | Where-Object { $_ } | Select-Object -Unique)
    if ($prefixes.Count -ne 1) { throw 'Peer acceptance requires a declared IPv4 subnet prefix; addresses are never guessed or sent credentials on an unverifiable DHCP network.' }
    $range = Get-CidrRange $prefixes[0]
    if ($number -le $range.Start -or $number -ge $range.End) { throw 'Peer NIC address is outside the approved logical subnet; no credential was delivered.' }
    if ($Workload.privateIpAddress -and $address -ne $Workload.privateIpAddress) { throw 'Peer NIC address drift; no client credential was delivered.' }
    $address
}

function Invoke-FleetPeerAcceptance {
    param([hashtable]$Answers, [array]$Resolved, [hashtable]$PasswordParameter, [DateTime]$Deadline)
    $client = $Resolved | Where-Object name -EQ $Answers.convergence.clientWorkloadName
    $sourceAddress = ConvertTo-IPv4Number (Get-FleetAddress $Answers $client)
    $targets = @()
    foreach ($workload in @($Resolved | Where-Object profile -In @('fileServer', 'sqlServer', 'iisServer', 'webServer'))) {
        $original = $Answers.workloads | Where-Object name -EQ $workload.name
        if (!@($original.allowedCidrs | Where-Object {
            $range = Get-CidrRange $_
            $sourceAddress -ge $range.Start -and $sourceAddress -le $range.End
        }).Count) { throw 'Configured client probe is outside a service allowlist; no credential was delivered.' }
        $target = @{ name = $workload.name; profile = $workload.profile; address = Get-FleetAddress $Answers $workload }
        switch ($workload.profile) {
            'fileServer' { $target.shareName = $original.fileServer.shareName }
            'iisServer' { $target.expectedContent = '<!doctype html><html lang="en"><title>Azure Local IIS</title><h1>Azure Local IIS reference workload</h1></html>' }
            'webServer' { $target.expectedContent = '<!doctype html><html lang="en"><title>Azure Local web server</title><h1>Nginx is ready</h1></html>' }
        }
        $targets += $target
    }
    for ($offset = 0; $offset -lt [Math]::Max(1, $targets.Count); $offset += 10) {
        $batch = @($targets | Select-Object -Skip $offset -First 10)
        Invoke-FleetPeerBatch $Answers $client $batch $PasswordParameter $Deadline
    }
}

function Invoke-FleetPeerBatch {
    param([hashtable]$Answers, [hashtable]$Client, [array]$Targets, [hashtable]$PasswordParameter, [DateTime]$Deadline)
    $guest = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-CommittedFleetGuest 'Test-FleetClient.ps1')))
    $run = [guid]::NewGuid().ToString('N')
    $command = "`$ErrorActionPreference='Stop'; . ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$guest'))))"
    $workDeadline = $Deadline.AddSeconds(-60)
    $null = Get-ConvergenceRemainingSeconds $workDeadline
    $issued = $null
    $certificate = $null
    $primaryFailure = $null
    try {
        $issued = Invoke-FleetGuestCommand $Answers $client "$command -Mode IssueCertificate -RunId '$run'" $workDeadline
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($issued.certificate))
        if ($issued.thumbprint -notmatch '^[A-Fa-f0-9]{40}$' -or $certificate.Thumbprint -ine $issued.thumbprint -or
            $certificate.Subject -cne "CN=WorkloadFleet-$run" -or $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
            throw 'Owned client did not return its expected unexpired certificate; no password was encrypted or delivered.'
        }
        if (!$PasswordParameter.ContainsKey('value') -or !$PasswordParameter.value) { throw 'Peer acceptance requires the requested in-memory administrator password.' }
        $encrypted = Protect-FleetCredential $certificate $Answers.adminUsername $PasswordParameter.value
        $configuration = @{ sourceName = $client.name; sourceDiskSizes = @($client.dataDisks | ForEach-Object sizeGB); targets = $targets }
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($configuration | ConvertTo-Json -Depth 8 -Compress)))
        $result = Invoke-FleetGuestCommand $Answers $client "$command -Mode Probe -RunId '$run' -CertificateThumbprint '$($issued.thumbprint)' -ConfigurationBase64 '$encoded' -EncryptedCredentialBase64 '$encrypted'" $workDeadline
        Assert-FleetPeerResult $result $targets
    } catch {
        $primaryFailure = $_
        throw
    } finally {
        if ($certificate) { $certificate.Dispose() }
        try {
            $null = Get-ConvergenceRemainingSeconds $Deadline
            $cleanup = "`$ErrorActionPreference='Stop'; `$certs=@(Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -CEQ 'CN=WorkloadFleet-$run'); if(`$certs.Count -gt 1){throw 'Ambiguous owned certificate'}; foreach(`$c in `$certs){Remove-Item -LiteralPath `$c.PSPath -DeleteKey};'WORKLOADFLEET_RESULT={`"certificateRemoved`":true}'"
            $removed = Invoke-FleetGuestCommand $Answers $client $cleanup $Deadline
            if ($removed['certificateRemoved'] -isnot [bool] -or !$removed.certificateRemoved) { throw 'Owned certificate cleanup was not verified.' }
        } catch {
            if (!$primaryFailure) { throw 'Peer acceptance finished but owned certificate/private-key cleanup was not verified; inspect the client before retrying.' }
            Write-Warning "Peer acceptance failed and its original error is preserved. Owned certificate cleanup remains unverified for CN=WorkloadFleet-$run; inspect that exact client certificate." -WarningAction Continue
        }
    }
}

function Assert-FleetPeerResult {
    param([hashtable]$Result, [array]$Targets)
    $expected = @($Targets | ForEach-Object name | Sort-Object)
    $actual = @($Result.targets | ForEach-Object name | Sort-Object)
    if ($Result['accepted'] -isnot [bool] -or $Result.accepted -ne $true -or ($expected -join '|') -cne ($actual -join '|')) { throw 'Peer acceptance did not verify every exact service target.' }
    foreach ($target in $Targets) {
        $evidence = $Result.targets | Where-Object name -EQ $target.name
        if ($evidence.profile -cne $target.profile) { throw 'Peer acceptance profile does not match the requested target.' }
        $required = switch ($target.profile) {
            'fileServer' { @('authenticatedWriteReadDelete', 'encryptedSmb3') }
            'sqlServer' { @('intendedAdministrator', 'normalModeQuery', 'encrypted') }
            default { @('http200') }
        }
        foreach ($flag in $required) {
            if ($evidence[$flag] -isnot [bool] -or $evidence[$flag] -ne $true) { throw 'Peer acceptance lacks a required typed service/security result.' }
        }
    }
}

function Protect-FleetCredential {
    param([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$Username, [string]$Password)
    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    if (!$rsa -or $rsa.KeySize -lt 3072) {
        if ($rsa) { $rsa.Dispose() }
        throw 'Peer encryption requires an RSA certificate of at least3072 bits.'
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes((@{ username = $Username; password = $Password } | ConvertTo-Json -Compress))
    try {
        $algorithm = [Security.Cryptography.Pkcs.AlgorithmIdentifier]::new([Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.1.42'))
        $cms = [Security.Cryptography.Pkcs.EnvelopedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($bytes), $algorithm)
        $cms.Encrypt([Security.Cryptography.Pkcs.CmsRecipient]::new($Certificate))
        [Convert]::ToBase64String($cms.Encode())
    } finally { [Array]::Clear($bytes, 0, $bytes.Length); if ($rsa) { $rsa.Dispose() } }
}

function Test-FleetMonitoringRows {
    param([hashtable]$Result, [string[]]$MachineIds)
    if ($Result.ContainsKey('error') -or !$Result['tables']) { throw 'Logs returned a partial/error result; no monitoring success is inferred.' }
    $table = $Result.tables[0]
    $columns = @($table.columns | ForEach-Object name)
    foreach ($required in @('ResourceId', 'Kind', 'Records')) {
        if ($required -notin $columns) { throw 'Logs result lacks required resource/kind/count schema.' }
    }
    $resourceIndex = [array]::IndexOf($columns, 'ResourceId')
    $kindIndex = [array]::IndexOf($columns, 'Kind')
    $countIndex = [array]::IndexOf($columns, 'Records')
    $seen = @{}
    foreach ($row in $table.rows) {
        if ($row[$countIndex] -isnot [long] -and $row[$countIndex] -isnot [int]) { throw 'Logs record counts must be integers, not success-shaped strings.' }
        if ($row[$countIndex] -gt 0 -and $row[$kindIndex] -in @('heartbeat', 'marker')) {
            $seen["$([string]$row[$resourceIndex])|$($row[$kindIndex])".ToLowerInvariant()] = $true
        }
    }
    foreach ($id in $MachineIds) {
        foreach ($kind in @('heartbeat', 'marker')) {
            if (!$seen.ContainsKey("$id|$kind".ToLowerInvariant())) { return $false }
        }
    }
    return $true
}

function Invoke-FleetMonitoringAcceptance {
    param([hashtable]$Answers, [array]$Resolved, [DateTime]$Deadline)
    $started = [DateTime]::UtcNow.ToString('o')
    $marker = [guid]::NewGuid().ToString('N')
    $workspace = Get-ArmResource $Answers.logAnalyticsWorkspaceId '2022-10-01'
    $workspaceId = [string]$workspace.properties.customerId
    if ($workspaceId -notmatch '^[0-9a-f-]{36}$') { throw 'Selected workspace has no valid Logs customer identifier.' }
    $ids = @($Resolved | ForEach-Object { Get-FleetMachineId $Answers $_ })
    $literals = ($ids | ForEach-Object { "'$_'" }) -join ','
    $query = "union isfuzzy=true withsource=TableName Heartbeat,Event,Syslog | where TimeGenerated >= datetime($started) | where _ResourceId in~ ($literals) | extend Kind=case(TableName == 'Heartbeat','heartbeat',strcat(tostring(column_ifexists('RenderedDescription','')),tostring(column_ifexists('SyslogMessage',''))) contains 'WorkloadFleet-$marker','marker','') | where Kind != '' | summarize Records=count() by ResourceId=tolower(_ResourceId),Kind"
    $seconds = if ($Answers.convergence.ContainsKey('monitoringTimeoutSeconds')) { $Answers.convergence.monitoringTimeoutSeconds } else { 900 }
    $monitoringDeadline = [DateTime]::UtcNow.AddSeconds($seconds)
    if ($monitoringDeadline -gt $Deadline) { $monitoringDeadline = $Deadline }
    $client = [Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(90)
    try {
        do {
            $null = Get-ConvergenceRemainingSeconds $monitoringDeadline
            foreach ($workload in $Resolved) {
                if ($workload.isLinux) {
                    $text = "set -eu`nlogger -p user.warning -- WorkloadFleet-$marker`nprintf 'WORKLOADFLEET_RESULT={`"markerEmitted`":true}\n'"
                } else {
                    $text = @'
$ErrorActionPreference='Stop'
$source='WorkloadFleet'
if([Diagnostics.EventLog]::SourceExists($source)){
 if([Diagnostics.EventLog]::LogNameFromSourceName($source,'.') -ne 'Application'){throw 'Event source belongs to another log.'}
}else{New-EventLog -LogName Application -Source $source}
Write-EventLog -LogName Application -Source $source -EntryType Warning -EventId 9001 -Message 'WorkloadFleet-__MARKER__'
'WORKLOADFLEET_RESULT={"markerEmitted":true}'
'@.Replace('__MARKER__', $marker)
                }
                $emitted = Invoke-FleetGuestCommand $Answers $workload $text $monitoringDeadline
                if ($emitted['markerEmitted'] -isnot [bool] -or !$emitted.markerEmitted) { throw 'Resource monitoring marker was not emitted; no ingestion success is inferred.' }
            }
            $result = Invoke-FleetMonitoringQuery $client $workspaceId $query $monitoringDeadline
            if (Test-FleetMonitoringRows $result $ids) { return }
            if ([DateTime]::UtcNow -ge $monitoringDeadline) {
                throw 'Selected workspace did not return fresh resource-scoped Heartbeat and unique Event/Syslog markers for every workload before the deadline.'
            }
            Start-Sleep -Seconds 30
        } while ($true)
    } finally { $client.Dispose() }
}

function Invoke-FleetMonitoringQuery {
    param([Net.Http.HttpClient]$Client, [string]$WorkspaceId, [string]$Query, [DateTime]$Deadline)
    $token = Get-ArmToken 'https://api.loganalytics.io'
    $Client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token.accessToken)
    $token = $null
    $content = [Net.Http.StringContent]::new((@{ query = $Query } | ConvertTo-Json -Compress), [Text.Encoding]::UTF8, 'application/json')
    $cancellation = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds([Math]::Min(90, (Get-ConvergenceRemainingSeconds $Deadline))))
    $response = $null
    try {
        $response = $Client.PostAsync("https://api.loganalytics.azure.com/v1/workspaces/$WorkspaceId/query", $content, $cancellation.Token).GetAwaiter().GetResult()
        if (!$response.IsSuccessStatusCode) { throw "Selected-workspace Logs query failed (HTTP $([int]$response.StatusCode)); no alternate workspace/account or policy modification was attempted." }
        $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json -AsHashtable
    } finally { $content.Dispose(); $cancellation.Dispose(); if ($response) { $response.Dispose() } }
}

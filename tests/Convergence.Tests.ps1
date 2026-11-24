BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\WorkloadDeployment.psm1') -Force
}

Describe 'Opt-in fleet convergence' {
    InModuleScope WorkloadDeployment {
        BeforeAll {
            function New-FleetFixture {
                $a = Get-Content (Join-Path $script:Root 'answers\example.json') -Raw | ConvertFrom-Json -AsHashtable
                $a.Remove('namingPrefix')
                $a.passwordSource = @{ type = 'environment'; name = 'UNIT_TEST_PASSWORD' }
                $a.workloads = @($a.workloads | Where-Object profile -In @('fileServer', 'windowsApp'))
                foreach ($w in $a.workloads) {
                    $w.name = if ($w.profile -eq 'fileServer') { 'FS-01' } else { 'WIN-01' }
                    $w.Remove('count')
                    $w.Remove('privateIpAddresses')
                }
                $a.convergence = @{ clientWorkloadName = 'WIN-01'; monitoringTimeoutSeconds = 60 }
                $a
            }
            function New-ResolvedFixture($Answers) {
                @($Answers.workloads | ForEach-Object {
                    @{ name = $_.name; profile = $_.profile; isLinux = $false; configureGuest = $_.profile -ne 'windowsApp'
                        configurationHash = 'a' * 64; privateIpAddress = ''; dataDisks = @(Get-WorkloadDisks $_) }
                })
            }
            function New-MonitoringFixture([string[]]$Ids) {
                @{ tables = @(@{
                    columns = @(@{name='Kind'}, @{name='Records'}, @{name='ResourceId'})
                    rows = @($Ids | ForEach-Object { ,@('heartbeat', 1, $_); ,@('marker', 1, $_) })
                }) }
            }
        }
        It 'validates the exact expanded Windows client and rejects unsupported credential references without Azure calls' {
            $a = New-FleetFixture
            $a.namingPrefix = 'BOS'
            $a.convergence.clientWorkloadName = 'BOS-WIN-01'
            $path = Join-Path $TestDrive 'convergence.json'
            $a | ConvertTo-Json -Depth 30 | Set-Content $path
            (Read-WorkloadAnswers $path).convergence.clientWorkloadName | Should -Be 'BOS-WIN-01'
            $a.convergence.clientWorkloadName = 'BOS-FS-01'
            $a | ConvertTo-Json -Depth 30 | Set-Content $path
            { Read-WorkloadAnswers $path } | Should -Throw '*windowsApp*'
            $a = New-FleetFixture
            $a.passwordSource = @{ type = 'keyVault' }
            { Assert-ConvergenceAnswers $a } | Should -Throw '*Key Vault*'
        }
        It 'keeps a zero-count convergent fleet a no-op without Azure authentication or password reads' {
            $a = New-FleetFixture
            foreach ($w in $a.workloads) { $w.count = 0 }
            $path = Join-Path $TestDrive 'zero-convergence.json'
            $a | ConvertTo-Json -Depth 30 | Set-Content $path
            Mock Open-ArmConnection { throw 'No Azure connection is allowed.' }
            Mock Get-PasswordParameter { throw 'No password read is allowed.' }
            ((Start-WorkloadDeployment -AnswerFile $path -Mode Deploy -Confirm:$false) -join "`n") | Should -Match 'All workload counts are zero'
            Should -Invoke Open-ArmConnection -Times 0
            Should -Invoke Get-PasswordParameter -Times 0
        }
        It 'requires explicit Marketplace SQL administrator and client-access policies for peer acceptance' {
            $a = New-FleetFixture
            $a.workloads += @{ name = 'SQL-01'; profile = 'sqlServer'; sqlServer = @{ installationMode = 'marketplace' } }
            { Assert-ConvergenceAnswers $a } | Should -Throw '*administratorPolicy*'
            $a.workloads[-1].sqlServer.administratorPolicy = 'grantIfAuthorized'
            $a.workloads[-1].sqlServer.clientAccess = $true
            { Assert-ConvergenceAnswers $a } | Should -Not -Throw
        }
        It 'bounds convergence and leaves existing resources intact at expiry' {
            { Get-ConvergenceRemainingSeconds ([DateTime]::UtcNow.AddSeconds(-1)) } | Should -Throw '*preserved*'
        }
        It 'uses Linux-compatible command names and waits for execution rather than provisioning alone' {
            $a = New-FleetFixture
            $w = (New-ResolvedFixture $a)[0]
            $script:commandReads=0
            $script:commandSubmitted=$false
            Mock Assert-OwnedResource {}
            Mock Start-Sleep {}
            Mock Invoke-ArmRequest {
                $script:commandSubmitted=$true
                $script:commandNonce=$Body.properties.forceUpdateTag
                (($Path -split '/runCommands/')[1] -split '\?')[0].Length | Should -BeLessOrEqual 36
                $Body.properties.source.script | Should -Not -Match "`r"
                $Body.properties.source.script.EndsWith("`n") | Should -BeTrue
            }
            Mock Get-ArmResource {
                if ($Id -notmatch '/runCommands/') { return @{properties=@{status='Connected'}} }
                if (!$script:commandSubmitted) { return $null }
                $script:commandReads++
                @{properties=@{provisioningState='Succeeded';instanceView=@{
                    executionState=$(if($script:commandReads -eq 1){'Running'}else{'Succeeded'})
                    exitCode=0;output="WORKLOADFLEET_INVOCATION=$script:commandNonce`n"+'WORKLOADFLEET_RESULT={"accepted":true}'
                }}}
            }
            (Invoke-FleetGuestCommand $a $w "NO LIVE`r`nEXECUTION" ([DateTime]::UtcNow.AddMinutes(5))).accepted | Should -BeTrue
            $script:commandReads | Should -Be 2
            Should -Invoke Assert-OwnedResource -Times 1
        }
        It 'waits for a newly submitted command to become readable without resubmitting it' {
            $a = New-FleetFixture
            $w = (New-ResolvedFixture $a)[0]
            $script:commandReads = 0
            $script:commandSubmitted=$false
            Mock Assert-OwnedResource {}
            Mock Start-Sleep {}
            Mock Invoke-ArmRequest { $script:commandSubmitted=$true; $script:commandNonce=$Body.properties.forceUpdateTag }
            Mock Get-ArmResource {
                if ($Id -notmatch '/runCommands/') { return @{properties=@{status='Connected'}} }
                if (!$script:commandSubmitted) { return $null }
                $AllowNotFound | Should -BeTrue
                $script:commandReads++
                if ($script:commandReads -eq 1) { return $null }
                @{properties=@{provisioningState='Succeeded';instanceView=@{
                    executionState='Succeeded';exitCode=0;output="WORKLOADFLEET_INVOCATION=$script:commandNonce`n"+'WORKLOADFLEET_RESULT={"accepted":true}'
                }}}
            }
            (Invoke-FleetGuestCommand $a $w 'NO LIVE EXECUTION' ([DateTime]::UtcNow.AddMinutes(5))).accepted | Should -BeTrue
            $script:commandReads | Should -Be 2
            Should -Invoke Invoke-ArmRequest -Times 1
            Should -Invoke Start-Sleep -Times 1
        }
        It 'does not retry or resubmit a command when its read fails for a non-not-found error' {
            $a = New-FleetFixture
            $w = (New-ResolvedFixture $a)[0]
            Mock Assert-OwnedResource {}
            Mock Start-Sleep {}
            Mock Invoke-ArmRequest {}
            Mock Get-ArmResource {
                if ($Id -notmatch '/runCommands/') { return @{properties=@{status='Connected'}} }
                throw 'HTTP 403'
            }
            { Invoke-FleetGuestCommand $a $w 'NO LIVE EXECUTION' ([DateTime]::UtcNow.AddMinutes(5)) } | Should -Throw '*HTTP 403*'
            Should -Invoke Invoke-ArmRequest -Times 0
            Should -Invoke Start-Sleep -Times 0
        }
        It 'reuses only a completed owned command and ignores stale success until the fresh nonce appears' {
            $a=New-FleetFixture
            $w=(New-ResolvedFixture $a)[0]
            $script:slotReads=0
            $script:slotNonce='previous'
            Mock Assert-OwnedResource {}
            Mock Start-Sleep {}
            Mock Invoke-ArmRequest {
                $CreateOnly | Should -BeFalse
                $Path | Should -Match "/runCommands/wlcf-$('a' * 24)\?"
                $Body.tags.configurationHash | Should -Be $w.configurationHash
                $script:slotNonce=$Body.properties.forceUpdateTag
            }
            Mock Get-ArmResource {
                if($Id -notmatch '/runCommands/'){return @{properties=@{status='Connected'}}}
                $script:slotReads++
                $nonce=if($script:slotReads -le 2){'previous'}else{$script:slotNonce}
                @{tags=@{project='azure-local-workload-templates'};properties=@{provisioningState='Succeeded';instanceView=@{
                    executionState='Succeeded';exitCode=0
                    output="WORKLOADFLEET_INVOCATION=$nonce`n"+'WORKLOADFLEET_RESULT={"accepted":true}'
                }}}
            }
            (Invoke-FleetGuestCommand $a $w 'NO LIVE EXECUTION' ([DateTime]::UtcNow.AddMinutes(2))).accepted | Should -BeTrue
            $script:slotReads | Should -Be 3
            Should -Invoke Invoke-ArmRequest -Times 1
            Should -Invoke Start-Sleep -Times 1
        }
        It 'does not overwrite an active owned command or reuse an unowned slot' {
            $a=New-FleetFixture
            $w=(New-ResolvedFixture $a)[0]
            Mock Invoke-ArmRequest {}
            Mock Assert-OwnedResource {}
            Mock Get-ArmResource {
                if($Id -notmatch '/runCommands/'){return @{properties=@{status='Connected'}}}
                @{tags=@{project='azure-local-workload-templates'};properties=@{provisioningState='Updating';instanceView=@{executionState='Running'}}}
            }
            { Invoke-FleetGuestCommand $a $w 'NO LIVE EXECUTION' ([DateTime]::UtcNow.AddMinutes(2)) } | Should -Throw '*active*'
            Mock Assert-OwnedResource { if($Resource.properties['instanceView']){throw 'Unowned slot'} }
            { Invoke-FleetGuestCommand $a $w 'NO LIVE EXECUTION' ([DateTime]::UtcNow.AddMinutes(2)) } | Should -Throw '*Unowned*'
            Should -Invoke Invoke-ArmRequest -Times 0
        }
        It 'reuses its completed source-stamped command after all returned tags disappear' {
            $a=New-FleetFixture
            $w=(New-ResolvedFixture $a)[0]
            $script:ownedSlot=$null
            $script:slotCreates=@()
            Mock Start-Sleep {}
            Mock Get-ArmResource {
                if($Id -notmatch '/runCommands/'){
                    return @{name=$w.name;tags=@{project='azure-local-workload-templates';deploymentSet=$a.deploymentName;configurationHash=$w.configurationHash};properties=@{status='Connected'}}
                }
                $script:ownedSlot
            }
            Mock Invoke-ArmRequest {
                $script:slotCreates+=@([bool]$CreateOnly)
                $script:ownedSlot=@{properties=@{
                    source=$Body.properties.source;provisioningState='Succeeded'
                    instanceView=@{executionState='Succeeded';exitCode=0;output="WORKLOADFLEET_INVOCATION=$($Body.properties.forceUpdateTag)`n"+'WORKLOADFLEET_RESULT={"accepted":true}'}
                }}
            }
            (Invoke-FleetGuestCommand $a $w 'NO LIVE EXECUTION' ([DateTime]::UtcNow.AddMinutes(2))).accepted | Should -BeTrue
            (Invoke-FleetGuestCommand $a $w 'SECOND SAFE SCRIPT' ([DateTime]::UtcNow.AddMinutes(2))).accepted | Should -BeTrue
            ($script:slotCreates -join ',') | Should -Be 'True,False'
            Should -Invoke Invoke-ArmRequest -Times 2
        }
        It 'refuses <change> even after previously creating the slot' -ForEach @(
            @{change='an unmarked source'},
            @{change='a missing source'},
            @{change='a foreign source stamp'},
            @{change='conflicting tags'},
            @{change='incomplete tags'},
            @{change='an active stamped command'}
        ) {
            $a=New-FleetFixture
            $w=(New-ResolvedFixture $a)[0]
            $script:ownedSlot=$null
            Mock Start-Sleep {}
            Mock Get-ArmResource {
                if($Id -notmatch '/runCommands/'){
                    return @{name=$w.name;tags=@{project='azure-local-workload-templates';deploymentSet=$a.deploymentName;configurationHash=$w.configurationHash};properties=@{status='Connected'}}
                }
                $script:ownedSlot
            }
            Mock Invoke-ArmRequest {
                $script:ownedSlot=@{properties=@{
                    source=$Body.properties.source;provisioningState='Succeeded'
                    instanceView=@{executionState='Succeeded';exitCode=0;output="WORKLOADFLEET_INVOCATION=$($Body.properties.forceUpdateTag)`n"+'WORKLOADFLEET_RESULT={"accepted":true}'}
                }}
            }
            (Invoke-FleetGuestCommand $a $w 'NO LIVE EXECUTION' ([DateTime]::UtcNow.AddMinutes(2))).accepted | Should -BeTrue
            switch($change){
                'an unmarked source' {$script:ownedSlot.properties.source.script=$script:ownedSlot.properties.source.script -replace '^#[^\n]+\n',''}
                'a missing source' {$script:ownedSlot.properties.Remove('source')}
                'a foreign source stamp' {$script:ownedSlot.properties.source.script=$script:ownedSlot.properties.source.script -replace '^#[^\n]+\n',"# WORKLOADFLEET_OWNER=foreign`n"}
                'conflicting tags' {$script:ownedSlot.tags=@{project='azure-local-workload-templates';deploymentSet='another-deployment';configurationHash=$w.configurationHash}}
                'incomplete tags' {$script:ownedSlot.tags=@{project='azure-local-workload-templates'}}
                'an active stamped command' {$script:ownedSlot.properties.provisioningState='Updating';$script:ownedSlot.properties.instanceView.executionState='Running'}
            }
            { Invoke-FleetGuestCommand $a $w 'MUST NOT EXECUTE' ([DateTime]::UtcNow.AddMinutes(2)) } | Should -Throw
            Should -Invoke Invoke-ArmRequest -Times 1
        }
        It 'batches growing peer fleets while retaining every exact target and no extra VM' {
            $a=New-FleetFixture
            $a.workloads[0].allowedCidrs=@('192.0.2.0/24')
            foreach($i in 2..21){$clone=$a.workloads[0].Clone();$clone.name=('FS-{0:D2}' -f $i);$a.workloads+=$clone}
            $resolved=New-ResolvedFixture $a
            $script:batchNames=[Collections.Generic.List[string]]::new()
            Mock Get-FleetAddress {'192.0.2.10'}
            Mock Invoke-FleetPeerBatch {
                $Targets.Count | Should -BeLessOrEqual 10
                $Client.name | Should -Be WIN-01
                foreach($target in $Targets){$script:batchNames.Add($target.name)}
            }
            Invoke-FleetPeerAcceptance $a $resolved @{value='unit-test-only'} ([DateTime]::UtcNow.AddMinutes(5))
            Should -Invoke Invoke-FleetPeerBatch -Times 3
            ($script:batchNames | Sort-Object) -join ',' | Should -Be (($resolved | Where-Object profile -EQ fileServer | ForEach-Object name | Sort-Object) -join ',')
        }
        It 'refuses NIC subnet/address drift before any peer credential delivery' {
            $a=New-FleetFixture
            $w=(New-ResolvedFixture $a)[0]
            Mock Assert-OwnedResource {}
            Mock Assert-ReadyResource {}
            Mock Get-ArmResource {
                if($Id -eq $a.logicalNetworkId){return @{properties=@{subnets=@(@{properties=@{addressPrefix='192.0.2.0/24'}})}}}
                @{properties=@{ipConfigurations=@(@{properties=@{subnet=@{id=$a.logicalNetworkId};privateIPAddress='192.0.3.10'}})}}
            }
            Mock Invoke-FleetPeerBatch {throw 'No credential delivery allowed.'}
            {Invoke-FleetPeerAcceptance $a (New-ResolvedFixture $a) @{value='unit-test-only'} ([DateTime]::UtcNow.AddMinutes(5))} | Should -Throw '*outside*'
            Should -Invoke Invoke-FleetPeerBatch -Times 0
        }
        It 'gates application deployment and every acceptance phase on Linux readiness' {
            $a = New-FleetFixture
            $a.workloads += @{ name = 'LIN-01'; profile = 'linuxApp'; image = @{os='Ubuntu2404'}; sshPublicKey='ssh-rsa dGVzdA==' }
            $resolved = @(New-ResolvedFixture $a)
            $resolved[-1].isLinux = $true
            Mock Wait-ArmResource { @{ properties = @{ provisioningState = 'Succeeded' } } }
            Mock Get-CommittedFleetGuest { 'SAFE-UNIT-TEST-VALIDATOR' }
            Mock Invoke-FleetWindowsPreparation { $false }
            Mock Invoke-FleetGuestCommand { throw 'invalid cloud-init schema' }
            Mock Invoke-ArmRequest { throw 'Must not deploy applications after a failed Linux gate' }
            Mock Invoke-FleetPeerAcceptance {}
            Mock Invoke-FleetMonitoringAcceptance {}
            $body = @{ properties = @{ parameters = @{ adminPassword = @{value='unit-test-only'} } } }
            { Invoke-FleetConvergence $a $resolved '/deployment' $body 120 } | Should -Throw '*invalid cloud-init schema*'
            Should -Invoke Invoke-ArmRequest -Times 0
            Should -Invoke Invoke-FleetPeerAcceptance -Times 0
            Should -Invoke Invoke-FleetMonitoringAcceptance -Times 0
        }
        It 'runs service deployment before peer checks and workspace ingestion without automatic restart by default' {
            $a = New-FleetFixture
            $resolved = New-ResolvedFixture $a
            $script:sequence = [Collections.Generic.List[string]]::new()
            Mock Wait-ArmResource { $script:sequence.Add('wait') }
            Mock Invoke-FleetWindowsPreparation { $script:sequence.Add('prepare'); $false }
            Mock Invoke-ArmRequest {
                $Body.properties.parameters.configureServices.value | Should -BeTrue
                $Body.properties.parameters.deployMonitoring.value | Should -BeTrue
                $script:sequence.Add('services')
            }

            Mock Invoke-FleetPeerAcceptance { $script:sequence.Add('peers') }
            Mock Invoke-FleetMonitoringAcceptance { $script:sequence.Add('monitoring') }
            $body = @{ properties = @{ parameters = @{ adminPassword = @{value='unit-test-only'} } } }
            Invoke-FleetConvergence $a $resolved '/deployment' $body 120
            ($script:sequence -join ',') | Should -Be 'wait,prepare,services,wait,peers,monitoring'
        }
        It 'requires distinct actual Linux identities before service or monitoring convergence' {
            $identities = @{}
            { Assert-FleetLinuxIdentity @{machineIdentitySha256='a' * 64} $identities } | Should -Not -Throw
            { Assert-FleetLinuxIdentity @{machineIdentitySha256='b' * 64} $identities } | Should -Not -Throw
            { Assert-FleetLinuxIdentity @{machineIdentitySha256='a' * 64} $identities } | Should -Throw '*duplicate*'
            foreach ($invalid in @($null, '', ('a' * 32), 'not-a-hash')) {
                { Assert-FleetLinuxIdentity @{machineIdentitySha256=$invalid} $identities } | Should -Throw '*identity*'
            }
        }
        It 'rejects non-restart configuration failures even when a different Windows failure is restart eligible' {
            $a = New-FleetFixture
            $a.workloads[0].windowsPreparation = @{scopeInheritedFirewall=$false;restartIfRequired=$true}
            $resolved = New-ResolvedFixture $a
            $resolved += @{ name='LIN-01';profile='linuxApp';configureGuest=$true;isLinux=$true }
            Mock Get-ArmResource {
                @{ properties = @{ provisioningState='Failed'; instanceView=@{status=@{message='A Windows restart is required.'}} } }
            }
            { Get-EligibleFleetRestartWorkloads $a $resolved } | Should -Throw '*non-restart*'
        }
        It 'allows only two verified restarts and never schedules a third' {
            $a = New-FleetFixture
            $w = (New-ResolvedFixture $a)[0]
            $counts = @{$w.name=0}
            Mock Get-WindowsPreparationCommand { 'PREPARE' }
            Mock Start-Sleep {}
            Mock Invoke-FleetGuestCommand {
                if ($Script -eq 'PREPARE') {
                    @{ restartScheduled=$true;bootUtc='2020-01-01T00:00:00Z';task=('AzureLocalWorkload-Restart-'+('a'*32)) }
                } else { @{restartVerified=$true;bootUtc='2020-01-02T00:00:00Z';pendingRestart=$false} }
            }
            foreach ($i in 1..2) { Invoke-FleetWindowsPreparation $a $w ([DateTime]::UtcNow.AddMinutes(5)) $counts | Should -BeTrue }
            { Invoke-FleetWindowsPreparation $a $w ([DateTime]::UtcNow.AddMinutes(5)) $counts } | Should -Throw '*third*'
            Should -Invoke Invoke-FleetGuestCommand -Times 4
        }
        It 'does not accept a scheduled restart whose boot evidence did not change' {
            $a = New-FleetFixture
            $w = (New-ResolvedFixture $a)[0]
            Mock Get-WindowsPreparationCommand { 'PREPARE' }
            Mock Start-Sleep {}
            Mock Invoke-FleetGuestCommand {
                @{ restartScheduled=$true;restartVerified=$true;bootUtc='2020-01-01T00:00:00Z';task=('AzureLocalWorkload-Restart-'+('a'*32)) }
            }
            { Invoke-FleetWindowsPreparation $a $w ([DateTime]::UtcNow.AddMinutes(5)) @{$w.name=0} } | Should -Throw '*restart acceptance*'
        }
        It 'waits through a pre-reboot observation and an interrupted command without scheduling another restart' {
            $a=New-FleetFixture
            $w=(New-ResolvedFixture $a)[0]
            $script:observations=0
            Mock Get-WindowsPreparationCommand {'PREPARE'}
            Mock Start-Sleep {}
            Mock Invoke-FleetGuestCommand {
                if($Script -eq 'PREPARE'){return @{restartScheduled=$true;bootUtc='2020-01-01T00:00:00Z';task=('AzureLocalWorkload-Restart-'+('a'*32))}}
                $script:observations++
                if($script:observations -eq 1){return @{restartVerified=$false;bootUtc='2020-01-01T00:00:00Z';pendingRestart=$true}}
                if($script:observations -eq 2){$e=[InvalidOperationException]::new('Interrupted reboot observation');$e.Data['RunCommandExecutionFailure']=$true;throw $e}
                @{restartVerified=$true;bootUtc='2020-01-02T00:00:00Z';pendingRestart=$false}
            }
            $counts=@{$w.name=0}
            Invoke-FleetWindowsPreparation $a $w ([DateTime]::UtcNow.AddMinutes(5)) $counts | Should -BeTrue
            $counts[$w.name] | Should -Be 1
            Should -Invoke Invoke-FleetGuestCommand -Times 1 -ParameterFilter {$Script -eq 'PREPARE'}
        }
        It 're-emits the same run-scoped warning while collection propagation is pending' {
            $a=New-FleetFixture
            $resolved=New-ResolvedFixture $a
            $script:queries=0
            Mock Get-ArmResource {@{properties=@{customerId='00000000-0000-0000-0000-000000000001'}}}
            Mock Invoke-FleetGuestCommand {@{markerEmitted=$true}}
            Mock Start-Sleep {}
            Mock Invoke-FleetMonitoringQuery {
                $script:queries++
                $r=New-MonitoringFixture @($resolved | ForEach-Object {Get-FleetMachineId $a $_})
                if($script:queries -eq 1){$r.tables[0].rows=@($r.tables[0].rows | Where-Object {$_[0] -eq 'heartbeat'})}
                $r
            }
            Invoke-FleetMonitoringAcceptance $a $resolved ([DateTime]::UtcNow.AddMinutes(5))
            Should -Invoke Invoke-FleetGuestCommand -Times 4
            Should -Invoke Invoke-FleetMonitoringQuery -Times 2
        }
        It 'rejects uncommitted preparation or validation scripts before guest execution' {
            Mock Invoke-SourceGit {
                if($Arguments[0] -eq 'hash-object'){return 'dirty-blob'}
                if($Arguments[0] -eq 'show'){throw 'Must not read changed working-tree content.'}
                'committed-blob'
            }
            foreach($name in @('Configure-Windows.ps1','validate-linux.sh','Test-FleetClient.ps1')){
                {Get-CommittedFleetGuest $name} | Should -Throw '*uncommitted*'
            }
            Should -Invoke Invoke-SourceGit -Times 0 -ParameterFilter {$Arguments[0] -eq 'show'}
        }
        It 'cleans the exact subject after failed certificate issuance and preserves the original failure' {
            $a=New-FleetFixture
            $client=(New-ResolvedFixture $a)[1]
            Mock Get-CommittedFleetGuest {'# No live script execution.'}
            Mock Invoke-FleetGuestCommand {
                if($Script -match '-Mode IssueCertificate'){throw 'Original issuance failure'}
                $Script | Should -Match 'Where-Object Subject -CEQ'
                $Script | Should -Match '\-DeleteKey'
                @{certificateRemoved=$true}
            }
            {Invoke-FleetPeerBatch $a $client @() @{value='unit-test-only'} ([DateTime]::UtcNow.AddMinutes(5))} | Should -Throw '*Original issuance failure*'
            Should -Invoke Invoke-FleetGuestCommand -Times 2
        }
        It 'decrypts the actual guest credential block under Windows PowerShell 5.1, not only modern .NET' -Skip:(!(Test-Path "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe")) {
            $rsa=[Security.Cryptography.RSA]::Create(3072)
            $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=WorkloadFleet-unit',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddMinutes(5))
            try {
                $pfx=Join-Path $TestDrive 'guest-unit.pfx'
                [IO.File]::WriteAllBytes($pfx,$cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx,'unit-pfx-only'))
                $cipher=Protect-FleetCredential $cert 'vmadmin' 'unit-credential-only'
                $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"targets":[]}'))
                $tokens=$null;$errors=$null
                $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'guest\Test-FleetClient.ps1'),[ref]$tokens,[ref]$errors)
                $block=$ast.FindAll({param($n);$n -is [Management.Automation.Language.TryStatementAst] -and $n.CatchClauses.Count -gt 0 -and (($n.CatchClauses | ForEach-Object {$_.Extent.Text}) -join "`n") -match 'Peer configuration/credential decryption failed'},$true)[0].Body.Extent.Text
                $harness=Join-Path $TestDrive 'decode-guest.ps1'
                @"
`$ErrorActionPreference='Stop'
`$cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new('$($pfx.Replace("'","''"))','unit-pfx-only',[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
`$ConfigurationBase64='$encoded'
`$EncryptedCredentialBase64='$cipher'
try{
 . $block
 if(`$credential.username -ne 'vmadmin' -or `$credential.password -ne 'unit-credential-only'){throw 'Guest decoder mismatch'}
 'decoded=true'
}finally{`$cert.Dispose()}
"@ | Set-Content -LiteralPath $harness
                $output=& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $harness 2>&1
                $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
                $output | Should -Contain 'decoded=true'
            } finally {$cert.Dispose();$rsa.Dispose()}
        }
        It 'requires both fresh evidence kinds for each exact resource, not row counts or neighboring identities' {
            $ids = @('/resources/one', '/resources/two')
            $result = New-MonitoringFixture $ids
            Test-FleetMonitoringRows $result $ids | Should -BeTrue
            $result.tables[0].rows[-1][2] = '/resources/two-neighbor'
            Test-FleetMonitoringRows $result $ids | Should -BeFalse
            $result.tables[0].rows[-1][2] = '/RESOURCES/TWO'
            $result.tables[0].rows[-1][1] = 0
            Test-FleetMonitoringRows $result $ids | Should -BeFalse
        }
        It 'does not mistake a guest accepted flag or correct names for authenticated service/security acceptance' {
            $targets = @(@{name='SQL-01';profile='sqlServer'})
            $result = @{accepted=$true;targets=@(@{name='SQL-01';profile='sqlServer';intendedAdministrator=$true;normalModeQuery=$true;encrypted=$true})}
            { Assert-FleetPeerResult $result $targets } | Should -Not -Throw
            $result.targets[0].encrypted=$false
            { Assert-FleetPeerResult $result $targets } | Should -Throw '*service/security*'
            $result.targets[0].encrypted='true'
            { Assert-FleetPeerResult $result $targets } | Should -Throw '*typed*'
            { Assert-FleetPeerResult @{accepted=$true;targets=@()} @() } | Should -Not -Throw
        }
        It 'rejects partial Logs failures, missing schema and success-shaped count strings' {
            { Test-FleetMonitoringRows @{error=@{code='PartialError'}} @('/resources/one') } | Should -Throw '*partial*'
            $r = New-MonitoringFixture @('/resources/one')
            $r.tables[0].columns = @(@{name='Computer'})
            { Test-FleetMonitoringRows $r @('/resources/one') } | Should -Throw '*schema*'
            $r = New-MonitoringFixture @('/resources/one')
            $r.tables[0].rows[0][1] = 'success'
            { Test-FleetMonitoringRows $r @('/resources/one') } | Should -Throw '*integers*'
        }
        It 'encrypts recoverable peer credentials with AES256/RSA3072 without placing plaintext in the transport' {
            $rsa = [Security.Cryptography.RSA]::Create(3072)
            $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=WorkloadFleet-unit', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddMinutes(5))
            try {
                $cipher = Protect-FleetCredential $cert 'vmadmin' 'Unit-test-only-not-a-live-password'
                $cipher | Should -Not -Match 'Unit-test-only'
                $cms = [Security.Cryptography.Pkcs.EnvelopedCms]::new()
                $cms.Decode([Convert]::FromBase64String($cipher))
                $cms.ContentEncryptionAlgorithm.Oid.Value | Should -Be '2.16.840.1.101.3.4.1.42'
                $cms.Decrypt([Security.Cryptography.X509Certificates.X509Certificate2Collection]::new($cert))
                $decoded = [Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content) | ConvertFrom-Json
                $decoded.username | Should -Be vmadmin
                $decoded.password | Should -Be 'Unit-test-only-not-a-live-password'
            } finally { $cert.Dispose(); $rsa.Dispose() }
        }
        It 'refuses weak peer encryption keys before returning a credential payload' {
            $rsa = [Security.Cryptography.RSA]::Create(2048)
            $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=WorkloadFleet-unit', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddMinutes(5))
            try { { Protect-FleetCredential $cert 'vmadmin' 'unit-test-only' } | Should -Throw '*3072*' }
            finally { $cert.Dispose(); $rsa.Dispose() }
        }
    }
}

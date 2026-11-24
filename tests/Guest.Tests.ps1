BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\guest\Configure-Windows.ps1'
    $tokens = $null
    $errors = $null
    $script:guestAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $scriptPath, [ref]$tokens, [ref]$errors)
    $script:parseErrors = @($errors)
    # Import only function definitions: no disk, firewall, role, network, or service calls.
    foreach ($definition in $script:guestAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $false)) {
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    function New-Payload($Configuration) {
        [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Configuration | ConvertTo-Json -Depth 8 -Compress)))
    }
    function New-Config {
        @{
            profile = 'fileServer'; adminUsername = 'vmadmin'
            allowedCidrs = @('192.0.2.0/24'); dataDiskSizeGB = 128
            fileServer = @{ shareName = 'Data' }
        }
    }
    function New-SqlConfig {
        $c = New-Config
        $c.profile = 'sqlServer'
        $c.Remove('fileServer')
        $c.sqlServer = @{
            installerUrl = 'https://downloads.example.com/SQL2022.iso'
            installerSha256 = 'a' * 64; edition = 'Developer'
            acceptLicenseTerms = $true; productionLicenseConfirmed = $false
        }
        $c
    }
}

Describe 'Windows guest script' {
    It 'parses the entire script without errors' { $script:parseErrors.Count | Should -Be 0 }
    It 'requires ConfigurationBase64 and guards execution when dot-sourced' {
        $script:guestAst.ParamBlock.Parameters.Name.VariablePath.UserPath | Should -Contain 'ConfigurationBase64'
        $script:guestAst.EndBlock.Statements[-1].Extent.Text | Should -Match "MyInvocation.InvocationName -ne '\.'"
    }
}

Describe 'Windows server compatibility' {
    It 'accepts Windows Server 2022 and 2025 without accepting desktop builds' {
        foreach ($build in @('20348', '26100')) {
            { Assert-WindowsServerVersion ([pscustomobject]@{ BuildNumber = $build; ProductType = 3 }) } | Should -Not -Throw
            { Assert-WindowsServerVersion ([pscustomobject]@{ BuildNumber = $build; ProductType = 1 }) } | Should -Throw '*Windows Server*'
        }
    }
    It 'rejects other or missing server versions before workload changes' {
        foreach ($build in @('17763', '26200', $null)) {
            { Assert-WindowsServerVersion ([pscustomobject]@{ BuildNumber = $build; ProductType = 3 }) } | Should -Throw '*Windows Server*'
        }
        { Assert-WindowsServerVersion ([pscustomobject]@{ BuildNumber = '26100'; ProductType = $null }) } | Should -Throw '*Windows Server*'
    }
}

Describe 'Explicit Marketplace SQL administrator convergence' {
    BeforeEach {
        $sql = [pscustomobject]@{ administratorPolicy = 'grantIfAuthorized' }
        $admin = [pscustomobject]@{ Name = 'vmadmin' }
        $script:granted = $false
        $script:systemRole = 1
        Mock Get-SqlResult {
            if ($Query -match 'DECLARE names CURSOR') {
                $script:granted = $true
                return [pscustomobject]@{ Rows = @([pscustomobject]@{ Granted = 1 }) }
            }
            [pscustomobject]@{ Rows = @([pscustomobject]@{
                AdminRole = $(if ($script:granted) { 1 } else { 0 })
                SystemRole = $(if ($script:granted) { 1 } else { $script:systemRole })
                CurrentRole = $(if ($script:granted) { 1 } else { $script:systemRole })
                SingleUser = 0
            }) }
        }
        Mock Invoke-EmptySqlAdministratorRecovery { throw 'Unexpected disruptive recovery.' }
        Mock Assert-EmptyIdleSqlInstance {}
    }
    It 'grants only the intended local administrator and SYSTEM using existing authority, without service recovery' {
        Set-MarketplaceSqlAdministrator $sql $admin
        $script:granted | Should -BeTrue
        Should -Invoke Invoke-EmptySqlAdministratorRecovery -Times 0
        Should -Invoke Get-SqlResult -Times 1 -ParameterFilter { $Query -match 'DECLARE names CURSOR' -and $Query -match 'QUOTENAME' }
    }
    It 'refuses missing grant authority without the explicit disruptive policy' {
        $script:systemRole = 0
        { Set-MarketplaceSqlAdministrator $sql $admin } | Should -Throw '*no service was stopped*'
        Should -Invoke Invoke-EmptySqlAdministratorRecovery -Times 0
    }
    It 'uses effective group-derived sysadmin authority without unnecessary single-user recovery' {
        Mock Get-SqlResult {
            if($Query -match 'DECLARE names CURSOR'){$script:granted=$true;return [pscustomobject]@{Rows=@([pscustomobject]@{Granted=1})}}
            [pscustomobject]@{Rows=@([pscustomobject]@{AdminRole=$(if($script:granted){1}else{0});SystemRole=$(if($script:granted){1}else{0});CurrentRole=1;SingleUser=0})}
        }
        Set-MarketplaceSqlAdministrator $sql $admin
        Should -Invoke Invoke-EmptySqlAdministratorRecovery -Times 0
        $script:granted | Should -BeTrue
    }
    It 'runs guarded recovery only for explicit recoverEmptyInstance and verifies normal-mode roles afterwards' {
        $script:systemRole = 0
        $sql.administratorPolicy = 'recoverEmptyInstance'
        Mock Invoke-EmptySqlAdministratorRecovery { $script:granted = $true }
        Set-MarketplaceSqlAdministrator $sql $admin
        Should -Invoke Assert-EmptyIdleSqlInstance -Times 1
        Should -Invoke Invoke-EmptySqlAdministratorRecovery -Times 1
        Should -Invoke Get-SqlResult -Times 2
    }
    It 'does not reinterpret an already single-user instance as permission to recover' {
        Mock Get-SqlResult { [pscustomobject]@{Rows=@([pscustomobject]@{AdminRole=0;SystemRole=0;SingleUser=1})} }
        $sql.administratorPolicy = 'recoverEmptyInstance'
        { Set-MarketplaceSqlAdministrator $sql $admin } | Should -Throw '*operator recovery*'
        Should -Invoke Invoke-EmptySqlAdministratorRecovery -Times 0
    }
    It 'bootstraps a denied normal-mode login only with the explicitly disposable policy' {
        $sql.administratorPolicy='recoverDisposableInstance'
        Mock Get-SqlResult {
            if(!$script:granted){throw [UnauthorizedAccessException]::new('Normal-mode SQL login denied.')}
            [pscustomobject]@{Rows=@([pscustomobject]@{AdminRole=1;SystemRole=1;SingleUser=0})}
        }
        Mock Invoke-EmptySqlAdministratorRecovery {$script:granted=$true}
        Set-MarketplaceSqlAdministrator $sql $admin
        Should -Invoke Invoke-EmptySqlAdministratorRecovery -Times 1 -ParameterFilter {$Disposable}
        Should -Invoke Assert-EmptyIdleSqlInstance -Times 0
    }
    It 'does not treat arbitrary SQL errors or existing single-user access failures as disposable recovery authorization' {
        $sql.administratorPolicy='recoverDisposableInstance'
        Mock Get-SqlResult {throw [InvalidOperationException]::new('Existing single-user or unexpected SQL failure.')}
        {Set-MarketplaceSqlAdministrator $sql $admin} | Should -Throw '*unexpected SQL failure*'
        Should -Invoke Invoke-EmptySqlAdministratorRecovery -Times 0
    }
    It 'does not mistake temporary single-user sysadmin authority for persistent Windows login membership' {
        $sql.administratorPolicy = 'recoverDisposableInstance'
        $script:systemRole = 0
        Mock Invoke-EmptySqlAdministratorRecovery {
            param($Grant)
            $Grant | Should -Not -Match 'IF SUSER_ID|IF IS_SRVROLEMEMBER'
            $Grant | Should -Match 'IF NOT EXISTS\(SELECT 1 FROM sys.server_principals WHERE name=@name\)'
            $Grant | Should -Match 'sys.server_role_members m'
            $Grant | Should -Match "p.type='U' AND p.is_disabled=0"
            $Grant | Should -Match 'THROW 51001'
            $script:granted = $true
        }
        Set-MarketplaceSqlAdministrator $sql $admin
        Should -Invoke Invoke-EmptySqlAdministratorRecovery -Times 1 -Exactly -ParameterFilter { $Disposable }
    }
}

Describe 'File server role-created firewall safety' {
    BeforeAll {
        function Install-WindowsFeature { param($Name) }
        function Get-NetFirewallRule { param($PolicyStore) }
        function Disable-NetFirewallRule { param([Parameter(ValueFromPipeline)]$InputObject) }
    }
    BeforeEach {
        $script:roleRuleEnabled = $false
        Mock Install-WindowsFeature {
            $script:roleRuleEnabled = $true
            [pscustomobject]@{ Success=$true; RestartNeeded='No' }
        }
        Mock Get-NetFirewallRule {
            [pscustomobject]@{ Name='FileServer-ServerManager-SMB-TCP-In' }
            [pscustomobject]@{ Name='unrelated-rule' }
        }
        Mock Disable-NetFirewallRule {
            param($InputObject)
            $InputObject.Name | Should -Be 'FileServer-ServerManager-SMB-TCP-In'
            $script:roleRuleEnabled = $false
        }
        Mock Assert-ScopedFirewall {
            if ($script:roleRuleEnabled) { throw 'Role-created SMB rule is still broad.' }
        }
        Mock Set-PrivateDirectory { throw 'Reached guarded share setup.' }
    }
    It 'closes the new broad role opening before effective-policy validation and share creation' {
        { Set-FileServer (New-Config) $null } | Should -Throw '*Reached guarded share setup*'
        Should -Invoke Disable-NetFirewallRule -Times 1 -Exactly
        Should -Invoke Assert-ScopedFirewall -Times 1 -Exactly -ParameterFilter { $Port -eq 445 }
    }
    It 'closes the role opening even when installation requires a restart' {
        Mock Install-WindowsFeature {
            $script:roleRuleEnabled = $true
            [pscustomobject]@{ Success=$true; RestartNeeded='Yes' }
        }
        { Set-FileServer (New-Config) $null } | Should -Throw '*Windows restart is required*'
        $script:roleRuleEnabled | Should -BeFalse
        Should -Invoke Set-PrivateDirectory -Times 0
    }
}

Describe 'SQL disruptive recovery preconditions' {
    It 'refuses user databases or active sessions before reading/stopping services or changing listener settings' {
        Mock Get-Service { throw 'Must not read services after failed empty/idle preconditions.' }
        Mock Set-ItemProperty { throw 'Must not alter SQL registry after failed empty/idle preconditions.' }
        foreach ($row in @(@{UserDatabases=1;ActiveSessions=0}, @{UserDatabases=0;ActiveSessions=1})) {
            Mock Get-SqlResult {
                if ($Query -match 'HAS_PERMS_BY_NAME') {
                    return [pscustomobject]@{Rows=@([pscustomobject]@{ViewDatabases=1;ViewOfflineDatabases=1;ViewSessions=1;SingleUser=0})}
                }
                [pscustomobject]@{Rows=@([pscustomobject]$row)}
            }
            { Invoke-EmptySqlAdministratorRecovery 'SELECT 1' } | Should -Throw '*empty instance*'
        }
        Should -Invoke Get-Service -Times 0
        Should -Invoke Set-ItemProperty -Times 0
    }
    It 'does not infer an empty instance from a permission-filtered database/session inventory' {
        Mock Get-SqlResult { [pscustomobject]@{Rows=@([pscustomobject]@{ViewDatabases=1;ViewOfflineDatabases=0;ViewSessions=0;SingleUser=0})} }
        Mock Get-Service { throw 'No services may be touched.' }
        { Invoke-EmptySqlAdministratorRecovery 'SELECT 1' } | Should -Throw '*complete normal-mode*'
        Should -Invoke Get-Service -Times 0
    }
}

Describe 'SQL restart and restoration lifecycle' {
    BeforeEach {
        $savedComputer = $env:COMPUTERNAME
        $savedProgramData = $env:ProgramData
        $env:COMPUTERNAME = 'UNIT-SQL-01'
        $env:ProgramData = $TestDrive
        $script:serviceEvents = [Collections.Generic.List[string]]::new()
        function New-TestService($Name, $Status) {
            $s = [pscustomobject]@{ ServiceName=$Name; Status=$Status; DependentServices=@() }
            $s | Add-Member ScriptMethod Stop { $script:serviceEvents.Add("stop:$($this.ServiceName)"); $this.Status='Stopped' }
            $s | Add-Member ScriptMethod Start { $script:serviceEvents.Add("start:$($this.ServiceName)"); $this.Status='Running' }
            $s | Add-Member ScriptMethod WaitForStatus { param($Status,$Timeout); if($this.Status -ne [string]$Status){throw 'Test service did not reach requested state.'} }
            $s | Add-Member ScriptMethod Refresh {}
            $s
        }
        $script:testServer = New-TestService MSSQLSERVER Running
        $script:testAgent = New-TestService SQLSERVERAGENT Running
        $script:testBrowser = New-TestService SQLBrowser Stopped
        Mock Get-Service {
            switch ($Name) { 'MSSQLSERVER' {$script:testServer}; 'SQLSERVERAGENT' {$script:testAgent}; 'SQLBrowser' {$script:testBrowser} }
        }
        Mock Get-CimInstance { [pscustomobject]@{StartName='NT Service\MSSQLSERVER';StartMode='Disabled'} }
        Mock Assert-EmptyIdleSqlInstance {}
        Mock Set-PrivateDirectory { $null=New-Item -ItemType Directory -Path $Path -Force }
        Mock Register-ScheduledTask { $script:serviceEvents.Add('watchdog') }
        Mock Unregister-ScheduledTask { $script:serviceEvents.Add('disarm') }
        Mock Start-Process {
            $p=[pscustomobject]@{ExitCode=0}
            $p | Add-Member ScriptMethod WaitForExit { param($Timeout); $true }
            $p
        }
        Mock Get-SqlResult {
            if($ApplicationName -eq 'SQLCMD' -and $Query -match 'CurrentRole'){
                return [pscustomobject]@{Rows=@([pscustomobject]@{Major=16;Edition='Enterprise Edition';WindowsOnly=1;SingleUser=1;CurrentRole=1})}
            }
            [pscustomobject]@{Rows=@([pscustomobject]@{SingleUser=0;Probe=1})}
        }
        Mock Invoke-SqlNormalRestore {
            $script:serviceEvents.Add('restore')
            $script:testServer.Status='Running'; $script:testAgent.Status='Running'
            Remove-Item -LiteralPath (Join-Path (Split-Path $Path) 'restore-required')
            $true
        }
    }
    AfterEach {
        $env:COMPUTERNAME=$savedComputer
        $env:ProgramData=$savedProgramData
    }
    It 'arms restoration before disruption and restores normal mode even when the grant fails' {
        Mock Get-SqlResult { throw 'Simulated grant failure' } -ParameterFilter { $ApplicationName -eq 'SQLCMD' -and $Query -notmatch 'CurrentRole' }
        { Invoke-EmptySqlAdministratorRecovery 'SELECT 1' } | Should -Throw '*grant failure*'
        ($script:serviceEvents -join ',') | Should -Be 'watchdog,stop:SQLSERVERAGENT,stop:MSSQLSERVER,restore,disarm'
        Should -Invoke Invoke-SqlNormalRestore -Times 1
        Should -Invoke Start-Process -Times 1 -ParameterFilter { $ArgumentList -eq 'start MSSQLSERVER /mSQLCMD' }
    }
    It 'retains the protected marker and watchdog when restoration fails' {
        Mock Invoke-SqlNormalRestore { $false }
        { Invoke-EmptySqlAdministratorRecovery 'SELECT 1' } | Should -Throw '*watchdog retained*'
        @(Get-ChildItem -LiteralPath $TestDrive -Recurse -Filter restore-required).Count | Should -BeGreaterThan 0
        Should -Invoke Unregister-ScheduledTask -Times 0
    }
    It 'rearms the watchdog rather than disarming when normal-mode acceptance fails' {
        Mock Get-SqlResult { [pscustomobject]@{Rows=@([pscustomobject]@{SingleUser=1})} }
        { Invoke-EmptySqlAdministratorRecovery 'SELECT 1' } | Should -Throw '*watchdog retained*'
        Should -Invoke Unregister-ScheduledTask -Times 0
        @(Get-ChildItem -LiteralPath $TestDrive -Recurse -Filter restore-required).Count | Should -BeGreaterThan 0
    }
    It 'refuses unexpected dependent services before any SQL listener registry mutation' {
        $script:testServer.DependentServices=@(New-TestService CustomerService Running)
        Mock Set-ItemProperty { throw 'No mutation allowed.' }
        { Set-MarketplaceSqlClientAccess ([pscustomobject]@{allowedCidrs=@('192.0.2.0/24')}) } | Should -Throw '*dependent service*'
        Should -Invoke Set-ItemProperty -Times 0
    }
    It 'checks disposable image metadata before disruption and verifies single-user authority before grants' {
        Mock Assert-DisposableSqlRecoveryImage {}
        Invoke-EmptySqlAdministratorRecovery 'GRANT-UNIT-TEST' -Disposable
        Should -Invoke Assert-DisposableSqlRecoveryImage -Times 1
        Should -Invoke Assert-EmptyIdleSqlInstance -Times 0
        Should -Invoke Get-SqlResult -Times 1 -ParameterFilter {$ApplicationName -eq 'SQLCMD' -and $Query -match 'CurrentRole'}
        Should -Invoke Get-SqlResult -Times 1 -ParameterFilter {$ApplicationName -eq 'SQLCMD' -and $Query -eq 'GRANT-UNIT-TEST'}
    }
    It 'restores rather than granting when single-user edition or administrator authority is wrong' {
        Mock Get-SqlResult {[pscustomobject]@{Rows=@([pscustomobject]@{Major=16;Edition='Evaluation Edition';WindowsOnly=1;SingleUser=1;CurrentRole=0})}} -ParameterFilter {$ApplicationName -eq 'SQLCMD'}
        {Invoke-EmptySqlAdministratorRecovery 'GRANT-UNIT-TEST'} | Should -Throw '*no grants*'
        Should -Invoke Get-SqlResult -Times 0 -ParameterFilter {$Query -eq 'GRANT-UNIT-TEST'}
        Should -Invoke Invoke-SqlNormalRestore -Times 1
    }
    It 'preserves either prior SQL Agent state during a listener restart' -ForEach @(@{AgentState='Running'},@{AgentState='Stopped'}) {
        $script:testAgent.Status=$AgentState
        Mock Get-ItemProperty { [pscustomobject]@{Enabled=0;ListenOnAllIPs=0} }
        Mock Get-ChildItem { @() }
        Mock Set-ItemProperty {}
        Mock Set-Service {}
        Mock Set-WorkloadFirewall {}
        Set-MarketplaceSqlClientAccess ([pscustomobject]@{allowedCidrs=@('192.0.2.0/24')})
        $script:testAgent.Status | Should -Be $AgentState
        $script:testServer.Status | Should -Be Running
        $script:serviceEvents | Should -Contain 'start:MSSQLSERVER'
        Should -Invoke Invoke-SqlNormalRestore -Times 0
    }
    It 'accepts an already-configured listener without disrupting a busy/nonempty instance' {
        Mock Get-ItemProperty {[pscustomobject]@{Enabled=1;ListenOnAllIPs=1}} -ParameterFilter {$Path -like '*\Tcp'}
        Mock Get-ItemProperty {[pscustomobject]@{Enabled=0}} -ParameterFilter {$Path -like '*\Np'}
        Mock Get-ChildItem {@()}
        Mock Set-WorkloadFirewall {}
        Mock Assert-EmptyIdleSqlInstance {throw 'Busy instance may not be restarted.'}
        Set-MarketplaceSqlClientAccess ([pscustomobject]@{allowedCidrs=@('192.0.2.0/24')})
        Should -Invoke Assert-EmptyIdleSqlInstance -Times 0
        $script:serviceEvents.Count | Should -Be 0
    }
    It 'rejects a required listener change before registry mutation when the instance is not empty/idle' {
        Mock Get-ItemProperty {[pscustomobject]@{Enabled=0;ListenOnAllIPs=0}}
        Mock Get-ChildItem {@()}
        Mock Set-ItemProperty {throw 'No registry mutation permitted.'}
        Mock Assert-EmptyIdleSqlInstance {throw 'Instance is not empty or idle.'}
        {Set-MarketplaceSqlClientAccess ([pscustomobject]@{allowedCidrs=@('192.0.2.0/24')})} | Should -Throw '*not empty*'
        Should -Invoke Set-ItemProperty -Times 0
        $script:serviceEvents.Count | Should -Be 0
    }

    Describe 'Disposable SQL recovery metadata guard' {
        It 'rejects other editions, versions, authentication modes and persisted single-user flags before service operations' {
            Mock Get-Service {throw 'No service operation allowed.'}
            foreach($bad in @('edition','version','mode','startup')){
                Mock Get-ItemProperty {
                    if($LiteralPath -like '*\Setup'){return [pscustomobject]@{Version=$(if($bad -eq 'version'){'15.0'}else{'16.0'});Edition=$(if($bad -eq 'edition'){'Developer Edition'}else{'Enterprise Edition'})}}
                    if($LiteralPath -like '*\Parameters'){return [pscustomobject]@{SQLArg0=$(if($bad -eq 'startup'){'-mSQLCMD'}else{'-dC:\Sql\master.mdf'})}}
                    [pscustomobject]@{LoginMode=$(if($bad -eq 'mode'){2}else{1})}
                }
                {Invoke-EmptySqlAdministratorRecovery 'GRANT-UNIT-TEST' -Disposable} | Should -Throw '*declared SQL 2022*'
            }
            Should -Invoke Get-Service -Times 0
        }
    }
}

Describe 'Convergence guest configuration contract' {
    It 'accepts typed pending-restart opt-in but rejects string truthiness' {
        $c = New-Config
        $c.windowsPreparation = @{scopeInheritedFirewall=$false;restartIfRequired=$true}
        (Read-WorkloadConfiguration (New-Payload $c)).windowsPreparation.restartIfRequired | Should -BeTrue
        $c.windowsPreparation.restartIfRequired = 'true'
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*boolean*'
    }
    It 'rejects Marketplace-only policies on ISO and requires explicit administrator policy for client access' {
        $c = New-SqlConfig
        $c.sqlServer.administratorPolicy = 'recoverEmptyInstance'
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*Marketplace policy*'
        $c.sqlServer.Remove('installerUrl'); $c.sqlServer.Remove('installerSha256')
        $c.sqlServer.installationMode='marketplace'
        $c.sqlServer.edition='Enterprise'; $c.sqlServer.productionLicenseConfirmed=$true
        $c.sqlServer.clientAccess=$true
        $c.sqlServer.Remove('administratorPolicy')
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*administratorPolicy*'
        $c.sqlServer.administratorPolicy='grantIfAuthorized'
        (Read-WorkloadConfiguration (New-Payload $c)).sqlServer.clientAccess | Should -BeTrue
    }
}

Describe 'IIS site safety' {
    BeforeEach {
        $sites = @([pscustomobject]@{ Name = 'Default Web Site'; physicalPath = '%SystemDrive%\inetpub\wwwroot' })
        $bindings = @([pscustomobject]@{ protocol = 'http'; bindingInformation = '*:80:' })
    }
    It 'accepts only the default site or its managed content path' {
        { Assert-IisLayout $sites $bindings } | Should -Not -Throw
        $sites[0].physicalPath = 'E:\Iis'
        { Assert-IisLayout $sites $bindings } | Should -Not -Throw
    }
    It 'refuses other sites, additional bindings and existing custom content locations' {
        { Assert-IisLayout @($sites[0], $sites[0]) $bindings } | Should -Throw '*only the default*'
        { Assert-IisLayout $sites @($bindings[0], $bindings[0]) } | Should -Throw '*bindings*'
        $bindings[0].bindingInformation = '*:8080:'
        { Assert-IisLayout $sites $bindings } | Should -Throw '*bindings*'
        $bindings[0].bindingInformation = '*:80:'
        $sites[0].physicalPath = 'E:\CustomerSite'
        { Assert-IisLayout $sites $bindings } | Should -Throw '*content path*'
    }
}

Describe 'Windows firewall address normalization' {
    BeforeAll {
        function Get-NetFirewallProfile { param($PolicyStore) }
        function Get-NetFirewallRule { param($PolicyStore, $Enabled, $Direction, $Action) }
        function Get-NetFirewallPortFilter { param([Parameter(ValueFromPipeline)]$InputObject) }
        function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline)]$InputObject) }
    }
    BeforeEach {
        Mock Get-NetFirewallProfile { [pscustomobject]@{ Enabled = $true; DefaultInboundAction = 'Block' } }
        Mock Get-NetFirewallRule { [pscustomobject]@{ Name = 'inherited-rule' } }
        Mock Get-NetFirewallPortFilter { [pscustomobject]@{ Protocol = 'TCP'; LocalPort = 'Any' } }
    }
    It 'accepts Windows dotted-netmask normalization only for a contained firewall scope' {
        Mock Get-NetFirewallAddressFilter { [pscustomobject]@{ RemoteAddress = @('192.0.2.0/255.255.255.0') } }
        { Assert-ScopedFirewall 445 @('192.0.2.0/24') } | Should -Not -Throw
        { Get-CidrRange '192.0.2.0/255.255.255.0' } | Should -Throw '*CIDR*'
        (Get-CidrRange '192.0.2.19/255.255.255.255' -AllowSubnetMask) -join ',' |
            Should -Be ((Get-CidrRange '192.0.2.19/32') -join ',')
    }
    It 'still rejects universal, noncontiguous, noncanonical and outside firewall scopes' {
        foreach ($address in @('Any', '192.0.2.0/0.0.0.0', '192.0.2.0/255.0.255.0',
            '192.0.2.0/255.255.256.0', '192.0.2.1/255.255.255.0', '192.0.0.0/255.255.0.0',
            '198.51.100.0/255.255.255.0')) {
            Mock Get-NetFirewallAddressFilter { [pscustomobject]@{ RemoteAddress = @($address) } }
            { Assert-ScopedFirewall 445 @('192.0.2.0/24') } | Should -Throw '*outside allowedCidrs*'
        }
    }
}

Describe 'Explicit inherited firewall preparation' {
    BeforeAll {
        function Get-NetFirewallProfile { param($PolicyStore) }
        function Get-NetFirewallRule { param($PolicyStore, $Enabled, $Direction, $Action, $Name) }
        function Get-NetFirewallPortFilter { param([Parameter(ValueFromPipeline)]$InputObject) }
        function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline)]$InputObject) }
        function Get-NetFirewallApplicationFilter { param([Parameter(ValueFromPipeline)]$InputObject) }
        function Get-NetFirewallServiceFilter { param([Parameter(ValueFromPipeline)]$InputObject) }
        function Set-NetFirewallRule { param($PolicyStore, $Name, $RemoteAddress) }
        function Disable-NetFirewallRule { param($PolicyStore, $Name) }
    }
    It 'requires a typed opt-in and leaves it absent by default' {
        $c = New-Config
        $parsed = Read-WorkloadConfiguration (New-Payload $c)
        $parsed.PSObject.Properties.Name | Should -Not -Contain 'windowsPreparation'
        $c.windowsPreparation = @{ scopeInheritedFirewall = $true }
        (Read-WorkloadConfiguration (New-Payload $c)).windowsPreparation.scopeInheritedFirewall | Should -BeTrue
        $c.windowsPreparation.scopeInheritedFirewall = 'true'
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*boolean*'
        $c.windowsPreparation = @{ scopeInheritedFirewall = $true; disableFirewall = $true }
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*Unsupported configuration property*'
    }
    It 'intersects inherited networks without widening an existing host or narrower subnet' {
        @(Get-NarrowedRemoteScope @('Any') @('192.0.2.0/24')) | Should -Be @('192.0.2.0/24')
        @(Get-NarrowedRemoteScope @('192.0.0.0/16') @('192.0.2.0/24')) | Should -Be @('192.0.2.0/24')
        @(Get-NarrowedRemoteScope @('192.0.2.19', '192.0.2.128/25') @('192.0.2.0/24')) |
            Should -Be @('192.0.2.128/25', '192.0.2.19')
        @(Get-NarrowedRemoteScope @('198.51.100.0/24') @('192.0.2.0/24')).Count | Should -Be 0
    }
    It 'rejects ambiguous keyword, IPv6 and invalid address scopes instead of replacing them with a broader subnet' {
        foreach ($scope in @('LocalSubnet', 'Internet', '::/0', '192.0.2.1/24')) {
            { Get-NarrowedRemoteScope @($scope) @('192.0.2.0/24') } | Should -Throw '*resolve that policy manually*'
        }
        { Get-NarrowedRemoteScope @() @('192.0.2.0/24') } | Should -Throw '*no remote scope*'
    }
    Context 'Local policy execution' {
        BeforeEach {
            $env:ProgramData = $TestDrive
            Mock Get-NetFirewallProfile { [pscustomobject]@{ Enabled=$true; DefaultInboundAction='Block' } }
            Mock Get-NetFirewallRule { [pscustomobject]@{ Name='broad-local'; PolicyStoreSourceType='Local'; Enabled='True'; Direction='Inbound'; Action='Allow' } }
            Mock Get-NetFirewallPortFilter { [pscustomobject]@{ Protocol='TCP'; LocalPort='Any' } }
            Mock Get-NetFirewallAddressFilter { [pscustomobject]@{ RemoteAddress=@('Any') } }
            Mock Get-NetFirewallApplicationFilter { [pscustomobject]@{ Program='C:\Windows\service.exe' } }
            Mock Get-NetFirewallServiceFilter { [pscustomobject]@{ Service='ExampleService' } }
            Mock Set-PrivateDirectory { param($Path) $null = New-Item -ItemType Directory -Path $Path -Force }
            Mock Set-NetFirewallRule {}
            Mock Disable-NetFirewallRule {}
            Mock Assert-ScopedFirewall {}
        }
        It 'snapshots local rules then changes only their remote addresses and rechecks effective policy' {
            Set-InheritedFirewallScope 445 @('192.0.2.0/24')
            @(Get-ChildItem $TestDrive -Filter before.clixml -Recurse).Count | Should -Be 1
            Should -Invoke Set-NetFirewallRule -Times 1 -Exactly -ParameterFilter {
                $PolicyStore -eq 'PersistentStore' -and $Name -eq 'broad-local' -and
                $RemoteAddress.Count -eq 1 -and $RemoteAddress[0] -eq '192.0.2.0/24'
            }
            Should -Invoke Disable-NetFirewallRule -Times 0
            Should -Invoke Assert-ScopedFirewall -Times 1
        }
        It 'does not modify any rule when external policy needs remediation' {
            Mock Get-NetFirewallRule { [pscustomobject]@{ Name='gpo'; PolicyStoreSourceType='GroupPolicy'; Enabled='True'; Direction='Inbound'; Action='Allow' } }
            { Set-InheritedFirewallScope 80 @('192.0.2.0/24') } | Should -Throw '*controlled outside*'
            Should -Invoke Set-NetFirewallRule -Times 0
            Should -Invoke Disable-NetFirewallRule -Times 0
        }
        It 'disables only the conflicting dynamic rule instead of attempting an unsupported static filter' {
            Mock Get-NetFirewallRule { [pscustomobject]@{ Name='WirelessDisplay-In-TCP'; PolicyStoreSourceType='Local'; Enabled='True'; Direction='Inbound'; Action='Allow' } }
            Set-InheritedFirewallScope 80 @('192.0.2.0/24')
            Should -Invoke Disable-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $Name -eq 'WirelessDisplay-In-TCP' -and $PolicyStore -eq 'PersistentStore' }
            Should -Invoke Set-NetFirewallRule -Times 0
        }
        AfterEach { $env:ProgramData = [Environment]::GetFolderPath('CommonApplicationData') }
    }
}

Describe 'Safe workload disk selection (pure inventory)' {
    BeforeEach {
        $disk = [pscustomobject]@{ Number = 1; Size = 128GB; IsBoot = $false; IsSystem = $false; PartitionStyle = 'RAW' }
        $boot = [pscustomobject]@{ Number = 0; Size = 128GB; IsBoot = $true; IsSystem = $true; PartitionStyle = 'GPT' }
        $part = [pscustomobject]@{ DiskNumber = 1; DriveLetter = 'E'; Type = 'Basic'; Size = (128GB - 17MB) }
        $volume = [pscustomobject]@{ DriveLetter = 'E'; FileSystemLabel = 'WorkloadData'; FileSystem = 'NTFS'; Size = (128GB - 17MB) }
    }
    It 'selects only the one raw nonboot nonsystem disk' {
        $result = Select-WorkloadDisk @($boot, $disk) @() @() 128
        $result.Initialize | Should -BeTrue
        $result.DiskNumber | Should -Be 1
    }
    It 'refuses a nonraw disk containing data' {
        $disk.PartitionStyle = 'GPT'
        { Select-WorkloadDisk @($disk) @() @() 128 } | Should -Throw
    }
    It 'refuses ambiguous raw disks even if only one has the expected size' {
        $other = [pscustomobject]@{ Number = 2; Size = 64GB; IsBoot = $false; IsSystem = $false; PartitionStyle = 'RAW' }
        { Select-WorkloadDisk @($disk, $other) @() @() 128 } | Should -Throw
        $other.Size = 128GB
        { Select-WorkloadDisk @($disk, $other) @() @() 128 } | Should -Throw
    }
    It 'never selects boot or system disks' {
        $disk.IsSystem = $true
        { Select-WorkloadDisk @($disk) @() @() 128 } | Should -Throw
        $disk.IsSystem = $false
        $disk.IsBoot = $true
        { Select-WorkloadDisk @($disk) @() @() 128 } | Should -Throw
    }
    It 'refuses a capacity mismatch and E drive collision before initialization' {
        { Select-WorkloadDisk @($disk) @() @() 64 } | Should -Throw
        { Select-WorkloadDisk @($disk) @() @($volume) 128 } | Should -Throw
        { Select-WorkloadDisk @($disk) @($part) @() 128 } | Should -Throw
    }
    It 'reuses the exact expected GPT volume with an optional MSR partition' {
        $disk.PartitionStyle = 'GPT'
        (Select-WorkloadDisk @($disk) @($part) @($volume) 128).Initialize | Should -BeFalse
        $msr = [pscustomobject]@{ DiskNumber = 1; DriveLetter = ''; Type = 'Reserved'; Size = 16MB }
        (Select-WorkloadDisk @($disk) @($part, $msr) @($volume) 128).Initialize | Should -BeFalse
    }
    It 'refuses wrong existing volume label, filesystem, or capacity' {
        $disk.PartitionStyle = 'GPT'
        $volume.FileSystemLabel = 'Other'
        { Select-WorkloadDisk @($disk) @($part) @($volume) 128 } | Should -Throw
        $volume.FileSystemLabel = 'WorkloadData'
        $volume.FileSystem = 'ReFS'
        { Select-WorkloadDisk @($disk) @($part) @($volume) 128 } | Should -Throw
        $volume.FileSystem = 'NTFS'
        $volume.Size = 100GB
        { Select-WorkloadDisk @($disk) @($part) @($volume) 128 } | Should -Throw
    }
    It 'refuses unexpected partitions and E on another disk' {
        $disk.PartitionStyle = 'GPT'
        $extra = [pscustomobject]@{ DiskNumber = 1; DriveLetter = 'F'; Type = 'Basic'; Size = 1MB }
        { Select-WorkloadDisk @($disk) @($part, $extra) @($volume) 128 } | Should -Throw
        $part.DiskNumber = 0
        { Select-WorkloadDisk @($disk) @($part) @($volume) 128 } | Should -Throw
    }
}

Describe 'Workload payload and licensing validation' {
    It 'accepts IIS without unrelated SQL or file-server settings and rejects cross-profile settings' {
        $c = New-Config
        $c.profile = 'iisServer'
        $c.Remove('fileServer')
        (Read-WorkloadConfiguration (New-Payload $c)).profile | Should -Be iisServer
        $c.fileServer = @{ shareName = 'Unexpected' }
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*do not match*'
    }

    It 'accepts UTF8 base64 JSON and both supported nonproduction SQL editions' {
        (Read-WorkloadConfiguration (New-Payload (New-Config))).profile | Should -Be 'fileServer'
        foreach ($edition in @('Developer', 'Evaluation')) {
            $c = New-SqlConfig
            $c.sqlServer.edition = $edition
            (Read-WorkloadConfiguration (New-Payload $c)).sqlServer.edition | Should -Be $edition
        }
        $c = New-SqlConfig
        $c.sqlServer.Remove('productionLicenseConfirmed')
        (Read-WorkloadConfiguration (New-Payload $c)).sqlServer.edition | Should -Be 'Developer'
    }
    It 'rejects malformed base64, JSON, UTF8, and missing settings' {
        foreach ($payload in @('!', 'bm90LWpzb24=', '/w==', 'e30=')) {
            { Read-WorkloadConfiguration $payload } | Should -Throw
        }
    }
    It 'rejects unsupported editions, missing or string consent, and production confirmation for free editions' {
        foreach ($edition in @('Express', 'EnterpriseCore', 'StandardDeveloper')) {
            $c = New-SqlConfig
            $c.sqlServer.edition = $edition
            { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*Only SQL*'
        }
        foreach ($consent in @($false, 'true', $null)) {
            $c = New-SqlConfig
            $c.sqlServer.acceptLicenseTerms = $consent
            { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw
        }
        $c = New-SqlConfig
        $c.sqlServer.productionLicenseConfirmed = $true
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw
    }
    It 'requires paid-edition licensing confirmation and a pinned Key Vault source' {
        foreach ($edition in @('Standard', 'Enterprise')) {
            $c = New-SqlConfig
            $c.sqlServer.edition = $edition
            { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*productionLicenseConfirmed*'
            $c.sqlServer.productionLicenseConfirmed = $true
            $c.sqlServer.productKeySource = @{
                type = 'keyVault'
                vaultResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/sql-vault'
                secretName = 'sql-pid'; secretVersion = 'a' * 32
            }
            (Read-WorkloadConfiguration (New-Payload $c)).sqlServer.edition | Should -Be $edition
            $c.sqlServer.productKeySource.secretVersion = 'latest'
            { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*pinned version*'
            $c.sqlServer.productKeySource.secretVersion = 'a' * 32
            $c.sqlServer.edition = 'Developer'
            { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*nonproduction*'
        }
    }
    It 'rejects product keys and other unknown properties without echoing their values' {
        $c = New-SqlConfig
        $c.sqlServer.productKeyEnvironmentVariable = 'SECRET_ENV'
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*Unsupported configuration property*'
        $c = New-Config
        $c.sqlServer = @{ password = 'must-not-be-accepted' }
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*Unsupported configuration property*'
    }
    It 'rejects credential-bearing, signed, non-ISO, and non-HTTPS media URLs' {
        foreach ($url in @('http://example.com/a.iso', 'https://user:pass@example.com/a.iso',
            'https://example.com/a.iso?sig=secret', 'https://example.com/a.iso#secret',
            'https://example.com/setup.exe', 'https://localhost/a.iso')) {
            $c = New-SqlConfig
            $c.sqlServer.installerUrl = $url
            { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw
        }
        $c = New-SqlConfig
        $c.sqlServer.installerSha256 = 'not-a-hash'
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw
    }
    It 'rejects empty or noncanonical CIDRs and unsafe names or fractional disk sizes' {
        foreach ($cidrs in @(@(), @('0.0.0.0/0'), @('300.1.1.0/24'), @('192.0.2.1/24'), @('::1/128'))) {
            $c = New-Config
            $c.allowedCidrs = $cidrs
            { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw
        }
        $c = New-Config
        $c.fileServer.shareName = '..\Other'
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw
        $c = New-Config
        $c.adminUsername = "bad'user"
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw
        $c = New-Config
        $c.dataDiskSizeGB = 128.5
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw
    }
}

Describe 'Preinstalled SQL Marketplace verification' {
    BeforeEach {
        $c = New-SqlConfig
        $c.sqlServer = @{ installationMode = 'marketplace'; edition = 'Enterprise'; acceptLicenseTerms = $true; productionLicenseConfirmed = $true }
        Mock Get-Service { [pscustomobject]@{ Status = 'Running' } }
        Mock Get-SqlResult {
            [pscustomobject]@{ Rows = @([pscustomobject]@{
                Probe = 1; Major = 16; Edition = 'Enterprise Edition (64-bit)'; WindowsOnly = 1; OfflineDatabases = 0
            }) }
        }
        Mock Assert-ScopedFirewall {}
        Mock Initialize-WorkloadData { throw 'Must not format a preinstalled SQL data disk.' }
        Mock Install-SqlInstance { throw 'Must not reinstall preinstalled SQL.' }
        Mock Get-SqlProductKey { throw 'Must not fetch a PID for a Marketplace image.' }
        Mock Set-WorkloadFirewall { throw 'Must not change preinstalled SQL firewall rules.' }
    }

    It 'accepts licensed verification-only mode without ISO media or a key reference' {
        (Read-WorkloadConfiguration (New-Payload $c)).sqlServer.installationMode | Should -Be 'marketplace'
        Assert-MarketplaceSqlInstance $c | Should -Match 'acceptance passed'
        Should -Invoke Assert-ScopedFirewall -Times 1 -ParameterFilter { $Port -eq 1433 }
        Should -Invoke Initialize-WorkloadData -Times 0
        Should -Invoke Install-SqlInstance -Times 0
        Should -Invoke Get-SqlProductKey -Times 0
        Should -Invoke Set-WorkloadFirewall -Times 0
        $body = ($script:guestAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-WorkloadConfiguration'
        }, $false))[0].Extent.Text
        $body | Should -Match "(?s)installationMode -eq 'marketplace'.*Assert-MarketplaceSqlInstance.*return\s+}.*Initialize-WorkloadData"
    }

    It 'rejects preinstalled mode with PID/media, other editions or missing licensing' {
        foreach ($field in @('installerUrl', 'installerSha256', 'productKeySource')) {
            $c.sqlServer[$field] = 'not-allowed'
            { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*cannot accept ISO media*'
            $c.sqlServer.Remove($field)
        }
        $c.sqlServer.edition = 'Developer'
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw
        $c.sqlServer.edition = 'Enterprise'; $c.sqlServer.productionLicenseConfirmed = $false
        { Read-WorkloadConfiguration (New-Payload $c) } | Should -Throw '*productionLicenseConfirmed*'
    }

    It 'refuses a stopped service, Evaluation, the wrong SQL version or offline databases without repair' {
        Mock Get-Service { [pscustomobject]@{ Status = 'Stopped' } }
        { Assert-MarketplaceSqlInstance $c } | Should -Throw '*not Running*'
        Mock Get-Service { [pscustomobject]@{ Status = 'Running' } }
        foreach ($invalid in @(
            @{ Major = 16; Edition = 'Enterprise Evaluation Edition'; WindowsOnly = 1; OfflineDatabases = 0 },
            @{ Major = 15; Edition = 'Enterprise Edition'; WindowsOnly = 1; OfflineDatabases = 0 },
            @{ Major = 16; Edition = 'Enterprise Edition'; WindowsOnly = 0; OfflineDatabases = 0 },
            @{ Major = 16; Edition = 'Enterprise Edition'; WindowsOnly = 1; OfflineDatabases = 1 }
        )) {
            Mock Get-SqlResult { [pscustomobject]@{ Rows = @([pscustomobject](@{ Probe = 1 } + $invalid)) } }
            { Assert-MarketplaceSqlInstance $c } | Should -Throw '*acceptance failed*'
        }
    }
}

Describe 'SQL guest-side Key Vault retrieval' {
    BeforeEach {
        $script:savedProgramData = $env:ProgramData
        $env:ProgramData = $TestDrive
        $directory = Join-Path $TestDrive 'AzureConnectedMachineAgent\Tokens'
        $null = New-Item -ItemType Directory -Path $directory -Force
        $script:tokenFile = Join-Path $directory 'challenge.key'
        Set-Content -LiteralPath $script:tokenFile -Value 'synthetic-challenge' -NoNewline
        $script:requests = @()
        $script:replies = [Collections.Generic.Queue[Net.Http.HttpResponseMessage]]::new()
        $challenge = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::Unauthorized)
        $null = $challenge.Headers.TryAddWithoutValidation('WWW-Authenticate', "Basic realm=`"$script:tokenFile`"")
        $script:replies.Enqueue($challenge)
        $token = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
        $token.Content = [Net.Http.StringContent]::new('{"access_token":"synthetic-token"}')
        $script:replies.Enqueue($token)
        $key = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK)
        $key.Content = [Net.Http.StringContent]::new('{"value":"ABCDE-FGHIJ-KLMNO-PQRST-UVWXY"}')
        $script:replies.Enqueue($key)
        $script:fakeClient = [pscustomobject]@{
            Timeout = [TimeSpan]::Zero
            DefaultRequestHeaders = ([Net.Http.HttpRequestMessage]::new()).Headers
        }
        $script:fakeClient | Add-Member ScriptMethod GetAsync {
            param($Uri)
            $script:requests += [pscustomobject]@{ Uri = $Uri; Auth = "$($this.DefaultRequestHeaders.Authorization)" }
            [Threading.Tasks.Task]::FromResult($script:replies.Dequeue())
        }
        $script:fakeClient | Add-Member ScriptMethod Dispose {}
        Mock New-Object {
            param($TypeName, $ArgumentList)
            switch ($TypeName) {
                'Net.Http.HttpClient' { $script:fakeClient }
                'Net.Http.HttpClientHandler' { [Net.Http.HttpClientHandler]::new() }
                'Net.Http.Headers.AuthenticationHeaderValue' { [Net.Http.Headers.AuthenticationHeaderValue]::new($ArgumentList[0], $ArgumentList[1]) }
                default { throw "Unexpected constructor in retrieval test: $TypeName" }
            }
        }
        $script:source = [pscustomobject]@{
            vaultResourceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/sql-vault'
            secretName = 'sql-pid'; secretVersion = 'a' * 32
        }
    }
    AfterEach { $env:ProgramData = $script:savedProgramData }

    It 'requests the vault audience and exact pinned secret using the guest Arc identity' {
        Get-SqlProductKey $script:source | Should -Be 'ABCDE-FGHIJ-KLMNO-PQRST-UVWXY'
        $script:requests.Count | Should -Be 3
        $script:requests[0].Uri | Should -Match '^http://localhost:40342/.*resource=https%3A%2F%2Fvault.azure.net$'
        $script:requests[1].Auth | Should -Be 'Basic synthetic-challenge'
        $script:requests[2].Uri | Should -Be ('https://sql-vault.vault.azure.net/secrets/sql-pid/' + ('a' * 32) + '?api-version=7.4')
        $script:requests[2].Auth | Should -Be 'Bearer synthetic-token'
    }
    It 'suppresses authorization and malformed-secret errors without returning a fallback PID' {
        $script:replies.ToArray()[2].StatusCode = [Net.HttpStatusCode]::Forbidden
        { Get-SqlProductKey $script:source } | Should -Throw '*retrieval failed*'
        $script:requests.Count | Should -Be 3
    }
    It 'refuses a challenge pointing outside the Arc token directory before reading it' {
        $challenge = $script:replies.ToArray()[0]
        $challenge.Headers.WwwAuthenticate.Clear()
        $null = $challenge.Headers.TryAddWithoutValidation('WWW-Authenticate', "Basic realm=`"$(Join-Path $TestDrive 'other.key')`"")
        { Get-SqlProductKey $script:source } | Should -Throw '*retrieval failed*'
        $script:requests.Count | Should -Be 1
    }
}

Describe 'SQL rerun ownership verification (mocked integrated query)' {
    BeforeEach {
        $script:sqlRow = [pscustomobject]@{
            Probe = 1; Major = 16; Edition = 'Developer Edition (64-bit)'; WindowsOnly = 1
            DataPath = 'E:\Sql\Data\'; LogPath = 'E:\Sql\Log\'
            AdminRole = 1; SystemRole = 1; BadPaths = 0
        }
        Mock Get-SqlResult { [pscustomobject]@{ Rows = @($script:sqlRow) } }
    }
    It 'accepts matching Developer, Evaluation, Standard and Enterprise instances without edition fallback' {
        { Assert-SqlInstance @{ edition = 'Developer' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Not -Throw
        $script:sqlRow.Edition = 'Enterprise Evaluation Edition (64-bit)'
        { Assert-SqlInstance @{ edition = 'Evaluation' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Not -Throw
        foreach ($edition in @('Standard', 'Enterprise')) {
            $script:sqlRow.Edition = "$edition Edition (64-bit)"
            { Assert-SqlInstance @{ edition = $edition } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Not -Throw
            $script:sqlRow.Edition = 'Enterprise Evaluation Edition (64-bit)'
            { Assert-SqlInstance @{ edition = $edition } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Throw '*refusing to repurpose*'
        }
    }

    Describe 'Private SQL PID setup delivery' {
        BeforeEach {
            $script:syntheticPid = 'ABCDE-FGHIJ-KLMNO-PQRST-UVWXY'
            Mock Set-PrivateDirectory {
                param($Path)
                $null = New-Item -ItemType Directory -Path $Path
            }
            Mock Get-SqlProductKey { $script:syntheticPid }
            Mock Start-Process {
                param($FilePath, $ArgumentList, $RedirectStandardOutput, $RedirectStandardError)
                $ArgumentList | Should -Not -Match ([regex]::Escape($script:syntheticPid))
                $ArgumentList | Should -Not -Match '/PID'
                $ArgumentList | Should -Match '/ConfigurationFile="([^"]+)"'
                $ini = [regex]::Match($ArgumentList, '/ConfigurationFile="([^"]+)"').Groups[1].Value
                Get-Content -LiteralPath $ini -Raw | Should -Be "[OPTIONS]`r`nPID=`"$script:syntheticPid`"`r`n"
                Set-Content -LiteralPath $RedirectStandardOutput -Value $script:syntheticPid
                Set-Content -LiteralPath $RedirectStandardError -Value $script:syntheticPid
                [pscustomobject]@{ ExitCode = 0 }
            }
        }
        It 'never includes a key in process arguments or returned output and removes transient config and output' {
            $result = Invoke-SqlSetup 'setup.exe' '/Q /ACTION=Install' @{ edition = 'Standard'; productKeySource = @{} } $TestDrive
            $result | Should -Be 0
            @(Get-ChildItem $TestDrive -Recurse -File).Count | Should -Be 0
            Should -Invoke Set-PrivateDirectory -Times 1
            Should -Invoke Get-SqlProductKey -Times 1
        }
        It 'suppresses secret-bearing exceptions and cleans the configuration on setup failure' {
            Mock Start-Process { throw "failure containing $script:syntheticPid" }
            $failure = $null
            try { Invoke-SqlSetup 'setup.exe' '/Q' @{ edition = 'Enterprise'; productKeySource = @{} } $TestDrive }
            catch { $failure = $_ }
            $failure.Exception.Message | Should -Match 'Secret-bearing output is suppressed'
            $failure.Exception.Message | Should -Not -Match ([regex]::Escape($script:syntheticPid))
            @(Get-ChildItem $TestDrive -Recurse -File).Count | Should -Be 0
        }
        It 'rejects empty, multiline, command-injection and predefined free PIDs without exposing input' {
            foreach ($key in @('', '22222-00000-00000-00000-00000', '00000-00000-00000-00000-00000',
                "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY`n", 'ABCDE-FGHIJ-KLMNO-PQRST-UVWXY" /Q')) {
                { Assert-SqlProductKey $key } | Should -Throw '*its value is not logged*'
            }
            { Assert-SqlProductKey $script:syntheticPid } | Should -Not -Throw
        }
    }
    It 'refuses a different edition, SQL version, or authentication mode' {
        $script:sqlRow.Edition = 'Standard Edition (64-bit)'
        { Assert-SqlInstance @{ edition = 'Developer' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Throw '*refusing to repurpose*'
        $script:sqlRow.Edition = 'Developer Edition (64-bit)'
        $script:sqlRow.Major = 17
        { Assert-SqlInstance @{ edition = 'Developer' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Throw
        $script:sqlRow.Major = 16
        $script:sqlRow.WindowsOnly = 0
        { Assert-SqlInstance @{ edition = 'Developer' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Throw
    }
    It 'refuses unexpected default paths, database files, and missing explicit sysadmins' {
        $script:sqlRow.LogPath = 'C:\Existing\'
        { Assert-SqlInstance @{ edition = 'Developer' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Throw
        $script:sqlRow.LogPath = 'E:\Sql\Log\'
        $script:sqlRow.BadPaths = 1
        { Assert-SqlInstance @{ edition = 'Developer' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Throw
        $script:sqlRow.BadPaths = 0
        $script:sqlRow.AdminRole = 0
        { Assert-SqlInstance @{ edition = 'Developer' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Throw
        $script:sqlRow.AdminRole = 1
        $script:sqlRow.SystemRole = 0
        { Assert-SqlInstance @{ edition = 'Developer' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Throw
    }
}

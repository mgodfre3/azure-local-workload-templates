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
    It 'rejects unsupported editions, missing or string consent, and production confirmation' {
        foreach ($edition in @('Standard', 'Enterprise', 'Express')) {
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

Describe 'SQL rerun ownership verification (mocked integrated query)' {
    BeforeEach {
        $script:sqlRow = [pscustomobject]@{
            Probe = 1; Major = 16; Edition = 'Developer Edition (64-bit)'; WindowsOnly = 1
            DataPath = 'E:\Sql\Data\'; LogPath = 'E:\Sql\Log\'
            AdminRole = 1; SystemRole = 1; BadPaths = 0
        }
        Mock Get-SqlResult { [pscustomobject]@{ Rows = @($script:sqlRow) } }
    }
    It 'accepts matching Developer and Evaluation instances' {
        { Assert-SqlInstance @{ edition = 'Developer' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Not -Throw
        $script:sqlRow.Edition = 'Enterprise Evaluation Edition (64-bit)'
        { Assert-SqlInstance @{ edition = 'Evaluation' } 'VM\vmadmin' 'NT AUTHORITY\SYSTEM' } | Should -Not -Throw
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

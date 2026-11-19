BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\WorkloadDeployment.psm1') -Force
}

Describe 'Answer contract and pure validation' {
    InModuleScope WorkloadDeployment {
        BeforeAll {
            function script:New-Answers {
                $a = Get-Content (Join-Path $script:Root 'answers\example.json') -Raw | ConvertFrom-Json -AsHashtable
                $a.workloads = @($a.workloads[0])
                $a.workloads[0].Remove('count')
                $a.workloads[0].name = 'files-01'
                $a
            }
            function script:New-Image {
                param([hashtable]$Answers, [string]$Name = 'existing-approved')
                @{
                    id = "/subscriptions/$($Answers.subscriptionId)/resourceGroups/images/providers/Microsoft.AzureStackHCI/marketplaceGalleryImages/$Name"
                    name = $Name; type = 'Microsoft.AzureStackHCI/marketplaceGalleryImages'; location = $Answers.location
                    extendedLocation = @{ name = $Answers.stamp.customLocationId }
                    properties = @{
                        provisioningState = 'Succeeded'; osType = 'Windows'; hyperVGeneration = 'V2'
                        identifier = @{ publisher = 'microsoftwindowsserver'; offer = 'windowsserver'; sku = '2022-datacenter-azure-edition' }
                        version = @{ name = $Answers.workloads[0].image.version }
                    }
                }
            }
            function Write-Answers {
                param([hashtable]$Answers, [string]$Path)
                $Answers | ConvertTo-Json -Depth 30 | Set-Content $Path
            }
            function script:New-LinuxAnswers {
                $a = New-Answers
                $w = $a.workloads[0]
                $w.profile = 'linuxApp'
                $w.Remove('fileServer')
                $w.Remove('dataDiskSizeGB')
                $rsa = [Security.Cryptography.RSA]::Create(2048)
                $stream = [IO.MemoryStream]::new()
                try {
                    $p = $rsa.ExportParameters($false)
                    foreach ($part in @([Text.Encoding]::ASCII.GetBytes('ssh-rsa'), $p.Exponent, (,[byte]0 + $p.Modulus))) {
                        $bytes = [byte[]]$part
                        $size = [BitConverter]::GetBytes([uint32]$bytes.Length)
                        [Array]::Reverse($size)
                        $stream.Write($size); $stream.Write($bytes)
                    }
                    $w.sshPublicKey = 'ssh-rsa ' + [Convert]::ToBase64String($stream.ToArray())
                } finally { $rsa.Dispose(); $stream.Dispose() }
                $w.image = @{
                    source = 'local'; os = 'Ubuntu2204'; name = 'ubuntu-prepared'
                    path = 'C:\ClusterStorage\Volume1\Images\ubuntu.vhdx'
                    stampPathConfirmed = $true; preparedImageConfirmed = $true; sha256 = 'a' * 64
                }
                $a
            }
            function script:New-PreparedImage {
                param([hashtable]$Answers)
                @{
                    id = "/subscriptions/$($Answers.subscriptionId)/resourceGroups/images/providers/Microsoft.AzureStackHCI/galleryImages/ubuntu-reused"
                    name = 'ubuntu-reused'; type = 'Microsoft.AzureStackHCI/galleryImages'; location = $Answers.location
                    extendedLocation = @{ name = $Answers.stamp.customLocationId }
                    tags = @{ preparedImageSha256 = 'a' * 64 }
                    properties = @{ provisioningState = 'Succeeded'; osType = 'Linux'; hyperVGeneration = 'V2'; cloudInitDataSource = 'NoCloud' }
                }
            }
        }

        It 'accepts a complete Windows file-server answer without any Azure call' {
            $a = New-Answers
            $path = Join-Path $TestDrive 'valid.json'
            Write-Answers $a $path
            Mock Invoke-AzJson { throw 'Must not contact Azure' }
            (Read-WorkloadAnswers $path).workloads[0].profile | Should -Be fileServer
            ((Start-WorkloadDeployment -AnswerFile $path -Mode Validate) -join "`n") | Should -Match 'Offline only'
            Should -Invoke Invoke-AzJson -Times 0
        }

        It 'rejects a plaintext password rather than silently ignoring it' {
            $a = New-Answers
            $a.password = 'not-a-real-secret'
            $path = Join-Path $TestDrive 'invalid.json'
            Write-Answers $a $path
            { Read-WorkloadAnswers $path } | Should -Throw '*schema*'
        }

        It 'accepts explicit existing Windows 2022 and 2025 images for every Windows profile' {
            $path = Join-Path $TestDrive 'windows-existing.json'
            foreach ($profile in @('fileServer', 'sqlServer', 'iisServer', 'windowsApp')) {
                foreach ($os in @('WindowsServer2022', 'WindowsServer2025')) {
                    $a = New-Answers
                    $sample = Get-Content (Join-Path $script:Root 'answers\example.json') -Raw | ConvertFrom-Json -AsHashtable
                    $a.workloads = @($sample.workloads | Where-Object profile -EQ $profile)
                    $a.workloads[0].count = 1
                    $a.workloads[0].image = @{
                        source = 'existing'; os = $os
                        resourceId = "/subscriptions/$($a.subscriptionId)/resourceGroups/images/providers/Microsoft.AzureStackHCI/marketplaceGalleryImages/windows-existing"
                    }
                    if ($profile -eq 'sqlServer') {
                        $a.workloads[0].sqlServer.installerUrl = 'https://media.contoso.invalid/sql.iso'
                        $a.workloads[0].sqlServer.installerSha256 = 'a' * 64
                    }
                    Write-Answers $a $path
                    (Read-WorkloadAnswers $path).workloads[0].image.os | Should -Be $os
                }
            }
        }

        It 'keeps Windows 2025 out of Marketplace imports and Linux profile answers' {
            $path = Join-Path $TestDrive 'windows-version-mismatch.json'
            $a = New-Answers
            $a.workloads[0].image.os = 'WindowsServer2025'
            Write-Answers $a $path
            { Read-WorkloadAnswers $path } | Should -Throw '*schema*'
            $a = New-LinuxAnswers
            $a.workloads[0].image.os = 'WindowsServer2025'
            Write-Answers $a $path
            { Read-WorkloadAnswers $path } | Should -Throw '*schema*'
        }

        It 'rejects invalid sizes and unsupported Windows SQL editions' {
            $a = New-Answers
            $a.workloads[0].memoryMB = 3000
            $path = Join-Path $TestDrive 'sizes.json'
            Write-Answers $a $path
            { Read-WorkloadAnswers $path } | Should -Throw
            $a = New-Answers
            $a.workloads[0].profile = 'sqlServer'
            $a.workloads[0].Remove('fileServer')
            $a.workloads[0].memoryMB = 8192
            $a.workloads[0].sqlServer = @{
                edition = 'Enterprise'; acceptLicenseTerms = $true
                installerUrl = 'https://media.contoso.invalid/sql.iso'; installerSha256 = 'a' * 64
            }
            Write-Answers $a $path
            { Read-WorkloadAnswers $path } | Should -Throw
        }

        It 'rejects cross-subscription resource IDs and duplicate names' {
            $a = New-Answers
            $a.logicalNetworkId = $a.logicalNetworkId.Replace('00000000-0000-0000-0000-000000000000', '11111111-1111-1111-1111-111111111111')
            { Assert-Answers $a } | Should -Throw '*subscription*'
            $a = New-Answers
            $a.workloads += $a.workloads[0].Clone()
            { Assert-Answers $a } | Should -Throw '*unique*'
        }

        It 'rejects malformed, noncanonical and unrestricted CIDRs' {
            foreach ($cidr in @('999.1.1.0/24', '10.0.0.1/24', '0.0.0.0/0', '127.0.0.0/8', '224.0.0.0/8', '10.01.0.0/16')) {
                { Get-CidrRange $cidr } | Should -Throw
            }
            (Get-CidrRange '10.40.0.0/24').End | Should -Be (ConvertTo-IPv4Number '10.40.0.255')
        }

        It 'validates RSA wire format and minimum size, not only the key prefix' {
            { Assert-RsaPublicKey 'ssh-rsa AAAA' } | Should -Throw '*2048*'
            $rsa = [Security.Cryptography.RSA]::Create(2048)
            try {
                $p = $rsa.ExportParameters($false)
                $m = [IO.MemoryStream]::new()
                foreach ($part in @([Text.Encoding]::ASCII.GetBytes('ssh-rsa'), $p.Exponent, (,[byte]0 + $p.Modulus))) {
                    $bytes = [byte[]]$part
                    $size = [BitConverter]::GetBytes([uint32]$bytes.Length)
                    [Array]::Reverse($size)
                    $m.Write($size); $m.Write($bytes)
                }
                $key = 'ssh-rsa ' + [Convert]::ToBase64String($m.ToArray())
                { Assert-RsaPublicKey $key } | Should -Not -Throw
                $m.Dispose()
            } finally { $rsa.Dispose() }
        }

        It 'requires real noncredentialed SQL media and a nonplaceholder hash' {
            $a = New-Answers
            $a.workloads = @((Get-Content (Join-Path $script:Root 'answers\example.json') -Raw | ConvertFrom-Json -AsHashtable).workloads[1])
            $a.workloads[0].count = 1
            { Assert-Answers $a } | Should -Throw '*real HTTPS*'
            $a.workloads[0].sqlServer.installerUrl = 'https://media.contoso.invalid/sql.iso'
            $a.workloads[0].sqlServer.installerSha256 = 'a' * 64
            { Assert-Answers $a } | Should -Not -Throw
            $a.workloads[0].sqlServer.installerUrl = 'https://user:password@media.contoso.invalid/sql.iso'
            { Assert-Answers $a } | Should -Throw
        }

        It 'does not put a Linux password in deployment parameters' {
            $a = New-Answers
            $a.workloads = @(@{ profile = 'webServer' })
            (Get-PasswordParameter $a).value | Should -BeExactly ''
        }

        It 'uses a pinned Key Vault ARM reference without fetching the secret' {
            $a = New-Answers
            $a.passwordSource = @{
                type = 'keyVault'; vaultResourceId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault'
                secretName = 'vm-password'; secretVersion = 'a' * 32
            }
            Mock Invoke-AzJson { throw 'Must not fetch secret' }
            $p = Get-PasswordParameter $a
            $p.ContainsKey('value') | Should -BeFalse
            $p.reference.secretVersion | Should -Be ('a' * 32)
            Should -Invoke Invoke-AzJson -Times 0
        }

        It 'does not permit adopting unmanaged existing resources or resizing owned VMs' {
            { Assert-OwnedResource @{ name = 'existing' } 'branch-office' 'hash' } | Should -Throw '*not owned*'
            $r = @{ name = 'ours'; tags = @{ project = 'azure-local-workload-templates'; deploymentSet = 'branch-office'; configurationHash = 'old' } }
            { Assert-OwnedResource $r 'branch-office' 'new' } | Should -Throw
            { Assert-OwnedResource $r 'branch-office' 'old' } | Should -Not -Throw
        }

        It 'does not hash credentials or depend on JSON property order' {
            $a = New-Answers
            $before = Get-ConfigurationHash $a $a.workloads[0] '/images/approved'
            $reordered = @{}
            foreach ($key in @($a.workloads[0].Keys | Sort-Object -Descending)) { $reordered[$key] = $a.workloads[0][$key] }
            (Get-ConfigurationHash $a $reordered '/images/approved') | Should -Be $before
            $a.passwordSource = @{ type = 'environment'; name = 'NEW_PASSWORD_SOURCE' }
            (Get-ConfigurationHash $a $a.workloads[0] '/images/approved') | Should -Be $before
            $a.workloads[0].processors = 8
            (Get-ConfigurationHash $a $a.workloads[0] '/images/approved') | Should -Not -Be $before
        }

        It 'refuses VM drift rather than detaching a customer-added disk or NIC' {
            $a = New-Answers
            $group = '/subscriptions/sub/resourceGroups/rg'
            $w = $a.workloads[0]
            $vm = @{
                properties = @{
                    hardwareProfile = @{ processors = $w.processors; memoryMB = $w.memoryMB }
                    networkProfile = @{ networkInterfaces = @(@{ id = "$group/providers/Microsoft.AzureStackHCI/networkInterfaces/$($w.name)-nic" }) }
                    storageProfile = @{
                        imageReference = @{ id = '/images/approved' }
                        dataDisks = @(@{ id = "$group/providers/Microsoft.AzureStackHCI/virtualHardDisks/$($w.name)-data" })
                    }
                }
            }
            { Assert-VmMatchesConfiguration $vm $w '/images/approved' $group } | Should -Not -Throw
            $vm.properties.storageProfile.dataDisks += @{ id = '/disks/customer-data' }
            { Assert-VmMatchesConfiguration $vm $w '/images/approved' $group } | Should -Throw '*drift*'
            $vm.properties.storageProfile.dataDisks = @(@{ id = "$group/providers/Microsoft.AzureStackHCI/virtualHardDisks/$($w.name)-data" })
            $vm.properties.networkProfile.networkInterfaces += @{ id = '/nics/customer-nic' }
            { Assert-VmMatchesConfiguration $vm $w '/images/approved' $group } | Should -Throw '*drift*'
        }
    }
}

Describe 'Counted profiles and capacity planning' {
    InModuleScope WorkloadDeployment {
        It 'expands explicit counts to stable names and leaves legacy single names unchanged' {
            $a = New-Answers
            @(Expand-Workloads $a.workloads)[0].name | Should -Be 'files-01'
            $w = $a.workloads[0]
            $w.name = 'files'; $w.count = 1
            @(Expand-Workloads @($w))[0].name | Should -Be 'files-01'
            $w.count = 3
            $expanded = @(Expand-Workloads @($w))
            $expanded.name | Should -Be @('files-01', 'files-02', 'files-03')
            @(Get-WorkloadDisks $expanded[2])[0].role | Should -Be 'data'
            $expanded[0].ContainsKey('count') | Should -BeFalse
        }

        It 'does not import, authenticate or read passwords for count zero in any mode' {
            $a = New-Answers
            $a.workloads[0].count = 0
            $path = Join-Path $TestDrive 'disabled.json'
            Write-Answers $a $path
            Mock Open-ArmConnection { throw 'Must not authenticate' }
            Mock Get-PasswordParameter { throw 'Must not read secret' }
            Mock Import-MissingImages { throw 'Must not import' }
            foreach ($mode in @('Validate', 'Preflight', 'Deploy')) {
                $text = (Start-WorkloadDeployment -AnswerFile $path -Mode $mode -Confirm:$false) -join "`n"
                $text | Should -Match 'Plan: 0 VMs'
            }
            Should -Invoke Open-ArmConnection -Times 0
            Should -Invoke Get-PasswordParameter -Times 0
            Should -Invoke Import-MissingImages -Times 0
        }

        It 'skips semantic prerequisites for disabled profiles, but not malformed schema' {
            $a = Get-Content (Join-Path $script:Root 'answers\example.json') -Raw | ConvertFrom-Json -AsHashtable
            $path = Join-Path $TestDrive 'catalog.json'
            Write-Answers $a $path
            (Read-WorkloadAnswers $path).workloads.Count | Should -Be 1
            $a.workloads[2].count = 1
            Write-Answers $a $path
            { Read-WorkloadAnswers $path } | Should -Throw '*2048*'
        }

        It 'rejects invalid counts, CPU, RAM, OS suggestions and data disk capacities' {
            $path = Join-Path $TestDrive 'bounds.json'
            foreach ($change in @(
                @{ count = -1 }, @{ count = 21 }, @{ count = 1.5 },
                @{ processors = 1 }, @{ processors = 65 }, @{ memoryMB = 4097 },
                @{ suggestedOsDiskSizeGB = 0 }, @{ suggestedOsDiskSizeGB = 2049 },
                @{ dataDiskSizeGB = 31 }, @{ dataDiskSizeGB = 8193 }
            )) {
                $a = New-Answers
                foreach ($key in $change.Keys) { $a.workloads[0][$key] = $change[$key] }
                Write-Answers $a $path
                { Read-WorkloadAnswers $path } | Should -Throw '*schema*'
            }
        }

        It 'rejects too-long generated names, expanded-name collisions and total count overflow' {
            $a = New-Answers
            $a.workloads[0].name = 'thirteenchars'; $a.workloads[0].count = 2
            { Expand-Workloads $a.workloads } | Should -Throw '*12 characters*'
            $a.workloads[0].name = 'files'
            $legacy = (New-Answers).workloads[0]
            { Expand-Workloads @($a.workloads[0], $legacy) } | Should -Throw '*collides*'
            $entries = @(1..6 | ForEach-Object { $w = (New-Answers).workloads[0]; $w.name = "group$_"; $w.count = 20; $w })
            { Expand-Workloads $entries } | Should -Throw '*100 VMs*'
        }

        It 'maps addresses one-to-one without arithmetic and rejects partial, mixed or duplicate lists' {
            $w = (New-Answers).workloads[0]
            $w.name = 'files'; $w.count = 2
            $w.privateIpAddresses = @('10.40.0.20', '10.40.0.30')
            $instances = @(Expand-Workloads @($w))
            $instances.privateIpAddress | Should -Be @('10.40.0.20', '10.40.0.30')
            $w.privateIpAddresses = @('10.40.0.20')
            { Expand-Workloads @($w) } | Should -Throw '*exactly one*'
            $w.privateIpAddresses = @('10.40.0.20', '10.40.0.20')
            { Expand-Workloads @($w) } | Should -Throw '*unique*'
            $w.privateIpAddress = '10.40.0.40'
            { Expand-Workloads @($w) } | Should -Throw
            $w.Remove('privateIpAddress'); $w.Remove('count')
            { Expand-Workloads @($w) } | Should -Throw '*requires count*'
        }

        It 'accepts IIS and Windows/Linux base profiles and validates disk roles and OS pairing' {
            $path = Join-Path $TestDrive 'profiles.json'
            foreach ($profile in @('iisServer', 'windowsApp', 'linuxApp')) {
                $a = if ($profile -eq 'linuxApp') { New-LinuxAnswers } else { New-Answers }
                $w = $a.workloads[0]; $w.profile = $profile; $w.Remove('fileServer')
                if ($profile -ne 'iisServer') {
                    $w.Remove('dataDiskSizeGB')
                    $w.dataDisks = @(@{ role = 'appdata'; sizeGB = 64 }, @{ role = 'logs'; sizeGB = 32 })
                }
                Write-Answers $a $path
                (Read-WorkloadAnswers $path).workloads[0].profile | Should -Be $profile
                if ($profile -ne 'iisServer') {
                    $w.dataDisks[1].role = 'appdata'
                    Write-Answers $a $path
                    { Read-WorkloadAnswers $path } | Should -Throw '*roles*'
                    $w.dataDisks = @(@{ role = 'data'; sizeGB = 0 })
                    Write-Answers $a $path
                    { Read-WorkloadAnswers $path } | Should -Throw '*schema*'
                }
                $w.image.os = if ($profile -eq 'linuxApp') { 'WindowsServer2022' } else { 'Ubuntu2204' }
                Write-Answers $a $path
                { Read-WorkloadAnswers $path } | Should -Throw '*schema*'
            }
        }

        It 'aggregates exact applied sizes separately from advisory OS capacities' {
            $a = New-Answers
            $a.workloads[0].name = 'files'; $a.workloads[0].count = 2
            $a.workloads[0].suggestedOsDiskSizeGB = 128
            $w = (New-LinuxAnswers).workloads[0]
            $w.dataDisks = @(@{ role = 'appdata'; sizeGB = 64 }, @{ role = 'logs'; sizeGB = 32 })
            $w.Remove('suggestedOsDiskSizeGB')
            $w.name = 'linuxapp'
            $summary = Get-WorkloadSummary @(Expand-Workloads @($a.workloads[0], $w))
            $summary.vmCount | Should -Be 3
            $summary.processors | Should -Be 6
            $summary.memoryMB | Should -Be 12288
            $summary.dataDiskCount | Should -Be 4
            $summary.dataDiskGB | Should -Be 352
            $summary.suggestedOsDiskGB | Should -Be 256
            $summary.unspecifiedOsDiskCount | Should -Be 1
        }

        It 'keeps instance hashes stable as count grows and excludes planning-only OS suggestions' {
            $a = New-Answers
            $w = $a.workloads[0]; $w.name = 'files'; $w.count = 1
            $first = @(Expand-Workloads @($w))[0]
            $hash = Get-ConfigurationHash $a $first '/images/id'
            $w.count = 3; $w.suggestedOsDiskSizeGB = 256
            (Get-ConfigurationHash $a @(Expand-Workloads @($w))[0] '/images/id') | Should -Be $hash
            $w = (New-LinuxAnswers).workloads[0]
            $w.dataDisks = @(@{ role = 'logs'; sizeGB = 32 }, @{ role = 'appdata'; sizeGB = 64 })
            $hash = Get-ConfigurationHash $a $w '/images/id'
            [array]::Reverse($w.dataDisks)
            (Get-ConfigurationHash $a $w '/images/id') | Should -Be $hash
            $w.dataDisks[0].sizeGB = 128
            (Get-ConfigurationHash $a $w '/images/id') | Should -Not -Be $hash
        }
    }
}

Describe 'Prepared Linux image source contracts and imports' {
    InModuleScope WorkloadDeployment {
        It 'accepts a stamp CSV source and rejects client paths, traversal, UNC and alternate streams' {
            $a = New-LinuxAnswers
            $path = Join-Path $TestDrive 'prepared.json'
            Write-Answers $a $path
            (Read-WorkloadAnswers $path).workloads[0].image.source | Should -Be 'local'
            foreach ($bad in @('C:\Users\operator\ubuntu.vhdx', '.\ubuntu.vhdx', '\\server\share\ubuntu.vhdx',
                'C:\ClusterStorage\Volume1\..\ubuntu.vhdx', 'C:\ClusterStorage\Volume1\ubuntu.vhd',
                'C:\ClusterStorage\Volume1\ubuntu:stream.vhdx')) {
                $a.workloads[0].image.path = $bad
                { Assert-PreparedImageSource $a.workloads[0].image } | Should -Throw '*CSV path*'
            }
        }

        It 'keeps source modes exclusive and requires explicit preparation, stamp and page-blob confirmation' {
            $a = New-LinuxAnswers
            $path = Join-Path $TestDrive 'modes.json'
            foreach ($key in @('preparedImageConfirmed', 'stampPathConfirmed', 'sha256')) {
                $image = $a.workloads[0].image.Clone()
                $a.workloads[0].image.Remove($key)
                Write-Answers $a $path
                { Read-WorkloadAnswers $path } | Should -Throw '*schema*'
                $a.workloads[0].image = $image
            }
            $a.workloads[0].image.resourceId = $a.storageContainerId
            Write-Answers $a $path
            { Read-WorkloadAnswers $path } | Should -Throw '*schema*'
            $a.workloads[0].image = @{
                source = 'blob'; os = 'Ubuntu2204'; name = 'prepared-blob'; preparedImageConfirmed = $true
                sha256 = 'a' * 64; uri = 'https://preparedimages.blob.core.windows.net/images/ubuntu.vhd'
                sasTokenEnvironmentVariable = 'AZLOCAL_TEST_SAS'; pageBlobConfirmed = $true
            }
            Write-Answers $a $path
            (Read-WorkloadAnswers $path).workloads[0].image.source | Should -Be 'blob'
            $a.workloads[0].image.Remove('pageBlobConfirmed')
            Write-Answers $a $path
            { Read-WorkloadAnswers $path } | Should -Throw '*schema*'
        }

        It 'rejects SAS-bearing or non-blob URI inputs without echoing credential values' {
            $image = @{ source = 'blob'; name = 'prepared'; sha256 = 'a' * 64 }
            foreach ($uri in @('https://preparedimages.blob.core.windows.net/images/ubuntu.vhd?sig=not-real',
                'https://user:pass@preparedimages.blob.core.windows.net/images/ubuntu.vhd',
                'http://preparedimages.blob.core.windows.net/images/ubuntu.vhd', 'https://example.com/ubuntu.vhd',
                'https://preparedimages.blob.core.windows.net/images/ubuntu.vhd#fragment')) {
                $image.uri = $uri
                { Assert-PreparedImageSource $image } | Should -Throw '*noncredentialed*'
            }
        }

        It 'reuses a ready digest-matching prepared image regardless of name and rejects conflicting names' {
            $a = New-LinuxAnswers
            $image = New-PreparedImage $a
            $plan = @(Get-ImagePlan $a @($image))
            $plan[0].import | Should -BeFalse
            $plan[0].imageId | Should -Be $image.id
            $image.id = "/subscriptions/$($a.subscriptionId)/resourceGroups/$($a.resourceGroup)/providers/Microsoft.AzureStackHCI/galleryImages/ubuntu-prepared"
            $image.tags.preparedImageSha256 = 'b' * 64
            { Get-ImagePlan $a @($image) } | Should -Throw '*occupied*'
            $image.tags.preparedImageSha256 = 'a' * 64
            $image.properties.cloudInitDataSource = 'Azure'
            { Get-ImagePlan $a @($image) } | Should -Throw '*occupied*'
        }

        It 'imports the prepared image once with the exact custom-gallery shape and bounded wait' {
            $a = New-LinuxAnswers
            $w = $a.workloads[0]; $w.name = 'linuxapp'; $w.count = 2
            $a.workloads = @(Expand-Workloads @($w))
            $plan = @(Get-ImagePlan $a @())
            Mock Get-ArmResource { $null }
            Mock Invoke-ArmRequest { $script:PreparedBody = $Body; @{} }
            Mock Wait-ArmResource { New-PreparedImage $a }
            Import-MissingImages $a $plan 123
            $script:PreparedBody.properties.imagePath | Should -Be 'C:\ClusterStorage\Volume1\Images\ubuntu.vhdx'
            $script:PreparedBody.properties.osType | Should -Be 'Linux'
            $script:PreparedBody.properties.cloudInitDataSource | Should -Be 'NoCloud'
            $script:PreparedBody.properties.containerId | Should -Be $a.storageContainerId
            $script:PreparedBody.tags.preparedImageSha256 | Should -Be ('a' * 64)
            $script:PreparedBody.properties.ContainsKey('identifier') | Should -BeFalse
            Should -Invoke Invoke-ArmRequest -Times 1 -ParameterFilter { $Method -eq 'PUT' -and $CreateOnly -and $Path -match '/galleryImages/' }
            Should -Invoke Wait-ArmResource -Times 1 -ParameterFilter { $TimeoutSeconds -eq 123 }
        }

        It 'fails safely if a prepared image appears after preflight or imports with wrong metadata' {
            $a = New-LinuxAnswers
            $plan = @(Get-ImagePlan $a @())
            Mock Get-ArmResource { New-PreparedImage $a }
            Mock Invoke-ArmRequest { @{} }
            { Import-MissingImages $a $plan 60 } | Should -Throw '*appeared*'
            Should -Invoke Invoke-ArmRequest -Times 0
            Mock Get-ArmResource { $null }
            Mock Wait-ArmResource { $image = New-PreparedImage $a; $image.properties.cloudInitDataSource = 'Azure'; $image }
            { Import-MissingImages $a $plan 60 } | Should -Throw '*NoCloud*'
        }

        It 'reads a blob SAS only at import time and never includes it in the answer or image plan' {
            $a = New-LinuxAnswers
            $a.workloads[0].image = @{
                source = 'blob'; os = 'Ubuntu2204'; name = 'prepared-blob'; preparedImageConfirmed = $true
                sha256 = 'a' * 64; uri = 'https://preparedimages.blob.core.windows.net/images/ubuntu.vhd'
                sasTokenEnvironmentVariable = 'AZLOCAL_TEST_IMAGE_SAS'; pageBlobConfirmed = $true
            }
            $old = [Environment]::GetEnvironmentVariable('AZLOCAL_TEST_IMAGE_SAS', 'Process')
            try {
                [Environment]::SetEnvironmentVariable('AZLOCAL_TEST_IMAGE_SAS', $null, 'Process')
                { Assert-Answers $a } | Should -Not -Throw
                $plan = @(Get-ImagePlan $a @())
                { Get-PreparedImagePath $a.workloads[0].image } | Should -Throw '*empty or missing*'
                $expiry = [uri]::EscapeDataString([DateTimeOffset]::UtcNow.AddHours(4).ToString('o'))
                $sas = "sp=r&sr=b&spr=https&se=$expiry&sig=fake-unit-test-signature"
                [Environment]::SetEnvironmentVariable('AZLOCAL_TEST_IMAGE_SAS', $sas, 'Process')
                Mock Get-ArmResource { $null }
                Mock Invoke-ArmRequest { $script:PreparedBody = $Body; @{} }
                Mock Wait-ArmResource { New-PreparedImage $a }
                Import-MissingImages $a $plan 60
                $script:PreparedBody.properties.imagePath | Should -Be "$($a.workloads[0].image.uri)?$sas"
                ($plan | ConvertTo-Json -Depth 20) | Should -Not -Match 'fake-unit-test-signature'
                foreach ($bad in @($sas.Replace('sp=r&', 'sp=rw&'), $sas.Replace('spr=https', 'spr=http'), $sas.Replace($expiry, '2000-01-01T00%3A00%3A00Z'))) {
                    [Environment]::SetEnvironmentVariable('AZLOCAL_TEST_IMAGE_SAS', $bad, 'Process')
                    { Get-PreparedImagePath $a.workloads[0].image } | Should -Throw '*read-only token*'
                }
            } finally { [Environment]::SetEnvironmentVariable('AZLOCAL_TEST_IMAGE_SAS', $old, 'Process') }
        }
    }
}

Describe 'Azure image decisions' {
    InModuleScope WorkloadDeployment {
        It 'reuses a matching pinned image even when it has a different name' {
            $a = New-Answers
            $image = New-Image $a
            $plan = @(Get-ImagePlan $a @($image))
            $plan[0].import | Should -BeFalse
            $plan[0].imageId | Should -Be $image.id
        }

        It 'imports a missing supported Windows image, never overwriting a mismatched name' {
            $a = New-Answers
            @(Get-ImagePlan $a @())[0].import | Should -BeTrue
            $image = New-Image $a $a.workloads[0].image.name
            $image.id = "/subscriptions/$($a.subscriptionId)/resourceGroups/$($a.resourceGroup)/providers/Microsoft.AzureStackHCI/marketplaceGalleryImages/$($image.name)"
            $image.properties.version.name = '1.2.3'
            { Get-ImagePlan $a @($image) } | Should -Throw '*occupied*'
        }

        It 'does not reuse failed, wrong-stamp or wrong-OS images' {
            $a = New-Answers
            $image = New-Image $a
            $image.properties.provisioningState = 'Failed'
            { Get-ImagePlan $a @($image) } | Should -Throw '*not provisioned*'
            $a.workloads[0].image = @{ source = 'existing'; resourceId = $image.id }
            $image.properties.provisioningState = 'Succeeded'
            $image.extendedLocation.name = 'different'
            { Get-ImagePlan $a @($image) } | Should -Throw '*another stamp*'
            $image.extendedLocation.name = $a.stamp.customLocationId
            $image.properties.osType = 'Linux'
            { Get-ImagePlan $a @($image) } | Should -Throw '*expected OS*'
        }

        It 'refuses a missing prepared Linux image, rather than importing a generic Ubuntu offer' {
            $a = New-Answers
            $a.workloads[0].image = @{ source = 'existing'; resourceId = '/missing/image' }
            { Get-ImagePlan $a @() } | Should -Throw '*not found*'
        }

        It 'imports one image for several workloads and validates each completed import' {
            $a = New-Answers
            $a.workloads += $a.workloads[0].Clone()
            $a.workloads[1].name = 'files-02'
            $plan = @(Get-ImagePlan $a @())
            Mock Get-ArmResource { $null }
            Mock Invoke-ArmRequest { @{} }
            Mock Wait-ArmResource {
                $image = New-Image $a
                $image
            }
            { Import-MissingImages $a $plan 60 } | Should -Not -Throw
            Should -Invoke Invoke-ArmRequest -Times 1 -ParameterFilter { $Method -eq 'PUT' -and $CreateOnly }
        }
    }
}

Describe 'Static addressing, RBAC and bounded polling' {
    InModuleScope WorkloadDeployment {
        BeforeEach {
            $script:networkFixture = @{
                properties = @{
                    subnets = @(@{
                        properties = @{
                            ipAllocationMethod = 'Static'; addressPrefix = '10.40.0.0/24'
                            ipPools = @(@{ start = '10.40.0.10'; end = '10.40.0.200'; ipPoolType = 'vm' })
                            ipConfigurationReferences = @()
                            routeTable = @{ properties = @{ routes = @(@{ properties = @{ nextHopIpAddress = '10.40.0.1' } }) } }
                        }
                    })
                }
            }
        }

        It 'requires an explicit pool-eligible host for static logical networks' {
            $workload = @{ name = 'files-01' }
            { Assert-NetworkConfiguration $script:networkFixture @($workload) } | Should -Throw '*explicit*'
            $workload.privateIpAddress = '10.41.0.20'
            { Assert-NetworkConfiguration $script:networkFixture @($workload) } | Should -Throw '*within*'
            $workload.privateIpAddress = '10.40.0.2'
            { Assert-NetworkConfiguration $script:networkFixture @($workload) } | Should -Throw '*pool*'
            $workload.privateIpAddress = '10.40.0.20'
            { Assert-NetworkConfiguration $script:networkFixture @($workload) } | Should -Not -Throw
        }

        It 'requires a static address on every expanded instance, and permits DHCP without lists' {
            $w = (New-Answers).workloads[0]
            $w.name = 'files'; $w.count = 2
            $instances = @(Expand-Workloads @($w))
            { Assert-NetworkConfiguration $script:networkFixture $instances } | Should -Throw '*explicit*'
            $w.privateIpAddresses = @('10.40.0.20', '10.40.0.21')
            $instances = @(Expand-Workloads @($w))
            { Assert-NetworkConfiguration $script:networkFixture $instances } | Should -Not -Throw
            $script:networkFixture.properties.subnets[0].properties.ipAllocationMethod = 'Dynamic'
            { Assert-NetworkConfiguration $script:networkFixture $instances } | Should -Throw '*DHCP*'
            $w.Remove('privateIpAddresses')
            { Assert-NetworkConfiguration $script:networkFixture @(Expand-Workloads @($w)) } | Should -Not -Throw
        }

        It 'rejects static addresses on DHCP networks and detects other NIC allocations' {
            $workload = @{ name = 'files-01'; privateIpAddress = '10.40.0.20' }
            $script:networkFixture.properties.subnets[0].properties.ipAllocationMethod = 'Dynamic'
            { Assert-NetworkConfiguration $script:networkFixture @($workload) } | Should -Throw '*DHCP*'
            $script:networkFixture.properties.subnets[0].properties.ipAllocationMethod = 'Static'
            $script:networkFixture.properties.subnets[0].properties.ipConfigurationReferences = @(@{ ID = '/nics/other/ipConfigurations/primary' })
            Mock Get-ArmResource { @{ name = 'other'; properties = @{ ipConfigurations = @(@{ properties = @{ privateIPAddress = '10.40.0.20' } }) } } }
            { Assert-NetworkConfiguration $script:networkFixture @($workload) } | Should -Throw '*another NIC*'
        }

        It 'respects notActions per grant but permits another grant to allow the action' {
            Mock Get-ArmCollection { @(@{ actions = @('*'); notActions = @('Microsoft.Insights/*') }) }
            { Assert-DeploymentPermissions '/scope' @('Microsoft.Insights/dataCollectionRules/write') } | Should -Throw '*permission*'
            Mock Get-ArmCollection { @(@{ actions = @('*'); notActions = @('Microsoft.Insights/*') }, @{ actions = @('Microsoft.Insights/*'); notActions = @() }) }
            { Assert-DeploymentPermissions '/scope' @('Microsoft.Insights/dataCollectionRules/write') } | Should -Not -Throw
        }

        It 'stops on terminal failure and does not report success on timeout' {
            Mock Get-ArmResource { @{ name = 'test'; properties = @{ provisioningState = 'Failed' } } }
            { Wait-ArmResource '/id' 'api' 0 0 } | Should -Throw '*Failed*'
            Mock Get-ArmResource { @{ name = 'test'; properties = @{ provisioningState = 'Creating' } } }
            { Wait-ArmResource '/id' 'api' 0 0 } | Should -Throw '*Timed out*'
        }

        It 'returns only when readiness is Succeeded' {
            Mock Get-ArmResource { @{ name = 'test'; properties = @{ provisioningState = 'Succeeded' } } }
            (Wait-ArmResource '/id' 'api' 60 0).properties.provisioningState | Should -Be Succeeded
        }
    }
}

Describe 'Guest delivery and deployment boundaries' {
    InModuleScope WorkloadDeployment {
        It 'does not run service scripts or read Windows artifacts for base application profiles' {
            $a = New-Answers
            Mock Get-WindowsGuestArtifact { throw 'Must not download a script' }
            foreach ($profile in @('windowsApp', 'linuxApp')) {
                (Get-GuestSettings $a @{ profile = $profile }).Count | Should -Be 0
            }
            Should -Invoke Get-WindowsGuestArtifact -Times 0
            $a.workloads = @(@{ profile = 'linuxApp' })
            (Get-PasswordParameter $a).value | Should -Be ''
        }

        It 'submits exactly the expanded base VM shapes including raw data disks' {
            $a = New-LinuxAnswers
            $w = $a.workloads[0]; $w.name = 'linuxapp'; $w.count = 2
            $w.dataDisks = @(@{ role = 'logs'; sizeGB = 32 }, @{ role = 'appdata'; sizeGB = 64 })
            $path = Join-Path $TestDrive 'expanded.json'
            Write-Answers $a $path
            Mock Open-ArmConnection {}
            Mock Close-ArmConnection {}
            Mock Invoke-WorkloadPreflight {
                foreach ($item in $Answers.workloads) { @{ workloadName = $item.name; imageId = '/images/prepared'; import = $false } }
            }
            Mock Get-CompiledTemplate { @{} }
            Mock Get-WindowsGuestArtifact { throw 'Must not read Windows script' }
            Mock Import-MissingImages {}
            Mock Invoke-ArmRequest { $script:ExpandedBody = $Body; @{} }
            Mock Wait-ArmResource { @{ properties = @{ provisioningState = 'Succeeded' } } }
            $null = Start-WorkloadDeployment -AnswerFile $path -Mode Deploy -Confirm:$false
            $items = $script:ExpandedBody.properties.parameters.workloads.value
            $items.Count | Should -Be 2
            $items.name | Should -Be @('linuxapp-01', 'linuxapp-02')
            foreach ($item in $items) {
                $item.isLinux | Should -BeTrue
                $item.configureGuest | Should -BeFalse
                $item.guestSettings.Count | Should -Be 0
                $item.dataDisks.role | Should -Be @('appdata', 'logs')
                $item.dataDisks.sizeGB | Should -Be @(64, 32)
                $item.processors | Should -Be 2
                $item.memoryMB | Should -Be 4096
            }
            $script:ExpandedBody.properties.parameters.adminPassword.value | Should -Be ''
            Should -Invoke Get-WindowsGuestArtifact -Times 0
        }

        It 'embeds restricted Linux content without an external script download' {
            $a = New-Answers
            $w = @{ profile = 'webServer'; allowedCidrs = @('10.40.0.0/24') }
            $settings = Get-GuestSettings $a $w
            $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($settings.script))
            $text | Should -Match "allowed_cidrs='10.40.0.0/24'"
            $text | Should -Not -Match '__ALLOWED_CIDRS__'
            $text | Should -Match 'deny all'
        }

        It 'pins Windows script bytes and keeps the command within the command processor limit' {
            $a = New-Answers
            Mock Get-WindowsGuestArtifact { @{ uri = 'https://raw.githubusercontent.com/example/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/guest/Configure-Windows.ps1'; sha256 = 'a' * 64 } }
            $settings = Get-GuestSettings $a $a.workloads[0]
            $settings.commandToExecute.Length | Should -BeLessOrEqual 8100
            $settings.commandToExecute | Should -Match 'Get-FileHash'
            $settings.fileUris[0] | Should -Match '/a{40}/guest/'
        }

        It 'refuses a dirty Windows script before creating an executable artifact URL' {
            Mock Invoke-SourceGit {
                switch ($Arguments[0]) {
                    'remote' { 'https://github.com/example/repo.git' }
                    'hash-object' { 'b' * 40 }
                    default { 'a' * 40 }
                }
            }
            { Get-WindowsGuestArtifact } | Should -Throw '*uncommitted*'
        }

        It 'derives an immutable public origin URL without a .git suffix' {
            Mock Invoke-SourceGit {
                if ($Arguments[0] -eq 'remote') { 'https://github.com/example/repo.git' } else { 'a' * 40 }
            }
            (Get-WindowsGuestArtifact).uri | Should -Be ('https://raw.githubusercontent.com/example/repo/' + ('a' * 40) + '/guest/Configure-Windows.ps1')
        }

        It 'submits an incremental deployment only after preflight and image readiness' {
            $a = New-Answers
            Mock Read-WorkloadAnswers { $a }
            Mock Open-ArmConnection {}
            Mock Close-ArmConnection {}
            Mock Invoke-WorkloadPreflight { @(@{ workloadName = 'files-01'; imageId = '/images/id'; import = $false }) }
            Mock Get-WindowsGuestArtifact { @{ uri = 'https://raw.githubusercontent.com/example/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/guest/Configure-Windows.ps1'; sha256 = 'a' * 64 } }
            Mock Assert-PublicGuestArtifact {}
            Mock Get-CompiledTemplate { @{ parameters = @{ adminPassword = @{ type = 'secureString' } } } }
            Mock Get-PasswordParameter { @{ value = 'fake-test-password-only' } }
            Mock Import-MissingImages { $script:ImagesReady = $true }
            Mock Invoke-ArmRequest {
                if (!$script:ImagesReady) { throw 'Deployment started before image readiness' }
                $script:SubmittedBody = $Body
                @{}
            }
            Mock Wait-ArmResource { @{ properties = @{ provisioningState = 'Succeeded' } } }
            $script:ImagesReady = $false
            $script:SubmittedBody = $null
            ((Start-WorkloadDeployment -AnswerFile 'test' -Mode Deploy -Confirm:$false) -join "`n") | Should -Match 'succeeded'
            $script:SubmittedBody.properties.mode | Should -Be Incremental
            $script:SubmittedBody.properties.parameters.workloads.value[0].imageId | Should -Be '/images/id'
            $script:SubmittedBody.properties.parameters.workloads.value[0].guestSettings.fileUris.Count | Should -Be 1
            Should -Invoke Wait-ArmResource -Times 1
        }

        It 'does not submit a deployment after image import fails' {
            $a = New-Answers
            Mock Read-WorkloadAnswers { $a }
            Mock Open-ArmConnection {}
            Mock Close-ArmConnection {}
            Mock Invoke-WorkloadPreflight { @(@{ workloadName = 'files-01'; imageId = '/images/id'; import = $true }) }
            Mock Get-WindowsGuestArtifact { @{ uri = 'https://raw.githubusercontent.com/example/repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/guest/Configure-Windows.ps1'; sha256 = 'a' * 64 } }
            Mock Assert-PublicGuestArtifact {}
            Mock Get-CompiledTemplate { @{} }
            Mock Get-PasswordParameter { @{ value = 'fake-test-password-only' } }
            Mock Import-MissingImages { throw 'Image failed' }
            Mock Invoke-ArmRequest { throw 'Must not deploy' }
            { Start-WorkloadDeployment -AnswerFile 'test' -Mode Deploy -Confirm:$false } | Should -Throw '*Image failed*'
            Should -Invoke Invoke-ArmRequest -Times 0
            Should -Invoke Close-ArmConnection -Times 1
        }

        It 'does not compile, prompt for secrets, import images or deploy during preflight' {
            $a = New-Answers
            Mock Read-WorkloadAnswers { $a }
            Mock Open-ArmConnection {}
            Mock Close-ArmConnection {}
            Mock Invoke-WorkloadPreflight { @(@{ workloadName = 'files-01'; imageId = '/id'; import = $true }) }
            Mock Get-CompiledTemplate { throw 'Must not compile' }
            Mock Get-PasswordParameter { throw 'Must not read secrets' }
            Mock Import-MissingImages { throw 'Must not import' }
            Mock Invoke-ArmRequest { throw 'Must not deploy' }
            ((Start-WorkloadDeployment -AnswerFile 'test' -Mode Preflight) -join "`n") | Should -Match 'import'
            Should -Invoke Get-CompiledTemplate -Times 0
            Should -Invoke Get-PasswordParameter -Times 0
            Should -Invoke Import-MissingImages -Times 0
            Should -Invoke Invoke-ArmRequest -Times 0
        }

        It 'does not mutate or read secrets with Deploy -WhatIf' {
            $a = New-Answers
            Mock Read-WorkloadAnswers { $a }
            Mock Open-ArmConnection {}
            Mock Close-ArmConnection {}
            Mock Invoke-WorkloadPreflight { @(@{ workloadName = 'files-01'; imageId = '/id'; import = $true }) }
            Mock Get-PasswordParameter { throw 'Must not read secrets' }
            Mock Import-MissingImages { throw 'Must not import' }
            $null = Start-WorkloadDeployment -AnswerFile 'test' -Mode Deploy -WhatIf
            Should -Invoke Get-PasswordParameter -Times 0
            Should -Invoke Import-MissingImages -Times 0
        }
    }
}

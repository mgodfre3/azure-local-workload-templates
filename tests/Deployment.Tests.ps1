BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\WorkloadDeployment.psm1') -Force
}

Describe 'Answer contract and pure validation' {
    InModuleScope WorkloadDeployment {
        BeforeAll {
            function script:New-Answers {
                $a = Get-Content (Join-Path $script:Root 'answers\example.json') -Raw | ConvertFrom-Json -AsHashtable
                $a.workloads = @($a.workloads[0])
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
        }

        It 'accepts a complete Windows file-server answer without any Azure call' {
            $a = New-Answers
            $path = Join-Path $TestDrive 'valid.json'
            Write-Answers $a $path
            Mock Invoke-AzJson { throw 'Must not contact Azure' }
            (Read-WorkloadAnswers $path).workloads[0].profile | Should -Be fileServer
            Start-WorkloadDeployment -AnswerFile $path -Mode Validate | Should -Match 'Offline only'
            Should -Invoke Invoke-AzJson -Times 0
        }

        It 'rejects a plaintext password rather than silently ignoring it' {
            $a = New-Answers
            $a.password = 'not-a-real-secret'
            $path = Join-Path $TestDrive 'invalid.json'
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
            Start-WorkloadDeployment -AnswerFile 'test' -Mode Preflight | Should -Match 'import'
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

#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Arm = 'https://management.azure.com'
$script:Client = $null
$script:TokenExpires = [DateTimeOffset]::MinValue
$script:Subscription = ''

function Invoke-AzJson {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $result = & az @Arguments --only-show-errors --output json 2>&1
    if ($LASTEXITCODE -ne 0) {
        # CLI output can contain token material or customer configuration.
        throw "Azure CLI command '$($Arguments[0])' failed. Check sign-in, permissions, and CLI installation independently."
    }
    ($result -join "`n") | ConvertFrom-Json -AsHashtable
}

function ConvertTo-IPv4Number {
    param([string]$Address)
    $parsed = $null
    if ($Address -notmatch '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$' -or
        ![Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Invalid dotted-decimal IPv4 address."
    }
    $bytes = $parsed.GetAddressBytes()
    [uint64]$bytes[0] * 16777216 + [uint64]$bytes[1] * 65536 + [uint64]$bytes[2] * 256 + $bytes[3]
}

function Get-CidrRange {
    param([string]$Cidr)
    if ($Cidr -notmatch '^([^/]+)/([0-9]{1,2})$') { throw 'Invalid IPv4 CIDR.' }
    $address = ConvertTo-IPv4Number $Matches[1]
    $prefix = [int]$Matches[2]
    if ($prefix -lt 8 -or $prefix -gt 32) { throw 'CIDR prefixes must be /8 through /32, never unrestricted.' }
    $size = [uint64][Math]::Pow(2, 32 - $prefix)
    $start = [uint64]([Math]::Floor($address / $size) * $size)
    if ($address -ne $start -or $start -lt 16777216 -or $start -ge 3758096384 -or
        ($start -le 2147483647 -and $start + $size -gt 2130706432)) {
        throw 'CIDR must be a canonical unicast network, not loopback, multicast, or unspecified.'
    }
    @{ Start = $start; End = $start + $size - 1; Prefix = $prefix }
}

function Assert-ResourceId {
    param([string]$Id, [string]$Type, [string]$SubscriptionId)
    $pattern = '^/subscriptions/' + [regex]::Escape($SubscriptionId) +
        '/resourceGroups/[^/]+/providers/(' + $Type + ')/[^/]+$'
    if ($Id -notmatch $pattern) { throw "Expected a resource ID of type $Type in the answer-file subscription." }
}

function Assert-RsaPublicKey {
    param([string]$Key)
    try {
        $bytes = [Convert]::FromBase64String(($Key -split ' ')[1])
        $stream = [IO.MemoryStream]::new($bytes, $false)
        $reader = [IO.BinaryReader]::new($stream)
        $parts = @()
        foreach ($i in 1..3) {
            $lengthBytes = $reader.ReadBytes(4)
            if ($lengthBytes.Length -ne 4) { throw 'Truncated key.' }
            [Array]::Reverse($lengthBytes)
            $length = [BitConverter]::ToUInt32($lengthBytes, 0)
            if ($length -gt 2048 -or $length -gt $stream.Length - $stream.Position) { throw 'Invalid key.' }
            $parts += ,$reader.ReadBytes([int]$length)
        }
        if ([Text.Encoding]::ASCII.GetString($parts[0]) -cne 'ssh-rsa' -or
            $parts[1].Length -eq 0 -or $stream.Position -ne $stream.Length) { throw 'Invalid RSA key.' }
        $modulus = $parts[2]
        if ($modulus[0] -eq 0) { $modulus = $modulus[1..($modulus.Length - 1)] }
        if ($modulus.Length -lt 256 -or ($modulus.Length -eq 256 -and $modulus[0] -lt 128)) {
            throw 'RSA modulus is below 2048 bits.'
        }
    } catch { throw 'Provide a valid ssh-rsa public key of at least 2048 bits (not the example placeholder).' }
    finally {
        if ($null -ne (Get-Variable reader -ValueOnly -ErrorAction Ignore)) { $reader.Dispose() }
        if ($null -ne (Get-Variable stream -ValueOnly -ErrorAction Ignore)) { $stream.Dispose() }
    }
}

function Read-WorkloadAnswers {
    param([string]$Path)
    $json = Get-Content -LiteralPath $Path -Raw
    if (!(Test-Json -Json $json -SchemaFile (Join-Path $script:Root 'answers\schema.json') -ErrorAction SilentlyContinue)) {
        throw 'Answer file does not match answers/schema.json. Unknown fields (including plaintext passwords), missing fields, and unsupported profiles are rejected.'
    }
    $answers = $json | ConvertFrom-Json -AsHashtable
    Assert-Answers $answers
    $answers
}

function Assert-Answers {
    param([hashtable]$Answers)
    $sub = $Answers.subscriptionId
    Assert-ResourceId $Answers.stamp.clusterResourceId 'Microsoft\.AzureStackHCI/clusters' $sub
    Assert-ResourceId $Answers.stamp.customLocationId 'Microsoft\.ExtendedLocation/customLocations' $sub
    Assert-ResourceId $Answers.logicalNetworkId 'Microsoft\.AzureStackHCI/logicalNetworks' $sub
    Assert-ResourceId $Answers.storageContainerId 'Microsoft\.AzureStackHCI/storageContainers' $sub
    Assert-ResourceId $Answers.logAnalyticsWorkspaceId 'Microsoft\.OperationalInsights/workspaces' $sub
    if ($Answers.passwordSource.type -eq 'keyVault') {
        Assert-ResourceId $Answers.passwordSource.vaultResourceId 'Microsoft\.KeyVault/vaults' $sub
    }
    if ($Answers.adminUsername -in @('root', 'admin', 'administrator', 'guest', 'user', 'test', 'support', 'system', 'sysadmin')) {
        throw 'Choose a nonreserved administrator username.'
    }
    $names = @{}
    $ips = @{}
    $imageDefinitions = @{}
    foreach ($workload in $Answers.workloads) {
        if ($names.ContainsKey($workload.name)) { throw 'Workload names must be unique (case-insensitive).' }
        $names[$workload.name] = $true
        foreach ($cidr in $workload.allowedCidrs) { $null = Get-CidrRange $cidr }
        if ($workload.ContainsKey('privateIpAddress')) {
            $null = ConvertTo-IPv4Number $workload.privateIpAddress
            if ($ips.ContainsKey($workload.privateIpAddress)) { throw 'Static IP addresses must be unique.' }
            $ips[$workload.privateIpAddress] = $true
        }
        if ($workload.profile -eq 'webServer') { Assert-RsaPublicKey $workload.sshPublicKey }
        $image = $workload.image
        if ($image.source -eq 'existing') {
            Assert-ResourceId $image.resourceId 'Microsoft\.AzureStackHCI/(galleryImages|marketplaceGalleryImages)' $sub
            if ($workload.profile -eq 'webServer' -and $image.resourceId -notmatch '/galleryImages/') {
                throw 'Ubuntu requires a prepared NoCloud custom gallery image, not a direct Marketplace import.'
            }
        } else {
            $definition = "$($image.publisher):$($image.offer):$($image.sku):$($image.version)"
            if ($imageDefinitions.ContainsKey($image.name) -and $imageDefinitions[$image.name] -ne $definition) {
                throw 'The same Marketplace image name cannot refer to different versions.'
            }
            $imageDefinitions[$image.name] = $definition
        }
        if ($workload.profile -eq 'sqlServer') {
            $uri = [uri]$workload.sqlServer.installerUrl
            if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
                $uri.Host -match '(^|\.)example\.(org|com|net)$' -or
                $workload.sqlServer.installerSha256 -match '^0{64}$') {
                throw 'SQL requires a real HTTPS full-media ISO URL without credentials/query/fragment and its verified SHA256, not the example placeholders.'
            }
        }
    }
}

function Open-ArmConnection {
    param([string]$SubscriptionId)
    $account = Invoke-AzJson @('account', 'show', '--subscription', $SubscriptionId)
    if ($account.environmentName -ne 'AzureCloud' -or $account.state -ne 'Enabled') {
        throw 'Version 1 supports enabled Azure public-cloud subscriptions only.'
    }
    $script:Subscription = $SubscriptionId
    $script:Client = [Net.Http.HttpClient]::new()
    $script:Client.Timeout = [TimeSpan]::FromSeconds(120)
    $script:TokenExpires = [DateTimeOffset]::MinValue
}

function Close-ArmConnection {
    if ($null -ne $script:Client) { $script:Client.Dispose(); $script:Client = $null }
    $script:TokenExpires = [DateTimeOffset]::MinValue
}

function Invoke-ArmRequest {
    param(
        [ValidateSet('GET', 'PUT')][string]$Method = 'GET',
        [string]$Path,
        [object]$Body,
        [switch]$AllowNotFound,
        [switch]$CreateOnly
    )
    if ($script:TokenExpires -lt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        $token = Invoke-AzJson @('account', 'get-access-token', '--subscription', $script:Subscription, '--resource', "$script:Arm/")
        $script:Client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token.accessToken)
        $script:TokenExpires = [DateTimeOffset]::FromUnixTimeSeconds([long]$token.expires_on)
        $token = $null
    }
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), "$script:Arm$Path")
    if ($CreateOnly) { $null = $request.Headers.TryAddWithoutValidation('If-None-Match', '*') }
    if ($null -ne $Body) {
        $request.Content = [Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 100 -Compress), [Text.Encoding]::UTF8, 'application/json')
    }
    try {
        $response = $script:Client.Send($request)
        $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (!$response.IsSuccessStatusCode) {
            if ($AllowNotFound -and [int]$response.StatusCode -eq 404) { return $null }
            # Do not echo ARM error bodies: some providers reflect secure request fields.
            throw "ARM $Method failed (HTTP $([int]$response.StatusCode)) for $($Path.Split('?')[0]). See Azure Activity Log for details; no rollback was attempted."
        }
        if ($text) { $text | ConvertFrom-Json -AsHashtable }
    } finally {
        $request.Dispose()
        if ($null -ne (Get-Variable response -ValueOnly -ErrorAction Ignore)) { $response.Dispose() }
    }
}

function Get-ArmResource {
    param([string]$Id, [string]$ApiVersion = '2024-01-01', [switch]$AllowNotFound)
    Invoke-ArmRequest -Path "${Id}?api-version=$ApiVersion" -AllowNotFound:$AllowNotFound
}

function Get-ArmCollection {
    param([string]$Path)
    $items = @()
    do {
        $page = Invoke-ArmRequest -Path $Path
        $items += @($page.value)
        $Path = ''
        if ($page.ContainsKey('nextLink') -and $page.nextLink) {
            $next = [uri]$page.nextLink
            if ($next.Scheme -ne 'https' -or $next.Host -ne 'management.azure.com') { throw 'Unexpected ARM pagination origin.' }
            $Path = $next.PathAndQuery
        }
    } while ($Path)
    $items
}

function Assert-ReadyResource {
    param([hashtable]$Resource, [string]$CustomLocationId = '', [string]$Location = '')
    if ($Resource.properties.provisioningState -ne 'Succeeded') { throw "Resource '$($Resource.name)' is not provisioned successfully." }
    if ($CustomLocationId -and $Resource.extendedLocation.name -ne $CustomLocationId) { throw "Resource '$($Resource.name)' belongs to another stamp/custom location." }
    if ($Location -and ($Resource.location -replace '\s', '') -ne $Location) { throw "Resource '$($Resource.name)' is in a different Azure region." }
}

function Assert-NetworkConfiguration {
    param([hashtable]$Network, [array]$Workloads, [string]$ResourceGroupId = '')
    $subnets = @($Network.properties.subnets)
    if ($subnets.Count -ne 1) { throw 'Version 1 requires a logical network with exactly one subnet.' }
    $subnet = $subnets[0].properties
    foreach ($workload in $Workloads) {
        $hasIp = $workload.ContainsKey('privateIpAddress')
        if ($subnet.ipAllocationMethod -eq 'Dynamic') {
            if ($hasIp) { throw 'Do not supply static IPs on a DHCP logical network.' }
            continue
        }
        if ($subnet.ipAllocationMethod -ne 'Static' -or !$hasIp) { throw 'Static logical networks require an explicit privateIpAddress for every workload.' }
        $prefixes = @()
        if ($subnet.ContainsKey('addressPrefix') -and $subnet.addressPrefix) { $prefixes += $subnet.addressPrefix }
        if ($subnet.ContainsKey('addressPrefixes')) { $prefixes += $subnet.addressPrefixes }
        if (@($prefixes | Select-Object -Unique).Count -ne 1) { throw 'Expected one IPv4 subnet prefix.' }
        $range = Get-CidrRange $prefixes[0]
        $ip = ConvertTo-IPv4Number $workload.privateIpAddress
        if ($ip -le $range.Start -or $ip -ge $range.End) { throw 'Static IP must be a usable host within the logical subnet.' }
        $pools = @($subnet['ipPools'] | Where-Object { $null -ne $_ -and (!$_.ContainsKey('ipPoolType') -or $_.ipPoolType -eq 'vm') })
        if (!@($pools | Where-Object { $ip -ge (ConvertTo-IPv4Number $_.start) -and $ip -le (ConvertTo-IPv4Number $_.end) }).Count) {
            throw 'Static IP must fall within a VM IP pool on the logical network.'
        }
        if ($subnet.ContainsKey('routeTable')) {
            foreach ($route in $subnet.routeTable.properties.routes) {
                if ($route.properties.nextHopIpAddress -eq $workload.privateIpAddress) { throw 'Static IP conflicts with a configured gateway.' }
            }
        }
        foreach ($reference in $subnet['ipConfigurationReferences']) {
            $nicId = $reference.ID -replace '/ipConfigurations/[^/]+$', ''
            $nic = Get-ArmResource $nicId
            foreach ($config in $nic.properties.ipConfigurations) {
                $expectedNicId = "$ResourceGroupId/providers/Microsoft.AzureStackHCI/networkInterfaces/$($workload.name)-nic"
                if ($config.properties.privateIPAddress -eq $workload.privateIpAddress -and $nic['id'] -ne $expectedNicId) {
                    throw 'Static IP is already referenced by another NIC.'
                }
            }
        }
    }
}

function Get-ImagePlan {
    param([hashtable]$Answers, [array]$Inventory)
    $plan = @()
    $rgId = "/subscriptions/$($Answers.subscriptionId)/resourceGroups/$($Answers.resourceGroup)"
    foreach ($workload in $Answers.workloads) {
        $wanted = $workload.image
        $matches = @()
        $import = $false
        if ($wanted.source -eq 'existing') {
            $matches = @($Inventory | Where-Object { $_.id -eq $wanted.resourceId })
            if (!$matches.Count) { throw "Existing image for '$($workload.name)' was not found or is inaccessible." }
        } else {
            $targetId = "$rgId/providers/Microsoft.AzureStackHCI/marketplaceGalleryImages/$($wanted.name)"
            $named = @($Inventory | Where-Object { $_.id -eq $targetId })
            $matches = @($Inventory | Where-Object {
                $_.type -eq 'Microsoft.AzureStackHCI/marketplaceGalleryImages' -and
                $_.extendedLocation.name -eq $Answers.stamp.customLocationId -and
                $_.properties['identifier'] -and $_.properties['version'] -and
                $_.properties.identifier.publisher -eq $wanted.publisher -and
                $_.properties.identifier.offer -eq $wanted.offer -and
                $_.properties.identifier.sku -eq $wanted.sku -and
                $_.properties.version.name -eq $wanted.version
            } | Sort-Object @{ Expression = { $_.properties.provisioningState -eq 'Succeeded' }; Descending = $true }, id)
            if ($named.Count -and !@($matches | Where-Object id -EQ $targetId).Count) { throw 'Requested image name is already occupied by an incompatible image. Nothing will be overwritten.' }
            if ($named.Count) { $matches = $named }
            if (!$matches.Count) { $import = $true }
        }
        if (!$import) {
            $image = $matches[0]
            Assert-ReadyResource $image $Answers.stamp.customLocationId $Answers.location
            $os = if ($workload.profile -eq 'webServer') { 'Linux' } else { 'Windows' }
            if ($image.properties.osType -ne $os -or $image.properties.hyperVGeneration -ne 'V2') { throw 'Image must have the expected OS type and Hyper-V generation V2.' }
            if ($os -eq 'Linux' -and $image.properties['cloudInitDataSource'] -and $image.properties.cloudInitDataSource -ne 'NoCloud') {
                throw 'Ubuntu custom image declares a data source other than NoCloud.'
            }
            $id = $image.id
        } else { $id = $targetId }
        $plan += @{ workloadName = $workload.name; imageId = $id; import = $import; definition = $wanted }
    }
    $plan
}

function Get-ConfigurationHash {
    param([hashtable]$Answers, [hashtable]$Workload, [string]$ImageId)
    # Explicit, ordered inputs avoid hash churn from JSON property order and exclude credentials.
    $value = [ordered]@{
        profile = $Workload.profile; image = $ImageId.ToLowerInvariant()
        cpu = $Workload.processors; memory = $Workload.memoryMB
        disk = $Workload['dataDiskSizeGB']; ip = $Workload['privateIpAddress']
        network = $Answers.logicalNetworkId.ToLowerInvariant()
        storage = $Answers.storageContainerId.ToLowerInvariant()
        customLocation = $Answers.stamp.customLocationId.ToLowerInvariant()
        username = $Answers.adminUsername; ssh = $Workload['sshPublicKey']
        allowedCidrs = @($Workload.allowedCidrs | Sort-Object)
        shareName = if ($Workload.profile -eq 'fileServer') { $Workload.fileServer.shareName } else { '' }
        sqlEdition = if ($Workload.profile -eq 'sqlServer') { $Workload.sqlServer.edition } else { '' }
        sqlMediaHash = if ($Workload.profile -eq 'sqlServer') { $Workload.sqlServer.installerSha256.ToLowerInvariant() } else { '' }
    }
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Compress)))).ToLowerInvariant()
}

function Assert-OwnedResource {
    param([hashtable]$Resource, [string]$DeploymentName, [string]$ConfigurationHash)
    if ($null -eq $Resource) { return }
    if (!$Resource.ContainsKey('tags') -or $null -eq $Resource.tags -or
        $Resource.tags['project'] -ne 'azure-local-workload-templates' -or
        $Resource.tags['deploymentSet'] -ne $DeploymentName -or
        $Resource.tags['configurationHash'] -ne $ConfigurationHash) {
        throw "Existing resource '$($Resource.name)' is not owned by this configuration. Refusing to modify/adopt it."
    }
}

function Assert-VmMatchesConfiguration {
    param([hashtable]$Vm, [hashtable]$Workload, [string]$ImageId, [string]$ResourceGroupId)
    if ($null -eq $Vm) { return }
    $properties = $Vm.properties
    $expectedNic = "$ResourceGroupId/providers/Microsoft.AzureStackHCI/networkInterfaces/$($Workload.name)-nic"
    $nicIds = @($properties.networkProfile.networkInterfaces | ForEach-Object { $_.id })
    $diskIds = @($properties.storageProfile['dataDisks'] | Where-Object { $null -ne $_ } | ForEach-Object { $_.id })
    $expectedDisks = if ($Workload.profile -eq 'webServer') { @() } else { @("$ResourceGroupId/providers/Microsoft.AzureStackHCI/virtualHardDisks/$($Workload.name)-data") }
    if ($properties.storageProfile.imageReference.id -ne $ImageId -or
        $properties.hardwareProfile.processors -ne $Workload.processors -or
        $properties.hardwareProfile.memoryMB -ne $Workload.memoryMB -or
        $nicIds.Count -ne 1 -or $nicIds[0] -ne $expectedNic -or
        ($diskIds -join '|') -ne ($expectedDisks -join '|')) {
        throw "Existing VM '$($Workload.name)' has image, hardware, NIC or disk drift. Refusing to replace settings or detach customer resources."
    }
}

function Assert-DeploymentPermissions {
    param([string]$Scope, [string[]]$Actions)
    $permissions = @(Get-ArmCollection "$Scope/providers/Microsoft.Authorization/permissions?api-version=2022-04-01")
    foreach ($action in $Actions) {
        $allowed = $false
        foreach ($grant in $permissions) {
            $included = @($grant.actions | Where-Object { $action -like $_ }).Count -gt 0
            $excluded = @($grant.notActions | Where-Object { $action -like $_ }).Count -gt 0
            if ($included -and !$excluded) { $allowed = $true; break }
        }
        if (!$allowed) { throw "Missing effective permission '$action' at deployment scope. No role assignments are changed automatically." }
    }
}

function Invoke-WorkloadPreflight {
    param([hashtable]$Answers)
    foreach ($provider in @('Microsoft.AzureStackHCI', 'Microsoft.HybridCompute', 'Microsoft.ExtendedLocation', 'Microsoft.Insights', 'Microsoft.OperationalInsights', 'Microsoft.EdgeMarketplace')) {
        $registration = Invoke-ArmRequest -Path "/subscriptions/$($Answers.subscriptionId)/providers/${provider}?api-version=2021-04-01"
        if ($registration.registrationState -ne 'Registered') { throw "Register $provider before deploying (no provider registrations are changed automatically)." }
    }
    $rgId = "/subscriptions/$($Answers.subscriptionId)/resourceGroups/$($Answers.resourceGroup)"
    $groupIds = @($rgId, ($Answers.stamp.clusterResourceId -split '/providers/')[0],
        ($Answers.stamp.customLocationId -split '/providers/')[0], ($Answers.logicalNetworkId -split '/providers/')[0],
        ($Answers.storageContainerId -split '/providers/')[0], ($Answers.logAnalyticsWorkspaceId -split '/providers/')[0])
    $groupIds += @($Answers.workloads | Where-Object { $_.image.source -eq 'existing' } | ForEach-Object { ($_.image.resourceId -split '/providers/')[0] })
    foreach ($groupId in @($groupIds | Sort-Object -Unique)) {
        $group = Get-ArmResource $groupId '2022-09-01'
        if (($group.location -replace '\s', '') -ne $Answers.location) { throw 'All selected resource groups must be in the stamp region for this Azure Local deployment.' }
    }
    $actions = @(
        'Microsoft.Resources/deployments/write',
        'Microsoft.HybridCompute/machines/write',
        'Microsoft.HybridCompute/machines/extensions/write',
        'Microsoft.AzureStackHCI/virtualMachineInstances/write',
        'Microsoft.AzureStackHCI/networkInterfaces/write',
        'Microsoft.Insights/dataCollectionRules/write',
        'Microsoft.Insights/dataCollectionRuleAssociations/write'
    )
    if (@($Answers.workloads | Where-Object profile -NE 'webServer').Count) { $actions += 'Microsoft.AzureStackHCI/virtualHardDisks/write' }
    Assert-DeploymentPermissions $rgId $actions
    $cluster = Get-ArmResource $Answers.stamp.clusterResourceId
    Assert-ReadyResource $cluster '' $Answers.location
    if ($cluster.properties.connectivityStatus -ne 'Connected') { throw 'Stamp must report Connected.' }
    $custom = Get-ArmResource $Answers.stamp.customLocationId '2021-08-15'
    Assert-ReadyResource $custom '' $Answers.location
    $network = Get-ArmResource $Answers.logicalNetworkId
    Assert-ReadyResource $network $Answers.stamp.customLocationId $Answers.location
    $storage = Get-ArmResource $Answers.storageContainerId
    Assert-ReadyResource $storage $Answers.stamp.customLocationId $Answers.location
    $workspace = Get-ArmResource $Answers.logAnalyticsWorkspaceId '2022-10-01'
    Assert-ReadyResource $workspace '' $Answers.location
    if ($workspace.properties['publicNetworkAccessForIngestion'] -eq 'Disabled' -or
        @($workspace.properties['privateLinkScopedResources']).Where({ $null -ne $_ }).Count) {
        throw 'Private Link/restricted-ingestion monitoring is unsupported in v1; use a separately designed DCE/AMPLS configuration.'
    }
    if ($Answers.passwordSource.type -eq 'keyVault') {
        $vault = Get-ArmResource $Answers.passwordSource.vaultResourceId '2023-07-01'
        if ($vault.properties['enabledForTemplateDeployment'] -ne $true) { throw 'Key Vault must enable ARM template deployment; deployer needs deploy/action permission.' }
    }
    Assert-NetworkConfiguration $network $Answers.workloads $rgId
    $inventory = @()
    foreach ($type in @('galleryImages', 'marketplaceGalleryImages')) {
        $inventory += @(Get-ArmCollection "/subscriptions/$($Answers.subscriptionId)/providers/Microsoft.AzureStackHCI/${type}?api-version=2024-01-01")
    }
    $plan = @(Get-ImagePlan $Answers $inventory)
    foreach ($imageGroupId in @($plan | ForEach-Object { ($_.imageId -split '/providers/')[0] } | Sort-Object -Unique)) {
        if ($imageGroupId -notin $groupIds) {
            $group = Get-ArmResource $imageGroupId '2022-09-01'
            if (($group.location -replace '\s', '') -ne $Answers.location) { throw 'Reused image resource group must be in the stamp region.' }
        }
    }
    if (@($plan | Where-Object import).Count) {
        Assert-DeploymentPermissions $rgId @('Microsoft.AzureStackHCI/marketplaceGalleryImages/write')
    }
    foreach ($workload in $Answers.workloads) {
        $resolved = $plan | Where-Object workloadName -EQ $workload.name
        $hash = Get-ConfigurationHash $Answers $workload $resolved.imageId
        foreach ($entry in @(
            @("Microsoft.HybridCompute/machines/$($workload.name)", '2024-07-10'),
            @("Microsoft.AzureStackHCI/networkInterfaces/$($workload.name)-nic", '2024-01-01'),
            @("Microsoft.Insights/dataCollectionRules/$($workload.name)-collection", '2023-03-11')
        )) {
            $resource = Get-ArmResource "$rgId/providers/$($entry[0])" $entry[1] -AllowNotFound
            Assert-OwnedResource $resource $Answers.deploymentName $hash
            if ($null -ne $resource -and $entry[0] -like 'Microsoft.HybridCompute/machines/*') {
                $vm = Get-ArmResource "$($resource.id)/providers/Microsoft.AzureStackHCI/virtualMachineInstances/default" -AllowNotFound
                Assert-VmMatchesConfiguration $vm $workload $resolved.imageId $rgId
            }
        }
        if ($workload.profile -ne 'webServer') {
            $disk = Get-ArmResource "$rgId/providers/Microsoft.AzureStackHCI/virtualHardDisks/$($workload.name)-data" -AllowNotFound
            Assert-OwnedResource $disk $Answers.deploymentName $hash
        }
    }
    $plan
}

function Wait-ArmResource {
    param([string]$Id, [string]$ApiVersion, [int]$TimeoutSeconds = 7200, [int]$PollSeconds = 15)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        $resource = Get-ArmResource $Id $ApiVersion
        $state = $resource.properties.provisioningState
        if ($state -eq 'Succeeded') { return $resource }
        if ($state -in @('Failed', 'Canceled', 'Cancelled', 'Deleting')) {
            throw "Resource '$($resource.name)' reached $state. Inspect its Azure operation details; existing resources were preserved."
        }
        if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'Timed out waiting for Azure. The operation may still be running; inspect it before retrying. No resources were deleted.' }
        Start-Sleep -Seconds $PollSeconds
    } while ($true)
}

function Import-MissingImages {
    param([hashtable]$Answers, [array]$Plan, [int]$TimeoutSeconds)
    foreach ($item in @($Plan | Where-Object import | Sort-Object imageId -Unique)) {
        # Re-read immediately before creation: never replace an image created since preflight.
        $existing = Get-ArmResource $item.imageId -AllowNotFound
        if ($null -ne $existing) { throw 'Image appeared after preflight. Rerun preflight; it was not overwritten.' }
        $body = @{
            location = $Answers.location
            extendedLocation = @{ type = 'CustomLocation'; name = $Answers.stamp.customLocationId }
            properties = @{
                containerId = $Answers.storageContainerId
                osType = 'Windows'; hyperVGeneration = 'V2'
                identifier = @{ publisher = $item.definition.publisher; offer = $item.definition.offer; sku = $item.definition.sku }
                version = @{ name = $item.definition.version }
            }
        }
        $null = Invoke-ArmRequest -Method PUT -Path "$($item.imageId)?api-version=2024-01-01" -Body $body -CreateOnly
        $image = Wait-ArmResource $item.imageId '2024-01-01' $TimeoutSeconds
        Assert-ReadyResource $image $Answers.stamp.customLocationId $Answers.location
        if ($image.properties.osType -ne 'Windows' -or $image.properties.hyperVGeneration -ne 'V2' -or
            $image.properties.version.name -ne $item.definition.version -or
            $image.properties.identifier.publisher -ne $item.definition.publisher -or
            $image.properties.identifier.offer -ne $item.definition.offer -or
            $image.properties.identifier.sku -ne $item.definition.sku) {
            throw 'Imported image metadata does not match the requested pinned image. VM deployment was not started.'
        }
    }
}

function Get-GuestSettings {
    param([hashtable]$Answers, [hashtable]$Workload)
    $config = @{ profile = $Workload.profile; adminUsername = $Answers.adminUsername; allowedCidrs = $Workload.allowedCidrs }
    if ($Workload.profile -eq 'webServer') {
        $scriptText = Get-Content -LiteralPath (Join-Path $script:Root 'guest\configure-nginx.sh') -Raw
        $cidrs = $Workload.allowedCidrs -join ' '
        $scriptText = $scriptText.Replace('__ALLOWED_CIDRS__', $cidrs)
        return @{ script = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($scriptText -replace "`r`n", "`n"))) }
    }
    $config.dataDiskSizeGB = $Workload.dataDiskSizeGB
    $config[$Workload.profile] = $Workload[$Workload.profile]
    $encodedConfig = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($config | ConvertTo-Json -Depth 10 -Compress)))
    $artifact = Get-WindowsGuestArtifact
    $bootstrap = "`$ErrorActionPreference='Stop';if((Get-FileHash -LiteralPath '.\Configure-Windows.ps1' -Algorithm SHA256).Hash -ne '$($artifact.sha256)'){throw 'Guest script checksum mismatch'};& '.\Configure-Windows.ps1' -ConfigurationBase64 '$encodedConfig'"
    $command = "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$bootstrap`""
    if ($command.Length -gt 8100) { throw 'Windows guest payload exceeds safe command-line length (8100 characters). Shorten configuration or use a reviewed file-hosting delivery method.' }
    @{ fileUris = @($artifact.uri); commandToExecute = $command }
}

function Invoke-SourceGit {
    param([string[]]$Arguments)
    $output = & git -C $script:Root @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Windows script delivery requires a clean committed Git checkout with a public GitHub origin. Commit and push reviewed guest scripts before deployment.' }
    ($output -join "`n").Trim()
}

function Get-WindowsGuestArtifact {
    $commit = Invoke-SourceGit @('rev-parse', 'HEAD')
    $origin = Invoke-SourceGit @('remote', 'get-url', 'origin')
    if ($commit -notmatch '^[0-9a-f]{40}$' -or
        $origin -notmatch '^(https://github\.com/|git@github\.com:)([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+?)(\.git)?$') {
        throw 'Windows script delivery supports public GitHub origins only, pinned to a full commit SHA.'
    }
    $repository = $Matches[2]
    $blob = Invoke-SourceGit @('rev-parse', "${commit}:guest/Configure-Windows.ps1")
    $localBlob = Invoke-SourceGit @('hash-object', '--path=guest/Configure-Windows.ps1', (Join-Path $script:Root 'guest\Configure-Windows.ps1'))
    if ($blob -ne $localBlob) { throw 'Windows guest script has uncommitted changes. Review, commit and push it before deploying.' }
    $bytes = [IO.File]::ReadAllBytes((Join-Path $script:Root 'guest\Configure-Windows.ps1'))
    $normalized = [Text.Encoding]::UTF8.GetBytes(([Text.Encoding]::UTF8.GetString($bytes) -replace "`r`n", "`n"))
    @{
        uri = "https://raw.githubusercontent.com/$repository/$commit/guest/Configure-Windows.ps1"
        sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($normalized)).ToLowerInvariant()
    }
}

function Assert-PublicGuestArtifact {
    param([hashtable]$Artifact)
    # Never use the ARM client here: its default headers contain an access token.
    $client = [Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    try {
        $response = $client.GetAsync($Artifact.uri).GetAwaiter().GetResult()
        if (!$response.IsSuccessStatusCode) { throw 'Pinned public Windows script cannot be downloaded. Push this commit to the public GitHub origin before deploying.' }
        $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        if ($hash -ne $Artifact.sha256) { throw 'Hosted Windows script does not match the reviewed local committed content.' }
    } finally {
        $client.Dispose()
        if ($null -ne (Get-Variable response -ValueOnly -ErrorAction Ignore)) { $response.Dispose() }
    }
}

function Get-PasswordParameter {
    param([hashtable]$Answers)
    if (!@($Answers.workloads | Where-Object profile -NE 'webServer').Count) { return @{ value = '' } }
    $source = $Answers.passwordSource
    if ($source.type -eq 'keyVault') {
        return @{ reference = @{ keyVault = @{ id = $source.vaultResourceId }; secretName = $source.secretName; secretVersion = $source.secretVersion } }
    }
    $password = ''
    if ($source.type -eq 'environment') {
        $password = [Environment]::GetEnvironmentVariable($source.name, 'Process')
        if (!$password) { throw 'Password environment variable is empty or missing.' }
    } else {
        $secure = Read-Host 'VM administrator password' -AsSecureString
        $password = [Net.NetworkCredential]::new('', $secure).Password
        $secure.Dispose()
    }
    if ($password.Length -lt 14 -or $password.Length -gt 123 -or $password -match '[\r\n]' -or
        $password -notmatch '[a-z]' -or $password -notmatch '[A-Z]' -or $password -notmatch '[0-9]' -or $password -notmatch '[^a-zA-Z0-9]' -or
        $password.IndexOf($Answers.adminUsername, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw 'Password must be 14-123 characters, contain upper/lowercase, digit and symbol, and not contain the username or newlines.'
    }
    @{ value = $password }
}

function Get-CompiledTemplate {
    $compiler = Get-Command bicep -ErrorAction Ignore
    $installedPath = Join-Path $HOME $(if ($IsWindows) { '.azure\bin\bicep.exe' } else { '.azure/bin/bicep' })
    if ($compiler) {
        $output = & $compiler.Source build (Join-Path $script:Root 'infra\main.bicep') --stdout
    } elseif (Test-Path -LiteralPath $installedPath) {
        $output = & $installedPath build (Join-Path $script:Root 'infra\main.bicep') --stdout
    } else {
        $output = & az bicep build --file (Join-Path $script:Root 'infra\main.bicep') --stdout --only-show-errors
    }
    if ($LASTEXITCODE -ne 0) { throw "Bicep compilation failed: $($output -join "`n")" }
    ($output -join "`n") | ConvertFrom-Json -AsHashtable
}

function Start-WorkloadDeployment {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$AnswerFile,
        [ValidateSet('Validate', 'Preflight', 'Deploy')][string]$Mode = 'Validate',
        [ValidateRange(60, 21600)][int]$TimeoutSeconds = 10800
    )
    $answers = Read-WorkloadAnswers $AnswerFile
    if ($Mode -eq 'Validate') { Write-Output 'Answer file is valid. Offline only; Azure resources, capacity, RBAC and guest readiness have not been checked.'; return }
    try {
        Open-ArmConnection $answers.subscriptionId
        $plan = @(Invoke-WorkloadPreflight $answers)
        $plan | ForEach-Object { Write-Output "$($_.workloadName): $(if ($_.import) { 'import missing Windows Marketplace image' } else { 'reuse existing image' })" }
        if ($Mode -eq 'Preflight' -or !$PSCmdlet.ShouldProcess($answers.resourceGroup, 'Import missing images and deploy Arc-enabled workloads and billable monitoring')) { return }
        $template = Get-CompiledTemplate
        if (@($answers.workloads | Where-Object profile -NE 'webServer').Count) {
            Assert-PublicGuestArtifact (Get-WindowsGuestArtifact)
        }
        $resolved = @()
        foreach ($workload in $answers.workloads) {
            $image = $plan | Where-Object workloadName -EQ $workload.name
            $resolved += @{
                name = $workload.name; profile = $workload.profile
                processors = $workload.processors; memoryMB = $workload.memoryMB
                dataDiskSizeGB = $workload['dataDiskSizeGB']
                privateIpAddress = if ($workload.ContainsKey('privateIpAddress')) { $workload.privateIpAddress } else { '' }
                sshPublicKey = if ($workload.ContainsKey('sshPublicKey')) { $workload.sshPublicKey } else { '' }
                imageId = $image.imageId
                configurationHash = Get-ConfigurationHash $answers $workload $image.imageId
                guestSettings = Get-GuestSettings $answers $workload
            }
        }
        $parameters = @{
            location = @{ value = $answers.location }
            customLocationId = @{ value = $answers.stamp.customLocationId }
            logicalNetworkId = @{ value = $answers.logicalNetworkId }
            storageContainerId = @{ value = $answers.storageContainerId }
            workspaceId = @{ value = $answers.logAnalyticsWorkspaceId }
            adminUsername = @{ value = $answers.adminUsername }
            adminPassword = Get-PasswordParameter $answers
            workloads = @{ value = $resolved }
            deploymentSet = @{ value = $answers.deploymentName }
            runId = @{ value = [guid]::NewGuid().ToString() }
        }
        Import-MissingImages $answers $plan $TimeoutSeconds
        $deploymentId = "/subscriptions/$($answers.subscriptionId)/resourceGroups/$($answers.resourceGroup)/providers/Microsoft.Resources/deployments/$($answers.deploymentName)"
        $body = @{ properties = @{ mode = 'Incremental'; template = $template; parameters = $parameters } }
        $null = Invoke-ArmRequest -Method PUT -Path "${deploymentId}?api-version=2022-09-01" -Body $body
        $null = Wait-ArmResource $deploymentId '2022-09-01' $TimeoutSeconds
        Write-Output "Deployment succeeded: $($answers.deploymentName). Guest scripts and AMA/DCR provisioning completed; verify remote client access and workspace ingestion separately."
    } finally {
        $parameters = $null
        $body = $null
        Close-ArmConnection
    }
}

Export-ModuleMember -Function Start-WorkloadDeployment, Read-WorkloadAnswers

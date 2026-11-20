#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Arm = 'https://management.azure.com'
$script:Client = $null
$script:TokenExpires = [DateTimeOffset]::MinValue
$script:Subscription = ''
$script:Authentication = 'AzureCli'
$script:AzContext = $null

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
    $answers.workloads = @(Expand-Workloads $answers.workloads $answers['namingPrefix'])
    $answers
}

function Test-LinuxProfile {
    param([hashtable]$Workload)
    $Workload.profile -in @('webServer', 'linuxApp')
}

function Get-WorkloadDisks {
    param([hashtable]$Workload)
    if ($Workload.ContainsKey('dataDiskSizeGB')) {
        @{ role = 'data'; sizeGB = $Workload.dataDiskSizeGB }
    } elseif ($Workload.ContainsKey('dataDisks')) {
        $Workload.dataDisks | Sort-Object role
    }
}

function Expand-Workloads {
    param([array]$Workloads, [string]$NamingPrefix = '')
    $instances = @()
    $names = @{}
    $ips = @{}
    foreach ($entry in $Workloads) {
        $count = if ($entry.ContainsKey('count')) { $entry.count } else { 1 }
        if ($entry.ContainsKey('count') -and $entry.name.Length -gt 12) { throw 'Counted workload names must be at most 12 characters, leaving room for -01 through -20.' }
        if ($entry.ContainsKey('privateIpAddresses')) {
            if (!$entry.ContainsKey('count') -or $entry.ContainsKey('privateIpAddress') -or $entry.privateIpAddresses.Count -ne $count) {
                throw 'privateIpAddresses requires count, exactly one address per instance, and no privateIpAddress.'
            }
        }
        if ($entry.ContainsKey('count') -and $entry.ContainsKey('privateIpAddress')) {
            throw 'Counted workloads require privateIpAddresses instead of privateIpAddress; no addresses are auto-incremented.'
        }
        for ($i = 0; $i -lt $count; $i++) {
            $item = $entry.Clone()
            $item.Remove('count')
            $item.Remove('privateIpAddresses')
            if ($entry.ContainsKey('count')) { $item.name = '{0}-{1:00}' -f $entry.name, ($i + 1) }
            if ($NamingPrefix) { $item.name = "$NamingPrefix-$($item.name)" }
            if ($item.name.Length -gt 15) { throw 'Final VM names including prefix, separators and instance suffix must be at most 15 characters.' }
            if ($names.ContainsKey($item.name)) { throw 'Expanded VM names must be unique; a counted name collides with another entry.' }
            $names[$item.name] = $true
            if ($entry.ContainsKey('privateIpAddresses')) { $item.privateIpAddress = $entry.privateIpAddresses[$i] }
            if ($item.ContainsKey('privateIpAddress')) {
                $null = ConvertTo-IPv4Number $item.privateIpAddress
                if ($ips.ContainsKey($item.privateIpAddress)) { throw 'Static IP addresses must be unique across all instances.' }
                $ips[$item.privateIpAddress] = $true
            }
            $instances += $item
            if ($instances.Count -gt 100) { throw 'A deployment may contain at most 100 VMs in total.' }
        }
    }
    $instances
}

function Get-WorkloadSummary {
    param([array]$Workloads)
    $summary = [ordered]@{ vmCount = $Workloads.Count; processors = 0; memoryMB = 0; dataDiskCount = 0; dataDiskGB = 0; suggestedOsDiskGB = 0; unspecifiedOsDiskCount = 0 }
    foreach ($item in $Workloads) {
        $summary.processors += $item.processors
        $summary.memoryMB += $item.memoryMB
        $disks = @(Get-WorkloadDisks $item)
        $summary.dataDiskCount += $disks.Count
        foreach ($disk in $disks) { $summary.dataDiskGB += $disk.sizeGB }
        if ($item.ContainsKey('suggestedOsDiskSizeGB')) { $summary.suggestedOsDiskGB += $item.suggestedOsDiskSizeGB }
        else { $summary.unspecifiedOsDiskCount++ }
    }
    $summary
}

function Assert-PreparedImageSource {
    param([hashtable]$Image)
    if ($Image.name -match 'windows' -or $Image.sha256 -match '^0{64}$') {
        throw 'Prepared image imports require a nonplaceholder verified SHA256 and an image name without the reserved keyword Windows.'
    }
    if ($Image.source -eq 'local') {
        # Deliberately do not Test-Path on the client: the path belongs to the stamp.
        if ($Image.path -notmatch '^[a-zA-Z]:\\ClusterStorage\\[^\\]+\\.+\.vhdx$' -or
            $Image.path -match '[\x00-\x1f"*?<>|]' -or $Image.path.Substring(2).Contains(':') -or
            @($Image.path.Split('\') | Where-Object { $_ -in @('.', '..') -or $_ -match '[. ]$' }).Count) {
            throw 'Local images require an absolute stamp CSV path such as C:\ClusterStorage\Volume1\Images\ubuntu.vhdx, not a client file, relative path or arbitrary UNC share.'
        }
    } else {
        $uri = $null
        if (![uri]::TryCreate($Image.uri, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or !$uri.IsDefaultPort -or
            $uri.Host -notmatch '^[a-z0-9]{3,24}\.blob\.core\.windows\.net$' -or
            $uri.AbsolutePath -notmatch '^/[^/]+/.+\.vhdx?$' -or $Image.uri -match '[\s\\]' -or
            $Image.uri -match '%(0[0-9a-f]|1[0-9a-f]|7f)') {
            throw 'Blob image URI must be a noncredentialed Azure public-cloud blob HTTPS VHD/VHDX URL without query/fragment; inject the SAS through the named process environment variable.'
        }
    }
}

function Assert-Answers {
    param([hashtable]$Answers)
    foreach ($key in $(if ($Answers['tags']) { @($Answers.tags.Keys) } else { @() })) {
        if ($key -in @('project', 'deploymentSet', 'configurationHash')) { throw 'Ownership tags are reserved and cannot be supplied in answers.' }
        if ($key -eq 'Date Built' -and $Answers.tags[$key] -cne 'auto') { throw 'Date Built must be auto; actual creation dates are preserved by the launcher.' }
    }
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
        if ($workload.ContainsKey('count') -and $workload.count -eq 0) { continue }
        foreach ($cidr in $workload.allowedCidrs) { $null = Get-CidrRange $cidr }
        if ($workload.ContainsKey('privateIpAddress')) {
            $null = ConvertTo-IPv4Number $workload.privateIpAddress
            if ($ips.ContainsKey($workload.privateIpAddress)) { throw 'Static IP addresses must be unique.' }
            $ips[$workload.privateIpAddress] = $true
        }
        $roles = @{}
        foreach ($disk in @(Get-WorkloadDisks $workload)) {
            if ($roles.ContainsKey($disk.role)) { throw 'Data disk roles must be unique per VM.' }
            $roles[$disk.role] = $true
        }
        if (Test-LinuxProfile $workload) { Assert-RsaPublicKey $workload.sshPublicKey }
        $image = $workload.image
        if ($image.source -eq 'existing') {
            Assert-ResourceId $image.resourceId 'Microsoft\.AzureStackHCI/(galleryImages|marketplaceGalleryImages)' $sub
            if ((Test-LinuxProfile $workload) -and $image.resourceId -notmatch '/galleryImages/') {
                throw 'Ubuntu requires a prepared NoCloud custom gallery image, not a direct Marketplace import.'
            }
        } elseif ($image.source -eq 'marketplace') {
            $definition = "$($image.publisher):$($image.offer):$($image.sku):$($image.version)"
            if ($imageDefinitions.ContainsKey($image.name) -and $imageDefinitions[$image.name] -ne $definition) {
                throw 'The same Marketplace image name cannot refer to different versions.'
            }
            $imageDefinitions[$image.name] = $definition
        } else {
            Assert-PreparedImageSource $image
            $definition = "$($image.source):$($image['path']):$($image['uri']):$($image.sha256):$($image.os)"
            if ($imageDefinitions.ContainsKey($image.name) -and $imageDefinitions[$image.name] -ne $definition) {
                throw 'The same prepared image name cannot refer to different source definitions.'
            }
            $imageDefinitions[$image.name] = $definition
        }
        if ($workload.profile -eq 'sqlServer') {
            if ($workload.sqlServer.ContainsKey('productKeySource')) {
                $source = $workload.sqlServer.productKeySource
                Assert-ResourceId $source.vaultResourceId 'Microsoft\.KeyVault/vaults' $sub
                if ($source.vaultResourceId.Split('/')[-1] -notmatch '^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$') {
                    throw 'SQL product key requires a valid Azure public-cloud Key Vault name.'
                }
            }
            if ($workload.sqlServer['installationMode'] -ne 'marketplace') {
                $uri = [uri]$workload.sqlServer.installerUrl
                if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
                    $uri.Host -match '(^|\.)example\.(org|com|net)$' -or
                    $workload.sqlServer.installerSha256 -match '^0{64}$') {
                    throw 'SQL requires a real HTTPS full-media ISO URL without credentials/query/fragment and its verified SHA256, not the example placeholders.'
                }
            }
        }
    }
    $null = @(Expand-Workloads $Answers.workloads $Answers['namingPrefix'])
}

function Open-ArmConnection {
    param([string]$SubscriptionId, [ValidateSet('AzureCli', 'AzPowerShell')][string]$Authentication = 'AzureCli')
    $script:Authentication = $Authentication
    if ($Authentication -eq 'AzPowerShell') {
        Import-Module Az.Accounts -MinimumVersion 5.0 -ErrorAction Stop
        $current = Get-AzContext
        $contexts = @(Get-AzContext -ListAvailable | Where-Object { $_.Subscription.Id -eq $SubscriptionId })
        $identities = @($contexts | Group-Object { "$($_.Environment.Name)|$($_.Tenant.Id)|$($_.Account.Id)" })
        if ($current -and $current.Subscription.Id -eq $SubscriptionId -and $current.Environment.Name -eq 'AzureCloud') {
            $script:AzContext = $current
        } elseif ($identities.Count -eq 1 -and $contexts[0].Environment.Name -eq 'AzureCloud') {
            $script:AzContext = $contexts[0]
        } else {
            throw 'AzPowerShell requires an unambiguous existing AzureCloud context for the requested subscription. Sign in explicitly; no global context is changed.'
        }
    } else {
        $account = Invoke-AzJson @('account', 'show', '--subscription', $SubscriptionId)
        if ($account.environmentName -ne 'AzureCloud' -or $account.state -ne 'Enabled') {
            throw 'Version 1 supports enabled Azure public-cloud subscriptions only.'
        }
    }
    $script:Subscription = $SubscriptionId
    $script:Client = [Net.Http.HttpClient]::new()
    $script:Client.Timeout = [TimeSpan]::FromSeconds(120)
    $script:TokenExpires = [DateTimeOffset]::MinValue
}

function Close-ArmConnection {
    if ($null -ne $script:Client) { $script:Client.Dispose(); $script:Client = $null }
    $script:TokenExpires = [DateTimeOffset]::MinValue
    $script:AzContext = $null
    $script:Authentication = 'AzureCli'
}

function Get-ArmToken {
    if ($script:Authentication -eq 'AzureCli') {
        return Invoke-AzJson @('account', 'get-access-token', '--subscription', $script:Subscription, '--resource', "$script:Arm/")
    }
    $result = $null
    try {
        $result = Get-AzAccessToken -ResourceUrl "$script:Arm/" -TenantId $script:AzContext.Tenant.Id -DefaultProfile $script:AzContext -ErrorAction Stop
        if ($result.Token -isnot [Security.SecureString] -or !$result.Token.Length) { throw 'Expected a protected ARM token.' }
        @{
            accessToken = [Net.NetworkCredential]::new('', $result.Token).Password
            expires_on = $result.ExpiresOn.ToUnixTimeSeconds()
        }
    } catch { throw 'AzPowerShell ARM token acquisition failed. Reauthenticate the requested subscription context; no alternate account or authentication mode was selected.' }
    finally { if ($result -and $result.Token -is [Security.SecureString]) { $result.Token.Dispose() } }
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
        $token = Get-ArmToken
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
        } elseif ($wanted.source -eq 'marketplace') {
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
        } else {
            $targetId = "$rgId/providers/Microsoft.AzureStackHCI/galleryImages/$($wanted.name)"
            $named = @($Inventory | Where-Object { $_.id -eq $targetId })
            $matches = @($Inventory | Where-Object {
                $_.type -eq 'Microsoft.AzureStackHCI/galleryImages' -and
                $_.extendedLocation.name -eq $Answers.stamp.customLocationId -and
                $_.properties.osType -eq 'Linux' -and $_.properties.hyperVGeneration -eq 'V2' -and
                $_.properties['cloudInitDataSource'] -eq 'NoCloud' -and
                $_['tags'] -and $_.tags['preparedImageSha256'] -eq $wanted.sha256
            } | Sort-Object @{ Expression = { $_.properties.provisioningState -eq 'Succeeded' }; Descending = $true }, id)
            if ($named.Count -and !@($matches | Where-Object id -EQ $targetId).Count) { throw 'Requested prepared image name is occupied by an incompatible or unverified image. Use its explicit existing resource ID after verification, or a new name.' }
            if ($named.Count) { $matches = $named }
            if (!$matches.Count) { $import = $true }
        }
        if (!$import) {
            $image = $matches[0]
            Assert-ReadyResource $image $Answers.stamp.customLocationId $Answers.location
            $os = if (Test-LinuxProfile $workload) { 'Linux' } else { 'Windows' }
            if ($image.properties.osType -ne $os -or $image.properties.hyperVGeneration -ne 'V2') { throw 'Image must have the expected OS type and Hyper-V generation V2.' }
            if ($os -eq 'Linux' -and $image.properties['cloudInitDataSource'] -and $image.properties.cloudInitDataSource -ne 'NoCloud') {
                throw 'Ubuntu custom image declares a data source other than NoCloud.'
            }
            $identifier = $image.properties['identifier']
            $preinstalledSql = $workload.profile -eq 'sqlServer' -and $workload.sqlServer['installationMode'] -eq 'marketplace'
            if ($preinstalledSql -and (!$identifier -or $identifier.publisher -ne 'microsoftsqlserver' -or
                $identifier.offer -ne 'sql2022-ws2022' -or $identifier.sku -ne 'enterprise-gen2')) {
                throw 'Marketplace SQL verification requires the exact microsoftsqlserver/sql2022-ws2022/enterprise-gen2 image; an OS-only image is not sufficient.'
            }
            if ($identifier -and $identifier.publisher -eq 'microsoftsqlserver' -and !$preinstalledSql) {
                throw 'A preinstalled SQL image requires the explicitly licensed SQL marketplace installationMode; it cannot be used as an OS-only image or reinstalled through the ISO path.'
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
        sqlMediaHash = if ($Workload.profile -eq 'sqlServer' -and $Workload.sqlServer['installerSha256']) { $Workload.sqlServer.installerSha256.ToLowerInvariant() } else { '' }
    }
    if ($Workload.profile -eq 'sqlServer' -and $Workload.sqlServer['installationMode'] -eq 'marketplace') {
        $value.sqlInstallationMode = 'marketplace'
    }
    if ($Workload.ContainsKey('dataDisks')) {
        $value.dataDisks = @(Get-WorkloadDisks $Workload | ForEach-Object { [ordered]@{ role = $_.role; sizeGB = $_.sizeGB } })
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

function Get-WorkloadTags {
    param([hashtable]$Answers, [hashtable]$ExistingMachine)
    $tags = @{}
    if ($ExistingMachine -and $ExistingMachine['tags']) {
        foreach ($key in $ExistingMachine.tags.Keys) { $tags[$key] = $ExistingMachine.tags[$key] }
    }
    if ($Answers['tags']) {
        foreach ($key in $Answers.tags.Keys) { $tags[$key] = $Answers.tags[$key] }
    }
    $built = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
    if ($ExistingMachine) {
        if ($ExistingMachine['tags'] -and $ExistingMachine.tags['Date Built']) {
            $built = $ExistingMachine.tags['Date Built']
        } elseif ($ExistingMachine['systemData'] -and $ExistingMachine.systemData['createdAt']) {
            $built = ([DateTimeOffset]::Parse($ExistingMachine.systemData.createdAt)).UtcDateTime.ToString('yyyy-MM-dd')
        } else {
            throw 'Existing workload has no verifiable creation date. Refusing to relabel it as newly built.'
        }
    }
    $date = [DateTime]::MinValue
    if (![DateTime]::TryParseExact($built, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$date)) { throw 'Existing Date Built tag must be an ISO calendar date.' }
    $tags['Date Built'] = $built
    if (@($tags.Keys | Where-Object { $_ -notin @('project', 'deploymentSet', 'configurationHash') }).Count -gt 47) {
        throw 'Merged workload metadata exceeds the Azure 50-tag limit including ownership tags.'
    }
    $tags
}

function Assert-VmMatchesConfiguration {
    param([hashtable]$Vm, [hashtable]$Workload, [string]$ImageId, [string]$ResourceGroupId)
    if ($null -eq $Vm) { return }
    $properties = $Vm.properties
    $expectedNic = "$ResourceGroupId/providers/Microsoft.AzureStackHCI/networkInterfaces/$($Workload.name)-nic"
    $nicIds = @($properties.networkProfile.networkInterfaces | ForEach-Object { $_.id })
    $diskIds = @($properties.storageProfile['dataDisks'] | Where-Object { $null -ne $_ } | ForEach-Object { $_.id })
    $expectedDisks = @(Get-WorkloadDisks $Workload | ForEach-Object { "$ResourceGroupId/providers/Microsoft.AzureStackHCI/virtualHardDisks/$($Workload.name)-$($_.role)" })
    if ($properties.storageProfile.imageReference.id -ne $ImageId -or
        $properties.hardwareProfile.processors -ne $Workload.processors -or
        $properties.hardwareProfile.memoryMB -ne $Workload.memoryMB -or
        $nicIds.Count -ne 1 -or $nicIds[0] -ne $expectedNic -or
        (@($diskIds | Sort-Object) -join '|') -ne (@($expectedDisks | Sort-Object) -join '|')) {
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
        ($Answers.storageContainerId -split '/providers/')[0])
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
    if (@($Answers.workloads | ForEach-Object { Get-WorkloadDisks $_ }).Count) { $actions += 'Microsoft.AzureStackHCI/virtualHardDisks/write' }
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
    Assert-ReadyResource $workspace
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
    foreach ($workload in @($Answers.workloads | Where-Object { $_.image.source -eq 'marketplace' -and $_.image.publisher -eq 'microsoftsqlserver' })) {
        Assert-SqlMarketplaceCatalog $Answers $workload.image
    }
    foreach ($imageGroupId in @($plan | ForEach-Object { ($_.imageId -split '/providers/')[0] } | Sort-Object -Unique)) {
        if ($imageGroupId -notin $groupIds) {
            $group = Get-ArmResource $imageGroupId '2022-09-01'
            if (($group.location -replace '\s', '') -ne $Answers.location) { throw 'Reused image resource group must be in the stamp region.' }
        }
    }
    foreach ($imageType in @($plan | Where-Object import | ForEach-Object { ($_.imageId -split '/')[-2] } | Sort-Object -Unique)) {
        Assert-DeploymentPermissions $rgId @("Microsoft.AzureStackHCI/$imageType/write")
    }
    foreach ($workload in $Answers.workloads) {
        $resolved = $plan | Where-Object workloadName -EQ $workload.name
        $hash = Get-ConfigurationHash $Answers $workload $resolved.imageId
        $existingMachine = $null
        foreach ($entry in @(
            @("Microsoft.HybridCompute/machines/$($workload.name)", '2024-07-10'),
            @("Microsoft.AzureStackHCI/networkInterfaces/$($workload.name)-nic", '2024-01-01'),
            @("Microsoft.Insights/dataCollectionRules/$($workload.name)-collection", '2023-03-11')
        )) {
            $resource = Get-ArmResource "$rgId/providers/$($entry[0])" $entry[1] -AllowNotFound
            Assert-OwnedResource $resource $Answers.deploymentName $hash
            if ($null -ne $resource -and $entry[0] -like 'Microsoft.HybridCompute/machines/*') {
                $existingMachine = $resource
                $vm = Get-ArmResource "$($resource.id)/providers/Microsoft.AzureStackHCI/virtualMachineInstances/default" -AllowNotFound
                Assert-VmMatchesConfiguration $vm $workload $resolved.imageId $rgId
            }
        }
        foreach ($diskDefinition in @(Get-WorkloadDisks $workload)) {
            $disk = Get-ArmResource "$rgId/providers/Microsoft.AzureStackHCI/virtualHardDisks/$($workload.name)-$($diskDefinition.role)" -AllowNotFound
            Assert-OwnedResource $disk $Answers.deploymentName $hash
            if ($null -ne $disk -and ($disk.properties.diskSizeGB -ne $diskDefinition.sizeGB -or $disk.properties.containerId -ne $Answers.storageContainerId)) {
                throw 'Existing data disk has size or storage-path drift. No disk resizing or replacement is performed.'
            }
        }
        $resolved.tags = Get-WorkloadTags $Answers $existingMachine
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
        $isMarketplace = $item.definition.source -eq 'marketplace'
        $body = @{
            location = $Answers.location
            extendedLocation = @{ type = 'CustomLocation'; name = $Answers.stamp.customLocationId }
            properties = @{
                containerId = $Answers.storageContainerId
                osType = if ($isMarketplace) { 'Windows' } else { 'Linux' }
                hyperVGeneration = 'V2'
            }
        }
        if ($isMarketplace) {
            $body.properties.identifier = @{ publisher = $item.definition.publisher; offer = $item.definition.offer; sku = $item.definition.sku }
            $body.properties.version = @{ name = $item.definition.version }
        } else {
            $body.properties.cloudInitDataSource = 'NoCloud'
            $body.properties.imagePath = Get-PreparedImagePath $item.definition
            $body.tags = @{ preparedImageSha256 = $item.definition.sha256.ToLowerInvariant() }
        }
        try {
            $null = Invoke-ArmRequest -Method PUT -Path "$($item.imageId)?api-version=2024-01-01" -Body $body -CreateOnly
            $image = Wait-ArmResource $item.imageId '2024-01-01' $TimeoutSeconds
            Assert-ReadyResource $image $Answers.stamp.customLocationId $Answers.location
            if ($image.properties.osType -ne $body.properties.osType -or $image.properties.hyperVGeneration -ne 'V2') {
                throw 'Imported image metadata does not match the requested OS/generation. VM deployment was not started.'
            }
            if ($isMarketplace) {
                if ($image.properties.version.name -ne $item.definition.version -or
                    $image.properties.identifier.publisher -ne $item.definition.publisher -or
                    $image.properties.identifier.offer -ne $item.definition.offer -or
                    $image.properties.identifier.sku -ne $item.definition.sku) {
                    throw 'Imported image metadata does not match the requested pinned image. VM deployment was not started.'
                }
            } elseif ($image.properties['cloudInitDataSource'] -ne 'NoCloud' -or
                !$image['tags'] -or $image.tags['preparedImageSha256'] -ne $item.definition.sha256) {
                throw 'Imported prepared image is missing its NoCloud setting or source digest. VM deployment was not started.'
            }
        } finally {
            $body = $null
        }
    }
}

function Assert-SqlMarketplaceCatalog {
    param([hashtable]$Answers, [hashtable]$Image)
    $offer = Invoke-ArmRequest -Path "$($Answers.stamp.clusterResourceId)/providers/Microsoft.EdgeMarketplace/offers/microsoftsqlserver:sql2022-ws2022?api-version=2023-08-01"
    $sku = @($offer.properties.marketplaceSkus | Where-Object marketplaceSkuId -EQ 'enterprise-gen2')
    if ($offer.properties.offerContent.offerId -ne 'sql2022-ws2022' -or
        $offer.properties.offerContent.offerPublisher.publisherId -ne 'microsoftsqlserver' -or
        $sku.Count -ne 1 -or $sku[0].generation -ne '2' -or $sku[0].operatingSystem.family -ne 'Windows' -or
        !@($sku[0].marketplaceSkuVersions | Where-Object name -EQ $Image.version).Count) {
        throw 'The exact pinned SQL Marketplace Windows/V2 image version is not available in this stamp catalog.'
    }
    if ($offer.properties.offerContent.termsAndConditions.legalTermsType -ne 'None') {
        throw 'SQL Marketplace offer requires a separately reviewed terms/purchase flow. No agreement or purchase was accepted.'
    }
    if ($offer.properties.offerContent.releaseType -eq 'Preview') {
        Write-Warning 'The stamp catalog labels this SQL Marketplace offer Preview. Catalog availability and legalTermsType None do not establish license entitlement or production certification.'
    }
}

function Get-PreparedImagePath {
    param([hashtable]$Image)
    if ($Image.source -eq 'local') { return $Image.path }
    $token = [Environment]::GetEnvironmentVariable($Image.sasTokenEnvironmentVariable, 'Process')
    if (!$token) { throw 'Prepared image SAS environment variable is empty or missing. No image was imported.' }
    try {
        $token = $token.TrimStart('?')
        $fields = @{}
        foreach ($part in $token.Split('&')) {
            $pair = $part.Split('=', 2)
            if ($pair.Count -ne 2 -or $fields.ContainsKey($pair[0]) -or $pair[1] -match '[\s#]') { throw 'Invalid SAS.' }
            $fields[$pair[0]] = [uri]::UnescapeDataString($pair[1])
        }
        $expires = [DateTimeOffset]::MinValue
        if (!$fields['sig'] -or $fields['sr'] -ne 'b' -or $fields['spr'] -ne 'https' -or
            $fields['sp'] -notmatch '^r(l)?$' -or
            ![DateTimeOffset]::TryParse($fields['se'], [ref]$expires) -or $expires -le [DateTimeOffset]::UtcNow) {
            throw 'Invalid SAS.'
        }
        "$($Image.uri)?$token"
    } catch { throw 'Prepared image SAS must be an unexpired HTTPS-only, blob-scoped, read-only token; its value is not logged.' }
    finally { $token = $null; $fields = $null }
}

function Get-GuestSettings {
    param([hashtable]$Answers, [hashtable]$Workload)
    if ($Workload.profile -eq 'windowsApp') { return @{} }
    $config = @{ profile = $Workload.profile; adminUsername = $Answers.adminUsername; allowedCidrs = $Workload.allowedCidrs }
    if (Test-LinuxProfile $Workload) {
        $scriptText = Get-Content -LiteralPath (Join-Path $script:Root 'guest\validate-linux.sh') -Raw
        $key = ($Workload.sshPublicKey -split ' ')[0..1] -join ' '
        $scriptText = $scriptText.Replace('__ADMIN_USERNAME__', $Answers.adminUsername).
            Replace('__SSH_KEY_BASE64__', [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($key))).
            Replace('__UBUNTU_VERSION__', $(if ($Workload.image.os -eq 'Ubuntu2404') { '24.04' } else { '22.04' }))
        if ($Workload.profile -eq 'webServer') {
            $nginx = Get-Content -LiteralPath (Join-Path $script:Root 'guest\configure-nginx.sh') -Raw
            $scriptText += "`n" + $nginx.Replace('__ALLOWED_CIDRS__', ($Workload.allowedCidrs -join ' '))
        }
        return @{ script = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($scriptText -replace "`r`n", "`n"))) }
    }
    $config.dataDiskSizeGB = $Workload.dataDiskSizeGB
    if ($Workload.ContainsKey('windowsPreparation')) { $config.windowsPreparation = $Workload.windowsPreparation }
    if ($Workload.profile -in @('fileServer', 'sqlServer')) { $config[$Workload.profile] = $Workload[$Workload.profile] }
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
    if (!@($Answers.workloads | Where-Object { !(Test-LinuxProfile $_) }).Count) { return @{ value = '' } }
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
        [ValidateRange(60, 21600)][int]$TimeoutSeconds = 10800,
        [ValidateSet('AzureCli', 'AzPowerShell')][string]$Authentication = 'AzureCli',
        [switch]$AllowUnverifiedExistingLinuxImage
    )
    $answers = Read-WorkloadAnswers $AnswerFile
    if (@($answers.workloads | Where-Object { $_.image.ContainsKey('pilotGuestValidation') }).Count) {
        if (!$AllowUnverifiedExistingLinuxImage) {
            throw 'pilotGuestValidation requires -AllowUnverifiedExistingLinuxImage for an explicitly authorized disposable pilot. Preparation provenance remains unknown.'
        }
        if (@($answers.workloads | Where-Object { $_.image.ContainsKey('pilotGuestValidation') }).Count -gt 2 -or
            @($answers.workloads | Where-Object { $_.image.ContainsKey('pilotGuestValidation') } | Group-Object profile | Where-Object Count -GT 1).Count) {
            throw 'Unverified-image pilots permit at most one intended VM per Linux profile.'
        }
        Write-Warning 'Pilot image preparation provenance is UNVERIFIED. Only public SSH keys are provisioned; guest acceptance must pass before any service is installed. Successful checks do not certify source-image provenance.'
    }
    $summary = Get-WorkloadSummary $answers.workloads
    Write-Output ("Plan: {0} VMs, {1} vCPU, {2} MiB RAM, {3} data disks / {4} GiB. OS-disk suggestions: {5} GiB ({6} unspecified); actual OS capacity is inherited from images, not resized." -f
        $summary.vmCount, $summary.processors, $summary.memoryMB, $summary.dataDiskCount, $summary.dataDiskGB, $summary.suggestedOsDiskGB, $summary.unspecifiedOsDiskCount)
    if ($Mode -eq 'Validate') { Write-Output 'Answer file is valid. Offline only; Azure resources, capacity, RBAC and guest readiness have not been checked.'; return }
    if (!$answers.workloads.Count) { Write-Output 'All workload counts are zero. No Azure connection, imports, password reads or deployments were performed.'; return }
    try {
        Open-ArmConnection $answers.subscriptionId $Authentication
        $plan = @(Invoke-WorkloadPreflight $answers)
        $plan | ForEach-Object { Write-Output "$($_.workloadName): $(if ($_.import) { 'import missing image' } else { 'reuse existing image' })" }
        if ($Mode -eq 'Preflight' -or !$PSCmdlet.ShouldProcess($answers.resourceGroup, 'Import missing images and deploy Arc-enabled workloads and billable monitoring')) { return }
        $template = Get-CompiledTemplate
        if (@($answers.workloads | Where-Object profile -In @('fileServer', 'sqlServer', 'iisServer')).Count) {
            Assert-PublicGuestArtifact (Get-WindowsGuestArtifact)
        }
        $resolved = @()
        foreach ($workload in $answers.workloads) {
            $image = $plan | Where-Object workloadName -EQ $workload.name
            $resolved += @{
                name = $workload.name; profile = $workload.profile
                processors = $workload.processors; memoryMB = $workload.memoryMB
                dataDiskSizeGB = $workload['dataDiskSizeGB']
                dataDisks = @(Get-WorkloadDisks $workload)
                isLinux = Test-LinuxProfile $workload
                configureGuest = $workload.profile -ne 'windowsApp'
                privateIpAddress = if ($workload.ContainsKey('privateIpAddress')) { $workload.privateIpAddress } else { '' }
                sshPublicKey = if ($workload.ContainsKey('sshPublicKey')) { $workload.sshPublicKey } else { '' }
                imageId = $image.imageId
                configurationHash = Get-ConfigurationHash $answers $workload $image.imageId
                tags = $image.tags
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
        Write-Output "Deployment succeeded: $($answers.deploymentName). Requested VM/extensions/monitoring provisioning completed; base profiles do not install applications. Verify remote client access and workspace ingestion separately."
    } finally {
        $parameters = $null
        $body = $null
        Close-ArmConnection
    }
}

Export-ModuleMember -Function Start-WorkloadDeployment, Read-WorkloadAnswers

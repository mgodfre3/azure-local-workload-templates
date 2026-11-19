[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ConfigurationBase64)

function Assert-Keys($Object, $Keys) {
    if ($null -eq $Object -or $Object -isnot [pscustomobject]) { throw 'Expected a JSON object.' }
    foreach ($p in $Object.PSObject.Properties.Name) {
        if ($p -cnotin $Keys) { throw 'Unsupported configuration property; plaintext secrets and product keys are not accepted.' }
    }
}

function Get-CidrRange([string]$Cidr) {
    if ($Cidr -notmatch '^(\d{1,3}\.){3}\d{1,3}/([1-9]|[12]\d|3[0-2])$') { throw 'Expected a non-universal IPv4 CIDR.' }
    $ip, $prefix = $Cidr.Split('/')
    [uint64]$n = 0
    foreach ($octet in $ip.Split('.')) {
        if ([int]$octet -gt 255 -or "$([int]$octet)" -cne $octet) { throw 'Invalid IPv4 address.' }
        $n = $n * 256 + [int]$octet
    }
    [uint64]$length = [math]::Pow(2, 32 - [int]$prefix)
    [uint64]$start = [math]::Floor($n / $length) * $length
    if ($n -ne $start) { throw 'CIDR must use its network address.' }
    return @($start, ($start + $length - 1))
}

function Assert-MediaUrl([string]$Url) {
    $uri = $null
    if (![uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https' -or
        $uri.UserInfo -or $uri.Query -or $uri.Fragment -or !$uri.IsDefaultPort -or
        $uri.DnsSafeHost -notmatch '\.' -or $uri.AbsolutePath -match '(?i)\.(exe|msi|zip)$') {
        throw 'Media must be a public, direct HTTPS full ISO URL without credentials, query, or fragment.'
    }
    return $uri
}

function Read-WorkloadConfiguration([string]$Payload) {
    try {
        $bytes = [Convert]::FromBase64String($Payload)
        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $c = $utf8.GetString($bytes) | ConvertFrom-Json -ErrorAction Stop
    } catch { throw 'ConfigurationBase64 must contain valid UTF8 JSON.' }
    Assert-Keys $c @('profile', 'adminUsername', 'allowedCidrs', 'dataDiskSizeGB', 'fileServer', 'sqlServer')
    if ($c.profile -cnotin @('fileServer', 'sqlServer', 'iisServer') -or
        $c.adminUsername -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,19}$' -or
        ($c.dataDiskSizeGB -isnot [int] -and $c.dataDiskSizeGB -isnot [long]) -or
        $c.dataDiskSizeGB -lt 1 -or $c.dataDiskSizeGB -gt 32767 -or
        $c.allowedCidrs -isnot [array] -or !$c.allowedCidrs.Count) { throw 'Invalid workload configuration.' }
    foreach ($cidr in $c.allowedCidrs) {
        if ($cidr -isnot [string]) { throw 'Invalid CIDR type.' }
        $null = Get-CidrRange $cidr
    }
    if ($null -ne $c.fileServer) { Assert-Keys $c.fileServer @('shareName') }
    if ($null -ne $c.sqlServer) {
        Assert-Keys $c.sqlServer @('installationMode', 'installerUrl', 'installerSha256', 'edition', 'acceptLicenseTerms', 'productionLicenseConfirmed', 'productKeySource')
    }
    if ($c.profile -eq 'fileServer') {
        Assert-Keys $c.fileServer @('shareName')
        if ($c.fileServer.shareName -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,63}$' -or
            $c.fileServer.shareName -in @('ADMIN', 'IPC', 'print')) { throw 'Invalid SMB share name.' }
    } elseif ($c.profile -eq 'sqlServer') {
        Assert-Keys $c.sqlServer @('installationMode', 'installerUrl', 'installerSha256', 'edition', 'acceptLicenseTerms', 'productionLicenseConfirmed', 'productKeySource')
        $s = $c.sqlServer
        $marketplace = $s.installationMode -ceq 'marketplace'
        if ($s.PSObject.Properties.Name -contains 'installationMode' -and $s.installationMode -cnotin @('iso', 'marketplace')) {
            throw 'Unsupported SQL installationMode.'
        }
        if ($s.edition -cnotin @('Developer', 'Evaluation', 'Standard', 'Enterprise')) { throw 'Only SQL Developer, Evaluation, Standard or Enterprise is supported.' }
        if ($s.acceptLicenseTerms -isnot [bool] -or !$s.acceptLicenseTerms) { throw 'Explicit SQL license consent is required.' }
        if ($s.edition -in @('Standard', 'Enterprise')) {
            if ($s.productionLicenseConfirmed -isnot [bool] -or !$s.productionLicenseConfirmed) {
                throw 'Paid SQL editions require explicit productionLicenseConfirmed and a pinned Key Vault productKeySource.'
            }
            if (!$marketplace) {
                Assert-Keys $s.productKeySource @('type', 'vaultResourceId', 'secretName', 'secretVersion')
                $source = $s.productKeySource
                if ($source.type -cne 'keyVault' -or
                    $source.vaultResourceId -notmatch '^/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/[a-z][a-z0-9-]{1,22}[a-z0-9]$' -or
                    $source.secretName -cnotmatch '^[a-zA-Z0-9-]{1,127}$' -or
                    $source.secretVersion -notmatch '^[0-9a-f]{32}$') {
                    throw 'SQL productKeySource must reference an Azure public-cloud Key Vault secret with a pinned version.'
                }
            }
        } elseif ($s.PSObject.Properties.Name -contains 'productKeySource' -or
            ($s.PSObject.Properties.Name -contains 'productionLicenseConfirmed' -and
                ($s.productionLicenseConfirmed -isnot [bool] -or $s.productionLicenseConfirmed))) {
            throw 'Developer and Evaluation require nonproduction use and cannot specify a product key source.'
        }
        if ($marketplace) {
            if ($s.edition -cne 'Enterprise' -or
                @($s.PSObject.Properties.Name | Where-Object { $_ -in @('installerUrl', 'installerSha256', 'productKeySource') }).Count) {
                throw 'Marketplace mode requires Enterprise and cannot accept ISO media or a product key source; preinstalled SQL is never reinstalled.'
            }
        } else {
            if ($s.installerSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'A SHA256 media checksum is required.' }
            $null = Assert-MediaUrl $s.installerUrl
        }
    }
    if (($c.profile -ne 'fileServer' -and $null -ne $c.fileServer) -or
        ($c.profile -ne 'sqlServer' -and $null -ne $c.sqlServer)) { throw 'Profile settings do not match the requested service.' }
    return $c
}

# Pure selection: never infer ownership from a drive letter alone.
function Select-WorkloadDisk($Disks, $Partitions, $Volumes, [long]$SizeGB) {
    $data = @($Disks | Where-Object { !$_.IsBoot -and !$_.IsSystem })
    if ($data.Count -ne 1 -or $data[0].Size -ne $SizeGB * 1GB) { throw 'Expected exactly one data disk of the configured capacity; conflicting disks are unsafe.' }
    $disk = $data[0]
    $parts = @($Partitions | Where-Object DiskNumber -eq $disk.Number)
    $ev = @($Volumes | Where-Object DriveLetter -eq 'E')
    $ep = @($Partitions | Where-Object DriveLetter -eq 'E')
    $labels = @($Volumes | Where-Object FileSystemLabel -eq 'WorkloadData')
    if ($disk.PartitionStyle -eq 'RAW') {
        if ($parts.Count -or $ev.Count -or $ep.Count -or $labels.Count) { throw 'RAW disk or E drive has conflicting existing content.' }
        return [pscustomobject]@{ DiskNumber = $disk.Number; Initialize = $true }
    }
    $reserved = @($parts | Where-Object { $_.Type -eq 'Reserved' -and !$_.DriveLetter -and $_.Size -le 16MB })
    if ($disk.PartitionStyle -ne 'GPT' -or $ev.Count -ne 1 -or $ep.Count -ne 1 -or $labels.Count -ne 1 -or
        $ep[0].DiskNumber -ne $disk.Number -or $ep[0].Type -ne 'Basic' -or
        $parts.Count -ne (1 + $reserved.Count) -or $reserved.Count -gt 1 -or
        $ev[0].FileSystemLabel -ne 'WorkloadData' -or $ev[0].FileSystem -ne 'NTFS' -or
        $ep[0].Size -lt ($disk.Size - 32MB) -or $ep[0].Size -gt $disk.Size -or
        $ev[0].Size -lt ($disk.Size - 32MB) -or $ev[0].Size -gt $ep[0].Size) {
        throw 'Existing data disk is not the expected single NTFS WorkloadData E volume; no disk was formatted.'
    }
    return [pscustomobject]@{ DiskNumber = $disk.Number; Initialize = $false }
}

function Initialize-WorkloadData([long]$SizeGB) {
    $plan = Select-WorkloadDisk @(Get-Disk) @(Get-Partition) @(Get-Volume) $SizeGB
    if ($plan.Initialize) {
        # Re-read immediately before the only destructive operations.
        $again = Select-WorkloadDisk @(Get-Disk) @(Get-Partition) @(Get-Volume) $SizeGB
        if (!$again.Initialize -or $again.DiskNumber -ne $plan.DiskNumber) { throw 'Disk inventory changed.' }
        Initialize-Disk -Number $plan.DiskNumber -PartitionStyle GPT | Out-Null
        New-Partition -DiskNumber $plan.DiskNumber -DriveLetter E -UseMaximumSize |
            Format-Volume -FileSystem NTFS -NewFileSystemLabel WorkloadData -Confirm:$false | Out-Null
    }
    $null = Select-WorkloadDisk @(Get-Disk) @(Get-Partition) @(Get-Volume) $SizeGB
}

function Assert-NoRestart {
    if ((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
        (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) {
        throw 'A Windows restart is required. Restart manually, then rerun the extension; no automatic reboot was attempted.'
    }
}

function Set-PrivateDirectory([string]$Path, [string[]]$Sids) {
    $parent = $Path
    while ($parent) {
        if ((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Reparse points are not supported in workload paths.'
        }
        $parent = Split-Path -Path $parent -Parent
    }
    $null = New-Item -ItemType Directory -Path $Path -Force
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in (@('S-1-5-32-544', 'S-1-5-18') + $Sids | Select-Object -Unique)) {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-PrivateTree([string]$Path, [string]$AdminSid) {
    $pending = New-Object 'Collections.Generic.Queue[string]'
    $pending.Enqueue($Path)
    while ($pending.Count) {
        foreach ($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points in the share are unsafe.' }
            foreach ($ace in (Get-Acl -LiteralPath $item.FullName).Access) {
                if ($ace.AccessControlType -eq 'Allow' -and
                    $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544', 'S-1-5-18', $AdminSid)) {
                    throw 'Existing share content has unexpected NTFS permissions.'
                }
            }
            if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) }
        }
    }
}

function Assert-ScopedFirewall([int]$Port, [string[]]$Cidrs) {
    foreach ($profile in Get-NetFirewallProfile -PolicyStore ActiveStore) {
        if (!$profile.Enabled -or $profile.DefaultInboundAction -ne 'Block') { throw 'All firewall profiles must be enabled with default inbound Block.' }
    }
    foreach ($r in Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow) {
        $f = $r | Get-NetFirewallPortFilter
        if ($f.Protocol -notin @('TCP', '6', 'Any', '256')) { continue }
        $matchesPort = $false
        foreach ($p in $f.LocalPort) {
            if ($p -in @('Any', '*') -or $p -eq "$Port" -or
                ($p -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2])) { $matchesPort = $true }
        }
        if (!$matchesPort) { continue }
        foreach ($address in ($r | Get-NetFirewallAddressFilter).RemoteAddress) {
            $contained = $false
            try {
                if ($address -notmatch '/') { $address += '/32' }
                $range = Get-CidrRange $address
                foreach ($cidr in $Cidrs) {
                    $allowed = Get-CidrRange $cidr
                    if ($range[0] -ge $allowed[0] -and $range[1] -le $allowed[1]) { $contained = $true }
                }
            } catch { $contained = $false }
            if (!$contained) { throw 'An enabled inbound firewall rule exposes the workload port outside allowedCidrs. Resolve that policy manually.' }
        }
    }
}

function Set-WorkloadFirewall([int]$Port, [string[]]$Cidrs) {
    Assert-ScopedFirewall $Port $Cidrs
    $name = "AzureLocalWorkload-TCP-$Port"
    $rule = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Name -eq $name)
    if ($rule.Count) {
        if ($rule.Count -ne 1 -or $rule[0].Group -ne 'AzureLocalWorkload') { throw 'Managed firewall rule name collision.' }
        $rule[0] | Remove-NetFirewallRule
    }
    New-NetFirewallRule -Name $name -DisplayName $name -Group AzureLocalWorkload -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $Port -RemoteAddress $Cidrs -Profile Any -Enabled True -EdgeTraversalPolicy Block | Out-Null
    if (!(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.Name -eq $name -and $_.Enabled -eq 'True' })) {
        throw 'Workload firewall rule is not effective.'
    }
    Assert-ScopedFirewall $Port $Cidrs
}

function Set-FileServer($Config, $Admin) {
    $feature = Install-WindowsFeature FS-FileServer
    if (!$feature.Success -or $feature.RestartNeeded -ne 'No') { throw 'File server role requires a restart or installation failed; rerun after manual recovery.' }
    Assert-ScopedFirewall 445 $Config.allowedCidrs
    $path = "E:\Shares\$($Config.fileServer.shareName)"
    Set-PrivateDirectory 'E:\Shares' @($Admin.SID.Value)
    Set-PrivateDirectory $path @($Admin.SID.Value)
    Assert-PrivateTree $path $Admin.SID.Value
    $share = @(Get-SmbShare | Where-Object Name -eq $Config.fileServer.shareName)
    if ($share.Count -and ($share.Count -ne 1 -or $share[0].Path -ne $path -or $share[0].Special)) { throw 'Existing share name collision.' }
    $account = "$env:COMPUTERNAME\$($Admin.Name)"
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSMB2Protocol $true -RejectUnencryptedAccess $true -Confirm:$false
    if (!$share.Count) {
        New-SmbShare -Name $Config.fileServer.shareName -Path $path -FullAccess $account -EncryptData $true -FolderEnumerationMode AccessBased | Out-Null
    } else {
        Set-SmbShare -Name $Config.fileServer.shareName -EncryptData $true -FolderEnumerationMode AccessBased -Force
        foreach ($entry in Get-SmbShareAccess -Name $Config.fileServer.shareName) {
            if ($entry.AccessControlType -eq 'Deny') { throw 'Unexpected deny ACL on existing share.' }
            Revoke-SmbShareAccess -Name $Config.fileServer.shareName -AccountName $entry.AccountName -Force
        }
        Grant-SmbShareAccess -Name $Config.fileServer.shareName -AccountName $account -AccessRight Full -Force | Out-Null
    }
    $actual = Get-SmbShare -Name $Config.fileServer.shareName
    $access = @(Get-SmbShareAccess -Name $Config.fileServer.shareName)
    if (!$actual.EncryptData -or $access.Count -ne 1 -or $access[0].AccountName -ne $account -or $access[0].AccessRight -ne 'Full') { throw 'SMB verification failed.' }
    Set-WorkloadFirewall 445 $Config.allowedCidrs
}

function Assert-IisLayout($Sites, $Bindings) {
    if ($Sites.Count -ne 1 -or $Sites[0].Name -ne 'Default Web Site') { throw 'Expected only the default IIS site; refusing to alter other sites.' }
    if ($Bindings.Count -ne 1 -or $Bindings[0].protocol -ne 'http' -or
        $Bindings[0].bindingInformation -ne '*:80:') { throw 'Unexpected IIS bindings; refusing to change them.' }
    if ($Sites[0].physicalPath -notin @('%SystemDrive%\inetpub\wwwroot', 'C:\inetpub\wwwroot', 'E:\Iis')) { throw 'Unexpected IIS site content path.' }
}

function Set-IisServer($Config) {
    $feature = Install-WindowsFeature Web-Server
    # Replace only the role's built-in network openings with the scoped rule below.
    Get-NetFirewallRule -PolicyStore PersistentStore |
        Where-Object Name -in @('IIS-WebServerRole-HTTP-In-TCP', 'IIS-WebServerRole-HTTPS-In-TCP') |
        Disable-NetFirewallRule | Out-Null
    if (!$feature.Success -or $feature.RestartNeeded -ne 'No') { throw 'IIS role requires a restart or installation failed; rerun after manual recovery.' }
    Import-Module WebAdministration -ErrorAction Stop
    Assert-IisLayout @(Get-Website) @(Get-WebBinding -Name 'Default Web Site')
    $path = 'E:\Iis'
    Set-PrivateDirectory $path @()
    # Anonymous IUSR and IIS workers get read-only access to site content.
    $acl = Get-Acl -LiteralPath $path
    foreach ($sid in @('S-1-5-17', 'S-1-5-32-568')) {
        $reader = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($reader, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $path -AclObject $acl
    $index = Join-Path $path 'index.html'
    $content = '<!doctype html><html lang="en"><title>Azure Local IIS</title><h1>Azure Local IIS reference workload</h1></html>'
    if (Test-Path -LiteralPath $index) {
        if ((Get-Item -LiteralPath $index -Force).Attributes -band [IO.FileAttributes]::ReparsePoint -or
            (Get-Content -LiteralPath $index -Raw).Trim() -ne $content) { throw 'IIS content collision; existing files were not overwritten.' }
    } elseif (@(Get-ChildItem -LiteralPath $path -Force).Count) { throw 'IIS content directory is not empty.' }
    else { Set-Content -LiteralPath $index -Value $content -Encoding ASCII }
    Set-ItemProperty 'IIS:\Sites\Default Web Site' -Name physicalPath -Value $path
    Set-WorkloadFirewall 80 $Config.allowedCidrs
    Start-Service W3SVC
    Start-WebSite -Name 'Default Web Site'
    $response = Invoke-WebRequest 'http://localhost/' -UseBasicParsing -TimeoutSec 30
    if ($response.StatusCode -ne 200 -or $response.Content.Trim() -ne $content) { throw 'IIS local HTTP readiness failed.' }
}

function Get-SqlResult([string]$Query, [string]$Server = 'lpc:.') {
    for ($i = 0; $i -lt 12; $i++) {
        $connection = New-Object System.Data.SqlClient.SqlConnection("Server=$Server;Integrated Security=SSPI;Encrypt=True;TrustServerCertificate=True;Connect Timeout=5")
        try {
            $connection.Open()
            $command = $connection.CreateCommand()
            $command.CommandTimeout = 10
            $command.CommandText = $Query
            $table = New-Object System.Data.DataTable
            $reader = $command.ExecuteReader()
            $table.Load($reader)
            return ,$table
        } catch {
            if ($i -eq 11) { throw 'SQL integrated query readiness failed after bounded retry.' }
        } finally { $connection.Dispose() }
        Start-Sleep -Seconds 5
    }
}

function Assert-SqlInstance($Sql, [string]$Account, [string]$SystemAccount, [string]$Server = 'lpc:.') {
    $Account = $Account.Replace("'", "''")
    $SystemAccount = $SystemAccount.Replace("'", "''")
    $query = @"
SELECT 1 AS Probe, CONVERT(int,SERVERPROPERTY('ProductMajorVersion')) AS Major,
CONVERT(nvarchar(128),SERVERPROPERTY('Edition')) AS Edition,
CONVERT(int,SERVERPROPERTY('IsIntegratedSecurityOnly')) AS WindowsOnly,
CONVERT(nvarchar(260),SERVERPROPERTY('InstanceDefaultDataPath')) AS DataPath,
CONVERT(nvarchar(260),SERVERPROPERTY('InstanceDefaultLogPath')) AS LogPath,
IS_SRVROLEMEMBER('sysadmin',N'$Account') AS AdminRole,
IS_SRVROLEMEMBER('sysadmin',N'$SystemAccount') AS SystemRole,
(SELECT COUNT(*) FROM sys.master_files WHERE physical_name NOT LIKE N'E:\Sql\%'
 OR (database_id > 4 AND physical_name NOT LIKE CASE WHEN type=1 THEN N'E:\Sql\Log\%' ELSE N'E:\Sql\Data\%' END)
 OR (database_id=2 AND physical_name NOT LIKE N'E:\Sql\Temp\%')) AS BadPaths
"@
    $row = (Get-SqlResult $query $Server).Rows[0]
    $edition = switch ($Sql.edition) {
        'Developer' { 'Developer Edition*' }
        'Evaluation' { 'Enterprise Evaluation Edition*' }
        'Standard' { 'Standard Edition*' }
        'Enterprise' { 'Enterprise Edition*' }
        default { throw 'Unsupported requested SQL edition.' }
    }
    if ($row.Probe -ne 1 -or $row.Major -ne 16 -or $row.Edition -notlike $edition -or $row.WindowsOnly -ne 1 -or
        $row.DataPath.TrimEnd('\') -ne 'E:\Sql\Data' -or $row.LogPath.TrimEnd('\') -ne 'E:\Sql\Log' -or
        $row.AdminRole -ne 1 -or $row.SystemRole -ne 1 -or $row.BadPaths -ne 0) {
        throw 'Existing SQL version, edition, authentication, sysadmins, or data/log paths do not match; refusing to repurpose the instance.'
    }
}

function Save-SqlIso($Sql, [string]$Path) {
    $uri = Assert-MediaUrl $Sql.installerUrl
    # Do not follow redirects to credential-bearing, private, or non-HTTPS locations.
    try { $addresses = [Net.Dns]::GetHostAddresses($uri.DnsSafeHost) }
    catch { throw 'SQL media DNS resolution failed.' }
    if (!$addresses.Count) { throw 'SQL media DNS resolution failed.' }
    foreach ($ip in $addresses) {
        $b = $ip.GetAddressBytes()
        if ($b.Length -eq 16) {
            if (($b[0] -band 224) -ne 32 -or ($b[0] -eq 32 -and $b[1] -eq 1 -and $b[2] -eq 13 -and $b[3] -eq 184)) {
                throw 'SQL media must resolve only to public addresses.'
            }
        } elseif ($b[0] -in @(0, 10, 127) -or $b[0] -ge 224 -or
            ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
            ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127)) {
            throw 'SQL media must resolve only to public addresses.'
        }
    }
    Add-Type -AssemblyName System.Net.Http
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(60)
    try {
        $response = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        try {
            if ([int]$response.StatusCode -ne 200) { throw 'Media HTTP status was not 200.' }
            $stream = [IO.File]::Create($Path)
            try {
                if (!$response.Content.CopyToAsync($stream).Wait([TimeSpan]::FromMinutes(60))) { throw 'Media download timeout.' }
            } finally { $stream.Dispose() }
        } finally { $response.Dispose() }
    } catch { throw 'SQL ISO download failed. Use a direct public HTTPS ISO URL; redirects are not accepted.' }
    finally { $client.Dispose(); $handler.Dispose() }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Sql.installerSha256) { throw 'SQL ISO SHA256 mismatch; setup was not executed.' }
}

function Get-SqlProductKey($Source) {
    # The key is fetched only inside the guest, never by ARM or the launcher.
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $handler.UseProxy = $false
    $client = New-Object Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $vaultClient = $null
    $vaultHandler = $null
    $endpoint = 'http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https%3A%2F%2Fvault.azure.net'
    try {
        $null = $client.DefaultRequestHeaders.TryAddWithoutValidation('Metadata', 'true')
        $challenge = $client.GetAsync($endpoint).GetAwaiter().GetResult()
        try {
            if ([int]$challenge.StatusCode -ne 401) { throw 'Arc identity challenge was not returned.' }
            $header = $challenge.Headers.WwwAuthenticate.ToString()
            if ($header -notmatch '^Basic realm="?([^"]+)"?$') { throw 'Invalid Arc identity challenge.' }
            $path = [IO.Path]::GetFullPath($Matches[1])
            $tokenDirectory = Join-Path $env:ProgramData 'AzureConnectedMachineAgent\Tokens'
            if ((Split-Path $path -Parent) -ine $tokenDirectory -or
                (Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint -or
                (Get-Item -LiteralPath $tokenDirectory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Unexpected Arc identity challenge path.'
            }
            $challengeSecret = [IO.File]::ReadAllText($path)
        } finally { $challenge.Dispose() }
        $null = $client.DefaultRequestHeaders.TryAddWithoutValidation('Authorization', "Basic $challengeSecret")
        $response = $client.GetAsync($endpoint).GetAwaiter().GetResult()
        try {
            if (!$response.IsSuccessStatusCode) { throw 'Arc identity token request failed.' }
            $token = ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json).access_token
            if (!$token) { throw 'Arc identity token is missing.' }
        } finally { $response.Dispose() }
        $vault = ($Source.vaultResourceId -split '/')[-1]
        $uri = "https://$vault.vault.azure.net/secrets/$($Source.secretName)/$($Source.secretVersion)?api-version=7.4"
        $vaultHandler = New-Object Net.Http.HttpClientHandler
        $vaultHandler.AllowAutoRedirect = $false
        $vaultClient = New-Object Net.Http.HttpClient($vaultHandler)
        $vaultClient.Timeout = [TimeSpan]::FromSeconds(30)
        $vaultClient.DefaultRequestHeaders.Authorization = New-Object Net.Http.Headers.AuthenticationHeaderValue('Bearer', $token)
        $secretResponse = $vaultClient.GetAsync($uri).GetAwaiter().GetResult()
        try {
            if (!$secretResponse.IsSuccessStatusCode) { throw 'Key Vault secret request failed.' }
            $key = ($secretResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json).value
            Assert-SqlProductKey $key
            return $key
        } finally { $secretResponse.Dispose() }
    } catch {
        throw 'SQL product key retrieval failed. Verify the pinned secret, guest Arc identity secret-get permission and vault connectivity; secret values and responses are suppressed.'
    } finally {
        $client.Dispose()
        $handler.Dispose()
        if ($null -ne $vaultClient) { $vaultClient.Dispose() }
        if ($null -ne $vaultHandler) { $vaultHandler.Dispose() }
        $key = $null; $token = $null; $challengeSecret = $null
    }
}

function Assert-MarketplaceSqlInstance($Config) {
    $service = Get-Service MSSQLSERVER -ErrorAction Stop
    if ($service.Status -ne 'Running') { throw 'Preinstalled SQL default-instance service is not Running; no reinstall or automatic repair was attempted.' }
    $row = (Get-SqlResult @"
SELECT 1 AS Probe, CONVERT(int,SERVERPROPERTY('ProductMajorVersion')) AS Major,
CONVERT(nvarchar(128),SERVERPROPERTY('Edition')) AS Edition,
CONVERT(int,SERVERPROPERTY('IsIntegratedSecurityOnly')) AS WindowsOnly,
(SELECT COUNT(*) FROM sys.databases WHERE state_desc <> N'ONLINE') AS OfflineDatabases
"@).Rows[0]
    if ($row.Probe -ne 1 -or $row.Major -ne 16 -or $row.Edition -notlike 'Enterprise Edition*' -or
        $row.WindowsOnly -ne 1 -or $row.OfflineDatabases -ne 0) {
        throw 'Preinstalled SQL 2022 Enterprise, Windows authentication or online-database acceptance failed; no reinstall, key injection or database relocation was attempted.'
    }
    Assert-ScopedFirewall 1433 $Config.allowedCidrs
    Write-Output 'Preinstalled SQL 2022 Enterprise local integrated query and database acceptance passed. Image database paths and extra RAW disks were preserved; no SQL listener or firewall rule was changed. Verify administrator/client access and licensing separately.'
}

function Assert-SqlProductKey([string]$Key) {
    if ($Key.Length -ne 29 -or $Key -cnotmatch '^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$' -or
        $Key -in @('22222-00000-00000-00000-00000', '00000-00000-00000-00000-00000', '11111-00000-00000-00000-00000')) {
        throw 'The SQL product key secret must contain a paid-edition PID in five groups of five uppercase letters/digits; its value is not logged.'
    }
}

function Invoke-SqlSetup([string]$Setup, [string]$Arguments, $Sql, [string]$Cache) {
    $directory = Join-Path $Cache ([guid]::NewGuid().ToString())
    Set-PrivateDirectory $directory @()
    $config = Join-Path $directory 'setup.ini'
    $stdout = Join-Path $directory 'stdout.log'
    $stderr = Join-Path $directory 'stderr.log'
    $key = $null
    try {
        if ($Sql.edition -eq 'Developer') { $key = '22222-00000-00000-00000-00000' }
        elseif ($Sql.edition -in @('Standard', 'Enterprise')) {
            $key = Get-SqlProductKey $Sql.productKeySource
            Assert-SqlProductKey $key
        }
        else { throw 'Evaluation setup must not use a PID configuration.' }
        # A new file inherits the private directory's SYSTEM/Administrators-only ACL.
        $stream = [IO.File]::Open($config, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $writer = New-Object IO.StreamWriter($stream, [Text.Encoding]::Unicode)
            try { $writer.Write("[OPTIONS]`r`nPID=`"$key`"`r`n") }
            finally { $writer.Dispose() }
        } finally { $stream.Dispose() }
        $process = Start-Process -FilePath $Setup -ArgumentList "$Arguments /ConfigurationFile=`"$config`"" -Wait -PassThru `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        return $process.ExitCode
    } catch {
        throw 'SQL setup could not complete using its private PID configuration. Secret-bearing output is suppressed; check guest prerequisites and protected SQL Setup logs.'
    } finally {
        $key = $null
        foreach ($file in @($config, $stdout, $stderr)) {
            if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force -ErrorAction Stop }
        }
        Remove-Item -LiteralPath $directory -Force -ErrorAction Stop
    }
}

function Install-SqlInstance($Sql, [string]$Account, [string]$SystemAccount) {
    # Public setup flags and predefined free-edition PIDs:
    # https://learn.microsoft.com/sql/database-engine/install-windows/install-sql-server-from-the-command-prompt?view=sql-server-ver16
    $cache = "$env:ProgramData\AzureLocalWorkload"
    Set-PrivateDirectory $cache @()
    $iso = Join-Path $cache "$([guid]::NewGuid()).iso"
    if ((Test-Path 'E:\Sql') -and @(Get-ChildItem 'E:\Sql' -Force).Count) { throw 'SQL data directory is not empty; refusing a new installation.' }
    Set-PrivateDirectory 'E:\Sql' @()
    try {
        Save-SqlIso $Sql $iso
        $image = Mount-DiskImage -ImagePath $iso -PassThru
        try {
            $volumes = @($image | Get-Volume)
            if ($volumes.Count -ne 1 -or !$volumes[0].DriveLetter) { throw 'SQL ISO has an unexpected volume layout.' }
            $root = "$($volumes[0].DriveLetter):\"
            $setup = Join-Path $root 'setup.exe'
            if (!(Test-Path "$($root)x64\setup\sql_engine_core_inst.msi") -or !(Test-Path $setup) -or
                (Get-Item $setup).VersionInfo.ProductVersion -notmatch '^(16\.|2022\.160\.)') { throw 'A full SQL Server 2022 x64 ISO is required.' }
            $signature = Get-AuthenticodeSignature $setup
            if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation,') { throw 'SQL setup signature verification failed.' }
            $arguments = '/Q /ACTION=Install /FEATURES=SQLENGINE /INSTANCENAME=MSSQLSERVER /IACCEPTSQLSERVERLICENSETERMS /SUPPRESSPRIVACYSTATEMENTNOTICE /UPDATEENABLED=False /TCPENABLED=0 /NPENABLED=0 /SQLSVCACCOUNT="NT Service\MSSQLSERVER" /SQLSVCSTARTUPTYPE=Automatic /AGTSVCACCOUNT="NT Service\SQLSERVERAGENT" /AGTSVCSTARTUPTYPE=Disabled /BROWSERSVCSTARTUPTYPE=Disabled /INSTALLSQLDATADIR="E:\Sql" /SQLUSERDBDIR="E:\Sql\Data" /SQLUSERDBLOGDIR="E:\Sql\Log" /SQLTEMPDBDIR="E:\Sql\Temp" /SQLTEMPDBLOGDIR="E:\Sql\Temp" /SQLBACKUPDIR="E:\Sql\Backup"'
            if ($Sql.edition -eq 'Evaluation') {
                # Omitted PID means Evaluation only on evaluation media, not media with a predefined paid/developer key.
                $defaults = Join-Path $root 'x64\DefaultSetup.ini'
                if ((Test-Path $defaults) -and ((Get-Content $defaults -Raw) -match '(?im)^\s*PID\s*=\s*"?([A-Za-z0-9-]+)' ) -and
                    $Matches[1] -ne '00000-00000-00000-00000-00000') {
                    throw 'Evaluation requires evaluation ISO media.'
                }
            }
            $arguments += " /SQLSYSADMINACCOUNTS=`"$Account`" `"$SystemAccount`""
            if ($Sql.edition -eq 'Evaluation') {
                $process = Start-Process -FilePath $setup -ArgumentList $arguments -Wait -PassThru
                $exitCode = $process.ExitCode
            } else { $exitCode = Invoke-SqlSetup $setup $arguments $Sql $cache }
            if ($exitCode -in @(3010, 1641)) { throw 'SQL setup requires a manual restart; rerun after restart.' }
            if ($exitCode -ne 0) { throw "SQL setup failed with exit code $exitCode. Review protected local SQL setup logs." }
        } finally { Dismount-DiskImage -ImagePath $iso | Out-Null }
    } finally { if (Test-Path $iso) { Remove-Item -LiteralPath $iso -Force } }
}

function Set-SqlServer($Config, $Admin) {
    $sql = $Config.sqlServer
    $account = "$env:COMPUTERNAME\$($Admin.Name)"
    $systemAccount = ([Security.Principal.SecurityIdentifier]'S-1-5-18').Translate([Security.Principal.NTAccount]).Value
    foreach ($path in @('E:\Sql', 'E:\Sql\Data', 'E:\Sql\Log', 'E:\Sql\Temp', 'E:\Sql\Backup')) {
        if ((Test-Path $path) -and ((Get-Item $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Reparse points in SQL paths are unsafe.'
        }
    }
    $instanceKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    $instances = Get-ItemProperty $instanceKey -ErrorAction SilentlyContinue
    $service = Get-Service MSSQLSERVER -ErrorAction SilentlyContinue
    if (!$service -and !$instances) { Install-SqlInstance $sql $account $systemAccount }
    elseif (!$service -or $instances.MSSQLSERVER -ne 'MSSQL16.MSSQLSERVER') { throw 'Unexpected or incomplete existing SQL installation.' }
    Assert-NoRestart
    $svc = Get-CimInstance Win32_Service -Filter "Name='MSSQLSERVER'"
    if ($svc.StartName -ne 'NT Service\MSSQLSERVER') { throw 'Unexpected SQL service identity.' }
    Start-Service MSSQLSERVER
    Assert-SqlInstance $sql $account $systemAccount
    $null = Get-SqlResult "DECLARE @q nvarchar(300); SELECT @q=N'ALTER LOGIN '+QUOTENAME(name)+N' DISABLE' FROM sys.server_principals WHERE sid=0x01; IF @q IS NOT NULL EXEC(@q); SELECT 1;"
    $base = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer'
    if ((Get-ItemProperty $base).LoginMode -ne 1) { throw 'SQL must use Windows authentication only.' }
    $tcp = "$base\SuperSocketNetLib\Tcp"
    $changed = $false
    foreach ($setting in @(@($tcp, 'Enabled', 1), @($tcp, 'ListenOnAllIPs', 1), @("$base\SuperSocketNetLib\Np", 'Enabled', 0))) {
        if ((Get-ItemProperty $setting[0]).($setting[1]) -ne $setting[2]) {
            Set-ItemProperty $setting[0] -Name $setting[1] -Value $setting[2]
            $changed = $true
        }
    }
    foreach ($ip in Get-ChildItem $tcp | Where-Object PSChildName -like 'IP*') {
        foreach ($setting in @(@('TcpDynamicPorts', ''), @('TcpPort', '1433'))) {
            if ((Get-ItemProperty $ip.PSPath).($setting[0]) -cne $setting[1]) {
                Set-ItemProperty $ip.PSPath -Name $setting[0] -Value $setting[1]
                $changed = $true
            }
        }
    }
    Stop-Service SQLBrowser -ErrorAction Stop
    Set-Service SQLBrowser -StartupType Disabled
    Set-Service MSSQLSERVER -StartupType Automatic
    if ($changed) { Restart-Service MSSQLSERVER -Force }
    Assert-SqlInstance $sql $account $systemAccount 'tcp:localhost,1433'
    $row = (Get-SqlResult 'SELECT COUNT(*) AS EnabledSa FROM sys.server_principals WHERE sid=0x01 AND is_disabled=0').Rows[0]
    if ($row.EnabledSa -ne 0 -or (Get-Service MSSQLSERVER).Status -ne 'Running' -or
        (Get-CimInstance Win32_Service -Filter "Name='SQLBrowser'").StartMode -ne 'Disabled') { throw 'SQL service or SA verification failed.' }
    Set-WorkloadFirewall 1433 $Config.allowedCidrs
}

function Assert-WindowsServerVersion($OperatingSystem) {
    if ($OperatingSystem.BuildNumber -notin @('20348', '26100') -or $OperatingSystem.ProductType -notin @(2, 3)) {
        throw 'Windows Server 2022 or 2025 is required.'
    }
}

function Invoke-WorkloadConfiguration([string]$Payload) {
    $ErrorActionPreference = 'Stop'
    $c = Read-WorkloadConfiguration $Payload
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or ![Environment]::Is64BitProcess) { throw 'Run using 64-bit Windows PowerShell as SYSTEM.' }
    $os = Get-CimInstance Win32_OperatingSystem
    Assert-WindowsServerVersion $os
    Assert-NoRestart
    $admin = Get-LocalUser -Name $c.adminUsername
    $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
    if (!$admin.Enabled -or $admin.SID.Value -notin $members.SID.Value) { throw 'adminUsername must be an enabled local Administrator.' }
    $port = switch ($c.profile) { 'fileServer' { 445 } 'sqlServer' { 1433 } 'iisServer' { 80 } }
    Assert-ScopedFirewall $port $c.allowedCidrs
    if ($c.profile -eq 'sqlServer' -and $c.sqlServer.installationMode -eq 'marketplace') {
        Assert-MarketplaceSqlInstance $c
        Assert-NoRestart
        return
    }
    Initialize-WorkloadData $c.dataDiskSizeGB
    switch ($c.profile) {
        'fileServer' { Set-FileServer $c $admin }
        'sqlServer' { Set-SqlServer $c $admin }
        'iisServer' { Set-IisServer $c }
    }
    Assert-NoRestart
    Write-Output 'Workload configuration verified.'
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-WorkloadConfiguration $ConfigurationBase64 }

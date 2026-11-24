[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$ConfigurationBase64)

function Assert-Keys($Object, $Keys) {
    if ($null -eq $Object -or $Object -isnot [pscustomobject]) { throw 'Expected a JSON object.' }
    foreach ($p in $Object.PSObject.Properties.Name) {
        if ($p -cnotin $Keys) { throw 'Unsupported configuration property; plaintext secrets and product keys are not accepted.' }
    }
}

function Get-CidrRange([string]$Cidr, [switch]$AllowSubnetMask) {
    if ($AllowSubnetMask -and $Cidr -match '^(\d{1,3}\.){3}\d{1,3}/(\d{1,3}\.){3}\d{1,3}$') {
        $ip, $mask = $Cidr.Split('/')
        $bits = -join ($mask.Split('.') | ForEach-Object {
            if ([int]$_ -gt 255 -or "$([int]$_)" -cne $_) { throw 'Invalid IPv4 subnet mask.' }
            [Convert]::ToString([int]$_, 2).PadLeft(8, '0')
        })
        if ($bits -notmatch '^1+0*$') { throw 'Expected a contiguous non-universal IPv4 subnet mask.' }
        $Cidr = "$ip/$($bits.TrimEnd('0').Length)"
    }
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
    Assert-Keys $c @('profile', 'adminUsername', 'allowedCidrs', 'dataDiskSizeGB', 'fileServer', 'sqlServer', 'windowsPreparation')
    if ($c.profile -cnotin @('fileServer', 'sqlServer', 'iisServer') -or
        $c.adminUsername -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,19}$' -or
        ($c.dataDiskSizeGB -isnot [int] -and $c.dataDiskSizeGB -isnot [long]) -or
        $c.dataDiskSizeGB -lt 1 -or $c.dataDiskSizeGB -gt 32767 -or
        $c.allowedCidrs -isnot [array] -or !$c.allowedCidrs.Count) { throw 'Invalid workload configuration.' }
    foreach ($cidr in $c.allowedCidrs) {
        if ($cidr -isnot [string]) { throw 'Invalid CIDR type.' }
        $null = Get-CidrRange $cidr
    }
    if ($null -ne $c.windowsPreparation) {
        Assert-Keys $c.windowsPreparation @('scopeInheritedFirewall', 'restartIfRequired')
        if ($c.windowsPreparation.scopeInheritedFirewall -isnot [bool]) { throw 'scopeInheritedFirewall must be a boolean.' }
        if ($c.windowsPreparation.PSObject.Properties.Name -contains 'restartIfRequired' -and
            $c.windowsPreparation.restartIfRequired -isnot [bool]) { throw 'restartIfRequired must be a boolean.' }
    }
    if ($null -ne $c.fileServer) { Assert-Keys $c.fileServer @('shareName') }
    if ($null -ne $c.sqlServer) {
        Assert-Keys $c.sqlServer @('installationMode', 'installerUrl', 'installerSha256', 'edition', 'acceptLicenseTerms', 'productionLicenseConfirmed', 'productKeySource', 'administratorPolicy', 'clientAccess')
    }
    if ($c.profile -eq 'fileServer') {
        Assert-Keys $c.fileServer @('shareName')
        if ($c.fileServer.shareName -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{0,63}$' -or
            $c.fileServer.shareName -in @('ADMIN', 'IPC', 'print')) { throw 'Invalid SMB share name.' }
    } elseif ($c.profile -eq 'sqlServer') {
        Assert-Keys $c.sqlServer @('installationMode', 'installerUrl', 'installerSha256', 'edition', 'acceptLicenseTerms', 'productionLicenseConfirmed', 'productKeySource', 'administratorPolicy', 'clientAccess')
        $s = $c.sqlServer
        $marketplace = $s.installationMode -ceq 'marketplace'
        if ($s.PSObject.Properties.Name -contains 'administratorPolicy' -and
            (!$marketplace -or $s.administratorPolicy -cnotin @('grantIfAuthorized', 'recoverEmptyInstance', 'recoverDisposableInstance'))) {
            throw 'administratorPolicy requires an explicit supported Marketplace policy.'
        }
        if ($s.PSObject.Properties.Name -contains 'clientAccess' -and
            (!$marketplace -or $s.clientAccess -isnot [bool])) { throw 'clientAccess requires a Marketplace boolean.' }
        if ($s.clientAccess -eq $true -and !$s.administratorPolicy) { throw 'Marketplace client access requires an explicit administratorPolicy.' }
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

function Test-PendingRestart {
    return [bool]((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
        (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
}

function Assert-NoRestart {
    if (Test-PendingRestart) {
        throw 'A Windows restart is required. Restart manually, then rerun the extension; no automatic reboot was attempted.'
    }
}

function Invoke-WorkloadPreparation([string]$Payload) {
    $ErrorActionPreference = 'Stop'
    $c = Read-WorkloadConfiguration $Payload
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or ![Environment]::Is64BitProcess) { throw 'Run using 64-bit Windows PowerShell as SYSTEM.' }
    Assert-WindowsServerVersion (Get-CimInstance Win32_OperatingSystem)
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    if (!(Test-PendingRestart)) { return @{ bootUtc = $boot; restartScheduled = $false } }
    if ($c.windowsPreparation.restartIfRequired -ne $true) { Assert-NoRestart }
    if (@(Get-SmbSession).Count) { throw 'Active SMB sessions prevent an automatic guest restart.' }
    if ($c.profile -eq 'sqlServer' -and (Get-Service MSSQLSERVER -ErrorAction SilentlyContinue)) {
        if ($c.sqlServer.administratorPolicy -ceq 'recoverDisposableInstance') {
            Assert-DisposableSqlRecoveryImage
            $null = Get-SqlRestartServiceState
        } else { Assert-EmptyIdleSqlInstance }
    }
    $task = 'AzureLocalWorkload-Restart-' + [guid]::NewGuid().ToString('N')
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\shutdown.exe" -Argument '/r /t 0 /d p:4:1'
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(45)
    $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    $null = Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    return @{ bootUtc = $boot; restartScheduled = $true; task = $task }
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
                $range = Get-CidrRange $address -AllowSubnetMask
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

function Get-NarrowedRemoteScope([string[]]$RemoteAddresses, [string[]]$Cidrs) {
    if (!$RemoteAddresses.Count) { throw 'Inherited firewall rule has no remote scope.' }
    $intersections = @()
    foreach ($remote in $RemoteAddresses) {
        if ($remote -in @('Any', '*')) { $intersections += $Cidrs; continue }
        $candidate = if ($remote -match '/') { $remote } else { "$remote/32" }
        try { $range = Get-CidrRange $candidate -AllowSubnetMask }
        catch { throw 'Inherited firewall scope is not an explicit IPv4 network; resolve that policy manually.' }
        foreach ($cidr in $Cidrs) {
            $allowed = Get-CidrRange $cidr
            if ($range[0] -ge $allowed[0] -and $range[1] -le $allowed[1]) { $intersections += $remote }
            elseif ($allowed[0] -ge $range[0] -and $allowed[1] -le $range[1]) { $intersections += $cidr }
        }
    }
    @($intersections | Sort-Object -Unique)
}

function Set-InheritedFirewallScope([int]$Port, [string[]]$Cidrs) {
    foreach ($profile in Get-NetFirewallProfile -PolicyStore ActiveStore) {
        if (!$profile.Enabled -or $profile.DefaultInboundAction -ne 'Block') { throw 'All firewall profiles must be enabled with default inbound Block.' }
    }
    $plan = @()
    foreach ($rule in Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow) {
        $filter = $rule | Get-NetFirewallPortFilter
        if ($filter.Protocol -notin @('TCP', '6', 'Any', '256')) { continue }
        $matchesPort = @($filter.LocalPort | Where-Object {
            $_ -in @('Any', '*', "$Port") -or
            ($_ -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2])
        }).Count -gt 0
        if (!$matchesPort) { continue }
        $addresses = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress)
        $narrowed = @(Get-NarrowedRemoteScope $addresses $Cidrs)
        if ((($addresses | Sort-Object) -join '|') -eq (($narrowed | Sort-Object) -join '|')) { continue }
        if ($rule.PolicyStoreSourceType -ne 'Local') { throw 'Inherited service-port exposure is controlled outside the guest local policy; no policy was changed.' }
        $persistent = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -ErrorAction Stop)
        if ($persistent.Count -ne 1 -or $persistent[0].Direction -ne 'Inbound' -or
            $persistent[0].Action -ne 'Allow' -or $persistent[0].Enabled -ne 'True') { throw 'Inherited firewall rule changed or is not uniquely local.' }
        # These dynamic Windows rules cannot take a static remote filter. Disabling only narrows access.
        $disable = !$narrowed.Count -or $rule.Name -in @('WirelessDisplay-In-TCP', 'WiFiDirect-KM-Driver-In-TCP')
        $plan += @{ name=$rule.Name; remote=$narrowed; disable=$disable; original=$persistent[0]; address=($rule | Get-NetFirewallAddressFilter)
            port=$filter; application=($rule | Get-NetFirewallApplicationFilter); service=($rule | Get-NetFirewallServiceFilter) }
    }
    if (!$plan.Count) { return }
    $directory = Join-Path "$env:ProgramData\AzureLocalWorkload\Firewall" ([guid]::NewGuid().ToString())
    Set-PrivateDirectory $directory @()
    $plan | Export-Clixml -LiteralPath (Join-Path $directory 'before.clixml') -Depth 12
    foreach ($item in $plan) {
        $current = Get-NetFirewallRule -PolicyStore PersistentStore -Name $item.name -ErrorAction Stop
        $remote = @(($current | Get-NetFirewallAddressFilter).RemoteAddress)
        if ((($remote | Sort-Object) -join '|') -ne (($item.address.RemoteAddress | Sort-Object) -join '|') -or
            $current.Enabled -ne 'True' -or $current.Direction -ne 'Inbound' -or $current.Action -ne 'Allow') {
            throw 'Inherited firewall policy changed during preparation; inspect the protected snapshot.'
        }
        if ($item.disable) { Disable-NetFirewallRule -PolicyStore PersistentStore -Name $item.name | Out-Null }
        else { Set-NetFirewallRule -PolicyStore PersistentStore -Name $item.name -RemoteAddress $item.remote | Out-Null }
    }
    Assert-ScopedFirewall $Port $Cidrs
    Write-Output 'Explicitly approved local inherited firewall scopes narrowed; protected before-snapshot retained. No host or Azure firewall policy was changed.'
}

function Set-FileServer($Config, $Admin) {
    $feature = Install-WindowsFeature FS-FileServer
    Get-NetFirewallRule -PolicyStore PersistentStore |
        Where-Object Name -eq 'FileServer-ServerManager-SMB-TCP-In' |
        Disable-NetFirewallRule | Out-Null
    if (!$feature.Success) { throw 'File server role installation failed; no restart was requested.' }
    if ($feature.RestartNeeded -ne 'No') { throw 'A Windows restart is required. File server role installation completed.' }
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
    if (!$feature.Success) { throw 'IIS role installation failed; no restart was requested.' }
    if ($feature.RestartNeeded -ne 'No') { throw 'A Windows restart is required. IIS role installation completed.' }
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

function Get-SqlResult([string]$Query, [string]$Server = 'lpc:.',
    [ValidateSet('AzureLocalWorkload', 'SQLCMD')][string]$ApplicationName = 'AzureLocalWorkload',
    [ValidateRange(1, 12)][int]$Attempts = 12, [switch]$ClassifyLoginFailure) {
    for ($i = 0; $i -lt $Attempts; $i++) {
        $connection = New-Object System.Data.SqlClient.SqlConnection("Server=$Server;Integrated Security=SSPI;Encrypt=True;TrustServerCertificate=True;Connect Timeout=5;Application Name=$ApplicationName")
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
            if ($ClassifyLoginFailure) {
                $failure = $_.Exception.GetBaseException()
                if ($failure -is [System.Data.SqlClient.SqlException]) {
                    if ($failure.Number -eq 18461) { throw [InvalidOperationException]::new('An existing SQL single-user instance requires operator recovery.') }
                    if ($failure.Number -eq 18456) { throw [UnauthorizedAccessException]::new('Normal-mode SQL login denied; credentials and SQL responses are suppressed.') }
                }
            }
            if ($i -eq $Attempts - 1) { throw 'SQL integrated query readiness failed after bounded retry.' }
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
    Write-Output 'Preinstalled SQL 2022 Enterprise local integrated query and database acceptance passed. Image database paths and extra RAW disks were preserved; licensing remains operator-confirmed.'
}

function Assert-EmptyIdleSqlInstance {
    $visibility = (Get-SqlResult @"
SELECT HAS_PERMS_BY_NAME(NULL,NULL,N'VIEW ANY DATABASE') AS ViewDatabases,
HAS_PERMS_BY_NAME(NULL,NULL,N'ALTER ANY DATABASE') AS ViewOfflineDatabases,
HAS_PERMS_BY_NAME(NULL,NULL,N'VIEW SERVER PERFORMANCE STATE') AS ViewSessions,
CAST(SERVERPROPERTY('IsSingleUser') AS int) AS SingleUser
"@).Rows[0]
    if ($visibility.ViewDatabases -ne 1 -or $visibility.ViewOfflineDatabases -ne 1 -or
        $visibility.ViewSessions -ne 1 -or $visibility.SingleUser -ne 0) {
        throw 'SQL recovery/restart cannot verify the complete normal-mode database/session inventory with current permissions; no disruptive operation was started.'
    }
    $row = (Get-SqlResult @"
SELECT (SELECT COUNT(*) FROM sys.databases WHERE database_id > 4) AS UserDatabases,
(SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process=1 AND session_id<>@@SPID
 AND (open_transaction_count>0 OR status<>N'sleeping')) AS ActiveSessions
"@).Rows[0]
    if ($row.UserDatabases -ne 0 -or $row.ActiveSessions -ne 0) {
        throw 'SQL recovery/restart requires an empty instance with no active user sessions or transactions.'
    }
}

function Get-SqlRestartServiceState {
    $server = Get-Service MSSQLSERVER
    $agent = Get-Service SQLSERVERAGENT
    if ($server.Status -ne 'Running' -or $agent.Status -notin @('Running', 'Stopped') -or
        @($server.DependentServices | Where-Object { $_.Status -eq 'Running' -and $_.ServiceName -ne 'SQLSERVERAGENT' }).Count) {
        throw 'Unexpected SQL/dependent service state; restart/recovery refused.'
    }
    if ((Get-CimInstance Win32_Service -Filter "Name='MSSQLSERVER'").StartName -ne 'NT Service\MSSQLSERVER') {
        throw 'Unexpected SQL service identity; restart/recovery refused.'
    }
    @{ server = $server; agent = $agent; agentWasRunning = $agent.Status -eq 'Running' }
}

function Set-MarketplaceSqlAdministrator($Sql, $Admin) {
    $account = "$env:COMPUTERNAME\$($Admin.Name)"
    $escaped = $account.Replace("'", "''")
    $system = ([Security.Principal.SecurityIdentifier]'S-1-5-18').Translate([Security.Principal.NTAccount]).Value.Replace("'", "''")
    $rolesQuery = "SELECT IS_SRVROLEMEMBER(N'sysadmin',N'$escaped') AS AdminRole, IS_SRVROLEMEMBER(N'sysadmin',N'$system') AS SystemRole, IS_SRVROLEMEMBER(N'sysadmin') AS CurrentRole, CAST(SERVERPROPERTY('IsSingleUser') AS int) AS SingleUser"
    $roles = $null
    try { $roles = (Get-SqlResult $rolesQuery -Attempts 1 -ClassifyLoginFailure).Rows[0] }
    catch [UnauthorizedAccessException] {
        if ($Sql.administratorPolicy -cne 'recoverDisposableInstance') { throw }
        Write-Output 'Normal-mode SQL login is unavailable; the explicit disposable-instance policy permits bounded recovery.'
    }
    if ($roles -and $roles.SingleUser -ne 0) { throw 'An existing single-user instance requires operator recovery; no new recovery was started.' }
    if ($roles.AdminRole -eq 1 -and $roles.SystemRole -eq 1) { return }
    $grant = @"
DECLARE @name sysname, @q nvarchar(max);
DECLARE names CURSOR LOCAL FAST_FORWARD FOR SELECT N'$escaped' UNION ALL SELECT N'$system';
OPEN names; FETCH NEXT FROM names INTO @name;
WHILE @@FETCH_STATUS=0 BEGIN
 IF EXISTS(SELECT 1 FROM sys.server_principals WHERE name=@name AND (type<>'U' OR is_disabled<>0))
  THROW 51000,'Intended Windows SQL login has an unexpected type or disabled state.',1;
 IF NOT EXISTS(SELECT 1 FROM sys.server_principals WHERE name=@name)
  BEGIN SET @q=N'CREATE LOGIN '+QUOTENAME(@name)+N' FROM WINDOWS'; EXEC(@q); END;
 IF NOT EXISTS(SELECT 1 FROM sys.server_role_members m
  JOIN sys.server_principals r ON r.principal_id=m.role_principal_id
  JOIN sys.server_principals p ON p.principal_id=m.member_principal_id
  WHERE r.name=N'sysadmin' AND p.name=@name)
  BEGIN SET @q=N'ALTER SERVER ROLE sysadmin ADD MEMBER '+QUOTENAME(@name); EXEC(@q); END;
 IF NOT EXISTS(SELECT 1 FROM sys.server_role_members m
  JOIN sys.server_principals r ON r.principal_id=m.role_principal_id
  JOIN sys.server_principals p ON p.principal_id=m.member_principal_id
  WHERE r.name=N'sysadmin' AND p.name=@name AND p.type='U' AND p.is_disabled=0)
  THROW 51001,'Persistent intended Windows SQL sysadmin membership was not verified.',1;
 FETCH NEXT FROM names INTO @name;
END;
CLOSE names; DEALLOCATE names;
SELECT 1 AS Granted;
"@
    # Single-user Windows administrator authority is temporary, not a persisted role grant.
    if ($roles.CurrentRole -eq 1) {
        $null = Get-SqlResult $grant
    } else {
        if ($Sql.administratorPolicy -cnotin @('recoverEmptyInstance', 'recoverDisposableInstance')) {
            throw 'SYSTEM lacks SQL sysadmin authority. An explicit recovery policy is required; no service was stopped.'
        }
        if ($Sql.administratorPolicy -ceq 'recoverEmptyInstance') { Assert-EmptyIdleSqlInstance }
        Invoke-EmptySqlAdministratorRecovery $grant -Disposable:($Sql.administratorPolicy -ceq 'recoverDisposableInstance')
    }
    $after = (Get-SqlResult $rolesQuery).Rows[0]
    if ($after.AdminRole -ne 1 -or $after.SystemRole -ne 1 -or $after.SingleUser -ne 0) {
        throw 'Normal-mode intended-administrator/SYSTEM SQL sysadmin acceptance failed.'
    }
}

function Assert-DisposableSqlRecoveryImage {
    $base = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER'
    $setup = Get-ItemProperty -LiteralPath "$base\Setup"
    $mode = Get-ItemProperty -LiteralPath "$base\MSSQLServer"
    $parameters = Get-ItemProperty -LiteralPath "$base\MSSQLServer\Parameters"
    if ($setup.Version -notmatch '^16\.' -or $setup.Edition -notlike 'Enterprise Edition*' -or $mode.LoginMode -ne 1 -or
        @($parameters.PSObject.Properties | Where-Object { $_.Name -match '^SQLArg\d+$' -and $_.Value -match '^\s*[-/][mf]' }).Count) {
        throw 'Disposable recovery requires the declared SQL 2022 Enterprise Windows-authenticated default instance with no persisted single-user/minimal startup flag.'
    }
}

function Invoke-EmptySqlAdministratorRecovery([string]$Grant, [switch]$Disposable) {
    # Supported lockout procedure, explicitly limited to an empty disposable instance:
    # https://learn.microsoft.com/sql/database-engine/configure-windows/connect-to-sql-server-when-system-administrators-are-locked-out
    if ($Disposable) { Assert-DisposableSqlRecoveryImage }
    else { Assert-EmptyIdleSqlInstance }
    $state = Get-SqlRestartServiceState
    $server = $state.server
    $agent = $state.agent
    if ($env:COMPUTERNAME -notmatch '^[A-Za-z][A-Za-z0-9-]{0,14}$') { throw 'Unexpected SQL computer name.' }
    $directory = Join-Path "$env:ProgramData\AzureLocalWorkloadSqlRecovery" ([guid]::NewGuid().ToString('N'))
    Set-PrivateDirectory $directory @()
    $marker = Join-Path $directory 'restore-required'
    $restorePath = Join-Path $directory 'restore-normal.ps1'
    $agentWasRunning = $state.agentWasRunning
    $restore = @'
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne '__COMPUTER__'){throw 'Unexpected SQL restoration target.'}
$marker='__MARKER__'
if(!(Test-Path -LiteralPath $marker)){exit 0}
$agent=Get-Service SQLSERVERAGENT
if($agent.Status -eq 'Running'){$agent.Stop();$agent.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))}
$server=Get-Service MSSQLSERVER
if($server.Status -eq 'StartPending'){$server.WaitForStatus('Running',[TimeSpan]::FromSeconds(60))}
$server.Refresh()
if($server.Status -eq 'Running'){$server.Stop()}
$server.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))
$server.Start();$server.WaitForStatus('Running',[TimeSpan]::FromSeconds(90))
if(__AGENT_RUNNING__){$agent.Start();$agent.WaitForStatus('Running',[TimeSpan]::FromSeconds(60))}
$connection=New-Object System.Data.SqlClient.SqlConnection('Server=localhost;Integrated Security=True;Connect Timeout=15;Application Name=AzureLocalWorkloadRestore')
try{
 $connection.Open();$command=$connection.CreateCommand();$command.CommandTimeout=15
 $command.CommandText="SELECT CAST(SERVERPROPERTY('IsSingleUser') AS int)"
 if($command.ExecuteScalar()-ne 0){throw 'Normal multi-user SQL restoration was not verified.'}
}finally{$connection.Dispose()}
$agent.Refresh()
if(($agent.Status-eq 'Running')-ne __AGENT_RUNNING__){throw 'Prior SQL Agent state was not restored.'}
Remove-Item -LiteralPath $marker -ErrorAction Stop
'@.Replace('__COMPUTER__', $env:COMPUTERNAME).Replace('__MARKER__', $marker).
        Replace('__AGENT_RUNNING__', $(if ($agentWasRunning) { '$true' } else { '$false' }))
    Set-Content -LiteralPath $restorePath -Value $restore -Encoding UTF8
    @{ utc = [DateTime]::UtcNow.ToString('o'); agentWasRunning = $agentWasRunning; emptyIdleVerified = $true } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'before.json')
    $task = 'AzureLocalWorkload-SqlRestore-' + [guid]::NewGuid().ToString('N')
    $powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$restorePath`""
    $triggers = @((New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(12)), (New-ScheduledTaskTrigger -AtStartup))
    $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 6)
    $null = Register-ScheduledTask -TaskName $task -Action $action -Trigger $triggers -Principal $principal -Settings $settings
    $null = New-Item -ItemType File -Path $marker
    try {
        if (!$Disposable) { Assert-EmptyIdleSqlInstance }
        else { Write-Output 'Explicit disposable SQL recovery can interrupt sessions and roll back in-flight work; no database is deleted or relocated.' }
        if ($agentWasRunning) { $agent.Stop(); $agent.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)) }
        $server.Stop(); $server.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
        $start = Start-Process -FilePath "$env:SystemRoot\System32\net.exe" -ArgumentList 'start MSSQLSERVER /mSQLCMD' -PassThru -WindowStyle Hidden
        if (!$start.WaitForExit(60000)) { Stop-Process -Id $start.Id; throw 'Single-user start timed out; normal restoration is armed.' }
        if ($start.ExitCode -ne 0) { throw 'Single-user start failed; normal restoration is armed.' }
        $single = (Get-SqlResult @"
SELECT CONVERT(int,SERVERPROPERTY('ProductMajorVersion')) AS Major,
CONVERT(nvarchar(128),SERVERPROPERTY('Edition')) AS Edition,
CONVERT(int,SERVERPROPERTY('IsIntegratedSecurityOnly')) AS WindowsOnly,
CONVERT(int,SERVERPROPERTY('IsSingleUser')) AS SingleUser, IS_SRVROLEMEMBER(N'sysadmin') AS CurrentRole
"@ -ApplicationName SQLCMD -Attempts 1).Rows[0]
        if ($single.Major -ne 16 -or $single.Edition -notlike 'Enterprise Edition*' -or
            $single.WindowsOnly -ne 1 -or $single.SingleUser -ne 1 -or $single.CurrentRole -ne 1) {
            throw 'Temporary single-user SQL edition/authentication/administrator authority was not verified; no grants were attempted.'
        }
        $null = Get-SqlResult $Grant -ApplicationName SQLCMD -Attempts 1
    } finally {
        if (!(Invoke-SqlNormalRestore $restorePath) -or (Test-Path -LiteralPath $marker)) {
            throw "Normal SQL restoration failed. Protected restoration watchdog retained: $task"
        }
        try {
            if ((Get-SqlResult "SELECT CAST(SERVERPROPERTY('IsSingleUser') AS int) AS SingleUser").Rows[0].SingleUser -ne 0 -or
                ((Get-Service SQLSERVERAGENT).Status -eq 'Running') -ne $agentWasRunning) {
                throw 'Normal SQL/Agent state acceptance failed.'
            }
        } catch {
            $null = New-Item -ItemType File -Path $marker -Force
            throw "Normal multi-user SQL or prior Agent state was not verified; restoration watchdog retained: $task"
        }
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
    }
}

function Invoke-SqlNormalRestore([string]$Path) {
    $process = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Path`"" -PassThru -WindowStyle Hidden
    if (!$process.WaitForExit(360000)) { Stop-Process -Id $process.Id; return $false }
    return $process.ExitCode -eq 0
}

function Set-MarketplaceSqlClientAccess($Config) {
    $null = Get-SqlRestartServiceState
    $browser = Get-Service SQLBrowser
    if ($browser.Status -notin @('Running', 'Stopped') -or @($browser.DependentServices | Where-Object Status -ne 'Stopped').Count) {
        throw 'Unexpected SQL Browser/dependent state; client configuration refused before registry changes.'
    }
    $base = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib'
    $changes = @()
    foreach ($setting in @(@("$base\Tcp", 'Enabled', 1), @("$base\Tcp", 'ListenOnAllIPs', 1), @("$base\Np", 'Enabled', 0))) {
        if ((Get-ItemProperty $setting[0]).($setting[1]) -ne $setting[2]) {
            $changes += @{ path = $setting[0]; name = $setting[1]; value = $setting[2] }
        }
    }
    foreach ($ip in Get-ChildItem "$base\Tcp" | Where-Object PSChildName -like 'IP*') {
        foreach ($setting in @(@('TcpDynamicPorts', ''), @('TcpPort', '1433'))) {
            if ((Get-ItemProperty $ip.PSPath).($setting[0]) -cne $setting[1]) {
                $changes += @{ path = $ip.PSPath; name = $setting[0]; value = $setting[1] }
            }
        }
    }
    $changed = $changes.Count -gt 0
    $browserChanged = $browser.Status -ne 'Stopped' -or
        (Get-CimInstance Win32_Service -Filter "Name='SQLBrowser'").StartMode -ne 'Disabled'
    if (!$changed) {
        try { $null = Get-SqlResult 'SELECT 1 AS Probe' 'tcp:localhost,1433' -Attempts 1 }
        catch { Write-Output 'TCP listener acceptance did not pass; attempting the explicit empty-instance guarded listener restart.'; $changed = $true }
    }
    if ($changed -or $browserChanged) {
        Assert-EmptyIdleSqlInstance
        foreach ($setting in $changes) { Set-ItemProperty $setting.path -Name $setting.name -Value $setting.value }
        if ($browser.Status -eq 'Running') { $browser.Stop(); $browser.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)) }
        Set-Service SQLBrowser -StartupType Disabled
    }
    if ($changed) {
        Assert-EmptyIdleSqlInstance
        $state = Get-SqlRestartServiceState
        try {
            if ($state.agentWasRunning) { $state.agent.Stop(); $state.agent.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)) }
            $state.server.Stop(); $state.server.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
        } finally {
            $state.server.Refresh()
            if ($state.server.Status -eq 'StopPending') { $state.server.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)); $state.server.Refresh() }
            if ($state.server.Status -eq 'Stopped') { $state.server.Start() }
            $state.server.WaitForStatus('Running', [TimeSpan]::FromSeconds(90))
            $state.agent.Refresh()
            if ($state.agentWasRunning -and $state.agent.Status -eq 'Stopped') { $state.agent.Start() }
            $state.agent.WaitForStatus($(if ($state.agentWasRunning) { 'Running' } else { 'Stopped' }), [TimeSpan]::FromSeconds(60))
        }
    }
    $null = Get-SqlResult 'SELECT 1 AS Probe' 'tcp:localhost,1433'
    Set-WorkloadFirewall 1433 $Config.allowedCidrs
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
    if ($c.windowsPreparation.scopeInheritedFirewall -eq $true) { Set-InheritedFirewallScope $port $c.allowedCidrs }
    Assert-ScopedFirewall $port $c.allowedCidrs
    if ($c.profile -eq 'sqlServer' -and $c.sqlServer.installationMode -eq 'marketplace') {
        if ($c.sqlServer.administratorPolicy -ceq 'recoverDisposableInstance') {
            Assert-DisposableSqlRecoveryImage
            Set-MarketplaceSqlAdministrator $c.sqlServer $admin
            Assert-MarketplaceSqlInstance $c
        } else {
            Assert-MarketplaceSqlInstance $c
            if ($c.sqlServer.administratorPolicy) { Set-MarketplaceSqlAdministrator $c.sqlServer $admin }
        }
        if ($c.sqlServer.clientAccess -eq $true) {
            if (!$c.sqlServer.administratorPolicy) { throw 'Marketplace client access requires an explicit administratorPolicy.' }
            Set-MarketplaceSqlClientAccess $c
        }
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

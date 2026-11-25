[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('IssueCertificate', 'Probe')][string]$Mode,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$RunId,
    [string]$CertificateThumbprint,
    [string]$ConfigurationBase64,
    [string]$EncryptedCredentialBase64
)
$ErrorActionPreference = 'Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18' -or ![Environment]::Is64BitProcess) {
    throw 'Fleet client checks require 64-bit Windows PowerShell as SYSTEM on the owned Windows probe.'
}
$subject = "CN=WorkloadFleet-$RunId"
if ($Mode -eq 'IssueCertificate') {
    $cert = New-SelfSignedCertificate -Type DocumentEncryptionCert -Subject $subject -CertStoreLocation Cert:\LocalMachine\My `
        -KeyLength 3072 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddHours(2)
    'WORKLOADFLEET_RESULT=' + (@{
        thumbprint = $cert.Thumbprint
        certificate = [Convert]::ToBase64String($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    } | ConvertTo-Json -Compress)
    return
}
if ($CertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Invalid peer certificate identity.' }
$certPath = "Cert:\LocalMachine\My\$CertificateThumbprint"
$cert = Get-Item -LiteralPath $certPath
if ($cert.Subject -cne $subject -or !$cert.HasPrivateKey -or $cert.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
    throw 'Peer certificate is not the current owned, unexpired encryption certificate.'
}
$credential = $null
try {
    try {
        $config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ConfigurationBase64)) | ConvertFrom-Json
        Add-Type -AssemblyName System.Security
        $cms = New-Object Security.Cryptography.Pkcs.EnvelopedCms
        $cms.Decode([Convert]::FromBase64String($EncryptedCredentialBase64))
        if ($cms.ContentEncryptionAlgorithm.Oid.Value -ne '2.16.840.1.101.3.4.1.42') { throw 'Expected AES256 CMS encryption.' }
        $cms.Decrypt((New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection($cert)))
        $credential = [Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content) | ConvertFrom-Json
    } catch { throw 'Peer configuration/credential decryption failed; decrypted values are not logged.' }
    if ($credential.username -cnotmatch '^[a-z][a-z0-9_]{2,19}$' -or $credential.password -isnot [string] -or
        !$credential.password -or $config.targets -isnot [array]) { throw 'Invalid protected peer configuration.' }
    if ($env:COMPUTERNAME -ine $config.sourceName) { throw 'Client computer identity does not match the owned probe.' }
    $disks = @(Get-Disk | Where-Object { !$_.IsBoot -and !$_.IsSystem })
    if ($disks.Count -ne @($config.sourceDiskSizes).Count -or
        @($disks | Where-Object PartitionStyle -NE 'RAW').Count -or
        ((@($disks.Size | Sort-Object) -join ',') -cne (@($config.sourceDiskSizes | ForEach-Object { $_ * 1GB } | Sort-Object) -join ','))) {
        throw 'Base Windows probe data disks must retain their exact requested capacities and RAW state.'
    }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class WorkloadFleetLogon {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool LogonUser(string user,string domain,string password,int type,int provider,out IntPtr token);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr token);
}
'@
    $accepted = @()
    foreach ($target in $config.targets) {
        if ($target.name -cnotmatch '^[A-Za-z][A-Za-z0-9-]{1,14}$' -or
            $target.address -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or
            $target.profile -notin @('fileServer', 'sqlServer', 'iisServer', 'webServer')) { throw 'Invalid peer target.' }
        $address = [Net.IPAddress]::Parse($target.address)
        if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'Peer target must use IPv4.' }
        if ($target.profile -in @('iisServer', 'webServer')) {
            $response = Invoke-WebRequest -Uri "http://$($target.address)/" -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 30
            if ($response.StatusCode -ne 200 -or $response.Content.Trim() -cne $target.expectedContent) { throw 'Peer HTTP content acceptance failed.' }
            $accepted += @{ name = $target.name; profile = $target.profile; http200 = $true }
            continue
        }
        $token = [IntPtr]::Zero
        $identity = $null
        try {
            if (![WorkloadFleetLogon]::LogonUser($credential.username, $target.name, $credential.password, 9, 3, [ref]$token)) {
                throw 'Protected network-only peer logon failed.'
            }
            $identity = [Security.Principal.WindowsIdentity]::Impersonate($token)
            if ($target.profile -eq 'fileServer') {
                if ($target.shareName -cnotmatch '^[A-Za-z][A-Za-z0-9_-]{1,31}$') { throw 'Invalid managed share.' }
                $path = "\\$($target.address)\$($target.shareName)\WorkloadFleet-$RunId-$([guid]::NewGuid().ToString('N')).txt"
                $created = $false
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes("WorkloadFleet-$RunId")
                    $file = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                    $created = $true
                    try { $file.Write($bytes, 0, $bytes.Length) } finally { $file.Dispose() }
                    if ([IO.File]::ReadAllText($path) -cne "WorkloadFleet-$RunId") { throw 'Authenticated peer SMB readback failed.' }
                    $connections = @(Get-SmbConnection | Where-Object {
                        $_.ShareName -eq $target.shareName -and $_.ServerName -in @($target.address, $target.name)
                    })
                    if (!$connections.Count -or @($connections | Where-Object { !$_.Encrypted -or [version]$_.Dialect -lt [version]'3.0' }).Count) {
                        throw 'Peer SMB connection did not establish encrypted SMB3.'
                    }
                } finally { if ($created) { [IO.File]::Delete($path) } }
                $accepted += @{ name = $target.name; profile = $target.profile; authenticatedWriteReadDelete = $true; encryptedSmb3 = $true }
            } else {
                $connection = New-Object Data.SqlClient.SqlConnection("Server=tcp:$($target.address),1433;Initial Catalog=master;Integrated Security=SSPI;Encrypt=True;TrustServerCertificate=True;Connect Timeout=15;Application Name=WorkloadFleetProbe")
                try {
                    $connection.Open()
                    $query = $connection.CreateCommand()
                    $query.CommandTimeout = 15
                    $query.CommandText = "SELECT ORIGINAL_LOGIN() AS LoginName,IS_SRVROLEMEMBER('sysadmin') AS AdminRole,CAST(SERVERPROPERTY('IsSingleUser') AS int) AS SingleUser,(SELECT encrypt_option FROM sys.dm_exec_connections WHERE session_id=@@SPID) AS Encrypted,1 AS Probe"
                    $table = New-Object Data.DataTable
                    $reader = $query.ExecuteReader()
                    $table.Load($reader)
                    $row = $table.Rows[0]
                    if ($row.LoginName -ine "$($target.name)\$($credential.username)" -or $row.AdminRole -ne 1 -or
                        $row.SingleUser -ne 0 -or $row.Encrypted -ne 'TRUE' -or $row.Probe -ne 1) {
                        throw 'Intended administrator encrypted normal-mode SQL peer query failed.'
                    }
                } finally { $connection.Dispose() }
                $accepted += @{ name = $target.name; profile = $target.profile; intendedAdministrator = $true; normalModeQuery = $true; encrypted = $true }
            }
        } finally {
            if ($identity) { $identity.Dispose() }
            if ($token -ne [IntPtr]::Zero) { $null = [WorkloadFleetLogon]::CloseHandle($token) }
        }
    }
    'WORKLOADFLEET_RESULT=' + (@{ accepted = $true; targets = $accepted } | ConvertTo-Json -Depth 5 -Compress)
} finally {
    $credential = $null
    Remove-Item -LiteralPath $certPath -DeleteKey -ErrorAction Stop
}
